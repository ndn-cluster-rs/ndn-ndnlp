#![warn(missing_docs)]
//! A partial implementation of NDNLPv2, the link-layer protocol NDN
//! packets are framed in before being sent over a transport (a TCP/Unix
//! socket, Ethernet, etc).
//!
//! [`Packet`] is the union of everything that can appear directly on the
//! wire: a bare [`Interest`], a bare [`Data`], or an NDNLPv2 [`LpPacket`].
//! An `LpPacket` wraps a fragment of an Interest or Data with link-layer
//! metadata -- a sequence number and fragment index/count for reassembly
//! ([`Sequence`], [`FragIndex`], [`FragCount`], [`Fragment`]) -- or carries
//! a link-layer [`Nack`] instead of a fragment.
//!
//! This crate only implements the parts of NDNLPv2 that
//! [`ndn-app`](https://crates.io/crates/ndn-app) needs, not the full
//! protocol. Headers it doesn't have a dedicated type for are preserved as
//! [`UnknownHeader`] rather than dropped.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_protocol::{Data, Interest};
use ndn_tlv::{find_tlv, GenericTlv, NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};

/// Anything that can appear directly on the wire: a bare Interest or Data
/// packet, or an NDNLPv2 link-layer packet.
#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Packet {
    /// An Interest packet, its application parameters still encoded as raw bytes.
    Interest(Interest<Bytes>),
    /// A Data packet, its content still encoded as raw bytes.
    Data(Data<Bytes>),
    /// An NDNLPv2 link-layer packet.
    LpPacket(LpPacket),
}

/// An NDNLPv2 header this crate doesn't have a dedicated type for
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownHeader(pub GenericTlv<Bytes>);

/// An NDNLPv2 link-layer packet: a fragment of an Interest or Data (or a
/// link-layer [`Nack`]), plus the metadata needed to reassemble and
/// deliver it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LpPacket {
    /// This fragment's sequence number, shared by every fragment of the
    /// same original packet.
    pub sequence: Option<Sequence>,
    /// This fragment's 0-based position among [`FragCount`] total fragments.
    pub frag_index: Option<FragIndex>,
    /// How many fragments the original packet was split into.
    pub frag_count: Option<FragCount>,
    /// Set if this packet carries a link-layer Nack rather than fragment data.
    pub nack: Option<Nack>,
    /// Headers this implementation doesn't have a dedicated type for
    pub other_headers: Vec<UnknownHeader>,
    /// The (possibly partial) encoded Interest or Data this packet carries.
    pub fragment: Option<Fragment>,
    // Any modification here likely needs an adjustment to Tlv/TlvDecode/TlvEncode impls
}

/// One (possibly the only) fragment of an encoded Interest or Data packet.
#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
#[tlv(80)]
pub struct Fragment {
    /// The fragment's raw bytes.
    pub data: Bytes,
}

/// A sequence number shared by every fragment of the same original packet,
/// used to group them back together on reassembly.
#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
#[tlv(81)]
pub struct Sequence(pub Bytes);

/// This fragment's 0-based position among [`FragCount`] total fragments.
#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[tlv(82)]
pub struct FragIndex(pub NonNegativeInteger);

/// How many fragments the original packet was split into.
#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[tlv(83)]
pub struct FragCount(pub NonNegativeInteger);

/// A marker indicating an [`LpPacket`] carries a link-layer negative
/// acknowledgement rather than fragment data.
#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[tlv(800)]
pub struct Nack;

impl UnknownHeader {
    /// Returns whether this header falls outside NDNLPv2's ignorable
    /// header range (TLV types 800-959, in steps of 4). A critical header
    /// this crate doesn't recognize is a decode error rather than
    /// something that's safe to silently skip.
    pub fn is_critical(&self) -> bool {
        let typ = self.0.typ.value();
        !(typ >= 800 && typ <= 959 && typ & 0b11 == 0)
    }
}

impl Packet {
    /// Wraps `interest`'s encoded bytes in an [`LpPacket`] carrying a
    /// link-layer [`Nack`] -- NDNLPv2's way of telling the next hop that
    /// this Interest couldn't be forwarded further.
    pub fn make_nack<T>(interest: Interest<T>) -> Self
    where
        T: TlvEncode,
    {
        Self::LpPacket(LpPacket {
            sequence: None,
            frag_index: None,
            frag_count: None,
            nack: Some(Nack),
            other_headers: vec![],
            fragment: Some(Fragment {
                data: interest.encode(),
            }),
        })
    }
}

impl LpPacket {
    /// This packet's sequence number, if set.
    pub fn seq_num(&self) -> Option<Bytes> {
        self.sequence.as_ref().map(|x| x.0.clone())
    }

    /// This fragment's `(index, count)` position among the original
    /// packet's fragments, if both are set.
    pub fn frag_info(&self) -> Option<(NonNegativeInteger, NonNegativeInteger)> {
        Some((self.frag_index?.0, self.frag_count?.0))
    }

    /// Whether this packet carries a link-layer Nack.
    pub fn is_nack(&self) -> bool {
        self.nack.is_some()
    }

    /// Headers this implementation doesn't recognize, preserved as-is.
    pub fn other_headers(&self) -> &Vec<UnknownHeader> {
        &self.other_headers
    }

    /// The raw bytes of the (possibly partial) Interest or Data this
    /// packet carries, if any.
    pub fn fragment(&self) -> Option<Bytes> {
        self.fragment.as_ref().map(|x| x.data.clone())
    }
}

impl Tlv for LpPacket {
    const TYP: usize = 100;

    fn inner_size(&self) -> usize {
        self.sequence.size()
            + self.frag_index.size()
            + self.frag_count.size()
            + self.nack.size()
            + self.other_headers.size()
            + self.fragment.size()
    }
}

impl TlvDecode for LpPacket {
    fn decode(bytes: &mut Bytes) -> ndn_tlv::Result<Self> {
        let mut cur = bytes.clone();
        find_tlv::<Self>(&mut cur, true)?;

        let typ = VarNum::decode(&mut cur)?.into();
        if typ != Self::TYP {
            return Err(ndn_tlv::TlvError::TypeMismatch {
                expected: Self::TYP,
                found: typ,
            });
        }

        let len = VarNum::decode(&mut cur)?.into();
        if cur.remaining() < len {
            return Err(ndn_tlv::TlvError::UnexpectedEndOfStream);
        }
        let mut inner_data = cur.split_to(len);

        let mut other_headers = Vec::new();

        // 80-100 headers
        let sequence = Option::<Sequence>::decode(&mut inner_data)?;
        let frag_index = Option::<FragIndex>::decode(&mut inner_data)?;
        let frag_count = Option::<FragCount>::decode(&mut inner_data)?;

        while inner_data.has_remaining() {
            let mut header_cur = inner_data.clone();
            let header_ty: usize = VarNum::decode(&mut header_cur)?.into();
            if header_ty > 100 {
                break;
            }
            let header = UnknownHeader::decode(&mut inner_data)?;
            other_headers.push(header);
        }

        // 800-1000 headers
        let nack = Option::<Nack>::decode(&mut inner_data)?;

        while inner_data.has_remaining() {
            let mut header_cur = inner_data.clone();
            let header_ty: usize = VarNum::decode(&mut header_cur)?.into();
            if header_ty < 800 {
                break;
            }
            let header = UnknownHeader::decode(&mut inner_data)?;
            other_headers.push(header);
        }

        let fragment = Option::<Fragment>::decode(&mut inner_data)?;
        bytes.advance(bytes.remaining() - cur.remaining());
        Ok(Self {
            sequence,
            frag_index,
            frag_count,
            nack,
            other_headers,
            fragment,
        })
    }
}

impl TlvEncode for LpPacket {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put(VarNum::from(Self::TYP).encode());
        bytes.put(VarNum::from(self.inner_size()).encode());

        let mut headers = self.other_headers.clone();
        headers.sort_by_key(|x| x.0.typ);

        // 80-100 headers
        bytes.put(self.sequence.encode());
        bytes.put(self.frag_index.encode());
        bytes.put(self.frag_count.encode());
        for header in &headers {
            if header.0.typ.value() <= 100 {
                bytes.put(header.encode());
            }
        }

        // 800-1000 headers
        bytes.put(self.nack.encode());
        for header in &headers {
            if header.0.typ.value() >= 800 {
                bytes.put(header.encode());
            }
        }

        // fragment
        bytes.put(self.fragment.encode());

        bytes.freeze()
    }

    fn size(&self) -> usize {
        VarNum::from(Self::TYP).size() + VarNum::from(self.inner_size()).size() + self.inner_size()
    }
}

impl TlvDecode for UnknownHeader {
    fn decode(bytes: &mut Bytes) -> ndn_tlv::Result<Self> {
        let mut cur = bytes.clone();
        let typ = VarNum::decode(&mut cur)?.into();

        if (typ <= 80 || typ >= 100) && (typ < 800 || typ > 1000) {
            // NDNLPv2 reseres 80-100 and 800-1000
            // Anything outside that range is invalid
            // 80 is the Fragment, not a header, therefore invalid
            // 100 is the entire LpPacket, also invalid
            // Everything else may be a header and will be treated as such
            return Err(ndn_tlv::TlvError::TypeMismatch {
                expected: 0,
                found: typ,
            });
        }

        Ok(Self(GenericTlv::decode(bytes)?))
    }
}

impl TlvEncode for UnknownHeader {
    fn encode(&self) -> Bytes {
        self.0.encode()
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

#[cfg(test)]
mod tests {
    use ndn_protocol::Name;

    use super::*;

    #[test]
    fn nack() {
        let interest: Interest<()> = Interest::new(Name::from_str("/test/nack").unwrap());
        let mut nack = Packet::make_nack(interest.clone());
        match nack {
            Packet::LpPacket(ref mut packet) => {
                packet.other_headers.push(UnknownHeader(GenericTlv {
                    typ: VarNum::new(1000),
                    len: VarNum::new(0),
                    content: Bytes::new(),
                }));

                packet.other_headers.push(UnknownHeader(GenericTlv {
                    typ: VarNum::new(999),
                    len: VarNum::new(0),
                    content: Bytes::new(),
                }));

                packet.other_headers.push(UnknownHeader(GenericTlv {
                    typ: VarNum::new(95),
                    len: VarNum::new(0),
                    content: Bytes::new(),
                }));
            }
            _ => unreachable!(),
        }
        let nack2 = LpPacket::decode(&mut nack.encode()).unwrap();

        assert!(nack2.is_nack());
        assert_eq!(nack2.other_headers.len(), 3);
        assert_eq!(nack2.other_headers[0].0.typ.value(), 95);
        assert_eq!(nack2.other_headers[1].0.typ.value(), 999);
        assert_eq!(nack2.other_headers[2].0.typ.value(), 1000);

        let mut fragment = nack2.fragment().unwrap();
        let interest2 = Interest::decode(&mut fragment).unwrap();
        assert_eq!(interest, interest2);
    }
}
