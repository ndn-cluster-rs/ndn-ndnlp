use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_protocol::{Data, Interest};
use ndn_tlv::{find_tlv, GenericTlv, NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};

#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Packet {
    Interest(Interest<Bytes>),
    Data(Data<Bytes>),
    LpPacket(LpPacket),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownHeader(pub GenericTlv<Bytes>);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LpPacket {
    pub sequence: Option<Sequence>,
    pub frag_index: Option<FragIndex>,
    pub frag_count: Option<FragCount>,
    pub nack: Option<Nack>,
    pub other_headers: Vec<UnknownHeader>,
    pub fragment: Option<Fragment>,
    // Any modification here likely needs an adjustment to Tlv/TlvDecode/TlvEncode impls
}

#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
#[tlv(80)]
pub struct Fragment {
    pub data: Bytes,
}

#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
#[tlv(81)]
pub struct Sequence(pub Bytes);

#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[tlv(82)]
pub struct FragIndex(pub NonNegativeInteger);

#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[tlv(83)]
pub struct FragCount(pub NonNegativeInteger);

#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[tlv(800)]
pub struct Nack;

impl UnknownHeader {
    pub fn is_critical(&self) -> bool {
        let typ = self.0.typ.value();
        !(typ >= 800 && typ <= 959 && typ & 0b11 == 0)
    }
}

impl Packet {
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
    pub fn seq_num(&self) -> Option<Bytes> {
        self.sequence.as_ref().map(|x| x.0.clone())
    }

    pub fn frag_info(&self) -> Option<(NonNegativeInteger, NonNegativeInteger)> {
        Some((self.frag_index?.0, self.frag_count?.0))
    }

    pub fn is_nack(&self) -> bool {
        self.nack.is_some()
    }

    pub fn other_headers(&self) -> &Vec<UnknownHeader> {
        &self.other_headers
    }

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
