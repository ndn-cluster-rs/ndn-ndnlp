use bytes::Bytes;
use ndn_protocol::{Data, Interest};
use ndn_tlv::{Tlv, TlvEncode};

#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Packet {
    Interest(Interest<Bytes>),
    Data(Data<Bytes>),
    LpPacket(LpPacket),
}

#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
#[tlv(100)]
pub struct LpPacket {
    headers: Vec<LpHeader>,
    fragment: Option<Fragment>,
}

#[derive(Tlv, Debug, Clone, PartialEq, Eq, Hash)]
#[tlv(80)]
pub struct Fragment {
    data: Bytes,
}

#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LpHeader {
    Nack(Nack),
}

#[derive(Tlv, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[tlv(800)]
pub struct Nack {}

impl Packet {
    pub fn make_nack<T>(interest: Interest<T>) -> Self
    where
        T: TlvEncode,
    {
        Self::LpPacket(LpPacket {
            headers: vec![LpHeader::Nack(Nack {})],
            fragment: Some(Fragment {
                data: interest.encode(),
            }),
        })
    }
}

impl LpPacket {
    pub fn is_nack(&self) -> bool {
        for header in &self.headers {
            #[allow(irrefutable_let_patterns)]
            if let LpHeader::Nack(_) = header {
                return true;
            }
        }
        false
    }

    pub fn fragment(&self) -> Option<Bytes> {
        self.fragment.as_ref().map(|x| x.data.clone())
    }
}
