use anyhow::Result;
use etherparse::{Ipv4Header, TcpHeader};

pub const IPV4_ETHER_TYPE: u16 = 0x0800;
pub const TCP_IP_TYPE: u8 = 0x06;

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub header: Ipv4Header,
    pub body: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, body) = Ipv4Header::from_slice(bytes)?;
        Ok(Self { body, header })
    }

    pub fn protocol(&self) -> u8 {
        self.header.protocol
    }
}

#[derive(Debug)]
pub struct TcpPacket<'a> {
    pub header: TcpHeader,
    pub body: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, body) = TcpHeader::from_slice(bytes)?;
        Ok(Self { body, header })
    }

    pub fn from_header(header: TcpHeader) -> Self {
        Self { header, body: &[] }
    }
}
