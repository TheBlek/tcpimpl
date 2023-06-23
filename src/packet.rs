use anyhow::Result;
use etherparse::{
    Ipv4Header,
    TcpHeader,
};

#[derive(Debug)]
pub struct IPPacket<'a> {
    pub header: Ipv4Header,
    pub body: &'a [u8],
}

impl<'a> IPPacket<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, body) = Ipv4Header::from_slice(bytes)?;
        Ok(
            Self {
                body,
                header,
            }
        )
    }

    pub fn protocol(&self) -> u8 {
        self.header.protocol
    }
}

#[derive(Debug)]
pub struct TCPPacket<'a> {
    pub header: TcpHeader,
    pub body: &'a [u8],
}

impl<'a> TCPPacket<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, body) = TcpHeader::from_slice(bytes)?;
        Ok(
            Self {
                body,
                header,
            }
        )
    }
}
