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

pub enum PacketResponse {
    Reset(u32),
    Syn(u32),
    SynAck(u32, u32),
    Ack(u32, u32),
    Fin(u32, u32),
}

impl<'a> TcpPacket<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, body) = TcpHeader::from_slice(bytes)?;
        Ok(Self { body, header })
    }

    pub fn from_header(header: TcpHeader) -> Self {
        Self { header, body: &[] }
    }

    pub fn is_checksum_valid(&self, source: [u8; 4], destination: [u8; 4]) -> bool {
        let intended = self
            .header
            .calc_checksum_ipv4_raw(source, destination, self.body)
            .unwrap();
        intended == self.header.checksum
    }

    pub fn respond<'b>(self, window: u16, response: PacketResponse, body: &'b [u8]) -> TcpPacket<'b> {
        let mut header = TcpHeader::new(
            self.header.destination_port,
            self.header.source_port,
            0,
            window,
        );
        match response {
            PacketResponse::Reset(seq) => {
                header.rst = true;
                header.sequence_number = seq;
            }
            PacketResponse::Syn(seq) => {
                header.syn = true;
                header.sequence_number = seq;
            }
            PacketResponse::SynAck(seq, ack) => {
                header.syn = true;
                header.ack = true;
                header.sequence_number = seq;
                header.acknowledgment_number = ack;
            }
            PacketResponse::Ack(seq, ack) => {
                header.ack = true;
                header.sequence_number = seq;
                header.acknowledgment_number = ack;
            }
            PacketResponse::Fin(seq, ack) => {
                header.ack = true;
                header.acknowledgment_number = ack;
                header.sequence_number = seq;
                header.fin = true;
            }
        }
        TcpPacket { header, body }
    }
}
