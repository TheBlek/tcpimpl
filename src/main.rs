use std::io::Read;
use anyhow::{
    Context,
    Result,
};
use etherparse::{
    Ipv4Header,
    TcpHeader,
};

#[derive(Debug)]
struct IPPacket<'a> {
    header: Ipv4Header,
    body: &'a [u8],
}

impl<'a> IPPacket<'a> {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, body) = Ipv4Header::from_slice(bytes)?;
        Ok(
            Self {
                body,
                header,
            }
        )
    }

    fn protocol(&self) -> u8 {
        self.header.protocol
    }
}

#[derive(Debug)]
struct TCPPacket<'a> {
    header: TcpHeader,
    body: &'a [u8],
}

impl<'a> TCPPacket<'a> {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, body) = TcpHeader::from_slice(bytes)?;
        Ok(
            Self {
                body,
                header,
            }
        )
    }
}

fn print_skip(message: &str) {
    println!("{}", message);
    println!("Skipping...");
}

const IPV4_ETHER_TYPE: u16 = 0x0800;
const TCP_IP_TYPE: u8 = 0x06;

fn main() {
    let mut config = tun::Configuration::default();
    config
        .layer(tun::Layer::L3)
        .address("10.0.0.1")
        .netmask("255.255.255.0")
        .platform(|config| {
            config.packet_information(true);
        })
        .up();

    let mut dev = tun::create(&config).unwrap();
    let mut buf = [0; 1504];

    loop {
        let amount = dev.read(&mut buf).unwrap();
        let eth_header = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_protocol = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_protocol != IPV4_ETHER_TYPE {
            // print_skip("Not IPv4 packet");
            continue;
        }

        let ip_packet = match IPPacket::from_bytes(&buf[4..amount]) {
            Ok(p) => p,
            Err(e) => {
                print_skip(&format!("Could not parse eth packet: {e}"));
                continue;
            },
        };

        if ip_packet.protocol() != TCP_IP_TYPE {
            // print_skip("Not TCP packet");
            continue;
        }


        let tcp_packet = match TCPPacket::from_bytes(ip_packet.body) {
            Ok(p) => p,
            Err(e) => {
                print_skip(&format!("Could not parse ip packet: {e}"));
                continue;
            },
        };

        println!(
            "Registered packet from {:?}:{:?} to {:?}:{:?}. {:?}",
            ip_packet.header.source,
            tcp_packet.header.source_port,
            ip_packet.header.destination,
            tcp_packet.header.destination_port,
            tcp_packet.body
        );
    }
}
