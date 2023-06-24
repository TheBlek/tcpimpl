use etherparse::{
    Ipv4Header,
    TcpHeader,
    IpNumber,
};
use packet::*;
use std::io::{
    Read,
    Write,
    BufWriter,
};
use tun::Device;

mod packet;

#[derive(Default, Debug)]
enum TcpState {
    #[default]
    Listening,
    Connecting(u32),
    BeingConnectedTo(u32, u32),
    Established(u32, u32),
}

impl TcpState {
    fn response(&mut self, packet: &TcpPacket) -> Option<TcpPacket> {
        let in_header = &packet.header;
        let mut header = TcpHeader::new(
            in_header.destination_port,
            in_header.source_port,
            0,
            in_header.window_size,
        );
        match self {
            TcpState::Listening => {
                match (in_header.syn, in_header.ack) {
                    (true, false) => {
                        let isn = 0; // TODO: use MD5 on some state. RFC 1948.
                        *self = TcpState::BeingConnectedTo(isn, in_header.sequence_number + 1);
                        header.syn = true;
                        header.ack = true;
                        header.sequence_number = isn;
                        header.acknowledgment_number = in_header.sequence_number + 1;
                        Some(TcpPacket::from_header(header))
                    }
                    (_, _) => {
                        println!(
                            "Invalid package from {}. Resetting connection",
                            in_header.source_port
                        );
                        header.rst = true;
                        Some(TcpPacket::from_header(header))
                    } 
                } 
            } 
            TcpState::Connecting(_) => todo!(),
            TcpState::BeingConnectedTo(seq, ack) => {
                match (in_header.syn, in_header.ack, in_header.acknowledgment_number) {
                    (false, true, ack) if ack == *seq + 1 => {
                        println!(
                            "Established connection {} <-> {}",
                            in_header.source_port,
                            in_header.destination_port,
                        );
                        *self = TcpState::Established(*seq, ack);
                        None
                    },
                    (_, _, _) => {
                        println!(
                            "Invalid packet from {}. Resetting connection",
                            in_header.source_port
                        );
                        println!("{:?}", in_header);
                        header.rst = true;
                        *self = TcpState::Listening;
                        Some(TcpPacket::from_header(header))
                    }
                }
            },
            TcpState::Established(_, _) => todo!(),
        }
    }
}

fn print_skip(message: &str) {
    println!("{}", message);
    println!("Skipping...");
}

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

    let mut device_buffered = BufWriter::new(tun::create(&config).unwrap());
    let mut buf = [0; 1504];

    let mut state = TcpState::Listening;
    loop {
        let device = device_buffered.get_mut();
        let amount = device.read(&mut buf).unwrap();
        let eth_header = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_protocol = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_protocol != IPV4_ETHER_TYPE {
            // print_skip("Not IPv4 packet");
            continue;
        }

        let ip_packet = match Ipv4Packet::from_bytes(&buf[4..amount]) {
            Ok(p) => p,
            Err(e) => {
                print_skip(&format!("Could not parse eth packet: {e}"));
                continue;
            }
        };

        if ip_packet.protocol() != TCP_IP_TYPE {
            // print_skip("Not TCP packet");
            continue;
        }

        let tcp_packet = match TcpPacket::from_bytes(ip_packet.body) {
            Ok(p) => p,
            Err(e) => {
                print_skip(&format!("Could not parse ip packet: {e}"));
                continue;
            }
        };

        println!(
            "Registered packet from {:?}:{:?} to {:?}:{:?}. {:?}",
            ip_packet.header.source,
            tcp_packet.header.source_port,
            ip_packet.header.destination,
            tcp_packet.header.destination_port,
            tcp_packet.body
        );

        let Some(mut tcp_response) = state.response(&tcp_packet) else {
            print_skip("No comments...");
            continue;
        };

        tcp_response.header.checksum = tcp_response
            .header
            .calc_checksum_ipv4_raw(
                ip_packet.header.destination,
                ip_packet.header.source,
                tcp_response.body,
            )
            .unwrap();
        let ip_response = Ipv4Header::new(
            tcp_response.header.header_len() + tcp_response.body.len() as u16,
            64, // TODO: Find out resonable time to live
            IpNumber::Tcp as u8,
            ip_packet.header.destination,
            ip_packet.header.source,
        );

        println!("Responding");

        device_buffered.write_all(&buf[..=3]).expect("Could not write eth bytes");
        ip_response.write(&mut device_buffered).expect("Failed to write ip header");
        tcp_response.header.write(&mut device_buffered).expect("Failed to write tcp header");
        if !tcp_response.body.is_empty() {
            device_buffered.write_all(tcp_response.body).expect("Failed to write tcp body");
        }
        device_buffered.flush().unwrap();
    }
}
