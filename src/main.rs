use anyhow::Result;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use generational_arena::Arena;
use packet::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{BufWriter, Read, Write};
use std::rc::Rc;
use tcp::{is_between_wrapping, ConnectionState, ReceiveConnectionState, SendConnectionState};

mod packet;
mod tcp;

fn parse_address(addr: &str) -> Result<([u8; 4], u16)> {
    let mut iter = addr.split(':');
    let address = iter
        .next()
        .unwrap()
        .split('.')
        .map(|s| s.parse::<u8>().unwrap())
        .collect::<Vec<_>>()[..4]
        .try_into()?;
    let port = iter.next().unwrap().parse().unwrap();
    Ok((address, port))
}

// struct TcpListener {
// }

// impl TcpListener {
//     fn new(port) -> Self;
//     fn accept(self) -> TcpStream;
// }

/// Synchronized states of TCP protocol
/// according to RFC 793
#[derive(PartialEq)]
enum SyncTcpState {
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

impl SyncTcpState {
    fn can_receive(&self) -> bool {
        !matches!(
            self,
            SyncTcpState::CloseWait | SyncTcpState::Closed | SyncTcpState::LastAck
        )
    }

    fn can_send(&self) -> bool {
        !matches!(
            self,
            SyncTcpState::FinWait1
                | SyncTcpState::Closed
                | SyncTcpState::FinWait2
                | SyncTcpState::Closing
        )
    }

}

struct TcpStream {
    connection: ConnectionState,
    state: SyncTcpState,
    manager: ConnectionManager,
    received: VecDeque<u8>,
    to_send: VecDeque<u8>,
    local: ([u8; 4], u16), // TODO: Type for an address
    remote: ([u8; 4], u16),
}

impl TcpStream {
    fn close(&mut self) {
        if self.state == SyncTcpState::Closed {
            return;
        }
        match self.state {
            SyncTcpState::Established | SyncTcpState::CloseWait => {
                let mut header = TcpHeader::new(
                    self.local.1,
                    self.remote.1,
                    self.connection.send.unacknowleged,
                    0,
                );

                header.ack = true;
                header.fin = true;
                header.acknowledgment_number = self.connection.receive.next;
                self.manager.inner.borrow_mut().send_packet(
                    TcpPacket::from_header(header),
                    self.local.0,
                    self.remote.0,
                    0,
                );
                self.state = if self.state == SyncTcpState::Established {
                    SyncTcpState::FinWait1
                } else {
                    SyncTcpState::LastAck
                }
            }
            _ => {}
        }
    }

    fn terminate(&mut self) {
        self.close();

        while self.state != SyncTcpState::Closed {
            self.update();
        }
    }

    fn state_transition(&mut self, packet: &TcpPacket) {
        // Packet assumed to be with correct sequence numbers
        let send = &mut self.connection.send;
        let receive = &mut self.connection.receive;
        match self.state {
            SyncTcpState::Established => {
                if packet.header.fin {
                    // Other side is finished sending data
                    receive.next += 1;
                    self.state = SyncTcpState::CloseWait;
                    return;
                }
            }
            SyncTcpState::CloseWait => return,
            SyncTcpState::LastAck => {
                if packet.header.acknowledgment_number == send.unacknowleged + 1 {
                    self.state = SyncTcpState::Closed;
                }
            }
            SyncTcpState::FinWait1 => {
                if packet.header.fin && packet.header.sequence_number == receive.next {
                    // Other side is finished sending data too
                    receive.next += 1;
                    self.state = SyncTcpState::Closing;
                }

                if packet.header.ack
                    && packet.header.acknowledgment_number == send.unacknowleged + 1
                {
                    send.unacknowleged += 1;
                    self.state = SyncTcpState::FinWait2;
                }
            }
            SyncTcpState::FinWait2 => {
                if packet.header.fin && packet.header.sequence_number == receive.next {
                    // Other side is finished sending data too
                    receive.next += 1;
                    // No time wait for now - timers not implemented yet
                    self.state = SyncTcpState::Closed;
                }
            }
            SyncTcpState::Closing => {
                if packet.header.acknowledgment_number == send.unacknowleged + 1
                {
                    self.state = SyncTcpState::Closed;
                }
            }
            SyncTcpState::Closed => return,
            _ => unimplemented!(),
        } 
    }

    fn update(&mut self) {
        let (_, packet) = self.manager.inner.borrow_mut().next(self.local);

        if packet.header.rst {
            println!("Connection is asked to be reset.");
            self.state = SyncTcpState::Closed;
            return;
        }

        let data = if !self.connection.is_valid_seq_nums(&packet) {
            // The packet does not contain proper acknowledgment or segment
            // Therefore, being in synchronized state,
            // we should send an empty packet containing current state
            println!("unexpected packet");
            &[]
        } else {
            self.state_transition(&packet);
            let receive = &mut self.connection.receive;
            let send = &mut self.connection.send;

            if self.state.can_receive() {
                let data_start = receive.next.wrapping_sub(packet.header.sequence_number);
                let received_data = &packet.body[data_start as usize..];
                self.received.extend(received_data.iter());
                receive.next += received_data.len() as u32;
            }

            if self.state.can_send() && !self.to_send.is_empty() {
                let acknowledged = packet.header.acknowledgment_number.wrapping_sub(send.unacknowleged);
                self.to_send.drain(..acknowledged as usize);
                send.unacknowleged = packet.header.acknowledgment_number;
                send.window = packet.header.window_size;

                let (data, _) = self.to_send.as_slices();
                let amt = std::cmp::min(data.len(), send.window as usize);
                &data[..amt]
            } else {
                &[]
            }
        };

        let response = packet.respond(
            self.connection.receive.window,
            PacketResponse::Ack(self.connection.send.unacknowleged, self.connection.receive.next),
            data
        );
        self.manager.inner.borrow_mut().send_packet(response, self.local.0, self.remote.0, 0);
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.received.is_empty() && self.state.can_receive() {
            self.update();
        }

        if !self.received.is_empty() {
            // Looking at the implementation of Read for VecDeque and &[],
            // It basically cant fail
            return self.received.read(buf);
        }
        // Means connection now is closed
        Ok(0)
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.terminate();
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.state.can_send() {
            return Err(std::io::ErrorKind::ConnectionReset.into());
        }
        self.to_send.extend(buf.iter());
        while !self.to_send.is_empty() {
            self.update()
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

enum UnsyncTcpState {
    Listen,
    SynReceived(ConnectionState),
    SynSent(ConnectionState),
}

struct InnerConnectionManager {
    tun: BufWriter<tun::platform::linux::Device>,
}

struct ConnectionManager {
    inner: Rc<RefCell<InnerConnectionManager>>,
}

impl InnerConnectionManager {
    fn send_packet(
        &mut self,
        mut packet: TcpPacket,
        source: [u8; 4],
        destination: [u8; 4],
        eth_header: u16,
    ) {
        packet.header.checksum = packet
            .header
            .calc_checksum_ipv4_raw(source, destination, &packet.body)
            .unwrap();

        let ip_response = Ipv4Header::new(
            packet.header.header_len() + packet.body.len() as u16,
            64, // TODO: Find out resonable time to live
            IpNumber::Tcp as u8,
            source,
            destination,
        );

        self.tun
            .write_all(&eth_header.to_be_bytes())
            .expect("Could not write eth header");
        self.tun
            .write_all(&IPV4_ETHER_TYPE.to_be_bytes())
            .expect("Could not write eth protocol");
        ip_response
            .write(&mut self.tun)
            .expect("Failed to write ip header");
        packet
            .header
            .write(&mut self.tun)
            .expect("Failed to write tcp header");

        if !packet.body.is_empty() {
            self.tun
                .write_all(&packet.body)
                .expect("Failed to write tcp body");
        }

        self.tun.flush().unwrap();
    }

    // TODO: make an iterator over the packets. (But what about writing?)
    // This way I do not need to make this abomination
    // Apperently, writing an iterator owning the buffer and returning refs to it
    // is not possible using Iterator trait and would require GATs for lifetimes
    // I would rather not write a separate type for an iterator (bc it won't
    // get all the nice stuff beyond next).
    fn next(&mut self, (address, port): ([u8; 4], u16)) -> ([u8; 4], TcpPacket) {
        let mut buf = [0; 1504];
        loop {
            let device = self.tun.get_mut();
            let amount = device.read(&mut buf).unwrap();
            let data = &buf;

            let eth_header = u16::from_be_bytes([data[0], data[1]]);
            let eth_protocol = u16::from_be_bytes([data[2], data[3]]);
            if eth_protocol != IPV4_ETHER_TYPE {
                continue;
            }

            let Ok(ip_packet) = Ipv4Packet::from_bytes(&data[4..amount]) else {
                continue;
            };

            if ip_packet.header.destination != address || ip_packet.protocol() != TCP_IP_TYPE {
                continue;
            }

            let Ok(tcp_packet) = TcpPacket::from_bytes(ip_packet.body) else {
                continue;
            };

            if !tcp_packet.is_checksum_valid(ip_packet.header.source, ip_packet.header.destination)
            {
                continue;
            }

            if tcp_packet.header.destination_port != port {
                continue;
            }

            return (ip_packet.header.source, tcp_packet);
        }
    }
}

impl ConnectionManager {
    const RECIEVE_WINDOW_SIZE: u16 = 200;

    fn new(addr: &str, netmask: &str) -> Result<ConnectionManager> {
        let mut config = tun::Configuration::default();
        config
            .layer(tun::Layer::L3)
            .address(addr)
            .netmask(netmask)
            .platform(|config| {
                config.packet_information(true);
            })
            .up();

        Ok(ConnectionManager {
            inner: Rc::new(RefCell::new(InnerConnectionManager {
                tun: BufWriter::new(tun::create(&config)?),
            })),
        })
    }

    // TODO: make a trait IntoAddr or smth
    fn accept(&mut self, addr: &str) -> TcpStream {
        let mut state = UnsyncTcpState::Listen;
        let address = parse_address(addr).expect("Invalid address");
        let mut manager = self.inner.borrow_mut();
        let (connection_state, remote) = loop {
            let (remote, packet) = manager.next(address);
            let in_header = &packet.header;
            if let Some(response) = match state {
                UnsyncTcpState::Listen => match (in_header.syn, in_header.ack) {
                    (true, false) => {
                        let isn = 0; // TODO: use MD5 on some state. RFC 1948.
                        let new_state = ConnectionState {
                            send: SendConnectionState {
                                unacknowleged: isn,
                                window: in_header.window_size,
                                isn,
                                urgent_pointer: false,
                                next: isn + Self::RECIEVE_WINDOW_SIZE as u32,
                            },
                            receive: ReceiveConnectionState {
                                next: in_header.sequence_number + 1,
                                window: Self::RECIEVE_WINDOW_SIZE,
                                isn: in_header.sequence_number,
                            },
                        };
                        state = UnsyncTcpState::SynReceived(new_state);
                        Some(packet.respond(
                            Self::RECIEVE_WINDOW_SIZE,
                            PacketResponse::SynAck(
                                new_state.send.unacknowleged,
                                new_state.receive.next,
                            ),
                            &[],
                        ))
                    }
                    (_, ack) => {
                        let seq = if ack {
                            in_header.acknowledgment_number
                        } else {
                            0
                        };
                        Some(packet.respond(
                            Self::RECIEVE_WINDOW_SIZE,
                            PacketResponse::Reset(seq),
                            &[],
                        ))
                    }
                },
                UnsyncTcpState::SynReceived(mut connection_state) => match (
                    in_header.rst,
                    in_header.syn,
                    in_header.ack,
                    in_header.acknowledgment_number,
                ) {
                    (true, ..) => {
                        state = UnsyncTcpState::Listen;
                        None
                    }
                    (_, false, true, ack) if ack == connection_state.send.unacknowleged + 1 => {
                        connection_state.send.unacknowleged = ack;
                        break (connection_state, (remote, packet.header.source_port));
                    }
                    (_, _, ack, _) => {
                        state = UnsyncTcpState::Listen;
                        let seq = if ack {
                            in_header.acknowledgment_number
                        } else {
                            0
                        };
                        Some(packet.respond(
                            connection_state.send.window,
                            PacketResponse::Reset(seq),
                            &[],
                        ))
                    }
                },
                UnsyncTcpState::SynSent(_) => panic!(),
            } {
                manager.send_packet(response, address.0, remote, 0)
            }
        };
        TcpStream {
            local: address,
            remote,
            connection: connection_state,
            manager: ConnectionManager {
                inner: Rc::clone(&self.inner),
            },
            received: VecDeque::new(),
            to_send: VecDeque::new(),
            state: SyncTcpState::Established,
        }
    }
}

fn print_skip(message: &str) {
    println!("{}", message);
    println!("Skipping...");
}

fn main() -> Result<()> {
    let mut manager = ConnectionManager::new("10.0.0.1", "255.255.255.0")?;

    {
        let mut stream = manager.accept("10.0.0.2:5000");
        write!(&mut stream, "Hello {}", "World!")?;
        let mut res = String::new();
        let _ = stream.read_to_string(&mut res);
        // let mut buffer = [0; 1504];
        // let n = stream.read(&mut buffer)?;
        println!("{}", res);
    }

    Ok(())
}
