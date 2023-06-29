use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use packet::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{BufWriter, Read, Write};
use std::rc::Rc;
use tcp::{is_between_wrapping, ConnectionState, ReceiveConnectionState, SendConnectionState};
use anyhow::Result;

mod packet;
mod tcp;

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

struct TcpStream<'a> {
    connection: ConnectionState,
    state: SyncTcpState,
    address: &'a str,
    manager: ConnectionManager,
    received: VecDeque<u8>,
}

impl TcpStream<'_> {
    fn update(&mut self) {
        self.manager.inner.borrow_mut().proccess_packets(
            self.address,
            |packet| {
                let send = &self.connection.send;
                let receive = &mut self.connection.receive;
                match self.state {
                    SyncTcpState::Established => {
                        if packet.header.rst {
                            println!("Connection is asked to be reset.");
                            self.state = SyncTcpState::Closed;
                            return TcpAnswer::Nothing;
                        }

                        if packet.header.fin {
                            // Other side is finished sending data
                            let ack = packet.header.sequence_number;
                            // Skip close wait for now `cause we can't write 
                            // anything yet
                            self.state = SyncTcpState::LastAck;
                            return TcpAnswer::PacketReturn(packet.respond(
                                ConnectionManager::RECIEVE_WINDOW_SIZE,
                                PacketResponse::Fin(
                                    self.connection.send.unacknowleged,
                                    ack,
                                ),
                            ), ());
                        }

                        let mut segment_len = packet.body.len();
                        if packet.header.syn {
                            segment_len += 1;
                        }
                        if packet.header.fin {
                            segment_len += 1;
                        }

                        if !packet.header.ack
                            || !is_between_wrapping(
                                send.unacknowleged.wrapping_sub(1), // It can equal send.unacknowleged
                                packet.header.acknowledgment_number,
                                send.next.wrapping_add(1), // It can equal send.next
                            )
                            || !receive.is_valid_segment(packet.header.sequence_number, segment_len)
                        {
                            // The packet does not contain proper acknowledgment or segment
                            // Therefore, being in synchronized state,
                            // we should send an empty packet containing current state
                            println!("unexpected packet");
                            return TcpAnswer::Packet(packet.respond(
                                ConnectionManager::RECIEVE_WINDOW_SIZE,
                                PacketResponse::Ack(
                                    self.connection.send.unacknowleged,
                                    self.connection.receive.next,
                                ),
                            ));
                        }

                        let data_start = receive.next.wrapping_sub(packet.header.sequence_number);
                        let received_data = &packet.body[data_start as usize..];
                        self.received.extend(received_data.iter());

                        receive.next += received_data.len() as u32;

                        TcpAnswer::PacketReturn(
                            packet.respond(
                                ConnectionManager::RECIEVE_WINDOW_SIZE,
                                PacketResponse::Ack(send.unacknowleged, receive.next),
                            ),
                            (),
                        )
                    }
                    SyncTcpState::CloseWait => {
                        // We can write data to the packet here
                        // And respond to acks

                        // Just a thought:
                        // What's the difference between closewait and established
                        // with 0 size window?
                        unimplemented!()
                    }
                    SyncTcpState::LastAck => {
                        if packet.header.ack 
                            && packet.header.acknowledgment_number == send.unacknowleged + 1 {
                            self.state = SyncTcpState::Closed;
                            TcpAnswer::Return(())
                        } else {
                            TcpAnswer::Packet(
                                packet.respond(
                                    0, // We cant receive anything
                                    PacketResponse::Ack(send.unacknowleged, receive.next)
                                )
                            )
                        }
                    }   
                    _ => unimplemented!(),
                }
            },
        );
    }
}

impl<'a> Read for TcpStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.received.is_empty() && self.state != SyncTcpState::Closed {
            self.update();
        }

        if !self.received.is_empty() {
            // Looking at the implementation of Read for VecDeque and &[],
            // It basically cant fail
            let copied = self.received.read(buf)?;
            return Ok(copied);
        }
        // Means connection now is closed
        Ok(0)
    }
}

// impl Write for TcpStream {

// }

enum UnsyncTcpState {
    Listen,
    SynReceived(ConnectionState),
    SynSent(ConnectionState),
}

struct InnerConnectionManager {
    tun: BufWriter<tun::platform::linux::Device>,
}

enum TcpAnswer<'a, T> {
    Packet(TcpPacket<'a>),
    PacketReturn(TcpPacket<'a>, T),
    Nothing,
    Return(T),
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
        eth_protocol: u16,
    ) {
        packet.header.checksum = packet
            .header
            .calc_checksum_ipv4_raw(source, destination, packet.body)
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
            .write_all(&eth_protocol.to_be_bytes())
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
                .write_all(packet.body)
                .expect("Failed to write tcp body");
        }

        self.tun.flush().unwrap();
    }

    // TODO: make an iterator over the packets. (But what about writing?)
    // This way I do not need to make this abomination
    //
    fn proccess_packets<F, T>(&mut self, addr: &str, mut f: F) -> T
    where
        F: FnMut(TcpPacket) -> TcpAnswer<T>,
    {
        let mut iter = addr.split(':');
        let address = &iter
            .next()
            .unwrap()
            .split('.')
            .map(|s| s.parse::<u8>().unwrap())
            .collect::<Vec<_>>()[..4];
        let port = iter.next().unwrap().parse().unwrap();
        let mut buf = [0; 1504];
        loop {
            let device = self.tun.get_mut();
            let amount = device.read(&mut buf).unwrap();
            let eth_header = u16::from_be_bytes([buf[0], buf[1]]);
            let eth_protocol = u16::from_be_bytes([buf[2], buf[3]]);
            if eth_protocol != IPV4_ETHER_TYPE {
                continue;
            }

            let Ok(ip_packet) = Ipv4Packet::from_bytes(&buf[4..amount]) else {
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

            match f(tcp_packet) {
                TcpAnswer::Packet(response) => self.send_packet(
                    response,
                    ip_packet.header.destination,
                    ip_packet.header.source,
                    eth_header,
                    eth_protocol,
                ),
                TcpAnswer::PacketReturn(response, result) => {
                    self.send_packet(
                        response,
                        ip_packet.header.destination,
                        ip_packet.header.source,
                        eth_header,
                        eth_protocol,
                    );
                    return result;
                }
                TcpAnswer::Nothing => continue,
                TcpAnswer::Return(r) => return r,
            }
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

        Ok(
            ConnectionManager {
                inner: Rc::new(RefCell::new(InnerConnectionManager {
                    tun: BufWriter::new(tun::create(&config)?),
                })),
            }
        )
    }

    // TODO: make a trait IntoAddr or smth
    fn accept<'a>(&'a mut self, addr: &'a str) -> TcpStream {
        let mut state = UnsyncTcpState::Listen;
        let connection_state = self.inner.borrow_mut().proccess_packets(addr, |packet| {
            let in_header = &packet.header;
            match state {
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
                        TcpAnswer::Packet(packet.respond(
                            Self::RECIEVE_WINDOW_SIZE,
                            PacketResponse::SynAck(
                                new_state.send.unacknowleged,
                                new_state.receive.next,
                            ),
                        ))
                    }
                    (_, ack) => {
                        let seq = if ack {
                            in_header.acknowledgment_number
                        } else {
                            0
                        };
                        TcpAnswer::Packet(packet.respond(
                            Self::RECIEVE_WINDOW_SIZE,
                            PacketResponse::Reset(seq),
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
                        TcpAnswer::Nothing
                    }
                    (_, false, true, ack) if ack == connection_state.send.unacknowleged + 1 => {
                        connection_state.send.unacknowleged = ack;
                        TcpAnswer::Return(connection_state)
                    }
                    (_, _, ack, _) => {
                        state = UnsyncTcpState::Listen;
                        let seq = if ack {
                            in_header.acknowledgment_number
                        } else {
                            0
                        };
                        TcpAnswer::Packet(packet.respond(
                            Self::RECIEVE_WINDOW_SIZE,
                            PacketResponse::Reset(seq),
                        ))
                    }
                },
                UnsyncTcpState::SynSent(_) => panic!(),
            }
        });
        TcpStream {
            address: addr,
            connection: connection_state,
            manager: ConnectionManager {
                inner: Rc::clone(&self.inner),
            }, received: VecDeque::new(), state: SyncTcpState::Established, }
    }
}

fn print_skip(message: &str) {
    println!("{}", message);
    println!("Skipping...");
}

fn main() -> Result<()> {
    let mut manager = ConnectionManager::new("10.0.0.1", "255.255.255.0")?;

    let mut stream = manager.accept("10.0.0.2:5000");
    let mut res = String::new();
    let _ = stream.read_to_string(&mut res);
    // let mut buffer = [0; 1504];
    // let n = stream.read(&mut buffer)?;
    println!("{}", res);

    Ok(())
}
