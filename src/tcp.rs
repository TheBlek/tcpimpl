use crate::packet::*;
use anyhow::Result;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::{BufWriter, Read, Write};
use std::rc::Rc;

pub fn is_between_wrapping(start: u32, x: u32, end: u32) -> bool {
    (end as i64 - start as i64) * (end as i64 - x as i64) * (x as i64 - start as i64) > 0
}

#[derive(Clone, Copy, Debug)]
pub struct SendConnectionState {
    pub unacknowleged: u32,
    pub next: u32,
    pub window: u16,
    pub urgent_pointer: bool,
    pub isn: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct ReceiveConnectionState {
    pub next: u32,
    pub window: u16,
    pub isn: u32,
}

impl ReceiveConnectionState {
    fn is_valid_segment(&self, start: u32, len: usize) -> bool {
        let before_next = self.next.wrapping_sub(1);
        match (len, self.window) {
            (0, 0) => start == self.next,
            (0, window) => {
                // is_between_wrapping is strict in checks, but
                // start can be equal to self.next.
                // Since we operate on integer values
                // a <= x <=> a - 1 < x
                is_between_wrapping(before_next, start, self.next.wrapping_add(window as u32))
            }
            (_, 0) => false,
            (len, window) => {
                let window_end = self.next.wrapping_add(window as u32);
                let segment_end = start.wrapping_add(len as u32).wrapping_sub(1);
                // Same as above
                is_between_wrapping(before_next, start, window_end)
                    || is_between_wrapping(before_next, segment_end, window_end)
            }
        }
    }
}

impl SendConnectionState {
    fn is_valid_ack(&self, ack: u32) -> bool {
        is_between_wrapping(
            self.unacknowleged.wrapping_sub(1), // It can equal send.unacknowleged
            ack,
            self.next.wrapping_add(1), // It can equal send.next
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectionState {
    pub send: SendConnectionState,
    pub receive: ReceiveConnectionState,
}

impl ConnectionState {
    pub fn is_valid_seq_nums(&self, packet: &TcpPacket) -> bool {
        if !packet.header.ack {
            return false;
        }

        let mut segment_len = packet.body.len();
        if packet.header.syn {
            segment_len += 1;
        }
        if packet.header.fin {
            segment_len += 1;
        }

        self.send.is_valid_ack(packet.header.acknowledgment_number)
            && self
                .receive
                .is_valid_segment(packet.header.sequence_number, segment_len)
    }
}

#[derive(Clone, Copy)]
pub struct Addr {
    ip: [u8; 4],
    port: u16,
}

impl From<([u8; 4], u16)> for Addr {
    fn from((ip, port): ([u8; 4], u16)) -> Self {
        Self { ip, port }
    }
}

impl TryFrom<&str> for Addr {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let mut iter = value.split(':');
        let address = iter
            .next()
            .unwrap()
            .split('.')
            .map(|s| s.parse::<u8>().unwrap())
            .collect::<Vec<_>>()[..4]
            .try_into()?;
        let port = iter.next().unwrap().parse().unwrap();
        Ok(Addr { ip: address, port })
    }
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

pub struct TcpStream {
    connection: ConnectionState,
    state: SyncTcpState,
    manager: ConnectionManager,
    received: VecDeque<u8>,
    to_send: VecDeque<u8>,
    local: Addr, // TODO: Type for an address
    remote: Addr,
}

impl TcpStream {
    pub fn close(&mut self) {
        if self.state == SyncTcpState::Closed {
            return;
        }
        match self.state {
            SyncTcpState::Established | SyncTcpState::CloseWait => {
                let mut header = TcpHeader::new(
                    self.local.port,
                    self.remote.port,
                    self.connection.send.unacknowleged,
                    0,
                );

                header.ack = true;
                header.fin = true;
                header.acknowledgment_number = self.connection.receive.next;
                self.manager.inner.borrow_mut().send_packet(
                    TcpPacket::from_header(header),
                    self.local.ip,
                    self.remote.ip,
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

    pub fn terminate(&mut self) {
        self.close();

        while self.state != SyncTcpState::Closed {
            self.update();
        }
    }

    fn state_transition(&mut self, packet: &TcpPacket) {
        // Packet is assumed to be with correct sequence numbers
        let send = &mut self.connection.send;
        let receive = &mut self.connection.receive;
        match self.state {
            SyncTcpState::Established => {
                if packet.header.fin && packet.header.sequence_number == receive.next {
                    // Other side is finished sending data
                    receive.next = receive.next.wrapping_add(1);
                    self.state = SyncTcpState::CloseWait;
                }
            }
            SyncTcpState::LastAck => {
                if packet.header.acknowledgment_number == send.unacknowleged.wrapping_add(1) {
                    self.state = SyncTcpState::Closed;
                }
            }
            SyncTcpState::FinWait1 => {
                if packet.header.fin && packet.header.sequence_number == receive.next {
                    // Other side is finished sending data too
                    receive.next = receive.next.wrapping_add(1);
                    self.state = SyncTcpState::Closing;
                }

                if packet.header.acknowledgment_number == send.unacknowleged.wrapping_add(1) {
                    send.unacknowleged = send.unacknowleged.wrapping_add(1);
                    self.state = SyncTcpState::FinWait2;
                }
            }
            SyncTcpState::FinWait2 => {
                if packet.header.fin && packet.header.sequence_number == receive.next {
                    // Other side is finished sending data too
                    receive.next = receive.next.wrapping_add(1);
                    // No time wait for now - timers not implemented yet
                    self.state = SyncTcpState::Closed;
                }
            }
            SyncTcpState::Closing => {
                if packet.header.acknowledgment_number == send.unacknowleged.wrapping_add(1) {
                    self.state = SyncTcpState::Closed;
                }
            }
            SyncTcpState::Closed | SyncTcpState::CloseWait => (),
            _ => unimplemented!(),
        }
    }

    fn blank_header(&self) -> TcpHeader {
        let mut result = TcpHeader::new(
            self.local.port,
            self.remote.port,
            self.connection.send.unacknowleged,
            self.connection.receive.window,
        );
        result.ack = true;
        result.acknowledgment_number = self.connection.receive.next;
        result
    }

    fn send_next_packet(&self) {
        let data = if self.state.can_send() && !self.to_send.is_empty() {
            let (data, _) = self.to_send.as_slices();
            let amt = std::cmp::min(data.len(), self.connection.send.window as usize);
            &data[..amt]
        } else {
            &[]
        };
        let packet = TcpPacket {
            header: self.blank_header(),
            body: data.into(),
        };
        self.manager
            .inner
            .borrow_mut()
            .send_packet(packet, self.local.ip, self.remote.ip, 0);
    }

    fn update(&mut self) {
        let (_, packet) = self.manager.inner.borrow_mut().next(self.local);

        let header = &packet.header;
        if header.rst {
            println!("Connection is asked to be reset.");
            self.state = SyncTcpState::Closed;
            return;
        }

        if !self.connection.is_valid_seq_nums(&packet) {
            // The packet does not contain proper acknowledgment or segment
            // Therefore, being in synchronized state,
            // we should send an empty packet containing current state
            println!("unexpected packet");
            return;
        }
        self.state_transition(&packet);
        let receive = &mut self.connection.receive;
        let send = &mut self.connection.send;

        if self.state.can_receive() {
            let data_start = receive.next.wrapping_sub(header.sequence_number);
            let received_data = &packet.body[data_start as usize..];
            self.received.extend(received_data.iter());
            receive.next = receive.next.wrapping_add(received_data.len() as u32);
        }

        if self.state.can_send() && !self.to_send.is_empty() {
            let acknowledged = header
                .acknowledgment_number
                .wrapping_sub(send.unacknowleged);
            self.to_send.drain(..acknowledged as usize);
            send.unacknowleged = header.acknowledgment_number;
            send.window = header.window_size;
            send.next = header
                .acknowledgment_number
                .wrapping_add(send.window as u32);
        }
        self.send_next_packet();
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
        self.send_next_packet();
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

pub struct ConnectionManager {
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
    fn next(&mut self, local: Addr) -> ([u8; 4], TcpPacket) {
        let mut buf = [0; 1504];
        loop {
            let device = self.tun.get_mut();
            let amount = device.read(&mut buf).unwrap();
            let data = &buf;

            let _eth_header = u16::from_be_bytes([data[0], data[1]]);
            let eth_protocol = u16::from_be_bytes([data[2], data[3]]);
            if eth_protocol != IPV4_ETHER_TYPE {
                continue;
            }

            let Ok(ip_packet) = Ipv4Packet::from_bytes(&data[4..amount]) else {
                continue;
            };

            if ip_packet.header.destination != local.ip || ip_packet.protocol() != TCP_IP_TYPE {
                continue;
            }

            let Ok(tcp_packet) = TcpPacket::from_bytes(ip_packet.body) else {
                continue;
            };

            if !tcp_packet.is_checksum_valid(ip_packet.header.source, ip_packet.header.destination)
            {
                continue;
            }

            if tcp_packet.header.destination_port != local.port {
                continue;
            }

            return (ip_packet.header.source, tcp_packet);
        }
    }
}

impl ConnectionManager {
    const RECIEVE_WINDOW_SIZE: u16 = 200;

    pub fn new(addr: impl tun::IntoAddress, netmask: &str) -> Result<ConnectionManager> {
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
    pub fn accept<T>(&mut self, addr: T) -> TcpStream
    where
        T: TryInto<Addr>,
        <T as TryInto<Addr>>::Error: Debug,
    {
        let mut state = UnsyncTcpState::Listen;
        let address = addr.try_into().expect("invalid address");
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
                                next: isn.wrapping_add(in_header.window_size as u32),
                            },
                            receive: ReceiveConnectionState {
                                next: in_header.sequence_number.wrapping_add(1),
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
                    (_, false, true, ack)
                        if ack == connection_state.send.unacknowleged.wrapping_add(1) =>
                    {
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
                manager.send_packet(response, address.ip, remote, 0)
            }
        };
        TcpStream {
            local: address,
            remote: remote.into(),
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
