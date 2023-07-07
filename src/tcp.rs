use crate::address::*;
use crate::packet::*;

use anyhow::Result;

use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::io::{BufWriter, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

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

        if !self.send.is_valid_ack(packet.header.acknowledgment_number) {
            println!("invalid ack");
            return false;
        }
        if !self
            .receive
            .is_valid_segment(packet.header.sequence_number, segment_len)
        {
            println!("invalid segment");
            return false;
        }
        true
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

trait PacketWrite: Write + Sized {
    fn write_packet(
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

        self.write_all(&eth_header.to_be_bytes())
            .expect("Could not write eth header");
        self.write_all(&IPV4_ETHER_TYPE.to_be_bytes())
            .expect("Could not write eth protocol");
        ip_response.write(self).expect("Failed to write ip header");
        packet
            .header
            .write(self)
            .expect("Failed to write tcp header");

        if !packet.body.is_empty() {
            self.write_all(&packet.body)
                .expect("Failed to write tcp body");
        }

        self.flush().unwrap();
    }
}

impl<T: Write + Sized> PacketWrite for T {}

pub struct TcpStream {
    connection: ConnectionState,
    state: SyncTcpState,
    received: VecDeque<u8>,
    to_send: VecDeque<u8>,

    id: ConnectionId,
}

impl TcpStream {
    fn blank_header(&self) -> TcpHeader {
        let mut result = TcpHeader::new(
            self.id.local.port,
            self.id.remote.port,
            self.connection.send.unacknowleged,
            self.connection.receive.window,
        );
        result.ack = true;
        result.acknowledgment_number = self.connection.receive.next;
        result
    }

    fn send_packet(&self, tun: &mut impl PacketWrite, packet: TcpPacket) {
        tun.write_packet(packet, self.id.local.ip, self.id.remote.ip, 0);
    }

    pub fn close(&mut self, tun: &mut impl PacketWrite) {
        if self.state == SyncTcpState::Closed {
            return;
        }
        match self.state {
            SyncTcpState::Established | SyncTcpState::CloseWait => {
                let mut header = self.blank_header();
                header.fin = true;
                self.send_packet(tun, TcpPacket::from_header(header));
                self.state = if self.state == SyncTcpState::Established {
                    SyncTcpState::FinWait1
                } else {
                    SyncTcpState::LastAck
                }
            }
            _ => {}
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

    fn send_next_packet(&self, tun: &mut impl PacketWrite) {
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
        self.send_packet(tun, packet);
    }

    fn on_packet(&mut self, tun: &mut impl PacketWrite, packet: TcpPacket) {
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

        let received = if self.state.can_receive() {
            let data_start = receive.next.wrapping_sub(header.sequence_number);
            let received_data = &packet.body[data_start as usize..];
            self.received.extend(received_data.iter());
            receive.next = receive.next.wrapping_add(received_data.len() as u32);
            !received_data.is_empty()
        } else {
            false
        } || packet.header.fin;

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
        if received || (self.state.can_send() && !self.to_send.is_empty()) {
            self.send_next_packet(tun);
        }
    }
}

pub struct TcpStreamHandle {
    id: ConnectionId,
    manager: ConnectionManager,
}

impl Read for TcpStreamHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut manager = self.manager
                .inner
                .lock()
                .unwrap();
            let stream = manager
                .connections
                .get_mut(&self.id)
                .ok_or::<std::io::Error>(std::io::ErrorKind::ConnectionAborted.into())?;
            if !stream.received.is_empty() {
                // Looking at the implementation of Read for VecDeque and &[],
                // It basically cant fail
                return stream.received.read(buf);
            }

            if !stream.state.can_receive() {
                break;
            }
            std::mem::drop(manager);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // No more data to be received
        Ok(0)
    }
}

impl Drop for TcpStreamHandle {
    fn drop(&mut self) {
        let mut manager_lock = self.manager
            .inner
            .lock()
            .unwrap();
        let manager = &mut *manager_lock;
        let stream = manager
            .connections
            .get_mut(&self.id)
            .unwrap();
        stream.close(&mut manager.tun);
        std::mem::drop(manager_lock);
        loop {
            let mut manager = self.manager
                .inner
                .lock()
                .unwrap();
            let stream = manager
                .connections
                .get_mut(&self.id)
                .unwrap();

            if let SyncTcpState::Closed | SyncTcpState::FinWait2 = stream.state {
                break;
            }
            std::mem::drop(manager);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let mut manager = self.manager
            .inner
            .lock()
            .unwrap();
        manager.connections.remove(&self.id);
    }
}

impl Write for TcpStreamHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut manager_lock = self
            .manager
            .inner
            .lock()
            .unwrap();
        let manager = &mut *manager_lock; 
        let stream = manager
            .connections
            .get_mut(&self.id)
            .ok_or::<std::io::Error>(std::io::ErrorKind::ConnectionAborted.into())?;

        if !stream.state.can_send() {
            return Err(std::io::ErrorKind::ConnectionReset.into());
        }
        stream.to_send.extend(buf.iter());
        stream.send_next_packet(&mut manager.tun);
        std::mem::drop(manager_lock);

        loop {
            let manager = self
                .manager
                .inner
                .lock()
                .unwrap();
            let stream = manager
                .connections
                .get(&self.id)
                .ok_or::<std::io::Error>(std::io::ErrorKind::ConnectionAborted.into())?;
            if stream.to_send.len() < buf.len() {
                break;
            }
            std::mem::drop(manager);
            thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        loop {
            let manager = self
                .manager
                .inner
                .lock()
                .unwrap();
            let stream = manager
                .connections
                .get(&self.id)
                .ok_or::<std::io::Error>(std::io::ErrorKind::ConnectionAborted.into())?;
            if stream.to_send.is_empty() {
                break Ok(());
            }
            std::mem::drop(manager);
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

enum PotentialConnection {
    None(UnsyncTcpState),
    Established(ConnectionId),
}

enum UnsyncTcpState {
    Listen,
    SynReceived(ConnectionState),
    SynSent(ConnectionState),
}

impl UnsyncTcpState {
    fn on_packet(
        &mut self,
        tun: &mut impl PacketWrite,
        packet: TcpPacket,
        id: &ConnectionId,
    ) -> Option<ConnectionState> {
        let in_header = &packet.header;
        let response = match self {
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
                            window: ConnectionManager::RECIEVE_WINDOW_SIZE,
                            isn: in_header.sequence_number,
                        },
                    };
                    *self = UnsyncTcpState::SynReceived(new_state);
                    Some(packet.respond(
                        ConnectionManager::RECIEVE_WINDOW_SIZE,
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
                        ConnectionManager::RECIEVE_WINDOW_SIZE,
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
                    *self = UnsyncTcpState::Listen;
                    None
                }
                (_, false, true, ack)
                    if ack == connection_state.send.unacknowleged.wrapping_add(1) =>
                {
                    connection_state.send.unacknowleged = ack;
                    return Some(connection_state);
                }
                (_, _, ack, _) => {
                    *self = UnsyncTcpState::Listen;
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
        };

        if let Some(response_packet) = response {
            tun.write_packet(response_packet, id.local.ip, id.remote.ip, 0)
        }

        None
    }
}

struct InnerConnectionManager {
    tun: BufWriter<tun::platform::linux::Device>,
    connections: HashMap<ConnectionId, TcpStream>,
    nonsync: HashMap<Addr, PotentialConnection>,
}

pub struct ConnectionManager {
    inner: Arc<Mutex<InnerConnectionManager>>,
}

impl InnerConnectionManager {
    // TODO: make an iterator over the packets. (But what about writing?)
    // This way I do not need to make this abomination
    // Apperently, writing an iterator owning the buffer and returning refs to it
    // is not possible using Iterator trait and would require GATs for lifetimes
    // I would rather not write a separate type for an iterator (bc it won't
    // get all the nice stuff beyond next).
    fn next(&mut self) -> Option<(ConnectionId, TcpPacket)> {
        let mut buf = [0; 1504];
        loop {
            let device = self.tun.get_mut();
            let amount = match device.read(&mut buf) {
                Ok(n) => n,
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    return None;
                }
                _ => panic!(),
            };
            let data = &buf;

            let _eth_header = u16::from_be_bytes([data[0], data[1]]);
            let eth_protocol = u16::from_be_bytes([data[2], data[3]]);
            if eth_protocol != IPV4_ETHER_TYPE {
                continue;
            }

            let Ok(ip_packet) = Ipv4Packet::from_bytes(&data[4..amount]) else {
                continue;
            };

            if ip_packet.protocol() != TCP_IP_TYPE {
                continue;
            }

            let Ok(tcp_packet) = TcpPacket::from_bytes(ip_packet.body) else {
                continue;
            };

            if !tcp_packet.is_checksum_valid(ip_packet.header.source, ip_packet.header.destination)
            {
                continue;
            }

            let id = ConnectionId {
                local: Addr {
                    ip: ip_packet.header.destination,
                    port: tcp_packet.header.destination_port,
                },
                remote: Addr {
                    ip: ip_packet.header.source,
                    port: tcp_packet.header.source_port,
                },
            };

            return Some((id, tcp_packet));
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

        let device = tun::create(&config)?;
        device.set_nonblock()?;
        let inner = Arc::new(Mutex::new(InnerConnectionManager {
            tun: BufWriter::new(device),
            connections: HashMap::new(),
            nonsync: HashMap::new(),
        }));
        let manager_ptr = Arc::clone(&inner);

        thread::spawn(move || {
            loop {
                // check if there is a packet to read
                // if so, act on it
                // check if any timers are due
                // if so, act on them
                let mut guarded_manager = manager_ptr.lock().unwrap();
                let manager = &mut *guarded_manager;
                if let Some((id, packet)) = manager.next() {
                    let tun = &mut manager.tun;
                    let connections = &mut manager.connections;
                    let nonsync = &mut manager.nonsync;
                    use std::collections::hash_map::Entry;
                    match connections.entry(id.clone()) {
                        Entry::Occupied(mut stream) => {
                            stream.get_mut().on_packet(tun, packet);
                        }
                        Entry::Vacant(vacant) => {
                            let potential_stream = nonsync
                                .get_mut(&id.local)
                                .and_then(|pot_state| {
                                    if let PotentialConnection::None(ref mut state) = pot_state {
                                        state.on_packet(tun, packet, &id)
                                    } else {
                                        None
                                    }
                                })
                                .map(|connection| TcpStream {
                                    id: id.clone(),
                                    connection,
                                    received: VecDeque::new(),
                                    to_send: VecDeque::new(),
                                    state: SyncTcpState::Established,
                                });
                            if let Some(stream) = potential_stream {
                                nonsync.insert(id.local, PotentialConnection::Established(id));
                                vacant.insert(stream);
                            }
                        }
                    }
                }
                std::mem::drop(guarded_manager);

                thread::sleep(std::time::Duration::from_millis(50));
            }
        });

        Ok(ConnectionManager { inner })
    }

    // TODO: make a trait IntoAddr or smth
    pub fn accept(&mut self, addr: &str) -> Result<TcpStreamHandle> {
        // All the proccessing should be done in a separete thread
        // Here we should indicate that this address is open to connections
        // And block until it is accepted. (Non-blocking mode blah-blah)
        let address = addr.try_into()?;
        {
            let mut manager = self.inner.lock().unwrap();
            manager
                .nonsync
                .insert(address, PotentialConnection::None(UnsyncTcpState::Listen));
        }
        loop {
            let mut manager = self.inner.lock().unwrap();
            if let Some(PotentialConnection::Established(id)) = manager.nonsync.get(&address) {
                let id = id.clone();
                manager.nonsync.remove(&address);
                return Ok(TcpStreamHandle {
                    id,
                    manager: ConnectionManager {
                        inner: Arc::clone(&self.inner),
                    },
                });
            }
            std::mem::drop(manager);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}
