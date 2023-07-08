mod address;
mod packet;
mod state;

use address::*;
use packet::*;
use state::*;

use anyhow::Result;

use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::io::{BufWriter, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

trait PacketWrite: Write + Sized {
    fn write_packet(
        &mut self,
        packet: &mut TcpPacket,
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
    retransmission: Option<Retransmission>,
    round_trip_time: f64,
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

    fn send_packet(&self, tun: &mut impl PacketWrite, packet: &mut TcpPacket) {
        tun.write_packet(packet, self.id.local.ip, self.id.remote.ip, 0);
    }

    fn close(&mut self, tun: &mut impl PacketWrite) {
        if let SyncTcpState::Closed | SyncTcpState::FinWait1 | SyncTcpState::LastAck = self.state {
            return;
        }
        match self.state {
            SyncTcpState::Established | SyncTcpState::CloseWait => {
                let mut header = self.blank_header();
                header.fin = true;
                let mut packet = TcpPacket::from_header(header);
                self.send_packet(tun, &mut packet);
                self.retransmission = Some(Retransmission {
                    packet,
                    last_sent: std::time::Instant::now(),
                    srtt: self.round_trip_time,
                });
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

    fn send_next_packet(&mut self, tun: &mut impl PacketWrite) {
        let data = if self.state.can_send() && !self.to_send.is_empty() {
            use std::cmp::min;
            let (data, other) = self.to_send.as_slices();
            let window = self.connection.send.window as usize;
            let amt = min(data.len(), window);
            let mut res: Vec<_> = data[..amt].into();
            if amt == data.len() {
                let remaining_amt = min(other.len(), window - amt);
                println!("I actually extended by {}", remaining_amt);
                res.extend_from_slice(&other[..remaining_amt]);
            }
            res
        } else {
            vec![]
        };
        let mut packet = TcpPacket {
            header: self.blank_header(),
            body: data,
        };
        self.send_packet(tun, &mut packet);
        if !packet.body.is_empty() {
            self.retransmission = Some(Retransmission {
                packet,
                last_sent: std::time::Instant::now(),
                srtt: self.round_trip_time,
            });
        }
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
            self.send_next_packet(tun);
            return;
        }
        self.state_transition(&packet);
        let receive = &mut self.connection.receive;
        let send = &mut self.connection.send;

        // TODO: Buffer packets before presenting them to address out-of-order
        // packets problem
        let received = if self.state.can_receive() && header.sequence_number == receive.next {
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

            if let Some(retransmission) = &self.retransmission {
                if acknowledged > 0 {
                    let elapsed = retransmission.last_sent.elapsed().as_secs_f64();
                    self.round_trip_time = (self.round_trip_time + elapsed) / 2.0;
                    self.retransmission = None;
                }
            }
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

impl TcpStreamHandle {
    pub fn close(&self) {
        let mut manager_lock = self.manager.lock().unwrap();
        let manager = &mut *manager_lock;
        let stream = manager.connections.get_mut(&self.id).unwrap();
        stream.close(&mut manager.tun);
    }
}

impl Read for TcpStreamHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut manager = self.manager.lock().unwrap();
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
        self.close();
        loop {
            let mut manager = self.manager.lock().unwrap();
            let stream = manager.connections.get_mut(&self.id).unwrap();

            if let SyncTcpState::Closed | SyncTcpState::FinWait2 = stream.state {
                break;
            }
            std::mem::drop(manager);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let mut manager = self.manager.lock().unwrap();
        manager.connections.remove(&self.id);
    }
}

impl Write for TcpStreamHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut manager_lock = self.manager.lock().unwrap();
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
            let manager = self.manager.lock().unwrap();
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
            let manager = self.manager.lock().unwrap();
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

struct Retransmission {
    packet: TcpPacket,
    last_sent: std::time::Instant,
    srtt: f64,
}

// Timeout procedure is following an example in RFC 793
impl Retransmission {
    const ALPHA: f64 = 0.8;
    const BETA: f64 = 1.2;
    const TIMEOUT_UBOUND: f64 = 10.0;
    const TIMEOUT_LBOUND: f64 = 0.5;

    fn due(&self) -> bool {
        let timeout = Self::TIMEOUT_UBOUND.min(Self::TIMEOUT_LBOUND.max(Self::BETA * self.srtt));
        self.last_sent.elapsed().as_secs_f64() >= timeout
    }

    fn recalculate_srtt(&mut self, round_trip_time: f64) {
        self.srtt = (Self::ALPHA * self.srtt) + ((1f64 - Self::ALPHA) * round_trip_time);
    }

    fn from_packet(packet: TcpPacket) -> Self {
        Self {
            packet,
            last_sent: std::time::Instant::now(),
            srtt: 1.0,
        }
    }
}

enum PotentialConnection {
    None(UnsyncTcpState),
    Established(ConnectionId),
}

pub struct InnerConnectionManager {
    tun: BufWriter<tun::platform::linux::Device>,
    connections: HashMap<ConnectionId, TcpStream>,
    nonsync: HashMap<Addr, PotentialConnection>,
}

pub struct ConnectionManager {
    inner: Arc<Mutex<InnerConnectionManager>>,
}

impl std::ops::DerefMut for ConnectionManager {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl std::ops::Deref for ConnectionManager {
    type Target = Arc<Mutex<InnerConnectionManager>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
// TODO: Drop for ConnectionManager. Do we need to drop all the conneciton properly?

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
                                    retransmission: None,
                                    round_trip_time: 1.0,
                                });
                            if let Some(stream) = potential_stream {
                                nonsync.insert(id.local, PotentialConnection::Established(id));
                                vacant.insert(stream);
                            }
                        }
                    }
                }
                let expired = manager
                    .connections
                    .values_mut()
                    .filter(|stream| stream.retransmission.as_ref().is_some_and(|x| x.due()))
                    .map(|stream| {
                        (
                            &mut stream.id,
                            stream.retransmission.as_mut().unwrap(),
                            stream.round_trip_time,
                        )
                    })
                    .chain(
                        manager
                            .nonsync
                            .values_mut()
                            .filter_map(|x| {
                                if let PotentialConnection::None(state) = x {
                                    Some(state)
                                } else {
                                    None
                                }
                            })
                            .filter_map(|state| {
                                if let UnsyncTcpState::SynReceived(_, id, retrans)
                                | UnsyncTcpState::SynSent(_, id, retrans) = state
                                {
                                    if retrans.due() {
                                        return Some((id, retrans, 1.0));
                                    }
                                }
                                None
                            }),
                    );

                let tun = &mut manager.tun;
                for (id, retransmission, rtt) in expired {
                    tun.write_packet(&mut retransmission.packet, id.local.ip, id.remote.ip, 0);
                    retransmission.last_sent = std::time::Instant::now();
                    retransmission.recalculate_srtt(rtt);
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
            let mut manager = self.lock().unwrap();
            manager
                .nonsync
                .insert(address, PotentialConnection::None(UnsyncTcpState::Listen));
        }
        loop {
            let mut manager = self.lock().unwrap();
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
