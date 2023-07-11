use super::packet::TcpPacket;
use crate::tcp::*;

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
    fn new(isn: u32) -> Self {
        Self {
            next: isn.wrapping_add(1),
            isn,
            window: UnsyncTcpState::RECIEVE_WINDOW_SIZE,
        }
    }

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
    fn new(isn: u32, window_size: u16) -> Self {
        SendConnectionState {
            unacknowleged: isn,
            window: window_size,
            isn,
            urgent_pointer: false,
            next: isn.wrapping_add(window_size as u32),
        }
    }

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
pub enum SyncTcpState {
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
    pub fn can_receive(&self) -> bool {
        !matches!(
            self,
            SyncTcpState::CloseWait | SyncTcpState::Closed | SyncTcpState::LastAck
        )
    }

    pub fn can_send(&self) -> bool {
        !matches!(
            self,
            SyncTcpState::FinWait1
                | SyncTcpState::Closed
                | SyncTcpState::FinWait2
                | SyncTcpState::Closing
        )
    }
}

pub(super) enum UnsyncTcpState {
    Listen,
    SynReceived(ConnectionState, ConnectionId, Retransmission),
    SynSent(u32, ConnectionId, Retransmission),
}

impl UnsyncTcpState {
    pub(super) const RECIEVE_WINDOW_SIZE: u16 = 200;

    pub(super) fn on_packet(
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
                        send: SendConnectionState::new(isn, in_header.window_size),
                        receive: ReceiveConnectionState::new(in_header.sequence_number),
                    };
                    let packet = packet.respond(
                        Self::RECIEVE_WINDOW_SIZE,
                        PacketResponse::SynAck(
                            new_state.send.unacknowleged,
                            new_state.receive.next,
                        ),
                        &[],
                    );
                    let retransmit = Retransmission::from_packet(packet.clone());
                    *self = UnsyncTcpState::SynReceived(new_state, id.clone(), retransmit);
                    Some(packet)
                }
                (_, ack) => {
                    let seq = if ack {
                        in_header.acknowledgment_number
                    } else {
                        0
                    };
                    Some(packet.respond(Self::RECIEVE_WINDOW_SIZE, PacketResponse::Reset(seq), &[]))
                }
            },
            UnsyncTcpState::SynReceived(mut connection_state, ..) => match (
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
            UnsyncTcpState::SynSent(isn, id, retransmission) => match (
                in_header.rst,
                in_header.syn,
                in_header.ack,
                in_header.acknowledgment_number,
            ) {
                (true, ..) => {
                    *self = UnsyncTcpState::Listen;
                    None
                }
                (_, true, ack, ack_num) => {
                    let new_state = ConnectionState {
                        send: SendConnectionState::new(*isn, in_header.window_size),
                        receive: ReceiveConnectionState::new(in_header.sequence_number),
                    };
                    let mut packet = TcpPacket::from_header(TcpHeader::new(
                        id.local.port,
                        id.remote.port,
                        new_state.send.unacknowleged,
                        UnsyncTcpState::RECIEVE_WINDOW_SIZE,
                    ));
                    packet.header.ack = true;
                    packet.header.acknowledgment_number = new_state.receive.next;

                    tun.write_packet(&mut packet, id);

                    if ack && ack_num == isn.wrapping_add(1) {
                        return Some(new_state);
                    }

                    *self = UnsyncTcpState::SynReceived(
                        new_state,
                        id.clone(), // TODO: This clone *theoretically* can be avoided
                        Retransmission::from_packet(packet.clone()),
                    );
                    None
                }
                (_, _, ack, _) => {
                    *self = UnsyncTcpState::Listen;
                    let seq = if ack {
                        in_header.acknowledgment_number
                    } else {
                        0
                    };
                    let window = in_header.window_size;
                    Some(packet.respond(window, PacketResponse::Reset(seq), &[]))
                }
            },
        };

        if let Some(mut response_packet) = response {
            tun.write_packet(&mut response_packet, id);
        }

        None
    }
}
