use crate::packet::*;
use etherparse::TcpHeader;

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

#[derive(Default, Debug)]
pub enum TcpState {
    #[default]
    Listening,
    Connecting(u32),
    BeingConnectedTo(ConnectionState),
    Established(ConnectionState),
}

impl TcpState {
    const RECIEVE_WINDOW_SIZE: u16 = 200;
    pub fn response(&mut self, packet: &TcpPacket) -> Option<TcpPacket> {
        let in_header = &packet.header;
        let mut header = TcpHeader::new(
            in_header.destination_port,
            in_header.source_port,
            0,
            in_header.window_size,
        );

        #[macro_export]
        macro_rules! reset_packet {
            ($sequence_number:expr) => {{
                // println!(
                //     "Invalid packet from {}. Resetting connection",
                //     in_header.source_port
                // );
                // println!("{:?}", in_header);
                header.rst = true;
                header.sequence_number = $sequence_number;
                TcpPacket::from_header(header)
            }};
        }

        match self {
            TcpState::Listening => match (in_header.syn, in_header.ack) {
                (true, false) => {
                    let isn = 0; // TODO: use MD5 on some state. RFC 1948.
                    let new_state = ConnectionState {
                        send: SendConnectionState {
                            unacknowleged: isn,
                            window: in_header.window_size,
                            isn,
                            urgent_pointer: false,
                            next: isn + TcpState::RECIEVE_WINDOW_SIZE as u32,
                        },
                        receive: ReceiveConnectionState {
                            next: in_header.sequence_number + 1,
                            window: TcpState::RECIEVE_WINDOW_SIZE,
                            isn: in_header.sequence_number,
                        },
                    };
                    header.syn = true;
                    header.ack = true;
                    header.sequence_number = new_state.send.unacknowleged;
                    header.acknowledgment_number = new_state.receive.next;
                    *self = TcpState::BeingConnectedTo(new_state);
                    return Some(TcpPacket::from_header(header));
                }
                (_, true) => Some(reset_packet!(in_header.acknowledgment_number)),
                _ => Some(reset_packet!(0)),
            },
            TcpState::BeingConnectedTo(state) => match (
                in_header.rst,
                in_header.syn,
                in_header.ack,
                in_header.acknowledgment_number,
            ) {
                (true, ..) => {
                    println!("Connection is asked to be reset.");
                    *self = TcpState::Listening;
                    None
                }
                (_, false, true, ack) if ack == state.send.unacknowleged + 1 => {
                    println!(
                        "Established connection {} <-> {}",
                        in_header.source_port, in_header.destination_port,
                    );
                    // This requires Copy on state
                    // Most likely it copies data
                    // I wonder if compiler can optimize it out
                    *self = TcpState::Established(*state);
                    None
                }
                (_, _, true, _) => {
                    *self = TcpState::Listening;
                    Some(reset_packet!(in_header.acknowledgment_number))
                }
                _ => {
                    *self = TcpState::Listening;
                    // This should not be zero TODO: RFC 793 p. 36
                    Some(reset_packet!(0))
                }
            },
            TcpState::Established(ConnectionState {
                send,
                ref mut receive,
            }) => {
                if in_header.rst {
                    println!("Connection is asked to be reset.");
                    *self = TcpState::Listening;
                    return None;
                }

                if in_header.fin {
                    unimplemented!();
                }

                let mut segment_len = packet.body.len();
                if in_header.syn {
                    segment_len += 1;
                }
                if in_header.fin {
                    segment_len += 1;
                }

                if !in_header.ack
                    || !is_between_wrapping(
                        send.unacknowleged,
                        in_header.acknowledgment_number,
                        send.next.wrapping_add(1),
                    )
                    || !receive.is_valid_segment(in_header.sequence_number, segment_len)
                {
                    // The packet does not contain proper acknowledgment or segment
                    // Therefore being in synchronized state,
                    // we should send an empty packet containing current state
                    header.sequence_number = send.unacknowleged;
                    header.ack = true;
                    header.acknowledgment_number = receive.next;
                    return Some(TcpPacket::from_header(header));
                }

                let data_start = receive.next.wrapping_sub(in_header.sequence_number);
                let received_data = &packet.body[data_start as usize..];
                println!("Got data! {:x?}", received_data);
                receive.next += received_data.len() as u32;

                header.ack = true;
                header.acknowledgment_number = receive.next;
                header.sequence_number = if send.unacknowleged == send.isn {
                    send.isn + 1
                } else {
                    send.unacknowleged
                };
                Some(TcpPacket::from_header(header))
            }
            TcpState::Connecting(_) => todo!(),
        }
    }
}
