mod tcp;
// Main *logic* thread ?
// Receives messages ?
// Listener thread ? On new connection it sends new TcpStreams
// Reading messages thread ? This would need TcpStreams. It's send/sync. cool
use std::env;
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::mpsc;
use std::{thread, time};
use tcp::*;
use anyhow::Result;

enum UserState {
    WaitingForLogin,
    LoggedIn,
}

struct User {
    id: u32,
    username: String,
    channel: mpsc::Sender<String>,
}

fn start_server(port: u16, mut manager: ConnectionManager) {
    let mut id = 0;
    let (tx_new_conns, rx_new_conns) = mpsc::channel::<(u32, mpsc::Sender<_>)>();
    let (tx_out_msgs, rx_out_msgs) = mpsc::channel::<(u32, String)>();

    thread::spawn(move || {
        // Logic thread
        let mut connections = Vec::new();

        loop {
            use mpsc::TryRecvError::*;
            match rx_new_conns.try_recv() {
                Ok((id, channel)) => {
                    println!("Getting username for new user");
                    channel
                        .send("Please enter your username: ".to_string())
                        .unwrap();
                    connections.push((User {
                        channel,
                        id,
                        username: "unknown".to_string(),
                    }, UserState::WaitingForLogin));
                }
                Err(Disconnected) => panic!("Lost connection to listening thread"),
                Err(Empty) => {}
            }

            for (id, msg) in rx_out_msgs.try_iter() {
                match connections.iter_mut().find(|(u, _)| u.id == id) {
                    Some(ref mut userstate @ &mut (_, UserState::WaitingForLogin)) => {
                        userstate.0.username = msg.trim().to_string(); 
                        userstate.1 = UserState::LoggedIn;
                    },
                    Some(&mut (ref u, UserState::LoggedIn)) => {
                        let mut dead_users = vec![];
                        let message = format!( "[{id}] {}: {msg}", u.username);
                        for (vec_index, (user, _)) in connections.iter().enumerate() {
                            let mut message = message.clone();
                            if user.id == id {
                                message.insert_str(0, "\r\x1b[1A"); 
                            }
                            if user.channel.send(message.clone()).is_err() {
                                dead_users.push(vec_index);
                            }
                        }
                        for (i, to_del) in dead_users.into_iter().enumerate() {
                            // Accounts for removed before elements
                            let index = to_del - i;
                            println!("Deleting user #{} from server list", connections[index].0.id);
                            connections.remove(to_del - i);
                        }
                    },
                    None => println!("User sent data and we lost connection. Oh, well. Skipping"),
                }
            }
            thread::sleep(time::Duration::from_millis(50));
        }
    });

    thread::spawn(move || {
        let mut listener = manager
            .bind(("10.0.0.2", port))
            .expect("Failed to start a listener");
        // Listening thread
        for mut stream in listener.incoming().flatten() {
            let (tx_in_msgs, rx_in_msgs) = mpsc::channel::<String>();
            let outgoing = tx_out_msgs.clone();
            let stream_id = id;
            id += 1;
            thread::spawn(move || {
                // TcpStream thread
                stream.set_nonblocking(true);

                let mut buffer = [0; 1500];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            println!("Lost connection with user #{stream_id}");
                            return;
                        }
                        Ok(n) => outgoing
                            .send((stream_id, String::from_utf8(buffer[..n].into()).unwrap()))
                            .expect("Failed to send data to logic thread"),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            panic!("Error reading from a TcpStream")
                        }
                    }

                    use mpsc::TryRecvError::*;
                    match rx_in_msgs.try_recv() {
                        Ok(msg) => {
                            stream.write_all(msg.as_bytes()).unwrap();
                        }
                        Err(Disconnected) => {
                            panic!("Lost connection to logic thread")
                        }
                        Err(Empty) => {}
                    }
                    thread::sleep(time::Duration::from_millis(100));
                }
            });
            tx_new_conns
                .send((stream_id, tx_in_msgs))
                .expect("Failed to send new connection to logic thread");
            println!("user #{} connected", stream_id);
        }
    });
}

fn main() -> Result<()> {
    let mut args = env::args();
    args.next();
    let manager = ConnectionManager::new("10.0.0.1", "255.255.255.0")?;
    match (args.next().as_deref(), args.next().as_deref()) {
        (Some("server"), Some(port)) if u16::from_str(port).is_ok() => {
            start_server(u16::from_str(port).unwrap(), manager);
            for line in std::io::stdin().lines().flatten() {
                if line.trim() == "quit" {
                    return Ok(());
                }
            }
        }
        _ => {
            println!("Invalid arguments.");
            println!("Example usage:");
            println!("To start a server on port 5000:  `./chat server 5000`");
        }
    }
    Ok(())
}
