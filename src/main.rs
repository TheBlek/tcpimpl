use anyhow::Result;
use std::io::{Read, Write};
use tcp::*;
mod tcp;

fn main() -> Result<()> {
    let mut manager = ConnectionManager::new("10.0.0.1", "255.255.255.0")?;

    // TODO: separate API of listening on a port into 2 calls:
    // .bind -> TcpListener
    // .accept -> TcpStreamHandle
    let mut handle = manager.accept("10.0.0.2:5000")?;
    let mut handle2 = manager.accept("10.0.0.2:5200")?;
    write!(handle, "Helloalasdjfalksjdf World! {}", 55555)?;
    write!(handle, "Hlskdfaelloalksjdf World! {}", 55555)?;
    let mut res = String::new();
    let _ = handle2.read_to_string(&mut res);
    println!("Got from 5200: {}", res);

    let mut res = String::new();
    let _ = handle.read_to_string(&mut res);
    println!("Got from 5000: {}", res);
    // let mut buffer = [0; 1504];
    // let n = handle.read(&mut buffer)?;
    // println!("Got bytes: {:?}", &buffer[..n]);

    Ok(())
}
