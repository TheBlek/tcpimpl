use anyhow::Result;
use std::io::{Read, Write};
use tcp::*;

mod packet;
mod tcp;
mod address;

fn main() -> Result<()> {
    let mut manager = ConnectionManager::new("10.0.0.1", "255.255.255.0")?;

    let mut handle = manager.accept("10.0.0.2:5000")?;
    // write!(&mut , "Hello World! {}", 55555)?;
    let mut res = String::new();
    let _ = handle.read_to_string(&mut res);
    println!("{}", res);
    // let mut buffer = [0; 1504];
    // let n = handle.read(&mut buffer)?;
    // println!("Got bytes: {:?}", &buffer[..n]);

    Ok(())
}
