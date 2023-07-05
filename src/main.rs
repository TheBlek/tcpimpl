use anyhow::Result;
use std::io::{Read, Write};
use tcp::*;

mod packet;
mod tcp;
mod address;

fn main() -> Result<()> {
    let mut manager = ConnectionManager::new("10.0.0.1", "255.255.255.0")?;

    let mut stream = manager.accept("10.0.0.2:5000");
    write!(&mut stream, "Hello World! {}", 55555)?;
    let mut res = String::new();
    let _ = stream.read_to_string(&mut res);
    // let mut buffer = [0; 1504];
    // let n = stream.read(&mut buffer)?;
    println!("{}", res);

    Ok(())
}
