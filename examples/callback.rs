use intentra::transport::Transport;
use parking_lot::Mutex;
use std::sync::Arc;

fn main() -> std::io::Result<()> {
    let delivered_packets = Arc::new(Mutex::new(Vec::new()));
    let delivered_clone = delivered_packets.clone();

    let mut transport = Transport::bind("127.0.0.1:9002", false)?;
    transport = transport.with_delivery_callback(delivered_clone);

    eprintln!("Transport listening on 127.0.0.1:9002");
    eprintln!("Packet delivery callback enabled");

    transport.run();

    Ok(())
}
