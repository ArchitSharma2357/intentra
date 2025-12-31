use intentra::transport::Transport;
use parking_lot::Mutex;
use std::sync::Arc;

fn main() -> std::io::Result<()> {
    let delivered = Arc::new(Mutex::new(Vec::new()));

    let mut transport = Transport::bind("127.0.0.1:9000", false)?;
    transport = transport.with_delivery_callback(delivered.clone());

    eprintln!("Transport listening on 127.0.0.1:9000");
    eprintln!("Waiting for packets...");
    eprintln!("Press Ctrl+C to exit");

    transport.run();

    Ok(())
}
