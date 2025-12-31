use intentra::transport::Transport;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let mut transport = Transport::bind("127.0.0.1:9001", false)?;

    let metrics = transport.metrics.clone();

    let metrics_thread = thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(10));
        eprintln!("{}", metrics.export_metrics());
    });

    eprintln!("Transport listening on 127.0.0.1:9001");
    eprintln!("Metrics exported every 10 seconds");

    transport.run();

    let _ = metrics_thread.join();
    Ok(())
}
