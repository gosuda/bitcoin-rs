//! P2P listener shutdown integration coverage.
use bitcoin_rs_p2p::listener::serve_with_shutdown;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn serve_with_shutdown_exits_when_flag_set() -> Result<(), Box<dyn Error>> {
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let helper = TcpListener::bind(bind_addr)?;
    let addr = helper.local_addr()?;
    drop(helper);

    let _unused_stream: Option<TcpStream> = None;
    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = serve_with_shutdown(addr, listener_shutdown);
        let _ = tx.send(result);
    });

    thread::sleep(Duration::from_millis(50));
    shutdown.store(true, Ordering::Relaxed);

    let result = rx.recv_timeout(Duration::from_secs(1))?;
    match handle.join() {
        Ok(()) => {}
        Err(_) => return Err(io::Error::other("listener thread panicked").into()),
    }

    result?;
    Ok(())
}
