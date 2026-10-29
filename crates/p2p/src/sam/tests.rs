use super::*;
use std::io::BufRead as _;
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;

#[derive(Default)]
struct LiveWorkers {
    count: Mutex<usize>,
    idle: parking_lot::Condvar,
}

struct WorkerExit(std::sync::Arc<LiveWorkers>);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        let mut count = self.0.count.lock();
        *count -= 1;
        if *count == 0 {
            self.0.idle.notify_all();
        }
    }
}

struct FakeSam {
    addr: SocketAddr,
    commands: mpsc::Receiver<String>,
    root_closed: mpsc::Receiver<()>,
    stop: std::sync::Arc<AtomicBool>,
    listener_handle: Option<std::thread::JoinHandle<io::Result<()>>>,
    workers: std::sync::Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<io::Result<()>>>>>,
    live: std::sync::Arc<LiveWorkers>,
    strangers: mpsc::Receiver<SocketAddr>,
    accepted: mpsc::Receiver<SocketAddr>,
}

impl FakeSam {
    fn wait_idle(&self, within: Duration) -> io::Result<()> {
        let give_up = Instant::now() + within;
        let mut count = self.live.count.lock();
        while *count != 0 {
            if self.live.idle.wait_until(&mut count, give_up).timed_out() && *count != 0 {
                let remaining = *count;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{remaining} fake SAM worker(s) still serving after {within:?}"),
                ));
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        let mut first_error: Option<io::Error> = None;
        if let Some(handle) = self.listener_handle.take() {
            self.stop.store(true, Ordering::Release);
            let _ = std::net::TcpStream::connect(self.addr);
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        let workers = std::mem::take(&mut *self.workers.lock());
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(())
    }
}

impl Drop for FakeSam {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[derive(Clone, Default)]
struct FakeSamOptions {
    accept_line: Option<String>,
    lose_root_after_first_me: bool,
    stall_stream_connect: Option<Duration>,
    truncate_stream_reply: bool,
    gate_invalid_stream: Option<(&'static str, GateHandle)>,
    kill_root: Option<std::sync::Arc<AtomicBool>>,
    held_reply: Option<HeldReply>,
    fail_creates: usize,
    creates: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Clone)]
struct HeldReply {
    prefix: &'static str,
    nth: usize,
    head: usize,
    gate: GateHandle,
    seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl HeldReply {
    fn new(prefix: &'static str, nth: usize, head: usize, gate: &GateHandle) -> Self {
        Self {
            prefix,
            nth,
            head,
            gate: std::sync::Arc::clone(gate),
            seen: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

enum GateWait {
    Opened,
    Stopped,
    HungUp,
}

fn client_hung_up(socket: &TcpStream) -> bool {
    if socket.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0u8; 1];
    let hung_up = match socket.peek(&mut byte) {
        Ok(read) => read == 0,
        Err(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
        ),
    };
    let _ = socket.set_nonblocking(false);
    hung_up
}

fn wait_for_gate(gate: &GateHandle, stop: &AtomicBool, socket: &TcpStream) -> GateWait {
    let (open, condvar) = &**gate;
    let mut opened = open.lock();
    while !*opened {
        if stop.load(Ordering::Acquire) {
            return GateWait::Stopped;
        }
        if client_hung_up(socket) {
            return GateWait::HungUp;
        }
        let _ = condvar.wait_for(&mut opened, Duration::from_millis(50));
    }
    GateWait::Opened
}

type GateHandle = std::sync::Arc<(Mutex<bool>, parking_lot::Condvar)>;

fn new_gate() -> GateHandle {
    std::sync::Arc::new((Mutex::new(false), parking_lot::Condvar::new()))
}

fn open_gate(gate: &GateHandle) {
    let (open, condvar) = &**gate;
    *open.lock() = true;
    condvar.notify_all();
}

struct ReleaseOnDrop(GateHandle);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        open_gate(&self.0);
    }
}

fn answer_gated_invalid_id(
    options: &FakeSamOptions,
    line: &str,
    writer: &mut TcpStream,
    stop: &AtomicBool,
) -> io::Result<bool> {
    let Some((prefix, gate)) = &options.gate_invalid_stream else {
        return Ok(false);
    };
    if !line.starts_with(*prefix) {
        return Ok(false);
    }
    let (open, condvar) = &**gate;
    let mut opened = open.lock();
    while !*opened {
        if stop.load(Ordering::Acquire) {
            return Ok(true);
        }
        let _ = condvar.wait_for(&mut opened, Duration::from_millis(50));
    }
    drop(opened);
    match writer.write_all(b"STREAM STATUS RESULT=INVALID_ID\n") {
        Err(error) if !stop.load(Ordering::Acquire) => Err(error),
        _ => Ok(true),
    }
}

fn root_kill_requested(options: &FakeSamOptions) -> bool {
    options
        .kill_root
        .as_ref()
        .is_some_and(|kill| kill.swap(false, Ordering::SeqCst))
}

fn close_root(writer: TcpStream, reader: BufReader<TcpStream>, closed_tx: &mpsc::Sender<()>) {
    let _ = writer.shutdown(std::net::Shutdown::Both);
    drop(writer);
    drop(reader);
    let _ = closed_tx.send(());
}

fn worker_failure(site: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("fake SAM worker {site}: {error}"))
}

fn fake_sam(script: Vec<(String, String)>) -> io::Result<FakeSam> {
    fake_sam_with(script, FakeSamOptions::default())
}

fn handle_stream_command(
    line: &str,
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    script: &[(String, String)],
    options: &FakeSamOptions,
    stop: &AtomicBool,
) -> io::Result<()> {
    let (_, reply) = script
        .iter()
        .find(|(p, _)| line.starts_with(p))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "scripted stream reply missing"))?;
    if let Some(stall) = options.stall_stream_connect {
        let until = Instant::now() + stall;
        while Instant::now() < until && !stop.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
    }
    if answer_gated_invalid_id(options, line, writer, stop)? {
        return Ok(());
    }
    if options.truncate_stream_reply && line.starts_with("STREAM CONNECT") {
        let unterminated = reply.trim_end_matches(['\r', '\n']);
        writer.write_all(unterminated.as_bytes())?;
        writer.shutdown(std::net::Shutdown::Both)?;
        return Ok(());
    }
    if let Err(error) = writer.write_all(reply.as_bytes()) {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        return Err(worker_failure(
            &format!("writing the reply to `{line}`"),
            &error,
        ));
    }
    if line.starts_with("STREAM ACCEPT") {
        let accept_line = options
            .accept_line
            .clone()
            .unwrap_or_else(|| format!("{} FROM_PORT=1 TO_PORT=8333\n", dest_b64()));
        if let Err(error) = writer.write_all(accept_line.as_bytes()) {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            return Err(worker_failure(
                &format!("writing the accept line for `{line}`"),
                &error,
            ));
        }
    }
    let mut byte = [0u8; 1];
    if !stop.load(Ordering::Acquire) {
        match reader.read_exact(&mut byte) {
            Ok(()) => {
                if let Err(error) = writer.write_all(&byte) {
                    if stop.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    return Err(worker_failure(
                        &format!("echoing the bridged byte for `{line}`"),
                        &error,
                    ));
                }
            }
            Err(err)
                if stop.load(Ordering::Acquire)
                    || matches!(
                        err.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
                    ) => {}
            Err(err) => {
                return Err(worker_failure(
                    &format!("reading the bridged byte for `{line}`"),
                    &err,
                ));
            }
        }
    }
    Ok(())
}

fn write_scripted_reply(
    line: &str,
    script: &[(String, String)],
    options: &FakeSamOptions,
    writer: &mut TcpStream,
    closed_tx: &mpsc::Sender<()>,
    stop: &AtomicBool,
) -> io::Result<bool> {
    let scripted = script
        .iter()
        .find(|(p, _)| line.starts_with(p))
        .map_or("SESSION STATUS RESULT=I2P_ERROR\n", |(_, r)| r.as_str());
    let refused = line.starts_with("SESSION CREATE")
        && options.creates.fetch_add(1, Ordering::SeqCst) < options.fail_creates;
    let reply = if refused {
        "SESSION STATUS RESULT=I2P_ERROR\n"
    } else {
        scripted
    };
    let held = options.held_reply.as_ref().filter(|held| {
        line.starts_with(held.prefix) && held.seen.fetch_add(1, Ordering::SeqCst) == held.nth
    });
    let (head, tail) = reply
        .as_bytes()
        .split_at(held.map_or(reply.len(), |held| held.head.min(reply.len())));
    if let Err(error) = writer.write_all(head) {
        if stop.load(Ordering::Acquire) {
            return Ok(true);
        }
        return Err(worker_failure(
            &format!("writing the reply to `{line}`"),
            &error,
        ));
    }
    let Some(held) = held else {
        return Ok(false);
    };
    match wait_for_gate(&held.gate, stop, writer) {
        GateWait::Opened => {}
        GateWait::Stopped => return Ok(true),
        GateWait::HungUp => {
            let _ = closed_tx.send(());
            return Ok(true);
        }
    }
    match writer.write_all(tail) {
        Ok(()) => Ok(false),
        Err(_) if stop.load(Ordering::Acquire) => Ok(true),
        Err(error) => Err(worker_failure(
            &format!("writing the held reply to `{line}`"),
            &error,
        )),
    }
}

#[derive(Clone, Copy)]
struct Peer {
    client: SocketAddr,
    bridge: SocketAddr,
}

impl Peer {
    fn opened_by_a_session(self) -> bool {
        SESSION_SOCKETS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&(self.client, self.bridge))
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_fake_sam_stream(
    stream: TcpStream,
    peer: Peer,
    tx: &mpsc::Sender<String>,
    closed_tx: &mpsc::Sender<()>,
    script: &[(String, String)],
    options: &FakeSamOptions,
    root_lost: &AtomicBool,
    stop: &AtomicBool,
    strangers: &mpsc::Sender<SocketAddr>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    let client = peer.client;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut pending: Vec<u8> = Vec::new();
    let mut is_root = false;
    let mut last_command = String::new();
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        if is_root && root_kill_requested(options) {
            close_root(writer, reader, closed_tx);
            return Ok(());
        }
        match reader.read_until(b'\n', &mut pending) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if stop.load(Ordering::Acquire) {
                    return Ok(());
                }
                continue;
            }
            Err(error) => {
                if stop.load(Ordering::Acquire) {
                    return Ok(());
                }
                if last_command.is_empty() && !peer.opened_by_a_session() {
                    let _ = strangers.send(client);
                    return Ok(());
                }
                let kind = if is_root {
                    "the root connection"
                } else {
                    "a bridge connection"
                };
                let after = if last_command.is_empty() {
                    "before any command".to_owned()
                } else {
                    format!("after `{last_command}`")
                };
                return Err(worker_failure(
                    &format!(
                        "reading a command on {kind} from {client} {after} \
                             with {} unterminated byte(s)",
                        pending.len()
                    ),
                    &error,
                ));
            }
        }
        if pending.last() != Some(&b'\n') {
            continue;
        }
        if last_command.is_empty() && !peer.opened_by_a_session() {
            let _ = strangers.send(client);
            return Ok(());
        }
        let line = String::from_utf8_lossy(&pending).trim_end().to_owned();
        pending.clear();
        let _ = tx.send(line.clone());
        last_command.clone_from(&line);
        is_root |= line.starts_with("SESSION CREATE");
        if line.starts_with("STREAM CONNECT") || line.starts_with("STREAM ACCEPT") {
            return handle_stream_command(&line, &mut writer, &mut reader, script, options, stop);
        }
        if write_scripted_reply(&line, script, options, &mut writer, closed_tx, stop)? {
            return Ok(());
        }
        if options.lose_root_after_first_me
            && line.starts_with("NAMING LOOKUP NAME=ME")
            && !root_lost.swap(true, Ordering::SeqCst)
        {
            let _ = writer.shutdown(std::net::Shutdown::Both);
            drop(writer);
            drop(reader);
            let _ = closed_tx.send(());
            return Ok(());
        }
    }
}

fn fake_sam_with(script: Vec<(String, String)>, options: FakeSamOptions) -> io::Result<FakeSam> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel();
    let (closed_tx, closed_rx) = mpsc::channel();
    let options = std::sync::Arc::new(options);
    let root_lost = std::sync::Arc::new(AtomicBool::new(false));
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let stop_listener = std::sync::Arc::clone(&stop);
    let stop_worker = std::sync::Arc::clone(&stop);
    let workers = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let workers_listener = std::sync::Arc::clone(&workers);
    let live = std::sync::Arc::new(LiveWorkers::default());
    let live_listener = std::sync::Arc::clone(&live);
    let (strangers_tx, strangers) = mpsc::channel();
    let (accepted_tx, accepted) = mpsc::channel();
    let listener_handle = std::thread::spawn(move || -> io::Result<()> {
        loop {
            let accepted = listener.accept();
            if stop_listener.load(Ordering::Acquire) {
                break;
            }
            let (stream, client) = match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    if stop_listener.load(Ordering::Acquire) {
                        break;
                    }
                    return Err(err);
                }
            };
            if stop_listener.load(Ordering::Acquire) {
                break;
            }
            let tx = tx.clone();
            let closed_tx = closed_tx.clone();
            let script = script.clone();
            let options = std::sync::Arc::clone(&options);
            let root_lost = std::sync::Arc::clone(&root_lost);
            let stop = std::sync::Arc::clone(&stop_worker);
            let live_worker = std::sync::Arc::clone(&live_listener);
            let strangers = strangers_tx.clone();
            *live_listener.count.lock() += 1;
            let _ = accepted_tx.send(client);
            let handle = std::thread::spawn(move || {
                let _exit = WorkerExit(live_worker);
                let peer = Peer {
                    client,
                    bridge: addr,
                };
                handle_fake_sam_stream(
                    stream, peer, &tx, &closed_tx, &script, &options, &root_lost, &stop, &strangers,
                )
            });
            workers_listener.lock().push(handle);
        }
        Ok(())
    });

    Ok(FakeSam {
        addr,
        commands: rx,
        root_closed: closed_rx,
        stop,
        listener_handle: Some(listener_handle),
        workers,
        live,
        strangers,
        accepted,
    })
}

const HELLO_OK: &str = "HELLO REPLY RESULT=OK VERSION=3.3\n";

fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let acc =
            chunk.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        let chars = [acc >> 18, acc >> 12, acc >> 6, acc].map(|v| {
            let idx = usize::try_from(v & 63).unwrap_or_default();
            char::from(ALPHABET[idx])
        });
        out.extend(chars.iter().take(chunk.len() + 1));
        out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
    }
    out
}

fn dest_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 384];
    bytes.extend_from_slice(&[5, 0, 4, 0, 7, 0, 4]);
    bytes
}

fn dest_b64() -> String {
    b64_encode(&dest_bytes())
}

fn priv_b64() -> String {
    let mut bytes = dest_bytes();
    bytes.extend_from_slice(&[2u8; 64]);
    b64_encode(&bytes)
}

fn session_script() -> Vec<(String, String)> {
    let dest = dest_b64();
    vec![
        ("HELLO".to_owned(), HELLO_OK.to_owned()),
        (
            "SESSION CREATE".to_owned(),
            format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
        ),
        (
            "NAMING LOOKUP".to_owned(),
            format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
        ),
        (
            "STREAM CONNECT".to_owned(),
            "STREAM STATUS RESULT=OK\n".to_owned(),
        ),
        (
            "STREAM ACCEPT".to_owned(),
            "STREAM STATUS RESULT=OK\n".to_owned(),
        ),
        (
            "DEST GENERATE SIGNATURE_TYPE=7".to_owned(),
            format!("DEST REPLY PUB={dest} PRIV={}\n", priv_b64()),
        ),
    ]
}

#[test]
fn base64_strict_canonicality() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(i2p_base64_decode("AA=garbage"), None);
    assert_eq!(i2p_base64_decode("AB"), None);
    assert_eq!(i2p_base64_decode("AAB="), None);
    assert_eq!(i2p_base64_decode("AA==AA"), None);
    assert_eq!(i2p_base64_decode("AA=A"), None);
    assert_eq!(i2p_base64_decode("A!AA"), None);
    assert_eq!(i2p_base64_decode("AA AA"), None);
    assert_eq!(i2p_base64_decode("AA\nAA"), None);
    assert_eq!(i2p_base64_decode("A"), None);
    assert_eq!(i2p_base64_decode("AAA=="), None);
    assert_eq!(i2p_base64_decode(""), None);
    assert_eq!(i2p_base64_decode("AQID"), Some(vec![1, 2, 3]));
    assert_eq!(i2p_base64_decode("AQIDBA=="), Some(vec![1, 2, 3, 4]));
    assert_eq!(i2p_base64_decode("AQI="), Some(vec![1, 2]));
    assert_eq!(i2p_base64_decode("AQ=="), Some(vec![1]));
    let expected: [u8; 32] = Sha256::digest([1u8, 2, 3]).into();
    let decoded = i2p_base64_decode("AQID")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "valid destination"))?;
    assert_eq!(destination_hash(&decoded), expected);
    assert!(valid_destination(&dest_bytes()));
    assert!(!valid_destination(&dest_bytes()[..390]));
    let mut trailing = dest_bytes();
    trailing.push(0);
    assert!(!valid_destination(&trailing));
    let mut bad_cert = dest_bytes();
    bad_cert[384] = 9;
    assert!(!valid_destination(&bad_cert));
    assert!(!valid_destination(&[0u8; 32]));
    Ok(())
}

#[test]
fn session_id_is_derived_per_destination() {
    assert_ne!(session_id_for(&dest_b64()), session_id_for(&priv_b64()));
    assert!(session_id_for(&dest_b64()).starts_with("btcrs-"));
    assert_eq!(session_id_for(&dest_b64()), session_id_for(&dest_b64()));
}

#[test]
fn session_negotiates_33_and_stream_connect_uses_fresh_bridge()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(session_script())?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
    assert_eq!(session.destination(), dest_b64());
    let mut stream = session
        .connect(destination_hash(&dest_bytes()), 8333)
        .map_err(crate::endpoint::DialFailure::into_io)?;
    stream.write_all(b"x")?;
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte)?;
    assert_eq!(byte, *b"x");
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert_eq!(commands[0], "HELLO VERSION MIN=3.1 MAX=3.3");
    assert!(commands[1].starts_with(&format!(
        "SESSION CREATE STYLE=STREAM ID={} DESTINATION=",
        session.id()
    )));
    assert!(session.id().starts_with("btcrs-"));
    assert_eq!(commands[2], "NAMING LOOKUP NAME=ME");
    assert!(
        commands
            .iter()
            .any(|c| c.starts_with("NAMING LOOKUP NAME=") && c.ends_with(".b32.i2p"))
    );
    assert!(
        commands
            .iter()
            .any(|c| c.starts_with(&format!("STREAM CONNECT ID={} DESTINATION=", session.id())))
    );
    assert_eq!(
        commands
            .iter()
            .filter(|c| c.starts_with("SESSION CREATE"))
            .count(),
        1,
        "a healthy root is never replaced: only the stream uses a fresh bridge"
    );
    fake.finish()?;
    Ok(())
}

#[test]
fn hello_requiring_below_33_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(vec![(
        "HELLO".to_owned(),
        "HELLO REPLY RESULT=OK VERSION=3.1\n".to_owned(),
    )])?;
    let Err(error) = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5)) else {
        panic!("3.1 must not satisfy the 3.3 requirement");
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    fake.finish()?;
    Ok(())
}

#[test]
fn accept_hashes_remote_destination() -> Result<(), Box<dyn std::error::Error>> {
    let mut remote_bytes = dest_bytes();
    remote_bytes[0] = 0x42;
    let remote_dest = b64_encode(&remote_bytes);
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            accept_line: Some(format!("{remote_dest} FROM_PORT=1 TO_PORT=8333\n")),
            ..FakeSamOptions::default()
        },
    )?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
    let (_stream, hash, port) = session.accept(Duration::from_secs(5), 9999)?;
    assert_eq!(hash, destination_hash(&remote_bytes));
    assert_ne!(
        hash,
        destination_hash(&dest_bytes()),
        "remote hash must differ from our own"
    );
    assert_eq!(port, 8333);
    fake.finish()?;
    Ok(())
}

#[test]
fn key_file_create_reuse_and_corrupt_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("sam-key-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("i2p_private_key");
    let mut fake = fake_sam(session_script())?;
    let first = load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))?;
    assert_eq!(first, priv_b64());
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let second = load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))?;
    assert_eq!(first, second);
    #[cfg(unix)]
    {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let third = load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))?;
        assert_eq!(first, third);
        let mode = std::fs::metadata(&path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "reused key file mode is repaired");
    }
    std::fs::write(&path, "not a destination!!")?;
    let Err(error) = load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))
    else {
        panic!("corrupt key must fail closed");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(std::fs::read(&path)?, b"not a destination!!");
    let _ = std::fs::remove_dir_all(&dir);
    fake.finish()?;
    Ok(())
}

#[test]
fn generate_destination_requests_ed25519_and_accepts_the_standard_reply()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(session_script())?;
    let (public, private) = generate_destination(fake.addr, Duration::from_secs(5))?;
    assert_eq!(public, dest_b64());
    assert_eq!(private, priv_b64());
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert_eq!(
        commands,
        [
            "HELLO VERSION MIN=3.1 MAX=3.3",
            "DEST GENERATE SIGNATURE_TYPE=7"
        ]
    );
    fake.finish()?;

    let mut script = session_script();
    script.retain(|(prefix, _)| !prefix.starts_with("DEST GENERATE"));
    script.push((
        "DEST GENERATE SIGNATURE_TYPE=7".to_owned(),
        format!(
            "DEST REPLY RESULT=OK PUB={} PRIV={}\n",
            dest_b64(),
            priv_b64()
        ),
    ));
    let mut fake = fake_sam(script)?;
    let (public, private) = generate_destination(fake.addr, Duration::from_secs(5))?;
    assert_eq!(public, dest_b64());
    assert_eq!(private, priv_b64());
    fake.finish()?;
    Ok(())
}

struct BadDestReply {
    label: &'static str,
    reply: String,
    kind: io::ErrorKind,
    fragment: &'static str,
}

fn result_bearing_dest_replies() -> Vec<BadDestReply> {
    let dest = dest_b64();
    let key = priv_b64();
    let case = |label, reply: String, fragment| BadDestReply {
        label,
        reply,
        kind: io::ErrorKind::ConnectionAborted,
        fragment,
    };
    vec![
        case(
            "explicit error",
            "DEST REPLY RESULT=I2P_ERROR MESSAGE=UNSUPPORTED_SIGNATURE_TYPE\n".to_owned(),
            "DEST REPLY RESULT=I2P_ERROR",
        ),
        case(
            "error contradicting its keys",
            format!("DEST REPLY RESULT=I2P_ERROR PUB={dest} PRIV={key}\n"),
            "DEST REPLY RESULT=I2P_ERROR",
        ),
        case(
            "private key in the result field",
            format!("DEST REPLY RESULT={key}\n"),
            "DEST REPLY RESULT=UNKNOWN",
        ),
    ]
}

fn malformed_dest_replies() -> Vec<BadDestReply> {
    let dest = dest_b64();
    let key = priv_b64();
    let case = |label, reply: String, fragment| BadDestReply {
        label,
        reply,
        kind: io::ErrorKind::InvalidData,
        fragment,
    };
    vec![
        case(
            "missing public destination",
            format!("DEST REPLY PRIV={key}\n"),
            "no public destination",
        ),
        case(
            "missing private destination",
            format!("DEST REPLY PUB={dest}\n"),
            "no private destination",
        ),
        case(
            "public key is not a destination",
            format!("DEST REPLY PUB=AAAA PRIV={key}\n"),
            "generated public destination is not a valid destination",
        ),
        case(
            "private key is not base64",
            format!("DEST REPLY PUB={dest} PRIV={key}!\n"),
            "corrupt base64",
        ),
        case(
            "private key lacks its secret bytes",
            format!("DEST REPLY PUB={dest} PRIV={dest}\n"),
            "truncated",
        ),
        case(
            "ok status does not rescue an unusable key",
            format!("DEST REPLY RESULT=OK PUB={dest} PRIV={dest}\n"),
            "truncated",
        ),
    ]
}

#[test]
fn bad_dest_replies_persist_no_key_and_reflect_no_key_material()
-> Result<(), Box<dyn std::error::Error>> {
    let dest = dest_b64();
    let key = priv_b64();
    let cases = result_bearing_dest_replies()
        .into_iter()
        .chain(malformed_dest_replies());
    for BadDestReply {
        label,
        reply,
        kind,
        fragment,
    } in cases
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("i2p_private_key");
        let mut fake = fake_sam(vec![
            ("HELLO".to_owned(), HELLO_OK.to_owned()),
            ("DEST GENERATE SIGNATURE_TYPE=7".to_owned(), reply),
        ])?;
        let Err(error) =
            load_or_create_private_destination(fake.addr, &path, Duration::from_secs(5))
        else {
            panic!("{label}: a refused DEST REPLY must not yield a key");
        };
        let text = error.to_string();
        assert_eq!(error.kind(), kind, "{label}: {text}");
        assert!(text.contains(fragment), "{label}: {text}");
        for secret in [&key, &dest] {
            assert!(
                !text.contains(secret.as_str()),
                "{label}: the error reflects reply material"
            );
        }
        assert!(!path.exists(), "{label}: no key file may be created");
        assert_eq!(
            std::fs::read_dir(dir.path())?.count(),
            0,
            "{label}: no temporary key file may remain"
        );
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(
            commands,
            [
                "HELLO VERSION MIN=3.1 MAX=3.3",
                "DEST GENERATE SIGNATURE_TYPE=7"
            ],
            "{label}"
        );
        fake.finish()?;
    }
    Ok(())
}

#[test]
fn missing_result_is_success_only_for_dest_reply() -> Result<(), Box<dyn std::error::Error>> {
    for (reply, prefix) in [
        ("SESSION STATUS DESTINATION=x", "SESSION STATUS"),
        ("NAMING REPLY NAME=ME VALUE=x", "NAMING REPLY"),
        ("STREAM STATUS", "STREAM STATUS"),
    ] {
        let Err(error) = require_ok(reply, prefix) else {
            panic!("`{prefix}` without RESULT must not succeed");
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
    let mut fake = fake_sam(vec![(
        "HELLO".to_owned(),
        "HELLO REPLY VERSION=3.3\n".to_owned(),
    )])?;
    let Err(error) = generate_destination(fake.addr, Duration::from_secs(5)) else {
        panic!("a HELLO reply without RESULT must not succeed");
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    fake.finish()?;
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert_eq!(commands, ["HELLO VERSION MIN=3.1 MAX=3.3"]);
    Ok(())
}

#[cfg(unix)]
const KEY_FIXTURE: &str = "unrelated-owned-fixture-token\n";

#[cfg(unix)]
#[test]
fn key_reader_refuses_a_symlink_and_leaves_its_target_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("unrelated");
    std::fs::write(&target, KEY_FIXTURE)?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))?;
    let link = dir.path().join("i2p_private_key");
    std::os::unix::fs::symlink(&target, &link)?;

    let Err(error) = read_key_file(&link) else {
        panic!("a symlinked key path must be refused");
    };
    assert_ne!(
        error.kind(),
        io::ErrorKind::NotFound,
        "a link is never an absent key"
    );

    assert_eq!(std::fs::read(&target)?, KEY_FIXTURE.as_bytes());
    assert_eq!(
        std::fs::metadata(&target)?.permissions().mode() & 0o777,
        0o644,
        "the link target's mode must not be repaired"
    );
    assert!(std::fs::symlink_metadata(&link)?.file_type().is_symlink());
    assert_eq!(std::fs::read_link(&link)?, target);
    Ok(())
}

#[cfg(unix)]
#[test]
fn dangling_key_symlink_is_refused_and_never_selects_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing-target");
    let link = dir.path().join("i2p_private_key");
    std::os::unix::fs::symlink(&missing, &link)?;
    let mut fake = fake_sam(session_script())?;

    let Err(error) = load_or_create_private_destination(fake.addr, &link, Duration::from_secs(5))
    else {
        panic!("a dangling key symlink must be refused");
    };
    assert_ne!(
        error.kind(),
        io::ErrorKind::NotFound,
        "a dangling link is not an absent key"
    );
    fake.finish()?;
    assert!(
        fake.commands.try_recv().is_err(),
        "a refused key path must not reach the SAM bridge"
    );
    assert!(!missing.exists(), "the link target must not be created");
    assert_eq!(std::fs::read_link(&link)?, missing);
    Ok(())
}

#[cfg(unix)]
#[test]
fn key_reader_refuses_a_directory_without_changing_its_mode()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("onion_v3_private_key");
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;

    let Err(error) = read_key_file(&path) else {
        panic!("a directory key path must be refused");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o755,
        "a refused directory must not be chmodded"
    );
    Ok(())
}

#[cfg(all(
    unix,
    not(any(
        target_vendor = "apple",
        target_os = "espidf",
        target_os = "horizon",
        target_os = "vita",
        target_os = "wasi",
        target_os = "redox",
    ))
))]
#[test]
fn key_reader_refuses_a_fifo_without_blocking_or_chmod() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("i2p_private_key");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(io::Error::from)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;

    let (done_tx, done_rx) = mpsc::channel();
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || {
        let _ = done_tx.send(read_key_file(&reader_path));
    });
    let outcome = done_rx.recv_timeout(Duration::from_secs(5));
    if outcome.is_err() {
        let _ = rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        );
    }
    reader
        .join()
        .map_err(|_| "the FIFO key reader thread panicked")?;
    let result = outcome.map_err(|_| "reading a FIFO key path blocked")?;

    let Err(error) = result else {
        panic!("a FIFO key path must be refused");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o640,
        "a refused FIFO must not be chmodded"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn key_reader_follows_a_symlinked_parent_and_repairs_the_mode_in_place()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let real = dir.path().join("real");
    std::fs::create_dir(&real)?;
    let key = real.join("onion_v3_private_key");
    std::fs::write(&key, KEY_FIXTURE)?;
    let linked = dir.path().join("datadir");
    std::os::unix::fs::symlink(&real, &linked)?;

    for loose in [0o644, 0o400] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(loose))?;
        let text = read_key_file(&linked.join("onion_v3_private_key"))?;
        assert_eq!(text, KEY_FIXTURE.trim());
        assert_eq!(
            std::fs::metadata(&key)?.permissions().mode() & 0o777,
            0o600,
            "mode {loose:o} is repaired through the opened handle"
        );
    }
    assert_eq!(std::fs::read(&key)?, KEY_FIXTURE.as_bytes());
    Ok(())
}

#[test]
fn cant_reach_peer_and_timeout_are_peer_unreachable() -> Result<(), Box<dyn std::error::Error>> {
    for result in ["CANT_REACH_PEER", "TIMEOUT"] {
        let reply = format!("STREAM STATUS RESULT={result}\n");
        let dest = dest_b64();
        let script: Vec<(String, String)> = vec![
            ("HELLO".to_owned(), HELLO_OK.to_owned()),
            (
                "SESSION CREATE".to_owned(),
                format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
            ),
            (
                "NAMING LOOKUP".to_owned(),
                format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
            ),
            ("STREAM CONNECT".to_owned(), reply),
        ];
        let mut fake = fake_sam(script)?;
        let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
        let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
            panic!("peer unreachable must fail the dial");
        };
        assert!(
            matches!(&error, crate::endpoint::DialFailure::PeerUnreachable(_)),
            "{result} must be peer-unreachable, got {error:?}"
        );
        assert!(error.counts_as_peer_failure());
        let commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(
            commands
                .iter()
                .filter(|c| c.starts_with("STREAM CONNECT"))
                .count(),
            1,
            "peer-unreachable is final, not a session fault: {commands:?}"
        );
        fake.finish()?;
    }
    Ok(())
}

#[test]
fn local_sam_protocol_failure_is_transport() -> Result<(), Box<dyn std::error::Error>> {
    let dest = dest_b64();
    let script: Vec<(String, String)> = vec![
        ("HELLO".to_owned(), HELLO_OK.to_owned()),
        (
            "SESSION CREATE".to_owned(),
            format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
        ),
        (
            "NAMING LOOKUP NAME=ME".to_owned(),
            format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
        ),
        (
            "NAMING LOOKUP".to_owned(),
            "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=x\n".to_owned(),
        ),
    ];
    let mut fake = fake_sam(script)?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
    let Err(error) = session.connect([9u8; 32], 8333) else {
        panic!("failed lookup must fail the dial");
    };
    assert!(
        matches!(&error, crate::endpoint::DialFailure::Transport(_)),
        "got {error:?}"
    );
    assert!(!error.counts_as_peer_failure());
    fake.finish()?;
    Ok(())
}

#[test]
fn dead_sam_is_a_transport_error() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:1".parse()?;
    let Err(error) = SamSession::establish(addr, &priv_b64(), Duration::from_secs(2)) else {
        panic!("dead sam must fail");
    };
    assert_ne!(error.kind(), io::ErrorKind::Unsupported);
    Ok(())
}

#[test]
fn naming_destination_hash_mismatch_is_transport_and_forbids_stream_connect()
-> Result<(), Box<dyn std::error::Error>> {
    let dest = dest_b64();
    let script: Vec<(String, String)> = vec![
        ("HELLO".to_owned(), HELLO_OK.to_owned()),
        (
            "SESSION CREATE".to_owned(),
            format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
        ),
        (
            "NAMING LOOKUP NAME=ME".to_owned(),
            format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
        ),
        (
            "NAMING LOOKUP".to_owned(),
            format!("NAMING REPLY RESULT=OK NAME=peer VALUE={dest}\n"),
        ),
        (
            "STREAM CONNECT".to_owned(),
            "STREAM STATUS RESULT=OK\n".to_owned(),
        ),
    ];
    let mut fake = fake_sam(script)?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;

    let requested_hash = [9u8; 32];
    assert_ne!(requested_hash, destination_hash(&dest_bytes()));

    let Err(error) = session.connect(requested_hash, 8333) else {
        panic!("substituted destination identity must fail the dial");
    };

    assert!(
        matches!(&error, crate::endpoint::DialFailure::Transport(_)),
        "mismatch must be DialFailure::Transport, got {error:?}"
    );
    assert!(
        !error.counts_as_peer_failure(),
        "transport mismatch must not count as peer failure"
    );

    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert!(
        commands.iter().all(|c| !c.starts_with("STREAM CONNECT")),
        "STREAM CONNECT must not be sent on identity mismatch: {commands:?}"
    );
    fake.finish()?;
    Ok(())
}

#[test]
fn secret_result_is_never_reflected_in_errors() -> Result<(), Box<dyn std::error::Error>> {
    let secret = priv_b64();
    assert_eq!(sanitize_sam_result(&secret), "UNKNOWN");
    let reply = format!("SESSION STATUS RESULT={secret}\n");
    let Err(err) = require_ok(&reply, "SESSION STATUS") else {
        panic!("must fail");
    };
    let err_str = err.to_string();
    assert!(
        !err_str.contains(&secret),
        "require_ok reflected private key material in error: {err_str}"
    );
    assert_eq!(
        err.kind(),
        io::ErrorKind::ConnectionAborted,
        "a refused SAM request is a local protocol refusal: {err_str}"
    );
    assert!(
        err_str.contains("SESSION STATUS"),
        "the refusal must name the refused verb, not the bridge value: {err_str}"
    );

    let dest = dest_b64();
    let script: Vec<(String, String)> = vec![
        ("HELLO".to_owned(), HELLO_OK.to_owned()),
        (
            "SESSION CREATE".to_owned(),
            format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n"),
        ),
        (
            "NAMING LOOKUP NAME=ME".to_owned(),
            format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n"),
        ),
        (
            "NAMING LOOKUP".to_owned(),
            format!("NAMING REPLY RESULT=OK NAME=peer VALUE={dest}\n"),
        ),
        (
            "STREAM CONNECT".to_owned(),
            format!("STREAM STATUS RESULT={secret}\n"),
        ),
    ];
    let mut fake = fake_sam(script)?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
    let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
        panic!("connect must fail");
    };
    let error_str = error.to_string();
    assert!(
        !error_str.contains(&secret),
        "connect reflected private key material in error: {error_str}"
    );
    assert!(
        matches!(&error, crate::endpoint::DialFailure::Transport(_)),
        "an unrecognized bridge result is a local transport failure: {error:?}"
    );
    assert!(
        !error.counts_as_peer_failure(),
        "an unrecognized bridge result is never peer evidence"
    );
    fake.finish()?;
    Ok(())
}

#[test]
fn parse_fields_handles_quotes_and_rejects_malformed_grammar()
-> Result<(), Box<dyn std::error::Error>> {
    let fields = parse_fields(
        r#"SESSION STATUS RESULT=I2P_ERROR MESSAGE="tunnel build failed: no peers""#,
        "SESSION STATUS",
    )?;
    assert_eq!(field(&fields, "RESULT"), Some("I2P_ERROR"));
    assert_eq!(
        field(&fields, "MESSAGE"),
        Some("tunnel build failed: no peers")
    );

    assert!(parse_fields("HELLO REPLY RESULT=OK GARBAGE VERSION=3.3", "HELLO REPLY").is_err());

    assert!(parse_fields("SESSION STATUS RESULT=OK RESULT=OK", "SESSION STATUS").is_err());

    assert!(parse_fields("HELLO REPLYEVIL RESULT=OK", "HELLO REPLY").is_err());

    assert!(
        parse_fields(
            r#"SESSION STATUS RESULT=OK MESSAGE="unterminated"#,
            "SESSION STATUS"
        )
        .is_err()
    );

    assert!(
        parse_fields(
            r#"SESSION STATUS RESULT=OK MESSAGE="msg"extra"#,
            "SESSION STATUS"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn valid_destination_accepts_387_byte_null_certificate() {
    let mut null_cert = vec![0u8; 384];
    null_cert.extend_from_slice(&[0, 0, 0]);
    assert_eq!(null_cert.len(), 387);
    assert_eq!(destination_identity_len(&null_cert), Some(387));
    assert!(
        valid_destination(&null_cert),
        "valid_destination must accept 387-byte null certificate"
    );
}

#[test]
fn validate_private_destination_strict_ivnp_rules() {
    let valid_key = priv_b64();
    assert!(validate_private_destination(&valid_key).is_ok());

    let mut bytes = dest_bytes();
    bytes.extend_from_slice(&[2u8; 64]);
    bytes.extend_from_slice(&[9u8; 4]);
    let with_trailing = b64_encode(&bytes);
    assert!(
        validate_private_destination(&with_trailing).is_err(),
        "trailing bytes must fail validation"
    );

    let mut truncated = dest_bytes();
    truncated.extend_from_slice(&[2u8; 32]);
    assert!(validate_private_destination(&b64_encode(&truncated)).is_err());
}

#[test]
fn stream_accept_refuses_bad_ports_and_uses_fallback_for_absent_or_zero()
-> Result<(), Box<dyn std::error::Error>> {
    let dest = dest_b64();
    let session_with =
        |accept_line: Option<String>| -> Result<(FakeSam, SamSession), Box<dyn std::error::Error>> {
            let fake = fake_sam_with(
                session_script(),
                FakeSamOptions {
                    accept_line,
                    ..FakeSamOptions::default()
                },
            )?;
            let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
            Ok((fake, session))
        };

    let (mut fake, session) = session_with(Some(format!("{dest} FROM_PORT=1\n")))?;
    let (_stream, hash, port) = session.accept(Duration::from_secs(5), 7777)?;
    assert_eq!(port, 7777, "an absent TO_PORT uses the fallback port");
    assert_eq!(hash, destination_hash(&dest_bytes()));
    fake.finish()?;

    let (mut fake, session) = session_with(Some(format!("{dest} TO_PORT=9999\n")))?;
    let (_stream, _hash, port) = session.accept(Duration::from_secs(5), 7777)?;
    assert_eq!(port, 9999);
    fake.finish()?;

    let (mut fake, session) = session_with(Some(format!("{dest} TO_PORT=0\n")))?;
    let (_stream, hash, port) = session.accept(Duration::from_secs(5), 7777)?;
    assert_eq!(port, 7777, "TO_PORT=0 uses the fallback port");
    assert_eq!(hash, destination_hash(&dest_bytes()));
    fake.finish()?;

    for bad in ["TO_PORT=not-a-port", "TO_PORT=65536"] {
        let (mut fake, session) = session_with(Some(format!("{dest} {bad}\n")))?;
        let Err(error) = session.accept(Duration::from_secs(5), 7777) else {
            panic!("a malformed present port must fail the accept");
        };
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "{bad} must be refused as malformed, got {error}"
        );
        fake.finish()?;
    }

    for duplicate in [
        "TO_PORT=9999 TO_PORT=9999",
        "TO_PORT=0 TO_PORT=0",
        "TO_PORT=0 TO_PORT=9999",
        "TO_PORT=9999 TO_PORT=0",
    ] {
        let (mut fake, session) = session_with(Some(format!("{dest} {duplicate}\n")))?;
        let Err(error) = session.accept(Duration::from_secs(5), 7777) else {
            panic!("a duplicate TO_PORT must fail the accept");
        };
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "`{duplicate}` must be refused, got {error}"
        );
        fake.finish()?;
    }
    Ok(())
}

#[test]
fn write_key_file_atomic_and_no_replace() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("sam-atomic-key-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("test_key");

    write_key_file(&path, "initial_key_data")?;
    assert_eq!(std::fs::read_to_string(&path)?, "initial_key_data\n");

    let Err(err) = write_key_file(&path, "new_key_data") else {
        panic!("must not replace");
    };
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

    assert_eq!(std::fs::read_to_string(&path)?, "initial_key_data\n");

    let addr: SocketAddr = "127.0.0.1:7656".parse()?;
    let Err(err) = SamSession::establish(addr, &dest_b64(), Duration::from_secs(5)) else {
        panic!("public destination must be rejected as private");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let mut corrupt = dest_bytes();
    corrupt.extend_from_slice(&[2u8; 64]);
    corrupt.extend_from_slice(&[9u8; 4]);
    let corrupt_b64 = b64_encode(&corrupt);
    let Err(err) = SamSession::establish(addr, &corrupt_b64, Duration::from_secs(5)) else {
        panic!("corrupt private key must be rejected");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let temp_files: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
        .collect();
    assert!(temp_files.is_empty(), "temporary files must be cleaned up");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn sam_root_session_loss_lifecycle_and_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let dest = dest_b64();
    let priv_key = priv_b64();
    let mut fake = fake_sam(session_script())?;
    let session = SamSession::establish(fake.addr, &priv_key, Duration::from_secs(5))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    let root = session.ensure_control(deadline)?;
    session.retire_root(root, deadline)?;

    let mut stream = session
        .connect(destination_hash(&dest_bytes()), 8333)
        .map_err(crate::endpoint::DialFailure::into_io)?;
    stream.write_all(b"x")?;
    assert_eq!(session.destination(), dest);
    fake.finish()?;
    Ok(())
}

#[test]
fn bridge_side_root_loss_recovers_the_same_identity_once() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            lose_root_after_first_me: true,
            ..FakeSamOptions::default()
        },
    )?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
    fake.root_closed
        .recv_timeout(Duration::from_secs(5))
        .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;

    for _ in 0..2 {
        let mut stream = session
            .connect(destination_hash(&dest_bytes()), 8333)
            .map_err(crate::endpoint::DialFailure::into_io)?;
        stream.write_all(b"x")?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        assert_eq!(byte, *b"x");
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut commands = Vec::new();
    let mut creates = 0_usize;
    while creates < 2 && std::time::Instant::now() < deadline {
        match fake.commands.recv_timeout(Duration::from_millis(50)) {
            Ok(command) => {
                if command.starts_with("SESSION CREATE") {
                    creates += 1;
                }
                commands.push(command);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    commands.extend(fake.commands.try_iter());
    let creates: Vec<&String> = commands
        .iter()
        .filter(|c| c.starts_with("SESSION CREATE"))
        .collect();
    assert_eq!(
        creates.len(),
        2,
        "the lost root is re-created exactly once: {commands:?}"
    );
    assert_eq!(
        creates[0], creates[1],
        "recovery must reuse the same session id and destination key"
    );
    assert_eq!(session.destination(), dest_b64());
    assert!(
        commands
            .iter()
            .filter(|c| c.starts_with("STREAM CONNECT"))
            .count()
            >= 2,
        "every dial still opens its own fresh bridge: {commands:?}"
    );
    fake.finish()?;
    Ok(())
}

#[test]
fn close_forbids_session_resurrection() -> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(session_script())?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
    session.close();

    let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
        panic!("a closed session must never dial");
    };
    assert!(matches!(&error, crate::endpoint::DialFailure::Transport(_)));
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert!(!error.counts_as_peer_failure());

    let Err(accept_error) = session.accept(Duration::from_secs(1), 8333) else {
        panic!("a closed session must never accept");
    };
    assert_eq!(accept_error.kind(), io::ErrorKind::NotConnected);

    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert_eq!(
        commands
            .iter()
            .filter(|c| c.starts_with("SESSION CREATE"))
            .count(),
        1,
        "close forbids a second session root: {commands:?}"
    );
    assert!(
        commands.iter().all(|c| !c.starts_with("STREAM")),
        "no stream request may follow a close: {commands:?}"
    );
    fake.finish()?;
    Ok(())
}

const LIVENESS: Duration = Duration::from_secs(10);

const HELD_BUDGET: Duration = Duration::from_millis(600);

#[derive(Clone, Copy)]
enum Verb {
    Connect,
    Accept,
}

impl Verb {
    fn request_prefix(self) -> &'static str {
        match self {
            Self::Connect => "STREAM CONNECT",
            Self::Accept => "STREAM ACCEPT",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Connect => Self::Accept,
            Self::Accept => Self::Connect,
        }
    }

    fn call(self, session: &SamSession, budget: Duration) -> io::Result<TcpStream> {
        match self {
            Self::Connect => session
                .connect(destination_hash(&dest_bytes()), 8333)
                .map_err(crate::endpoint::DialFailure::into_io),
            Self::Accept => session
                .accept(budget, 8333)
                .map(|(stream, _hash, _port)| stream),
        }
    }
}

fn wait_for_command(
    commands: &mpsc::Receiver<String>,
    seen: &mut Vec<String>,
    prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let line = commands.recv_timeout(Duration::from_secs(5))?;
        let hit = line.starts_with(prefix);
        seen.push(line);
        if hit {
            return Ok(());
        }
    }
}

fn wait_until_root_is_dead(session: &SamSession) -> io::Result<()> {
    let give_up = Instant::now() + Duration::from_secs(5);
    while session.live_control_generation(give_up)?.is_some() {
        std::thread::yield_now();
    }
    Ok(())
}

fn finish_stream_exchange(stream: &mut TcpStream) -> io::Result<()> {
    stream.set_write_timeout(Some(LIVENESS))?;
    stream.set_read_timeout(Some(LIVENESS))?;
    stream.write_all(b"x")?;
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte)?;
    if byte != *b"x" {
        return Err(invalid("bridge echoed a different byte"));
    }
    Ok(())
}

fn step<T>(label: &str, result: io::Result<T>) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|error| -> Box<dyn std::error::Error> {
        io::Error::new(error.kind(), format!("{label}: {error}")).into()
    })
}

fn finish_bridge_after(fake: &mut FakeSam, step: &str) -> Result<(), Box<dyn std::error::Error>> {
    fake.finish()
        .map_err(|error| -> Box<dyn std::error::Error> {
            io::Error::new(
                error.kind(),
                format!("bridge teardown after {step}: {error}"),
            )
            .into()
        })
}

fn session_creates(commands: &[String]) -> usize {
    commands
        .iter()
        .filter(|command| command.starts_with("SESSION CREATE"))
        .count()
}

#[test]
fn recovery_wait_is_charged_to_each_callers_own_deadline() -> Result<(), Box<dyn std::error::Error>>
{
    for verb in [Verb::Connect, Verb::Accept] {
        let mut fake = fake_sam_with(
            session_script(),
            FakeSamOptions {
                lose_root_after_first_me: true,
                ..FakeSamOptions::default()
            },
        )?;
        let mut session = step(
            "held-lock establish",
            SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
        )?;
        session.timeout = HELD_BUDGET;
        fake.root_closed.recv_timeout(Duration::from_secs(5))?;
        step(
            "held-lock wait for the lost root",
            wait_until_root_is_dead(&session),
        )?;

        let outcome = std::thread::scope(
            |scope| -> Result<io::Result<()>, Box<dyn std::error::Error>> {
                let session = &session;
                let (reported_tx, reported_rx) = mpsc::channel();
                let held = session.recovery.lock();
                scope.spawn(move || {
                    let _ = reported_tx.send(verb.call(session, HELD_BUDGET).map(|_stream| ()));
                });
                let outcome = reported_rx.recv_timeout(LIVENESS)?;
                drop(held);
                Ok(outcome)
            },
        )?;

        let Err(error) = outcome else {
            return Err("a caller blocked behind recovery must fail at its deadline".into());
        };
        assert_eq!(
            error.kind(),
            io::ErrorKind::TimedOut,
            "the caller must report its own deadline, got {error:?}"
        );
        let mut commands: Vec<String> = fake.commands.try_iter().collect();
        assert_eq!(
            session_creates(&commands),
            1,
            "the refused caller must not touch recovery: {commands:?}"
        );
        assert!(
            commands.iter().all(|c| !c.starts_with("STREAM")),
            "the refused caller must not reach the bridge: {commands:?}"
        );

        session.timeout = LIVENESS;
        let mut stream = step("held-lock recovered call", verb.call(&session, LIVENESS))?;
        step(
            "held-lock echo on the recovered stream",
            finish_stream_exchange(&mut stream),
        )?;
        drop(stream);
        commands.extend(fake.commands.try_iter());
        assert_eq!(
            session_creates(&commands),
            2,
            "recovery runs once after release: {commands:?}"
        );
        assert_eq!(session.destination(), dest_b64());
        finish_bridge_after(&mut fake, "held-lock recovery")?;
    }
    Ok(())
}

fn delayed_invalid_id_spares_the_recovered_root(
    gated: Verb,
) -> Result<(), Box<dyn std::error::Error>> {
    let gate = new_gate();
    let kill = std::sync::Arc::new(AtomicBool::new(false));
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            gate_invalid_stream: Some((gated.request_prefix(), std::sync::Arc::clone(&gate))),
            kill_root: Some(std::sync::Arc::clone(&kill)),
            ..FakeSamOptions::default()
        },
    )?;
    let session = step(
        "delayed INVALID_ID establish",
        SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
    )?;
    let mut seen: Vec<String> = Vec::new();

    let outcome = std::thread::scope(
        |scope| -> Result<io::Result<()>, Box<dyn std::error::Error>> {
            let _release = ReleaseOnDrop(std::sync::Arc::clone(&gate));
            let session = &session;
            let (reported_tx, reported_rx) = mpsc::channel();
            scope.spawn(move || {
                let _ = reported_tx.send(gated.call(session, LIVENESS).map(|_stream| ()));
            });
            wait_for_command(&fake.commands, &mut seen, gated.request_prefix())?;
            kill.store(true, Ordering::SeqCst);
            fake.root_closed.recv_timeout(Duration::from_secs(5))?;
            step(
                "delayed INVALID_ID wait for the lost root",
                wait_until_root_is_dead(session),
            )?;
            let mut recovered = step(
                "delayed INVALID_ID recovering call",
                gated.other().call(session, LIVENESS),
            )?;
            step(
                "delayed INVALID_ID echo on the recovering stream",
                finish_stream_exchange(&mut recovered),
            )?;
            drop(recovered);
            open_gate(&gate);
            Ok(reported_rx.recv_timeout(LIVENESS)?)
        },
    )?;

    let Err(error) = outcome else {
        return Err("the delayed INVALID_ID must still fail the old request".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::NotConnected, "got {error:?}");

    let mut stream = step(
        "delayed INVALID_ID follow-up call",
        gated.other().call(&session, LIVENESS),
    )?;
    step(
        "delayed INVALID_ID echo on the follow-up stream",
        finish_stream_exchange(&mut stream),
    )?;
    drop(stream);
    seen.extend(fake.commands.try_iter());
    assert_eq!(
        session_creates(&seen),
        2,
        "stale evidence about the first root must not retire the recovered one: {seen:?}"
    );
    assert_eq!(session.destination(), dest_b64());
    finish_bridge_after(&mut fake, "delayed INVALID_ID")?;
    Ok(())
}

#[test]
fn delayed_invalid_id_never_retires_a_recovered_root() -> Result<(), Box<dyn std::error::Error>> {
    for gated in [Verb::Connect, Verb::Accept] {
        delayed_invalid_id_spares_the_recovered_root(gated)?;
    }
    Ok(())
}

fn session_with_held_recovery(
    prefix: &'static str,
    gate: &GateHandle,
) -> Result<(FakeSam, SamSession, Vec<String>), Box<dyn std::error::Error>> {
    let fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            lose_root_after_first_me: true,
            held_reply: Some(HeldReply::new(prefix, 1, 0, gate)),
            ..FakeSamOptions::default()
        },
    )?;
    let session = step(
        "held recovery establish",
        SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
    )?;
    fake.root_closed.recv_timeout(Duration::from_secs(5))?;
    step(
        "held recovery wait for the lost root",
        wait_until_root_is_dead(&session),
    )?;
    let seen = fake.commands.try_iter().collect();
    Ok((fake, session, seen))
}

fn pending_phase_is(session: &SamSession, expected: &RootPhase) -> bool {
    session
        .recovery
        .lock()
        .pending
        .as_ref()
        .is_some_and(|pending| {
            std::mem::discriminant(&pending.phase) == std::mem::discriminant(expected)
        })
}

fn pending_root_resumes_across_short_callers(
    verb: Verb,
    held_prefix: &'static str,
    paused_in: &RootPhase,
) -> Result<(), Box<dyn std::error::Error>> {
    let gate = new_gate();
    let (mut fake, mut session, mut seen) = session_with_held_recovery(held_prefix, &gate)?;
    session.timeout = HELD_BUDGET;
    for _ in 0..2 {
        let Err(error) = verb.call(&session, HELD_BUDGET) else {
            return Err("a caller behind a held reply must time out".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
    }
    seen.extend(fake.commands.try_iter());
    assert!(
        pending_phase_is(&session, paused_in),
        "the paused exchange stays pending in its own phase"
    );
    assert_eq!(
        session_creates(&seen),
        if matches!(paused_in, RootPhase::Hello) {
            1
        } else {
            2
        },
        "short callers resume the pending root; they never restart it: {seen:?}"
    );
    assert_eq!(
        session.control.lock().generation,
        1,
        "a pending root never moves the generation"
    );
    step(
        "pending delayed retire",
        session.retire_root(1, Instant::now() + LIVENESS),
    )?;
    assert!(pending_phase_is(&session, paused_in));

    open_gate(&gate);
    session.timeout = LIVENESS;
    let mut stream = step("pending resumed call", verb.call(&session, LIVENESS))?;
    step("pending echo", finish_stream_exchange(&mut stream))?;
    drop(stream);
    seen.extend(fake.commands.try_iter());
    assert_eq!(session_creates(&seen), 2, "installed once: {seen:?}");
    assert_eq!(session.control.lock().generation, 2);
    assert!(session.recovery.lock().pending.is_none());
    assert_eq!(session.destination(), dest_b64());
    session.close();
    step("pending root bridge drain", fake.wait_idle(LIVENESS))?;
    finish_bridge_after(&mut fake, "pending root resumed")?;
    Ok(())
}

#[test]
fn pending_root_outlives_short_callers_and_installs_once() -> Result<(), Box<dyn std::error::Error>>
{
    for verb in [Verb::Connect, Verb::Accept] {
        pending_root_resumes_across_short_callers(verb, "SESSION CREATE", &RootPhase::Create)?;
    }
    Ok(())
}

#[test]
fn caller_deadline_during_hello_keeps_the_connected_exchange()
-> Result<(), Box<dyn std::error::Error>> {
    for verb in [Verb::Connect, Verb::Accept] {
        pending_root_resumes_across_short_callers(verb, "HELLO", &RootPhase::Hello)?;
    }
    Ok(())
}

fn spent_root_is_discarded_and_the_next_caller_starts_fresh(
    verb: Verb,
) -> Result<(), Box<dyn std::error::Error>> {
    let gate = new_gate();
    let (mut fake, mut session, mut seen) = session_with_held_recovery("SESSION CREATE", &gate)?;
    session.timeout = HELD_BUDGET;
    let Err(paused) = verb.call(&session, HELD_BUDGET) else {
        return Err("a caller behind a held reply must time out".into());
    };
    assert!(
        paused.to_string().contains("before this caller's deadline"),
        "the caller's own deadline paused it: {paused}"
    );
    {
        let mut recovery = session.recovery.lock();
        let Some(pending) = recovery.pending.as_mut() else {
            return Err("the paused root must still be pending".into());
        };
        pending.deadline = Instant::now();
    }
    session.timeout = LIVENESS;
    let Err(spent) = verb.call(&session, LIVENESS) else {
        return Err("a spent root must not install".into());
    };
    assert_eq!(spent.kind(), io::ErrorKind::TimedOut, "got {spent:?}");
    assert!(
        spent.to_string().contains("readiness budget expired"),
        "the root deadline, not the caller's, ended it: {spent}"
    );
    assert!(session.recovery.lock().pending.is_none());
    assert_eq!(session.control.lock().generation, 1);
    fake.root_closed.recv_timeout(LIVENESS)?;
    seen.extend(fake.commands.try_iter());
    assert_eq!(session_creates(&seen), 2, "{seen:?}");

    let mut stream = step("spent root fresh call", verb.call(&session, LIVENESS))?;
    step("spent root echo", finish_stream_exchange(&mut stream))?;
    drop(stream);
    seen.extend(fake.commands.try_iter());
    assert_eq!(session_creates(&seen), 3, "{seen:?}");
    assert_eq!(session.control.lock().generation, 2);
    finish_bridge_after(&mut fake, "spent root")?;
    Ok(())
}

#[test]
fn root_deadline_discards_the_pending_root_without_extending_any_caller()
-> Result<(), Box<dyn std::error::Error>> {
    for verb in [Verb::Connect, Verb::Accept] {
        spent_root_is_discarded_and_the_next_caller_starts_fresh(verb)?;
    }
    Ok(())
}

fn close_wakes_a_caller_blocked_on_a_held_root_reply(
    verb: Verb,
) -> Result<(), Box<dyn std::error::Error>> {
    let gate = new_gate();
    let (mut fake, session, mut seen) = session_with_held_recovery("SESSION CREATE", &gate)?;
    let outcome = std::thread::scope(
        |scope| -> Result<io::Result<()>, Box<dyn std::error::Error>> {
            let session = &session;
            let (reported_tx, reported_rx) = mpsc::channel();
            scope.spawn(move || {
                let _ = reported_tx.send(verb.call(session, LIVENESS).map(|_stream| ()));
            });
            wait_for_command(&fake.commands, &mut seen, "SESSION CREATE")?;
            let (closed_tx, closed_rx) = mpsc::channel();
            scope.spawn(move || {
                session.close();
                let _ = closed_tx.send(());
            });
            closed_rx.recv_timeout(LIVENESS)?;
            Ok(reported_rx.recv_timeout(LIVENESS)?)
        },
    )?;
    let Err(error) = outcome else {
        return Err("close must fail the caller blocked on the held reply".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::NotConnected, "got {error:?}");
    fake.root_closed.recv_timeout(LIVENESS)?;
    assert!(session.recovery.lock().pending.is_none());
    assert!(session.control.lock().conn.is_none());
    assert_eq!(
        session.control.lock().generation,
        1,
        "nothing is installed after close"
    );
    let Err(refused) = verb.call(&session, LIVENESS) else {
        return Err("a closed session must never dial".into());
    };
    assert_eq!(refused.kind(), io::ErrorKind::NotConnected);
    seen.extend(fake.commands.try_iter());
    assert_eq!(session_creates(&seen), 2, "{seen:?}");
    assert!(
        seen.iter().all(|command| !command.starts_with("STREAM")),
        "no stream request may follow the close: {seen:?}"
    );
    finish_bridge_after(&mut fake, "close during a held root reply")?;
    Ok(())
}

#[test]
fn close_during_a_held_root_reply_wakes_the_caller_and_installs_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    for verb in [Verb::Connect, Verb::Accept] {
        close_wakes_a_caller_blocked_on_a_held_root_reply(verb)?;
    }
    Ok(())
}

#[test]
fn close_drains_a_paused_pending_root() -> Result<(), Box<dyn std::error::Error>> {
    let gate = new_gate();
    let (mut fake, mut session, _seen) = session_with_held_recovery("SESSION CREATE", &gate)?;
    session.timeout = HELD_BUDGET;
    let Err(error) = Verb::Accept.call(&session, HELD_BUDGET) else {
        return Err("a caller behind a held reply must time out".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
    assert!(pending_phase_is(&session, &RootPhase::Create));
    session.close();
    assert!(session.recovery.lock().pending.is_none());
    fake.root_closed.recv_timeout(LIVENESS)?;
    let Err(refused) = Verb::Connect.call(&session, LIVENESS) else {
        return Err("a closed session must never dial".into());
    };
    assert_eq!(refused.kind(), io::ErrorKind::NotConnected);
    finish_bridge_after(&mut fake, "close of a paused root")?;
    Ok(())
}

#[cfg(unix)]
fn abort(stream: TcpStream) -> io::Result<()> {
    rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO))
        .map_err(io::Error::from)?;
    drop(stream);
    Ok(())
}

#[cfg(unix)]
fn wait_for_strangers(fake: &FakeSam, clients: &[SocketAddr]) -> io::Result<()> {
    let mut missing = clients.to_vec();
    while !missing.is_empty() {
        let refused = fake.strangers.recv_timeout(LIVENESS).map_err(|error| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("bridge never refused {missing:?}: {error}"),
            )
        })?;
        missing.retain(|client| *client != refused);
    }
    Ok(())
}

#[cfg(unix)]
fn wait_accepted(fake: &FakeSam, client: SocketAddr) -> io::Result<()> {
    loop {
        let accepted = fake.accepted.recv_timeout(LIVENESS).map_err(|error| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("bridge never accepted {client}: {error}"),
            )
        })?;
        if accepted == client {
            return Ok(());
        }
    }
}

#[cfg(unix)]
#[test]
fn probes_no_session_opened_never_disturb_a_paused_root() -> Result<(), Box<dyn std::error::Error>>
{
    let gate = new_gate();
    let (mut fake, mut session, _seen) = session_with_held_recovery("SESSION CREATE", &gate)?;
    session.timeout = HELD_BUDGET;
    let Err(error) = Verb::Accept.call(&session, HELD_BUDGET) else {
        return Err("a caller behind a held reply must time out".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
    assert!(pending_phase_is(&session, &RootPhase::Create));

    let mut http_probe = TcpStream::connect(fake.addr)?;
    let silent_probe = TcpStream::connect(fake.addr)?;
    let probes = [http_probe.local_addr()?, silent_probe.local_addr()?];
    http_probe.write_all(
        b"GET / HTTP/1.1\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n\r\n",
    )?;
    abort(http_probe)?;
    abort(silent_probe)?;
    step("probes refused", wait_for_strangers(&fake, &probes))?;

    assert!(
        pending_phase_is(&session, &RootPhase::Create),
        "the paused root survives the probes"
    );
    assert_eq!(session.control.lock().generation, 1);
    open_gate(&gate);
    session.timeout = LIVENESS;
    let mut stream = step("resumed call", Verb::Accept.call(&session, LIVENESS))?;
    step("resumed echo", finish_stream_exchange(&mut stream))?;
    drop(stream);
    assert_eq!(session.control.lock().generation, 2);
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert!(
        commands.iter().all(|command| !command.starts_with("GET")),
        "a probe's request is not a bridge command: {commands:?}"
    );
    session.close();
    step("probe bridge drain", fake.wait_idle(LIVENESS))?;
    finish_bridge_after(&mut fake, "probes during a paused root")?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_session_socket_reset_before_any_command_still_fails_the_bridge()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(session_script())?;
    let conn = SamConn::connect_with_deadline(fake.addr, Instant::now() + LIVENESS)?;
    let stream = conn.into_stream();
    let client = stream.local_addr()?;
    step("session socket accepted", wait_accepted(&fake, client))?;
    abort(stream)?;
    step("reset session socket drain", fake.wait_idle(LIVENESS))?;
    let Err(error) = fake.finish() else {
        return Err("a session socket's reset must fail the bridge".into());
    };
    assert_eq!(
        error.kind(),
        io::ErrorKind::ConnectionReset,
        "got {error:?}"
    );
    assert!(error.to_string().contains("before any command"), "{error}");
    assert!(
        fake.strangers.try_iter().all(|refused| refused != client),
        "a session socket is no stranger"
    );
    Ok(())
}

#[test]
fn a_finished_bridge_never_dials_its_freed_address() -> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(session_script())?;
    let addr = fake.addr;
    fake.finish()?;
    let successor = TcpListener::bind(addr)?;
    successor.set_nonblocking(true)?;
    drop(fake);
    match successor.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
        Ok((_, peer)) => {
            Err(format!("a finished fixture dialed its freed address from {peer}").into())
        }
    }
}

struct WakeGate<'a> {
    guard: Option<MutexGuard<'a, Option<TcpStream>>>,
    session: &'a SamSession,
    bridge_addr: SocketAddr,
}

impl<'a> WakeGate<'a> {
    fn new(session: &'a SamSession, bridge_addr: SocketAddr) -> Self {
        Self {
            guard: Some(session.wake.lock()),
            session,
            bridge_addr,
        }
    }

    fn release(&mut self) {
        drop(self.guard.take());
    }
}

impl Drop for WakeGate<'_> {
    fn drop(&mut self) {
        self.release();
        if !self.session.closed.load(Ordering::Acquire) {
            self.session.close();
        }
        let _ = TcpStream::connect_timeout(&self.bridge_addr, Duration::from_millis(100));
    }
}

struct RecoveryBridge {
    listener: TcpListener,
    addr: SocketAddr,
}

impl RecoveryBridge {
    fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        Ok(Self { listener, addr })
    }

    fn assert_clean_eof(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        let mut received = Vec::new();
        let bytes_read = stream.read_to_end(&mut received)?;
        assert_eq!(
            bytes_read, 0,
            "expected EOF with no HELLO, got {bytes_read} bytes: {received:?}"
        );
        assert!(
            received.is_empty(),
            "expected no HELLO payload, got: {received:?}"
        );
        Ok(())
    }
}

struct RetiredRootSession {
    fake: FakeSam,
    session: SamSession,
}

impl RetiredRootSession {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let fake = fake_sam(session_script())?;
        let session = step(
            "close before wake establish",
            SamSession::establish(fake.addr, &priv_b64(), LIVENESS),
        )?;
        step(
            "close before wake retire root",
            session.retire_root(1, Instant::now() + LIVENESS),
        )?;
        assert!(
            session.control.lock().conn.is_none(),
            "root connection must be retired"
        );
        assert_eq!(session.control.lock().generation, 1);
        Ok(Self { fake, session })
    }

    fn assert_quiescent(&self) {
        assert!(
            self.session.recovery.lock().pending.is_none(),
            "no pending root may remain"
        );
        assert!(
            self.session.control.lock().conn.is_none(),
            "no installed root may remain"
        );
        assert_eq!(
            self.session.control.lock().generation,
            1,
            "root generation must not advance"
        );
        assert!(
            self.session.wake.lock().is_none(),
            "no wake socket may remain registered"
        );
        assert!(
            self.session.closed.load(Ordering::Acquire),
            "session must remain closed"
        );
    }

    fn finish(mut self, step_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        finish_bridge_after(&mut self.fake, step_name)
    }
}

fn orchestrate_close_before_wake(
    session: &SamSession,
    bridge: &RecoveryBridge,
    verb: Verb,
) -> Result<(io::Result<()>, TcpStream), Box<dyn std::error::Error>> {
    std::thread::scope(
        |scope| -> Result<(io::Result<()>, TcpStream), Box<dyn std::error::Error>> {
            let (accepted_tx, accepted_rx) = mpsc::channel();
            scope.spawn(move || {
                let _ = accepted_tx.send(bridge.listener.accept().map(|(stream, _)| stream));
            });

            let (reported_tx, reported_rx) = mpsc::channel();
            let (closed_tx, closed_rx) = mpsc::channel();

            let (rep, stream) = {
                let mut gate = WakeGate::new(session, bridge.addr);

                scope.spawn(move || {
                    let res = verb.call(session, LIVENESS).map(|_stream| ());
                    let _ = reported_tx.send(res);
                });

                let accepted = match accepted_rx.recv_timeout(LIVENESS) {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(err)) => Err(io::Error::new(
                        err.kind(),
                        format!("recovery listener accept failed: {err}"),
                    )),
                    Err(err) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("recovery connect not accepted: {err}"),
                    )),
                };

                let closed_published = if accepted.is_ok() {
                    scope.spawn(move || {
                        session.close();
                        let _ = closed_tx.send(());
                    });

                    let give_up = Instant::now() + LIVENESS;
                    let mut published = false;
                    while Instant::now() < give_up {
                        if session.closed.load(Ordering::Acquire) {
                            published = true;
                            break;
                        }
                        std::thread::yield_now();
                    }
                    published
                } else {
                    false
                };

                gate.release();

                let stream = accepted?;
                if !closed_published {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "terminal closed was not published before timeout",
                    )
                    .into());
                }

                let rep = reported_rx.recv_timeout(LIVENESS).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("caller thread did not exit: {err}"),
                    )
                })?;
                closed_rx.recv_timeout(LIVENESS).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("close thread did not exit: {err}"),
                    )
                })?;

                (rep, stream)
            };

            Ok((rep, stream))
        },
    )
}

fn close_between_root_connect_and_wake_registration(
    verb: Verb,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RetiredRootSession::new()?;
    let bridge = RecoveryBridge::bind()?;
    fixture.session.sam = bridge.addr;

    let (reported, accepted_stream) =
        orchestrate_close_before_wake(&fixture.session, &bridge, verb)?;

    let Err(error) = reported else {
        return Err("recovery caller must fail when session is closed".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::NotConnected, "got {error:?}");

    RecoveryBridge::assert_clean_eof(accepted_stream)?;
    fixture.assert_quiescent();
    fixture.finish("close before wake registration")?;
    Ok(())
}

#[test]
fn close_between_root_connect_and_wake_registration_installs_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    for verb in [Verb::Connect, Verb::Accept] {
        close_between_root_connect_and_wake_registration(verb)?;
    }
    Ok(())
}

fn split_hello_bridge(
    listener: TcpListener,
    head: &'static str,
    release: mpsc::Receiver<()>,
    lines: mpsc::Sender<String>,
) -> std::thread::JoinHandle<io::Result<()>> {
    let replies = [
        "SESSION STATUS RESULT=OK\n".to_owned(),
        format!("NAMING REPLY RESULT=OK NAME=ME VALUE={}\n", dest_b64()),
    ];
    std::thread::spawn(move || {
        let (stream, _) = listener.accept()?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let _ = lines.send(line.trim_end().to_owned());
        writer.write_all(head.as_bytes())?;
        release.recv_timeout(LIVENESS).map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "the reply tail was never released")
        })?;
        writer.write_all(b"SION=3.3\n")?;
        for reply in replies {
            line.clear();
            reader.read_line(&mut line)?;
            let _ = lines.send(line.trim_end().to_owned());
            writer.write_all(reply.as_bytes())?;
        }
        Ok(())
    })
}

#[test]
fn paused_exchange_keeps_the_partial_reply_and_resumes_the_same_command()
-> Result<(), Box<dyn std::error::Error>> {
    const HEAD: &str = "HELLO REPLY RESULT=OK VER";
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (release_tx, release_rx) = mpsc::channel();
    let (lines_tx, lines_rx) = mpsc::channel();
    let bridge = split_hello_bridge(listener, HEAD, release_rx, lines_tx);
    let private = priv_b64();
    let id = session_id_for(&private);
    let root_deadline = Instant::now() + LIVENESS;
    let mut root = PendingRoot::connect(addr, root_deadline, root_deadline, &|| false)
        .map_err(|stop| stop.into_io(startup_cancelled))?;
    let give_up = Instant::now() + LIVENESS;
    while root.line.len() < HEAD.len() {
        match root.advance(
            &id,
            &private,
            Instant::now() + Duration::from_millis(50),
            &|| false,
        ) {
            Err(Stop::Paused) => {}
            Err(stop) => return Err(stop.into_io(startup_cancelled).into()),
            Ok(()) => return Err("the exchange finished before its tail arrived".into()),
        }
        if Instant::now() >= give_up {
            return Err("the reply head was never consumed".into());
        }
    }
    assert_eq!(root.line, HEAD.as_bytes());
    assert!(matches!(root.phase, RootPhase::Hello));
    assert_eq!(
        root.sent,
        "HELLO VERSION MIN=3.1 MAX=3.3\n".len(),
        "the whole command was accepted once"
    );
    release_tx.send(())?;
    root.advance(&id, &private, Instant::now() + LIVENESS, &|| false)
        .map_err(|stop| stop.into_io(startup_cancelled))?;
    assert!(matches!(
        &root.phase,
        RootPhase::Ready(destination) if *destination == dest_b64()
    ));
    match bridge.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.into()),
        Err(payload) => std::panic::resume_unwind(payload),
    }
    let lines: Vec<String> = lines_rx.try_iter().collect();
    assert_eq!(lines.len(), 3, "one line per command: {lines:?}");
    assert_eq!(lines[0], "HELLO VERSION MIN=3.1 MAX=3.3");
    assert!(lines[1].starts_with(&format!("SESSION CREATE STYLE=STREAM ID={id} DESTINATION=")));
    assert_eq!(lines[2], "NAMING LOOKUP NAME=ME");
    Ok(())
}

#[test]
fn a_recorded_write_offset_resumes_the_same_command_mid_line()
-> Result<(), Box<dyn std::error::Error>> {
    const COMMAND: &str = "HELLO VERSION MIN=3.1 MAX=3.3\n";
    const ACCEPTED: usize = 10;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (received_tx, received_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let bridge = std::thread::spawn(move || -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        let mut received = Vec::new();
        reader.read_until(b'\n', &mut received)?;
        let _ = received_tx.send(received);
        writer.write_all(HELLO_OK.as_bytes())?;
        let _ = release_rx.recv_timeout(LIVENESS);
        Ok(())
    });
    let private = priv_b64();
    let id = session_id_for(&private);
    let root_deadline = Instant::now() + LIVENESS;
    let mut root = PendingRoot::connect(addr, root_deadline, root_deadline, &|| false)
        .map_err(|stop| stop.into_io(startup_cancelled))?;
    root.sent = ACCEPTED;
    let give_up = Instant::now() + LIVENESS;
    while !matches!(root.phase, RootPhase::Create) {
        match root.advance(
            &id,
            &private,
            Instant::now() + Duration::from_millis(50),
            &|| false,
        ) {
            Err(Stop::Paused) => {}
            Err(stop) => return Err(stop.into_io(startup_cancelled).into()),
            Ok(()) => return Err("the exchange cannot finish without a bridge".into()),
        }
        if Instant::now() >= give_up {
            return Err("the HELLO reply was never consumed".into());
        }
    }
    let received = received_rx.recv_timeout(LIVENESS)?;
    assert_eq!(
        received,
        COMMAND.as_bytes()[ACCEPTED..].to_vec(),
        "the resumed write sends only what was not yet accepted"
    );
    release_tx.send(())?;
    match bridge.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.into()),
        Err(payload) => std::panic::resume_unwind(payload),
    }
    Ok(())
}

#[test]
fn startup_generates_an_ephemeral_key_once_across_session_retries()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            fail_creates: 1,
            ..FakeSamOptions::default()
        },
    )?;
    let session = step(
        "startup retry",
        SamSession::establish_startup(fake.addr, None, Instant::now() + LIVENESS, &|| false),
    )?;
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.starts_with("DEST GENERATE"))
            .count(),
        1,
        "one identity for every attempt: {commands:?}"
    );
    let creates: Vec<&String> = commands
        .iter()
        .filter(|command| command.starts_with("SESSION CREATE"))
        .collect();
    assert_eq!(creates.len(), 2, "{commands:?}");
    assert_eq!(creates[0], creates[1], "a retry reuses the identity");
    assert_eq!(session.id(), session_id_for(&priv_b64()));
    assert_eq!(session.destination(), dest_b64());
    finish_bridge_after(&mut fake, "startup retry")?;
    Ok(())
}

#[test]
fn startup_cancellation_during_root_readiness_publishes_no_session()
-> Result<(), Box<dyn std::error::Error>> {
    let gate = new_gate();
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            held_reply: Some(HeldReply::new("SESSION CREATE", 0, 0, &gate)),
            ..FakeSamOptions::default()
        },
    )?;
    let cancelled = AtomicBool::new(false);
    let mut seen: Vec<String> = Vec::new();
    let outcome = std::thread::scope(
        |scope| -> Result<io::Result<SamSession>, Box<dyn std::error::Error>> {
            let (reported_tx, reported_rx) = mpsc::channel();
            let (addr, flag) = (fake.addr, &cancelled);
            let deadline = Instant::now() + LIVENESS;
            scope.spawn(move || {
                let _ =
                    reported_tx.send(SamSession::establish_startup(addr, None, deadline, &|| {
                        flag.load(Ordering::Acquire)
                    }));
            });
            wait_for_command(&fake.commands, &mut seen, "SESSION CREATE")?;
            cancelled.store(true, Ordering::Release);
            Ok(reported_rx.recv_timeout(LIVENESS)?)
        },
    )?;
    let Err(error) = outcome else {
        return Err("a cancelled startup must not return a session".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::Interrupted, "got {error:?}");
    fake.root_closed.recv_timeout(LIVENESS)?;
    seen.extend(fake.commands.try_iter());
    assert_eq!(session_creates(&seen), 1, "no retry after cancel: {seen:?}");
    finish_bridge_after(&mut fake, "cancelled startup")?;
    Ok(())
}

#[test]
fn startup_cancellation_after_the_final_reply_publishes_no_session()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(session_script())?;
    let lookup_seen = std::cell::Cell::new(false);
    let creates = std::cell::Cell::new(0usize);
    let cancelled = || {
        while let Ok(line) = fake.commands.try_recv() {
            creates.set(creates.get() + usize::from(line.starts_with("SESSION CREATE")));
            if line.starts_with("NAMING LOOKUP NAME=ME") {
                lookup_seen.set(true);
            }
        }
        lookup_seen.get()
    };
    let Err(error) =
        SamSession::establish_startup(fake.addr, None, Instant::now() + LIVENESS, &cancelled)
    else {
        return Err("a cancelled startup must not return a session".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::Interrupted, "got {error:?}");
    assert!(lookup_seen.get());
    assert_eq!(creates.get(), 1, "no retry after cancel");
    finish_bridge_after(&mut fake, "startup cancelled at publication")?;
    Ok(())
}

#[test]
fn startup_owner_deadline_bounds_a_root_that_never_becomes_ready()
-> Result<(), Box<dyn std::error::Error>> {
    let gate = new_gate();
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            held_reply: Some(HeldReply::new("SESSION CREATE", 0, 0, &gate)),
            ..FakeSamOptions::default()
        },
    )?;
    let deadline = Instant::now() + Duration::from_millis(1500);
    let Err(error) = SamSession::establish_startup(fake.addr, None, deadline, &|| false) else {
        return Err("a root that never becomes ready must not establish".into());
    };
    let returned = Instant::now();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
    assert!(
        error.to_string().contains("readiness budget expired"),
        "{error}"
    );
    assert!(returned >= deadline, "the owner deadline was waited out");
    assert!(
        returned < deadline + LIVENESS,
        "nothing extended the owner deadline"
    );
    fake.root_closed.recv_timeout(LIVENESS)?;
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert_eq!(session_creates(&commands), 1, "{commands:?}");
    finish_bridge_after(&mut fake, "owner deadline")?;
    Ok(())
}

#[test]
fn the_reached_flag_tells_an_unreachable_bridge_from_a_slow_one()
-> Result<(), Box<dyn std::error::Error>> {
    let refused: SocketAddr = "127.0.0.1:1".parse()?;
    let reached = Cell::new(false);
    let deadline = Instant::now() + LIVENESS;
    let Err(_error) = SamSession::establish_within(
        refused,
        &priv_b64(),
        EXCHANGE_BUDGET,
        deadline,
        deadline,
        &|| false,
        &reached,
    ) else {
        return Err("a refused bridge must not establish".into());
    };
    assert!(!reached.get(), "a refused connect never reached the bridge");

    let mut fake = fake_sam(session_script())?;
    let session = SamSession::establish_within(
        fake.addr,
        &priv_b64(),
        EXCHANGE_BUDGET,
        deadline,
        deadline,
        &|| false,
        &reached,
    )?;
    assert!(reached.get(), "a connected bridge is reached");
    drop(session);
    finish_bridge_after(&mut fake, "reached flag")?;
    Ok(())
}

#[test]
fn startup_connect_is_clipped_to_the_unreachable_window_until_the_bridge_connects()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam(session_script())?;
    let deadline = Instant::now() + LIVENESS;
    let unreachable_after = Instant::now();
    let reached = Cell::new(false);

    let Err(error) = SamSession::retry_establish(
        fake.addr,
        &priv_b64(),
        deadline,
        unreachable_after,
        &|| false,
        &reached,
    ) else {
        return Err("a connect past the unreachable window must not establish".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "got {error:?}");
    assert!(error.to_string().contains("connect deadline"), "{error}");
    assert!(!reached.get(), "no connection was accepted");
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert!(
        commands.is_empty(),
        "the bridge was never contacted: {commands:?}"
    );

    reached.set(true);
    let session = SamSession::retry_establish(
        fake.addr,
        &priv_b64(),
        deadline,
        unreachable_after,
        &|| false,
        &reached,
    )?;
    let commands: Vec<String> = fake.commands.try_iter().collect();
    assert_eq!(session_creates(&commands), 1, "{commands:?}");
    drop(session);
    finish_bridge_after(&mut fake, "unreachable window connect")?;
    Ok(())
}

#[test]
fn a_bridge_that_never_accepted_is_abandoned_at_the_window_with_its_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let refused: SocketAddr = "127.0.0.1:1".parse()?;
    let started = Instant::now();
    let unreachable_after = started + Duration::from_millis(100);
    let deadline = started + LIVENESS;
    let reached = Cell::new(false);
    let Err(error) = SamSession::retry_establish(
        refused,
        &priv_b64(),
        deadline,
        unreachable_after,
        &|| false,
        &reached,
    ) else {
        return Err("a refused bridge must not establish".into());
    };
    let returned = Instant::now();
    assert_eq!(
        error.kind(),
        io::ErrorKind::ConnectionRefused,
        "got {error:?}"
    );
    assert!(!reached.get(), "a refused connect never reached the bridge");
    assert!(
        returned >= unreachable_after,
        "given up before the window ended"
    );
    assert!(returned < deadline, "the owner deadline was waited out");
    Ok(())
}

#[test]
fn a_bridge_that_connected_is_not_abandoned_when_a_later_connect_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (create_tx, create_rx) = mpsc::channel();
    let bridge = std::thread::spawn(move || -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(LIVENESS))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        let mut line = String::new();
        reader.read_line(&mut line)?;
        writer.write_all(HELLO_OK.as_bytes())?;
        line.clear();
        reader.read_line(&mut line)?;
        let _ = create_tx.send(line.trim_end().to_owned());
        drop(listener);
        writer.write_all(b"SESSION STATUS RESULT=I2P_ERROR\n")?;
        Ok(())
    });
    let started = Instant::now();
    let unreachable_after = started + Duration::from_millis(100);
    let deadline = started + Duration::from_millis(1000);
    let reached = Cell::new(false);
    let outcome = SamSession::retry_establish(
        addr,
        &priv_b64(),
        deadline,
        unreachable_after,
        &|| false,
        &reached,
    );
    let returned = Instant::now();
    match bridge.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.into()),
        Err(payload) => std::panic::resume_unwind(payload),
    }
    let create = create_rx.try_recv()?;
    assert!(create.starts_with("SESSION CREATE"), "{create}");
    assert!(outcome.is_err(), "a closed bridge must not establish");
    assert!(reached.get(), "the first attempt reached the bridge");
    assert!(
        returned >= deadline,
        "a bridge that connected once was given up on as unreachable"
    );
    Ok(())
}

#[test]
fn retry_gives_up_on_the_first_failure_only_when_told_to() -> Result<(), Box<dyn std::error::Error>>
{
    let refused = || io::Error::from(io::ErrorKind::ConnectionRefused);
    let attempts = Cell::new(0u32);
    let far = Instant::now() + LIVENESS;

    let Err(error) = retry_until(
        far,
        &|| false,
        || true,
        |_left| {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(refused())
        },
    ) else {
        return Err("a give-up verdict must end the retry".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(attempts.get(), 1);

    attempts.set(0);
    let value = retry_until(
        far,
        &|| false,
        || false,
        |_left| {
            attempts.set(attempts.get() + 1);
            if attempts.get() < 2 {
                Err(refused())
            } else {
                Ok(7u8)
            }
        },
    )?;
    assert_eq!((value, attempts.get()), (7, 2));
    Ok(())
}

#[test]
fn startup_pause_is_cut_by_cancellation_and_clipped_to_the_owner_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let polls = std::cell::Cell::new(0u32);
    let cancelled = || {
        polls.set(polls.get() + 1);
        polls.get() >= 3
    };
    let Err(error) = startup_pause(PAUSE_STEPS_MAX, Instant::now() + LIVENESS, &cancelled) else {
        return Err("a cancelled pause must report the cancellation".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(polls.get(), 3);

    let started = Instant::now();
    let deadline = started + Duration::from_millis(150);
    startup_pause(PAUSE_STEPS_MAX, deadline, &|| false)?;
    assert!(Instant::now() >= deadline);
    assert!(
        started.elapsed() < Duration::from_millis(PAUSE_STEP_MS * PAUSE_STEPS_MAX),
        "the full grown pause would have outlasted the deadline"
    );
    Ok(())
}

#[test]
fn stream_deadline_bounds_the_whole_exchange_and_yields_no_stream()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            stall_stream_connect: Some(Duration::from_millis(600)),
            ..FakeSamOptions::default()
        },
    )?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_millis(200))?;
    let started = Instant::now();
    let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
        panic!("a stalled STREAM CONNECT must fail inside the deadline");
    };
    let elapsed = started.elapsed();
    assert!(
        matches!(&error, crate::endpoint::DialFailure::Transport(_)),
        "a local bridge stall is transport evidence, never peer-unreachable: {error:?}"
    );
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ),
        "the stall must end on the exchange deadline, got {error:?}"
    );
    assert!(
        !error.counts_as_peer_failure(),
        "a local bridge stall is never peer evidence"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "the whole exchange must stay under the 200ms deadline, took {elapsed:?}"
    );
    fake.finish()?;
    Ok(())
}

#[test]
fn crlf_reply_is_parsed_without_the_carriage_return() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let bridge = std::thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut byte = [0u8; 1];
        while stream.read(&mut byte).is_ok_and(|read| read == 1) {
            if byte[0] == b'\n' {
                break;
            }
        }
        stream.write_all(b"STREAM STATUS RESULT=OK\r\n")?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut conn = SamConn::connect_with_deadline(addr, deadline)?;
    let reply = conn.command(
        "STREAM CONNECT ID=btcrs-deadbeef DESTINATION=x TO_PORT=8333",
        deadline,
    )?;
    match bridge.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.into()),
        Err(payload) => std::panic::resume_unwind(payload),
    }
    assert_eq!(reply, "STREAM STATUS RESULT=OK");
    assert!(
        !reply.contains('\r'),
        "the carriage return is not part of the reply: {reply:?}"
    );
    Ok(())
}

#[test]
fn unterminated_status_line_is_never_accepted_as_a_reply() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let bridge = std::thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut byte = [0u8; 1];
        while stream.read(&mut byte).is_ok_and(|read| read == 1) {
            if byte[0] == b'\n' {
                break;
            }
        }
        stream.write_all(b"STREAM STATUS RESULT=OK")?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut conn = SamConn::connect_with_deadline(addr, deadline)?;
    let Err(error) = conn.command(
        "STREAM CONNECT ID=btcrs-deadbeef DESTINATION=x TO_PORT=8333",
        deadline,
    ) else {
        panic!("an unterminated reply must not decode");
    };
    match bridge.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.into()),
        Err(payload) => std::panic::resume_unwind(payload),
    }
    assert_eq!(
        error.kind(),
        io::ErrorKind::UnexpectedEof,
        "EOF before the newline is truncation, not a reply: {error:?}"
    );
    Ok(())
}

#[test]
fn unterminated_stream_connect_reply_fails_the_dial_without_promoting_a_stream()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fake = fake_sam_with(
        session_script(),
        FakeSamOptions {
            truncate_stream_reply: true,
            ..FakeSamOptions::default()
        },
    )?;
    let session = SamSession::establish(fake.addr, &priv_b64(), Duration::from_secs(5))?;
    let Err(error) = session.connect(destination_hash(&dest_bytes()), 8333) else {
        panic!("an unterminated STREAM STATUS must fail the dial");
    };
    assert!(
        matches!(&error, crate::endpoint::DialFailure::Transport(_)),
        "truncation is a local transport failure: {error:?}"
    );
    assert_eq!(
        error.kind(),
        io::ErrorKind::UnexpectedEof,
        "a closed, unterminated status line is EOF: {error:?}"
    );
    assert!(
        !error.counts_as_peer_failure(),
        "a truncated bridge exchange is never peer evidence"
    );
    fake.finish()?;
    Ok(())
}

#[test]
fn slow_trickle_handshake_exceeds_absolute_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let bridge = std::thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut byte = [0u8; 1];
        while stream.read_exact(&mut byte).is_ok() {
            if byte[0] == b'\n' {
                break;
            }
        }
        let trickle = HELLO_OK.as_bytes();
        for byte in trickle {
            std::thread::sleep(Duration::from_millis(30));
            if stream.write_all(&[*byte]).is_err() {
                return Ok(());
            }
        }
        Ok(())
    });
    let started = Instant::now();
    let Err(error) = SamSession::establish(addr, &priv_b64(), Duration::from_millis(100)) else {
        panic!("a trickling bridge must not outlive the deadline");
    };
    let elapsed = started.elapsed();
    match bridge.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.into()),
        Err(payload) => std::panic::resume_unwind(payload),
    }
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ),
        "trickling exchange must end on its deadline, got {error:?}"
    );
    assert!(
        elapsed < Duration::from_millis(900),
        "whole exchange must stay bounded by the 100ms deadline, took {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(50),
        "the deadline must actually be waited out, took {elapsed:?}"
    );
    Ok(())
}
