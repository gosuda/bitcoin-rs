use super::*;
use crate::context::{ScriptIndexQuery, ScriptIndexSnapshot};

mod load;

struct GatedIndex {
    entered: Sender<()>,
    release: std::sync::Mutex<Receiver<()>>,
    calls: AtomicUsize,
}

impl ScriptIndexQuery for GatedIndex {
    fn history_snapshot(&self, _: ScriptHash) -> Result<ScriptIndexSnapshot, TxQueryError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.entered.send(()).expect("signal admitted work");
        self.release
            .lock()
            .expect("release gate")
            .recv_timeout(Duration::from_secs(30))
            .expect("release admitted work");
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::ScriptHashLimitExceeded { limit: 25_000 },
        ))
    }

    fn unspent_outputs(&self, _: ScriptHash) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        panic!("rejected request reached the index")
    }

    fn spender(&self, _: OutPoint) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
        panic!("rejected request reached the index")
    }
}

#[test]
fn concurrent_routes_reject_before_index_work_and_release_after_errors() {
    let (entered_send, entered_recv) = channel();
    let (release_send, release_recv) = channel();
    let index = Arc::new(GatedIndex {
        entered: entered_send,
        release: std::sync::Mutex::new(release_recv),
        calls: AtomicUsize::new(0),
    });
    let mut ctx =
        Context::new().with_esplora_query_limit(std::num::NonZeroUsize::new(2).expect("limit"));
    ctx.indexes.script_index = Some(index.clone());
    let handler = Arc::new(Handler::new(Arc::new(ctx)));
    let hash = "00".repeat(32);
    let mut workers = Vec::new();
    for prefix in ["/api", "/esplora"] {
        let handler = Arc::clone(&handler);
        let path = format!("{prefix}/scripthash/{hash}");
        workers.push(std::thread::spawn(move || dispatch(&handler, &path, "")));
    }
    for _ in 0..2 {
        entered_recv
            .recv_timeout(Duration::from_secs(30))
            .expect("concurrent query entered");
    }
    for suffix in [
        "",
        "/utxo",
        "/txs",
        "/txs/chain",
        "/txs/chain/cursor",
        "/txs/summary",
        "/txs/mempool",
    ] {
        let response = route(&handler, &format!("/scripthash/{hash}{suffix}"), "");
        assert_eq!(response.status, 503);
        assert_eq!(response.body, b"expensive Esplora query limit reached");
    }
    assert_eq!(index.calls.load(Ordering::Relaxed), 2);
    assert_eq!(route(&handler, "/blocks/tip/height", "").status, 200);
    for _ in 0..2 {
        release_send.send(()).expect("release");
    }
    for worker in workers {
        assert_eq!(worker.join().expect("request thread").status, 422);
    }
    assert_eq!(route(&handler, "/address/invalid", "").status, 400);
    let first = handler
        .context()
        .esplora_admission
        .try_acquire()
        .expect("recovered first slot");
    let second = handler
        .context()
        .esplora_admission
        .try_acquire()
        .expect("recovered second slot");
    assert!(handler.context().esplora_admission.try_acquire().is_none());
    drop((first, second));
}
