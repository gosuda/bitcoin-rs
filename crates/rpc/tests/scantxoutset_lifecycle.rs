//! Bounded real HTTP admission and cancellation for the shared scan owner.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use bitcoin_rs_e2e::rpc::Connection;
use bitcoin_rs_rpc::{Auth, Handler, RpcServer, context::Context};
use serde_json::{Value, json};

fn call(connection: &mut Connection, method: &str, params: Value) -> anyhow::Result<Value> {
    let mut request = json!({"jsonrpc":"2.0", "id":1,"method":method});
    request["params"] = params;
    Ok(connection.rpc(
        &request,
        ("scan", "test"),
        Instant::now() + Duration::from_secs(3),
    )?)
}

fn reserved(context: &Context) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while context.chain.utxo.scan_progress().is_none() {
        anyhow::ensure!(Instant::now() < deadline, "scan never reserved");
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

#[test]
fn scan_preserves_control_capacity_and_observes_server_shutdown() -> anyhow::Result<()> {
    let transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let context = Arc::new(Context::new().with_chain_transition(transition.clone()));
    let handler = Arc::new(Handler::new(Arc::clone(&context)));
    let server = RpcServer::bind(
        "127.0.0.1:0",
        Arc::new(Auth::basic("scan", "test")),
        handler,
        2,
        Duration::from_secs(3),
        false,
    )?;
    let address = server.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let serving = std::thread::spawn(move || server.serve_with_shutdown(flag));
    let mut control = Connection::new(address);
    let result = (|| -> anyhow::Result<()> {
        assert_eq!(
            call(&mut control, "getblockcount", json!([]))?["result"],
            json!(0)
        );
        for stop in [false, true] {
            let held = transition.lock();
            let scan = std::thread::spawn(move || {
                call(
                    &mut Connection::new(address),
                    "scantxoutset",
                    json!(["start", []]),
                )
            });
            let operation = (|| -> anyhow::Result<()> {
                reserved(&context)?;
                assert_eq!(
                    call(&mut control, "scantxoutset", json!(["status"]))?["result"]["progress"],
                    json!(0)
                );
                assert_eq!(
                    call(&mut control, "getblockcount", json!([]))?["result"],
                    json!(0)
                );
                assert_eq!(
                    call(&mut control, "scantxoutset", json!(["start", []]))?["error"]["code"],
                    json!(-8)
                );
                if stop {
                    shutdown.store(true, Ordering::Release);
                } else {
                    assert_eq!(
                        call(&mut control, "scantxoutset", json!(["abort"]))?["result"],
                        json!(true)
                    );
                }
                // The RPC transport deadline proves cancellation finishes while
                // the authoritative transition is still excluded here.
                let response = scan
                    .join()
                    .map_err(|_| anyhow::anyhow!("scan worker panicked"))??;
                assert_eq!(response["result"]["success"], json!(false));
                assert_eq!(response["result"]["txouts"], json!(0));
                assert_eq!(context.chain.utxo.scan_progress(), None);
                Ok(())
            })();
            drop(held);
            operation?;
        }
        Ok(())
    })();
    shutdown.store(true, Ordering::Release);
    serving
        .join()
        .map_err(|_| anyhow::anyhow!("server panicked"))??;
    result
}
