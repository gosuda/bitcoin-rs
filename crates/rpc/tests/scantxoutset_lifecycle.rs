use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::support::TestError;
use bitcoin_rs_e2e::rpc::Connection;
use bitcoin_rs_rpc::{Auth, Handler, RpcServer, context::Context};
use sonic_rs::{Value, json};

type TestResult<T = ()> = Result<T, TestError>;

fn call(connection: &mut Connection, method: &str, params: Value) -> TestResult<Value> {
    let mut request = json!({"jsonrpc":"2.0", "id":1,"method":method});
    request["params"] = params;
    Ok(connection.rpc(
        &request,
        ("scan", "test"),
        Instant::now() + Duration::from_secs(3),
    )?)
}

fn reserved(context: &Context) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while context.chain.utxo.scan_progress().is_none() {
        assert!(Instant::now() < deadline, "scan never reserved");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn scan_preserves_control_capacity_and_observes_server_shutdown() -> TestResult {
    check_scan_cancellation(CancellationMode::Abort)?;
    check_scan_cancellation(CancellationMode::Shutdown)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CancellationMode {
    Abort,
    Shutdown,
}

fn check_scan_cancellation(mode: CancellationMode) -> TestResult {
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
    let shutdown = bitcoin_rs_chain::LatchWriter::new();
    let flag = shutdown.reader();
    let serving = std::thread::spawn(move || server.serve_with_shutdown(flag));
    let mut control = Connection::new(address);
    let result = (|| -> TestResult<()> {
        assert_eq!(
            call(&mut control, "getblockcount", json!([]))?["result"],
            json!(0)
        );
        let held = transition.lock();
        let scan = std::thread::spawn(move || {
            call(
                &mut Connection::new(address),
                "scantxoutset",
                json!(["start", []]),
            )
        });
        let operation = (|| -> TestResult<()> {
            reserved(&context);
            assert_eq!(
                call(&mut control, "scantxoutset", json!(["status"]))?["result"]["progress"],
                json!(0)
            );
            assert_eq!(
                call(&mut control, "getblockcount", json!([]))?["result"],
                json!(0)
            );
            match mode {
                CancellationMode::Shutdown => {
                    assert_eq!(
                        call(&mut control, "scantxoutset", json!(["start", []]))?["error"]["code"],
                        json!(-8)
                    );
                    shutdown.trigger();
                }
                CancellationMode::Abort => {
                    assert_eq!(
                        call(&mut control, "scantxoutset", json!(["abort"]))?["result"],
                        json!(true)
                    );
                }
            }

            let response = scan.join().map_err(|_| "scan worker panicked")??;
            assert_eq!(response["result"]["success"], json!(false));
            assert_eq!(response["result"]["txouts"], json!(0));
            assert_eq!(context.chain.utxo.scan_progress(), None);
            Ok(())
        })();
        drop(held);
        operation?;
        Ok(())
    })();
    shutdown.trigger();
    serving.join().map_err(|_| "server panicked")??;
    result
}
