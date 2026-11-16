//! Admission for raw transaction materialization, shared by RPC and Esplora.

use parking_lot::Mutex;

use crate::RpcError;

pub(crate) const MAX_WIRE_BYTES: usize = crate::server::MAX_BODY_BYTES / 2;
const MAX_ACTIVE: usize = 8;
const BUSY: &str = "raw transaction decode budget exhausted; retry";

pub(crate) fn wire_bytes(hex: &str) -> Result<usize, RpcError> {
    if hex.len() > MAX_WIRE_BYTES * 2 {
        return Err(too_large());
    }
    Ok(hex.len().div_ceil(2))
}

fn too_large() -> RpcError {
    RpcError::Deserialization("raw transaction hex exceeds the request size limit".to_owned())
}

#[derive(Debug, Default)]
pub(crate) struct Admission {
    used: Mutex<Usage>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Usage {
    active: usize,
    bytes: usize,
}

impl Admission {
    pub(crate) fn reserve<'a>(
        &self,
        hexes: impl IntoIterator<Item = &'a str>,
    ) -> Result<Permit<'_>, RpcError> {
        let mut bytes = 0_usize;
        for hex in hexes {
            bytes = bytes.checked_add(wire_bytes(hex)?).ok_or_else(too_large)?;
            if bytes > MAX_WIRE_BYTES {
                return Err(too_large());
            }
        }
        let bytes = bytes.max(1);
        let mut used = self.used.lock();
        if used.active >= MAX_ACTIVE || bytes > MAX_WIRE_BYTES - used.bytes {
            metrics::counter!("rpc.tx_decode.rejected_total").increment(1);
            return Err(RpcError::Misc(BUSY.to_owned()));
        }
        used.active += 1;
        used.bytes += bytes;
        metrics::gauge!("rpc.tx_decode.active").increment(1.0);
        Ok(Permit {
            admission: self,
            bytes,
        })
    }
}

pub(crate) struct Permit<'a> {
    admission: &'a Admission,
    bytes: usize,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut used = self.admission.used.lock();
        used.active -= 1;
        used.bytes -= self.bytes;
        metrics::gauge!("rpc.tx_decode.active").decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    use sonic_rs::json;

    use super::*;
    use crate::{Handler, context::Context};

    // API-10
    #[test]
    fn byte_and_worker_reservations_are_shared_and_released() {
        let budget = Arc::new(Admission::default());
        let full = "00".repeat(MAX_WIRE_BYTES);
        let permit = budget
            .reserve([full.as_str()])
            .expect("one full inspection");
        assert!(budget.reserve(["00"]).is_err());
        drop(permit);

        let barrier = Arc::new(Barrier::new(MAX_ACTIVE + 1));
        let (tx, rx) = mpsc::channel();
        let workers = (0..MAX_ACTIVE)
            .map(|_| {
                let budget = Arc::clone(&budget);
                let barrier = Arc::clone(&barrier);
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let _permit = budget.reserve(["00"]).expect("reserved worker");
                    tx.send(()).expect("admitted");
                    barrier.wait();
                })
            })
            .collect::<Vec<_>>();
        for _ in 0..MAX_ACTIVE {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("worker ready");
        }
        let refused = budget.reserve(["00"]).is_err();
        barrier.wait();
        for worker in workers {
            worker.join().expect("worker exit");
        }
        assert!(refused);
        assert!(budget.reserve([full.as_str()]).is_ok());
    }

    // API-10
    #[test]
    fn rpc_and_public_broadcast_refuse_before_decode_without_taking_blocking_slots() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        handler.configure_blocking_admission(1);
        let full = "00".repeat(MAX_WIRE_BYTES);
        let permit = ctx
            .tx_decode_admission
            .reserve([full.as_str()])
            .expect("reserve bytes");
        for (method, params) in [
            ("sendrawtransaction", json!(["not hex"])),
            ("decoderawtransaction", json!({"hexstring":"not hex"})),
            ("testmempoolaccept", json!([["not hex"]])),
            ("submitpackage", json!([["not hex"]])),
        ] {
            let error = handler.dispatch(method, &params).expect_err("overload");
            assert_eq!(error.code(), -1);
            assert_eq!(error.to_string(), BUSY);
        }
        for surface in [
            crate::esplora::Surface::Public,
            crate::esplora::Surface::Backend,
        ] {
            let response = crate::esplora::route_post(&handler, surface, "/tx", b"not hex");
            assert_eq!(response.status, 503);
            let oversize = "00".repeat(400_001);
            assert_eq!(
                crate::esplora::route_post(&handler, surface, "/tx", oversize.as_bytes()).status,
                400
            );
        }
        assert!(handler.dispatch("getblockcount", &json!([])).is_ok());
        drop(permit);
        assert_eq!(
            handler
                .dispatch("decoderawtransaction", &json!(["not hex"]))
                .expect_err("decode")
                .code(),
            RpcError::CORE_DESERIALIZATION_ERROR
        );
        assert_eq!(*ctx.tx_decode_admission.used.lock(), Usage::default());
    }

    // API-10
    #[test]
    fn oversized_hex_and_package_do_not_consume_a_reservation() {
        let budget = Admission::default();
        let at_limit = "00".repeat(MAX_WIRE_BYTES);
        assert!(budget.reserve([at_limit.as_str()]).is_ok());
        assert_eq!(
            budget
                .reserve([at_limit.as_str(), "00"])
                .err()
                .expect("aggregate bound")
                .code(),
            RpcError::CORE_DESERIALIZATION_ERROR
        );
        let over_limit = at_limit + "00";
        assert_eq!(
            budget
                .reserve([over_limit.as_str()])
                .err()
                .expect("single bound")
                .code(),
            RpcError::CORE_DESERIALIZATION_ERROR
        );
        assert_eq!(*budget.used.lock(), Usage::default());
    }
}
