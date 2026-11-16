use std::task::{Context, Poll, Waker};

use bitcoin_rs_consensus::primitives::{Hash256, Script, Txid};

pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

pub(crate) fn p2sh_true_output() -> Script {
    let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    Script::from_bytes(redeem.to_p2sh().into_bytes())
}

pub(crate) fn p2sh_true_spend_script_sig() -> Script {
    Script::from_bytes(vec![0x01, 0x51])
}

pub(crate) fn parent_txid(marker: u8) -> Txid {
    Txid::from(Hash256::from_le_bytes(&[marker; 32]))
}
