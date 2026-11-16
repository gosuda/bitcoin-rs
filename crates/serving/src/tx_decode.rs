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
    used: Mutex<(usize, usize)>,
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
        if used.0 >= MAX_ACTIVE || bytes > MAX_WIRE_BYTES - used.1 {
            metrics::counter!("rpc.tx_decode.rejected_total").increment(1);
            return Err(RpcError::Misc(BUSY.to_owned()));
        }
        used.0 += 1;
        used.1 += bytes;
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
        used.0 -= 1;
        used.1 -= self.bytes;
        metrics::gauge!("rpc.tx_decode.active").decrement(1.0);
    }
}

#[cfg(test)]
mod tests;
