use std::collections::BTreeMap;
use std::path::Path;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{OutPoint, TxOut};
use bitcoin_rs_primitives::hex::{hex_decode, hex_encode};

use crate::chain::{Chain, Coin};
use crate::error::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HintSet {
    pub height: u32,
    pub coins: BTreeMap<OutPoint, Coin>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetDiff {
    pub missing: u64,
    pub extra: u64,
    pub mismatched: u64,
}

impl SetDiff {
    pub const fn is_empty(self) -> bool {
        self.missing == 0 && self.extra == 0 && self.mismatched == 0
    }
}

impl HintSet {
    pub fn from_chain(chain: &Chain) -> Self {
        Self {
            height: chain.height(),
            coins: chain.final_set.clone(),
        }
    }

    pub fn encode(&self) -> String {
        let mut text = String::with_capacity(self.coins.len().saturating_mul(120));
        text.push_str("swiftsync-hints 1\n");
        text.push_str(&format!("height {}\n", self.height));
        text.push_str(&format!("coins {}\n", self.coins.len()));
        for (outpoint, coin) in &self.coins {
            text.push_str(&format!(
                "{} {} {} {} {}\n",
                outpoint.txid,
                outpoint.vout,
                coin.height,
                u8::from(coin.coinbase),
                hex_encode(&serialize(&coin.txout)),
            ));
        }
        text
    }

    pub fn decode(text: &str) -> Result<Self, Error> {
        let mut height = None;
        let mut coins: BTreeMap<OutPoint, Coin> = BTreeMap::new();
        let mut declared = None;
        for (index, line) in text.lines().enumerate() {
            let line_number = index.saturating_add(1);
            if index == 0 {
                if line != "swiftsync-hints 1" {
                    return Err(Error::HintsFormat {
                        line: line_number,
                        reason: "expected `swiftsync-hints 1`".to_owned(),
                    });
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("height ") {
                height = Some(rest.parse::<u32>().map_err(|_| Error::HintsFormat {
                    line: line_number,
                    reason: format!("cannot parse height `{rest}`"),
                })?);
                continue;
            }
            if let Some(rest) = line.strip_prefix("coins ") {
                declared = Some(rest.parse::<usize>().map_err(|_| Error::HintsFormat {
                    line: line_number,
                    reason: format!("cannot parse coin count `{rest}`"),
                })?);
                continue;
            }
            let fields: Vec<&str> = line.split(' ').collect();
            if fields.len() != 5 {
                return Err(Error::HintsFormat {
                    line: line_number,
                    reason: "expected `<txid> <vout> <height> <0|1> <txout>`".to_owned(),
                });
            }
            let outpoint = parse_outpoint(fields[0], fields[1], line_number)?;
            let coin_height = fields[2].parse::<u32>().map_err(|_| Error::HintsFormat {
                line: line_number,
                reason: format!("cannot parse height `{}`", fields[2]),
            })?;
            let coinbase = match fields[3].parse::<u8>() {
                Ok(0) => false,
                Ok(1) => true,
                _ => {
                    return Err(Error::HintsFormat {
                        line: line_number,
                        reason: format!("coinbase flag `{}`", fields[3]),
                    });
                }
            };
            let bytes = hex_decode(fields[4]).map_err(|error| Error::HintsFormat {
                line: line_number,
                reason: error.to_string(),
            })?;
            let txout: TxOut = deserialize(&bytes).map_err(|error| Error::HintsFormat {
                line: line_number,
                reason: format!("txout bytes: {error}"),
            })?;
            let coin = Coin {
                txout,
                height: coin_height,
                coinbase,
            };
            if coins.insert(outpoint, coin).is_some() {
                return Err(Error::HintDuplicate {
                    outpoint: outpoint.to_string(),
                });
            }
        }
        let Some(height) = height else {
            return Err(Error::HintsFormat {
                line: 1,
                reason: "missing height".to_owned(),
            });
        };
        if let Some(declared) = declared {
            if declared != coins.len() {
                return Err(Error::HintsFormat {
                    line: 3,
                    reason: format!("file declares {declared} coins but carries {}", coins.len()),
                });
            }
        }
        Ok(Self { height, coins })
    }

    pub fn write(&self, path: &Path) -> Result<(), Error> {
        std::fs::write(path, self.encode()).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn read(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::decode(&text)
    }

    /// Fixed payload of one hint coin: outpoint, height, coinbase flag, value,
    /// script length and script. Both this and the reconstruction's export carry
    /// the same coin, so the two sizes are comparable.
    pub fn payload_bytes(&self) -> u64 {
        self.coins
            .values()
            .map(|coin| {
                let script = coin.txout.script_pubkey.len();
                u64::try_from(
                    36 + 4
                        + 1
                        + 8
                        + bitcoin::consensus::encode::VarInt(
                            u64::try_from(script).unwrap_or(u64::MAX),
                        )
                        .size()
                        + script,
                )
                .unwrap_or(u64::MAX)
            })
            .sum()
    }
}

pub fn compare(hints: &HintSet, final_set: &BTreeMap<OutPoint, Coin>) -> SetDiff {
    let mut diff = SetDiff::default();
    for (outpoint, coin) in final_set {
        match hints.coins.get(outpoint) {
            None => diff.missing = diff.missing.saturating_add(1),
            Some(hinted) if hinted != coin => diff.mismatched = diff.mismatched.saturating_add(1),
            Some(_) => {}
        }
    }
    for outpoint in hints.coins.keys() {
        if !final_set.contains_key(outpoint) {
            diff.extra = diff.extra.saturating_add(1);
        }
    }
    diff
}

fn parse_outpoint(txid: &str, vout: &str, line: usize) -> Result<OutPoint, Error> {
    let txid = txid
        .parse::<bitcoin::Txid>()
        .map_err(|_| Error::HintsFormat {
            line,
            reason: format!("cannot parse txid `{txid}`"),
        })?;
    let vout = vout.parse::<u32>().map_err(|_| Error::HintsFormat {
        line,
        reason: format!("cannot parse vout `{vout}`"),
    })?;
    Ok(OutPoint { txid, vout })
}
