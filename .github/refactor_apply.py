from pathlib import Path
import re

p = Path('crates/node/src/apply.rs')
orig = p.read_text(); lines = orig.splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel, body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')
def localize(body):
 out=[]
 for line in body.splitlines(True):
  if re.match(r'^(fn|struct|enum)\s+', line): line='pub(super) '+line
  out.append(line)
 return ''.join(out)

write('apply/body_store.rs', '//! Prunable block-body persistence and flat-file readers.\n\nuse super::*;\n\n'+sl(89,585))
adm=localize(sl(587,746))
write('apply/admission.rs','//! Apply admission, transition locking, and pruning authority.\n\nuse super::*;\n\n'+adm)
model=localize(sl(748,1021))
model=model.replace('    chainstate: &\'a Chainstate,','    pub(super) chainstate: &\'a Chainstate,').replace('    proof: ChainChangeProof<\'a>,','    pub(super) proof: ChainChangeProof<\'a>,')
write('apply/model.rs','//! Public chainstate facade types and mutation outcomes.\n\nuse super::*;\n\n'+model)
write('apply/chainstate.rs','//! Chainstate and admitted-transition behavior.\n\nuse super::*;\nuse super::admission::*;\nuse super::disconnect::*;\nuse super::validation::*;\nuse super::window::*;\n\n'+sl(1022,1398))
write('apply/disconnect.rs','//! Single-block connect/disconnect entry points and publication accounting.\n\nuse super::*;\nuse super::admission::*;\nuse super::validation::*;\n\n'+localize(sl(1400,1877)))
write('apply/window.rs','//! Bounded consecutive-block apply windows and failure classification.\n\nuse super::*;\nuse super::admission::*;\nuse super::disconnect::*;\nuse super::validation::*;\n\n'+localize(sl(1879,2386)))
write('apply/validation.rs','//! Block preparation, contextual validation, and UTXO commit mechanics.\n\nuse super::*;\nuse super::admission::*;\nuse super::disconnect::*;\n\n'+localize(sl(2388,4124)))
write('apply/tests.rs','use super::*;\nuse super::admission::*;\nuse super::body_store::*;\nuse super::disconnect::*;\nuse super::model::*;\nuse super::validation::*;\nuse super::window::*;\n\n'+sl(4126,len(lines)))

root=sl(1,53)+'''\nmod admission;\nmod body_store;\nmod chainstate;\nmod disconnect;\nmod model;\nmod validation;\nmod window;\n#[cfg(test)]\nmod tests;\n\npub(crate) use admission::{ApplyAdmission, ChainChangeProof, PruneAuthority, PruneGuard, TransitionLock};\npub(crate) use body_store::{FlatFilePruneBodyStore, PruneBodyReader, PruneBodyStore};\npub use disconnect::{apply_block, apply_block_with_serialized, disconnect_block, replay_local_block, validate_block};\npub(crate) use disconnect::{apply_block_with_serialized_admitted, disconnect_block_admitted};\npub use model::{AssumeValidGate, BlockProvenance, ChainTransition, Chainstate, ChainstateSnapshot, ConnectOutcome, DisconnectOutcome};\nuse model::{ApplyFinish, ApplyIntent};\npub use window::{SCRIPT_BATCH_MAX_BYTES, SCRIPT_BATCH_WINDOW, WindowApplyDisposition, WindowApplyError, apply_window, window_len};\npub(crate) use window::is_permanent_apply_error;\npub(crate) use validation::bytes_are_block;\n#[cfg(test)]\npub(crate) use validation::check_coinbase_maturity;\n\n'''+sl(55,87)
p.write_text(root.rstrip()+'\n')
