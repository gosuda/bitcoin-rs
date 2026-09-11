"""Add a request-producing tick lane to the unchanged workbench probe."""
from pathlib import Path
import runpy
import sys

here = Path(__file__).resolve().parent
if len(sys.argv) > 1 and sys.argv[1] == 'compare':
    source = (here / 'compare.py').read_text()
    source = source.replace("('gate', 'tick')", "('gate', 'refill', 'tick')")
    source = source.replace('synthetic 262144-header branch-gate and saturated BlockSync tick; NOT end-to-end IBD',
                            'synthetic 262144-header branch gate, request-producing tick, and saturated tick; NOT end-to-end IBD')
    sys.argv.pop(1)
    exec(compile(source, str(here / 'compare.py'), 'exec'))
    raise SystemExit(0)
runpy.run_path(str(here / 'measure.py'), run_name='__main__')
path = Path('crates/node/src/sync.rs')
s = path.read_text()
start = s.index('        for sample in 0..21 {')
end = s.index('        let final_applied =', start)
s = s[:start] + r'''        let mut trace = Vec::new();
        let mut requested = 0_usize;
        let mut drain_requests = || -> Result<usize, Box<dyn std::error::Error>> {
            let mut count = 0;
            for message in rx.try_iter() {
                let Message::GetData(inventory) = message else {
                    return Err("unexpected non-getdata message in frozen-height probe".into());
                };
                for item in inventory {
                    let Inventory::WitnessBlock(hash) = item else {
                        return Err("unexpected inventory kind".into());
                    };
                    count += 1;
                    trace.extend_from_slice(hash.as_byte_array());
                }
            }
            requested += count;
            Ok(count)
        };
        assert_eq!(drain_requests()?, 256);
        for sample in 0..21 {
            let elapsed = if mode == "refill" {
                let mut total = Duration::ZERO;
                for _ in 0..16 {
                    // Setup an empty, eligible request window outside timing.
                    // The actual tick must then select and emit 256 hashes.
                    sync.install_budget(super::default_sync_budget());
                    sync.known_sessions.lock().clear();
                    let started = Instant::now();
                    std::hint::black_box(&sync).tick();
                    total += started.elapsed();
                    assert_eq!(drain_requests()?, 256);
                }
                total
            } else {
                let started = Instant::now();
                for _ in 0..16 {
                    if mode == "gate" {
                        assert!(std::hint::black_box(&sync).outweighed_branch_target().is_none());
                    } else {
                        std::hint::black_box(&sync).tick();
                    }
                }
                started.elapsed()
            };
            println!("SYNC_SAMPLE {{\"mode\":\"{mode}\",\"height\":{height},\"sample\":{sample},\"iterations\":16,\"elapsed_ns\":{}}}", elapsed.as_nanos());
        }
        drain_requests()?;
''' + s[end:]
path.write_text(s)
