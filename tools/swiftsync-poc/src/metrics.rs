use std::time::{Duration, Instant};

use rustix::time::{ClockId, clock_gettime};

#[derive(Debug)]
pub struct Meter {
    wall: Instant,
    cpu: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct Measure {
    pub wall: Duration,
    pub cpu: Duration,
    pub process_peak_rss_kib: Option<u64>,
}

impl Meter {
    pub fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu_now(),
        }
    }

    pub fn finish(self) -> Measure {
        Measure {
            wall: self.wall.elapsed(),
            cpu: cpu_now().saturating_sub(self.cpu),
            process_peak_rss_kib: peak_rss_kib(),
        }
    }
}

pub fn milliseconds(duration: Duration) -> String {
    format!("{:.3}", duration.as_secs_f64() * 1000.0)
}
pub fn mib(value: u64) -> String {
    let whole = value / 1024;
    let tenth = value % 1024 * 10 / 1024;
    format!("{whole}.{tenth}")
}

fn cpu_now() -> Duration {
    let timespec = clock_gettime(ClockId::ProcessCPUTime);
    let secs = u64::try_from(timespec.tv_sec).unwrap_or(0);
    let nanos = u32::try_from(timespec.tv_nsec).unwrap_or(0);
    Duration::new(secs, nanos)
}

#[cfg(target_os = "linux")]
fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("VmHWM:")?;
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

#[cfg(not(target_os = "linux"))]
fn peak_rss_kib() -> Option<u64> {
    None
}
