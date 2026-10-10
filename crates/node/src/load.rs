//! How busy the machine is, for the node to step back when other programs need it (our seeds share their
//! servers with other services): CPU load per core and the memory left, including a systemd/cgroup limit.
//! Linux only; elsewhere nothing is reported and the node never throttles.

/// CPU load (1-minute average per core) and the fraction of memory still available.
#[derive(Clone, Copy, Debug)]
pub struct Pressure {
    pub cpu: f64,
    pub mem_free: f64,
}

impl Pressure {
    /// Busy: more than 1.2 runnable tasks per core, or less than 10% of memory left.
    pub fn busy(&self) -> bool {
        self.cpu > 1.2 || self.mem_free < 0.10
    }
}

#[cfg(target_os = "linux")]
pub fn pressure() -> Option<Pressure> {
    let load: f64 = std::fs::read_to_string("/proc/loadavg").ok()?.split_whitespace().next()?.parse().ok()?;
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb = |key: &str| -> Option<f64> {
        meminfo.lines().find(|l| l.starts_with(key))?.split_whitespace().nth(1)?.parse::<f64>().ok()
    };
    let (total, avail) = (kb("MemTotal:")? * 1024.0, kb("MemAvailable:")? * 1024.0);
    let mut free = avail / total.max(1.0);
    // under a cgroup memory limit (systemd MemoryMax) what counts is the room left in it
    // this process's own cgroup (cgroup v2: "0::/system.slice/requantd.service")
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string())))
        .unwrap_or_default();
    let base = format!("/sys/fs/cgroup{own}");
    let cg = |f: &str| std::fs::read_to_string(format!("{base}/{f}")).ok().and_then(|s| s.trim().parse::<f64>().ok());
    if let (Some(max), Some(cur)) = (cg("memory.max"), cg("memory.current")) {
        // page cache (the epoch weights file) is reclaimable: count only what the kernel cannot take back
        let file = std::fs::read_to_string(format!("{base}/memory.stat"))
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("file "))?.split_whitespace().nth(1)?.parse::<f64>().ok())
            .unwrap_or(0.0);
        free = free.min(1.0 - (cur - file).max(0.0) / max.max(1.0));
    }
    Some(Pressure { cpu: load / cores, mem_free: free })
}

#[cfg(not(target_os = "linux"))]
pub fn pressure() -> Option<Pressure> {
    None
}
