//! Known peer addresses: learned from `Addr` messages, from peers' announced listening ports and from
//! `--connect`; kept on disk (`peers.txt`), tried with exponential back-off, dropped after repeated failures.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

pub const MAX_ADDRS: usize = 1000;
const MAX_FAILURES: u32 = 8;

#[derive(Clone, Copy, Default)]
struct Info {
    last_ok: u64,
    last_try: u64,
    failures: u32,
}

pub struct AddrBook {
    map: HashMap<SocketAddr, Info>,
    path: Option<PathBuf>,
    /// Accept loopback and private addresses (regtest and tests).
    allow_local: bool,
}

/// Worth gossiping and dialling: a concrete port and, unless `allow_local`, a public address.
pub fn routable(a: &SocketAddr, allow_local: bool) -> bool {
    if a.port() == 0 || a.ip().is_unspecified() {
        return false;
    }
    if allow_local {
        return true;
    }
    match a.ip() {
        IpAddr::V4(ip) => {
            !(ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_broadcast() || ip.is_documentation())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

impl AddrBook {
    pub fn load(path: Option<PathBuf>, allow_local: bool) -> AddrBook {
        let mut b = AddrBook { map: HashMap::new(), path, allow_local };
        if let Some(text) = b.path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()) {
            for a in text.lines().filter_map(|l| l.trim().parse::<SocketAddr>().ok()) {
                b.add(a);
            }
        }
        b
    }

    pub fn save(&self) {
        if let Some(p) = &self.path {
            let mut v: Vec<String> = self.map.keys().map(|a| a.to_string()).collect();
            v.sort();
            let tmp = p.with_extension("tmp");
            if std::fs::write(&tmp, v.join("\n") + "\n").is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn contains(&self, a: &SocketAddr) -> bool {
        self.map.contains_key(a)
    }

    pub fn add(&mut self, a: SocketAddr) {
        if !routable(&a, self.allow_local) || self.map.contains_key(&a) {
            return;
        }
        if self.map.len() >= MAX_ADDRS {
            let worst = self.map.iter().max_by_key(|(_, i)| (i.failures, u64::MAX - i.last_ok)).map(|(a, _)| *a);
            if let Some(w) = worst {
                self.map.remove(&w);
            }
        }
        self.map.insert(a, Info::default());
    }

    pub fn remove(&mut self, a: &SocketAddr) {
        self.map.remove(a);
    }

    pub fn attempt(&mut self, a: &SocketAddr, now: u64) {
        if let Some(i) = self.map.get_mut(a) {
            i.last_try = now;
        }
    }

    pub fn good(&mut self, a: &SocketAddr, now: u64) {
        self.add(*a);
        if let Some(i) = self.map.get_mut(a) {
            i.failures = 0;
            i.last_ok = now;
        }
    }

    pub fn failed(&mut self, a: &SocketAddr) {
        if let Some(i) = self.map.get_mut(a) {
            i.failures += 1;
            if i.failures > MAX_FAILURES {
                self.map.remove(a);
            }
        }
    }

    /// Addresses not in `exclude` whose back-off (1 min doubling per failure, at most 1 h) has passed.
    pub fn candidates(&self, exclude: &HashSet<SocketAddr>, now: u64) -> Vec<SocketAddr> {
        let mut v: Vec<SocketAddr> = self
            .map
            .iter()
            .filter(|(a, i)| {
                !exclude.contains(a) && now.saturating_sub(i.last_try) >= (60u64 << i.failures.min(6)).min(3600)
            })
            .map(|(a, _)| *a)
            .collect();
        v.sort();
        v
    }

    /// Up to `n` addresses, most recently good first.
    pub fn sample(&self, n: usize) -> Vec<SocketAddr> {
        let mut v: Vec<(&SocketAddr, &Info)> = self.map.iter().filter(|(_, i)| i.failures == 0).collect();
        v.sort_by_key(|(a, i)| (u64::MAX - i.last_ok, **a));
        v.into_iter().take(n).map(|(a, _)| *a).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_backoff_and_persistence() {
        let p: SocketAddr = "8.8.8.8:19333".parse().unwrap();
        assert!(routable(&p, false));
        for local in
            ["127.0.0.1:1", "10.0.0.1:1", "192.168.0.70:19333", "0.0.0.0:1", "[::1]:1", "[fd00::1]:1", "8.8.8.8:0"]
        {
            assert!(!routable(&local.parse().unwrap(), false), "{local}");
        }
        assert!(routable(&"127.0.0.1:5".parse().unwrap(), true));

        let path = std::env::temp_dir().join(format!("requant-addrbook-{}.txt", std::process::id()));
        let mut b = AddrBook::load(Some(path.clone()), false);
        b.add(p);
        b.add("10.0.0.1:1".parse().unwrap());
        assert_eq!(b.len(), 1);
        let none = HashSet::new();
        assert_eq!(b.candidates(&none, 1000), vec![p]);
        b.attempt(&p, 1000);
        assert!(b.candidates(&none, 1030).is_empty(), "back-off after a try");
        b.failed(&p);
        assert!(b.candidates(&none, 1100).is_empty(), "two minutes after one failure");
        assert_eq!(b.candidates(&none, 1121), vec![p]);
        for _ in 0..MAX_FAILURES {
            b.failed(&p);
        }
        assert!(b.is_empty(), "dropped after repeated failures");
        b.good(&p, 5);
        b.save();
        assert!(AddrBook::load(Some(path.clone()), false).contains(&p));
        std::fs::remove_file(path).unwrap();
    }
}
