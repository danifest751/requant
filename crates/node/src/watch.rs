//! The node's own watchman: health, forks, the work of old blocks and the supply, checked in the background;
//! what it finds becomes an event in the log, in `getevents`, on the explorer's network page and, if set, on a
//! webhook (`--notify-url`, JSON POST) or a Telegram chat (`--notify-telegram TOKEN:CHAT`).

use crate::node::{now, Shared};
use std::collections::VecDeque;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Events kept for `getevents` and the explorer.
const KEPT: usize = 100;
/// A tip this old (20 target spacings) is stale.
const STALE: u64 = 1200;
/// The network rate moving by this factor within an hour is reported.
const RATE_JUMP: f64 = 3.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Critical,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warning => "warning",
            Level::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub time: u64,
    pub level: Level,
    pub text: String,
}

#[derive(Default)]
pub struct Events {
    pub list: VecDeque<Event>,
    /// Events not yet sent to the webhook or chat.
    unsent: VecDeque<Event>,
}

impl Events {
    pub fn push(&mut self, level: Level, text: String) {
        eprintln!("{}: {text}", level.name());
        let e = Event { time: now(), level, text };
        self.list.push_back(e.clone());
        self.unsent.push_back(e);
        while self.list.len() > KEPT {
            self.list.pop_front();
        }
        while self.unsent.len() > KEPT {
            self.unsent.pop_front();
        }
    }
}

#[derive(Clone, Default)]
pub struct NotifyConfig {
    /// Webhook URL: each event POSTed as `{"event": level, "text": ..., "node": agent, "height": ...}`.
    pub url: Option<String>,
    /// Telegram bot token and chat id.
    pub telegram: Option<(String, String)>,
}

fn send(cfg: &NotifyConfig, e: &Event, height: u64) {
    let text = format!("Requant {} at height {height}: {}", e.level.name(), e.text);
    if let Some(url) = &cfg.url {
        let body = serde_json::json!({"event": e.level.name(), "text": e.text, "time": e.time,
            "node": crate::node::agent(), "height": height})
        .to_string();
        let _ = Command::new("curl")
            .args(["-fsS", "--max-time", "15", "-H", "Content-Type: application/json", "-d", &body, url])
            .output();
    }
    if let Some((token, chat)) = &cfg.telegram {
        let url = format!("https://api.telegram.org/bot{token}/sendMessage");
        let _ = Command::new("curl")
            .args(["-fsS", "--max-time", "15", "--data-urlencode", &format!("chat_id={chat}")])
            .args(["--data-urlencode", &format!("text={text}"), &url])
            .output();
    }
}

/// The watch loop (every 30 s): stale tip, no peers, a jump in the network rate, re-verification of a random
/// block's work (every 30 min), the supply audit (every 10 min), then pending notifications.
pub fn watch(shared: Shared, cfg: NotifyConfig, stop: Arc<AtomicBool>) {
    let (mut stale_said, mut alone_said, mut upload_said) = (false, false, false);
    let mut rates: VecDeque<(u64, f64)> = VecDeque::new();
    let (mut last_verify, mut last_audit) = (now(), 0u64);
    let mut rng = crate::node::random_u64() | 1;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(30));
        let t = now();
        // health
        {
            let mut st = shared.lock().unwrap();
            let height = st.chain.height();
            let tip_time = st.chain.block(&st.chain.tip()).map(|b| b.header.time).unwrap_or(0);
            let stale = height > 0 && t.saturating_sub(tip_time) > STALE;
            if stale && !stale_said {
                st.events.push(Level::Warning, format!("no new block for {} min", t.saturating_sub(tip_time) / 60));
            } else if !stale && stale_said {
                st.events.push(Level::Info, "blocks arrive again".into());
            }
            stale_said = stale;
            let alone = st.peer_count() == 0 && t.saturating_sub(st.started) > 120;
            if alone && !alone_said {
                st.events.push(Level::Warning, "no peers".into());
            } else if !alone && alone_said {
                st.events.push(Level::Info, "peers are back".into());
            }
            alone_said = alone;
            // the network rate against an hour ago
            if height > 70 {
                let (rate, _) = crate::pool::network_rate(&st.chain, 60);
                rates.push_back((t, rate));
                while rates.front().is_some_and(|r| t.saturating_sub(r.0) > 3600) {
                    rates.pop_front();
                }
                if let Some(&(t0, r0)) = rates.front() {
                    if t.saturating_sub(t0) >= 3000 && r0 > 0.0 && rate > 0.0 {
                        let k = rate / r0;
                        if !(1.0 / RATE_JUMP..=RATE_JUMP).contains(&k) {
                            st.events.push(
                                Level::Warning,
                                format!(
                                    "the network rate went from {:.2} to {:.2} M tickets/s within an hour",
                                    r0 / 1e6,
                                    rate / 1e6
                                ),
                            );
                            rates.clear();
                        }
                    }
                }
            }
            if t >= last_audit + 600 {
                last_audit = t;
                let a = crate::node::supply_audit(&st);
                if a["ok"] != true {
                    st.events.push(Level::Critical, format!("supply audit failed: {a}"));
                }
            }
        }
        // step back while the machine is busy: one verification thread, no background re-verification
        let busy = crate::load::pressure().is_some_and(|p| p.busy());
        {
            let mut st = shared.lock().unwrap();
            if busy != st.busy {
                st.busy = busy;
                let n = if busy { 1 } else { st.base_threads };
                st.chain.set_threads(n);
                st.headers.set_threads(n);
                let text = if busy {
                    "the machine is busy: verifying with one thread, background checks paused".to_string()
                } else {
                    format!("the machine has room again: verifying with {n} threads")
                };
                st.events.push(Level::Info, text);
            }
            if let Some(m) = st.max_upload {
                let over = st.uploaded() >= m;
                if over && !upload_said {
                    st.events.push(
                        Level::Info,
                        format!("upload limit of {} GiB reached: serving recent blocks only", m >> 30),
                    );
                }
                upload_said = over;
            }
        }
        // the work of a random block of the current epoch, verified again from scratch
        if t >= last_verify + 1800 && !busy {
            last_verify = t;
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            reverify(&shared, rng);
        }
        // notifications
        let (pending, height) = {
            let mut st = shared.lock().unwrap();
            (st.events.unsent.drain(..).collect::<Vec<_>>(), st.chain.height())
        };
        if cfg.url.is_some() || cfg.telegram.is_some() {
            for e in &pending {
                send(&cfg, e, height);
            }
        }
    }
}

/// Verify the claim of a random block since the start of the current epoch again (it was verified on
/// arrival; a mismatch now means corrupted data, memory or weights).
fn reverify(shared: &Shared, r: u64) {
    let (header, claim, net, seed, threads, height, keep) = {
        let st = shared.lock().unwrap();
        let tip = st.chain.height();
        let epoch_start = tip / st.chain.net.epoch_len * st.chain.net.epoch_len;
        let from = epoch_start.max(1);
        if tip < from {
            return;
        }
        let h = from + r % (tip - from + 1);
        let Some(b) = st.chain.active_id(h).and_then(|id| st.chain.block(&id)) else { return };
        let seed = st.chain.epoch_seed(&b.header.prev, h);
        let keep = st.chain.upcoming_epoch_seeds();
        (b.header, b.claim.clone(), st.chain.net.clone(), seed, st.headers.threads(), h, keep)
    };
    // the current epoch's weights are cached; nothing prepared is dropped
    let epoch = crate::node::epoch_for(shared, &seed, &keep);
    if let Err(e) = requant_consensus::chain::verify_claim(&net, &epoch, &header, &claim, threads) {
        shared.lock().unwrap().events.push(
            Level::Critical,
            format!("block {height} no longer verifies ({e}): stored data, memory or epoch weights are damaged"),
        );
    }
}
