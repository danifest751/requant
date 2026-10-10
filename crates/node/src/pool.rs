//! Mining pool inside the node (`--pool ADDR`). Miners speak the node's `getwork`/`submitwork` to it (the
//! CPPminer TNet backend works unchanged, adding its payee to `submitwork`), get the pool's block template
//! with an easier *share* target, and submit shares. A share that also meets the network target is a block,
//! which the pool submits. Rewards are split PPLNS over the last shares, credited when the block matures,
//! and paid out automatically in transactions with many outputs. State survives restarts (`pool.json`).

use crate::node::{now, Shared, State};
use crate::rpc::{hex, serve_with, unhex, Handler};
use ed25519_dalek::SigningKey;
use requant_consensus::address::{address, format_amount};
use requant_consensus::block::{Block, Claim};
use requant_consensus::chain::Chain;
use requant_consensus::tx::{pkh, Hash, Input, Output, Tx};
use requant_consensus::u256::U256;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_WORKER: &str = "default";

/// A device name from the 7th `submitwork` parameter: letters, digits, `.`, `_`, `-`, at most 32.
fn worker_name(v: Option<&Value>) -> String {
    let w: String = v
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(32)
        .collect();
    if w.is_empty() {
        DEFAULT_WORKER.to_string()
    } else {
        w
    }
}

/// Shares kept for PPLNS and statistics.
const MAX_WINDOW: usize = 20_000;
/// A job is refreshed (new transactions, time) after this many seconds even without a new tip.
const JOB_REFRESH: u64 = 30;
const JOBS_KEPT: usize = 4;
/// Window for the hashrate estimates.
const RATE_WINDOW: u64 = 600;
/// Shares for the previous tip are accepted this many seconds after it changed (credited, never blocks).
const STALE_GRACE: u64 = 10;
/// A client address with this many invalid shares within `INVALID_WINDOW` seconds is refused `REFUSE_SECS`.
const INVALID_LIMIT: u32 = 20;
const INVALID_WINDOW: u64 = 600;
const REFUSE_SECS: u64 = 3600;
/// A device without a share for this long is dropped from the statistics (rewards are unaffected: they
/// follow the share window); a device that comes back starts counting again.
const DEVICE_KEPT: u64 = 3600;

#[derive(Clone)]
pub struct PoolConfig {
    pub listen: SocketAddr,
    /// Secret key of the pool wallet (block rewards in, payouts out).
    pub key: [u8; 32],
    /// Pool fee in basis points (100 = 1%).
    pub fee_bp: u64,
    /// Expected tickets per share: `2^share_bits`.
    pub share_bits: u32,
    /// Smallest payout in atoms.
    pub min_payout: u64,
    /// Seconds between payout rounds.
    pub payout_every: u64,
}

struct Job {
    digest: Hash,
    block: Block,
    share_target: U256,
    seed: Hash,
    tip: Hash,
    created: u64,
}

#[derive(Default, Clone)]
struct MinerStats {
    shares: u64,
    rejected: u64,
    last: u64,
    paid: u64,
}

struct Credit {
    block: Hash,
    height: u64,
    credits: Vec<(Hash, u64)>,
}

struct Found {
    height: u64,
    id: Hash,
    time: u64,
    finder: Hash,
    reward: u64,
    status: &'static str,
    /// Shares the round took against the shares a block needs on average (1.0 = as expected); unknown for
    /// blocks found before this was recorded.
    effort: Option<f64>,
}

/// A sample of the pool every `SAMPLE_EVERY` seconds: (time, pool tickets/s, network tickets/s, devices).
type Sample = (u64, f64, f64, u32);

struct Payout {
    txid: Hash,
    time: u64,
    total: u64,
    outputs: usize,
    /// Amount per miner, to give back if the transaction can never confirm.
    paid: Vec<(Hash, u64)>,
    /// "pending" (sent, not in a block yet), "confirmed", or "returned" (an input was spent elsewhere, so it
    /// can never confirm; balances restored).
    status: &'static str,
    /// The transaction, for sending it again while pending.
    tx: Option<Tx>,
}

pub struct Pool {
    cfg: PoolConfig,
    key: SigningKey,
    pub owner: Hash,
    path: PathBuf,
    jobs: Vec<Job>,
    seen: HashSet<(Hash, u64, u32, u32)>,
    /// The chain tip as last seen, the one before it, and when it changed (for the stale-share grace).
    tip: Hash,
    prev_tip: Hash,
    tip_since: u64,
    /// Shares that failed the expensive check, per client address: (count, start of the count window), and
    /// addresses refused until a time. A share meeting the share target costs a forger only hashing, the
    /// check a row recomputation, so this bounds the work a forger can make the pool do.
    invalid: HashMap<IpAddr, (u32, u64)>,
    refused: HashMap<IpAddr, u64>,
    /// Recent shares: (payee, time, worker).
    window: VecDeque<(Hash, u64, String)>,
    miners: HashMap<Hash, MinerStats>,
    /// Per device ("worker") under a payee: statistics only, rewards go to the payee.
    workers: HashMap<(Hash, String), MinerStats>,
    balances: HashMap<Hash, u64>,
    immature: Vec<Credit>,
    found: Vec<Found>,
    payouts: Vec<Payout>,
    last_payout: u64,
    /// Shares since the last block the pool found (the current round).
    round_shares: u64,
    /// Pool and network rate over the last day, and each address's rate.
    history: VecDeque<Sample>,
    miner_history: HashMap<Hash, VecDeque<(u64, f64)>>,
}

/// Seconds between history samples, and samples kept (a day).
const SAMPLE_EVERY: u64 = 300;
const SAMPLES_KEPT: usize = 288;

fn h32(v: &Value) -> Option<Hash> {
    unhex(v.as_str()?).ok()?.try_into().ok()
}

impl Pool {
    pub fn new(cfg: PoolConfig, path: PathBuf) -> Pool {
        let key = SigningKey::from_bytes(&cfg.key);
        let owner = pkh(&key.verifying_key().to_bytes());
        let mut p = Pool {
            cfg,
            key,
            owner,
            path,
            jobs: Vec::new(),
            seen: HashSet::new(),
            tip: [0; 32],
            prev_tip: [0; 32],
            tip_since: 0,
            invalid: HashMap::new(),
            refused: HashMap::new(),
            window: VecDeque::new(),
            miners: HashMap::new(),
            workers: HashMap::new(),
            balances: HashMap::new(),
            immature: Vec::new(),
            found: Vec::new(),
            payouts: Vec::new(),
            last_payout: now(),
            round_shares: 0,
            history: VecDeque::new(),
            miner_history: HashMap::new(),
        };
        p.load();
        p
    }

    fn refused(&self, ip: &IpAddr) -> bool {
        self.refused.get(ip).is_some_and(|&until| until > now())
    }

    fn note_invalid(&mut self, ip: IpAddr) {
        let t = now();
        let e = self.invalid.entry(ip).or_insert((0, t));
        if t.saturating_sub(e.1) > INVALID_WINDOW {
            *e = (0, t);
        }
        e.0 += 1;
        if e.0 >= INVALID_LIMIT {
            self.invalid.remove(&ip);
            self.refused.insert(ip, t + REFUSE_SECS);
            eprintln!("pool: refusing {ip} for {REFUSE_SECS} s after {INVALID_LIMIT} invalid shares");
        }
    }

    fn share_target(&self, network: &U256) -> U256 {
        U256::low_mask(256 - self.cfg.share_bits.min(255)).max(*network)
    }

    fn save(&self) {
        let map = |m: &HashMap<Hash, u64>| -> Value {
            m.iter().map(|(k, v)| (hex(k), json!(v))).collect::<serde_json::Map<_, _>>().into()
        };
        let v = json!({
            "balances": map(&self.balances),
            "miners": self.miners.iter().map(|(k, s)| (hex(k), json!([s.shares, s.rejected, s.last, s.paid]))).collect::<serde_json::Map<_, _>>(),
            "window": self.window.iter().map(|(m, t, w)| json!([hex(m), t, w])).collect::<Vec<_>>(),
            "workers": self.workers.iter().map(|((m, w), s)| json!([hex(m), w, s.shares, s.rejected, s.last])).collect::<Vec<_>>(),
            "immature": self.immature.iter().map(|c| json!({"block": hex(&c.block), "height": c.height,
                "credits": c.credits.iter().map(|(m, a)| json!([hex(m), a])).collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "found": self.found.iter().map(|f| json!([f.height, hex(&f.id), f.time, hex(&f.finder), f.reward, f.status, f.effort])).collect::<Vec<_>>(),
            "round_shares": self.round_shares,
            "history": self.history.iter().map(|h| json!([h.0, h.1, h.2, h.3])).collect::<Vec<_>>(),
            "miner_history": self.miner_history.iter().map(|(m, v)| (hex(m), json!(v.iter().map(|(t, r)| json!([t, r])).collect::<Vec<_>>()))).collect::<serde_json::Map<_, _>>(),
            "payouts": self.payouts.iter().map(|p| json!([hex(&p.txid), p.time, p.total, p.outputs, p.status,
                p.paid.iter().map(|(m, a)| json!([hex(m), a])).collect::<Vec<_>>(),
                p.tx.as_ref().filter(|_| p.status == "pending").map(|t| hex(&t.encode()))])).collect::<Vec<_>>(),
            "last_payout": self.last_payout,
        });
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, v.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }

    fn load(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.path) else { return };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { return };
        if let Some(m) = v["balances"].as_object() {
            for (k, a) in m {
                if let (Ok(Ok(k)), Some(a)) = (unhex(k).map(<[u8; 32]>::try_from), a.as_u64()) {
                    self.balances.insert(k, a);
                }
            }
        }
        if let Some(m) = v["miners"].as_object() {
            for (k, s) in m {
                if let Ok(Ok(k)) = unhex(k).map(<[u8; 32]>::try_from) {
                    let n = |i: usize| s[i].as_u64().unwrap_or(0);
                    self.miners.insert(k, MinerStats { shares: n(0), rejected: n(1), last: n(2), paid: n(3) });
                }
            }
        }
        for e in v["window"].as_array().into_iter().flatten() {
            if let (Some(m), Some(t)) = (h32(&e[0]), e[1].as_u64()) {
                self.window.push_back((m, t, e[2].as_str().unwrap_or(DEFAULT_WORKER).to_string()));
            }
        }
        for e in v["workers"].as_array().into_iter().flatten() {
            if let (Some(m), Some(w)) = (h32(&e[0]), e[1].as_str()) {
                let n = |i: usize| e[i].as_u64().unwrap_or(0);
                self.workers
                    .insert((m, w.to_string()), MinerStats { shares: n(2), rejected: n(3), last: n(4), paid: 0 });
            }
        }
        for c in v["immature"].as_array().into_iter().flatten() {
            let credits = c["credits"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| Some((h32(&x[0])?, x[1].as_u64()?)))
                .collect();
            if let (Some(block), Some(height)) = (h32(&c["block"]), c["height"].as_u64()) {
                self.immature.push(Credit { block, height, credits });
            }
        }
        for f in v["found"].as_array().into_iter().flatten() {
            let status = match f[5].as_str() {
                Some("credited") => "credited",
                Some("orphaned") => "orphaned",
                _ => "immature",
            };
            if let (Some(height), Some(id), Some(time), Some(finder), Some(reward)) =
                (f[0].as_u64(), h32(&f[1]), f[2].as_u64(), h32(&f[3]), f[4].as_u64())
            {
                self.found.push(Found { height, id, time, finder, reward, status, effort: f[6].as_f64() });
            }
        }
        for p in v["payouts"].as_array().into_iter().flatten() {
            if let (Some(txid), Some(time), Some(total), Some(outputs)) =
                (h32(&p[0]), p[1].as_u64(), p[2].as_u64(), p[3].as_u64())
            {
                let status = match p[4].as_str() {
                    Some("pending") => "pending",
                    Some("returned") => "returned",
                    _ => "confirmed",
                };
                let paid =
                    p[5].as_array().into_iter().flatten().filter_map(|x| Some((h32(&x[0])?, x[1].as_u64()?))).collect();
                let tx = p[6].as_str().and_then(|s| unhex(s).ok()).and_then(|b| Tx::decode_exact(&b).ok());
                self.payouts.push(Payout { txid, time, total, outputs: outputs as usize, paid, status, tx });
            }
        }
        self.last_payout = v["last_payout"].as_u64().unwrap_or(self.last_payout);
        self.round_shares = v["round_shares"].as_u64().unwrap_or(0);
        for h in v["history"].as_array().into_iter().flatten() {
            if let (Some(t), Some(p), Some(n)) = (h[0].as_u64(), h[1].as_f64(), h[2].as_f64()) {
                self.history.push_back((t, p, n, h[3].as_u64().unwrap_or(0) as u32));
            }
        }
        if let Some(m) = v["miner_history"].as_object() {
            for (k, list) in m {
                if let Ok(Ok(k)) = unhex(k).map(<[u8; 32]>::try_from) {
                    let v: VecDeque<(u64, f64)> = list
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|x| Some((x[0].as_u64()?, x[1].as_f64()?)))
                        .collect();
                    self.miner_history.insert(k, v);
                }
            }
        }
    }

    /// Split a block reward over the last shares (PPLNS): the window is twice the expected shares per block.
    fn credits(&self, reward: u64, shares_per_block: f64) -> Vec<(Hash, u64)> {
        let n = ((2.0 * shares_per_block) as usize).clamp(16, MAX_WINDOW).min(self.window.len());
        if n == 0 {
            return Vec::new();
        }
        let distributable = reward - reward * self.cfg.fee_bp / 10_000;
        let mut counts: HashMap<Hash, u64> = HashMap::new();
        for (m, _, _) in self.window.iter().rev().take(n) {
            *counts.entry(*m).or_default() += 1;
        }
        let mut v: Vec<(Hash, u64)> =
            counts.into_iter().map(|(m, c)| (m, (distributable as u128 * c as u128 / n as u128) as u64)).collect();
        v.sort();
        v
    }
}

/// Run `f` with the pool taken out of the state (so it can use the rest of the state freely).
fn with_pool<R>(st: &mut State, f: impl FnOnce(&mut State, &mut Pool) -> R) -> Option<R> {
    let mut pool = st.pool.take()?;
    let r = f(st, &mut pool);
    st.pool = Some(pool);
    Some(r)
}

/// Notice a new chain tip: jobs on the previous tip stay for `STALE_GRACE` seconds, older ones go.
fn observe_tip(st: &State, pool: &mut Pool) {
    let tip = st.chain.tip();
    if tip == pool.tip {
        return;
    }
    pool.prev_tip = std::mem::replace(&mut pool.tip, tip);
    pool.tip_since = now();
    let prev = pool.prev_tip;
    pool.jobs.retain(|j| j.tip == prev);
    let jobs = &pool.jobs;
    pool.seen.retain(|(d, ..)| jobs.iter().any(|j| j.digest == *d));
}

/// The current job, refreshed on a new tip or after `JOB_REFRESH` seconds.
fn current_job(st: &mut State, pool: &mut Pool) -> usize {
    observe_tip(st, pool);
    let tip = st.chain.tip();
    let fresh = pool.jobs.last().is_some_and(|j| j.tip == tip && now().saturating_sub(j.created) < JOB_REFRESH);
    if !fresh {
        let (block, seed) = st.new_work(&pool.owner);
        let digest = block.header.digest(&st.chain.net.chain_id);
        let share_target = pool.share_target(&block.header.target);
        pool.jobs.push(Job { digest, block, share_target, seed, tip, created: now() });
        if pool.jobs.len() > JOBS_KEPT {
            pool.jobs.remove(0);
        }
    }
    pool.jobs.len() - 1
}

fn getwork(shared: &Shared) -> Result<Value, String> {
    let mut st = shared.lock().unwrap();
    with_pool(&mut st, |st, pool| {
        let k = current_job(st, pool);
        let j = &pool.jobs[k];
        let net = &st.chain.net;
        json!({
            "height": j.block.header.height,
            "header": hex(&j.block.header.encode()),
            "header_digest": hex(&j.digest),
            "epoch_seed": hex(&j.seed),
            "target": hex(&j.share_target.to_be_bytes()),
            "network_target": hex(&j.block.header.target.to_be_bytes()),
            "share_bits": pool.cfg.share_bits,
            "pool": true,
            "tnet": {"n": net.tnet.n, "b": net.tnet.b, "L": net.tnet.layers, "w": net.tnet.w, "mult": net.tnet.mult},
        })
    })
    .ok_or_else(|| "pool disabled".to_string())
}

fn submitwork(shared: &Shared, p: &[Value]) -> Result<Value, String> {
    let digest = p.first().and_then(h32).ok_or("digest")?;
    let nonce = p.get(1).and_then(|v| v.as_u64()).ok_or("nonce")?;
    let i = p.get(2).and_then(|v| v.as_u64()).filter(|&x| x <= u32::MAX as u64).ok_or("row")? as u32;
    let c = p.get(3).and_then(|v| v.as_u64()).filter(|&x| x <= u32::MAX as u64).ok_or("piece index")? as u32;
    let piece: Vec<i8> =
        unhex(p.get(4).and_then(|v| v.as_str()).ok_or("piece")?)?.into_iter().map(|x| x as i8).collect();
    let miner = p.get(5).and_then(h32).ok_or("payee: the miner's 32-byte key hash is required by the pool")?;
    let worker = worker_name(p.get(6));
    let reject = |st: &mut State| {
        with_pool(st, |_, pool| {
            pool.miners.entry(miner).or_default().rejected += 1;
            pool.workers.entry((miner, worker.clone())).or_default().rejected += 1;
        })
    };

    let ip = crate::rpc::client_ip();
    // 1. cheap checks under the lock
    let (epoch, threads, block, share_target, net, late) = {
        let mut st = shared.lock().unwrap();
        let tip = st.chain.tip();
        let r = with_pool(&mut st, |st, pool| -> Result<_, &'static str> {
            if ip.is_some_and(|ip| pool.refused(&ip)) {
                return Err("too many invalid shares from this address; try again later");
            }
            observe_tip(st, pool);
            // a share for the previous tip, found while the news travelled, still counts (not as a block)
            let in_grace = now().saturating_sub(pool.tip_since) <= STALE_GRACE;
            let j = pool
                .jobs
                .iter()
                .find(|j| j.digest == digest && (j.tip == tip || (j.tip == pool.prev_tip && in_grace)))
                .ok_or("stale")?;
            let late = j.tip != tip;
            if piece.len() != st.chain.net.tnet.w {
                return Err("piece length");
            }
            let h = tnet::ticket_hash(&piece, &digest, nonce, i, c);
            if !tnet::meets_target(&h, &j.share_target.to_be_bytes()) {
                return Err("above the share target");
            }
            if !pool.seen.insert((digest, nonce, i, c)) {
                return Err("duplicate");
            }
            let (block, share_target, seed) = (j.block.clone(), j.share_target, j.seed);
            Ok((st.chain.epoch(&seed), st.headers.threads(), block, share_target, st.chain.net.clone(), late))
        })
        .ok_or("pool disabled")?;
        match r {
            Ok(x) => x,
            Err(why) => {
                reject(&mut st);
                return Ok(json!({"accepted": false, "reason": why}));
            }
        }
    };
    // 2. the expensive check (recompute the row) without the lock
    let valid = epoch.check(&digest, nonce, i, c, &piece, &share_target.to_be_bytes(), threads).is_ok();
    // 3. record
    let mut st = shared.lock().unwrap();
    if !valid {
        reject(&mut st);
        if let Some(ip) = ip {
            with_pool(&mut st, |_, pool| pool.note_invalid(ip));
        }
        return Ok(json!({"accepted": false, "reason": "invalid share"}));
    }
    let t = now();
    with_pool(&mut st, |_, pool| {
        pool.window.push_back((miner, t, worker.clone()));
        while pool.window.len() > MAX_WINDOW {
            pool.window.pop_front();
        }
        for s in [pool.miners.entry(miner).or_default(), pool.workers.entry((miner, worker.clone())).or_default()] {
            s.shares += 1;
            s.last = t;
        }
        pool.round_shares += 1;
    });
    let h = tnet::ticket_hash(&piece, &digest, nonce, i, c);
    let is_block = !late && tnet::meets_target(&h, &block.header.target.to_be_bytes());
    let mut height = None;
    if is_block {
        let mut b = block;
        b.claim = Claim { nonce, i, c, piece };
        let id = b.id(&net);
        let reward: u64 = b.txs[0].outputs().iter().filter(|o| with_owner(&st, o)).map(|o| o.value).sum();
        let work_ratio = u256_f64(&U256::work(&b.header.target)) / u256_f64(&U256::work(&share_target));
        if matches!(st.process_block(b.clone(), None), Ok(Some(acc)) if acc != requant_consensus::chain::Accepted::SideChain)
        {
            height = Some(b.header.height);
            with_pool(&mut st, |_, pool| {
                let credits = pool.credits(reward, work_ratio);
                pool.immature.push(Credit { block: id, height: b.header.height, credits });
                // effort: the round's shares against the shares a block needs on average
                let effort = (work_ratio > 0.0).then(|| pool.round_shares as f64 / work_ratio);
                pool.round_shares = 0;
                pool.found.push(Found {
                    height: b.header.height,
                    id,
                    time: t,
                    finder: miner,
                    reward,
                    status: "immature",
                    effort,
                });
                pool.save();
            });
        }
    }
    Ok(json!({"accepted": true, "block": height.is_some(), "height": height}))
}

fn with_owner(st: &State, o: &Output) -> bool {
    st.pool.as_ref().is_some_and(|p| o.pkh == p.owner)
}

fn u256_f64(x: &U256) -> f64 {
    x.0.iter().enumerate().map(|(k, &l)| l as f64 * 2f64.powi(64 * k as i32)).sum()
}

/// Credit matured blocks (dropping orphaned ones) and pay balances above the minimum.
fn maintain(st: &mut State, pool: &mut Pool) {
    let next = st.chain.height() + 1;
    let maturity = st.chain.net.maturity;
    let mut changed = false;
    let mut keep = Vec::new();
    for c in std::mem::take(&mut pool.immature) {
        let on_chain = st.chain.active_id(c.height) == Some(c.block);
        // a block that left the chain may come back with a reorganisation: it is given up only once the chain
        // has gone `maturity` blocks past it
        if next.saturating_sub(c.height) < maturity {
            keep.push(c);
            continue;
        }
        let status = if on_chain {
            for (m, a) in &c.credits {
                *pool.balances.entry(*m).or_default() += a;
            }
            "credited"
        } else {
            "orphaned"
        };
        if let Some(f) = pool.found.iter_mut().find(|f| f.id == c.block) {
            f.status = status;
        }
        changed = true;
    }
    pool.immature = keep;
    let t = now();
    let devices = pool.workers.len();
    pool.workers.retain(|_, s| t.saturating_sub(s.last) <= DEVICE_KEPT);
    changed |= pool.workers.len() != devices;
    pool.refused.retain(|_, until| *until > t);
    pool.invalid.retain(|_, (_, since)| t.saturating_sub(*since) <= INVALID_WINDOW);
    changed |= track_payouts(st, pool);
    changed |= sample(st, pool, t);

    if now().saturating_sub(pool.last_payout) >= pool.cfg.payout_every {
        pool.last_payout = now();
        changed |= payout(st, pool);
    }
    if changed {
        pool.save();
    }
}

/// Follow pending payouts: confirmed once in a block; sent again if the mempool lost them while their coins
/// are unspent; returned to the balances only when a coin they spend was spent by another transaction (then
/// they can never confirm, so nobody is paid twice).
fn track_payouts(st: &mut State, pool: &mut Pool) -> bool {
    let mut changed = false;
    for k in 0..pool.payouts.len() {
        let p = &pool.payouts[k];
        if p.status != "pending" || st.mempool.contains(&p.txid) {
            continue;
        }
        if st.index.locate(&p.txid).is_some() {
            pool.payouts[k].status = "confirmed";
            pool.payouts[k].tx = None;
            changed = true;
            continue;
        }
        let Some(tx) = p.tx.clone() else { continue };
        let Tx::Transfer { inputs, .. } = &tx else { continue };
        if inputs.iter().all(|i| st.chain.coin(&i.prev).is_some()) {
            if let Err(e) = st.process_tx(tx, None) {
                eprintln!("pool: payout {} could not be sent again: {e}", hex(&pool.payouts[k].txid));
            }
            continue;
        }
        let p = &mut pool.payouts[k];
        for (m, a) in &p.paid {
            *pool.balances.entry(*m).or_default() += a;
            if let Some(s) = pool.miners.get_mut(m) {
                s.paid = s.paid.saturating_sub(*a);
            }
        }
        eprintln!("pool: payout {} can no longer confirm; balances restored", hex(&p.txid));
        p.status = "returned";
        p.tx = None;
        changed = true;
    }
    changed
}

/// One payout transaction to every miner whose balance reached the minimum (as many as the pool's
/// spendable coins cover). Returns whether anything was paid.
fn payout(st: &mut State, pool: &mut Pool) -> bool {
    let mut due: Vec<(Hash, u64)> =
        pool.balances.iter().filter(|(_, a)| **a >= pool.cfg.min_payout).map(|(m, a)| (*m, *a)).collect();
    if due.is_empty() {
        return false;
    }
    due.sort_by_key(|d| std::cmp::Reverse(d.1));
    due.truncate(200);
    let next = st.chain.height() + 1;
    let maturity = st.chain.net.maturity;
    let coins: Vec<_> = st
        .chain
        .coins_of(&pool.owner)
        .into_iter()
        .filter(|(op, c)| (!c.coinbase || next - c.height >= maturity) && !st.mempool.is_spent(op))
        .collect();
    let available: u64 = coins.iter().map(|(_, c)| c.output.value).sum();
    let mut outputs = Vec::new();
    let mut total = 0u64;
    let fee_of = |inputs: usize, outs: usize| 1_000 + 200 * (inputs + outs) as u64;
    for (m, a) in &due {
        if total + a + fee_of(coins.len(), outputs.len() + 2) > available {
            break;
        }
        total += a;
        outputs.push(Output { value: *a, pkh: *m });
    }
    if outputs.is_empty() {
        return false;
    }
    // spend just enough coins, largest first
    let mut coins = coins;
    coins.sort_by_key(|c| std::cmp::Reverse(c.1.output.value));
    let (mut inputs, mut gathered) = (Vec::new(), 0u64);
    for (op, c) in coins {
        if gathered >= total + fee_of(inputs.len() + 1, outputs.len() + 1) {
            break;
        }
        gathered += c.output.value;
        inputs.push(Input { prev: op, pubkey: [0; 32], sig: [0; 64] });
    }
    let fee = fee_of(inputs.len(), outputs.len() + 1);
    if gathered < total + fee {
        return false;
    }
    let paid = outputs.clone();
    if gathered > total + fee {
        outputs.push(Output { value: gathered - total - fee, pkh: pool.owner });
    }
    let keys: Vec<&SigningKey> = inputs.iter().map(|_| &pool.key).collect();
    let mut tx = Tx::Transfer { inputs, outputs };
    tx.sign(&st.chain.net.chain_id, &keys);
    match st.process_tx(tx.clone(), None) {
        Ok(txid) => {
            for o in &paid {
                if let Some(b) = pool.balances.get_mut(&o.pkh) {
                    *b -= o.value;
                }
                pool.miners.entry(o.pkh).or_default().paid += o.value;
            }
            pool.balances.retain(|_, a| *a > 0);
            pool.payouts.push(Payout {
                txid,
                time: now(),
                total,
                outputs: paid.len(),
                paid: paid.iter().map(|o| (o.pkh, o.value)).collect(),
                status: "pending",
                tx: Some(tx),
            });
            true
        }
        Err(e) => {
            eprintln!("pool: payout transaction refused: {e}");
            false
        }
    }
}

/// Rates over the last `RATE_WINDOW` seconds in tickets/s, per address and per device. A device that started
/// recently is rated over the time it has been sending shares (at least a minute), not the whole window.
fn rates(pool: &Pool, t: u64) -> (HashMap<Hash, f64>, HashMap<(Hash, String), f64>) {
    let share_work = 2f64.powi(pool.cfg.share_bits as i32);
    let mut recent: HashMap<Hash, (u64, u64)> = HashMap::new();
    let mut recent_w: HashMap<(Hash, String), (u64, u64)> = HashMap::new();
    for (m, at, w) in pool.window.iter().rev() {
        if t.saturating_sub(*at) > RATE_WINDOW {
            break;
        }
        for e in [recent.entry(*m).or_insert((0, *at)), recent_w.entry((*m, w.clone())).or_insert((0, *at))] {
            e.0 += 1;
            e.1 = *at;
        }
    }
    let rate = |&(n, first): &(u64, u64)| n as f64 * share_work / t.saturating_sub(first).clamp(60, RATE_WINDOW) as f64;
    (recent.iter().map(|(k, v)| (*k, rate(v))).collect(), recent_w.iter().map(|(k, v)| (k.clone(), rate(v))).collect())
}

/// The network's rate from its last `window` blocks (expected tickets over elapsed time), and the expected
/// tickets for the next block (the difficulty).
pub fn network_rate(chain: &Chain, window: u64) -> (f64, f64) {
    let tip_h = chain.height();
    let block = |h: u64| chain.block(&chain.active_id(h).unwrap()).unwrap();
    let tip = block(tip_h);
    let difficulty = u256_f64(&U256::work(&tip.header.target));
    let from = tip_h.saturating_sub(window);
    if tip_h == from {
        return (0.0, difficulty);
    }
    let tickets: f64 = (from + 1..=tip_h).map(|h| u256_f64(&U256::work(&block(h).header.target))).sum();
    let span = tip.header.time.saturating_sub(block(from).header.time).max(1) as f64;
    (tickets / span, difficulty)
}

/// A history sample every `SAMPLE_EVERY` seconds: the pool, the network, and every address mining.
fn sample(st: &State, pool: &mut Pool, t: u64) -> bool {
    if pool.history.back().is_some_and(|h| t.saturating_sub(h.0) < SAMPLE_EVERY) {
        return false;
    }
    let (per_addr, per_dev) = rates(pool, t);
    let devices = per_dev.values().filter(|r| **r > 0.0).count() as u32;
    let (net, _) = network_rate(&st.chain, 60);
    pool.history.push_back((t, per_addr.values().sum(), net, devices));
    while pool.history.len() > SAMPLES_KEPT {
        pool.history.pop_front();
    }
    // addresses mining now, and those with a history (a zero shows them stopping)
    let keys: HashSet<Hash> = per_addr.keys().chain(pool.miner_history.keys()).copied().collect();
    for m in keys {
        let h = pool.miner_history.entry(m).or_default();
        h.push_back((t, per_addr.get(&m).copied().unwrap_or(0.0)));
        while h.len() > SAMPLES_KEPT {
            h.pop_front();
        }
    }
    pool.miner_history.retain(|_, h| h.iter().any(|(_, r)| *r > 0.0));
    true
}

/// The last day by the hour, from the chain itself (available at once, no sampling needed): the network's
/// rate (expected tickets of its blocks per second) and the pool's (of the blocks it found).
fn hourly(st: &State, pool: &Pool, t: u64, finder: Option<&Hash>) -> Vec<Value> {
    let start = t.saturating_sub(24 * 3600);
    let mut net = [0f64; 24];
    let mut mine = [0f64; 24];
    let bucket = |time: u64| ((time.saturating_sub(start)) / 3600).min(23) as usize;
    let mut h = st.chain.height();
    while let Some(b) = st.chain.active_id(h).and_then(|id| st.chain.block(&id)) {
        if b.header.time < start || h == 0 {
            break;
        }
        net[bucket(b.header.time)] += u256_f64(&U256::work(&b.header.target));
        h -= 1;
    }
    for f in pool.found.iter().rev() {
        if f.time < start {
            break;
        }
        if f.status == "orphaned" || finder.is_some_and(|m| *m != f.finder) {
            continue;
        }
        if let Some(b) = st.chain.block(&f.id) {
            mine[bucket(f.time)] += u256_f64(&U256::work(&b.header.target));
        }
    }
    // the current hour is partial: rate over the part that has passed
    (0..24)
        .map(|k| {
            let from = start + k as u64 * 3600;
            let span = (t.min(from + 3600).saturating_sub(from)).max(60) as f64;
            json!([from + 1800, mine[k] / span, net[k] / span])
        })
        .collect()
}

fn immature_by_miner(pool: &Pool) -> HashMap<Hash, u64> {
    let mut immature: HashMap<Hash, u64> = HashMap::new();
    for c in &pool.immature {
        for (m, a) in &c.credits {
            *immature.entry(*m).or_default() += a;
        }
    }
    immature
}

/// Statistics for the `poolstats` method and the explorer.
pub fn stats(st: &State) -> Option<Value> {
    let pool = st.pool.as_ref()?;
    let net = &st.chain.net;
    let t = now();
    let (per_addr, per_dev) = rates(pool, t);
    let immature = immature_by_miner(pool);
    let mut miners: Vec<Value> = pool
        .miners
        .iter()
        .map(|(m, s)| {
            // an address's counts are the sums over its active devices (see DEVICE_KEPT), so the rows add up
            let mine: Vec<(&String, &MinerStats)> =
                pool.workers.iter().filter(|((wm, _), _)| wm == m).map(|((_, w), ws)| (w, ws)).collect();
            let (shares, rejected, last) =
                mine.iter().fold((0, 0, s.last), |(n, r, l), (_, ws)| (n + ws.shares, r + ws.rejected, l.max(ws.last)));
            let mut workers: Vec<Value> = mine
                .iter()
                .map(|(w, ws)| {
                    json!({"name": w, "tickets_per_s": per_dev.get(&(*m, (*w).clone())).copied().unwrap_or(0.0),
                           "shares": ws.shares, "rejected": ws.rejected, "last_share": ws.last})
                })
                .collect();
            workers.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            json!({"address": address(net, m), "tickets_per_s": per_addr.get(m).copied().unwrap_or(0.0), "shares": shares,
                   "rejected": rejected, "last_share": last, "balance": pool.balances.get(m).copied().unwrap_or(0),
                   "immature": immature.get(m).copied().unwrap_or(0), "paid": s.paid, "workers": workers,
                   "blocks_found": pool.found.iter().filter(|f| f.finder == *m && f.status != "orphaned").count()})
        })
        .collect();
    miners.sort_by(|a, b| b["tickets_per_s"].as_f64().partial_cmp(&a["tickets_per_s"].as_f64()).unwrap());
    let total_rate: f64 = per_addr.values().sum();
    let (net_rate, difficulty) = network_rate(&st.chain, 60);
    let tip = st.chain.height();
    let good: Vec<&Found> = pool.found.iter().filter(|f| f.status != "orphaned").collect();
    let efforts: Vec<f64> = good.iter().rev().take(100).filter_map(|f| f.effort).collect();
    let share_work = 2f64.powi(pool.cfg.share_bits as i32);
    Some(json!({
        "address": address(net, &pool.owner),
        "fee_percent": pool.cfg.fee_bp as f64 / 100.0,
        "share_bits": pool.cfg.share_bits,
        "min_payout": format_amount(pool.cfg.min_payout),
        "min_payout_atoms": pool.cfg.min_payout,
        "payout_every_s": pool.cfg.payout_every,
        "blocks_total": good.len(),
        "blocks_24h": good.iter().filter(|f| t.saturating_sub(f.time) <= 86_400).count(),
        "last_block_time": good.last().map(|f| f.time),
        "round_shares": pool.round_shares,
        "round_effort": if difficulty > 0.0 { pool.round_shares as f64 * share_work / difficulty } else { 0.0 },
        "effort_avg": if efforts.is_empty() { None } else { Some(efforts.iter().sum::<f64>() / efforts.len() as f64) },
        "paid_total": pool.payouts.iter().filter(|p| p.status != "returned").map(|p| p.total).sum::<u64>(),
        "payouts_total": pool.payouts.iter().filter(|p| p.status != "returned").count(),
        "port": pool.cfg.listen.port(),
        "maturity": net.maturity,
        "tickets_per_s": total_rate,
        "network_tickets_per_s": net_rate,
        "difficulty": difficulty,
        "devices": per_dev.values().filter(|r| **r > 0.0).count(),
        "history": pool.history.iter().map(|h| json!([h.0, h.1, h.2, h.3])).collect::<Vec<_>>(),
        "hourly": hourly(st, pool, t, None),
        // the network around the pool: addresses and transactions on the best chain
        "network": {
            "addresses_holding": st.chain.holder_count(),
            "addresses_used": st.index.address_count(),
            "transactions": st.index.tx_count(),
            "transfers": st.index.tx_count().saturating_sub(tip as usize + 1),
            "height": tip,
        },
        "miners": miners,
        "blocks": pool.found.iter().rev().take(50).map(|f| json!({"height": f.height, "id": hex(&f.id), "time": f.time,
            "finder": address(net, &f.finder), "reward": f.reward, "status": f.status, "effort": f.effort,
            "confirmations": (tip + 1).saturating_sub(f.height)})).collect::<Vec<_>>(),
        "payouts": pool.payouts.iter().rev().take(50).map(|p| json!({"txid": hex(&p.txid), "time": p.time,
            "total": p.total, "outputs": p.outputs, "status": p.status})).collect::<Vec<_>>(),
    }))
}

/// One address in the pool, for the `minerstats` method and the explorer's miner page: rate and history,
/// devices, balance, maturing credits, payouts. `known` is false for an address the pool has not seen.
pub fn miner_stats(st: &State, owner: &Hash) -> Option<Value> {
    let pool = st.pool.as_ref()?;
    let net = &st.chain.net;
    let t = now();
    let (per_addr, per_dev) = rates(pool, t);
    let pool_rate: f64 = per_addr.values().sum();
    let rate = per_addr.get(owner).copied().unwrap_or(0.0);
    let mut workers: Vec<Value> = pool
        .workers
        .iter()
        .filter(|((m, _), _)| m == owner)
        .map(|((_, w), ws)| {
            json!({"name": w, "tickets_per_s": per_dev.get(&(*owner, w.clone())).copied().unwrap_or(0.0),
                   "shares": ws.shares, "rejected": ws.rejected, "last_share": ws.last})
        })
        .collect();
    workers.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let payouts: Vec<Value> = pool
        .payouts
        .iter()
        .rev()
        .filter_map(|p| {
            let amount: u64 = p.paid.iter().filter(|(m, _)| m == owner).map(|(_, a)| a).sum();
            (amount > 0).then(|| json!({"txid": hex(&p.txid), "time": p.time, "amount": amount, "status": p.status}))
        })
        .take(100)
        .collect();
    Some(json!({
        "address": address(net, owner),
        "known": pool.miners.contains_key(owner),
        "tickets_per_s": rate,
        "share_of_pool": if pool_rate > 0.0 { rate / pool_rate } else { 0.0 },
        "balance": pool.balances.get(owner).copied().unwrap_or(0),
        "immature": immature_by_miner(pool).get(owner).copied().unwrap_or(0),
        "paid": pool.miners.get(owner).map(|s| s.paid).unwrap_or(0),
        "min_payout_atoms": pool.cfg.min_payout,
        "payout_every_s": pool.cfg.payout_every,
        "blocks_found": pool.found.iter().filter(|f| f.finder == *owner && f.status != "orphaned").count(),
        "workers": workers,
        "history": pool.miner_history.get(owner).map(|h| h.iter().map(|(t, r)| json!([t, r])).collect::<Vec<_>>()).unwrap_or_default(),
        "payouts": payouts,
        "hourly": hourly(st, pool, t, Some(owner)),
    }))
}

/// Serve the pool's public JSON-RPC and run its maintenance (maturity, payouts) every few seconds.
pub fn serve(shared: Shared, addr: SocketAddr) -> std::io::Result<SocketAddr> {
    let s2 = shared.clone();
    let handler: Handler = Arc::new(move |method: &str, params: &[Value]| match method {
        "getwork" => getwork(&s2),
        "submitwork" => submitwork(&s2, params),
        "getinfo" => {
            let st = s2.lock().unwrap();
            Ok(
                json!({"tip": hex(&st.chain.tip()), "height": st.chain.height(), "network": st.chain.net.name, "pool": true}),
            )
        }
        "poolstats" => stats(&s2.lock().unwrap()).ok_or_else(|| "pool disabled".to_string()),
        "minerstats" => {
            let who = params.first().and_then(|v| v.as_str()).ok_or("address or key hash expected")?;
            let st = s2.lock().unwrap();
            let owner = requant_consensus::address::parse_address(&st.chain.net, who)
                .ok()
                .or_else(|| h32(&json!(who)))
                .ok_or("not an address or key hash")?;
            miner_stats(&st, &owner).ok_or_else(|| "pool disabled".to_string())
        }
        _ => Err(format!("unknown method {method}")),
    });
    let at = serve_with(addr, vec![], 64 << 10, 64, handler)?;
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let mut st = shared.lock().unwrap();
        with_pool(&mut st, maintain);
    });
    Ok(at)
}
