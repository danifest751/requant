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
use requant_consensus::tx::{pkh, Hash, Input, Output, Tx};
use requant_consensus::u256::U256;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
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
}

struct Payout {
    txid: Hash,
    time: u64,
    total: u64,
    outputs: usize,
}

pub struct Pool {
    cfg: PoolConfig,
    key: SigningKey,
    pub owner: Hash,
    path: PathBuf,
    jobs: Vec<Job>,
    seen: HashSet<(Hash, u64, u32, u32)>,
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
}

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
            window: VecDeque::new(),
            miners: HashMap::new(),
            workers: HashMap::new(),
            balances: HashMap::new(),
            immature: Vec::new(),
            found: Vec::new(),
            payouts: Vec::new(),
            last_payout: now(),
        };
        p.load();
        p
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
            "found": self.found.iter().map(|f| json!([f.height, hex(&f.id), f.time, hex(&f.finder), f.reward, f.status])).collect::<Vec<_>>(),
            "payouts": self.payouts.iter().map(|p| json!([hex(&p.txid), p.time, p.total, p.outputs])).collect::<Vec<_>>(),
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
                self.found.push(Found { height, id, time, finder, reward, status });
            }
        }
        for p in v["payouts"].as_array().into_iter().flatten() {
            if let (Some(txid), Some(time), Some(total), Some(outputs)) =
                (h32(&p[0]), p[1].as_u64(), p[2].as_u64(), p[3].as_u64())
            {
                self.payouts.push(Payout { txid, time, total, outputs: outputs as usize });
            }
        }
        self.last_payout = v["last_payout"].as_u64().unwrap_or(self.last_payout);
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

/// The current job, refreshed on a new tip or after `JOB_REFRESH` seconds.
fn current_job(st: &mut State, pool: &mut Pool) -> usize {
    let tip = st.chain.tip();
    let fresh = pool.jobs.last().is_some_and(|j| j.tip == tip && now().saturating_sub(j.created) < JOB_REFRESH);
    if !fresh {
        if pool.jobs.last().is_some_and(|j| j.tip != tip) {
            pool.jobs.clear();
            pool.seen.clear();
        }
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

    // 1. cheap checks under the lock
    let (epoch, threads, block, share_target, net) = {
        let mut st = shared.lock().unwrap();
        let tip = st.chain.tip();
        let r = with_pool(&mut st, |st, pool| -> Result<_, &'static str> {
            let j = pool.jobs.iter().find(|j| j.digest == digest && j.tip == tip).ok_or("stale")?;
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
            Ok((st.chain.epoch(&seed), st.headers.threads(), block, share_target, st.chain.net.clone()))
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
    });
    let h = tnet::ticket_hash(&piece, &digest, nonce, i, c);
    let is_block = tnet::meets_target(&h, &block.header.target.to_be_bytes());
    let mut height = None;
    if is_block {
        let mut b = block;
        b.claim = Claim { nonce, i, c, piece };
        let id = b.id(&net);
        let reward: u64 = b.txs[0].outputs().iter().filter(|o| with_owner(&st, o)).map(|o| o.value).sum();
        let work_ratio = u256_f64(&U256::work(&b.header.target)) / u256_f64(&U256::work(&share_target));
        if matches!(st.process_block(b.clone(), None), Ok(Some(_))) {
            height = Some(b.header.height);
            with_pool(&mut st, |_, pool| {
                let credits = pool.credits(reward, work_ratio);
                pool.immature.push(Credit { block: id, height: b.header.height, credits });
                pool.found.push(Found {
                    height: b.header.height,
                    id,
                    time: t,
                    finder: miner,
                    reward,
                    status: "immature",
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
        if on_chain && next - c.height < maturity {
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

    if now().saturating_sub(pool.last_payout) >= pool.cfg.payout_every {
        pool.last_payout = now();
        changed |= payout(st, pool);
    }
    if changed {
        pool.save();
    }
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
    match st.process_tx(tx, None) {
        Ok(txid) => {
            for o in &paid {
                if let Some(b) = pool.balances.get_mut(&o.pkh) {
                    *b -= o.value;
                }
                pool.miners.entry(o.pkh).or_default().paid += o.value;
            }
            pool.balances.retain(|_, a| *a > 0);
            pool.payouts.push(Payout { txid, time: now(), total, outputs: paid.len() });
            true
        }
        Err(e) => {
            eprintln!("pool: payout transaction refused: {e}");
            false
        }
    }
}

/// Statistics for the `poolstats` method and the explorer.
pub fn stats(st: &State) -> Option<Value> {
    let pool = st.pool.as_ref()?;
    let net = &st.chain.net;
    let t = now();
    let share_work = 2f64.powi(pool.cfg.share_bits as i32);
    let mut recent: HashMap<Hash, u64> = HashMap::new();
    let mut recent_w: HashMap<(Hash, &str), u64> = HashMap::new();
    for (m, at, w) in pool.window.iter().rev() {
        if t.saturating_sub(*at) > RATE_WINDOW {
            break;
        }
        *recent.entry(*m).or_default() += 1;
        *recent_w.entry((*m, w.as_str())).or_default() += 1;
    }
    let rate = |n: u64| n as f64 * share_work / RATE_WINDOW as f64;
    let mut immature: HashMap<Hash, u64> = HashMap::new();
    for c in &pool.immature {
        for (m, a) in &c.credits {
            *immature.entry(*m).or_default() += a;
        }
    }
    let mut miners: Vec<Value> = pool
        .miners
        .iter()
        .map(|(m, s)| {
            let mut workers: Vec<Value> = pool
                .workers
                .iter()
                .filter(|((wm, _), _)| wm == m)
                .map(|((_, w), ws)| {
                    json!({"name": w, "tickets_per_s": rate(recent_w.get(&(*m, w.as_str())).copied().unwrap_or(0)),
                           "shares": ws.shares, "rejected": ws.rejected, "last_share": ws.last})
                })
                .collect();
            workers.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            json!({"address": address(net, m), "tickets_per_s": rate(recent.get(m).copied().unwrap_or(0)), "shares": s.shares,
                   "rejected": s.rejected, "last_share": s.last, "balance": pool.balances.get(m).copied().unwrap_or(0),
                   "immature": immature.get(m).copied().unwrap_or(0), "paid": s.paid, "workers": workers})
        })
        .collect();
    miners.sort_by(|a, b| b["tickets_per_s"].as_f64().partial_cmp(&a["tickets_per_s"].as_f64()).unwrap());
    let total_rate: f64 = miners.iter().map(|m| m["tickets_per_s"].as_f64().unwrap_or(0.0)).sum();
    Some(json!({
        "address": address(net, &pool.owner),
        "fee_percent": pool.cfg.fee_bp as f64 / 100.0,
        "share_bits": pool.cfg.share_bits,
        "min_payout": format_amount(pool.cfg.min_payout),
        "min_payout_atoms": pool.cfg.min_payout,
        "port": pool.cfg.listen.port(),
        "maturity": net.maturity,
        "tickets_per_s": total_rate,
        "miners": miners,
        "blocks": pool.found.iter().rev().take(50).map(|f| json!({"height": f.height, "id": hex(&f.id), "time": f.time,
            "finder": address(net, &f.finder), "reward": f.reward, "status": f.status})).collect::<Vec<_>>(),
        "payouts": pool.payouts.iter().rev().take(50).map(|p| json!({"txid": hex(&p.txid), "time": p.time,
            "total": p.total, "outputs": p.outputs})).collect::<Vec<_>>(),
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
        _ => Err(format!("unknown method {method}")),
    });
    let at = serve_with(addr, None, 64 << 10, 64, handler)?;
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let mut st = shared.lock().unwrap();
        with_pool(&mut st, maintain);
    });
    Ok(at)
}
