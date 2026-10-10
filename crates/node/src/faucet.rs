//! Test-network faucet (`--faucet-key`): the explorer's /faucet page sends a fixed amount to an address,
//! at most once a day per address and per client address, within a daily total. Coins come from the
//! faucet key's outputs, confirmed or still in the mempool (so requests within one block chain on the
//! change).

use crate::node::{now, State};
use crate::rpc::{hex, unhex};
use ed25519_dalek::SigningKey;
use requant_consensus::tx::{pkh, Hash, Input, OutPoint, Output, Tx};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;

const DAY: u64 = 86_400;

#[derive(Clone)]
pub struct FaucetConfig {
    /// Secret key of the faucet wallet.
    pub key: [u8; 32],
    /// Atoms per request.
    pub amount: u64,
    /// Atoms handed out per day at most.
    pub daily: u64,
}

pub struct Faucet {
    pub cfg: FaucetConfig,
    key: SigningKey,
    pub owner: Hash,
    last_ip: HashMap<IpAddr, u64>,
    last_to: HashMap<Hash, u64>,
    day: u64,
    pub given_today: u64,
    /// Recent payments: (time, recipient, txid), newest last.
    pub recent: Vec<(u64, Hash, Hash)>,
    /// Where limits and history are kept across restarts.
    path: std::path::PathBuf,
}

impl Faucet {
    pub fn new(cfg: FaucetConfig, path: std::path::PathBuf) -> Faucet {
        let key = SigningKey::from_bytes(&cfg.key);
        let owner = pkh(&key.verifying_key().to_bytes());
        let mut f = Faucet {
            cfg,
            key,
            owner,
            last_ip: HashMap::new(),
            last_to: HashMap::new(),
            day: 0,
            given_today: 0,
            recent: Vec::new(),
            path,
        };
        f.load();
        f
    }

    fn save(&self) {
        let v = json!({
            "day": self.day,
            "given_today": self.given_today,
            "last_ip": self.last_ip.iter().map(|(ip, t)| (ip.to_string(), json!(t))).collect::<serde_json::Map<_, _>>(),
            "last_to": self.last_to.iter().map(|(m, t)| (hex(m), json!(t))).collect::<serde_json::Map<_, _>>(),
            "recent": self.recent.iter().map(|(t, to, id)| json!([t, hex(to), hex(id)])).collect::<Vec<_>>(),
        });
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, v.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }

    fn load(&mut self) {
        let Some(v) = std::fs::read_to_string(&self.path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok())
        else {
            return;
        };
        let h32 = |s: &str| -> Option<Hash> { unhex(s).ok()?.try_into().ok() };
        self.day = v["day"].as_u64().unwrap_or(0);
        self.given_today = v["given_today"].as_u64().unwrap_or(0);
        for (k, t) in v["last_ip"].as_object().into_iter().flatten() {
            if let (Ok(ip), Some(t)) = (k.parse(), t.as_u64()) {
                self.last_ip.insert(ip, t);
            }
        }
        for (k, t) in v["last_to"].as_object().into_iter().flatten() {
            if let (Some(m), Some(t)) = (h32(k), t.as_u64()) {
                self.last_to.insert(m, t);
            }
        }
        for r in v["recent"].as_array().into_iter().flatten() {
            if let (Some(t), Some(to), Some(id)) =
                (r[0].as_u64(), r[1].as_str().and_then(h32), r[2].as_str().and_then(h32))
            {
                self.recent.push((t, to, id));
            }
        }
    }
}

/// Spendable faucet coins: confirmed (mature, not spent by a pooled transaction) and pooled change.
pub fn coins(st: &State, owner: &Hash) -> Vec<(OutPoint, u64)> {
    let next = st.chain.height() + 1;
    let maturity = st.chain.net.maturity;
    let mut v: Vec<(OutPoint, u64)> = st
        .chain
        .coins_of(owner)
        .into_iter()
        .filter(|(op, c)| (!c.coinbase || next - c.height >= maturity) && !st.mempool.is_spent(op))
        .map(|(op, c)| (op, c.output.value))
        .collect();
    v.extend(st.mempool.pending_outputs(owner).into_iter().map(|(op, o)| (op, o.value)));
    v
}

/// Send the faucet amount to `to` for a request from `ip`; returns the txid.
pub fn request(st: &mut State, ip: IpAddr, to: Hash) -> Result<Hash, String> {
    let mut f = st.faucet.take().ok_or("this node runs no faucet")?;
    let r = pay(st, &mut f, ip, to);
    st.faucet = Some(f);
    r
}

fn pay(st: &mut State, f: &mut Faucet, ip: IpAddr, to: Hash) -> Result<Hash, String> {
    let t = now();
    if t / DAY != f.day {
        f.day = t / DAY;
        f.given_today = 0;
        f.last_ip.retain(|_, at| t - *at < DAY);
        f.last_to.retain(|_, at| t - *at < DAY);
    }
    let wait = |at: Option<&u64>| at.map(|a| DAY.saturating_sub(t - a)).filter(|w| *w > 0);
    if let Some(w) = wait(f.last_ip.get(&ip)).or(wait(f.last_to.get(&to))) {
        return Err(format!("one request a day; try again in {} h {} min", w / 3600, w / 60 % 60));
    }
    if to == f.owner {
        return Err("that is the faucet's own address".into());
    }
    if f.given_today + f.cfg.amount > f.cfg.daily {
        return Err("today's faucet budget is spent; try again tomorrow".into());
    }
    let mut coins = coins(st, &f.owner);
    coins.sort_by_key(|c| std::cmp::Reverse(c.1));
    let fee_of = |inputs: usize| 1_000 + 200 * (inputs + 2) as u64;
    let (mut chosen, mut total) = (Vec::new(), 0u64);
    for c in coins.into_iter().take(500) {
        if total >= f.cfg.amount + fee_of(chosen.len()) {
            break;
        }
        total += c.1;
        chosen.push(c.0);
    }
    let fee = fee_of(chosen.len());
    if total < f.cfg.amount + fee {
        return Err("the faucet is empty for now".into());
    }
    let mut outputs = vec![Output { value: f.cfg.amount, pkh: to }];
    if total > f.cfg.amount + fee {
        outputs.push(Output { value: total - f.cfg.amount - fee, pkh: f.owner });
    }
    let inputs = chosen.iter().map(|op| Input::new(*op)).collect();
    let mut tx = Tx::Transfer { inputs, outputs };
    let keys: Vec<&SigningKey> = chosen.iter().map(|_| &f.key).collect();
    tx.sign(&st.chain.net.chain_id, &keys);
    let txid = st.process_tx(tx, None).map_err(|e| format!("could not send: {e}"))?;
    f.last_ip.insert(ip, t);
    f.last_to.insert(to, t);
    f.given_today += f.cfg.amount;
    f.recent.push((t, to, txid));
    if f.recent.len() > 20 {
        f.recent.remove(0);
    }
    f.save();
    Ok(txid)
}
