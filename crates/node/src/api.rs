//! Public read-only API on the explorer's port, for wallets without their own node and for other services.
//! JSON over HTTP, open to any origin (CORS), rate-limited per client address:
//!
//! - `GET /api/info`: height, tip, network, version, pool size, fee estimate;
//! - `GET /api/fee?blocks=N`: `estimatefee` (default 3 blocks);
//! - `GET /api/block/<height|id>`: a block's header fields and txids;
//! - `GET /api/tx/<txid>`: a transaction with its inputs' values and owners (as RPC `gettx`);
//! - `GET /api/address/<address|key hash>/balance`, `/utxos`, `/history?limit=N`;
//! - `GET /api/utxos?owners=K1,K2,...`, `/api/history?owners=...&limit=N`: many key hashes at once (a
//!   wallet's addresses), every entry marked with its `owner`;
//! - `POST /api/tx` with the signed transaction in hex (the body, or `{"hex": ...}`): relays it; `{"txid"}`;
//! - `POST /api/package` with `{"hex": [parent, ..., child]}`: a transaction with unconfirmed parents that
//!   may pay below the minimum fee on their own (package relay); `{"txids"}` admitted.
//!
//! Answers are what this node sees: a remote wallet trusts the node for balances and history (it cannot
//! take coins: keys never leave the wallet), and the node learns which addresses it asks about.

use crate::node::Shared;
use crate::rpc::{hex, unhex};
use requant_consensus::address::parse_address;
use requant_consensus::tx::{Hash, Tx};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// A client's budget: `BURST` requests at once, refilled at `PER_SECOND`; a submitted transaction costs
/// `SEND_COST`.
const BURST: f64 = 120.0;
const PER_SECOND: f64 = 20.0;
const SEND_COST: f64 = 10.0;
/// Bytes accepted in a POST (a package is at most 200 kB, 400 kB in hex).
pub const MAX_POST: usize = 512 << 10;

static BUCKETS: Mutex<Option<HashMap<IpAddr, (f64, Instant)>>> = Mutex::new(None);

/// Take `cost` from the client's budget; false when it is spent.
fn allow(ip: IpAddr, cost: f64) -> bool {
    let mut g = BUCKETS.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    if map.len() > 10_000 {
        // forget clients whose budget has refilled
        map.retain(|_, (t, at)| *t + now.duration_since(*at).as_secs_f64() * PER_SECOND < BURST);
    }
    let (tokens, at) = map.entry(ip).or_insert((BURST, now));
    *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * PER_SECOND).min(BURST);
    *at = now;
    if *tokens < cost {
        return false;
    }
    *tokens -= cost;
    true
}

fn query(q: &str, key: &str) -> Option<u64> {
    q.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
}

fn owner(st: &crate::node::State, s: &str) -> Option<Hash> {
    parse_address(&st.chain.net, s).ok().or_else(|| unhex(s).ok()?.try_into().ok())
}

fn err(status: &'static str, msg: &str) -> (&'static str, Value) {
    (status, json!({"error": msg}))
}

/// The answer to `method path` from `ip`: an HTTP status and a JSON body.
pub fn answer(shared: &Shared, method: &str, path: &str, body: &[u8], ip: IpAddr) -> (&'static str, Value) {
    let post = method == "POST";
    let (path, q) = path.split_once('?').unwrap_or((path, ""));
    // many owners at once cost more than one
    let owners: Vec<&str> = q
        .split('&')
        .find_map(|kv| kv.strip_prefix("owners="))
        .map(|l| l.split(',').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let cost = if post { SEND_COST } else { 1.0 + owners.len() as f64 / 10.0 };
    if !allow(ip, cost) {
        return err("429 Too Many Requests", "too many requests; slow down");
    }
    let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    let mut st = shared.lock().unwrap();
    match (post, parts.as_slice()) {
        (false, ["", "api", "info"]) => (
            "200 OK",
            json!({
                "network": st.chain.net.name, "height": st.chain.height(), "tip": hex(&st.chain.tip()),
                "version": crate::node::VERSION, "mempool": st.mempool.len(),
                "feerate": st.mempool.rate_for(crate::node::TEMPLATE_TX_BYTES * 3),
            }),
        ),
        (false, ["", "api", "fee"]) => {
            let blocks = query(q, "blocks").unwrap_or(3).clamp(1, 100);
            let r = st.mempool.rate_for(crate::node::TEMPLATE_TX_BYTES * blocks as usize);
            ("200 OK", json!({"feerate": r, "blocks": blocks, "min_feerate": crate::mempool::MIN_FEE_RATE}))
        }
        (false, ["", "api", "block", key]) => {
            let id = match key.parse::<u64>() {
                Ok(h) => st.chain.active_id(h),
                Err(_) => unhex(key).ok().and_then(|b| b.try_into().ok()).filter(|id| st.chain.contains(id)),
            };
            let Some(id) = id else { return err("404 Not Found", "unknown block") };
            let Some(b) = st.chain.block(&id) else { return err("404 Not Found", "block body not stored") };
            let h = b.header.height;
            (
                "200 OK",
                json!({
                    "id": hex(&id), "height": h, "time": b.header.time, "prev": hex(&b.header.prev),
                    "target": hex(&b.header.target.to_be_bytes()), "best_chain": st.chain.active_id(h) == Some(id),
                    "confirmations": if st.chain.active_id(h) == Some(id) { st.chain.height() - h + 1 } else { 0 },
                    "txids": b.txs.iter().map(|t| hex(&t.txid())).collect::<Vec<_>>(),
                }),
            )
        }
        (false, ["", "api", "tx", txid]) => {
            let Some(txid) = unhex(txid).ok().and_then(|b| <Hash>::try_from(b).ok()) else {
                return err("400 Bad Request", "a txid is 64 hex digits");
            };
            let (tx, height) = match st.index.locate(&txid) {
                Some(loc) => (st.chain.block(&loc.block).unwrap().txs[loc.pos as usize].clone(), Some(loc.height)),
                None => match st.mempool.get(&txid) {
                    Some(t) => (t.clone(), None),
                    None => return err("404 Not Found", "unknown transaction"),
                },
            };
            ("200 OK", crate::rpc::tx_json(&st, &tx, height))
        }
        (false, ["", "api", "address", a, what]) => {
            let Some(o) = owner(&st, a) else { return err("400 Bad Request", "not an address or key hash") };
            match *what {
                "utxos" => ("200 OK", json!(crate::rpc::utxos_of(&st, &o))),
                "balance" => ("200 OK", crate::rpc::balance_of(&st, &o)),
                "history" => {
                    let limit = query(q, "limit").unwrap_or(100).clamp(1, 1000) as usize;
                    ("200 OK", json!(crate::rpc::history_of(&st, &o, limit)))
                }
                _ => err("404 Not Found", "unknown address view (balance, utxos, history)"),
            }
        }
        (false, ["", "api", view @ ("utxos" | "history")]) => {
            if owners.is_empty() || owners.len() > crate::rpc::MAX_OWNERS {
                return err("400 Bad Request", "owners=K1,K2,... (1 to 200 key hashes or addresses)");
            }
            let Some(list) = owners.iter().map(|s| owner(&st, s)).collect::<Option<Vec<Hash>>>() else {
                return err("400 Bad Request", "not an address or key hash in owners");
            };
            let limit = query(q, "limit").unwrap_or(100).clamp(1, 1000) as usize;
            let v = if *view == "utxos" {
                crate::rpc::per_owner(&list, |o| crate::rpc::utxos_of(&st, o))
            } else {
                crate::rpc::per_owner(&list, |o| crate::rpc::history_of(&st, o, limit))
            };
            ("200 OK", json!(v))
        }
        (true, ["", "api", "tx"]) => {
            let text = String::from_utf8_lossy(body);
            let hex_tx = match serde_json::from_str::<Value>(&text) {
                Ok(v) => v["hex"].as_str().map(str::to_string).unwrap_or_default(),
                Err(_) => text.trim().to_string(),
            };
            let tx = match unhex(&hex_tx)
                .map_err(|e| e.to_string())
                .and_then(|b| Tx::decode_exact(&b).map_err(|e| e.to_string()))
            {
                Ok(t) => t,
                Err(e) => return err("400 Bad Request", &format!("not a transaction: {e}")),
            };
            match st.process_tx(tx, None) {
                Ok(id) => ("200 OK", json!({"txid": hex(&id)})),
                Err(e) => err("422 Unprocessable Entity", &e.to_string()),
            }
        }
        (true, ["", "api", "package"]) => {
            let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let Some(list) = v["hex"].as_array() else {
                return err("400 Bad Request", "expected {\"hex\": [parent, ..., child]}");
            };
            let txs = match list
                .iter()
                .map(|h| {
                    unhex(h.as_str().unwrap_or_default())
                        .map_err(|e| e.to_string())
                        .and_then(|b| Tx::decode_exact(&b).map_err(|e| e.to_string()))
                })
                .collect::<Result<Vec<Tx>, String>>()
            {
                Ok(t) => t,
                Err(e) => return err("400 Bad Request", &format!("not a transaction: {e}")),
            };
            match st.process_package(txs, None) {
                Ok(ids) => ("200 OK", json!({"txids": ids.iter().map(|id| hex(id)).collect::<Vec<_>>()})),
                Err(e) => err("422 Unprocessable Entity", &e.to_string()),
            }
        }
        _ => err("404 Not Found", "unknown API path (see /api/info)"),
    }
}
