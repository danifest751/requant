//! JSON-RPC over HTTP: `POST /` with a request object or a batch (an array of up to `MAX_BATCH`).
//!
//! A JSON-RPC 2.0 request (`"jsonrpc": "2.0"`) gets a 2.0 answer: `{"jsonrpc", "id", "result"}` or
//! `{"jsonrpc", "id", "error": {"code", "message"}}` with the standard codes (-32700 parse error, -32600
//! invalid request, -32601 unknown method, -32602 invalid parameters, -32000 for the node's own errors);
//! one without an `id` is a notification and gets no answer. A request without `"jsonrpc"` (the older form
//! used by miners and tools) is answered as before: `{"result": ..., "error": null | "message", "id"}`.
//! Parameters are positional.
//!
//! Bind it to localhost. With tokens configured (`--rpc-token-file`, `--rpc-cookie`), requests must carry
//! `Authorization: Bearer <token>`; clients here read it from `REQUANT_RPC_TOKEN` or the cookie file named
//! by `REQUANT_RPC_COOKIE`.

use crate::node::{agent, now, Shared, VERSION};
use requant_consensus::block::Claim;
use requant_consensus::tx::{Hash, Tx};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

const MAX_BODY: usize = 4 << 20;
/// Requests in one batch.
const MAX_BATCH: usize = 100;
/// How long a `getwork` long poll waits for a new block.
const LONG_POLL: std::time::Duration = std::time::Duration::from_secs(60);

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..s.len() / 2).map(|k| u8::from_str_radix(&s[2 * k..2 * k + 2], 16).map_err(|_| "bad hex".to_string())).collect()
}

fn hash_param(v: &Value) -> Result<Hash, String> {
    unhex(v.as_str().ok_or("expected a hex string")?)?.try_into().map_err(|_| "expected 32 bytes".to_string())
}

fn u64_param(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| "expected an integer".to_string())
}

pub fn serve(shared: Shared, addr: SocketAddr, tokens: Vec<String>) -> io::Result<SocketAddr> {
    let handler: Handler = Arc::new(move |method: &str, params: &[Value]| call(&shared, method, params));
    serve_with(addr, tokens, MAX_BODY, usize::MAX, handler)
}

/// A JSON-RPC method dispatcher.
pub type Handler = Arc<dyn Fn(&str, &[Value]) -> Result<Value, String> + Send + Sync>;

/// Serve JSON-RPC over HTTP with `handler`, at most `max_active` requests at once and `max_body` bytes
/// per request; with tokens, requests must carry one of them.
pub fn serve_with(
    addr: SocketAddr,
    tokens: Vec<String>,
    max_body: usize,
    max_active: usize,
    handler: Handler,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            if active.fetch_add(1, SeqCst) >= max_active {
                active.fetch_sub(1, SeqCst);
                continue;
            }
            let (tokens, handler, active) = (tokens.clone(), handler.clone(), active.clone());
            std::thread::spawn(move || {
                let _ = handle(s, &tokens, max_body, &handler);
                active.fetch_sub(1, SeqCst);
            });
        }
    });
    Ok(local)
}

thread_local! {
    static CLIENT: std::cell::Cell<Option<IpAddr>> = const { std::cell::Cell::new(None) };
}

/// Address of the client whose request the current thread is answering (each request has its own thread).
pub fn client_ip() -> Option<IpAddr> {
    CLIENT.with(|c| c.get())
}

/// Constant-time comparison for the token.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The JSON-RPC 2.0 error code of a handler's error message.
fn code(e: &str) -> i64 {
    if e.starts_with("unknown method") {
        -32601
    } else if e.starts_with("missing parameter") || e.starts_with("expected") || e.contains("parameter") {
        -32602
    } else {
        -32000
    }
}

fn error2(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Answer one request object; `None` for a notification.
fn one(req: &Value, handler: &Handler) -> Option<Value> {
    let v2 = req.get("jsonrpc").and_then(Value::as_str) == Some("2.0");
    let id = req.get("id").cloned();
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return Some(if v2 {
            error2(id.unwrap_or(Value::Null), -32600, "invalid request: no method")
        } else {
            json!({"result": null, "error": "invalid request: no method", "id": id})
        });
    };
    let empty = vec![];
    let params = match req.get("params") {
        None | Some(Value::Null) => Ok(&empty),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err("parameters must be an array (positional)"),
    };
    let r = params.map_err(str::to_string).and_then(|p| handler(method, p));
    if !v2 {
        return Some(match r {
            Ok(r) => json!({"result": r, "error": null, "id": id}),
            Err(e) => json!({"result": null, "error": e, "id": id}),
        });
    }
    let id = id?;
    Some(match r {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err(e) => error2(id, code(&e), &e),
    })
}

fn handle(stream: TcpStream, tokens: &[String], max_body: usize, handler: &Handler) -> io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    CLIENT.with(|c| c.set(stream.peer_addr().ok().map(|a| a.ip())));
    let mut reader = BufReader::new(stream.try_clone()?);
    let (mut len, mut auth) = (0usize, None::<String>);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        let lower = l.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("authorization:") {
            auth = l["authorization:".len()..].trim().strip_prefix("Bearer ").map(|s| s.trim().to_string());
        }
    }
    if !tokens.is_empty() && !auth.as_deref().is_some_and(|a| tokens.iter().any(|t| same(a, t))) {
        // HTTP 401, with a body either kind of client reads
        let body = json!({"jsonrpc": "2.0", "id": null, "result": null, "error": "unauthorized"});
        return respond(stream, "401 Unauthorized", Some(&body));
    }
    if len > max_body {
        return respond(stream, "413 Payload Too Large", Some(&json!({"result": null, "error": "request too large"})));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    let reply = match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Array(reqs)) => {
            if reqs.is_empty() || reqs.len() > MAX_BATCH {
                Some(error2(Value::Null, -32600, &format!("a batch holds 1 to {MAX_BATCH} requests")))
            } else {
                let answers: Vec<Value> = reqs.iter().filter_map(|r| one(r, handler)).collect();
                (!answers.is_empty()).then_some(Value::Array(answers))
            }
        }
        Ok(req) => one(&req, handler),
        Err(_) => Some(json!({"result": null, "error": "invalid JSON", "jsonrpc": "2.0", "id": null})),
    };
    match reply {
        Some(v) => respond(stream, "200 OK", Some(&v)),
        None => respond(stream, "204 No Content", None),
    }
}

fn respond(mut stream: TcpStream, status: &str, v: Option<&Value>) -> io::Result<()> {
    let body = v.map(|v| v.to_string()).unwrap_or_default();
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A transaction as RPC shows it: inputs with the values and owners of the coins they spend (from the
/// index or the pool), outputs, fee, and where it is (`height`: `None` while pooled or not yet sent).
pub(crate) fn tx_json(st: &crate::node::State, tx: &Tx, height: Option<u64>) -> Value {
    let tip = st.chain.height();
    let mut total_in = 0u64;
    let inputs: Vec<Value> = match tx {
        Tx::Transfer { inputs, .. } => inputs
            .iter()
            .map(|i| {
                let out = st.index.output(&i.prev).or_else(|| {
                    st.mempool.get(&i.prev.txid).and_then(|t| t.outputs().get(i.prev.vout as usize).copied())
                });
                total_in += out.map(|o| o.value).unwrap_or(0);
                let mut v = json!({"txid": hex(&i.prev.txid), "vout": i.prev.vout,
                       "value": out.map(|o| o.value), "owner": out.map(|o| hex(&o.pkh))});
                if !i.is_plain() {
                    // a kind-2 input: its locks and how it unlocks the coin (CHAIN.md §4.1)
                    use requant_consensus::tx::Unlock;
                    let unlock = match &i.unlock {
                        Unlock::Key => json!({"kind": "key"}),
                        Unlock::Multi2 { pubkey2, .. } => json!({"kind": "multi2", "pubkey2": hex(pubkey2)}),
                        Unlock::HtlcClaim { htlc, preimage } => {
                            json!({"kind": "htlc-claim", "hash": hex(&htlc.hash), "preimage": hex(preimage), "timeout": htlc.timeout})
                        }
                        Unlock::HtlcRefund { htlc } => {
                            json!({"kind": "htlc-refund", "hash": hex(&htlc.hash), "timeout": htlc.timeout})
                        }
                        Unlock::DelayedOwner { d } => {
                            json!({"kind": "delayed-owner", "owner": hex(&d.owner), "revoke": hex(&d.revoke), "delay": d.delay})
                        }
                        Unlock::DelayedRevoke { d } => {
                            json!({"kind": "delayed-revoke", "owner": hex(&d.owner), "revoke": hex(&d.revoke), "delay": d.delay})
                        }
                        Unlock::RevocableClaim { h, preimage } => json!({"kind": "revocable-claim", "hash": hex(&h.hash),
                            "preimage": hex(preimage), "timeout": h.timeout, "claim_delay": h.claim_delay}),
                        Unlock::RevocableRefund { h } => json!({"kind": "revocable-refund", "hash": hex(&h.hash),
                            "timeout": h.timeout, "refund_delay": h.refund_delay}),
                        Unlock::RevocableRevoke { h } => json!({"kind": "revocable-revoke", "hash": hex(&h.hash)}),
                    };
                    v["anyone_can_pay"] = json!(i.anyone_can_pay);
                    v["after_height"] = json!(i.after_height);
                    v["after_blocks"] = json!(i.after_blocks);
                    v["unlock"] = unlock;
                }
                v
            })
            .collect(),
        Tx::Coinbase { .. } => vec![],
    };
    let outputs: Vec<Value> = tx.outputs().iter().map(|o| json!({"value": o.value, "owner": hex(&o.pkh)})).collect();
    let total_out: u64 = tx.outputs().iter().map(|o| o.value).sum();
    let size = tx.encode().len();
    json!({
        "txid": hex(&tx.txid()), "coinbase": tx.is_coinbase(), "height": height,
        "confirmations": height.map(|h| tip - h + 1).unwrap_or(0),
        "inputs": inputs, "outputs": outputs, "size": size,
        "fee": if tx.is_coinbase() { 0 } else { total_in.saturating_sub(total_out) },
        "hex": hex(&tx.encode()),
    })
}

/// Spendable coins of `owner`: confirmed unspent outputs (minus those spent by pooled transactions) and
/// unconfirmed outputs of pooled transactions; both are spendable by a new transaction.
pub(crate) fn utxos_of(st: &crate::node::State, owner: &Hash) -> Vec<Value> {
    let next = st.chain.height() + 1;
    let maturity = st.chain.net.maturity;
    let mut v: Vec<Value> = st
        .chain
        .coins_of(owner)
        .into_iter()
        .filter(|(op, _)| !st.mempool.is_spent(op))
        .map(|(op, c)| {
            json!({
                "txid": hex(&op.txid), "vout": op.vout, "value": c.output.value, "height": c.height,
                "coinbase": c.coinbase, "confirmed": true,
                "spendable": !c.coinbase || next - c.height >= maturity,
            })
        })
        .collect();
    for (op, o) in st.mempool.pending_outputs(owner) {
        v.push(json!({"txid": hex(&op.txid), "vout": op.vout, "value": o.value, "height": null,
                      "coinbase": false, "confirmed": false, "spendable": true}));
    }
    v
}

/// Confirmed, unconfirmed (spendable) and immature amounts of `owner`.
pub(crate) fn balance_of(st: &crate::node::State, owner: &Hash) -> Value {
    let (mut confirmed, mut unconfirmed, mut immature) = (0u64, 0u64, 0u64);
    for c in utxos_of(st, owner) {
        let v = c["value"].as_u64().unwrap_or(0);
        match (c["spendable"] == true, c["confirmed"] == true) {
            (false, _) => immature += v,
            (true, false) => unconfirmed += v,
            (true, true) => confirmed += v,
        }
    }
    json!({"confirmed": confirmed, "unconfirmed": unconfirmed, "immature": immature})
}

/// `owner`'s transactions, newest first (pooled ones first): received and sent per transaction.
pub(crate) fn history_of(st: &crate::node::State, owner: &Hash, limit: usize) -> Vec<Value> {
    let tip = st.chain.height();
    let mut v: Vec<Value> = st
        .mempool
        .activity(&st.chain, owner)
        .into_iter()
        .rev()
        .map(|(txid, r, s, _)| {
            json!({"txid": hex(&txid), "height": null, "confirmations": 0, "time": null, "received": r, "sent": s})
        })
        .collect();
    for e in st.index.history(owner, limit) {
        let time = st.chain.active_id(e.height).and_then(|id| st.chain.block(&id)).map(|b| b.header.time);
        v.push(json!({"txid": hex(&e.txid), "height": e.height, "confirmations": tip - e.height + 1,
                      "time": time, "received": e.received, "sent": e.sent}));
    }
    v.truncate(limit);
    v
}

/// Owners asked about in one call, at most.
pub(crate) const MAX_OWNERS: usize = 200;

/// One owner (a hex key hash) or a list of them (`utxos`, `history` for a whole wallet in one call).
fn owners_param(v: &Value) -> Result<Option<Vec<Hash>>, String> {
    match v.as_array() {
        None => Ok(None),
        Some(a) if a.len() > MAX_OWNERS => Err(format!("expected at most {MAX_OWNERS} key hashes")),
        Some(a) => a.iter().map(hash_param).collect::<Result<_, _>>().map(Some),
    }
}

/// `f` of each owner, flattened, every entry marked with its `owner`.
pub(crate) fn per_owner(owners: &[Hash], mut f: impl FnMut(&Hash) -> Vec<Value>) -> Vec<Value> {
    let mut all = Vec::new();
    for o in owners {
        for mut e in f(o) {
            e["owner"] = json!(hex(o));
            all.push(e);
        }
    }
    all
}

/// A block id from a height or a hex id.
fn block_param(st: &crate::node::State, v: &Value) -> Result<Hash, String> {
    match v.as_u64() {
        Some(h) => st.chain.active_id(h).ok_or_else(|| "no block at that height".to_string()),
        None => {
            let id = hash_param(v)?;
            st.chain.header(&id).map(|_| id).ok_or_else(|| "unknown block".to_string())
        }
    }
}

/// Wait, without holding the node's lock, until the best tip is no longer the block `longpollid` (hex) or
/// `LONG_POLL` has passed.
pub fn long_poll(shared: &Shared, longpollid: &str) {
    let since = std::time::Instant::now();
    while hex(&shared.lock().unwrap().chain.tip()) == longpollid && since.elapsed() < LONG_POLL {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn call(shared: &Shared, method: &str, p: &[Value]) -> Result<Value, String> {
    let arg = |k: usize| p.get(k).ok_or_else(|| format!("missing parameter {k}"));
    // long poll: `getwork payee <longpollid>` waits until the tip is no longer that block
    if method == "getwork" {
        if let Some(lp) = p.get(1).and_then(Value::as_str) {
            long_poll(shared, lp);
        }
    }
    let mut st = shared.lock().unwrap();
    match method {
        "getinfo" => {
            let peers = st.peers();
            let outbound = peers.iter().filter(|p| p.outbound).count();
            Ok(json!({
                "version": VERSION,
                "agent": agent(),
                "network": st.chain.net.name,
                "height": st.chain.height(),
                "headers": st.headers.height(),
                "tip": hex(&st.chain.tip()),
                "chainwork": hex(&st.chain.tip_work().to_be_bytes()),
                "load": crate::load::pressure().map(|p| json!({"cpu_per_core": p.cpu, "memory_free": p.mem_free, "busy": st.busy})),
                "uploaded_bytes": st.uploaded(),
                "bodies_in_memory": st.chain.bodies_in_memory(),
                "snapshot_height": st.restored,
                "update_available": st.release.as_ref().filter(|r| r.version > crate::release::own_version())
                    .map(|r| r.version_string()),
                "issued_atoms": st.chain.issued(),
                "peers": peers.len(),
                "outbound": outbound,
                "known_addresses": st.book.len(),
                "mempool": st.mempool.len(),
                "mempool_bytes": st.mempool.bytes(),
                "indexed_txs": st.index.tx_count(),
                "uptime_s": now().saturating_sub(st.started),
            }))
        }
        // the supply audit: what the UTXO set holds against what the emission allows, and the set's hash
        "auditsupply" => Ok(crate::node::supply_audit(&st)),
        // what the watchman found, newest first
        "getevents" => Ok(json!(st
            .events
            .list
            .iter()
            .rev()
            .map(|e| json!({"time": e.time, "level": e.level.name(),
            "text": e.text}))
            .collect::<Vec<_>>())),
        // the newest signed release this node knows, and whether it is newer than this node
        "getrelease" => Ok(match &st.release {
            Some(r) => json!({"version": r.version_string(), "newer": r.version > crate::release::own_version(),
                "manifest": r.text, "signature": hex(&r.sig), "platform": crate::release::platform(),
                "auto_update": st.auto_update}),
            None => json!(null),
        }),
        // publish a signed release manifest: verified, kept, passed to every peer
        "submitrelease" => {
            let text = arg(0)?.as_str().ok_or("manifest text expected")?;
            let sig: [u8; 64] = unhex(arg(1)?.as_str().ok_or("signature hex expected")?)?
                .try_into()
                .map_err(|_| "signature must be 64 bytes")?;
            let r = crate::release::Release::verify_with(text, &sig, &st.release_key).map_err(|e| e.to_string())?;
            let version = r.version_string();
            let new = st.take_release(r);
            if new {
                st.relay_release(None);
            }
            Ok(json!({"version": version, "new": new}))
        }
        "getblock" => {
            let id = block_param(&st, arg(0)?)?;
            let b = st.chain.block(&id).ok_or("block body not stored")?;
            let h = b.header.height;
            let txids: Vec<String> = b.txs.iter().map(|t| hex(&t.txid())).collect();
            Ok(
                json!({"id": hex(&id), "height": h, "time": b.header.time, "target": hex(&b.header.target.to_be_bytes()),
                      "prev": hex(&b.header.prev), "best_chain": st.chain.active_id(h) == Some(id),
                      "txs": b.txs.len(), "txids": txids, "hex": hex(&b.encode())}),
            )
        }
        "getblockhash" => {
            let h = u64_param(arg(0)?)?;
            st.chain.active_id(h).map(|id| json!(hex(&id))).ok_or_else(|| "no block at that height".into())
        }
        "getblockheader" => {
            let id = block_param(&st, arg(0)?)?;
            let hd = st.chain.header(&id).unwrap();
            let on_best = st.chain.active_id(hd.height) == Some(id);
            let next = if on_best { st.chain.active_id(hd.height + 1).map(|n| hex(&n)) } else { None };
            Ok(json!({
                "id": hex(&id), "height": hd.height, "time": hd.time, "prev": hex(&hd.prev), "next": next,
                "target": hex(&hd.target.to_be_bytes()), "best_chain": on_best,
                "confirmations": if on_best { st.chain.height() - hd.height + 1 } else { 0 },
                "header": hex(&hd.encode()),
            }))
        }
        "getchaintips" => Ok(json!(st
            .chain
            .tips()
            .into_iter()
            .map(|(id, h, status, branch)| json!({"id": hex(&id), "height": h, "status": status, "branch_length": branch}))
            .collect::<Vec<_>>())),
        "getrawmempool" => {
            let verbose = p.first().and_then(Value::as_bool).unwrap_or(false);
            Ok(json!(st
                .mempool
                .list()
                .into_iter()
                .map(|(id, fee, size)| {
                    if verbose {
                        json!({"txid": hex(&id), "fee": fee, "size": size, "feerate": fee / size.max(1) as u64})
                    } else {
                        json!(hex(&id))
                    }
                })
                .collect::<Vec<_>>()))
        }
        "getmempoolinfo" => Ok(json!({
            "size": st.mempool.len(), "bytes": st.mempool.bytes(), "max_bytes": st.mempool.max_bytes(),
            "min_feerate": crate::mempool::MIN_FEE_RATE, "max_tx_bytes": crate::mempool::MAX_TX_BYTES,
        })),
        "estimatefee" => {
            // the rate that keeps a new transaction within the next `blocks` blocks' worth of the pool
            let blocks = p.first().map(u64_param).transpose()?.unwrap_or(3);
            if !(1..=100).contains(&blocks) {
                return Err("expected 1 to 100 blocks".into());
            }
            let ahead = crate::node::TEMPLATE_TX_BYTES * blocks as usize;
            Ok(json!({
                "feerate": st.mempool.rate_for(ahead), "blocks": blocks, "pool_bytes": st.mempool.bytes(),
                "min_feerate": crate::mempool::MIN_FEE_RATE,
            }))
        }
        "getnetworkinfo" => {
            let peers = st.peers();
            let outbound = peers.iter().filter(|p| p.outbound).count();
            Ok(json!({
                "agent": agent(), "version": VERSION, "protocol": crate::msg::PROTOCOL,
                "min_protocol": crate::msg::MIN_PROTOCOL, "network": st.chain.net.name,
                "listen_port": st.listen_port, "peers": peers.len(), "outbound": outbound,
                "inbound": peers.len() - outbound, "known_addresses": st.book.len(),
                "uploaded_bytes": st.uploaded(),
            }))
        }
        "conditionaddress" => {
            // the address that locks coins under a condition (CHAIN.md §4.1):
            // ["multi2", pubkey_a, pubkey_b] or ["htlc", sha256_hash, claim, refund, timeout_height]; from
            // CHAIN.md §4.2 also ["delayed", owner, revoke, delay_blocks] and
            // ["htlc-revocable", sha256_hash, claim, refund, revoke, timeout_height, claim_delay, refund_delay]
            // (claim, refund, owner and revoke: addresses or key hashes)
            use requant_consensus::tx::{multi2_owner, Delayed, Htlc, HtlcRevocable};
            let u32_arg = |v: &Value| -> Result<u32, String> {
                u64_param(v).and_then(|n| u32::try_from(n).map_err(|_| "expected a 32-bit number".to_string()))
            };
            let net = &st.chain.net;
            let who = |v: &Value| -> Result<Hash, String> {
                let s = v.as_str().ok_or("expected an address or key hash")?;
                requant_consensus::address::parse_address(net, s).or_else(|_| hash_param(v))
            };
            let owner = match arg(0)?.as_str() {
                Some("multi2") => multi2_owner(&hash_param(arg(1)?)?, &hash_param(arg(2)?)?),
                Some("htlc") => {
                    Htlc { hash: hash_param(arg(1)?)?, claim: who(arg(2)?)?, refund: who(arg(3)?)?, timeout: u64_param(arg(4)?)? }
                        .owner()
                }
                Some("delayed") => Delayed { owner: who(arg(1)?)?, revoke: who(arg(2)?)?, delay: u32_arg(arg(3)?)? }.owner_hash(),
                Some("htlc-revocable") => HtlcRevocable {
                    hash: hash_param(arg(1)?)?,
                    claim: who(arg(2)?)?,
                    refund: who(arg(3)?)?,
                    revoke: who(arg(4)?)?,
                    timeout: u64_param(arg(5)?)?,
                    claim_delay: u32_arg(arg(6)?)?,
                    refund_delay: u32_arg(arg(7)?)?,
                }
                .owner(),
                _ => return Err("expected parameter 0: multi2, htlc, delayed or htlc-revocable".into()),
            };
            Ok(json!({"key_hash": hex(&owner), "address": requant_consensus::address::address(net, &owner)}))
        }
        "validateaddress" => {
            let s = arg(0)?.as_str().ok_or("expected an address")?;
            let net = &st.chain.net;
            Ok(match requant_consensus::address::parse_address(net, s) {
                Ok(o) => json!({"valid": true, "address": requant_consensus::address::address(net, &o), "key_hash": hex(&o)}),
                Err(e) => json!({"valid": false, "error": e}),
            })
        }
        "decodetx" => {
            let tx = Tx::decode_exact(&unhex(arg(0)?.as_str().ok_or("expected hex")?)?).map_err(|e| e.to_string())?;
            let height = st.index.locate(&tx.txid()).map(|l| l.height);
            Ok(tx_json(&st, &tx, height))
        }
        "getbalance" => {
            let owner = hash_param(arg(0)?)?;
            Ok(balance_of(&st, &owner))
        }
        "stop" => {
            // only from this machine: a remote client must not be able to stop the node
            if !client_ip().is_some_and(|ip| ip.is_loopback()) {
                return Err("stop is only accepted from localhost".into());
            }
            crate::signal::request();
            Ok(json!("stopping"))
        }
        "gettx" => {
            let txid = hash_param(arg(0)?)?;
            let (tx, height) = match st.index.locate(&txid) {
                Some(loc) => (st.chain.block(&loc.block).unwrap().txs[loc.pos as usize].clone(), Some(loc.height)),
                None => (st.mempool.get(&txid).cloned().ok_or("unknown transaction")?, None),
            };
            Ok(tx_json(&st, &tx, height))
        }
        "history" => {
            let limit = p.get(1).and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            match owners_param(arg(0)?)? {
                Some(list) => Ok(json!(per_owner(&list, |o| history_of(&st, o, limit)))),
                None => Ok(json!(history_of(&st, &hash_param(arg(0)?)?, limit))),
            }
        }
        "getwork" => {
            let payee = hash_param(arg(0)?)?;
            let (b, seed) = st.new_work(&payee);
            let net = &st.chain.net;
            Ok(json!({
                "height": b.header.height,
                // pass it back as the second parameter to wait for the next block (long poll)
                "longpollid": hex(&b.header.prev),
                "header": hex(&b.header.encode()),
                "header_digest": hex(&b.header.digest(&net.chain_id)),
                "epoch_seed": hex(&seed),
                "target": hex(&b.header.target.to_be_bytes()),
                "tnet": {"n": net.tnet.n, "b": net.tnet.b, "L": net.tnet.layers, "w": net.tnet.w, "mult": net.tnet.mult},
            }))
        }
        "submitwork" => {
            let digest = hash_param(arg(0)?)?;
            let claim = Claim {
                nonce: u64_param(arg(1)?)?,
                i: u64_param(arg(2)?)? as u32,
                c: u64_param(arg(3)?)? as u32,
                piece: unhex(arg(4)?.as_str().ok_or("piece: expected hex")?)?.into_iter().map(|x| x as i8).collect(),
            };
            match st.submit_work(&digest, claim) {
                Ok(acc) => Ok(json!({"accepted": true, "result": format!("{acc:?}")})),
                Err(e) => Ok(json!({"accepted": false, "reason": e.to_string()})),
            }
        }
        "sendtx" => {
            let tx = Tx::decode_exact(&unhex(arg(0)?.as_str().ok_or("expected hex")?)?).map_err(|e| e.to_string())?;
            st.process_tx(tx, None).map(|id| json!(hex(&id))).map_err(|e| e.to_string())
        }
        "utxos" => match owners_param(arg(0)?)? {
            Some(list) => Ok(json!(per_owner(&list, |o| utxos_of(&st, o)))),
            None => Ok(json!(utxos_of(&st, &hash_param(arg(0)?)?))),
        },
        "getpeerinfo" | "peers" => {
            let v: Vec<Value> = st
                .peers()
                .iter()
                .map(|p| {
                    json!({"addr": p.addr.to_string(), "outbound": p.outbound, "listen": p.listen.map(|a| a.to_string()),
                           "agent": p.agent, "height": p.height, "connected_s": now().saturating_sub(p.since)})
                })
                .collect();
            Ok(json!(v))
        }
        "addpeer" => {
            let addr = arg(0)?.as_str().ok_or("expected host:port")?.to_string();
            drop(st);
            crate::node::connect(shared, &addr).map(|_| json!(true)).map_err(|e| e.to_string())
        }
        _ => Err(format!("unknown method {method}")),
    }
}

/// The token a client sends: `REQUANT_RPC_TOKEN`, else the contents of the cookie file named by
/// `REQUANT_RPC_COOKIE`.
fn client_token() -> Option<String> {
    if let Ok(t) = std::env::var("REQUANT_RPC_TOKEN") {
        return Some(t);
    }
    let path = std::env::var("REQUANT_RPC_COOKIE").ok()?;
    std::fs::read_to_string(path).ok().map(|t| t.trim().to_string())
}

/// Minimal client for tests and tools: one request per connection; sends the token if one is configured
/// (see `client_token`).
pub fn request(addr: SocketAddr, method: &str, params: Value) -> io::Result<Value> {
    let body = json!({"method": method, "params": params}).to_string();
    let auth = client_token().map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let mut s = TcpStream::connect(addr)?;
    write!(
        s,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    let json = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: Value = serde_json::from_str(json).map_err(io::Error::other)?;
    if !v["error"].is_null() {
        return Err(io::Error::other(v["error"].to_string()));
    }
    Ok(v["result"].clone())
}
