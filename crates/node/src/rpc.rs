//! JSON-RPC over HTTP: `POST /` with `{"method": ..., "params": [...]}`, answered by
//! `{"result": ..., "error": null}`. Bind it to localhost; with a token configured, requests must carry
//! `Authorization: Bearer <token>` (clients here read it from `REQUANT_RPC_TOKEN`).

use crate::node::{agent, now, Shared, VERSION};
use requant_consensus::block::Claim;
use requant_consensus::tx::{Hash, Tx};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

const MAX_BODY: usize = 4 << 20;

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

pub fn serve(shared: Shared, addr: SocketAddr, token: Option<String>) -> io::Result<SocketAddr> {
    let handler: Handler = Arc::new(move |method: &str, params: &[Value]| call(&shared, method, params));
    serve_with(addr, token, MAX_BODY, usize::MAX, handler)
}

/// A JSON-RPC method dispatcher.
pub type Handler = Arc<dyn Fn(&str, &[Value]) -> Result<Value, String> + Send + Sync>;

/// Serve JSON-RPC over HTTP with `handler`, at most `max_active` requests at once and `max_body` bytes
/// per request; with a token, requests must carry it.
pub fn serve_with(
    addr: SocketAddr,
    token: Option<String>,
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
            let (token, handler, active) = (token.clone(), handler.clone(), active.clone());
            std::thread::spawn(move || {
                let _ = handle(s, token, max_body, &handler);
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

fn handle(stream: TcpStream, token: Option<String>, max_body: usize, handler: &Handler) -> io::Result<()> {
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
    if let Some(t) = &token {
        if !auth.as_deref().is_some_and(|a| same(a, t)) {
            return respond(stream, &json!({"result": null, "error": "unauthorized"}));
        }
    }
    if len > max_body {
        return respond(stream, &json!({"result": null, "error": "request too large"}));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    let reply = match serde_json::from_slice::<Value>(&body) {
        Ok(req) => {
            let method = req["method"].as_str().unwrap_or("");
            let empty = vec![];
            let params = req["params"].as_array().unwrap_or(&empty);
            match handler(method, params) {
                Ok(r) => json!({"result": r, "error": null}),
                Err(e) => json!({"result": null, "error": e}),
            }
        }
        Err(_) => json!({"result": null, "error": "invalid JSON"}),
    };
    respond(stream, &reply)
}

fn respond(mut stream: TcpStream, v: &Value) -> io::Result<()> {
    let body = v.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn call(shared: &Shared, method: &str, p: &[Value]) -> Result<Value, String> {
    let arg = |k: usize| p.get(k).ok_or_else(|| format!("missing parameter {k}"));
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
            let h = u64_param(arg(0)?)?;
            let id = st.chain.active_id(h).ok_or("no block at that height")?;
            let b = st.chain.block(&id).unwrap();
            let txids: Vec<String> = b.txs.iter().map(|t| hex(&t.txid())).collect();
            Ok(
                json!({"id": hex(&id), "height": h, "time": b.header.time, "target": hex(&b.header.target.to_be_bytes()),
                      "txs": b.txs.len(), "txids": txids, "hex": hex(&b.encode())}),
            )
        }
        "gettx" => {
            let txid = hash_param(arg(0)?)?;
            let (tx, height) = match st.index.locate(&txid) {
                Some(loc) => (st.chain.block(&loc.block).unwrap().txs[loc.pos as usize].clone(), Some(loc.height)),
                None => (st.mempool.get(&txid).cloned().ok_or("unknown transaction")?, None),
            };
            let tip = st.chain.height();
            let mut total_in = 0u64;
            let inputs: Vec<Value> = match &tx {
                Tx::Transfer { inputs, .. } => inputs
                    .iter()
                    .map(|i| {
                        let out = st.index.output(&i.prev).or_else(|| {
                            st.mempool.get(&i.prev.txid).and_then(|t| t.outputs().get(i.prev.vout as usize).copied())
                        });
                        total_in += out.map(|o| o.value).unwrap_or(0);
                        json!({"txid": hex(&i.prev.txid), "vout": i.prev.vout,
                               "value": out.map(|o| o.value), "owner": out.map(|o| hex(&o.pkh))})
                    })
                    .collect(),
                Tx::Coinbase { .. } => vec![],
            };
            let outputs: Vec<Value> =
                tx.outputs().iter().map(|o| json!({"value": o.value, "owner": hex(&o.pkh)})).collect();
            let total_out: u64 = tx.outputs().iter().map(|o| o.value).sum();
            Ok(json!({
                "txid": hex(&txid), "coinbase": tx.is_coinbase(), "height": height,
                "confirmations": height.map(|h| tip - h + 1).unwrap_or(0),
                "inputs": inputs, "outputs": outputs,
                "fee": if tx.is_coinbase() { 0 } else { total_in.saturating_sub(total_out) },
                "hex": hex(&tx.encode()),
            }))
        }
        "history" => {
            let owner = hash_param(arg(0)?)?;
            let limit = p.get(1).and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            let tip = st.chain.height();
            let mut v: Vec<Value> = st
                .mempool
                .activity(&st.chain, &owner)
                .into_iter()
                .rev()
                .map(|(txid, r, s, _)| {
                    json!({"txid": hex(&txid), "height": null, "confirmations": 0, "time": null, "received": r, "sent": s})
                })
                .collect();
            for e in st.index.history(&owner, limit) {
                let time = st.chain.active_id(e.height).and_then(|id| st.chain.block(&id)).map(|b| b.header.time);
                v.push(json!({"txid": hex(&e.txid), "height": e.height, "confirmations": tip - e.height + 1,
                              "time": time, "received": e.received, "sent": e.sent}));
            }
            v.truncate(limit);
            Ok(json!(v))
        }
        "getwork" => {
            let payee = hash_param(arg(0)?)?;
            let (b, seed) = st.new_work(&payee);
            let net = &st.chain.net;
            Ok(json!({
                "height": b.header.height,
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
        "utxos" => {
            // Confirmed unspent outputs (minus those spent by pooled transactions) and unconfirmed outputs
            // of pooled transactions; both are spendable by a new transaction.
            let owner = hash_param(arg(0)?)?;
            let next = st.chain.height() + 1;
            let maturity = st.chain.net.maturity;
            let mut v: Vec<Value> = st
                .chain
                .coins_of(&owner)
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
            for (op, o) in st.mempool.pending_outputs(&owner) {
                v.push(json!({"txid": hex(&op.txid), "vout": op.vout, "value": o.value, "height": null,
                              "coinbase": false, "confirmed": false, "spendable": true}));
            }
            Ok(json!(v))
        }
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

/// Minimal client for tests and tools: one request per connection; sends `REQUANT_RPC_TOKEN` if set.
pub fn request(addr: SocketAddr, method: &str, params: Value) -> io::Result<Value> {
    let body = json!({"method": method, "params": params}).to_string();
    let auth = std::env::var("REQUANT_RPC_TOKEN").map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
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
