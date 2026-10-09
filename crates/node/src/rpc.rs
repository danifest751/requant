//! JSON-RPC over HTTP on a local address: `POST /` with `{"method": ..., "params": [...]}`, answered by
//! `{"result": ..., "error": null}`. No authentication: bind it to localhost only.

use crate::node::Shared;
use requant_consensus::block::Claim;
use requant_consensus::tx::{Hash, Tx};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

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

pub fn serve(shared: Shared, addr: SocketAddr) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let shared = shared.clone();
            std::thread::spawn(move || {
                let _ = handle(shared, s);
            });
        }
    });
    Ok(local)
}

fn handle(shared: Shared, stream: TcpStream) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut len = 0usize;
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
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    if len > MAX_BODY {
        return respond(stream, &json!({"result": null, "error": "request too large"}));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    let reply = match serde_json::from_slice::<Value>(&body) {
        Ok(req) => {
            let method = req["method"].as_str().unwrap_or("");
            let empty = vec![];
            let params = req["params"].as_array().unwrap_or(&empty);
            match call(&shared, method, params) {
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
        "getinfo" => Ok(json!({
            "network": st.chain.net.name,
            "height": st.chain.height(),
            "tip": hex(&st.chain.tip()),
            "issued_atoms": st.chain.issued(),
            "peers": st.peer_count(),
            "mempool": st.mempool.len(),
        })),
        "getblock" => {
            let h = u64_param(arg(0)?)?;
            let id = st.chain.active_id(h).ok_or("no block at that height")?;
            let b = st.chain.block(&id).unwrap();
            Ok(json!({"id": hex(&id), "height": h, "time": b.header.time, "txs": b.txs.len(), "hex": hex(&b.encode())}))
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
            let owner = hash_param(arg(0)?)?;
            let next = st.chain.height() + 1;
            let maturity = st.chain.net.maturity;
            let v: Vec<Value> = st
                .chain
                .coins_of(&owner)
                .into_iter()
                .map(|(op, c)| {
                    json!({
                        "txid": hex(&op.txid), "vout": op.vout, "value": c.output.value, "height": c.height,
                        "coinbase": c.coinbase, "spendable": !c.coinbase || next - c.height >= maturity,
                    })
                })
                .collect();
            Ok(json!(v))
        }
        "addpeer" => {
            let addr = arg(0)?.as_str().ok_or("expected host:port")?.to_string();
            drop(st);
            crate::node::connect(shared, &addr).map(|_| json!(true)).map_err(|e| e.to_string())
        }
        "peers" => Ok(json!(st.peer_addrs().iter().map(|a| a.to_string()).collect::<Vec<_>>())),
        _ => Err(format!("unknown method {method}")),
    }
}

/// Minimal client for tests and tools: one request per connection.
pub fn request(addr: SocketAddr, method: &str, params: Value) -> io::Result<Value> {
    let body = json!({"method": method, "params": params}).to_string();
    let mut s = TcpStream::connect(addr)?;
    write!(
        s,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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
