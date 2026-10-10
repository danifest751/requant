//! The explorer's public API on regtest: views, errors, CORS, many owners at once, the rate limit.

use requant_consensus::params::Network;
use requant_node::node::{start, Config};
use requant_node::rpc::hex;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// (status, headers, JSON body)
fn http(addr: SocketAddr, verb: &str, path: &str, body: &str) -> (u16, String, Value) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(s, "{verb} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        .unwrap();
    let mut r = String::new();
    s.read_to_string(&mut r).unwrap();
    let (head, body) = r.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_string(), serde_json::from_str(body).unwrap_or(Value::Null))
}

#[test]
fn public_api() {
    let dir = std::env::temp_dir().join(format!("requant-api-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let explorer = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let payee = [6u8; 32];
    let h = start(Config {
        net: Network::regtest(),
        datadir: dir.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: None,
        connect: vec![],
        mine_to: Some(payee),
        mine_interval: Duration::from_millis(100),
        threads: 1,
        max_reorg: 100,
        rpc_token: None,
        rpc_cookie: false,
        peer_interval: Duration::from_millis(200),
        discover: false,
        explorer: Some(explorer),
        pool: None,
        auto_update: false,
        release_key: requant_node::release::RELEASE_KEY,
        notify: Default::default(),
        max_upload: None,
        faucet: None,
    })
    .unwrap();
    let t0 = Instant::now();
    while h.shared.lock().unwrap().chain.height() < 3 {
        assert!(t0.elapsed() < Duration::from_secs(60), "mining stalled");
        std::thread::sleep(Duration::from_millis(50));
    }
    let (code, head, info) = http(explorer, "GET", "/api/info", "");
    assert_eq!(code, 200);
    assert!(head.contains("Access-Control-Allow-Origin: *"), "{head}");
    assert_eq!(info["network"], "regtest");
    assert_eq!(http(explorer, "OPTIONS", "/api/tx", "").0, 204);

    // a block by height and by id, its coinbase, the payee's views
    let (_, _, b1) = http(explorer, "GET", "/api/block/1", "");
    let (_, _, again) = http(explorer, "GET", &format!("/api/block/{}", b1["id"].as_str().unwrap()), "");
    assert_eq!(again["height"], 1);
    let (_, _, tx) = http(explorer, "GET", &format!("/api/tx/{}", b1["txids"][0].as_str().unwrap()), "");
    assert_eq!(tx["coinbase"], true);
    let addr = requant_consensus::address::address(&Network::regtest(), &payee);
    let (code, _, bal) = http(explorer, "GET", &format!("/api/address/{addr}/balance"), "");
    assert_eq!(code, 200);
    assert!(bal["immature"].as_u64().unwrap() + bal["confirmed"].as_u64().unwrap() > 0);
    let (_, _, hist) = http(explorer, "GET", &format!("/api/address/{}/history?limit=2", hex(&payee)), "");
    assert_eq!(hist.as_array().unwrap().len(), 2);
    // many owners at once: every entry names its owner
    let (_, _, many) = http(explorer, "GET", &format!("/api/utxos?owners={},{}", hex(&payee), hex(&[1; 32])), "");
    assert!(many.as_array().unwrap().iter().all(|c| c["owner"] == hex(&payee)));
    // the full 200 fit in the request line
    let full: Vec<String> = (0..199u8).map(|k| hex(&[k; 32])).chain([hex(&payee)]).collect();
    let (code, _, many) = http(explorer, "GET", &format!("/api/history?owners={}&limit=1", full.join(",")), "");
    assert_eq!(code, 200, "{many}");
    assert!(many.as_array().unwrap().iter().any(|e| e["owner"] == hex(&payee)));
    let (_, _, fee) = http(explorer, "GET", "/api/fee?blocks=2", "");
    assert_eq!((fee["blocks"].as_u64(), fee["feerate"].as_u64()), (Some(2), Some(1)));

    // errors say what is wrong
    assert_eq!(http(explorer, "GET", "/api/tx/zz", "").0, 400);
    assert_eq!(http(explorer, "GET", &format!("/api/tx/{}", "00".repeat(32)), "").0, 404);
    assert_eq!(http(explorer, "GET", "/api/address/nope/utxos", "").0, 400);
    assert_eq!(http(explorer, "GET", "/api/utxos", "").0, 400);
    assert_eq!(http(explorer, "GET", "/api/nothing", "").0, 404);
    let (code, _, e) = http(explorer, "POST", "/api/tx", "{\"hex\":\"00\"}");
    assert_eq!(code, 400, "{e}");
    let (code, _, e) = http(explorer, "POST", "/api/package", "{\"hex\":\"00\"}");
    assert_eq!(code, 400, "{e}");
    let (code, _, e) = http(explorer, "POST", "/api/package", "{\"hex\":[\"00\",\"zz\"]}");
    assert_eq!(code, 400, "{e}");

    // the rate limit: a burst is served, then 429
    let mut limited = false;
    for _ in 0..400 {
        if http(explorer, "GET", "/api/info", "").0 == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "a client sending without pause is slowed down");

    h.shutdown();
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}
