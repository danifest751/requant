//! The RPC on regtest: the cookie, JSON-RPC 2.0 next to the older form, batches and notifications, the
//! newer methods, the getwork long poll and stop.

use requant_consensus::params::Network;
use requant_node::node::{start, Config};
use requant_node::rpc::{hex, request};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// One raw HTTP request: (status code, body as JSON or Null).
fn post(addr: SocketAddr, token: Option<&str>, body: &str) -> (u16, Value) {
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "POST / HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status = resp.split(' ').nth(1).unwrap().parse().unwrap();
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

#[test]
fn rpc_formats_methods_long_poll_and_cookie() {
    let dir = std::env::temp_dir().join(format!("requant-rpc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let payee = [5u8; 32];
    let h = start(Config {
        net: Network::regtest(),
        datadir: dir.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        connect: vec![],
        mine_to: Some(payee),
        mine_interval: Duration::from_millis(200),
        threads: 1,
        max_reorg: 100,
        rpc_token: None,
        rpc_cookie: true,
        peer_interval: Duration::from_millis(200),
        discover: false,
        explorer: None,
        pool: None,
        auto_update: false,
        release_key: requant_node::release::RELEASE_KEY,
        notify: Default::default(),
        max_upload: None,
        faucet: None,
    })
    .unwrap();
    let rpc = h.rpc.unwrap();
    let cookie_path = dir.join("regtest").join(".cookie");
    let cookie = std::fs::read_to_string(&cookie_path).unwrap();
    let t = Some(cookie.as_str());
    let call2 =
        |m: &str, p: Value| post(rpc, t, &json!({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).to_string()).1;

    // the cookie is required
    assert_eq!(post(rpc, None, r#"{"method":"getinfo"}"#).0, 401);
    assert_eq!(post(rpc, Some("wrong"), r#"{"method":"getinfo"}"#).0, 401);
    // the older form is answered as before
    let (code, v) = post(rpc, t, r#"{"method":"getblockhash","params":[0]}"#);
    assert_eq!(code, 200);
    assert!(v["error"].is_null() && v["result"].is_string() && v.get("jsonrpc").is_none());
    let genesis = v["result"].as_str().unwrap().to_string();
    // JSON-RPC 2.0: the id comes back; errors carry codes
    let (_, v) = post(rpc, t, r#"{"jsonrpc":"2.0","id":"x7","method":"getblockhash","params":[0]}"#);
    assert_eq!(v["jsonrpc"].as_str(), Some("2.0"));
    assert_eq!(v["id"].as_str(), Some("x7"));
    assert_eq!(v["result"].as_str(), Some(genesis.as_str()));
    assert_eq!(call2("nosuch", json!([]))["error"]["code"], -32601);
    assert_eq!(call2("getblockhash", json!([]))["error"]["code"], -32602);
    assert_eq!(post(rpc, t, "{not json").1["error"], "invalid JSON");
    // a notification gets no answer; a batch answers its requests in order and skips notifications
    assert_eq!(post(rpc, t, r#"{"jsonrpc":"2.0","method":"getinfo"}"#).0, 204);
    let batch = r#"[{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]},
                    {"jsonrpc":"2.0","method":"getinfo"},
                    {"jsonrpc":"2.0","id":2,"method":"nosuch"}]"#;
    let (_, v) = post(rpc, t, batch);
    let a = v.as_array().unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(a[0]["id"], json!(1));
    assert_eq!(a[1]["error"]["code"], json!(-32601));
    assert_eq!(post(rpc, t, "[]").1["error"]["code"], -32600);

    // newer methods
    let t0 = Instant::now();
    while call2("getblockhash", json!([2]))["result"].is_null() {
        assert!(t0.elapsed() < Duration::from_secs(60), "mining stalled");
        std::thread::sleep(Duration::from_millis(50));
    }
    let hdr = call2("getblockheader", json!([1]))["result"].clone();
    assert_eq!(hdr["prev"].as_str(), Some(genesis.as_str()));
    assert_eq!(call2("getblockheader", json!([hdr["id"]]))["result"]["height"], 1);
    assert_eq!(call2("getblock", json!([hdr["id"]]))["result"]["height"], 1);
    let tips = call2("getchaintips", json!([]))["result"].clone();
    assert_eq!(tips[0]["status"].as_str(), Some("active"));
    assert_eq!(tips[0]["branch_length"].as_u64(), Some(0));
    assert_eq!(call2("getmempoolinfo", json!([]))["result"]["size"], 0);
    assert_eq!(call2("getrawmempool", json!([true]))["result"], json!([]));
    assert_eq!(call2("estimatefee", json!([3]))["result"]["feerate"], 1);
    assert_eq!(call2("estimatefee", json!([0]))["error"]["code"], -32602);
    let addr = requant_consensus::address::address(&Network::regtest(), &payee);
    let va = call2("validateaddress", json!([addr]))["result"].clone();
    assert_eq!(va["valid"].as_bool(), Some(true));
    assert_eq!(va["key_hash"].as_str(), Some(hex(&payee).as_str()));
    assert_eq!(call2("validateaddress", json!(["trq1nope"]))["result"]["valid"], false);
    let block1 = call2("getblock", json!([1]))["result"].clone();
    let cb = call2("gettx", json!([block1["txids"][0]]))["result"].clone();
    let dec = call2("decodetx", json!([cb["hex"]]))["result"].clone();
    assert_eq!(dec["txid"], cb["txid"]);
    assert_eq!(dec["height"], json!(1));
    let bal = call2("getbalance", json!([hex(&payee)]))["result"].clone();
    assert!(bal["confirmed"].as_u64().unwrap() + bal["immature"].as_u64().unwrap() > 0);
    assert_eq!(call2("getnetworkinfo", json!([]))["result"]["version"], requant_node::node::VERSION);

    // long poll: a current id waits for the next block, a stale one answers at once
    let work = call2("getwork", json!([hex(&payee)]))["result"].clone();
    let lp = work["longpollid"].as_str().unwrap().to_string();
    let t1 = Instant::now();
    let next = call2("getwork", json!([hex(&payee), lp]))["result"].clone();
    assert_ne!(next["longpollid"].as_str(), Some(lp.as_str()), "a new block arrived");
    assert!(next["height"].as_u64() > work["height"].as_u64());
    let t2 = Instant::now();
    call2("getwork", json!([hex(&payee), lp]));
    assert!(t2.elapsed() < Duration::from_secs(2) && t1.elapsed() < Duration::from_secs(60));

    // the client sends the cookie from REQUANT_RPC_COOKIE
    std::env::set_var("REQUANT_RPC_COOKIE", &cookie_path);
    assert!(request(rpc, "getinfo", json!([])).is_ok());
    // stop asks the process to stop (the binary's main loop then saves and exits)
    assert_eq!(call2("stop", json!([]))["result"], "stopping");
    assert!(requant_node::signal::requested());
    h.shutdown();
    assert!(!cookie_path.exists(), "the cookie is removed at shutdown");
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}
