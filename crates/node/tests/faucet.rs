//! The faucet on regtest: the explorer's form sends coins once, refuses a second request the same day
//! and refuses what is not an address.

use ed25519_dalek::SigningKey;
use requant_consensus::address::address;
use requant_consensus::params::Network;
use requant_consensus::tx::pkh;
use requant_node::faucet::FaucetConfig;
use requant_node::node::{start, Config};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

fn post(at: SocketAddr, form: &str) -> String {
    let mut s = TcpStream::connect(at).unwrap();
    write!(
        s,
        "POST /faucet HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
        form.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn faucet_sends_once_a_day() {
    let dir = std::env::temp_dir().join(format!("requant-faucet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fkey = [0x42u8; 32];
    let owner = pkh(&SigningKey::from_bytes(&fkey).verifying_key().to_bytes());
    let explorer: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let n = start(Config {
        net: Network::regtest(),
        datadir: dir.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: None,
        rpc_token: None,
        connect: vec![],
        mine_to: Some(owner),
        mine_interval: Duration::from_millis(30),
        threads: 1,
        max_reorg: 100,
        peer_interval: Duration::from_millis(300),
        discover: false,
        explorer: Some(explorer),
        pool: None,
        auto_update: false,
        release_key: requant_node::release::RELEASE_KEY,
        faucet: Some(FaucetConfig { key: fkey, amount: 100_000_000, daily: 1_000_000_000 }),
    })
    .unwrap();
    // mined coins must mature first
    let t = Instant::now();
    while n.shared.lock().unwrap().chain.height() < 10 {
        assert!(t.elapsed() < Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(50));
    }
    let to = address(&Network::regtest(), &[7; 32]);
    let first = post(explorer, &format!("to={to}"));
    assert!(first.contains(">sent<"), "{first}");
    let again = post(explorer, &format!("to={to}"));
    assert!(again.contains("one request a day"), "{again}");
    let junk = post(explorer, "to=%3Cscript%3E");
    assert!(junk.contains("not a test-network address") && !junk.contains("<script>"), "{junk}");
    n.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = std::fs::remove_dir_all(&dir);
}
