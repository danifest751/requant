//! Mining pool on regtest: two miners submit shares through the pool's public JSON-RPC; blocks found,
//! credits matured, payouts made on chain.

use ed25519_dalek::SigningKey;
use requant_consensus::block::Header;
use requant_consensus::codec::Reader;
use requant_consensus::params::Network;
use requant_consensus::tx::{pkh, Hash};
use requant_node::node::{start, Config};
use requant_node::pool::PoolConfig;
use requant_node::rpc::{hex, request, unhex};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn addr(k: &SigningKey) -> Hash {
    pkh(&k.verifying_key().to_bytes())
}

/// Find one ticket meeting the job's (share) target, as a miner would.
fn find_share(work: &Value, start_nonce: u64) -> (u64, u32, u32, String) {
    let net = Network::regtest();
    let hb = unhex(work["header"].as_str().unwrap()).unwrap();
    let header = Header::decode(&mut Reader::new(&hb)).unwrap();
    let hd = header.digest(&net.chain_id);
    let seed: Hash = unhex(work["epoch_seed"].as_str().unwrap()).unwrap().try_into().unwrap();
    let target: [u8; 32] = unhex(work["target"].as_str().unwrap()).unwrap().try_into().unwrap();
    let epoch = tnet::Epoch::from_seed(&seed, net.tnet);
    let p = net.tnet;
    for nonce in start_nonce.. {
        let s = tnet::x0_seed(&hd, nonce);
        for i in 0..p.b {
            let row = epoch.forward_row(&s, i, 1);
            for c in 0..p.tickets_per_row() {
                let piece = &row[c * p.w..(c + 1) * p.w];
                if tnet::meets_target(&tnet::ticket_hash(piece, &hd, nonce, i as u32, c as u32), &target) {
                    return (nonce, i as u32, c as u32, hex(&piece.iter().map(|&x| x as u8).collect::<Vec<_>>()));
                }
            }
        }
    }
    unreachable!()
}

fn submit(pool: SocketAddr, miner: &Hash, nonce_base: u64) -> Value {
    submit_as(pool, miner, None, nonce_base)
}

/// A share from a named device (worker) of `miner`.
fn submit_as(pool: SocketAddr, miner: &Hash, worker: Option<&str>, nonce_base: u64) -> Value {
    let work = request(pool, "getwork", json!([hex(miner)])).unwrap();
    let (nonce, i, c, piece) = find_share(&work, nonce_base);
    let mut params =
        vec![work["header_digest"].clone(), json!(nonce), json!(i), json!(c), json!(piece), json!(hex(miner))];
    if let Some(w) = worker {
        params.push(json!(w));
    }
    request(pool, "submitwork", Value::Array(params)).unwrap()
}

#[test]
fn pool_shares_blocks_and_payouts() {
    let dir = std::env::temp_dir().join(format!("requant-pool-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let pool_key = [0x50u8; 32];
    let n = start(Config {
        net: Network::regtest(),
        datadir: dir.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        rpc_token: None,
        connect: vec![],
        mine_to: None,
        mine_interval: Duration::from_millis(0),
        threads: 1,
        max_reorg: 100,
        peer_interval: Duration::from_millis(300),
        discover: false,
        explorer: None,
        pool: Some(PoolConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            key: pool_key,
            fee_bp: 100,
            share_bits: 1,
            min_payout: 100_000_000,
            payout_every: 1,
        }),
    })
    .unwrap();
    // the pool's address comes from the pool server's port: read it from the node log-free way
    let pool_addr = wait_pool_addr(&n);
    let rpc = n.rpc.unwrap();
    let (alice, bob) = (addr(&SigningKey::from_bytes(&[1; 32])), addr(&SigningKey::from_bytes(&[2; 32])));

    // shares (on regtest every share is also a block): alice twice as often as bob
    let mut blocks = 0;
    for k in 0..12u64 {
        let who = if k % 3 == 2 { &bob } else { &alice };
        // alice mines from two devices under one address
        let worker = if who == &alice { Some(if k % 2 == 0 { "rig-a" } else { "rtx5070" }) } else { None };
        let r = submit_as(pool_addr, who, worker, k * 1000);
        assert_eq!(r["accepted"], true, "{r}");
        if r["block"] == true {
            blocks += 1;
        }
    }
    assert!(blocks >= 10, "blocks {blocks}");

    // a duplicate share and a garbage share are refused
    let work = request(pool_addr, "getwork", json!([hex(&alice)])).unwrap();
    let (nonce, i, c, piece) = find_share(&work, 777_000);
    let first =
        request(pool_addr, "submitwork", json!([work["header_digest"], nonce, i, c, piece, hex(&alice)])).unwrap();
    assert_eq!(first["accepted"], true);
    let again =
        request(pool_addr, "submitwork", json!([work["header_digest"], nonce, i, c, piece, hex(&alice)])).unwrap();
    assert_eq!(again["accepted"], false);
    let work = request(pool_addr, "getwork", json!([hex(&alice)])).unwrap();
    let junk = request(pool_addr, "submitwork", json!([work["header_digest"], 1, 0, 0, "00".repeat(64), hex(&alice)]))
        .unwrap();
    assert_eq!(junk["accepted"], false);

    // matured credits are paid on chain to both miners, alice about twice bob
    let t = Instant::now();
    let paid = |who: &Hash| -> u64 {
        request(rpc, "utxos", json!([hex(who)]))
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["value"].as_u64().unwrap())
            .sum()
    };
    loop {
        // keep the chain moving so coinbases mature and payouts confirm
        let _ = submit(pool_addr, &alice, t.elapsed().as_millis() as u64 * 7);
        if paid(&alice) > 0 && paid(&bob) > 0 {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(120), "no payouts");
        std::thread::sleep(Duration::from_millis(200));
    }
    let stats = request(pool_addr, "poolstats", json!([])).unwrap();
    assert!(stats["blocks"].as_array().unwrap().len() >= blocks);
    assert!(!stats["payouts"].as_array().unwrap().is_empty());
    let (a, b) = (paid(&alice), paid(&bob));
    assert!(a > b, "alice {a} bob {b}");
    // per-device statistics under alice's one address (payouts go to the address)
    let alice_addr = requant_consensus::address::address(&Network::regtest(), &alice);
    let row = stats["miners"].as_array().unwrap().iter().find(|m| m["address"] == alice_addr.as_str()).unwrap().clone();
    let names: Vec<&str> = row["workers"].as_array().unwrap().iter().map(|w| w["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"rig-a") && names.contains(&"rtx5070"), "{names:?}");
    let sum: u64 = row["workers"].as_array().unwrap().iter().map(|w| w["shares"].as_u64().unwrap()).sum();
    assert_eq!(sum, row["shares"].as_u64().unwrap());
}

fn wait_pool_addr(n: &requant_node::node::Handle) -> SocketAddr {
    n.pool.expect("pool address in the handle")
}
