//! Two regtest nodes on localhost: sync, transaction relay and mining, restart from storage.

use ed25519_dalek::SigningKey;
use requant_consensus::block::Block;
use requant_consensus::chain::{claim_hash_ok, mine, Accepted};
use requant_consensus::params::Network;
use requant_consensus::tx::{pkh, Hash, Input, OutPoint, Output, Tx};
use requant_node::node::{start, Config, Handle};
use requant_node::rpc::{hex, request, unhex};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn addr(k: &SigningKey) -> Hash {
    pkh(&k.verifying_key().to_bytes())
}

fn datadir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("requant-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn node(dir: &Path, connect: Vec<String>, mine_to: Option<Hash>) -> Handle {
    node_with(dir, connect, mine_to, requant_node::release::RELEASE_KEY)
}

fn node_with(dir: &Path, connect: Vec<String>, mine_to: Option<Hash>, release_key: [u8; 32]) -> Handle {
    start(Config {
        net: Network::regtest(),
        datadir: dir.to_path_buf(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        connect,
        mine_to,
        mine_interval: Duration::from_millis(30),
        threads: 1,
        max_reorg: 100,
        rpc_token: None,
        rpc_cookie: false,
        peer_interval: Duration::from_millis(300),
        discover: true,
        explorer: None,
        pool: None,
        auto_update: false,
        release_key,
        notify: Default::default(),
        max_upload: None,
        faucet: None,
    })
    .unwrap()
}

fn height(h: &Handle) -> u64 {
    h.shared.lock().unwrap().chain.height()
}

fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn sync_relay_mine_and_restart() {
    let (alice, bob) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
    let (dir_a, dir_b) = (datadir("a"), datadir("b"));
    let a = node(&dir_a, vec![], Some(addr(&alice)));
    wait("a to mine 5 blocks", 60, || height(&a) >= 5);

    // b joins later and catches up, then follows new blocks
    let b = node(&dir_b, vec![a.p2p.to_string()], None);
    wait("b to sync", 60, || height(&b) >= 5 && height(&b) + 1 >= height(&a));
    let target = height(&a) + 3;
    wait("b to follow", 60, || height(&b) >= target);

    // alice pays bob through b's RPC; the transaction reaches a's pool and a mines it
    let rpc_b = b.rpc.unwrap();
    let coins = request(rpc_b, "utxos", json!([hex(&addr(&alice))])).unwrap();
    let coin = coins.as_array().unwrap().iter().find(|c| c["spendable"].as_bool().unwrap()).unwrap().clone();
    let op = OutPoint {
        txid: unhex(coin["txid"].as_str().unwrap()).unwrap().try_into().unwrap(),
        vout: coin["vout"].as_u64().unwrap() as u32,
    };
    let value = coin["value"].as_u64().unwrap();
    let mut tx = Tx::Transfer {
        inputs: vec![Input { prev: op, pubkey: [0; 32], sig: [0; 64] }],
        outputs: vec![
            Output { value: 12_345, pkh: addr(&bob) },
            Output { value: value - 12_345 - 500, pkh: addr(&alice) },
        ],
    };
    tx.sign(&Network::regtest().chain_id, &[&alice]);
    let txid = request(rpc_b, "sendtx", json!([hex(&tx.encode())])).unwrap();
    assert_eq!(txid.as_str().unwrap(), hex(&tx.txid()));
    // double spend of the same coin is refused by the pool
    let mut dup = tx.clone();
    if let Tx::Transfer { outputs, .. } = &mut dup {
        outputs[0].value += 1;
    }
    dup.sign(&Network::regtest().chain_id, &[&alice]);
    assert!(request(rpc_b, "sendtx", json!([hex(&dup.encode())])).is_err());

    let bob_hex = hex(&addr(&bob));
    wait("the payment to be mined and seen by b", 60, || {
        request(rpc_b, "utxos", json!([bob_hex]))
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["value"] == 12_345 && c["confirmed"] == true)
    });
    assert_eq!(b.shared.lock().unwrap().mempool.len(), 0);

    // restart b from its storage: same tip without network or re-verifying the work
    a.stop.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(200));
    let tip_b = b.shared.lock().unwrap().chain.tip();
    let h_b = height(&b);
    drop(b);
    let b2 = node(&dir_b, vec![], None);
    let st = b2.shared.lock().unwrap();
    assert!(st.chain.height() >= h_b);
    assert!(st.chain.contains(&tip_b));
    assert_eq!(st.chain.coins_of(&addr(&bob)).len(), 1);
}

#[test]
fn getwork_submitwork_roundtrip() {
    let dir = datadir("w");
    let n = node(&dir, vec![], None);
    let rpc = n.rpc.unwrap();
    let miner = SigningKey::from_bytes(&[3; 32]);
    let work = request(rpc, "getwork", json!([hex(&addr(&miner))])).unwrap();
    assert_eq!(work["height"], 1);
    // mine it here as an external miner would
    let net = Network::regtest();
    let header_bytes = unhex(work["header"].as_str().unwrap()).unwrap();
    let mut r = requant_consensus::codec::Reader::new(&header_bytes);
    let header = requant_consensus::block::Header::decode(&mut r).unwrap();
    let seed: Hash = unhex(work["epoch_seed"].as_str().unwrap()).unwrap().try_into().unwrap();
    let epoch = tnet::Epoch::from_seed(&seed, net.tnet);
    let claim = requant_consensus::chain::mine(&net, &epoch, &header, 0, 100).unwrap();
    let res = request(
        rpc,
        "submitwork",
        json!([
            work["header_digest"],
            claim.nonce,
            claim.i,
            claim.c,
            hex(&claim.piece.iter().map(|&x| x as u8).collect::<Vec<_>>())
        ]),
    )
    .unwrap();
    assert_eq!(res["accepted"], true, "{res}");
    assert_eq!(request(rpc, "getinfo", json!([])).unwrap()["height"], 1);
    // a wrong piece is refused
    let work = request(rpc, "getwork", json!([hex(&addr(&miner))])).unwrap();
    let res = request(rpc, "submitwork", json!([work["header_digest"], 0, 0, 0, "00".repeat(64)])).unwrap();
    assert_eq!(res["accepted"], false);
}

#[test]
fn discovery_history_and_unconfirmed_change() {
    let (alice, bob) = (SigningKey::from_bytes(&[4; 32]), SigningKey::from_bytes(&[5; 32]));
    let (da, db, dc) = (datadir("da"), datadir("db"), datadir("dc"));
    let a = node(&da, vec![], Some(addr(&alice)));
    wait("a to mine", 60, || height(&a) >= 4);
    let b = node(&db, vec![a.p2p.to_string()], None);
    // c only knows b
    let c = node(&dc, vec![b.p2p.to_string()], None);
    let a_addr = a.p2p;
    // a and c never were told about each other; gossip through b connects them (either may dial)
    wait("a and c to find each other", 60, || {
        c.shared.lock().unwrap().peers().iter().any(|p| p.listen == Some(a_addr))
    });
    wait("c to sync", 60, || height(&c) >= 4);
    let info = request(c.rpc.unwrap(), "getinfo", json!([])).unwrap();
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["known_addresses"].as_u64().unwrap() >= 2);

    // two payments in a row: the second spends the first one's unconfirmed change
    let rpc = c.rpc.unwrap();
    let net = Network::regtest();
    let pay = |to: Hash, value: u64| {
        let coins = request(rpc, "utxos", json!([hex(&addr(&alice))])).unwrap();
        let coin = coins
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["spendable"].as_bool().unwrap())
            .max_by_key(|c| (c["confirmed"] == false, c["value"].as_u64().unwrap()))
            .unwrap()
            .clone();
        let op = OutPoint {
            txid: unhex(coin["txid"].as_str().unwrap()).unwrap().try_into().unwrap(),
            vout: coin["vout"].as_u64().unwrap() as u32,
        };
        let v = coin["value"].as_u64().unwrap();
        let mut tx = Tx::Transfer {
            inputs: vec![Input { prev: op, pubkey: [0; 32], sig: [0; 64] }],
            outputs: vec![Output { value, pkh: to }, Output { value: v - value - 300, pkh: addr(&alice) }],
        };
        tx.sign(&net.chain_id, &[&alice]);
        request(rpc, "sendtx", json!([hex(&tx.encode())])).map(|_| tx)
    };
    let t1 = pay(addr(&bob), 1_000).unwrap();
    let t2 = pay(addr(&bob), 2_000).expect("spending unconfirmed change");
    assert_eq!(c.shared.lock().unwrap().mempool.len(), 2);
    let pending = request(rpc, "history", json!([hex(&addr(&bob))])).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 2);
    assert!(pending.as_array().unwrap().iter().all(|e| e["confirmations"] == 0));

    // both get mined (parent before child) and show up in history and gettx
    wait("both payments confirmed", 60, || {
        let h = request(rpc, "history", json!([hex(&addr(&bob))])).unwrap();
        h.as_array().unwrap().iter().filter(|e| e["confirmations"].as_u64().unwrap_or(0) >= 1).count() == 2
    });
    let tx2 = request(rpc, "gettx", json!([hex(&t2.txid())])).unwrap();
    assert_eq!(tx2["fee"], 300);
    assert_eq!(tx2["inputs"][0]["txid"], hex(&t1.txid()));
    assert_eq!(tx2["outputs"][0]["value"], 2_000);
    let hist = request(rpc, "history", json!([hex(&addr(&alice)), 1000])).unwrap();
    let sent: u64 = hist.as_array().unwrap().iter().map(|e| e["sent"].as_u64().unwrap()).sum();
    assert!(sent > 0);
    a.stop.store(true, Ordering::Relaxed);
}

#[test]
fn orphan_pool_is_bounded() {
    let dir = datadir("orph");
    let n = node(&dir, vec![], None);
    let mut st = n.shared.lock().unwrap();
    let tip = st.chain.tip();
    let net = st.chain.net.clone();
    // an orphan is kept only if its ticket hash meets its target (the row itself cannot be checked yet)
    let with_hash = |mut b: Block| {
        while claim_hash_ok(&net, &b.header, &b.claim).is_err() {
            b.claim.nonce += 1;
        }
        b
    };
    for k in 0..100u64 {
        let mut b = st.chain.template_on(&tip, &[1; 32], vec![], 0);
        b.header.prev = [k as u8 + 1; 32]; // unknown parents
        b.header.prev[31] = (k >> 8) as u8;
        let _ = st.process_block(with_hash(b), Some(7));
    }
    let (count, bytes) = st.orphan_count();
    assert_eq!(count, requant_node::node::MAX_ORPHANS_PER_PEER);
    assert!(bytes <= requant_node::node::MAX_ORPHAN_BYTES);
    // far-future orphans are not kept at all
    let mut far = st.chain.template_on(&tip, &[1; 32], vec![], 0);
    far.header.prev = [0xee; 32];
    far.header.height = 1_000_000;
    let _ = st.process_block(with_hash(far), Some(8));
    assert_eq!(st.orphan_count().0, count);
    // nor orphans without the work their header claims
    let mut junk = st.chain.template_on(&tip, &[1; 32], vec![], 0);
    junk.header.prev = [0xdd; 32];
    while claim_hash_ok(&net, &junk.header, &junk.claim).is_ok() {
        junk.claim.nonce += 1;
    }
    assert!(st.process_block(junk, Some(9)).is_err());
    assert_eq!(st.orphan_count().0, count);
}

#[test]
fn junk_body_does_not_kill_a_valid_header() {
    let dir = datadir("junk");
    let n = node(&dir, vec![], None);
    let mut st = n.shared.lock().unwrap();
    let tip = st.chain.tip();
    let mut b = st.chain.template_on(&tip, &[1; 32], vec![], st.chain.net.genesis_time + 60);
    let seed = st.chain.epoch_seed(&tip, 1);
    let epoch = st.chain.epoch(&seed);
    b.claim = mine(&st.chain.net, &epoch, &b.header, 0, 1000).unwrap();
    let id = b.id(&st.chain.net);
    st.headers.add_valid(&b.header, &b.claim);
    // the same header with other transactions: refused, but the header stays
    let mut junk = b.clone();
    junk.txs.push(junk.txs[0].clone());
    assert!(st.process_block(junk, Some(7)).is_err());
    assert!(st.headers.contains(&id));
    // and the real body is accepted
    assert_eq!(st.process_block(b, Some(8)), Ok(Some(Accepted::NewTip)));
}

#[test]
fn headers_first_sync_from_two_peers() {
    let (da, db, dc) = (datadir("ha"), datadir("hb"), datadir("hc"));
    let miner = SigningKey::from_bytes(&[9; 32]);
    let a = start(Config {
        net: Network::regtest(),
        datadir: da.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        rpc_token: None,
        rpc_cookie: false,
        connect: vec![],
        mine_to: Some(addr(&miner)),
        mine_interval: Duration::from_millis(0),
        threads: 1,
        max_reorg: 1000,
        peer_interval: Duration::from_millis(300),
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
    wait("a to mine 150 blocks", 120, || height(&a) >= 150);
    a.stop.store(true, Ordering::Relaxed);
    let b = node(&db, vec![a.p2p.to_string()], None);
    wait("b to sync", 120, || height(&b) == height(&a));
    // c learns 150 headers, verifies their claims, and downloads bodies from a and b in parallel
    let c = node(&dc, vec![a.p2p.to_string(), b.p2p.to_string()], None);
    wait("c to sync", 120, || height(&c) == height(&a));
    let tip_a = a.shared.lock().unwrap().chain.tip();
    {
        let st = c.shared.lock().unwrap();
        assert_eq!(st.headers.height(), st.chain.height());
        assert_eq!(st.chain.tip(), tip_a);
    } // release c's lock before asking c over RPC
    let info = request(c.rpc.unwrap(), "getinfo", json!([])).unwrap();
    assert_eq!(info["headers"], height(&a));
}

#[test]
fn signed_releases_spread_and_persist() {
    use ed25519_dalek::Signer;
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let pk = key.verifying_key().to_bytes();
    let manifest = |v: &str| {
        let text = format!(
            "requant-release 1
version {v}
asset linux-x86_64 {} https://example.org/requantd
",
            "00".repeat(32)
        );
        let sig = hex(&key.sign(&requant_node::release::signed_message(&text)).to_bytes());
        (text, sig)
    };
    let (da, db) = (datadir("rel-a"), datadir("rel-b"));
    let a = node_with(&da, vec![], None, pk);
    let b = node_with(&db, vec![a.p2p.to_string()], None, pk);
    wait("b to connect", 30, || b.shared.lock().unwrap().peer_count() > 0);
    let (text, sig) = manifest("99.0.0");
    let r = request(a.rpc.unwrap(), "submitrelease", json!([text, sig])).unwrap();
    assert_eq!(r["new"], true);
    wait("the release to reach b", 30, || {
        request(b.rpc.unwrap(), "getrelease", json!([])).unwrap()["version"] == "99.0.0"
    });
    let info = request(b.rpc.unwrap(), "getinfo", json!([])).unwrap();
    assert_eq!(info["update_available"], "99.0.0");
    // an older release is not taken; a forged signature is refused
    let (old, old_sig) = manifest("98.0.0");
    assert_eq!(request(a.rpc.unwrap(), "submitrelease", json!([old, old_sig])).unwrap()["new"], false);
    let (t2, _) = manifest("100.0.0");
    assert!(request(a.rpc.unwrap(), "submitrelease", json!([t2, sig])).is_err());
    // kept across a restart
    b.stop.store(true, Ordering::Relaxed);
    drop(b);
    let b2 = node_with(&db, vec![], None, pk);
    assert_eq!(request(b2.rpc.unwrap(), "getrelease", json!([])).unwrap()["version"], "99.0.0");
}
