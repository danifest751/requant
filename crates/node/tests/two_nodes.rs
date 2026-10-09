//! Two regtest nodes on localhost: sync, transaction relay and mining, restart from storage.

use ed25519_dalek::SigningKey;
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
    start(Config {
        net: Network::regtest(),
        datadir: dir.to_path_buf(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        connect,
        mine_to,
        mine_interval: Duration::from_millis(30),
        threads: 1,
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
        request(rpc_b, "utxos", json!([bob_hex])).unwrap().as_array().unwrap().iter().any(|c| c["value"] == 12_345)
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
