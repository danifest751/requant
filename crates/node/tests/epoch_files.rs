//! Epoch changes with the weights in files (as on the test network, forced here for regtest's small
//! weights): a miner crosses several epochs, keeping at most the current and the next epoch on disk; a
//! new node syncs across all of them, verifying every claim through file-backed weights.

use ed25519_dalek::SigningKey;
use requant_consensus::params::Network;
use requant_consensus::tx::pkh;
use requant_node::node::{start, Config, Handle};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn node(dir: &Path, connect: Vec<String>, mine: bool) -> Handle {
    let miner = SigningKey::from_bytes(&[9; 32]);
    start(Config {
        net: Network::regtest(),
        datadir: dir.to_path_buf(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: None,
        rpc_token: None,
        connect,
        mine_to: mine.then(|| pkh(&miner.verifying_key().to_bytes())),
        mine_interval: Duration::from_millis(200),
        threads: 2,
        max_reorg: 1000,
        peer_interval: Duration::from_millis(300),
        discover: false,
        explorer: None,
        pool: None,
        auto_update: false,
        release_key: requant_node::release::RELEASE_KEY,
        notify: Default::default(),
        faucet: None,
    })
    .unwrap()
}

fn height(h: &Handle) -> u64 {
    h.shared.lock().unwrap().chain.height()
}

fn weight_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir.join("regtest").join("epochs"))
        .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect())
        .unwrap_or_default();
    v.retain(|n| n.ends_with(".tnet"));
    v.sort();
    v
}

#[test]
fn epochs_change_with_weights_in_files() {
    std::env::set_var("REQUANT_EPOCH_FILES", "1");
    let base = std::env::temp_dir().join(format!("requant-epochfiles-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (da, dc) = (base.join("a"), base.join("c"));
    let a = node(&da, vec![], true);
    let net = Network::regtest();
    let target = 5 * net.epoch_len + 3; // into the sixth epoch
    let t = Instant::now();
    let mut most = 0;
    while height(&a) < target {
        most = most.max(weight_files(&da).len());
        assert!(t.elapsed() < Duration::from_secs(180), "mining stalled at {}", height(&a));
        std::thread::sleep(Duration::from_millis(20));
    }
    a.stop.store(true, Ordering::Relaxed);
    // never more than the current and the next epoch on disk, and the current one is there
    assert!(most <= 2, "{most} weight files at once");
    let current = {
        let st = a.shared.lock().unwrap();
        st.chain.upcoming_epoch_seeds()[0]
    };
    let name = format!("{}.tnet", requant_node::rpc::hex(&current));
    assert!(weight_files(&da).contains(&name), "{:?} lacks {name}", weight_files(&da));
    // a new node verifies the whole history through file-backed weights
    let c = node(&dc, vec![a.p2p.to_string()], false);
    let tip = a.shared.lock().unwrap().chain.tip();
    let t = Instant::now();
    while c.shared.lock().unwrap().chain.tip() != tip {
        assert!(t.elapsed() < Duration::from_secs(180), "sync stalled at {}", height(&c));
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(weight_files(&dc).len() <= 2);
    let _ = std::fs::remove_dir_all(&base);
}
