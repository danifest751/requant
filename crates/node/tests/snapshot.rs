//! Start-up snapshot: a restart restores the state from `chainstate.bin` and replays only the newer
//! block records; a damaged or stale snapshot falls back to replaying the whole block file.

use requant_consensus::params::Network;
use requant_node::node::{start, Config, Handle};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn datadir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("requant-snap-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn node(dir: &Path, mine: bool) -> Handle {
    start(Config {
        net: Network::regtest(),
        datadir: dir.to_path_buf(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: None,
        connect: vec![],
        mine_to: mine.then_some([7; 32]),
        mine_interval: Duration::from_millis(30),
        threads: 1,
        max_reorg: 100,
        rpc_token: None,
        peer_interval: Duration::from_millis(100),
        discover: false,
        explorer: None,
        pool: None,
        auto_update: false,
        release_key: requant_node::release::RELEASE_KEY,
        notify: Default::default(),
        max_upload: None,
        faucet: None,
    })
    .unwrap()
}

/// What a restart must reproduce: height, tip, UTXO audit, indexed transactions and addresses, header height.
type State = (u64, [u8; 32], (u64, usize, [u8; 32]), usize, usize, u64);

fn state(h: &Handle) -> State {
    let st = h.shared.lock().unwrap();
    let c = &st.chain;
    (c.height(), c.tip(), c.utxo_audit(), st.index.tx_count(), st.index.address_count(), st.headers.height())
}

/// Stop the node as `requantd` does on a signal: save the state, then let the threads wind down.
fn stop(h: Handle) {
    h.shutdown();
    std::thread::sleep(Duration::from_millis(600));
    drop(h);
}

fn mine_to(h: &Handle, height: u64) {
    let t = Instant::now();
    while h.shared.lock().unwrap().chain.height() < height {
        assert!(t.elapsed() < Duration::from_secs(60), "mining stalled");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn restart_from_snapshot_replays_only_the_tail() {
    let dir = datadir("tail");
    let snap = dir.join("regtest").join("chainstate.bin");
    let a = node(&dir, true);
    mine_to(&a, 6);
    let h = a.shared.lock().unwrap().chain.height();
    a.shutdown();
    // the snapshot written at shutdown covers at least the tip of that moment
    let saved = requant_node::snapshot::load(&snap, &Network::regtest(), 1).unwrap();
    assert!(saved.chain.height() >= h);
    stop(a);
    let early = std::fs::read(&snap).expect("snapshot written at shutdown");

    // more blocks, then put the older snapshot back: the restart restores it and replays the rest
    let a = node(&dir, true);
    assert!(a.shared.lock().unwrap().restored.is_some_and(|h| h >= 6));
    let target = a.shared.lock().unwrap().chain.height() + 4;
    mine_to(&a, target);
    stop(a);
    let full = {
        let b = node(&dir, false);
        let s = state(&b);
        stop(b);
        s
    };
    std::fs::write(&snap, &early).unwrap();
    let b = node(&dir, false);
    let restored = b.shared.lock().unwrap().restored.unwrap();
    assert!(restored < full.0, "an older snapshot: the newer records are replayed");
    assert_eq!(state(&b), full);
    stop(b);

    // a damaged snapshot is not used
    let mut bad = std::fs::read(&snap).unwrap();
    let k = bad.len() / 2;
    bad[k] ^= 1;
    std::fs::write(&snap, &bad).unwrap();
    let c = node(&dir, false);
    assert_eq!(c.shared.lock().unwrap().restored, None);
    assert_eq!(state(&c), full);
    stop(c);

    // nor one whose covered record is not in the block file (here: the file was cut short)
    let good = std::fs::read(&snap).unwrap();
    let blocks = dir.join("regtest").join("blocks.dat");
    let len = std::fs::metadata(&blocks).unwrap().len();
    std::fs::OpenOptions::new().write(true).open(&blocks).unwrap().set_len(len - 10).unwrap();
    std::fs::write(&snap, &good).unwrap();
    let d = node(&dir, false);
    assert_eq!(d.shared.lock().unwrap().restored, None);
    assert_eq!(state(&d).0, full.0 - 1, "the torn last block is dropped and the rest replayed");
    stop(d);
    let _ = std::fs::remove_dir_all(&dir);
}
