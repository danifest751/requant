//! The wallet binary against a regtest node: create, receive mined coins, new addresses, a payment with
//! change to a fresh address, the offline flow (watch-only prepare, sign, broadcast) including a tampered
//! file, restore from the phrase with the address scan, and an encrypted wallet.

use requant_consensus::params::Network;
use requant_node::node::{start, Config, Handle};
use requant_wallet::wallet::WalletFile;
use requant_wallet::{address, parse_address};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("requant-wallet-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn node(data: &Path, mine_to: [u8; 32], explorer: std::net::SocketAddr) -> Handle {
    start(Config {
        net: Network::regtest(),
        datadir: data.to_path_buf(),
        listen: "127.0.0.1:0".parse().unwrap(),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        connect: vec![],
        mine_to: Some(mine_to),
        mine_interval: Duration::from_millis(30),
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
    .unwrap()
}

struct Cli {
    dir: PathBuf,
    rpc: String,
    /// When set, the wallet goes through this public API instead of the RPC.
    api: Option<String>,
}

impl Cli {
    /// Run the wallet; returns (success, stdout, stderr).
    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> (bool, String, String) {
        let mut c = Command::new(env!("CARGO_BIN_EXE_requant-wallet"));
        c.current_dir(&self.dir).args(args).args(["--network", "regtest", "--rpc", &self.rpc]);
        if let Some(a) = &self.api {
            c.args(["--api", a]);
        }
        c.env_remove("REQUANT_WALLET_PASSPHRASE").env_remove("REQUANT_WALLET_PHRASE");
        for (k, v) in env {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        (o.status.success(), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
    }

    fn ok(&self, args: &[&str]) -> String {
        let (ok, out, err) = self.run_env(args, &[]);
        assert!(ok, "{args:?} failed: {err}");
        out
    }

    fn wallet(&self, name: &str) -> WalletFile {
        WalletFile::parse(&std::fs::read_to_string(self.dir.join(name)).unwrap()).unwrap()
    }

    /// Confirmed spendable balance in atoms, from `balance`.
    fn confirmed(&self, src: &str) -> u64 {
        let out = self.ok(&["balance", src]);
        let line = out.lines().find(|l| l.starts_with("confirmed")).unwrap();
        requant_wallet::parse_amount(line.split_whitespace().nth(1).unwrap()).unwrap()
    }
}

fn wait(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(90), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn txid_of(out: &str) -> String {
    out.trim().rsplit(' ').next().unwrap().to_string()
}

#[test]
fn wallet_end_to_end() {
    let net = Network::regtest();
    let d = dir();
    let mut cli = Cli { dir: d.clone(), rpc: "127.0.0.1:1".into(), api: None };

    // a new wallet shows 24 words and its first address
    let out = cli.ok(&["create", "w.json", "--no-passphrase"]);
    let words: Vec<String> = out
        .lines()
        .filter(|l| l.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .flat_map(|l| l.split_whitespace().filter(|w| !w.ends_with('.')).map(str::to_string).collect::<Vec<_>>())
        .collect();
    assert_eq!(words.len(), 24, "{out}");
    let phrase = words.join(" ");
    let first = out.lines().find(|l| l.starts_with("address")).unwrap().split_whitespace().nth(1).unwrap().to_string();
    assert!(!cli.run_env(&["create", "w.json", "--no-passphrase"], &[]).0, "never overwrites");

    // mine to it
    let explorer = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let h = node(&d.join("node"), parse_address(&net, &first).unwrap(), explorer);
    cli.rpc = h.rpc.unwrap().to_string();
    wait("mined coins to mature", || cli.confirmed("w.json") > 0);

    // a second address, and a payment to it: change goes to a fresh change address
    let second = cli.ok(&["newaddress", "w.json"]).trim().to_string();
    assert_ne!(second, first);
    let sent = cli.ok(&["send", "w.json", &second, "1.5", "--yes"]);
    assert!(sent.starts_with("sent, txid"), "{sent}");
    let w = cli.wallet("w.json");
    assert_eq!((w.receive_issued, w.change_issued), (2, 1));
    wait("the payment to confirm", || cli.confirmed(&second) == 150_000_000);
    let change = address(&net, &w.change[0]);
    wait("the change to confirm", || cli.confirmed(&change) > 0);
    // the wallet's history nets the move between its own addresses down to the fee
    let hist = cli.ok(&["history", "w.json", "50"]);
    assert!(hist.lines().any(|l| l.contains(&txid_of(&sent)) && l.contains("-0.")), "{hist}");

    // offline: a watch-only copy prepares, the full wallet signs, anyone broadcasts
    cli.ok(&["watchonly", "w.json", "watch.json"]);
    assert!(cli.wallet("watch.json").watch_only());
    let (ok, _, err) = cli.run_env(&["send", "watch.json", &second, "1", "--yes"], &[]);
    assert!(!ok && err.contains("watch-only"), "{err}");
    let outside = address(&net, &[0x42; 32]);
    cli.ok(&["prepare", "watch.json", &outside, "2", "--out", "unsigned.json"]);
    // a tampered file is refused: the change output re-labelled as the payment's
    let text = std::fs::read_to_string(d.join("unsigned.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut bad = v.clone();
    bad["change"][0][0] = serde_json::json!(0);
    std::fs::write(d.join("bad.json"), bad.to_string()).unwrap();
    let (ok, _, err) = cli.run_env(&["sign", "w.json", "bad.json", "--yes"], &[]);
    assert!(!ok && err.contains("refusing to sign"), "{err}");
    let mut gone = v.clone();
    gone["prev"] = serde_json::json!([]);
    std::fs::write(d.join("gone.json"), gone.to_string()).unwrap();
    assert!(!cli.run_env(&["sign", "w.json", "gone.json", "--yes"], &[]).0);
    cli.ok(&["sign", "w.json", "unsigned.json", "--out", "signed.hex", "--yes"]);
    let b = cli.ok(&["broadcast", "signed.hex"]);
    assert!(b.starts_with("sent, txid"), "{b}");
    wait("the offline payment to confirm", || cli.confirmed(&outside) == 200_000_000);

    // restore from the phrase finds both receive addresses and both change addresses in use
    let (ok, out, err) = cli.run_env(&["restore", "r.json", "--no-passphrase"], &[("REQUANT_WALLET_PHRASE", &phrase)]);
    assert!(ok, "{err}");
    assert!(out.contains("found 2 receive and 2 change"), "{out}");
    let (r, w) = (cli.wallet("r.json"), cli.wallet("w.json"));
    assert_eq!(r.receive[..2], w.receive[..2]);
    assert_eq!(r.change[..2], w.change[..2]);
    assert_eq!(cli.ok(&["phrase", "r.json"]).trim(), phrase);
    let (ok, _, err) =
        cli.run_env(&["restore", "x.json", "--no-passphrase"], &[("REQUANT_WALLET_PHRASE", "abandon art")]);
    assert!(!ok && err.contains("24 words"), "{err}");

    // a deposit list: 30 addresses at once (past the derived-ahead 20), written to a file; a restore
    // with --count covers them although they are an unused run longer than the scan's gap
    cli.ok(&["newaddress", "w.json", "--count", "30", "--out", "deposits.txt"]);
    let list: Vec<String> =
        std::fs::read_to_string(d.join("deposits.txt")).unwrap().lines().map(str::to_string).collect();
    assert_eq!(list.len(), 30);
    let w = cli.wallet("w.json");
    assert_eq!(w.receive_issued, 32);
    assert_eq!(list, w.receive[2..32].iter().map(|o| address(&net, o)).collect::<Vec<_>>());
    assert!(!cli.run_env(&["newaddress", "w.json", "--count", "0"], &[]).0);
    let (ok, out, err) =
        cli.run_env(&["restore", "r3.json", "--no-passphrase", "--count", "32"], &[("REQUANT_WALLET_PHRASE", &phrase)]);
    assert!(ok, "{out} {err}");
    let r = cli.wallet("r3.json");
    assert_eq!(r.receive_issued, 32);
    assert_eq!(r.receive[..32], w.receive[..32]);

    // without a node of one's own: the same wallet through the explorer's public API (the RPC address is
    // made unreachable to be sure)
    cli.api = Some(format!("http://{explorer}"));
    cli.rpc = "127.0.0.1:1".into();
    assert_eq!(cli.confirmed(&outside), 200_000_000);
    let hist = cli.ok(&["history", "w.json", "50"]);
    assert!(hist.lines().any(|l| l.contains(&txid_of(&b))), "{hist}");
    let paid = cli.ok(&["send", "w.json", &outside, "0.5", "--yes"]);
    assert!(paid.starts_with("sent, txid"), "{paid}");
    wait("the payment through the API to confirm", || cli.confirmed(&outside) == 250_000_000);
    let (ok, out, err) = cli.run_env(&["restore", "r2.json", "--no-passphrase"], &[("REQUANT_WALLET_PHRASE", &phrase)]);
    assert!(ok && out.contains("found 2 receive and 3 change"), "{out} {err}");
    // what the API does not offer is said so
    let (ok, _, err) = cli.run_env(&["tx", "nothex"], &[]);
    assert!(!ok, "{err}");
    cli.api = None;
    cli.rpc = h.rpc.unwrap().to_string();

    // an encrypted wallet: the passphrase opens it, a wrong one does not, the file holds no plain secret
    let pw = [("REQUANT_WALLET_PASSPHRASE", "correct horse")];
    assert!(cli.run_env(&["create", "e.json"], &pw).0);
    let e = std::fs::read_to_string(d.join("e.json")).unwrap();
    assert!(e.contains("requant-seed:1:argon2id"));
    let (ok, phrase_e, _) = cli.run_env(&["phrase", "e.json"], &pw);
    assert!(ok && phrase_e.trim().split(' ').count() == 24);
    let (ok, _, err) = cli.run_env(&["phrase", "e.json"], &[("REQUANT_WALLET_PASSPHRASE", "wrong")]);
    assert!(!ok && err.contains("wrong passphrase"), "{err}");
    // balance needs no passphrase
    assert!(cli.run_env(&["balance", "e.json"], &[]).0);

    h.shutdown();
    drop(h);
    let _ = std::fs::remove_dir_all(&d);
}
