//! `requant-wallet`: wallets, keys, addresses, balance and payments through a node's JSON-RPC.
//!
//! A wallet (one file, many addresses, one 24-word backup phrase):
//! requant-wallet create      WALLET [--no-passphrase]          (shows the backup phrase once)
//! requant-wallet restore     WALLET [--no-passphrase] [--no-scan]   (from the phrase; finds the used addresses)
//! requant-wallet phrase      WALLET                           (show the backup phrase again)
//! requant-wallet newaddress  WALLET                           (a fresh receive address)
//! requant-wallet addresses   WALLET                           (addresses handed out, with their coins)
//! requant-wallet watchonly   WALLET OUT                       (a copy without the secret, for an online machine)
//! Offline signing: prepare on an online machine (a watch-only copy is enough), sign on one without network:
//! requant-wallet prepare     WALLET ADDRESS AMOUNT [ADDRESS AMOUNT]... [--out FILE]   (AMOUNT in RQT, or "all")
//! requant-wallet sign        WALLET FILE [--out FILE]
//! requant-wallet broadcast   FILE
//!
//! A single key (the older format; still works everywhere a WALLET does, except the commands above):
//! requant-wallet keygen      KEYFILE [--no-passphrase]
//! requant-wallet address     KEYFILE|WALLET
//! requant-wallet encrypt     KEYFILE|WALLET                   (encrypt, or change the passphrase)
//!
//! Either: balance, history [N], coins of an ADDRESS, KEYFILE or WALLET; tx TXID;
//! send WALLET|KEYFILE ADDRESS AMOUNT|all [ADDRESS AMOUNT]...; consolidate WALLET|KEYFILE.
//!
//! Options: --network test|regtest (default test, or the wallet's), --rpc HOST:PORT, --fee-rate
//! ATOMS_PER_BYTE|fast|normal|slow (default normal: the node's `estimatefee` for 3 blocks), --api
//! http://HOST:PORT (a node's public API instead of RPC: no node of one's own needed), --yes (send
//! without asking), --out FILE, --rpc-cookie FILE (the node's `.cookie`, when it runs with `--rpc-cookie`).
//! Environment (for scripts): REQUANT_WALLET_PASSPHRASE, REQUANT_WALLET_PHRASE (for restore),
//! REQUANT_RPC_TOKEN, REQUANT_RPC_COOKIE.

use ed25519_dalek::SigningKey;
use requant_consensus::params::Network;
use requant_consensus::tx::{Hash, OutPoint, Tx};
use requant_node::rpc::{hex, unhex};
use requant_wallet::backend::Backend;
use requant_wallet::hd;
use requant_wallet::wallet::{Unsigned, WalletFile};
use requant_wallet::*;
use serde_json::json;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use zeroize::Zeroizing;

fn die(msg: &str) -> ! {
    eprintln!("requant-wallet: {msg}");
    std::process::exit(1)
}

/// Passphrase from `REQUANT_WALLET_PASSPHRASE`, else asked on the terminal (twice when `confirm`).
fn passphrase(prompt: &str, confirm: bool) -> Zeroizing<String> {
    if let Ok(p) = std::env::var("REQUANT_WALLET_PASSPHRASE") {
        return Zeroizing::new(p);
    }
    let p = Zeroizing::new(rpassword::prompt_password(prompt).unwrap_or_else(|e| die(&format!("passphrase: {e}"))));
    if confirm && *Zeroizing::new(rpassword::prompt_password("repeat it: ").unwrap_or_default()) != *p {
        die("the passphrases differ");
    }
    p
}

/// A new passphrase, or none with `--no-passphrase`.
fn new_passphrase(plain: bool) -> Option<Zeroizing<String>> {
    if plain {
        return None;
    }
    let p = passphrase("new passphrase: ", true);
    if p.is_empty() {
        die("empty passphrase; use --no-passphrase for an unencrypted file");
    }
    Some(p)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).unwrap_or_else(|e| die(&format!("random: {e}")));
    b
}

/// Write a file atomically (temporary file, then rename).
fn write_file(path: &str, text: &str) {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, format!("{}\n", text.trim_end())).unwrap_or_else(|e| die(&format!("{tmp}: {e}")));
    std::fs::rename(&tmp, path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}")))
}

fn refuse_existing(path: &str) {
    if std::path::Path::new(path).exists() {
        die(&format!("{path} exists; refusing to overwrite it"));
    }
}

fn load_key(path: &str) -> SigningKey {
    let text = read(path);
    let pass = is_encrypted(&text).then(|| passphrase(&format!("passphrase for {path}: "), false));
    SigningKey::from_bytes(&decrypt_key(&text, pass.as_ref().map(|p| p.as_str())).unwrap_or_else(|e| die(e)))
}

/// What a command works on.
enum Source {
    Address(Hash),
    Key(String),
    Wallet(String, WalletFile),
}

fn source(net: &Network, s: &str) -> Source {
    match parse_address(net, s) {
        Ok(o) => Source::Address(o),
        Err(e) if !std::path::Path::new(s).is_file() => die(e),
        Err(_) => {
            let text = read(s);
            if WalletFile::is_wallet(&text) {
                let w = WalletFile::parse(&text).unwrap_or_else(|e| die(&format!("{s}: {e}")));
                if w.network != net.name {
                    die(&format!("{s} is a wallet of the {} network (pass --network {})", w.network, w.network));
                }
                Source::Wallet(s.to_string(), w)
            } else {
                Source::Key(s.to_string())
            }
        }
    }
}

fn wallet_arg(net: &Network, s: &str) -> (String, WalletFile) {
    match source(net, s) {
        Source::Wallet(p, w) => (p, w),
        _ => die(&format!("{s} is not a wallet file (make one with `create` or `restore`)")),
    }
}

/// The wallet's seed, after the passphrase if it is encrypted.
fn unlock(path: &str, w: &WalletFile) -> Zeroizing<[u8; 64]> {
    if w.watch_only() {
        die(&format!("{path} is watch-only: sign on the machine that holds the wallet (see `prepare`)"));
    }
    let pass = w.is_encrypted().then(|| passphrase(&format!("passphrase for {path}: "), false));
    let e = w
        .entropy(pass.as_ref().map(|p| p.as_str()))
        .unwrap_or_else(|e| die(if e == "wrong" { "wrong passphrase or damaged wallet file" } else { &e }));
    hd::seed_of(&e, "")
}

fn save(path: &str, w: &WalletFile) {
    write_file(path, &w.to_text());
}

/// `(coin, spendable now, confirmed)` of one owner.
fn coins(rpc: &Backend, owner: &Hash) -> Vec<(Spendable, bool, bool)> {
    let v = rpc.call("utxos", json!([hex(owner)])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
    let Some(list) = v.as_array() else { die(&format!("unexpected answer to utxos: {v}")) };
    list.iter()
        .map(|c| {
            let txid: [u8; 32] = unhex(c["txid"].as_str().unwrap()).unwrap().try_into().unwrap();
            let op = OutPoint { txid, vout: c["vout"].as_u64().unwrap() as u32 };
            (
                Spendable { op, value: c["value"].as_u64().unwrap(), owner: *owner },
                c["spendable"].as_bool().unwrap(),
                c["confirmed"].as_bool().unwrap_or(true),
            )
        })
        .collect()
}

/// Coins of many owners: a hundred per request (each entry names its owner), or one request per owner
/// with a node too old for lists.
fn all_coins(rpc: &Backend, owners: &[Hash]) -> Vec<(Spendable, bool, bool)> {
    let mut all = Vec::new();
    for chunk in owners.chunks(100) {
        let list: Vec<String> = chunk.iter().map(|o| hex(o)).collect();
        let Ok(v) = rpc.call("utxos", json!([list])) else {
            return owners.iter().flat_map(|o| coins(rpc, o)).collect();
        };
        let Some(items) = v.as_array() else { die(&format!("unexpected answer to utxos: {v}")) };
        for c in items {
            let owner = c["owner"].as_str().and_then(|h| unhex(h).ok()).and_then(|b| b.try_into().ok());
            let txid = c["txid"].as_str().and_then(|h| unhex(h).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok());
            let (Some(owner), Some(txid)) = (owner, txid) else { die(&format!("unexpected coin in utxos: {c}")) };
            let op = OutPoint { txid, vout: c["vout"].as_u64().unwrap_or(0) as u32 };
            all.push((
                Spendable { op, value: c["value"].as_u64().unwrap_or(0), owner },
                c["spendable"].as_bool().unwrap_or(false),
                c["confirmed"].as_bool().unwrap_or(true),
            ));
        }
    }
    all
}

fn owners(src: &Source) -> Vec<Hash> {
    match src {
        Source::Address(o) => vec![*o],
        Source::Key(p) => vec![owner_of(&load_key(p))],
        Source::Wallet(_, w) => w.owners(),
    }
}

/// Ask before sending, unless `--yes` was given.
fn confirm(question: &str, yes: bool) {
    if yes {
        return;
    }
    eprint!("{question} [y/N] ");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    if !matches!(line.trim(), "y" | "Y" | "yes" | "д" | "да") {
        die("cancelled");
    }
}

fn send(rpc: &Backend, tx: &Tx) -> String {
    let txid = rpc.call("sendtx", json!([hex(&tx.encode())])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
    txid.as_str().unwrap_or("").to_string()
}

fn show_payment(net: &Network, lines: &[(Hash, u64, bool)], fee: u64, size: usize) {
    for (to, v, change) in lines {
        let what = if *change { "change" } else { "to" };
        eprintln!("  {:>20} RQT  {what} {}", format_amount(*v), address(net, to));
    }
    eprintln!("  {:>20} RQT  fee ({size} bytes)", format_amount(fee));
}

/// An unsigned transaction, the coins it spends (in input order), `(to, amount, is change)` per output, and
/// its fee.
type Planned = (Tx, Vec<Spendable>, Vec<(Hash, u64, bool)>, u64);

/// A payment from `spendable` as asked on the command line: `[ADDRESS all]` sweeps, otherwise pairs of
/// address and amount with change to `change_to`. Unsigned; returns the coins spent and what it pays.
fn plan(
    net: &Network,
    mut spendable: Vec<Spendable>,
    pairs: &[(&str, &str)],
    rate: u64,
    change_to: impl FnOnce() -> Hash,
) -> Planned {
    if let [(to, "all")] = pairs {
        let to = parse_address(net, to).unwrap_or_else(|e| die(e));
        spendable.sort_by_key(|c| std::cmp::Reverse(c.value));
        if spendable.len() > MAX_INPUTS {
            eprintln!("note: {} coins; this sends the largest {MAX_INPUTS} (send again for the rest)", spendable.len());
        }
        let (tx, chosen, sent, fee) = plan_sweep(&spendable, &to, rate).unwrap_or_else(|e| die(&e));
        return (tx, chosen, vec![(to, sent, false)], fee);
    }
    let payments: Vec<(Hash, u64)> = pairs
        .iter()
        .map(|(to, a)| {
            if *a == "all" {
                die("\"all\" works with a single recipient");
            }
            (parse_address(net, to).unwrap_or_else(|e| die(e)), parse_amount(a).unwrap_or_else(|e| die(e)))
        })
        .collect();
    let change = change_to();
    let (tx, chosen, fee) = plan_payment(&spendable, &payments, rate, change).unwrap_or_else(|e| die(&e));
    let n = payments.len();
    let lines = tx.outputs().iter().enumerate().map(|(k, o)| (o.pkh, o.value, k >= n)).collect();
    (tx, chosen, lines, fee)
}

/// Next change address of a wallet, deriving more first when the seed is at hand.
/// Next change address of a wallet, deriving more first when the seed is at hand. Addresses the node has
/// seen used are skipped: a watch-only copy and the wallet it came from hand out change separately.
fn next_change(w: &mut WalletFile, seed: Option<&[u8; 64]>, rpc: &Backend) -> Hash {
    loop {
        if let Some(s) = seed {
            w.top_up(s);
        }
        let c = w.next_change().unwrap_or_else(|| {
            die("no unused change address left in this copy: export a fresh watch-only copy from the signing wallet")
        });
        let used = rpc.call("history", json!([hex(&c), 1])).is_ok_and(|v| v.as_array().is_some_and(|a| !a.is_empty()));
        if !used {
            return c;
        }
    }
}

fn print_history(rpc: &Backend, owners: &[Hash], limit: u64) {
    // per transaction, what the whole wallet received and sent (moves between its own addresses net out)
    type Row = (Option<u64>, serde_json::Value, u64, u64);
    let mut by_tx: HashMap<String, Row> = HashMap::new();
    // a hundred owners per request, or one request each with a node too old for lists
    let mut answers = Vec::new();
    for chunk in owners.chunks(100) {
        let list: Vec<String> = chunk.iter().map(|o| hex(o)).collect();
        match rpc.call("history", json!([list, limit])) {
            Ok(v) => answers.push(v),
            Err(_) => {
                answers = owners
                    .iter()
                    .map(|o| rpc.call("history", json!([hex(o), limit])).unwrap_or_else(|e| die(&format!("rpc: {e}"))))
                    .collect();
                break;
            }
        }
    }
    for v in answers {
        let Some(items) = v.as_array() else { die(&format!("unexpected answer to history: {v}")) };
        for e in items {
            let id = e["txid"].as_str().unwrap_or("").to_string();
            let entry = by_tx.entry(id).or_insert((e["height"].as_u64(), e["confirmations"].clone(), 0, 0));
            entry.2 += e["received"].as_u64().unwrap_or(0);
            entry.3 += e["sent"].as_u64().unwrap_or(0);
        }
    }
    let mut rows: Vec<_> = by_tx.into_iter().collect();
    rows.sort_by_key(|(_, (h, ..))| std::cmp::Reverse(h.unwrap_or(u64::MAX)));
    println!("{:>8}  {:>6}  {:>20}  txid", "height", "conf", "amount RQT");
    for (txid, (height, conf, r, s)) in rows.into_iter().take(limit as usize) {
        let amount = if r >= s { format!("+{}", format_amount(r - s)) } else { format!("-{}", format_amount(s - r)) };
        let height = height.map(|h| h.to_string()).unwrap_or_else(|| "pending".into());
        println!("{height:>8}  {conf:>6}  {amount:>20}  {txid}");
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut flag = |name: &str| args.iter().position(|a| a == name).map(|k| args.remove(k)).is_some();
    let plain = flag("--no-passphrase");
    let yes = flag("--yes");
    let no_scan = flag("--no-scan");
    let mut opt = |name: &str| -> Option<String> {
        let k = args.iter().position(|a| a == name)?;
        let v = args.get(k + 1).cloned().unwrap_or_else(|| die(&format!("{name} needs a value")));
        args.drain(k..k + 2);
        Some(v)
    };
    let net_opt = opt("--network");
    let api = opt("--api");
    let rpc_opt = opt("--rpc");
    let out = opt("--out");
    if let Some(c) = opt("--rpc-cookie") {
        // the RPC client reads the cookie file named here (see `requant_node::rpc::request`)
        std::env::set_var("REQUANT_RPC_COOKIE", c);
    }
    if opt("--fee").is_some() {
        die("--fee is replaced by --fee-rate ATOMS_PER_BYTE (the fee now follows the transaction's size)");
    }
    let fee_opt = opt("--fee-rate").unwrap_or_else(|| "normal".into());
    // the network: as given, else the wallet file's (second argument), else the test network
    let wallet_net = args.get(1).filter(|p| std::path::Path::new(p.as_str()).is_file()).and_then(|p| {
        let t = std::fs::read_to_string(p).ok()?;
        if WalletFile::is_wallet(&t) {
            WalletFile::parse(&t).ok().map(|w| w.network)
        } else {
            None
        }
    });
    let net_name = net_opt.or(wallet_net).unwrap_or_else(|| "test".into());
    let net = Network::by_name(&net_name).unwrap_or_else(|| die("unknown network"));
    let default_rpc = if net.name == "test" { "127.0.0.1:19334" } else { "127.0.0.1:19445" };
    let rpc_s = rpc_opt.unwrap_or_else(|| default_rpc.into());
    let rpc = || -> Backend {
        match &api {
            Some(url) => Backend::api(url).unwrap_or_else(|e| die(&format!("--api: {e}"))),
            None => Backend::Rpc(
                rpc_s.to_socket_addrs().ok().and_then(|mut a| a.next()).unwrap_or_else(|| die("bad --rpc address")),
            ),
        }
    };
    // the fee rate: a number of atoms per byte, or fast / normal / slow from the node's estimate (the next
    // 1, 3 or 10 blocks' worth of its pool), falling back to the default with a node that has no estimate
    let rate = || -> u64 {
        let blocks = match fee_opt.as_str() {
            "fast" => 1,
            "normal" => 3,
            "slow" => 10,
            n => return n.parse().unwrap_or_else(|_| die("bad --fee-rate: a number, fast, normal or slow")),
        };
        match rpc().call("estimatefee", json!([blocks])) {
            Ok(v) => {
                let r = v["feerate"].as_u64().unwrap_or(DEFAULT_FEE_RATE);
                eprintln!("fee rate {r} atoms/byte ({fee_opt}: the next {blocks} block(s))");
                r
            }
            Err(_) => DEFAULT_FEE_RATE,
        }
    };
    let write_out = |text: &str, what: &str| match &out {
        Some(p) => {
            write_file(p, text);
            eprintln!("{what} written to {p}");
        }
        None => println!("{text}"),
    };
    match args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
        // ---- wallets ----------------------------------------------------------------------------
        ["create", path] => {
            refuse_existing(path);
            let entropy = Zeroizing::new(random::<32>());
            let pass = new_passphrase(plain);
            let w = WalletFile::new(&net, &entropy, pass.as_ref().map(|p| p.as_str()), &random(), &random())
                .unwrap_or_else(|e| die(&e));
            save(path, &w);
            let phrase = hd::phrase_of(&entropy);
            println!("wallet written to {path}");
            println!();
            println!("Backup phrase. Write these 24 words down, in order, and keep them offline:");
            println!("they restore every address of this wallet. Anyone who has them can spend its coins.");
            println!();
            for (k, word) in phrase.split(' ').enumerate() {
                print!("{:>2}. {word:<10}", k + 1);
                if k % 6 == 5 {
                    println!();
                }
            }
            println!();
            println!("address  {}", address(&net, &w.receive[0]));
        }
        ["restore", path] => {
            refuse_existing(path);
            let phrase = match std::env::var("REQUANT_WALLET_PHRASE") {
                Ok(p) => Zeroizing::new(p),
                Err(_) => Zeroizing::new(
                    rpassword::prompt_password("backup phrase (24 words, not shown): ")
                        .unwrap_or_else(|e| die(&format!("phrase: {e}"))),
                ),
            };
            let entropy = hd::entropy_of(&phrase).unwrap_or_else(|e| die(&e));
            let pass = new_passphrase(plain);
            let mut w = WalletFile::new(&net, &entropy, pass.as_ref().map(|p| p.as_str()), &random(), &random())
                .unwrap_or_else(|e| die(&e));
            if no_scan {
                eprintln!("not scanning: only the first address is handed out (restore again with a node to find the rest)");
            } else {
                let seed = hd::seed_of(&entropy, "");
                let addr = rpc();
                w.scan(&seed, |batch| {
                    // one request for the batch (entries name their owner); one per address with an older node
                    let list: Vec<String> = batch.iter().map(|o| hex(o)).collect();
                    if let Ok(v) = addr.call("history", json!([list, 1])) {
                        let seen: std::collections::HashSet<&str> =
                            v.as_array().into_iter().flatten().filter_map(|e| e["owner"].as_str()).collect();
                        return Ok(list.iter().map(|o| seen.contains(o.as_str())).collect());
                    }
                    batch
                        .iter()
                        .map(|o| {
                            let v = addr.call("history", json!([hex(o), 1])).map_err(|e| format!("rpc: {e}"))?;
                            Ok(v.as_array().is_some_and(|a| !a.is_empty()))
                        })
                        .collect()
                })
                .unwrap_or_else(|e| die(&format!("{e} (use --no-scan to restore without a node)")));
                println!("found {} receive and {} change addresses in use", w.receive_issued, w.change_issued);
            }
            save(path, &w);
            println!("wallet restored to {path}");
            println!("address  {}", address(&net, &w.receive[w.receive_issued as usize - 1]));
        }
        ["phrase", path] => {
            let (path, w) = wallet_arg(&net, path);
            if w.watch_only() {
                die("a watch-only copy holds no phrase");
            }
            let pass = w.is_encrypted().then(|| passphrase(&format!("passphrase for {path}: "), false));
            let e = w
                .entropy(pass.as_ref().map(|p| p.as_str()))
                .unwrap_or_else(|_| die("wrong passphrase or damaged wallet file"));
            println!("{}", hd::phrase_of(&e).as_str());
        }
        ["newaddress", path] => {
            let (path, mut w) = wallet_arg(&net, path);
            let owner = match w.next_receive() {
                Some(o) => o,
                None => {
                    // every derived address is handed out: derive more (needs the seed)
                    let seed = unlock(&path, &w);
                    w.top_up(&seed);
                    w.next_receive().unwrap()
                }
            };
            save(&path, &w);
            println!("{}", address(&net, &owner));
        }
        ["addresses", path] => {
            let (_, w) = wallet_arg(&net, path);
            let mut held: HashMap<Hash, u64> = HashMap::new();
            for (c, ..) in all_coins(&rpc(), &w.owners()) {
                *held.entry(c.owner).or_default() += c.value;
            }
            println!("{:<8}  {:>20}  address", "path", "amount RQT");
            for (chain, list, issued) in [("r", &w.receive, w.receive_issued), ("c", &w.change, w.change_issued)] {
                for (i, o) in list.iter().enumerate() {
                    let value = held.get(o).copied().unwrap_or(0);
                    // handed-out addresses always; derived-ahead ones only when they hold something
                    if (i as u32) < issued || value > 0 {
                        println!("{:<8}  {:>20}  {}", format!("{chain}/{i}"), format_amount(value), address(&net, o));
                    }
                }
            }
        }
        ["watchonly", path, dest] => {
            let (_, w) = wallet_arg(&net, path);
            refuse_existing(dest);
            save(dest, &w.watch_copy());
            println!("watch-only copy written to {dest}: it can show balances and prepare payments, not sign them");
        }
        ["prepare", path, rest @ ..] if !rest.is_empty() && rest.len() % 2 == 0 => {
            let (path, mut w) = wallet_arg(&net, path);
            let addr = rpc();
            let spendable: Vec<Spendable> =
                all_coins(&addr, &w.owners()).into_iter().filter(|c| c.1).map(|c| c.0).collect();
            let pairs: Vec<(&str, &str)> = rest.chunks(2).map(|p| (p[0], p[1])).collect();
            let (tx, chosen, lines, fee) = plan(&net, spendable, &pairs, rate(), || next_change(&mut w, None, &addr));
            // the transactions that created the coins spent, so the signer can check their values
            let mut prev: Vec<Tx> = Vec::new();
            for c in &chosen {
                if prev.iter().any(|t| t.txid() == c.op.txid) {
                    continue;
                }
                let v =
                    addr.call("gettx", json!([hex(&c.op.txid)])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
                let bytes =
                    v["hex"].as_str().and_then(|h| unhex(h).ok()).unwrap_or_else(|| die("rpc: gettx gave no hex"));
                let t = Tx::decode_exact(&bytes).unwrap_or_else(|e| die(&format!("rpc: {e}")));
                if t.txid() != c.op.txid {
                    die("rpc: gettx returned another transaction");
                }
                prev.push(t);
            }
            let change = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.2)
                .map(|(k, l)| {
                    let (c, i) = w.path_of(&l.0).unwrap();
                    (k as u32, c, i)
                })
                .collect();
            let u = Unsigned {
                network: net.name.to_string(),
                paths: chosen.iter().map(|c| w.path_of(&c.owner).unwrap()).collect(),
                tx,
                prev,
                change,
            };
            show_payment(&net, &lines, fee, transfer_size(chosen.len(), lines.len()) as usize);
            save(&path, &w);
            write_out(&u.to_text(), "unsigned payment");
            eprintln!("next: `requant-wallet sign WALLET FILE` on the signing machine, then `broadcast` the result here");
        }
        ["sign", path, file] => {
            let (path, w) = wallet_arg(&net, path);
            let u = Unsigned::parse(&read(file)).unwrap_or_else(|e| die(&e));
            if u.network != net.name {
                die(&format!("{file} is a payment on the {} network", u.network));
            }
            let seed = unlock(&path, &w);
            let r = u.review(&seed).unwrap_or_else(|e| die(&format!("refusing to sign: {e}")));
            eprintln!("  {:>20} RQT  spent from this wallet", format_amount(r.spent));
            show_payment(&net, &r.outputs, r.fee, u.tx.encode().len());
            confirm("sign?", yes);
            let tx = u.sign(&net, &seed);
            tx.check_standalone(&net.chain_id).unwrap_or_else(|e| die(&format!("signing failed: {e}")));
            write_out(&hex(&tx.encode()), "signed transaction");
        }
        ["broadcast", file] => {
            let text = read(file);
            let bytes = unhex(text.trim()).unwrap_or_else(|_| die(&format!("{file}: not a signed transaction (hex)")));
            let tx = Tx::decode_exact(&bytes).unwrap_or_else(|e| die(&format!("{file}: {e}")));
            tx.check_standalone(&net.chain_id).unwrap_or_else(|e| die(&format!("{file}: {e}")));
            println!("sent, txid {}", send(&rpc(), &tx));
        }
        // ---- single keys ------------------------------------------------------------------------
        ["keygen", path] => {
            refuse_existing(path);
            let secret = Zeroizing::new(random::<32>());
            match new_passphrase(plain) {
                None => {
                    write_file(path, &hex(&secret[..]));
                    println!("unencrypted key written to {path} (back it up; anyone with this file can spend its coins)");
                }
                Some(pass) => {
                    write_file(path, &encrypt_key(&secret, &pass, &random(), &random()).unwrap_or_else(|e| die(e)));
                    println!("encrypted key written to {path} (back it up and remember the passphrase: both are needed)");
                }
            }
            let key = SigningKey::from_bytes(&secret);
            println!("address  {}", address(&net, &owner_of(&key)));
            println!("key hash {}", hex(&owner_of(&key)));
        }
        ["encrypt", path] => match source(&net, path) {
            Source::Wallet(path, mut w) => {
                if w.watch_only() {
                    die("a watch-only copy holds no secret to encrypt");
                }
                let pass = w.is_encrypted().then(|| passphrase(&format!("passphrase for {path}: "), false));
                let e = w
                    .entropy(pass.as_ref().map(|p| p.as_str()))
                    .unwrap_or_else(|_| die("wrong passphrase or damaged wallet file"));
                let new = passphrase("new passphrase: ", true);
                if new.is_empty() {
                    die("empty passphrase");
                }
                w.reseal(&e, Some(&new), &random(), &random()).unwrap_or_else(|e| die(&e));
                save(&path, &w);
                println!("{path} is now encrypted under the new passphrase");
            }
            Source::Key(path) => {
                // encrypt an unencrypted key file, or change the passphrase of an encrypted one
                let key = load_key(&path);
                let pass = passphrase("new passphrase: ", true);
                if pass.is_empty() {
                    die("empty passphrase");
                }
                write_file(&path, &encrypt_key(&key.to_bytes(), &pass, &random(), &random()).unwrap_or_else(|e| die(e)));
                println!("{path} is now encrypted ({})", address(&net, &owner_of(&key)));
            }
            Source::Address(_) => die("encrypt takes a key file or a wallet"),
        },
        ["address", path] => match source(&net, path) {
            Source::Wallet(_, w) => {
                // the latest receive address; its key hash is what a miner's --payee takes
                let o = w.receive[w.receive_issued as usize - 1];
                println!("address  {}", address(&net, &o));
                println!("key hash {}", hex(&o));
            }
            Source::Key(path) => {
                let key = load_key(&path);
                println!("address  {}", address(&net, &owner_of(&key)));
                println!("key hash {}", hex(&owner_of(&key)));
                println!("pubkey   {}", hex(&key.verifying_key().to_bytes()));
            }
            Source::Address(_) => die("address takes a key file or a wallet"),
        },
        // release signing (maintainers): the signature of a release manifest, checked by the manifest parser
        ["sign-release", path, manifest] => {
            use ed25519_dalek::Signer;
            let key = load_key(path);
            let text = read(manifest);
            let sig = key.sign(&requant_node::release::signed_message(&text)).to_bytes();
            requant_node::release::Release::verify_with(&text, &sig, &key.verifying_key().to_bytes())
                .unwrap_or_else(|e| die(e));
            println!("{}", hex(&sig));
        }
        // ---- either -----------------------------------------------------------------------------
        ["balance", src] => {
            let list = all_coins(&rpc(), &owners(&source(&net, src)));
            let sum = |f: &dyn Fn(&(Spendable, bool, bool)) -> bool| {
                list.iter().filter(|c| f(c)).map(|c| c.0.value).sum::<u64>()
            };
            let confirmed = sum(&|c| c.1 && c.2);
            let pending = sum(&|c| !c.2);
            let immature = sum(&|c| !c.1);
            println!(
                "confirmed   {} RQT in {} outputs",
                format_amount(confirmed),
                list.iter().filter(|c| c.1 && c.2).count()
            );
            println!("unconfirmed {} RQT (spendable)", format_amount(pending));
            println!("immature    {} RQT (mined, not yet spendable)", format_amount(immature));
        }
        ["history", src, rest @ ..] if rest.len() <= 1 => {
            let limit: u64 = rest.first().map(|n| n.parse().unwrap_or_else(|_| die("bad count"))).unwrap_or(20);
            print_history(&rpc(), &owners(&source(&net, src)), limit);
        }
        ["tx", txid] => {
            let v = rpc().call("gettx", json!([txid])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
            let show = |owner: &serde_json::Value| -> String {
                owner
                    .as_str()
                    .and_then(|h| unhex(h).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .map(|o| address(&net, &o))
                    .unwrap_or_else(|| "?".into())
            };
            let height = v["height"].as_u64().map(|h| h.to_string()).unwrap_or_else(|| "pending".into());
            println!(
                "txid {}  height {height}  confirmations {}",
                v["txid"].as_str().unwrap_or(""),
                v["confirmations"]
            );
            if v["coinbase"] == true {
                println!("  coinbase (newly mined)");
            }
            for i in v["inputs"].as_array().unwrap() {
                println!("  in  {:>20}  {}", format_amount(i["value"].as_u64().unwrap_or(0)), show(&i["owner"]));
            }
            for o in v["outputs"].as_array().unwrap() {
                println!("  out {:>20}  {}", format_amount(o["value"].as_u64().unwrap_or(0)), show(&o["owner"]));
            }
            println!("  fee {:>20}", format_amount(v["fee"].as_u64().unwrap_or(0)));
        }
        ["coins", src] => {
            let mut list = all_coins(&rpc(), &owners(&source(&net, src)));
            list.sort_by_key(|c| std::cmp::Reverse(c.0.value));
            println!("{:>20}  {:<11}  outpoint", "amount RQT", "status");
            for (c, spendable, confirmed) in &list {
                let status = match (spendable, confirmed) {
                    (false, _) => "immature",
                    (true, false) => "unconfirmed",
                    (true, true) => "spendable",
                };
                println!("{:>20}  {status:<11}  {}:{}", format_amount(c.value), hex(&c.op.txid), c.op.vout);
            }
            let total: u64 = list.iter().map(|c| c.0.value).sum();
            println!("{} coins, {} RQT", list.len(), format_amount(total));
        }
        ["send", src, rest @ ..] if !rest.is_empty() && rest.len() % 2 == 0 => {
            let pairs: Vec<(&str, &str)> = rest.chunks(2).map(|p| (p[0], p[1])).collect();
            match source(&net, src) {
                Source::Key(path) => {
                    let key = load_key(&path);
                    let me = owner_of(&key);
                    let spendable: Vec<Spendable> =
                        coins(&rpc(), &me).into_iter().filter(|c| c.1).map(|c| c.0).collect();
                    let (mut tx, chosen, lines, fee) = plan(&net, spendable, &pairs, rate(), || me);
                    show_payment(&net, &lines, fee, transfer_size(chosen.len(), lines.len()) as usize);
                    confirm("send?", yes);
                    let keys = HashMap::from([(me, key)]);
                    sign_with(&net, &mut tx, &chosen, &keys).unwrap_or_else(|e| die(&e));
                    println!("sent, txid {}", send(&rpc(), &tx));
                }
                Source::Wallet(path, mut w) => {
                    let seed = unlock(&path, &w);
                    let spendable: Vec<Spendable> =
                        all_coins(&rpc(), &w.owners()).into_iter().filter(|c| c.1).map(|c| c.0).collect();
                    let (mut tx, chosen, lines, fee) =
                        plan(&net, spendable, &pairs, rate(), || next_change(&mut w, Some(&seed), &rpc()));
                    show_payment(&net, &lines, fee, transfer_size(chosen.len(), lines.len()) as usize);
                    confirm("send?", yes);
                    sign_with(&net, &mut tx, &chosen, &w.keyring(&seed)).unwrap_or_else(|e| die(&e));
                    save(&path, &w);
                    println!("sent, txid {}", send(&rpc(), &tx));
                }
                Source::Address(_) => die("send takes a wallet or a key file"),
            }
        }
        ["consolidate", src] => {
            let (keys, mut spendable, to, wallet) = match source(&net, src) {
                Source::Key(path) => {
                    let key = load_key(&path);
                    let me = owner_of(&key);
                    let c: Vec<Spendable> = coins(&rpc(), &me).into_iter().filter(|c| c.1).map(|c| c.0).collect();
                    (HashMap::from([(me, key)]), c, me, None)
                }
                Source::Wallet(path, mut w) => {
                    let seed = unlock(&path, &w);
                    let c: Vec<Spendable> =
                        all_coins(&rpc(), &w.owners()).into_iter().filter(|c| c.1).map(|c| c.0).collect();
                    let to = next_change(&mut w, Some(&seed), &rpc());
                    (w.keyring(&seed), c, to, Some((path, w)))
                }
                Source::Address(_) => die("consolidate takes a wallet or a key file"),
            };
            if spendable.len() < 2 {
                die("nothing to merge: fewer than two spendable coins");
            }
            // the smallest first: those are what make payments large
            spendable.sort_by_key(|c| c.value);
            let n = spendable.len().min(MAX_INPUTS);
            let (mut tx, chosen, kept, fee) = plan_sweep(&spendable, &to, rate()).unwrap_or_else(|e| die(&e));
            eprintln!(
                "  merge {n} of {} coins into one of {} RQT, fee {} RQT",
                spendable.len(),
                format_amount(kept),
                format_amount(fee)
            );
            confirm("send?", yes);
            sign_with(&net, &mut tx, &chosen, &keys).unwrap_or_else(|e| die(&e));
            if let Some((path, w)) = wallet {
                save(&path, &w);
            }
            println!("sent, txid {}", send(&rpc(), &tx));
        }
        _ => die(concat!(
            "usage: requant-wallet create WALLET [--no-passphrase] | restore WALLET [--no-scan] | phrase WALLET\n",
            "       | newaddress WALLET | addresses WALLET | watchonly WALLET OUT\n",
            "       | prepare WALLET ADDRESS AMOUNT|all [ADDRESS AMOUNT]... [--out FILE] | sign WALLET FILE [--out FILE]\n",
            "       | broadcast FILE | keygen KEYFILE [--no-passphrase] | encrypt KEYFILE|WALLET | address KEYFILE|WALLET\n",
            "       | balance SRC | history SRC [N] | coins SRC | tx TXID   (SRC: an address, a key file or a wallet)\n",
            "       | send WALLET|KEYFILE ADDRESS AMOUNT|all [ADDRESS AMOUNT]... | consolidate WALLET|KEYFILE\n",
            "options: --network test|regtest (default test, or the wallet's) --rpc HOST:PORT\n",
            "         --fee-rate ATOMS_PER_BYTE|fast|normal|slow (default normal: the node's estimate) --yes --out FILE"
        )),
    }
}
