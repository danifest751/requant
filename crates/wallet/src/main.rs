//! `requant-wallet`: wallets, keys, addresses, balance and payments through a node's JSON-RPC.
//!
//! A wallet (one file, many addresses, one 24-word backup phrase):
//! requant-wallet create      WALLET [--no-passphrase]          (shows the backup phrase once)
//! requant-wallet restore     WALLET [--no-passphrase] [--no-scan] [--count N]   (from the phrase; finds the used
//!                                                           addresses; --count: at least N receive addresses,
//!                                                           for a deposit list with long unused runs)
//! requant-wallet phrase      WALLET                           (show the backup phrase again)
//! requant-wallet newaddress  WALLET [--count N] [--out FILE] (fresh receive addresses, one per line;
//!                                                           N at once for a service's deposit list)
//! requant-wallet addresses   WALLET                           (addresses handed out, with their coins)
//! requant-wallet watchonly   WALLET OUT                       (a copy without the secret, for an online machine)
//! Offline signing: prepare on an online machine (a watch-only copy is enough), sign on one without network:
//! requant-wallet prepare     WALLET ADDRESS AMOUNT [ADDRESS AMOUNT]... [--out FILE]   (AMOUNT in RQT, or "all")
//! requant-wallet sign        WALLET FILE [--out FILE]
//! requant-wallet broadcast   FILE [FILE]...               (several: a package, parents first, so a child can
//!                                                           pay for a parent below the minimum fee)
//!
//! A single key (the older format; still works everywhere a WALLET does, except the commands above):
//! requant-wallet keygen      KEYFILE [--no-passphrase]
//! requant-wallet address     KEYFILE|WALLET
//! requant-wallet encrypt     KEYFILE|WALLET                   (encrypt, or change the passphrase)
//!
//! Spending conditions (CHAIN.md §4.1–4.2): lock coins with an ordinary `send` to a condition's address.
//! requant-wallet secret                                      (a random 32-byte secret and its SHA-256)
//! requant-wallet pubkey      WALLET|KEYFILE                  (public key of the current address, for 2-of-2)
//! requant-wallet condition   multi2 PUB_A PUB_B | htlc HASH CLAIM REFUND TIMEOUT | delayed OWNER REVOKE DELAY
//!                            | htlc-revocable HASH CLAIM REFUND REVOKE TIMEOUT CLAIM_DELAY REFUND_DELAY [--out FILE]
//! requant-wallet spend-condition WALLET|KEYFILE COND.json PATH ADDRESS [--preimage HEX] [--anyone-can-pay]
//!                            (PATH: both | claim | refund | owner | revoke; every coin under the condition)
//! requant-wallet cosign      WALLET|KEYFILE PARTIAL.json      (second signature of a 2-of-2 spend)
//!
//! One-way payment channels (SWAPS.md §3; `channel.rs`): one deposit, many payments, two transactions.
//! client: requant-wallet channel open WALLET|KEYFILE SERVER_PUBKEY SERVER_ADDRESS AMOUNT EXPIRY --out CH.json
//! server: requant-wallet channel accept WALLET|KEYFILE CH.json [--min-blocks N]   (signs the refund)
//! client: requant-wallet channel fund WALLET|KEYFILE CH.json                      (sends the deposit)
//! client: requant-wallet channel pay WALLET|KEYFILE CH.json TOTAL --out STATE     (TOTAL paid so far, RQT)
//! server: requant-wallet channel receive CH.json STATE                            (checks it; JSON)
//! server: requant-wallet channel close WALLET|KEYFILE CH.json STATE              (before the expiry)
//! client: requant-wallet channel refund CH.json                                   (from the expiry)
//!         requant-wallet channel show CH.json
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
use requant_consensus::tx::{multi2_owner, Hash, OutPoint, Tx};
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

/// Coins of many owners: a list per request (each entry names its owner), or one request per owner
/// with a node too old for lists.
fn all_coins(rpc: &Backend, owners: &[Hash]) -> Vec<(Spendable, bool, bool)> {
    let mut all = Vec::new();
    for chunk in owners.chunks(rpc.list_max()) {
        let list: Vec<String> = chunk.iter().map(|o| hex(o)).collect();
        let v = match rpc.call("utxos", json!([list])) {
            Ok(v) => v,
            Err(_) if rpc.per_owner_fallback() => return owners.iter().flat_map(|o| coins(rpc, o)).collect(),
            Err(e) => die(&format!("api: {e}")),
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

/// Every signing key of a wallet or key file.
fn keys_of(net: &Network, src: &str, what: &str) -> Vec<SigningKey> {
    match source(net, src) {
        Source::Key(path) => vec![load_key(&path)],
        Source::Wallet(path, w) => w.keyring(&unlock(&path, &w)).into_values().collect(),
        Source::Address(_) => die(&format!("{what} takes a wallet or a key file")),
    }
}

/// The key of `pubkey` among `keys`.
fn key_for<'a>(keys: &'a [SigningKey], pubkey: &[u8; 32], who: &str) -> &'a SigningKey {
    keys.iter()
        .find(|k| k.verifying_key().to_bytes() == *pubkey)
        .unwrap_or_else(|| die(&format!("this wallet does not hold the {who} key of the channel")))
}

fn read_channel(net: &Network, file: &str) -> channel::Channel {
    let v = serde_json::from_str(&read(file)).unwrap_or_else(|e| die(&format!("{file}: {e}")));
    channel::Channel::from_json(net, &v).unwrap_or_else(|e| die(&format!("{file}: {e}")))
}

fn write_channel(net: &Network, file: &str, c: &channel::Channel) {
    write_file(file, &serde_json::to_string_pretty(&c.to_json(net)).unwrap());
}

fn read_tx(file: &str) -> Tx {
    let bytes = unhex(read(file).trim()).unwrap_or_else(|_| die(&format!("{file}: not a transaction (hex)")));
    Tx::decode_exact(&bytes).unwrap_or_else(|e| die(&format!("{file}: {e}")))
}

fn tip(rpc: &Backend) -> u64 {
    let v = rpc.call("getinfo", json!([])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
    v["height"].as_u64().unwrap_or_else(|| die("rpc: getinfo gave no height"))
}

/// Where a channel's deposit stands on the chain: `(funded and unspent, confirmed, spent)`.
fn channel_status(rpc: &Backend, c: &channel::Channel) -> (bool, bool, bool) {
    let op = c.outpoint();
    if let Some((_, _, confirmed)) = coins(rpc, &c.owner()).into_iter().find(|x| x.0.op == op) {
        return (true, confirmed, false);
    }
    // not unspent: spent if the funding transfer is known, otherwise not sent yet
    let known = rpc.call("gettx", json!([hex(&op.txid)])).is_ok();
    (false, false, known)
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
    // a list of owners per request, or one request each with a node too old for lists
    let mut answers = Vec::new();
    for chunk in owners.chunks(rpc.list_max()) {
        let list: Vec<String> = chunk.iter().map(|o| hex(o)).collect();
        match rpc.call("history", json!([list, limit])) {
            Ok(v) => answers.push(v),
            Err(e) if !rpc.per_owner_fallback() => die(&format!("api: {e}")),
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
    let anyone_can_pay = flag("--anyone-can-pay");
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
    let preimage_opt = opt("--preimage");
    let min_blocks =
        opt("--min-blocks").map(|n| n.parse::<u64>().unwrap_or_else(|_| die("--min-blocks: a number of blocks")));
    let count = opt("--count").map(|c| match c.parse::<u32>() {
        Ok(n @ 1..=100_000) => n,
        _ => die("--count needs a number from 1 to 100000"),
    });
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
                    match addr.call("history", json!([list, 1])) {
                        Ok(v) => {
                            let seen: std::collections::HashSet<&str> =
                                v.as_array().into_iter().flatten().filter_map(|e| e["owner"].as_str()).collect();
                            return Ok(list.iter().map(|o| seen.contains(o.as_str())).collect());
                        }
                        Err(e) if !addr.per_owner_fallback() => return Err(format!("api: {e}")),
                        Err(_) => {}
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
            if let Some(n) = count {
                // a scan stops after LOOKAHEAD unused addresses in a row; a deposit list handed out more
                w.receive_issued = w.receive_issued.max(n);
                w.top_up(&hd::seed_of(&entropy, ""));
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
            let mut seed = None;
            let mut list = Vec::new();
            for _ in 0..count.unwrap_or(1) {
                let owner = match w.next_receive() {
                    Some(o) => o,
                    None => {
                        // every derived address is handed out: derive more (needs the seed, asked once)
                        let s = seed.get_or_insert_with(|| unlock(&path, &w));
                        w.top_up(s);
                        w.next_receive().unwrap()
                    }
                };
                list.push(address(&net, &owner));
            }
            // handed out before they are shown: a list that was printed is never handed out again
            save(&path, &w);
            write_out(&list.join("
"), &format!("{} addresses", list.len()));
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
        ["broadcast", files @ ..] if !files.is_empty() => {
            let txs: Vec<Tx> = files
                .iter()
                .map(|file| {
                    let text = read(file);
                    let bytes =
                        unhex(text.trim()).unwrap_or_else(|_| die(&format!("{file}: not a signed transaction (hex)")));
                    let tx = Tx::decode_exact(&bytes).unwrap_or_else(|e| die(&format!("{file}: {e}")));
                    tx.check_standalone(&net.chain_id).unwrap_or_else(|e| die(&format!("{file}: {e}")));
                    tx
                })
                .collect();
            if let [tx] = txs.as_slice() {
                println!("sent, txid {}", send(&rpc(), tx));
            } else {
                let hexes: Vec<String> = txs.iter().map(|t| hex(&t.encode())).collect();
                let ids =
                    rpc().call("sendpackage", json!([hexes])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
                for id in ids.as_array().into_iter().flatten() {
                    println!("sent, txid {}", id.as_str().unwrap_or(""));
                }
            }
        }
        // ---- spending conditions ----------------------------------------------------------------
        ["secret"] => {
            let secret = Zeroizing::new(random::<32>());
            println!("secret  {}", hex(secret.as_ref()));
            println!("sha256  {}", hex(&contracts::sha256(secret.as_ref())));
            eprintln!("keep the secret private until you claim; give out only the sha256");
        }
        ["pubkey", src] => {
            let key = match source(&net, src) {
                Source::Key(path) => load_key(&path),
                Source::Wallet(path, w) => {
                    let seed = unlock(&path, &w);
                    let current = w.receive[w.receive_issued.max(1) as usize - 1];
                    w.keyring(&seed).remove(&current).unwrap_or_else(|| die("the current address has no key here"))
                }
                Source::Address(_) => die("pubkey takes a wallet or a key file"),
            };
            println!("address {}", address(&net, &owner_of(&key)));
            println!("pubkey  {}", hex(&key.verifying_key().to_bytes()));
        }
        ["condition", rest @ ..] => {
            let cond = contracts::Condition::from_words(&net, rest).unwrap_or_else(|e| die(&e));
            eprintln!("address {}  (send coins here to lock them)", address(&net, &cond.owner()));
            write_out(&serde_json::to_string_pretty(&cond.to_json(&net)).unwrap(), "condition");
        }
        ["spend-condition", src, file, how, to] => {
            let cond = contracts::Condition::from_json(&net, &serde_json::from_str(&read(file)).unwrap_or_else(|e| die(&format!("{file}: {e}"))))
                .unwrap_or_else(|e| die(&format!("{file}: {e}")));
            let to = contracts::who(&net, to).unwrap_or_else(|e| die(&e));
            let preimage = preimage_opt.as_ref().map(|p| {
                unhex(p).ok().and_then(|b| b.try_into().ok()).unwrap_or_else(|| die("--preimage: expected 64 hex digits"))
            });
            // confirmed coins only: relative locks count from a coin's block
            let held: Vec<(OutPoint, u64)> = coins(&rpc(), &cond.owner())
                .into_iter()
                .filter(|c| c.2)
                .map(|c| (c.0.op, c.0.value))
                .collect();
            let (mut tx, fee) = contracts::spend(&cond, how, &held, &to, rate(), preimage, anyone_can_pay)
                .unwrap_or_else(|e| die(&e));
            let signers = cond.signers(how).unwrap_or_else(|e| die(&e));
            let keys: Vec<SigningKey> = match source(&net, src) {
                Source::Key(path) => vec![load_key(&path)],
                Source::Wallet(path, w) => w.keyring(&unlock(&path, &w)).into_values().collect(),
                Source::Address(_) => die("spend-condition takes a wallet or a key file"),
            };
            let first = keys
                .iter()
                .find(|k| contracts::role(&signers, &k.verifying_key().to_bytes()).0)
                .unwrap_or_else(|| die("this wallet holds no key that signs this path"));
            let n = held.len();
            tx.sign(&net.chain_id, &vec![first; n]);
            eprintln!(
                "  spend {n} coin(s) of {} along {how}: {} RQT to {}, fee {} RQT",
                address(&net, &cond.owner()),
                format_amount(tx.outputs()[0].value),
                address(&net, &to),
                format_amount(fee)
            );
            if let contracts::Signers::Both(_, second) = signers {
                match keys.iter().find(|k| k.verifying_key().to_bytes() == second) {
                    Some(k) => (0..n).for_each(|i| tx.sign_second(&net.chain_id, i, k)),
                    None => {
                        let partial = json!({"requant_partial": 1, "network": net.name, "tx": hex(&tx.encode()),
                                             "second": hex(&second)});
                        let Some(path) = &out else { die("the other key signs next: pass --out FILE and send it the file") };
                        write_file(path, &serde_json::to_string_pretty(&partial).unwrap());
                        eprintln!("partly signed; the holder of the second key runs `cosign WALLET {path}`");
                        return;
                    }
                }
            }
            tx.check_standalone(&net.chain_id).unwrap_or_else(|e| die(&e.to_string()));
            match &out {
                Some(path) => {
                    write_file(path, &hex(&tx.encode()));
                    eprintln!("signed transfer written to {path}; send it with `broadcast {path}`");
                }
                None => {
                    confirm("send?", yes);
                    println!("sent, txid {}", send(&rpc(), &tx));
                }
            }
        }
        ["cosign", src, file] => {
            let v: serde_json::Value = serde_json::from_str(&read(file)).unwrap_or_else(|e| die(&format!("{file}: {e}")));
            if v["requant_partial"] != json!(1) || v["network"] != json!(net.name) {
                die(&format!("{file}: not a partly signed transfer of this network"));
            }
            let mut tx = v["tx"]
                .as_str()
                .and_then(|h| unhex(h).ok())
                .and_then(|b| Tx::decode_exact(&b).ok())
                .unwrap_or_else(|| die(&format!("{file}: bad transaction")));
            let second: [u8; 32] = v["second"]
                .as_str()
                .and_then(|h| unhex(h).ok())
                .and_then(|b| b.try_into().ok())
                .unwrap_or_else(|| die(&format!("{file}: bad second key")));
            let keys: Vec<SigningKey> = match source(&net, src) {
                Source::Key(path) => vec![load_key(&path)],
                Source::Wallet(path, w) => w.keyring(&unlock(&path, &w)).into_values().collect(),
                Source::Address(_) => die("cosign takes a wallet or a key file"),
            };
            let key = keys
                .iter()
                .find(|k| k.verifying_key().to_bytes() == second)
                .unwrap_or_else(|| die("this wallet does not hold the second key"));
            let n = match &tx {
                Tx::Transfer { inputs, .. } => inputs.len(),
                Tx::Coinbase { .. } => 0,
            };
            for i in 0..n {
                tx.sign_second(&net.chain_id, i, key);
            }
            tx.check_standalone(&net.chain_id).unwrap_or_else(|e| die(&e.to_string()));
            eprintln!("  {} RQT to {}", format_amount(tx.outputs()[0].value), address(&net, &tx.outputs()[0].pkh));
            match &out {
                Some(path) => {
                    write_file(path, &hex(&tx.encode()));
                    eprintln!("signed transfer written to {path}; send it with `broadcast {path}`");
                }
                None => {
                    confirm("send?", yes);
                    println!("sent, txid {}", send(&rpc(), &tx));
                }
            }
        }
        // ---- payment channels ---------------------------------------------------------------------
        ["channel", "open", src, server, server_to, amount, expiry] => {
            let server: [u8; 32] = unhex(server)
                .ok()
                .and_then(|b| b.try_into().ok())
                .unwrap_or_else(|| die("SERVER_PUBKEY: expected 64 hex digits (the server's `pubkey`)"));
            let server_to = contracts::who(&net, server_to).unwrap_or_else(|e| die(&e));
            let amount = parse_amount(amount).unwrap_or_else(|e| die(e));
            let expiry: u64 = expiry.parse().unwrap_or_else(|_| die("EXPIRY: a block height"));
            let Some(file) = &out else { die("channel open needs --out FILE (the channel file for both sides)") };
            refuse_existing(file);
            let addr = rpc();
            let now = tip(&addr);
            if expiry <= now + 20 {
                die(&format!("the expiry must be well after the current height {now}"));
            }
            type Wallet = Option<(String, WalletFile)>;
            let (key, keys, spendable, change, wallet): (SigningKey, HashMap<Hash, SigningKey>, Vec<Spendable>, Hash, Wallet) =
                match source(&net, src) {
                    Source::Key(path) => {
                        let key = load_key(&path);
                        let me = owner_of(&key);
                        let spendable = coins(&addr, &me).into_iter().filter(|c| c.1).map(|c| c.0).collect();
                        (key.clone(), HashMap::from([(me, key)]), spendable, me, None)
                    }
                    Source::Wallet(path, mut w) => {
                        let seed = unlock(&path, &w);
                        let keys = w.keyring(&seed);
                        let current = w.receive[w.receive_issued.max(1) as usize - 1];
                        let key = keys.get(&current).cloned().unwrap_or_else(|| die("the current address has no key here"));
                        let spendable =
                            all_coins(&addr, &w.owners()).into_iter().filter(|c| c.1).map(|c| c.0).collect();
                        let change = next_change(&mut w, Some(&seed), &addr);
                        (key, keys, spendable, change, Some((path, w)))
                    }
                    Source::Address(_) => die("channel open takes a wallet or a key file"),
                };
            let client = key.verifying_key().to_bytes();
            let owner = multi2_owner(&client, &server);
            let (mut tx, chosen, fee) =
                plan_payment(&spendable, &[(owner, amount)], rate(), change).unwrap_or_else(|e| die(&e));
            sign_with(&net, &mut tx, &chosen, &keys).unwrap_or_else(|e| die(&e));
            let vout = tx.outputs().iter().position(|o| o.pkh == owner).unwrap() as u32;
            let funding_owners = chosen.iter().map(|c| c.owner).collect();
            let mut ch = channel::Channel::new(client, server, owner_of(&key), server_to, expiry, &tx, vout, funding_owners)
                .unwrap_or_else(|e| die(&e));
            ch.refund.sign(&net.chain_id, &[&key]);
            if let Some((path, w)) = &wallet {
                save(path, w);
            }
            write_channel(&net, file, &ch);
            eprintln!(
                "  deposit {} RQT to {} (funding fee {} RQT), refund to {} from height {expiry}",
                format_amount(amount),
                address(&net, &owner),
                format_amount(fee),
                address(&net, &ch.client_to)
            );
            eprintln!(
                "channel written to {file}; nothing is sent yet. Give the file to the server: it runs `channel accept`, then run `channel fund`"
            );
        }
        ["channel", "accept", src, file] => {
            let mut ch = read_channel(&net, file);
            let keys = keys_of(&net, src, "channel accept");
            let key = key_for(&keys, &ch.server, "server");
            if !keys.iter().any(|k| owner_of(k) == ch.server_to) {
                die("the payments go to an address this wallet holds no key for");
            }
            let min_blocks = min_blocks.unwrap_or(144);
            let now = tip(&rpc());
            if ch.expiry < now + min_blocks {
                die(&format!("the expiry {} is less than {min_blocks} blocks after the current height {now}", ch.expiry));
            }
            ch.refund.sign_second(&net.chain_id, 0, key);
            if !ch.refund_accepted(&net) {
                die("the refund does not verify");
            }
            let dest = out.clone().unwrap_or_else(|| file.to_string());
            write_channel(&net, &dest, &ch);
            eprintln!(
                "  accepted: deposit {} RQT, expiry {} ({} blocks from now); refund signed, written to {dest}",
                format_amount(ch.deposit),
                ch.expiry,
                ch.expiry - now
            );
        }
        ["channel", "fund", src, file] => {
            let ch = read_channel(&net, file);
            if !ch.refund_accepted(&net) {
                die("the server has not signed the refund yet: never fund a channel without it");
            }
            let ring: HashMap<Hash, SigningKey> =
                keys_of(&net, src, "channel fund").into_iter().map(|k| (owner_of(&k), k)).collect();
            let Tx::Transfer { inputs, .. } = &ch.funding else { die("bad funding transfer") };
            let chosen: Vec<Spendable> = inputs
                .iter()
                .zip(&ch.funding_owners)
                .map(|(i, o)| Spendable { op: i.prev, value: 0, owner: *o })
                .collect();
            let mut tx = ch.funding.clone();
            sign_with(&net, &mut tx, &chosen, &ring).unwrap_or_else(|e| die(&e));
            if tx.txid() != ch.funding.txid() {
                die("the signed funding transfer differs from the channel's");
            }
            tx.check_standalone(&net.chain_id).unwrap_or_else(|e| die(&e.to_string()));
            confirm(&format!("send the deposit of {} RQT?", format_amount(ch.deposit)), yes);
            println!("sent, txid {}", send(&rpc(), &tx));
        }
        ["channel", "pay", src, file, total] => {
            let mut ch = read_channel(&net, file);
            if !ch.refund_accepted(&net) {
                die("the channel is not accepted by the server yet");
            }
            let total = parse_amount(total).unwrap_or_else(|e| die(e));
            if total <= ch.paid {
                die(&format!("TOTAL is what has been paid so far: more than {} RQT", format_amount(ch.paid)));
            }
            let keys = keys_of(&net, src, "channel pay");
            let key = key_for(&keys, &ch.client, "client");
            let mut state = ch.state(total).unwrap_or_else(|e| die(&e));
            state.sign(&net.chain_id, &[key]);
            let Some(path) = &out else { die("channel pay needs --out FILE (the state to give the server)") };
            write_file(path, &hex(&state.encode()));
            ch.paid = total;
            write_channel(&net, file, &ch);
            eprintln!(
                "  state paying {} RQT in total ({} RQT left) written to {path}",
                format_amount(total),
                format_amount(ch.deposit - channel::CHANNEL_FEE - total)
            );
        }
        ["channel", "receive", file, state] => {
            let ch = read_channel(&net, file);
            let st = read_tx(state);
            let paid = ch.paid_by(&net, &st).unwrap_or_else(|e| die(&e));
            let addr = rpc();
            let (unspent, confirmed, spent) = channel_status(&addr, &ch);
            let now = tip(&addr);
            println!(
                "{}",
                json!({"paid": paid, "deposit": ch.deposit, "expiry": ch.expiry, "height": now,
                       "blocks_left": ch.expiry.saturating_sub(now), "funded": unspent, "confirmed": confirmed,
                       "closed": spent, "state_txid": hex(&st.txid())})
            );
        }
        ["channel", "close", src, file, state] => {
            let ch = read_channel(&net, file);
            let mut st = read_tx(state);
            let paid = ch.paid_by(&net, &st).unwrap_or_else(|e| die(&e));
            let keys = keys_of(&net, src, "channel close");
            st.sign_second(&net.chain_id, 0, key_for(&keys, &ch.server, "server"));
            st.check_standalone(&net.chain_id).unwrap_or_else(|e| die(&e.to_string()));
            eprintln!("  close: {} RQT to {}", format_amount(paid), address(&net, &ch.server_to));
            match &out {
                Some(path) => {
                    write_file(path, &hex(&st.encode()));
                    eprintln!("signed state written to {path}; send it with `broadcast {path}` before height {}", ch.expiry);
                }
                None => {
                    confirm("send?", yes);
                    println!("sent, txid {}", send(&rpc(), &st));
                }
            }
        }
        ["channel", "refund", file] => {
            let ch = read_channel(&net, file);
            if !ch.refund_accepted(&net) {
                die("the refund has no server signature");
            }
            let now = tip(&rpc());
            if now + 1 < ch.expiry {
                die(&format!("the refund is valid from height {}; the chain is at {now}", ch.expiry));
            }
            println!("sent, txid {}", send(&rpc(), &ch.refund));
        }
        ["channel", "show", file] => {
            let ch = read_channel(&net, file);
            let addr = rpc();
            let (unspent, confirmed, spent) = channel_status(&addr, &ch);
            let now = tip(&addr);
            println!("deposit   {} RQT at {}", format_amount(ch.deposit), address(&net, &ch.owner()));
            println!("client    {} (refund and change)", address(&net, &ch.client_to));
            println!("server    {} (payments)", address(&net, &ch.server_to));
            println!("expiry    height {} (now {now})", ch.expiry);
            println!("paid      {} RQT (this file's record)", format_amount(ch.paid));
            let status = match (ch.refund_accepted(&net), unspent, confirmed, spent) {
                (false, ..) => "proposed: waiting for the server to sign the refund",
                (true, true, false, _) => "funding sent, not confirmed yet",
                (true, true, true, _) => "open",
                (true, false, _, true) => "closed: the deposit was spent (the last state or the refund)",
                (true, false, _, false) => "accepted: the deposit is not sent yet (`channel fund`)",
            };
            println!("status    {status}");
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
            "usage: requant-wallet create WALLET [--no-passphrase] | restore WALLET [--no-scan] [--count N]\n",
            "       | phrase WALLET | newaddress WALLET [--count N] | addresses WALLET | watchonly WALLET OUT\n",
            "       | prepare WALLET ADDRESS AMOUNT|all [ADDRESS AMOUNT]... [--out FILE] | sign WALLET FILE [--out FILE]\n",
            "       | broadcast FILE [FILE]... | keygen KEYFILE [--no-passphrase] | encrypt KEYFILE|WALLET | address KEYFILE|WALLET\n",
            "       | balance SRC | history SRC [N] | coins SRC | tx TXID   (SRC: an address, a key file or a wallet)\n",
            "       | send WALLET|KEYFILE ADDRESS AMOUNT|all [ADDRESS AMOUNT]... | consolidate WALLET|KEYFILE\n",
            "       | secret | pubkey SRC | condition KIND ARGS... [--out FILE]\n",
            "       | spend-condition SRC COND.json PATH ADDRESS [--preimage HEX] [--anyone-can-pay] | cosign SRC FILE\n",
            "       | channel open SRC SERVER_PUBKEY SERVER_ADDRESS AMOUNT EXPIRY --out CH | channel accept SRC CH\n",
            "       | channel fund SRC CH | channel pay SRC CH TOTAL --out STATE | channel receive CH STATE\n",
            "       | channel close SRC CH STATE | channel refund CH | channel show CH\n",
            "options: --network test|regtest (default test, or the wallet's) --rpc HOST:PORT\n",
            "         --fee-rate ATOMS_PER_BYTE|fast|normal|slow (default normal: the node's estimate) --yes --out FILE"
        )),
    }
}
