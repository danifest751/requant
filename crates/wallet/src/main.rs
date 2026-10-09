//! `requant-wallet`: keys, addresses, balance and payments through a node's JSON-RPC.
//!
//! requant-wallet keygen      KEYFILE [--no-passphrase]
//! requant-wallet encrypt     KEYFILE                          (encrypt, or change the passphrase)
//! requant-wallet address     KEYFILE
//! requant-wallet balance     ADDRESS|KEYFILE
//! requant-wallet history     ADDRESS|KEYFILE [N]
//! requant-wallet coins       ADDRESS|KEYFILE                  (unspent outputs)
//! requant-wallet tx          TXID
//! requant-wallet send        KEYFILE ADDRESS AMOUNT [ADDRESS AMOUNT]...   (AMOUNT in RQT, or "all")
//! requant-wallet consolidate KEYFILE                          (merge the smallest coins into one)
//!
//! Options: --network test|regtest (default test), --rpc HOST:PORT, --fee-rate ATOMS_PER_BYTE (default 5),
//! --yes (send without asking).

use ed25519_dalek::SigningKey;
use requant_consensus::params::Network;
use requant_node::rpc::{hex, request, unhex};
use requant_wallet::*;
use serde_json::json;
use std::net::{SocketAddr, ToSocketAddrs};

fn die(msg: &str) -> ! {
    eprintln!("requant-wallet: {msg}");
    std::process::exit(1)
}

/// Passphrase from `REQUANT_WALLET_PASSPHRASE`, else asked on the terminal (twice when `confirm`).
fn passphrase(prompt: &str, confirm: bool) -> String {
    if let Ok(p) = std::env::var("REQUANT_WALLET_PASSPHRASE") {
        return p;
    }
    let p = rpassword::prompt_password(prompt).unwrap_or_else(|e| die(&format!("passphrase: {e}")));
    if confirm && rpassword::prompt_password("repeat it: ").unwrap_or_default() != p {
        die("the passphrases differ");
    }
    p
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).unwrap_or_else(|e| die(&format!("random: {e}")));
    b
}

/// Write a key file atomically (temporary file, then rename).
fn write_key(path: &str, text: &str) {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, format!("{text}\n")).unwrap_or_else(|e| die(&format!("{tmp}: {e}")));
    std::fs::rename(&tmp, path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
}

fn load_key(path: &str) -> SigningKey {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let pass = is_encrypted(&text).then(|| passphrase(&format!("passphrase for {path}: "), false));
    SigningKey::from_bytes(&decrypt_key(&text, pass.as_deref()).unwrap_or_else(|e| die(e)))
}

/// `(coin, spendable now, confirmed)`.
fn coins(rpc: SocketAddr, owner: &[u8; 32]) -> Vec<(Spendable, bool, bool)> {
    let v = request(rpc, "utxos", json!([hex(owner)])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
    v.as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let txid: [u8; 32] = unhex(c["txid"].as_str().unwrap()).unwrap().try_into().unwrap();
            let op = requant_consensus::tx::OutPoint { txid, vout: c["vout"].as_u64().unwrap() as u32 };
            (
                Spendable { op, value: c["value"].as_u64().unwrap() },
                c["spendable"].as_bool().unwrap(),
                c["confirmed"].as_bool().unwrap_or(true),
            )
        })
        .collect()
}

/// The owner behind an argument: an address, or a key file (then its passphrase may be asked).
fn owner_arg(net: &Network, s: &str) -> [u8; 32] {
    match parse_address(net, s) {
        Ok(o) => o,
        Err(e) if !std::path::Path::new(s).is_file() => die(e),
        Err(_) => owner_of(&load_key(s)),
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

fn send(rpc: SocketAddr, tx: &requant_consensus::tx::Tx) -> String {
    let txid = request(rpc, "sendtx", json!([hex(&tx.encode())])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
    txid.as_str().unwrap_or("").to_string()
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut flag = |name: &str| args.iter().position(|a| a == name).map(|k| args.remove(k)).is_some();
    let plain = flag("--no-passphrase");
    let yes = flag("--yes");
    let mut opt = |name: &str| -> Option<String> {
        let k = args.iter().position(|a| a == name)?;
        let v = args.get(k + 1).cloned().unwrap_or_else(|| die(&format!("{name} needs a value")));
        args.drain(k..k + 2);
        Some(v)
    };
    let net =
        Network::by_name(&opt("--network").unwrap_or_else(|| "test".into())).unwrap_or_else(|| die("unknown network"));
    let default_rpc = if net.name == "test" { "127.0.0.1:19334" } else { "127.0.0.1:19445" };
    let rpc_s = opt("--rpc").unwrap_or_else(|| default_rpc.into());
    if opt("--fee").is_some() {
        die("--fee is replaced by --fee-rate ATOMS_PER_BYTE (the fee now follows the transaction's size)");
    }
    let rate = opt("--fee-rate")
        .map(|f| f.parse::<u64>().unwrap_or_else(|_| die("bad --fee-rate")))
        .unwrap_or(DEFAULT_FEE_RATE);
    let rpc = || rpc_s.to_socket_addrs().ok().and_then(|mut a| a.next()).unwrap_or_else(|| die("bad --rpc address"));
    match args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
        ["keygen", path] => {
            if std::path::Path::new(path).exists() {
                die(&format!("{path} exists; refusing to overwrite a key"));
            }
            let secret: [u8; 32] = random();
            if plain {
                write_key(path, &hex(&secret));
                println!("unencrypted key written to {path} (back it up; anyone with this file can spend its coins)");
            } else {
                let pass = passphrase("new passphrase: ", true);
                if pass.is_empty() {
                    die("empty passphrase; use --no-passphrase for an unencrypted key file");
                }
                write_key(path, &encrypt_key(&secret, &pass, &random(), &random()).unwrap_or_else(|e| die(e)));
                println!("encrypted key written to {path} (back it up and remember the passphrase: both are needed)");
            }
            let key = SigningKey::from_bytes(&secret);
            println!("address  {}", address(&net, &owner_of(&key)));
            println!("key hash {}", hex(&owner_of(&key)));
        }
        ["encrypt", path] => {
            // encrypt an unencrypted key file, or change the passphrase of an encrypted one
            let key = load_key(path);
            let pass = passphrase("new passphrase: ", true);
            if pass.is_empty() {
                die("empty passphrase");
            }
            write_key(path, &encrypt_key(&key.to_bytes(), &pass, &random(), &random()).unwrap_or_else(|e| die(e)));
            println!("{path} is now encrypted ({})", address(&net, &owner_of(&key)));
        }
        ["address", path] => {
            let key = load_key(path);
            println!("address  {}", address(&net, &owner_of(&key)));
            println!("key hash {}", hex(&owner_of(&key)));
            println!("pubkey   {}", hex(&key.verifying_key().to_bytes()));
        }
        // release signing (maintainers): the signature of a release manifest, checked by the manifest parser
        ["sign-release", path, manifest] => {
            use ed25519_dalek::Signer;
            let key = load_key(path);
            let text = std::fs::read_to_string(manifest).unwrap_or_else(|e| die(&format!("{manifest}: {e}")));
            let sig = key.sign(&requant_node::release::signed_message(&text)).to_bytes();
            requant_node::release::Release::verify_with(&text, &sig, &key.verifying_key().to_bytes())
                .unwrap_or_else(|e| die(e));
            println!("{}", hex(&sig));
        }
        ["balance", addr] => {
            let owner = owner_arg(&net, addr);
            let list = coins(rpc(), &owner);
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
        ["history", addr, rest @ ..] if rest.len() <= 1 => {
            let owner = owner_arg(&net, addr);
            let limit: u64 = rest.first().map(|n| n.parse().unwrap_or_else(|_| die("bad count"))).unwrap_or(20);
            let v =
                request(rpc(), "history", json!([hex(&owner), limit])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
            println!("{:>8}  {:>6}  {:>20}  txid", "height", "conf", "amount RQT");
            for e in v.as_array().unwrap() {
                let (r, s) = (e["received"].as_u64().unwrap_or(0), e["sent"].as_u64().unwrap_or(0));
                let amount =
                    if r >= s { format!("+{}", format_amount(r - s)) } else { format!("-{}", format_amount(s - r)) };
                let height = e["height"].as_u64().map(|h| h.to_string()).unwrap_or_else(|| "pending".into());
                println!("{height:>8}  {:>6}  {amount:>20}  {}", e["confirmations"], e["txid"].as_str().unwrap_or(""));
            }
        }
        ["tx", txid] => {
            let v = request(rpc(), "gettx", json!([txid])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
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
        ["coins", addr] => {
            let owner = owner_arg(&net, addr);
            let mut list = coins(rpc(), &owner);
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
        ["send", path, rest @ ..] if !rest.is_empty() && rest.len() % 2 == 0 => {
            let key = load_key(path);
            let mut spendable: Vec<Spendable> =
                coins(rpc(), &owner_of(&key)).into_iter().filter(|c| c.1).map(|c| c.0).collect();
            let pairs: Vec<(&str, &str)> = rest.chunks(2).map(|p| (p[0], p[1])).collect();
            let (tx, lines, fee) = if let [(to, "all")] = pairs.as_slice() {
                let to = parse_address(&net, to).unwrap_or_else(|e| die(e));
                spendable.sort_by_key(|c| std::cmp::Reverse(c.value));
                let (tx, sent, fee) = build_sweep(&net, &key, &spendable, &to, rate).unwrap_or_else(|e| die(&e));
                if spendable.len() > MAX_INPUTS {
                    eprintln!(
                        "note: {} coins; this sends the largest {MAX_INPUTS} (send again for the rest)",
                        spendable.len()
                    );
                }
                (tx, vec![(address(&net, &to), sent)], fee)
            } else {
                let payments: Vec<([u8; 32], u64)> = pairs
                    .iter()
                    .map(|(to, a)| {
                        if *a == "all" {
                            die("\"all\" works with a single recipient");
                        }
                        (parse_address(&net, to).unwrap_or_else(|e| die(e)), parse_amount(a).unwrap_or_else(|e| die(e)))
                    })
                    .collect();
                let (tx, fee) = build_payment(&net, &key, &spendable, &payments, rate).unwrap_or_else(|e| die(&e));
                (tx, payments.iter().map(|(to, v)| (address(&net, to), *v)).collect(), fee)
            };
            for (to, v) in &lines {
                eprintln!("  {:>20} RQT  to {to}", format_amount(*v));
            }
            eprintln!("  {:>20} RQT  fee ({} bytes)", format_amount(fee), tx.encode().len());
            confirm("send?", yes);
            println!("sent, txid {}", send(rpc(), &tx));
        }
        ["consolidate", path] => {
            let key = load_key(path);
            let me = owner_of(&key);
            let mut spendable: Vec<Spendable> = coins(rpc(), &me).into_iter().filter(|c| c.1).map(|c| c.0).collect();
            if spendable.len() < 2 {
                die("nothing to merge: fewer than two spendable coins");
            }
            // the smallest first: those are what make payments large
            spendable.sort_by_key(|c| c.value);
            let n = spendable.len().min(MAX_INPUTS);
            let (tx, kept, fee) = build_sweep(&net, &key, &spendable, &me, rate).unwrap_or_else(|e| die(&e));
            eprintln!(
                "  merge {n} of {} coins into one of {} RQT, fee {} RQT",
                spendable.len(),
                format_amount(kept),
                format_amount(fee)
            );
            confirm("send?", yes);
            println!("sent, txid {}", send(rpc(), &tx));
        }
        _ => die(concat!(
            "usage: requant-wallet keygen KEYFILE [--no-passphrase] | encrypt KEYFILE | address KEYFILE\n",
            "       | balance ADDRESS|KEYFILE | history ADDRESS|KEYFILE [N] | coins ADDRESS|KEYFILE | tx TXID\n",
            "       | send KEYFILE ADDRESS AMOUNT|all [ADDRESS AMOUNT]... | consolidate KEYFILE\n",
            "options: --network test|regtest (default test) --rpc HOST:PORT --fee-rate ATOMS_PER_BYTE (default 5) --yes"
        )),
    }
}
