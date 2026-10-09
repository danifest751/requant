//! `requant-wallet`: keys, addresses, balance and payments through a node's JSON-RPC.
//!
//! requant-wallet keygen  KEYFILE                       [--network N]
//! requant-wallet address KEYFILE                       [--network N]
//! requant-wallet balance ADDRESS                       [--network N] [--rpc HOST:PORT]
//! requant-wallet send    KEYFILE ADDRESS AMOUNT_RQT    [--fee ATOMS] [--network N] [--rpc HOST:PORT]

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

fn load_key(path: &str) -> SigningKey {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let bytes: [u8; 32] = unhex(text.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| die("key file must hold 64 hex digits"));
    SigningKey::from_bytes(&bytes)
}

fn coins(rpc: SocketAddr, owner: &[u8; 32]) -> Vec<(Spendable, bool, u64)> {
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
                c["height"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut opt = |name: &str| -> Option<String> {
        let k = args.iter().position(|a| a == name)?;
        let v = args.get(k + 1).cloned().unwrap_or_else(|| die(&format!("{name} needs a value")));
        args.drain(k..k + 2);
        Some(v)
    };
    let net = Network::by_name(&opt("--network").unwrap_or_else(|| "regtest".into()))
        .unwrap_or_else(|| die("unknown network"));
    let default_rpc = if net.name == "test" { "127.0.0.1:19334" } else { "127.0.0.1:19445" };
    let rpc_s = opt("--rpc").unwrap_or_else(|| default_rpc.into());
    let fee = opt("--fee").map(|f| f.parse::<u64>().unwrap_or_else(|_| die("bad fee"))).unwrap_or(1000);
    let rpc = || rpc_s.to_socket_addrs().ok().and_then(|mut a| a.next()).unwrap_or_else(|| die("bad --rpc address"));
    match args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
        ["keygen", path] => {
            if std::path::Path::new(path).exists() {
                die(&format!("{path} exists; refusing to overwrite a key"));
            }
            let mut secret = [0u8; 32];
            getrandom::getrandom(&mut secret).unwrap_or_else(|e| die(&format!("random: {e}")));
            std::fs::write(path, hex(&secret) + "\n").unwrap_or_else(|e| die(&format!("{path}: {e}")));
            let key = SigningKey::from_bytes(&secret);
            println!("key written to {path} (back it up; anyone with this file can spend its coins)");
            println!("address  {}", address(&net, &owner_of(&key)));
            println!("key hash {}", hex(&owner_of(&key)));
        }
        ["address", path] => {
            let key = load_key(path);
            println!("address  {}", address(&net, &owner_of(&key)));
            println!("key hash {}", hex(&owner_of(&key)));
        }
        ["balance", addr] => {
            let owner = parse_address(&net, addr).unwrap_or_else(|e| die(e));
            let list = coins(rpc(), &owner);
            let spendable: u64 = list.iter().filter(|c| c.1).map(|c| c.0.value).sum();
            let immature: u64 = list.iter().filter(|c| !c.1).map(|c| c.0.value).sum();
            println!("spendable {} RQT in {} outputs", format_amount(spendable), list.iter().filter(|c| c.1).count());
            println!("immature  {} RQT", format_amount(immature));
        }
        ["send", path, to, amount] => {
            let key = load_key(path);
            let to = parse_address(&net, to).unwrap_or_else(|e| die(e));
            let amount = parse_amount(amount).unwrap_or_else(|e| die(e));
            let spendable: Vec<Spendable> =
                coins(rpc(), &owner_of(&key)).into_iter().filter(|c| c.1).map(|c| c.0).collect();
            let tx = build_transfer(&net, &key, &spendable, &to, amount, fee).unwrap_or_else(|e| die(&e));
            let txid =
                request(rpc(), "sendtx", json!([hex(&tx.encode())])).unwrap_or_else(|e| die(&format!("rpc: {e}")));
            println!("sent {} RQT, fee {} atoms, txid {}", format_amount(amount), fee, txid.as_str().unwrap_or(""));
        }
        _ => die(
            "usage: requant-wallet keygen KEYFILE | address KEYFILE | balance ADDRESS | send KEYFILE ADDRESS AMOUNT \
             [--fee ATOMS] [--network test|regtest] [--rpc HOST:PORT]",
        ),
    }
}
