//! `requantd`: the Requant full node.
//!
//! requantd [--network test|regtest] [--datadir DIR] [--listen ADDR] [--rpc ADDR] [--connect HOST:PORT]...
//!          [--mine PKH_HEX] [--mine-interval-ms N] [--threads N] [--max-reorg BLOCKS] [--rpc-token-file FILE]
//!          [--no-discover] [--explorer ADDR] [--version]
//!          [--pool ADDR --pool-key FILE [--pool-fee PERCENT] [--pool-share-bits N] [--pool-min-payout RQT]
//!           [--pool-payout-every SECS]]

use requant_consensus::params::Network;
use requant_node::node::{agent, default_max_reorg, start, Config};
use requant_node::rpc::unhex;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut net = Network::regtest();
    let (mut datadir, mut listen, mut rpc) = ("requant-data".to_string(), None, None);
    let (mut connect, mut mine_to, mut interval, mut threads) = (Vec::new(), None, 1000u64, 4usize);
    let mut max_reorg = None::<u64>;
    let (mut rpc_token, mut discover) = (None::<String>, true);
    let mut explorer = None;
    let (mut pool_addr, mut pool_key, mut pool_fee, mut share_bits) = (None, None::<[u8; 32]>, 1.0f64, 24u32);
    let (mut min_payout, mut payout_every) = (100_000_000u64, 600u64);
    let mut k = 0;
    let value = |k: usize| args.get(k + 1).cloned().unwrap_or_else(|| usage(&format!("{} needs a value", args[k])));
    while k < args.len() {
        match args[k].as_str() {
            "--network" => net = Network::by_name(&value(k)).unwrap_or_else(|| usage("unknown network")),
            "--datadir" => datadir = value(k),
            "--listen" => listen = Some(value(k)),
            "--rpc" => rpc = Some(value(k)),
            "--connect" => connect.push(value(k)),
            "--pool" => pool_addr = Some(value(k).parse().unwrap_or_else(|_| usage("bad --pool address"))),
            "--pool-key" => {
                let f = value(k);
                let t = std::fs::read_to_string(&f).unwrap_or_else(|e| usage(&format!("{f}: {e}")));
                pool_key = Some(
                    unhex(t.trim())
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .unwrap_or_else(|| usage("--pool-key: unencrypted 64-hex key file")),
                );
            }
            "--pool-fee" => {
                pool_fee = value(k)
                    .parse()
                    .ok()
                    .filter(|f| (0.0..=50.0).contains(f))
                    .unwrap_or_else(|| usage("bad --pool-fee"))
            }
            "--pool-share-bits" => {
                share_bits = value(k)
                    .parse()
                    .ok()
                    .filter(|b| (1..=200).contains(b))
                    .unwrap_or_else(|| usage("bad --pool-share-bits"))
            }
            "--pool-min-payout" => {
                min_payout = requant_consensus::address::parse_amount(&value(k))
                    .unwrap_or_else(|_| usage("bad --pool-min-payout"))
            }
            "--pool-payout-every" => {
                payout_every = value(k).parse().unwrap_or_else(|_| usage("bad --pool-payout-every"))
            }
            "--explorer" => explorer = Some(value(k).parse().unwrap_or_else(|_| usage("bad --explorer address"))),
            "--mine" => {
                let h: [u8; 32] = unhex(&value(k))
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .unwrap_or_else(|| usage("--mine needs a 32-byte hex key hash"));
                mine_to = Some(h)
            }
            "--mine-interval-ms" => interval = value(k).parse().unwrap_or_else(|_| usage("bad interval")),
            "--threads" => threads = value(k).parse().unwrap_or_else(|_| usage("bad thread count")),
            "--max-reorg" => max_reorg = Some(value(k).parse().unwrap_or_else(|_| usage("bad --max-reorg"))),
            "--rpc-token-file" => {
                let f = value(k);
                let t = std::fs::read_to_string(&f).unwrap_or_else(|e| usage(&format!("{f}: {e}")));
                rpc_token = Some(t.trim().to_string());
            }
            "--no-discover" => {
                discover = false;
                k += 1;
                continue;
            }
            "--version" => {
                println!("{}", agent());
                return;
            }
            "-h" | "--help" => usage(""),
            other => usage(&format!("unknown argument {other}")),
        }
        k += 2;
    }
    let default_port = if net.name == "test" { 19333 } else { 19444 };
    let listen = listen.unwrap_or_else(|| format!("0.0.0.0:{default_port}"));
    let rpc = rpc.unwrap_or_else(|| format!("127.0.0.1:{}", default_port + 1));
    let max_reorg = max_reorg.unwrap_or_else(|| default_max_reorg(&net));
    let cfg = Config {
        net,
        datadir: datadir.into(),
        listen: listen.parse().unwrap_or_else(|_| usage("bad --listen address")),
        rpc: Some(rpc.parse().unwrap_or_else(|_| usage("bad --rpc address"))),
        connect,
        mine_to,
        mine_interval: Duration::from_millis(interval),
        threads,
        max_reorg,
        rpc_token,
        peer_interval: Duration::from_secs(15),
        discover,
        explorer,
        pool: pool_addr.map(|listen| requant_node::pool::PoolConfig {
            listen,
            key: pool_key.unwrap_or_else(|| usage("--pool needs --pool-key")),
            fee_bp: (pool_fee * 100.0).round() as u64,
            share_bits,
            min_payout,
            payout_every,
        }),
    };
    let net_name = cfg.net.name;
    match start(cfg) {
        Ok(h) => {
            eprintln!("{} {net_name}: p2p {} rpc {}", agent(), h.p2p, h.rpc.map(|a| a.to_string()).unwrap_or_default());
            loop {
                std::thread::sleep(Duration::from_secs(60));
                let st = h.shared.lock().unwrap();
                eprintln!("height {} peers {} mempool {}", st.chain.height(), st.peer_count(), st.mempool.len());
            }
        }
        Err(e) => {
            eprintln!("requantd: {e}");
            std::process::exit(1);
        }
    }
}

fn usage(msg: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("requantd: {msg}");
    }
    eprintln!(
        "usage: requantd [--network test|regtest] [--datadir DIR] [--listen ADDR] [--rpc ADDR] [--connect HOST:PORT]...\n\
         \x20               [--mine PKH_HEX] [--mine-interval-ms N] [--threads N] [--max-reorg BLOCKS]
\n                         [--rpc-token-file FILE] [--no-discover] [--explorer ADDR] [--version]"
    );
    std::process::exit(2)
}
