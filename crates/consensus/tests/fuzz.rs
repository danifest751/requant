//! Deterministic fuzzing without external tools: mutated and random bytes into every decoder, and every
//! decodable mutant into the chain. Nothing may panic; invalid input must be refused.

use ed25519_dalek::SigningKey;
use requant_consensus::address::{parse_address, parse_amount};
use requant_consensus::block::{Block, Header};
use requant_consensus::chain::{mine, Chain};
use requant_consensus::codec::Reader;
use requant_consensus::params::Network;
use requant_consensus::tx::{pkh, Input, OutPoint, Output, Tx};

const NOW: u64 = u64::MAX / 2;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// A random edit: flip, set, insert or delete bytes, truncate, or splice in a big varint.
fn mutate(rng: &mut Rng, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(7) {
            0 if !v.is_empty() => {
                let k = rng.below(v.len());
                v[k] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let k = rng.below(v.len());
                v[k] = rng.next() as u8;
            }
            2 => {
                let k = rng.below(v.len() + 1);
                v.insert(k, rng.next() as u8);
            }
            3 if !v.is_empty() => {
                let k = rng.below(v.len());
                v.remove(k);
            }
            4 => {
                let k = rng.below(v.len() + 1);
                v.truncate(k);
            }
            5 => {
                let k = rng.below(v.len() + 1);
                for (j, b) in [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f].iter().enumerate() {
                    v.insert(k + j, *b);
                }
            }
            _ => {
                let k = rng.below(v.len() + 1);
                v.insert(k, 0xfe);
            }
        }
    }
    v
}

fn key(b: u8) -> SigningKey {
    SigningKey::from_bytes(&[b; 32])
}

/// A short regtest chain with a coinbase spend, so mutants exercise transaction paths too.
fn corpus() -> (Chain, Vec<Block>, Vec<Tx>) {
    let net = Network::regtest();
    let mut chain = Chain::new(net.clone(), 1);
    let alice = key(1);
    let a = pkh(&alice.verifying_key().to_bytes());
    let mut blocks = Vec::new();
    for h in 1..=4u64 {
        let mut txs = vec![];
        if h == 4 {
            let cb = &blocks[0];
            let op = OutPoint { txid: Block::clone(cb).txs[0].txid(), vout: 0 };
            let v = chain.coin(&op).unwrap().output.value;
            let mut t = Tx::Transfer {
                inputs: vec![Input { prev: op, pubkey: [0; 32], sig: [0; 64] }],
                outputs: vec![Output { value: 1000, pkh: [9; 32] }, Output { value: v - 2000, pkh: a }],
            };
            t.sign(&net.chain_id, &[&alice]);
            txs.push(t);
        }
        let mut b = chain.template(&a, txs, net.genesis_time + 60 * h);
        let seed = chain.epoch_seed(&b.header.prev, b.header.height);
        let epoch = chain.epoch(&seed);
        b.claim = mine(&net, &epoch, &b.header, 0, 1000).unwrap();
        chain.accept(b.clone(), NOW).unwrap();
        blocks.push(b);
    }
    let txs = blocks.iter().flat_map(|b| b.txs.clone()).collect();
    (chain, blocks, txs)
}

#[test]
fn decoders_never_panic() {
    let net = Network::regtest();
    let (_, blocks, txs) = corpus();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let block_bytes: Vec<Vec<u8>> = blocks.iter().map(|b| b.encode()).collect();
    let tx_bytes: Vec<Vec<u8>> = txs.iter().map(|t| t.encode()).collect();
    for round in 0..20_000 {
        let b = mutate(&mut rng, &block_bytes[round % block_bytes.len()]);
        let _ = Block::decode(&b, &net);
        let _ = Header::decode(&mut Reader::new(&b));
        let t = mutate(&mut rng, &tx_bytes[round % tx_bytes.len()]);
        if let Ok(tx) = Tx::decode_exact(&t) {
            let _ = tx.check_standalone(&net.chain_id);
            assert_eq!(tx.encode(), t, "a decodable transaction re-encodes to the same bytes (canonical)");
        }
        let n = rng.below(300);
        let random: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        let _ = Block::decode(&random, &net);
        let _ = Tx::decode_exact(&random);
        let s = String::from_utf8_lossy(&random);
        let _ = parse_address(&net, &s);
        let _ = parse_amount(&s);
    }
}

#[test]
fn mutated_blocks_are_refused_without_panicking() {
    let net = Network::regtest();
    let (chain0, blocks, _) = corpus();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut chain = Chain::new(net.clone(), 1);
    for b in &blocks[..3] {
        chain.accept(b.clone(), NOW).unwrap();
    }
    let target = blocks[3].encode();
    let tip_before = chain.tip();
    let mut decoded = 0;
    for _ in 0..3_000 {
        let m = mutate(&mut rng, &target);
        if m == target {
            continue;
        }
        if let Ok(b) = Block::decode(&m, &net) {
            decoded += 1;
            // a different block that still passes every rule would be a forgery; it may only happen if the
            // mutation did not change consensus data (then the block id equals the original)
            if chain.accept(b.clone(), NOW).is_ok() {
                assert_eq!(b.id(&net), blocks[3].id(&net), "a mutated block was accepted");
            }
        }
    }
    assert!(decoded > 100, "the fuzzer reached the validation code ({decoded} decodable mutants)");
    assert!(chain.tip() == tip_before || chain.tip() == chain0.tip());
}
