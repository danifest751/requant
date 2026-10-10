//! Spending conditions from the wallet (CHAIN.md §4.1–4.2). A condition — 2-of-2, HTLC, revocable output
//! or revocable HTLC — is described in a small JSON file; its address is computed locally; coins are
//! locked under it with an ordinary payment to that address and spent along one of its paths with a
//! kind-2 transfer that carries the unlock data and the time locks the path needs.

use requant_consensus::address::{address, parse_address};
use requant_consensus::params::Network;
use requant_consensus::tx::{
    multi2_owner, pkh, Delayed, Hash, Htlc, HtlcRevocable, Input, OutPoint, Output, Tx, Unlock,
};
use requant_node::rpc::{hex, unhex};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// SHA-256 of a secret, as HTLCs check it (and Bitcoin-family `OP_SHA256` and EVM `sha256`).
pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Condition {
    /// Both keys sign, `first` then `second`.
    Multi2 {
        first: [u8; 32],
        second: [u8; 32],
    },
    Htlc(Htlc),
    Delayed(Delayed),
    Revocable(HtlcRevocable),
}

/// Who signs a path: one key (by its hash) or both keys of a 2-of-2 (by their public keys).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Signers {
    One(Hash),
    Both([u8; 32], [u8; 32]),
}

fn h32(v: &Value, what: &str) -> Result<Hash, String> {
    let s = v.as_str().ok_or(format!("{what}: expected 64 hex digits"))?;
    unhex(s).ok().and_then(|b| b.try_into().ok()).ok_or(format!("{what}: expected 64 hex digits"))
}

fn num(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64().ok_or(format!("{what}: expected a number"))
}

fn small(v: &Value, what: &str) -> Result<u32, String> {
    u32::try_from(num(v, what)?).map_err(|_| format!("{what}: too large"))
}

/// A key hash from an address of `net` or 64 hex digits.
pub fn who(net: &Network, s: &str) -> Result<Hash, String> {
    parse_address(net, s)
        .or_else(|_| unhex(s).ok().and_then(|b| b.try_into().ok()).ok_or(format!("{s}: not an address or key hash")))
}

impl Condition {
    /// The hash an output pays to lock coins under this condition.
    pub fn owner(&self) -> Hash {
        match self {
            Condition::Multi2 { first, second } => multi2_owner(first, second),
            Condition::Htlc(h) => h.owner(),
            Condition::Delayed(d) => d.owner_hash(),
            Condition::Revocable(h) => h.owner(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Condition::Multi2 { .. } => "multi2",
            Condition::Htlc(_) => "htlc",
            Condition::Delayed(_) => "delayed",
            Condition::Revocable(_) => "htlc-revocable",
        }
    }

    /// The paths that spend it.
    pub fn paths(&self) -> &'static [&'static str] {
        match self {
            Condition::Multi2 { .. } => &["both"],
            Condition::Htlc(_) => &["claim", "refund"],
            Condition::Delayed(_) => &["owner", "revoke"],
            Condition::Revocable(_) => &["claim", "refund", "revoke"],
        }
    }

    /// From command-line words: `multi2 PUBKEY_A PUBKEY_B`, `htlc HASH CLAIM REFUND TIMEOUT`,
    /// `delayed OWNER REVOKE DELAY`, `htlc-revocable HASH CLAIM REFUND REVOKE TIMEOUT CLAIM_DELAY REFUND_DELAY`
    /// (CLAIM, REFUND, OWNER, REVOKE: addresses or key hashes; HASH: the SHA-256 of a 32-byte secret).
    pub fn from_words(net: &Network, words: &[&str]) -> Result<Condition, String> {
        let hex32 = |s: &str, what: &str| h32(&json!(s), what);
        let n = |s: &str, what: &str| s.parse::<u64>().map_err(|_| format!("{what}: expected a number"));
        let n32 = |s: &str, what: &str| s.parse::<u32>().map_err(|_| format!("{what}: expected a number"));
        Ok(match words {
            ["multi2", a, b] => Condition::Multi2 { first: hex32(a, "pubkey A")?, second: hex32(b, "pubkey B")? },
            ["htlc", hash, claim, refund, timeout] => Condition::Htlc(Htlc {
                hash: hex32(hash, "hash")?,
                claim: who(net, claim)?,
                refund: who(net, refund)?,
                timeout: n(timeout, "timeout")?,
            }),
            ["delayed", owner, revoke, delay] => Condition::Delayed(Delayed {
                owner: who(net, owner)?,
                revoke: who(net, revoke)?,
                delay: n32(delay, "delay")?,
            }),
            ["htlc-revocable", hash, claim, refund, revoke, timeout, cd, rd] => Condition::Revocable(HtlcRevocable {
                hash: hex32(hash, "hash")?,
                claim: who(net, claim)?,
                refund: who(net, refund)?,
                revoke: who(net, revoke)?,
                timeout: n(timeout, "timeout")?,
                claim_delay: n32(cd, "claim delay")?,
                refund_delay: n32(rd, "refund delay")?,
            }),
            _ => return Err("expected: multi2 PUBKEY_A PUBKEY_B | htlc HASH CLAIM REFUND TIMEOUT | delayed OWNER REVOKE DELAY | htlc-revocable HASH CLAIM REFUND REVOKE TIMEOUT CLAIM_DELAY REFUND_DELAY".into()),
        })
    }

    pub fn to_json(&self, net: &Network) -> Value {
        let a = |h: &Hash| address(net, h);
        let mut v = match self {
            Condition::Multi2 { first, second } => json!({"first": hex(first), "second": hex(second)}),
            Condition::Htlc(h) => json!({"hash": hex(&h.hash), "claim": a(&h.claim), "refund": a(&h.refund),
                "timeout": h.timeout}),
            Condition::Delayed(d) => json!({"owner": a(&d.owner), "revoke": a(&d.revoke), "delay": d.delay}),
            Condition::Revocable(h) => json!({"hash": hex(&h.hash), "claim": a(&h.claim), "refund": a(&h.refund),
                "revoke": a(&h.revoke), "timeout": h.timeout, "claim_delay": h.claim_delay,
                "refund_delay": h.refund_delay}),
        };
        v["requant_condition"] = json!(1);
        v["network"] = json!(net.name);
        v["kind"] = json!(self.kind());
        v["address"] = json!(address(net, &self.owner()));
        v["paths"] = json!(self.paths());
        v
    }

    pub fn from_json(net: &Network, v: &Value) -> Result<Condition, String> {
        if v["requant_condition"] != json!(1) {
            return Err("not a condition file".into());
        }
        if v["network"] != json!(net.name) {
            return Err(format!("a condition of the {} network", v["network"].as_str().unwrap_or("?")));
        }
        let w = |k: &str| -> Result<Hash, String> { who(net, v[k].as_str().ok_or(format!("{k} missing"))?) };
        let c = match v["kind"].as_str() {
            Some("multi2") => {
                Condition::Multi2 { first: h32(&v["first"], "first")?, second: h32(&v["second"], "second")? }
            }
            Some("htlc") => Condition::Htlc(Htlc {
                hash: h32(&v["hash"], "hash")?,
                claim: w("claim")?,
                refund: w("refund")?,
                timeout: num(&v["timeout"], "timeout")?,
            }),
            Some("delayed") => Condition::Delayed(Delayed {
                owner: w("owner")?,
                revoke: w("revoke")?,
                delay: small(&v["delay"], "delay")?,
            }),
            Some("htlc-revocable") => Condition::Revocable(HtlcRevocable {
                hash: h32(&v["hash"], "hash")?,
                claim: w("claim")?,
                refund: w("refund")?,
                revoke: w("revoke")?,
                timeout: num(&v["timeout"], "timeout")?,
                claim_delay: small(&v["claim_delay"], "claim_delay")?,
                refund_delay: small(&v["refund_delay"], "refund_delay")?,
            }),
            _ => return Err("unknown condition kind".into()),
        };
        // the address in the file must be the one these parameters give
        if v["address"].as_str() != Some(address(net, &c.owner()).as_str()) {
            return Err("the address in the file does not match its parameters".into());
        }
        Ok(c)
    }

    /// Who must sign `path`.
    pub fn signers(&self, path: &str) -> Result<Signers, String> {
        Ok(match (self, path) {
            (Condition::Multi2 { first, second }, "both") => Signers::Both(*first, *second),
            (Condition::Htlc(h), "claim") => Signers::One(h.claim),
            (Condition::Htlc(h), "refund") => Signers::One(h.refund),
            (Condition::Delayed(d), "owner") => Signers::One(d.owner),
            (Condition::Delayed(d), "revoke") => Signers::One(d.revoke),
            (Condition::Revocable(h), "claim") => Signers::One(h.claim),
            (Condition::Revocable(h), "refund") => Signers::One(h.refund),
            (Condition::Revocable(h), "revoke") => Signers::One(h.revoke),
            _ => return Err(format!("{} has the paths {}", self.kind(), self.paths().join(", "))),
        })
    }

    /// The input that spends `op` along `path`, with the unlock data and the time locks the path needs
    /// (keys and signatures filled in when signing).
    pub fn input(&self, op: OutPoint, path: &str, preimage: Option<[u8; 32]>) -> Result<Input, String> {
        let secret = || preimage.ok_or_else(|| "this path needs --preimage HEX (the 32-byte secret)".to_string());
        let check = |hash: &Hash, p: &[u8; 32]| {
            if sha256(p) == *hash {
                Ok(())
            } else {
                Err("the preimage does not hash to the condition's hash".to_string())
            }
        };
        let base = Input::new(op);
        Ok(match (self, path) {
            (Condition::Multi2 { second, .. }, "both") => {
                Input { unlock: Unlock::Multi2 { pubkey2: *second, sig2: [0; 64] }, ..base }
            }
            (Condition::Htlc(h), "claim") => {
                let p = secret()?;
                check(&h.hash, &p)?;
                Input { unlock: Unlock::HtlcClaim { htlc: *h, preimage: p }, ..base }
            }
            (Condition::Htlc(h), "refund") => {
                Input { after_height: h.timeout, unlock: Unlock::HtlcRefund { htlc: *h }, ..base }
            }
            (Condition::Delayed(d), "owner") => {
                Input { after_blocks: d.delay, unlock: Unlock::DelayedOwner { d: *d }, ..base }
            }
            (Condition::Delayed(d), "revoke") => Input { unlock: Unlock::DelayedRevoke { d: *d }, ..base },
            (Condition::Revocable(h), "claim") => {
                let p = secret()?;
                check(&h.hash, &p)?;
                Input { after_blocks: h.claim_delay, unlock: Unlock::RevocableClaim { h: *h, preimage: p }, ..base }
            }
            (Condition::Revocable(h), "refund") => Input {
                after_height: h.timeout,
                after_blocks: h.refund_delay,
                unlock: Unlock::RevocableRefund { h: *h },
                ..base
            },
            (Condition::Revocable(h), "revoke") => Input { unlock: Unlock::RevocableRevoke { h: *h }, ..base },
            _ => return Err(format!("{} has the paths {}", self.kind(), self.paths().join(", "))),
        })
    }
}

/// An unsigned transfer of every coin in `coins` (`(outpoint, value)`, all under `cond`) along `path` to
/// `to`, paying `rate` atoms per byte (at least 1000 atoms). Returns it with its fee.
pub fn spend(
    cond: &Condition,
    path: &str,
    coins: &[(OutPoint, u64)],
    to: &Hash,
    rate: u64,
    preimage: Option<[u8; 32]>,
    anyone_can_pay: bool,
) -> Result<(Tx, u64), String> {
    if coins.is_empty() {
        return Err("no coins under this condition".into());
    }
    let mut inputs = Vec::new();
    for (op, _) in coins {
        inputs.push(Input { anyone_can_pay, ..cond.input(*op, path, preimage)? });
    }
    let total: u64 = coins.iter().map(|(_, v)| v).sum();
    let mut tx = Tx::Transfer { inputs, outputs: vec![Output { value: total, pkh: *to }] };
    let fee = (tx.encode().len() as u64 * rate).max(1000);
    if fee >= total {
        return Err("the coins do not cover the fee".into());
    }
    if let Tx::Transfer { outputs, .. } = &mut tx {
        outputs[0].value = total - fee;
    }
    Ok((tx, fee))
}

/// Whether `key` (a 32-byte public key) is the one `signers` needs first, and whether it is the second
/// of a 2-of-2.
pub fn role(signers: &Signers, pubkey: &[u8; 32]) -> (bool, bool) {
    match signers {
        Signers::One(h) => (pkh(pubkey) == *h, false),
        Signers::Both(a, b) => (pubkey == a, pubkey == b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn pk(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    #[test]
    fn every_path_unlocks_its_condition_and_signs() {
        let net = Network::regtest();
        let secret = [7u8; 32];
        let hash = sha256(&secret);
        let (a, b, c) = (key(1), key(2), key(3));
        let conds = [
            Condition::Multi2 { first: pk(&a), second: pk(&b) },
            Condition::Htlc(Htlc { hash, claim: pkh(&pk(&a)), refund: pkh(&pk(&b)), timeout: 50 }),
            Condition::Delayed(Delayed { owner: pkh(&pk(&a)), revoke: pkh(&pk(&b)), delay: 9 }),
            Condition::Revocable(HtlcRevocable {
                hash,
                claim: pkh(&pk(&a)),
                refund: pkh(&pk(&b)),
                revoke: pkh(&pk(&c)),
                timeout: 50,
                claim_delay: 2,
                refund_delay: 3,
            }),
        ];
        let op = OutPoint { txid: [5; 32], vout: 0 };
        for cond in conds {
            // the file round-trips and keeps its address
            let back = Condition::from_json(&net, &cond.to_json(&net)).unwrap();
            assert_eq!(back, cond);
            for path in cond.paths() {
                let (mut tx, fee) = spend(&cond, path, &[(op, 1_000_000)], &[9; 32], 1, Some(secret), false).unwrap();
                assert!(fee >= 1000);
                let signers = cond.signers(path).unwrap();
                let first = [&a, &b, &c].into_iter().find(|k| role(&signers, &pk(k)).0).unwrap();
                tx.sign(&net.chain_id, &[first]);
                if let Signers::Both(_, _) = signers {
                    tx.sign_second(&net.chain_id, 0, &b);
                }
                tx.check_standalone(&net.chain_id).unwrap();
                let Tx::Transfer { inputs, .. } = &tx else { unreachable!() };
                assert_eq!(inputs[0].owner(), Ok(cond.owner()), "{} {path}", cond.kind());
            }
        }
        // a wrong secret is refused before anything is signed
        let htlc = conds_htlc(hash, &a, &b);
        assert!(spend(&htlc, "claim", &[(op, 1_000_000)], &[9; 32], 1, Some([8; 32]), false).is_err());
        assert!(spend(&htlc, "claim", &[(op, 1_000_000)], &[9; 32], 1, None, false).is_err());
        assert!(htlc.signers("revoke").is_err());
    }

    fn conds_htlc(hash: Hash, a: &SigningKey, b: &SigningKey) -> Condition {
        Condition::Htlc(Htlc { hash, claim: pkh(&pk(a)), refund: pkh(&pk(b)), timeout: 50 })
    }

    #[test]
    fn a_tampered_condition_file_is_refused() {
        let net = Network::regtest();
        let cond = Condition::Delayed(Delayed { owner: [1; 32], revoke: [2; 32], delay: 9 });
        let mut v = cond.to_json(&net);
        v["delay"] = json!(1);
        assert!(Condition::from_json(&net, &v).is_err());
        assert!(Condition::from_json(&Network::test(), &cond.to_json(&net)).is_err());
    }
}
