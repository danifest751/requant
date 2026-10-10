//! Wallet files and offline signing.
//!
//! A wallet file (JSON) holds the 32-byte entropy of the backup phrase, encrypted like a key file (or as
//! plain hex when made with `--no-passphrase`; absent in a watch-only copy), and the key hashes of the
//! addresses derived so far on the receive and change chains (see `hd`), with how many of each were handed
//! out. The address lists are public: balance, history and preparing a payment need no passphrase. ed25519
//! has no public derivation, so new addresses are derived ahead (`LOOKAHEAD` per chain) whenever the seed
//! is unlocked.
//!
//! Offline signing: `prepare` (online, no secret needed) writes an [`Unsigned`] payment holding the
//! unsigned transaction, the derivation path of each input, the change outputs' paths and the full
//! transactions that created the coins spent. Signatures commit to the transaction, not to the values of
//! the coins spent, so the signing machine reads those values from the included transactions (checked by
//! their txids) instead of trusting the online machine about them, and checks that every input and change
//! output belongs to its own seed before it shows the payment and signs it.

use crate::hd;
use crate::{decrypt_secret, encrypt_secret, hexs, unhexs};
use ed25519_dalek::SigningKey;
use requant_consensus::params::Network;
use requant_consensus::tx::{pkh, Hash, Tx};
use serde_json::{json, Value};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const SEED_TAG: &str = "requant-seed:1:argon2id";
/// Addresses derived ahead of the last one handed out (and the gap a restore scans past).
pub const LOOKAHEAD: u32 = 20;
const ACCOUNT: u32 = 0;

pub struct WalletFile {
    pub network: String,
    seed: Option<String>,
    pub receive: Vec<Hash>,
    pub receive_issued: u32,
    pub change: Vec<Hash>,
    pub change_issued: u32,
}

fn owner_at(seed: &[u8; 64], chain: u32, index: u32) -> Hash {
    pkh(&hd::key_at(seed, ACCOUNT, chain, index).verifying_key().to_bytes())
}

fn hashes(v: &Value, what: &str) -> Result<Vec<Hash>, String> {
    v.as_array()
        .ok_or(format!("wallet file: {what} missing"))?
        .iter()
        .map(|x| {
            x.as_str().and_then(unhexs).and_then(|b| b.try_into().ok()).ok_or(format!("wallet file: bad {what} entry"))
        })
        .collect()
}

impl WalletFile {
    /// A new wallet of `entropy`, encrypted under `pass` (`None`: stored in plain hex), with the first
    /// receive address handed out.
    pub fn new(
        net: &Network,
        entropy: &[u8; 32],
        pass: Option<&str>,
        salt: &[u8; 16],
        nonce: &[u8; 24],
    ) -> Result<WalletFile, String> {
        let seed = match pass {
            Some(p) => encrypt_secret(SEED_TAG, entropy, p, salt, nonce)?,
            None => hexs(entropy),
        };
        let mut w = WalletFile {
            network: net.name.to_string(),
            seed: Some(seed),
            receive: vec![],
            receive_issued: 1,
            change: vec![],
            change_issued: 0,
        };
        w.top_up(&hd::seed_of(entropy, ""));
        Ok(w)
    }

    pub fn is_wallet(text: &str) -> bool {
        text.trim_start().starts_with('{') && text.contains("\"requant_wallet\"")
    }

    pub fn parse(text: &str) -> Result<WalletFile, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("wallet file: {e}"))?;
        if v["requant_wallet"] != 1 {
            return Err("wallet file: unknown format version".into());
        }
        let num = |k: &str| v[k].as_u64().and_then(|n| u32::try_from(n).ok()).ok_or(format!("wallet file: {k}"));
        let w = WalletFile {
            network: v["network"].as_str().ok_or("wallet file: network")?.to_string(),
            seed: v["seed"].as_str().map(str::to_string),
            receive: hashes(&v["receive"], "receive")?,
            receive_issued: num("receive_issued")?,
            change: hashes(&v["change"], "change")?,
            change_issued: num("change_issued")?,
        };
        if w.receive_issued as usize > w.receive.len() || w.change_issued as usize > w.change.len() {
            return Err("wallet file: more addresses handed out than derived".into());
        }
        Ok(w)
    }

    pub fn to_text(&self) -> String {
        let list = |v: &[Hash]| v.iter().map(|h| hexs(h)).collect::<Vec<_>>();
        let v = json!({
            "requant_wallet": 1,
            "network": self.network,
            "seed": self.seed,
            "receive_issued": self.receive_issued,
            "change_issued": self.change_issued,
            "receive": list(&self.receive),
            "change": list(&self.change),
        });
        serde_json::to_string_pretty(&v).unwrap()
    }

    pub fn watch_only(&self) -> bool {
        self.seed.is_none()
    }

    pub fn is_encrypted(&self) -> bool {
        self.seed.as_deref().is_some_and(|s| s.starts_with(SEED_TAG))
    }

    /// The same wallet without its secret: for an online machine that prepares payments.
    pub fn watch_copy(&self) -> WalletFile {
        WalletFile {
            seed: None,
            receive: self.receive.clone(),
            change: self.change.clone(),
            network: self.network.clone(),
            ..*self
        }
    }

    /// The backup phrase's entropy (`pass` for an encrypted wallet).
    pub fn entropy(&self, pass: Option<&str>) -> Result<Zeroizing<[u8; 32]>, String> {
        let s = self.seed.as_deref().ok_or("a watch-only wallet holds no keys")?;
        Ok(Zeroizing::new(decrypt_secret(SEED_TAG, s, pass)?))
    }

    /// Store the entropy again under a new passphrase (or none).
    pub fn reseal(
        &mut self,
        entropy: &[u8; 32],
        pass: Option<&str>,
        salt: &[u8; 16],
        nonce: &[u8; 24],
    ) -> Result<(), String> {
        self.seed = Some(match pass {
            Some(p) => encrypt_secret(SEED_TAG, entropy, p, salt, nonce)?,
            None => hexs(entropy),
        });
        Ok(())
    }

    /// Every derived address, receive then change.
    pub fn owners(&self) -> Vec<Hash> {
        self.receive.iter().chain(&self.change).copied().collect()
    }

    /// The `(chain, index)` of one of this wallet's addresses.
    pub fn path_of(&self, owner: &Hash) -> Option<(u32, u32)> {
        if let Some(i) = self.receive.iter().position(|h| h == owner) {
            return Some((hd::RECEIVE, i as u32));
        }
        self.change.iter().position(|h| h == owner).map(|i| (hd::CHANGE, i as u32))
    }

    /// Derive addresses until each chain has `LOOKAHEAD` beyond those handed out.
    pub fn top_up(&mut self, seed: &[u8; 64]) {
        while self.receive.len() < (self.receive_issued + LOOKAHEAD) as usize {
            self.receive.push(owner_at(seed, hd::RECEIVE, self.receive.len() as u32));
        }
        while self.change.len() < (self.change_issued + LOOKAHEAD) as usize {
            self.change.push(owner_at(seed, hd::CHANGE, self.change.len() as u32));
        }
    }

    /// Hand out the next receive address (`None`: derive more first, which needs the seed).
    pub fn next_receive(&mut self) -> Option<Hash> {
        let h = *self.receive.get(self.receive_issued as usize)?;
        self.receive_issued += 1;
        Some(h)
    }

    pub fn next_change(&mut self) -> Option<Hash> {
        let h = *self.change.get(self.change_issued as usize)?;
        self.change_issued += 1;
        Some(h)
    }

    /// The addresses in use after a restore: on each chain, scan until `LOOKAHEAD` unused addresses in a
    /// row; everything up to the last used one counts as handed out (at least one receive address).
    pub fn scan(&mut self, seed: &[u8; 64], mut used: impl FnMut(&Hash) -> Result<bool, String>) -> Result<(), String> {
        for chain in [hd::RECEIVE, hd::CHANGE] {
            let (mut index, mut gap, mut last) = (0u32, 0u32, None);
            while gap < LOOKAHEAD {
                let list = if chain == hd::RECEIVE { &mut self.receive } else { &mut self.change };
                while list.len() <= index as usize {
                    list.push(owner_at(seed, chain, list.len() as u32));
                }
                if used(&list[index as usize])? {
                    (last, gap) = (Some(index), 0);
                } else {
                    gap += 1;
                }
                index += 1;
            }
            let issued = last.map_or(0, |i| i + 1);
            if chain == hd::RECEIVE {
                self.receive_issued = issued.max(1);
            } else {
                self.change_issued = issued;
            }
        }
        self.top_up(seed);
        Ok(())
    }

    /// Signing keys of this wallet's addresses, by key hash.
    pub fn keyring(&self, seed: &[u8; 64]) -> HashMap<Hash, SigningKey> {
        let mut keys = HashMap::new();
        for (chain, list) in [(hd::RECEIVE, &self.receive), (hd::CHANGE, &self.change)] {
            for (i, owner) in list.iter().enumerate() {
                let k = hd::key_at(seed, ACCOUNT, chain, i as u32);
                if pkh(&k.verifying_key().to_bytes()) == *owner {
                    keys.insert(*owner, k);
                }
            }
        }
        keys
    }
}

/// An unsigned payment for offline signing (see the module documentation).
pub struct Unsigned {
    pub network: String,
    pub tx: Tx,
    /// `(chain, index)` of the key of each input.
    pub paths: Vec<(u32, u32)>,
    /// The transactions whose outputs the inputs spend.
    pub prev: Vec<Tx>,
    /// `(vout, chain, index)` of the outputs that return change to the wallet.
    pub change: Vec<(u32, u32, u32)>,
}

/// What a payment does, as the signing machine checked it.
#[derive(Debug)]
pub struct Review {
    /// `(to, amount, is change back to this wallet)` per output.
    pub outputs: Vec<(Hash, u64, bool)>,
    pub spent: u64,
    pub fee: u64,
}

impl Unsigned {
    pub fn to_text(&self) -> String {
        let v = json!({
            "requant_unsigned": 1,
            "network": self.network,
            "tx": hexs(&self.tx.encode()),
            "paths": self.paths.iter().map(|(c, i)| json!([c, i])).collect::<Vec<_>>(),
            "prev": self.prev.iter().map(|t| hexs(&t.encode())).collect::<Vec<_>>(),
            "change": self.change.iter().map(|(v, c, i)| json!([v, c, i])).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&v).unwrap()
    }

    pub fn parse(text: &str) -> Result<Unsigned, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("unsigned payment: {e}"))?;
        if v["requant_unsigned"] != 1 {
            return Err("not an unsigned payment file".into());
        }
        let tx_of = |s: &Value| -> Result<Tx, String> {
            let b = s.as_str().and_then(unhexs).ok_or("unsigned payment: bad hex")?;
            Tx::decode_exact(&b).map_err(|e| format!("unsigned payment: {e}"))
        };
        let nums = |x: &Value, n: usize| -> Result<Vec<u32>, String> {
            let a = x.as_array().filter(|a| a.len() == n).ok_or("unsigned payment: bad path")?;
            a.iter()
                .map(|y| y.as_u64().and_then(|k| u32::try_from(k).ok()).ok_or("unsigned payment: bad path".into()))
                .collect()
        };
        let list = |k: &str| v[k].as_array().cloned().ok_or(format!("unsigned payment: {k} missing"));
        Ok(Unsigned {
            network: v["network"].as_str().ok_or("unsigned payment: network")?.to_string(),
            tx: tx_of(&v["tx"])?,
            paths: list("paths")?.iter().map(|p| nums(p, 2).map(|n| (n[0], n[1]))).collect::<Result<_, _>>()?,
            prev: list("prev")?.iter().map(tx_of).collect::<Result<_, _>>()?,
            change: list("change")?.iter().map(|p| nums(p, 3).map(|n| (n[0], n[1], n[2]))).collect::<Result<_, _>>()?,
        })
    }

    /// Check the payment against the seed: every input spends an output of an included transaction that
    /// belongs to the key at its path, and every change output pays this wallet. Returns what it does.
    pub fn review(&self, seed: &[u8; 64]) -> Result<Review, String> {
        let Tx::Transfer { inputs, outputs } = &self.tx else { return Err("not a transfer".into()) };
        if inputs.len() != self.paths.len() || inputs.is_empty() {
            return Err("one key path per input is needed".into());
        }
        let prev: HashMap<Hash, &Tx> = self.prev.iter().map(|t| (t.txid(), t)).collect();
        let mut spent = 0u64;
        for (k, (inp, &(chain, index))) in inputs.iter().zip(&self.paths).enumerate() {
            let t = prev.get(&inp.prev.txid).ok_or(format!("input {k}: the transaction it spends is not included"))?;
            let out = t.outputs().get(inp.prev.vout as usize).ok_or(format!("input {k}: no such output"))?;
            if owner_at(seed, chain, index) != out.pkh {
                return Err(format!("input {k}: the coin does not belong to this wallet's key {chain}/{index}"));
            }
            spent = spent.checked_add(out.value).ok_or("amount overflow")?;
        }
        let mut is_change = vec![false; outputs.len()];
        for &(vout, chain, index) in &self.change {
            let o = outputs.get(vout as usize).ok_or("change output out of range")?;
            if owner_at(seed, chain, index) != o.pkh {
                return Err(format!("output {vout} is marked as change but does not pay this wallet"));
            }
            is_change[vout as usize] = true;
        }
        let paid = outputs.iter().try_fold(0u64, |s, o| s.checked_add(o.value)).ok_or("amount overflow")?;
        let fee = spent.checked_sub(paid).ok_or("the outputs exceed the coins spent")?;
        let outputs = outputs.iter().zip(is_change).map(|(o, c)| (o.pkh, o.value, c)).collect();
        Ok(Review { outputs, spent, fee })
    }

    /// The signed transaction (call [`Unsigned::review`] first).
    pub fn sign(&self, net: &Network, seed: &[u8; 64]) -> Tx {
        let keys: Vec<SigningKey> = self.paths.iter().map(|&(c, i)| hd::key_at(seed, ACCOUNT, c, i)).collect();
        let mut tx = self.tx.clone();
        tx.sign(&net.chain_id, &keys.iter().collect::<Vec<_>>());
        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan_payment, Spendable};
    use requant_consensus::tx::{OutPoint, Output};

    fn wallet() -> (WalletFile, Zeroizing<[u8; 64]>) {
        let net = Network::regtest();
        let e = [9u8; 32];
        (WalletFile::new(&net, &e, None, &[1; 16], &[2; 24]).unwrap(), hd::seed_of(&e, ""))
    }

    #[test]
    fn file_roundtrip_watch_copy_and_encryption() {
        let net = Network::regtest();
        let (w, seed) = wallet();
        assert_eq!((w.receive.len(), w.change.len()), (21, 20));
        let back = WalletFile::parse(&w.to_text()).unwrap();
        assert_eq!(back.receive, w.receive);
        assert_eq!(*back.entropy(None).unwrap(), [9u8; 32]);
        let watch = WalletFile::parse(&w.watch_copy().to_text()).unwrap();
        assert!(watch.watch_only() && watch.entropy(None).is_err());
        assert_eq!(watch.owners(), w.owners());
        let enc = WalletFile::new(&net, &[9; 32], Some("pw"), &[1; 16], &[2; 24]).unwrap();
        assert!(enc.is_encrypted() && !enc.to_text().contains(&hexs(&[9u8; 32])));
        assert!(enc.entropy(Some("no")).is_err());
        assert_eq!(*enc.entropy(Some("pw")).unwrap(), [9u8; 32]);
        assert_eq!(enc.receive, w.receive);
        assert_eq!(w.keyring(&seed).len(), 41);
    }

    #[test]
    fn restore_scan_finds_used_addresses_past_gaps() {
        let (mut w, seed) = wallet();
        let used = [w.receive[3], w.receive[19], w.change[0]];
        let far = owner_at(&seed, hd::RECEIVE, 45); // beyond a gap of 20 after index 19: 20..39 unused, so 45 is not found
        let mut fresh =
            WalletFile { receive: vec![], change: vec![], receive_issued: 1, change_issued: 0, ..w.watch_copy() };
        fresh.seed = w.seed.clone();
        fresh.scan(&seed, |h| Ok(used.contains(h) || *h == far)).unwrap();
        assert_eq!((fresh.receive_issued, fresh.change_issued), (20, 1));
        assert_eq!(fresh.receive.len(), 40);
        assert_eq!(fresh.next_receive(), Some(w.receive[20]));
        // handing out past the derived ones needs the seed
        w.receive_issued = w.receive.len() as u32;
        assert_eq!(w.next_receive(), None);
        w.top_up(&seed);
        assert!(w.next_receive().is_some());
    }

    #[test]
    fn offline_payment_is_checked_against_the_seed() {
        let net = Network::regtest();
        let (mut w, seed) = wallet();
        // a coin to the wallet's first address, created by some earlier transaction
        let funding =
            Tx::Coinbase { height: 5, extra: vec![], outputs: vec![Output { value: 1_000_000, pkh: w.receive[0] }] };
        let coin = Spendable { op: OutPoint { txid: funding.txid(), vout: 0 }, value: 1_000_000, owner: w.receive[0] };
        let change = w.next_change().unwrap();
        let (tx, chosen, fee) = plan_payment(&[coin], &[([7; 32], 300_000)], 5, change).unwrap();
        let mk = |prev: Vec<Tx>| Unsigned {
            network: "regtest".into(),
            tx: tx.clone(),
            paths: chosen.iter().map(|c| w.path_of(&c.owner).unwrap()).collect(),
            prev,
            change: vec![(1, hd::CHANGE, 0)],
        };
        let u = Unsigned::parse(&mk(vec![funding.clone()]).to_text()).unwrap();
        let r = u.review(&seed).unwrap();
        assert_eq!((r.spent, r.fee), (1_000_000, fee));
        assert_eq!(r.outputs, vec![([7; 32], 300_000, false), (change, 1_000_000 - 300_000 - fee, true)]);
        u.sign(&net, &seed).check_standalone(&net.chain_id).unwrap();
        // the coins' transactions must be there, and the coin must be the wallet's
        assert!(mk(vec![]).review(&seed).unwrap_err().contains("not included"));
        let other = Tx::Coinbase { height: 5, extra: vec![], outputs: vec![Output { value: 1_000_000, pkh: [1; 32] }] };
        let mut bad = mk(vec![other.clone()]);
        if let Tx::Transfer { inputs, .. } = &mut bad.tx {
            inputs[0].prev.txid = other.txid();
        }
        assert!(bad.review(&seed).unwrap_err().contains("does not belong"));
        // change that pays someone else is caught
        let mut lie = mk(vec![funding]);
        lie.change = vec![(0, hd::CHANGE, 0)];
        assert!(lie.review(&seed).unwrap_err().contains("marked as change"));
    }
}
