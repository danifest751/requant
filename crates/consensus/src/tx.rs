//! Transactions (CHAIN.md §4): coinbase and transfers signed with ed25519. An output pays a hash: a
//! public key's (`pkh`), or a spending condition's (2-of-2 keys, or a hash/time-locked contract), which
//! the spending input reveals. Inputs of version-2 transfers may also carry absolute and relative time
//! locks (CHAIN.md §4.1). These are the primitives for atomic swaps and payment channels; the protocols
//! themselves are software above them.

use crate::codec::{Reader, Writer};
use crate::params::{tagged, MAX_AMOUNT, MAX_COINBASE_EXTRA, MAX_TX_IO};
use crate::Error;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub type Hash = [u8; 32];

pub fn pkh(pubkey: &[u8; 32]) -> Hash {
    tagged("requant/pkh", &[pubkey])
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash,
    pub vout: u32,
}

/// A hash/time-locked contract: `claim`'s key takes the coin with the 32-byte preimage of `hash`
/// (SHA-256); after height `timeout`, `refund`'s key takes it back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Htlc {
    pub hash: Hash,
    pub claim: Hash,
    pub refund: Hash,
    pub timeout: u64,
}

impl Htlc {
    /// The hash an output pays to lock a coin under this contract.
    pub fn owner(&self) -> Hash {
        tagged("requant/htlc", &[&self.hash, &self.claim, &self.refund, &self.timeout.to_le_bytes()])
    }
}

/// A revocable output, the building block of two-way payment channels: `owner`'s key takes the coin once
/// it is `delay` blocks deep; `revoke`'s key takes it at any time (the penalty for publishing a revoked
/// channel state).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Delayed {
    pub owner: Hash,
    pub revoke: Hash,
    pub delay: u32,
}

impl Delayed {
    pub fn owner_hash(&self) -> Hash {
        tagged("requant/delayed", &[&self.owner, &self.revoke, &self.delay.to_le_bytes()])
    }
}

/// A hash/time-locked contract with a revocation path, for payments routed through channels: as
/// [`Htlc`], with relative delays on the claim and refund paths (so the other side can still revoke a
/// published old state) and `revoke`'s key taking the coin at any time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HtlcRevocable {
    pub hash: Hash,
    pub claim: Hash,
    pub refund: Hash,
    pub revoke: Hash,
    pub timeout: u64,
    pub claim_delay: u32,
    pub refund_delay: u32,
}

impl HtlcRevocable {
    pub fn owner(&self) -> Hash {
        tagged(
            "requant/htlc-revocable",
            &[
                &self.hash,
                &self.claim,
                &self.refund,
                &self.revoke,
                &self.timeout.to_le_bytes(),
                &self.claim_delay.to_le_bytes(),
                &self.refund_delay.to_le_bytes(),
            ],
        )
    }
}

/// The hash an output pays to lock a coin under both keys (in this order).
pub fn multi2_owner(first: &[u8; 32], second: &[u8; 32]) -> Hash {
    tagged("requant/multi2", &[first, second])
}

/// How an input satisfies the output it spends, beyond `pubkey`/`sig`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unlock {
    /// The output pays `pkh(pubkey)`.
    Key,
    /// The output pays `multi2_owner(pubkey, pubkey2)`; both keys sign.
    Multi2 { pubkey2: [u8; 32], sig2: [u8; 64] },
    /// The output pays `htlc.owner()`; `pkh(pubkey) == htlc.claim` and `SHA256(preimage) == htlc.hash`.
    HtlcClaim { htlc: Htlc, preimage: [u8; 32] },
    /// The output pays `htlc.owner()`; `pkh(pubkey) == htlc.refund` and `after_height >= htlc.timeout`.
    HtlcRefund { htlc: Htlc },
    /// The output pays `d.owner_hash()`; `pkh(pubkey) == d.owner` and `after_blocks >= d.delay`.
    DelayedOwner { d: Delayed },
    /// The output pays `d.owner_hash()`; `pkh(pubkey) == d.revoke`.
    DelayedRevoke { d: Delayed },
    /// The output pays `h.owner()`; claim key, preimage, and `after_blocks >= h.claim_delay`.
    RevocableClaim { h: HtlcRevocable, preimage: [u8; 32] },
    /// The output pays `h.owner()`; refund key, `after_height >= h.timeout`, `after_blocks >= h.refund_delay`.
    RevocableRefund { h: HtlcRevocable },
    /// The output pays `h.owner()`; `pkh(pubkey) == h.revoke`.
    RevocableRevoke { h: HtlcRevocable },
}

impl Unlock {
    /// Unlocks added after the first conditions (CHAIN.md §4.2), valid from `Network::contracts_height`.
    pub fn is_contract(&self) -> bool {
        !matches!(self, Unlock::Key | Unlock::Multi2 { .. } | Unlock::HtlcClaim { .. } | Unlock::HtlcRefund { .. })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Input {
    pub prev: OutPoint,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
    /// The block containing the spend must be at least this high (0: no lock).
    pub after_height: u64,
    /// The spent coin must have this many blocks above its own (0: no lock): the block containing the
    /// spend is at least `coin height + after_blocks`.
    pub after_blocks: u32,
    pub unlock: Unlock,
    /// The signature(s) cover this input and all outputs only, so others may add inputs later (to raise
    /// the fee, or to fund a shared payment). Valid from `Network::contracts_height`.
    pub anyone_can_pay: bool,
}

impl Input {
    /// A plain key spend of `prev`, keys and signature filled in by [`Tx::sign`].
    pub fn new(prev: OutPoint) -> Input {
        Input {
            prev,
            pubkey: [0; 32],
            sig: [0; 64],
            after_height: 0,
            after_blocks: 0,
            unlock: Unlock::Key,
            anyone_can_pay: false,
        }
    }

    /// A version-1 input: a key spend without locks.
    pub fn is_plain(&self) -> bool {
        self.after_height == 0 && self.after_blocks == 0 && self.unlock == Unlock::Key && !self.anyone_can_pay
    }

    /// The output hash this input may spend, after the condition's own checks (the preimage, the key of
    /// the path taken, the refund time). Needs no chain state.
    pub fn owner(&self) -> Result<Hash, Error> {
        match &self.unlock {
            Unlock::Key => Ok(pkh(&self.pubkey)),
            Unlock::Multi2 { pubkey2, .. } => Ok(multi2_owner(&self.pubkey, pubkey2)),
            Unlock::HtlcClaim { htlc, preimage } => {
                if pkh(&self.pubkey) != htlc.claim {
                    return Err(Error::Invalid("htlc claim by another key"));
                }
                if tnet::sha256::sha256(preimage) != htlc.hash {
                    return Err(Error::Invalid("htlc preimage does not match"));
                }
                Ok(htlc.owner())
            }
            Unlock::HtlcRefund { htlc } => {
                if pkh(&self.pubkey) != htlc.refund {
                    return Err(Error::Invalid("htlc refund by another key"));
                }
                if self.after_height < htlc.timeout {
                    return Err(Error::Invalid("htlc refund before its timeout"));
                }
                Ok(htlc.owner())
            }
            Unlock::DelayedOwner { d } => {
                if pkh(&self.pubkey) != d.owner {
                    return Err(Error::Invalid("delayed output spent by another key"));
                }
                if self.after_blocks < d.delay {
                    return Err(Error::Invalid("delayed output spent before its delay"));
                }
                Ok(d.owner_hash())
            }
            Unlock::DelayedRevoke { d } => {
                if pkh(&self.pubkey) != d.revoke {
                    return Err(Error::Invalid("revocation by another key"));
                }
                Ok(d.owner_hash())
            }
            Unlock::RevocableClaim { h, preimage } => {
                if pkh(&self.pubkey) != h.claim {
                    return Err(Error::Invalid("htlc claim by another key"));
                }
                if tnet::sha256::sha256(preimage) != h.hash {
                    return Err(Error::Invalid("htlc preimage does not match"));
                }
                if self.after_blocks < h.claim_delay {
                    return Err(Error::Invalid("htlc claim before its delay"));
                }
                Ok(h.owner())
            }
            Unlock::RevocableRefund { h } => {
                if pkh(&self.pubkey) != h.refund {
                    return Err(Error::Invalid("htlc refund by another key"));
                }
                if self.after_height < h.timeout {
                    return Err(Error::Invalid("htlc refund before its timeout"));
                }
                if self.after_blocks < h.refund_delay {
                    return Err(Error::Invalid("htlc refund before its delay"));
                }
                Ok(h.owner())
            }
            Unlock::RevocableRevoke { h } => {
                if pkh(&self.pubkey) != h.revoke {
                    return Err(Error::Invalid("revocation by another key"));
                }
                Ok(h.owner())
            }
        }
    }

    /// Whether the time locks allow this spend in a block at `height` of a coin created at `coin_height`.
    pub fn unlocked_at(&self, height: u64, coin_height: u64) -> bool {
        height >= self.after_height && height.saturating_sub(coin_height) >= self.after_blocks as u64
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Output {
    pub value: u64,
    pub pkh: Hash,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Tx {
    Coinbase {
        height: u64,
        extra: Vec<u8>,
        outputs: Vec<Output>,
    },
    /// Encoded as kind 1 when every input is plain, else as kind 2 (CHAIN.md §4.1).
    Transfer {
        inputs: Vec<Input>,
        outputs: Vec<Output>,
    },
}

pub const TX_VERSION: u32 = 1;

impl Tx {
    pub fn outputs(&self) -> &[Output] {
        match self {
            Tx::Coinbase { outputs, .. } | Tx::Transfer { outputs, .. } => outputs,
        }
    }

    pub fn is_coinbase(&self) -> bool {
        matches!(self, Tx::Coinbase { .. })
    }

    /// A transfer using conditions or time locks (kind 2), valid only from `Network::conditions_height`.
    pub fn is_v2(&self) -> bool {
        matches!(self, Tx::Transfer { inputs, .. } if inputs.iter().any(|i| !i.is_plain()))
    }

    /// A transfer using the later contract unlocks or anyone-can-pay signatures (CHAIN.md §4.2), valid only
    /// from `Network::contracts_height`.
    pub fn uses_contracts(&self) -> bool {
        matches!(self, Tx::Transfer { inputs, .. }
            if inputs.iter().any(|i| i.anyone_can_pay || i.unlock.is_contract()))
    }

    fn encode_into(&self, w: &mut Writer, with_sigs: bool) {
        w.u32(TX_VERSION);
        match self {
            Tx::Coinbase { height, extra, outputs } => {
                w.u8(0);
                w.u64(*height);
                w.bytes(extra);
                encode_outputs(w, outputs);
            }
            Tx::Transfer { inputs, outputs } => {
                let v2 = self.is_v2();
                w.u8(if v2 { 2 } else { 1 });
                w.varint(inputs.len() as u64);
                for inp in inputs {
                    w.raw(&inp.prev.txid);
                    w.u32(inp.prev.vout);
                    w.raw(&inp.pubkey);
                    if with_sigs {
                        w.raw(&inp.sig);
                    }
                    if v2 {
                        encode_v2_input(w, inp, with_sigs);
                    }
                }
                encode_outputs(w, outputs);
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.encode_into(&mut w, true);
        w.0
    }

    pub fn decode(r: &mut Reader) -> Result<Tx, Error> {
        if r.u32()? != TX_VERSION {
            return Err(Error::Decode("tx version"));
        }
        let tx = match r.u8()? {
            0 => {
                let height = r.u64()?;
                let extra = r.bytes(MAX_COINBASE_EXTRA)?.to_vec();
                Tx::Coinbase { height, extra, outputs: decode_outputs(r)? }
            }
            kind @ (1 | 2) => {
                let n = r.varint(MAX_TX_IO)?;
                let mut inputs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let prev = OutPoint { txid: r.arr32()?, vout: r.u32()? };
                    let mut inp = Input { pubkey: r.arr32()?, sig: r.arr64()?, ..Input::new(prev) };
                    if kind == 2 {
                        decode_v2_input(r, &mut inp)?;
                    }
                    inputs.push(inp);
                }
                let tx = Tx::Transfer { inputs, outputs: decode_outputs(r)? };
                // one encoding per transaction: kind 2 only when some input needs it
                if kind == 2 && !tx.is_v2() {
                    return Err(Error::Decode("kind-2 transfer without conditions or locks"));
                }
                tx
            }
            _ => return Err(Error::Decode("tx kind")),
        };
        Ok(tx)
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Tx, Error> {
        let mut r = Reader::new(bytes);
        let tx = Tx::decode(&mut r)?;
        r.finish()?;
        Ok(tx)
    }

    /// Hash without signatures: what outputs are referenced by and what inputs sign.
    pub fn txid(&self) -> Hash {
        let mut w = Writer::default();
        self.encode_into(&mut w, false);
        tagged("requant/txid", &[&w.0])
    }

    /// Hash of the full transaction, committed by the block's `tx_root`.
    pub fn wtxid(&self) -> Hash {
        tagged("requant/wtxid", &[&self.encode()])
    }

    pub fn sighash(chain_id: &Hash, txid: &Hash, k: u32) -> Hash {
        tagged("requant/sighash", &[chain_id, txid, &k.to_le_bytes()])
    }

    /// What input `k` signs: the whole transaction (`sighash`), or with anyone-can-pay only this input
    /// (without signatures) and every output.
    pub fn input_sighash(&self, chain_id: &Hash, txid: &Hash, k: usize) -> Hash {
        match self {
            Tx::Transfer { inputs, outputs } if inputs[k].anyone_can_pay => {
                let mut w = Writer::default();
                w.u32(TX_VERSION);
                let inp = &inputs[k];
                w.raw(&inp.prev.txid);
                w.u32(inp.prev.vout);
                w.raw(&inp.pubkey);
                encode_v2_input(&mut w, inp, false);
                encode_outputs(&mut w, outputs);
                tagged("requant/sighash-acp", &[chain_id, &w.0])
            }
            _ => Self::sighash(chain_id, txid, k as u32),
        }
    }

    /// Add the second signature of a 2-of-2 input `k` (its `pubkey2` set before signing, as part of the
    /// txid); call after [`Tx::sign`] filled in the first.
    pub fn sign_second(&mut self, chain_id: &Hash, k: usize, key: &SigningKey) {
        let sighash = self.input_sighash(chain_id, &self.txid(), k);
        if let Tx::Transfer { inputs, .. } = self {
            if let Unlock::Multi2 { pubkey2, sig2 } = &mut inputs[k].unlock {
                assert_eq!(*pubkey2, key.verifying_key().to_bytes(), "the second key of this input");
                *sig2 = key.sign(&sighash).to_bytes();
            }
        }
    }

    /// Fill in the signatures of a transfer; `keys[k]` signs input `k`.
    pub fn sign(&mut self, chain_id: &Hash, keys: &[&SigningKey]) {
        // Public keys are part of the txid, so they go in before it is computed.
        if let Tx::Transfer { inputs, .. } = self {
            assert_eq!(inputs.len(), keys.len(), "one key per input");
            for (inp, key) in inputs.iter_mut().zip(keys) {
                inp.pubkey = key.verifying_key().to_bytes();
            }
        }
        let txid = self.txid();
        let sighashes: Vec<Hash> = (0..keys.len()).map(|k| self.input_sighash(chain_id, &txid, k)).collect();
        if let Tx::Transfer { inputs, .. } = self {
            for ((inp, key), sighash) in inputs.iter_mut().zip(keys).zip(&sighashes) {
                inp.sig = key.sign(sighash).to_bytes();
            }
        }
    }

    /// Sign input `k` alone (its `pubkey` set before), leaving the others as they are: for adding an
    /// input to a transaction whose other inputs signed anyone-can-pay.
    pub fn sign_input(&mut self, chain_id: &Hash, k: usize, key: &SigningKey) {
        if let Tx::Transfer { inputs, .. } = self {
            inputs[k].pubkey = key.verifying_key().to_bytes();
        }
        let sighash = self.input_sighash(chain_id, &self.txid(), k);
        if let Tx::Transfer { inputs, .. } = self {
            inputs[k].sig = key.sign(&sighash).to_bytes();
        }
    }

    /// Checks that need no chain state: shape, amounts, duplicate inputs, signatures.
    pub fn check_standalone(&self, chain_id: &Hash) -> Result<(), Error> {
        self.check_shape()?;
        self.check_signatures(chain_id)
    }

    /// Every input's ed25519 signature (strict verification). The expensive part of the checks; callers that
    /// face untrusted input run it last.
    pub fn check_signatures(&self, chain_id: &Hash) -> Result<(), Error> {
        if let Tx::Transfer { inputs, .. } = self {
            let txid = self.txid();
            for (k, inp) in inputs.iter().enumerate() {
                let sighash = self.input_sighash(chain_id, &txid, k);
                verify(&inp.pubkey, &inp.sig, &sighash)?;
                if let Unlock::Multi2 { pubkey2, sig2 } = &inp.unlock {
                    verify(pubkey2, sig2, &sighash)?;
                }
            }
        }
        Ok(())
    }

    /// Checks without signatures: amounts, empty transfers, duplicate inputs.
    pub fn check_shape(&self) -> Result<(), Error> {
        let outputs = self.outputs();
        let mut total: u64 = 0;
        for o in outputs {
            if o.value == 0 {
                return Err(Error::Invalid("zero-value output"));
            }
            total = total.checked_add(o.value).filter(|&t| t <= MAX_AMOUNT).ok_or(Error::Invalid("output total"))?;
        }
        if let Tx::Transfer { inputs, .. } = self {
            if inputs.is_empty() || outputs.is_empty() {
                return Err(Error::Invalid("empty transfer"));
            }
            let mut seen: Vec<&OutPoint> = inputs.iter().map(|i| &i.prev).collect();
            seen.sort();
            if seen.windows(2).any(|p| p[0] == p[1]) {
                return Err(Error::Invalid("duplicate input"));
            }
        }
        Ok(())
    }
}

fn verify(pubkey: &[u8; 32], sig: &[u8; 64], msg: &Hash) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(pubkey).map_err(|_| Error::Invalid("bad public key"))?;
    key.verify_strict(msg, &Signature::from_bytes(sig)).map_err(|_| Error::Invalid("bad signature"))
}

fn encode_htlc(w: &mut Writer, h: &Htlc) {
    w.raw(&h.hash);
    w.raw(&h.claim);
    w.raw(&h.refund);
    w.u64(h.timeout);
}

fn decode_htlc(r: &mut Reader) -> Result<Htlc, Error> {
    Ok(Htlc { hash: r.arr32()?, claim: r.arr32()?, refund: r.arr32()?, timeout: r.u64()? })
}

fn encode_delayed(w: &mut Writer, d: &Delayed) {
    w.raw(&d.owner);
    w.raw(&d.revoke);
    w.u32(d.delay);
}

fn decode_delayed(r: &mut Reader) -> Result<Delayed, Error> {
    Ok(Delayed { owner: r.arr32()?, revoke: r.arr32()?, delay: r.u32()? })
}

fn encode_revocable(w: &mut Writer, h: &HtlcRevocable) {
    w.raw(&h.hash);
    w.raw(&h.claim);
    w.raw(&h.refund);
    w.raw(&h.revoke);
    w.u64(h.timeout);
    w.u32(h.claim_delay);
    w.u32(h.refund_delay);
}

fn decode_revocable(r: &mut Reader) -> Result<HtlcRevocable, Error> {
    Ok(HtlcRevocable {
        hash: r.arr32()?,
        claim: r.arr32()?,
        refund: r.arr32()?,
        revoke: r.arr32()?,
        timeout: r.u64()?,
        claim_delay: r.u32()?,
        refund_delay: r.u32()?,
    })
}

/// The anyone-can-pay flag rides in the top bit of the unlock byte, so the encodings of the first
/// conditions are unchanged.
const ANYONE_CAN_PAY: u8 = 0x80;

/// The kind-2 part of an input: locks and the unlock (second signatures omitted from the txid).
fn encode_v2_input(w: &mut Writer, inp: &Input, with_sigs: bool) {
    w.u64(inp.after_height);
    w.u32(inp.after_blocks);
    let flag = if inp.anyone_can_pay { ANYONE_CAN_PAY } else { 0 };
    match &inp.unlock {
        Unlock::Key => w.u8(flag),
        Unlock::Multi2 { pubkey2, sig2 } => {
            w.u8(1 | flag);
            w.raw(pubkey2);
            if with_sigs {
                w.raw(sig2);
            }
        }
        Unlock::HtlcClaim { htlc, preimage } => {
            w.u8(2 | flag);
            encode_htlc(w, htlc);
            w.raw(preimage);
        }
        Unlock::HtlcRefund { htlc } => {
            w.u8(3 | flag);
            encode_htlc(w, htlc);
        }
        Unlock::DelayedOwner { d } => {
            w.u8(4 | flag);
            encode_delayed(w, d);
        }
        Unlock::DelayedRevoke { d } => {
            w.u8(5 | flag);
            encode_delayed(w, d);
        }
        Unlock::RevocableClaim { h, preimage } => {
            w.u8(6 | flag);
            encode_revocable(w, h);
            w.raw(preimage);
        }
        Unlock::RevocableRefund { h } => {
            w.u8(7 | flag);
            encode_revocable(w, h);
        }
        Unlock::RevocableRevoke { h } => {
            w.u8(8 | flag);
            encode_revocable(w, h);
        }
    }
}

fn decode_v2_input(r: &mut Reader, inp: &mut Input) -> Result<(), Error> {
    inp.after_height = r.u64()?;
    inp.after_blocks = r.u32()?;
    let byte = r.u8()?;
    inp.anyone_can_pay = byte & ANYONE_CAN_PAY != 0;
    inp.unlock = match byte & !ANYONE_CAN_PAY {
        0 => Unlock::Key,
        1 => Unlock::Multi2 { pubkey2: r.arr32()?, sig2: r.arr64()? },
        2 => Unlock::HtlcClaim { htlc: decode_htlc(r)?, preimage: r.arr32()? },
        3 => Unlock::HtlcRefund { htlc: decode_htlc(r)? },
        4 => Unlock::DelayedOwner { d: decode_delayed(r)? },
        5 => Unlock::DelayedRevoke { d: decode_delayed(r)? },
        6 => Unlock::RevocableClaim { h: decode_revocable(r)?, preimage: r.arr32()? },
        7 => Unlock::RevocableRefund { h: decode_revocable(r)? },
        8 => Unlock::RevocableRevoke { h: decode_revocable(r)? },
        _ => return Err(Error::Decode("unlock kind")),
    };
    Ok(())
}

fn encode_outputs(w: &mut Writer, outputs: &[Output]) {
    w.varint(outputs.len() as u64);
    for o in outputs {
        w.u64(o.value);
        w.raw(&o.pkh);
    }
}

fn decode_outputs(r: &mut Reader) -> Result<Vec<Output>, Error> {
    let n = r.varint(MAX_TX_IO)?;
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        v.push(Output { value: r.u64()?, pkh: r.arr32()? });
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn transfer(chain: &Hash) -> Tx {
        let k = key(1);
        let mut tx = Tx::Transfer {
            inputs: vec![Input::new(OutPoint { txid: [9; 32], vout: 0 })],
            outputs: vec![Output { value: 5, pkh: pkh(&key(2).verifying_key().to_bytes()) }],
        };
        tx.sign(chain, &[&k]);
        tx
    }

    #[test]
    fn roundtrip_and_hashes() {
        let chain = [7u8; 32];
        let tx = transfer(&chain);
        assert_eq!(Tx::decode_exact(&tx.encode()).unwrap(), tx);
        let cb = Tx::Coinbase { height: 5, extra: b"hi".to_vec(), outputs: vec![] };
        assert_eq!(Tx::decode_exact(&cb.encode()).unwrap(), cb);
        // signatures change wtxid, not txid
        let mut t2 = tx.clone();
        if let Tx::Transfer { inputs, .. } = &mut t2 {
            inputs[0].sig[0] ^= 1;
        }
        assert_eq!(t2.txid(), tx.txid());
        assert_ne!(t2.wtxid(), tx.wtxid());
        assert!(Tx::decode_exact(&[tx.encode(), vec![0]].concat()).is_err());
    }

    #[test]
    fn signatures_bind_chain_and_content() {
        let chain = [7u8; 32];
        let tx = transfer(&chain);
        tx.check_standalone(&chain).unwrap();
        assert_eq!(tx.check_standalone(&[8u8; 32]), Err(Error::Invalid("bad signature")));
        let mut t2 = tx.clone();
        if let Tx::Transfer { outputs, .. } = &mut t2 {
            outputs[0].value = 6;
        }
        assert_eq!(t2.check_standalone(&chain), Err(Error::Invalid("bad signature")));
    }

    #[test]
    fn shape_rules() {
        let chain = [7u8; 32];
        let mut tx = transfer(&chain);
        if let Tx::Transfer { inputs, .. } = &mut tx {
            inputs.push(inputs[0].clone());
        }
        assert_eq!(tx.check_standalone(&chain), Err(Error::Invalid("duplicate input")));
        let zero = Tx::Coinbase { height: 1, extra: vec![], outputs: vec![Output { value: 0, pkh: [0; 32] }] };
        assert_eq!(zero.check_standalone(&chain), Err(Error::Invalid("zero-value output")));
        let big = Output { value: 1 << 62, pkh: [0; 32] };
        let over = Tx::Coinbase { height: 1, extra: vec![], outputs: vec![big, big, big] };
        assert_eq!(over.check_standalone(&chain), Err(Error::Invalid("output total")));
        let long = Tx::Coinbase { height: 1, extra: vec![0; 65], outputs: vec![] };
        assert!(Tx::decode_exact(&long.encode()).is_err());
    }
}
