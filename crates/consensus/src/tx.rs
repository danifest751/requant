//! Transactions (CHAIN.md §4): coinbase and pay-to-public-key-hash transfers signed with ed25519.

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Input {
    pub prev: OutPoint,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Output {
    pub value: u64,
    pub pkh: Hash,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Tx {
    Coinbase { height: u64, extra: Vec<u8>, outputs: Vec<Output> },
    Transfer { inputs: Vec<Input>, outputs: Vec<Output> },
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
                w.u8(1);
                w.varint(inputs.len() as u64);
                for inp in inputs {
                    w.raw(&inp.prev.txid);
                    w.u32(inp.prev.vout);
                    w.raw(&inp.pubkey);
                    if with_sigs {
                        w.raw(&inp.sig);
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
            1 => {
                let n = r.varint(MAX_TX_IO)?;
                let mut inputs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let prev = OutPoint { txid: r.arr32()?, vout: r.u32()? };
                    inputs.push(Input { prev, pubkey: r.arr32()?, sig: r.arr64()? });
                }
                Tx::Transfer { inputs, outputs: decode_outputs(r)? }
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
        if let Tx::Transfer { inputs, .. } = self {
            for (k, (inp, key)) in inputs.iter_mut().zip(keys).enumerate() {
                inp.sig = key.sign(&Self::sighash(chain_id, &txid, k as u32)).to_bytes();
            }
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
                let key = VerifyingKey::from_bytes(&inp.pubkey).map_err(|_| Error::Invalid("bad public key"))?;
                let sig = Signature::from_bytes(&inp.sig);
                key.verify_strict(&Self::sighash(chain_id, &txid, k as u32), &sig)
                    .map_err(|_| Error::Invalid("bad signature"))?;
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
            inputs: vec![Input { prev: OutPoint { txid: [9; 32], vout: 0 }, pubkey: [0; 32], sig: [0; 64] }],
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
