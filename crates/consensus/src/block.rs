//! Blocks (CHAIN.md §3, §5, §10): header, TNet work claim, transactions, `tx_root`.

use crate::codec::{Reader, Writer};
use crate::params::{tagged, Network, MAX_BLOCK_BYTES};
use crate::tx::{Hash, Tx};
use crate::u256::U256;
use crate::Error;

pub const BLOCK_VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 116;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub version: u32,
    pub height: u64,
    pub prev: Hash,
    pub tx_root: Hash,
    pub time: u64,
    pub target: U256,
}

/// TNet work claim `(nonce, i, c, piece)` (SPEC.md §7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Claim {
    pub nonce: u64,
    pub i: u32,
    pub c: u32,
    pub piece: Vec<i8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: Header,
    pub claim: Claim,
    pub txs: Vec<Tx>,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut w = Writer::default();
        w.u32(self.version);
        w.u64(self.height);
        w.raw(&self.prev);
        w.raw(&self.tx_root);
        w.u64(self.time);
        w.raw(&self.target.to_be_bytes());
        w.0.try_into().unwrap()
    }

    pub fn decode(r: &mut Reader) -> Result<Header, Error> {
        Ok(Header {
            version: r.u32()?,
            height: r.u64()?,
            prev: r.arr32()?,
            tx_root: r.arr32()?,
            time: r.u64()?,
            target: U256::from_be_bytes(&r.arr32()?),
        })
    }

    /// The `header_digest` of SPEC.md: everything but the work claim.
    pub fn digest(&self, chain_id: &Hash) -> Hash {
        tagged("requant/header", &[chain_id, &self.encode()])
    }
}

impl Claim {
    pub fn empty(w: usize) -> Claim {
        Claim { nonce: 0, i: 0, c: 0, piece: vec![0; w] }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.nonce);
        w.u32(self.i);
        w.u32(self.c);
        w.0.extend(self.piece.iter().map(|&x| x as u8));
        w.0
    }

    pub fn decode(r: &mut Reader, w: usize) -> Result<Claim, Error> {
        Ok(Claim { nonce: r.u64()?, i: r.u32()?, c: r.u32()?, piece: r.take(w)?.iter().map(|&x| x as i8).collect() })
    }
}

/// `block_id = H("requant/block", header_digest || claim)`.
pub fn block_id(header_digest: &Hash, claim: &Claim) -> Hash {
    tagged("requant/block", &[header_digest, &claim.encode()])
}

fn merkle(leaves: &[Hash]) -> Hash {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = leaves.len().next_power_of_two() / 2; // largest power of two below len
    tagged("requant/node", &[&merkle(&leaves[..k]), &merkle(&leaves[k..])])
}

/// `tx_root = H("requant/txroot", LE32 n || M(wtxids))`.
pub fn tx_root(txs: &[Tx]) -> Hash {
    let leaves: Vec<Hash> = txs.iter().map(|t| t.wtxid()).collect();
    let m = if leaves.is_empty() { [0u8; 32] } else { merkle(&leaves) };
    tagged("requant/txroot", &[&(txs.len() as u32).to_le_bytes(), &m])
}

impl Block {
    pub fn id(&self, net: &Network) -> Hash {
        block_id(&self.header.digest(&net.chain_id), &self.claim)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.raw(&self.header.encode());
        w.raw(&self.claim.encode());
        w.varint(self.txs.len() as u64);
        for t in &self.txs {
            w.raw(&t.encode());
        }
        w.0
    }

    pub fn decode(bytes: &[u8], net: &Network) -> Result<Block, Error> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(Error::Invalid("block too large"));
        }
        let mut r = Reader::new(bytes);
        let header = Header::decode(&mut r)?;
        let claim = Claim::decode(&mut r, net.tnet.w)?;
        let n = r.varint(MAX_BLOCK_BYTES as u64)?;
        let mut txs = Vec::new();
        for _ in 0..n {
            txs.push(Tx::decode(&mut r)?);
        }
        r.finish()?;
        Ok(Block { header, claim, txs })
    }

    /// Checks that need no chain state: version, size, `tx_root`, coinbase placement and height,
    /// transaction shapes and signatures. The claim and everything contextual are checked by the chain.
    pub fn check_standalone(&self, net: &Network) -> Result<(), Error> {
        self.check_structure(net)?;
        self.txs.iter().try_for_each(|t| t.check_signatures(&net.chain_id))
    }

    /// [`Block::check_standalone`] without the signatures (cheap): version, size, piece length, `tx_root`,
    /// coinbase placement and height, transaction shapes.
    pub fn check_structure(&self, net: &Network) -> Result<(), Error> {
        if self.header.version != BLOCK_VERSION {
            return Err(Error::Invalid("block version"));
        }
        if self.encode().len() > MAX_BLOCK_BYTES {
            return Err(Error::Invalid("block too large"));
        }
        if self.claim.piece.len() != net.tnet.w {
            return Err(Error::Invalid("claim piece length"));
        }
        if tx_root(&self.txs) != self.header.tx_root {
            return Err(Error::Invalid("tx_root mismatch"));
        }
        match self.txs.first() {
            Some(Tx::Coinbase { height, .. }) if *height == self.header.height => {}
            _ => return Err(Error::Invalid("first transaction must be the coinbase of this height")),
        }
        if self.txs[1..].iter().any(Tx::is_coinbase) {
            return Err(Error::Invalid("second coinbase"));
        }
        self.txs.iter().try_for_each(Tx::check_shape)
    }
}

/// The fixed genesis block of `net` (CHAIN.md §10).
pub fn genesis(net: &Network) -> Block {
    let coinbase =
        Tx::Coinbase { height: 0, extra: format!("Requant {} genesis", net.name).into_bytes(), outputs: vec![] };
    let txs = vec![coinbase];
    let header = Header {
        version: BLOCK_VERSION,
        height: 0,
        prev: [0; 32],
        tx_root: tx_root(&txs),
        time: net.genesis_time,
        target: net.genesis_target,
    };
    Block { header, claim: Claim::empty(net.tnet.w), txs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Output;

    #[test]
    fn merkle_shapes() {
        let h = |b: u8| [b; 32];
        assert_eq!(merkle(&[h(1)]), h(1));
        let n = |a: Hash, b: Hash| tagged("requant/node", &[&a, &b]);
        assert_eq!(merkle(&[h(1), h(2), h(3)]), n(n(h(1), h(2)), h(3)));
        assert_eq!(merkle(&[h(1), h(2), h(3), h(4), h(5)]), n(n(n(h(1), h(2)), n(h(3), h(4))), h(5)));
        // no duplicated-leaf ambiguity: [a, b, c] and [a, b, c, c] differ
        assert_ne!(merkle(&[h(1), h(2), h(3)]), merkle(&[h(1), h(2), h(3), h(3)]));
    }

    #[test]
    fn genesis_roundtrip_and_standalone() {
        let net = Network::regtest();
        let g = genesis(&net);
        let bytes = g.encode();
        assert_eq!(bytes.len(), HEADER_BYTES + 16 + net.tnet.w + 1 + g.txs[0].encode().len());
        assert_eq!(Block::decode(&bytes, &net).unwrap(), g);
        g.check_standalone(&net).unwrap();
        assert_ne!(genesis(&Network::test()).id(&Network::test()), g.id(&net));
    }

    #[test]
    fn standalone_rejections() {
        let net = Network::regtest();
        let mut b = genesis(&net);
        b.txs.push(Tx::Coinbase { height: 0, extra: vec![], outputs: vec![Output { value: 1, pkh: [0; 32] }] });
        b.header.tx_root = tx_root(&b.txs);
        assert_eq!(b.check_standalone(&net), Err(Error::Invalid("second coinbase")));
        let mut b = genesis(&net);
        b.header.height = 1;
        assert!(b.check_standalone(&net).is_err());
        let mut b = genesis(&net);
        b.header.tx_root[0] ^= 1;
        assert_eq!(b.check_standalone(&net), Err(Error::Invalid("tx_root mismatch")));
    }
}
