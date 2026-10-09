//! Transaction and address index over the best chain: where each transaction is, every output (to resolve
//! inputs), and per-address history (received and sent per transaction). Follows reorganisations by
//! unindexing blocks above the fork point. Held in memory and rebuilt on start.

use requant_consensus::block::Block;
use requant_consensus::chain::Chain;
use requant_consensus::tx::{Hash, OutPoint, Output, Tx};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxLoc {
    pub height: u64,
    pub block: Hash,
    pub pos: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub height: u64,
    pub txid: Hash,
    pub received: u64,
    pub sent: u64,
}

#[derive(Default)]
pub struct TxIndex {
    active: Vec<Hash>,
    txs: HashMap<Hash, TxLoc>,
    outputs: HashMap<OutPoint, Output>,
    addr: HashMap<Hash, Vec<Event>>,
}

impl TxIndex {
    /// Bring the index to the chain's best chain.
    pub fn sync(&mut self, chain: &Chain) {
        let mut h = 0usize;
        while h < self.active.len() && chain.active_id(h as u64) == Some(self.active[h]) {
            h += 1;
        }
        while self.active.len() > h {
            let id = self.active.pop().unwrap();
            let height = self.active.len() as u64;
            if let Some(b) = chain.block(&id) {
                self.unindex(&b, height);
            }
        }
        let mut height = self.active.len() as u64;
        while let Some(id) = chain.active_id(height) {
            let b = chain.block(&id).expect("active block");
            self.index(&b, &id, height);
            self.active.push(id);
            height += 1;
        }
    }

    fn index(&mut self, b: &Block, id: &Hash, height: u64) {
        for (pos, tx) in b.txs.iter().enumerate() {
            let txid = tx.txid();
            self.txs.insert(txid, TxLoc { height, block: *id, pos: pos as u32 });
            let mut delta: HashMap<Hash, (u64, u64)> = HashMap::new();
            if let Tx::Transfer { inputs, .. } = tx {
                for i in inputs {
                    if let Some(o) = self.outputs.get(&i.prev) {
                        delta.entry(o.pkh).or_default().1 += o.value;
                    }
                }
            }
            for (k, o) in tx.outputs().iter().enumerate() {
                self.outputs.insert(OutPoint { txid, vout: k as u32 }, *o);
                delta.entry(o.pkh).or_default().0 += o.value;
            }
            for (owner, (received, sent)) in delta {
                self.addr.entry(owner).or_default().push(Event { height, txid, received, sent });
            }
        }
    }

    fn unindex(&mut self, b: &Block, height: u64) {
        for tx in b.txs.iter().rev() {
            let txid = tx.txid();
            self.txs.remove(&txid);
            for k in 0..tx.outputs().len() {
                self.outputs.remove(&OutPoint { txid, vout: k as u32 });
            }
        }
        for v in self.addr.values_mut() {
            v.retain(|e| e.height < height);
        }
        self.addr.retain(|_, v| !v.is_empty());
    }

    pub fn height(&self) -> Option<u64> {
        (self.active.len() as u64).checked_sub(1)
    }

    pub fn locate(&self, txid: &Hash) -> Option<TxLoc> {
        self.txs.get(txid).copied()
    }

    pub fn output(&self, op: &OutPoint) -> Option<Output> {
        self.outputs.get(op).copied()
    }

    /// Newest first, at most `limit`.
    pub fn history(&self, owner: &Hash, limit: usize) -> Vec<Event> {
        self.addr.get(owner).map(|v| v.iter().rev().take(limit).copied().collect()).unwrap_or_default()
    }

    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }
}
