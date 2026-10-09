//! Pool of transfers valid on the current tip: no conflicts among them, inputs only from the UTXO set
//! (no chains of unconfirmed transactions yet), bounded size.

use requant_consensus::chain::Chain;
use requant_consensus::tx::{Hash, OutPoint, Tx};
use requant_consensus::Error;
use std::collections::HashMap;

pub const MAX_TX_BYTES: usize = 100_000;
pub const MAX_POOL_BYTES: usize = 32 << 20;

struct Entry {
    tx: Tx,
    fee: u64,
    size: usize,
}

#[derive(Default)]
pub struct Mempool {
    txs: HashMap<Hash, Entry>,
    spends: HashMap<OutPoint, Hash>,
    bytes: usize,
}

impl Mempool {
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.txs.contains_key(txid)
    }

    /// Admit a transfer; returns its txid.
    pub fn add(&mut self, tx: Tx, chain: &Chain) -> Result<Hash, Error> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err(Error::Duplicate);
        }
        let size = tx.encode().len();
        if size > MAX_TX_BYTES {
            return Err(Error::Invalid("transaction too large for the pool"));
        }
        if self.bytes + size > MAX_POOL_BYTES {
            return Err(Error::Invalid("pool full"));
        }
        tx.check_standalone(&chain.net.chain_id)?;
        let Tx::Transfer { inputs, .. } = &tx else { return Err(Error::Invalid("coinbase outside a block")) };
        if inputs.iter().any(|i| self.spends.contains_key(&i.prev)) {
            return Err(Error::Invalid("conflicts with a pooled transaction"));
        }
        let fee = chain.check_spend(&tx)?;
        for i in inputs {
            self.spends.insert(i.prev, txid);
        }
        self.bytes += size;
        self.txs.insert(txid, Entry { tx, fee, size });
        Ok(txid)
    }

    fn remove(&mut self, txid: &Hash) {
        if let Some(e) = self.txs.remove(txid) {
            if let Tx::Transfer { inputs, .. } = &e.tx {
                for i in inputs {
                    self.spends.remove(&i.prev);
                }
            }
            self.bytes -= e.size;
        }
    }

    /// Drop everything no longer spendable on the new tip (included in a block, or conflicting).
    pub fn revalidate(&mut self, chain: &Chain) {
        let stale: Vec<Hash> =
            self.txs.iter().filter(|(_, e)| chain.check_spend(&e.tx).is_err()).map(|(id, _)| *id).collect();
        for id in stale {
            self.remove(&id);
        }
    }

    /// Highest fee rate first, up to `max_bytes`.
    pub fn select(&self, max_bytes: usize) -> Vec<Tx> {
        let mut v: Vec<&Entry> = self.txs.values().collect();
        v.sort_by(|a, b| (b.fee as u128 * a.size as u128).cmp(&(a.fee as u128 * b.size as u128)));
        let mut used = 0;
        let mut out = Vec::new();
        for e in v {
            if used + e.size <= max_bytes {
                used += e.size;
                out.push(e.tx.clone());
            }
        }
        out
    }

    pub fn get(&self, txid: &Hash) -> Option<&Tx> {
        self.txs.get(txid).map(|e| &e.tx)
    }
}
