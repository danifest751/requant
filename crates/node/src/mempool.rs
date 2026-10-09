//! Pool of transfers valid on the current tip. Inputs may spend the UTXO set or outputs of other pooled
//! transactions (chains of unconfirmed transactions, e.g. spending change at once); no two pooled
//! transactions spend the same output; blocks take parents before children.
//!
//! Spam bounds: a fee of at least `MIN_FEE_RATE` atoms per byte; when the pool is full, a transaction
//! paying a higher rate pushes out the lowest-rate ones (with what spends them); transactions waiting
//! longer than `MAX_AGE` are dropped.

use requant_consensus::chain::Chain;
use requant_consensus::params::MAX_AMOUNT;
use requant_consensus::tx::{pkh, Hash, OutPoint, Output, Tx};
use requant_consensus::Error;
use std::collections::{HashMap, HashSet};

pub const MAX_TX_BYTES: usize = 100_000;
pub const MAX_POOL_BYTES: usize = 32 << 20;
/// Longest chain of unconfirmed ancestors a transaction may have.
pub const MAX_ANCESTORS: usize = 25;
/// Smallest fee accepted, in atoms per byte of the transaction.
pub const MIN_FEE_RATE: u64 = 1;
/// Seconds a transaction may wait in the pool.
pub const MAX_AGE: u64 = 72 * 3600;

struct Entry {
    tx: Tx,
    fee: u64,
    size: usize,
    /// Pooled transactions whose outputs this one spends.
    parents: Vec<Hash>,
    /// Arrival order, for stable selection.
    seq: u64,
    /// Arrival time.
    time: u64,
}

pub struct Mempool {
    txs: HashMap<Hash, Entry>,
    spends: HashMap<OutPoint, Hash>,
    bytes: usize,
    seq: u64,
    max_bytes: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Mempool::with_limit(MAX_POOL_BYTES)
    }
}

/// `a` pays a lower rate than `b` (fee per byte, compared without division).
fn lower_rate(a: (u64, usize), b: (u64, usize)) -> bool {
    (a.0 as u128 * b.1 as u128) < (b.0 as u128 * a.1 as u128)
}

fn inputs(tx: &Tx) -> &[requant_consensus::tx::Input] {
    match tx {
        Tx::Transfer { inputs, .. } => inputs,
        Tx::Coinbase { .. } => &[],
    }
}

impl Mempool {
    /// A pool holding at most `max_bytes` of transactions.
    pub fn with_limit(max_bytes: usize) -> Mempool {
        Mempool { txs: HashMap::new(), spends: HashMap::new(), bytes: 0, seq: 0, max_bytes }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &Hash) -> Option<&Tx> {
        self.txs.get(txid).map(|e| &e.tx)
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Pooled transactions, newest first: (txid, fee, size in bytes).
    pub fn list(&self) -> Vec<(Hash, u64, usize)> {
        let mut v: Vec<_> = self.txs.iter().map(|(id, e)| (e.seq, *id, e.fee, e.size)).collect();
        v.sort_unstable_by_key(|x| std::cmp::Reverse(x.0));
        v.into_iter().map(|(_, id, fee, size)| (id, fee, size)).collect()
    }

    /// An output spendable by a pool transaction: from the UTXO set (with its maturity) or created by a
    /// pooled transaction. Returns the output and the pooled parent, if any.
    fn coin(&self, chain: &Chain, op: &OutPoint) -> Result<(Output, Option<Hash>), Error> {
        if let Some(c) = chain.coin(op) {
            if c.coinbase && chain.height() + 1 - c.height < chain.net.maturity {
                return Err(Error::Invalid("immature coinbase spend"));
            }
            return Ok((c.output, None));
        }
        let e = self.txs.get(&op.txid).ok_or(Error::Invalid("missing or spent input"))?;
        let o = e.tx.outputs().get(op.vout as usize).ok_or(Error::Invalid("missing or spent input"))?;
        Ok((*o, Some(op.txid)))
    }

    fn ancestors(&self, txid: &Hash, seen: &mut HashSet<Hash>) {
        if let Some(e) = self.txs.get(txid) {
            for p in &e.parents {
                if seen.insert(*p) {
                    self.ancestors(p, seen);
                }
            }
        }
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
        // cheap checks and input lookups first; the signatures (the expensive part) last
        tx.check_shape()?;
        let Tx::Transfer { inputs, outputs } = &tx else { return Err(Error::Invalid("coinbase outside a block")) };
        let mut total_in: u64 = 0;
        let mut parents = Vec::new();
        for i in inputs {
            if self.spends.contains_key(&i.prev) {
                return Err(Error::Invalid("conflicts with a pooled transaction"));
            }
            let (out, parent) = self.coin(chain, &i.prev)?;
            if pkh(&i.pubkey) != out.pkh {
                return Err(Error::Invalid("input key does not match the output"));
            }
            total_in =
                total_in.checked_add(out.value).filter(|&t| t <= MAX_AMOUNT).ok_or(Error::Invalid("input total"))?;
            if let Some(p) = parent {
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
        }
        let total_out: u64 = outputs.iter().map(|o| o.value).sum();
        let fee = total_in.checked_sub(total_out).ok_or(Error::Invalid("outputs exceed inputs"))?;
        if fee < size as u64 * MIN_FEE_RATE {
            return Err(Error::Invalid("fee below the minimum (1 atom per byte)"));
        }
        let mut anc = HashSet::new();
        for p in &parents {
            anc.insert(*p);
            self.ancestors(p, &mut anc);
        }
        if anc.len() > MAX_ANCESTORS {
            return Err(Error::Invalid("too many unconfirmed ancestors"));
        }
        tx.check_signatures(&chain.net.chain_id)?;
        self.make_room(size, fee, &anc)?;
        for i in inputs {
            self.spends.insert(i.prev, txid);
        }
        self.bytes += size;
        self.seq += 1;
        self.txs.insert(txid, Entry { tx, fee, size, parents, seq: self.seq, time: crate::node::now() });
        Ok(txid)
    }

    /// Pooled transactions that spend `txid`'s outputs, directly or further down.
    fn descendants(&self, txid: &Hash) -> Vec<Hash> {
        let mut out = vec![*txid];
        let mut k = 0;
        while k < out.len() {
            let cur = out[k];
            let next: Vec<Hash> = self
                .txs
                .iter()
                .filter(|(id, e)| e.parents.contains(&cur) && !out.contains(id))
                .map(|(id, _)| *id)
                .collect();
            out.extend(next);
            k += 1;
        }
        out
    }

    /// Free `size` bytes for a transaction paying `fee` by dropping the lowest-rate transactions (and their
    /// descendants), never the new one's ancestors and never one paying at least its rate.
    fn make_room(&mut self, size: usize, fee: u64, ancestors: &HashSet<Hash>) -> Result<(), Error> {
        while self.bytes + size > self.max_bytes {
            let victim = self
                .txs
                .iter()
                .filter(|(id, _)| !ancestors.contains(*id))
                .min_by(|a, b| {
                    let (x, y) = ((a.1.fee, a.1.size), (b.1.fee, b.1.size));
                    if lower_rate(x, y) {
                        std::cmp::Ordering::Less
                    } else if lower_rate(y, x) {
                        std::cmp::Ordering::Greater
                    } else {
                        b.1.seq.cmp(&a.1.seq) // equal rate: the newest goes first
                    }
                })
                .map(|(id, e)| (*id, e.fee, e.size));
            match victim {
                Some((id, f, s)) if lower_rate((f, s), (fee, size)) => {
                    for d in self.descendants(&id) {
                        self.remove(&d);
                    }
                }
                _ => return Err(Error::Invalid("pool full: the fee rate is too low")),
            }
        }
        Ok(())
    }

    fn remove(&mut self, txid: &Hash) {
        if let Some(e) = self.txs.remove(txid) {
            for i in inputs(&e.tx) {
                self.spends.remove(&i.prev);
            }
            self.bytes -= e.size;
        }
    }

    /// After the tip changed: drop transactions whose inputs no longer exist (included in a block,
    /// conflicting, or children of dropped ones), and re-link parents that were confirmed.
    pub fn revalidate(&mut self, chain: &Chain) {
        // transactions that waited too long go, with what spends them
        let t = crate::node::now();
        let old: Vec<Hash> =
            self.txs.iter().filter(|(_, e)| t.saturating_sub(e.time) > MAX_AGE).map(|(id, _)| *id).collect();
        for id in old {
            for d in self.descendants(&id) {
                self.remove(&d);
            }
        }
        loop {
            let stale: Vec<Hash> = self
                .txs
                .iter()
                .filter(|(_, e)| inputs(&e.tx).iter().any(|i| self.coin(chain, &i.prev).is_err()))
                .map(|(id, _)| *id)
                .collect();
            if stale.is_empty() {
                break;
            }
            for id in stale {
                self.remove(&id);
            }
        }
        let ids: Vec<Hash> = self.txs.keys().copied().collect();
        for id in ids {
            let parents: Vec<Hash> = {
                let e = &self.txs[&id];
                let mut v: Vec<Hash> =
                    inputs(&e.tx).iter().map(|i| i.prev.txid).filter(|t| self.txs.contains_key(t)).collect();
                v.dedup();
                v
            };
            self.txs.get_mut(&id).unwrap().parents = parents;
        }
    }

    /// Transactions for a block, highest fee rate first but never a child before its parents, up to
    /// `max_bytes`; returns them with their total fee.
    pub fn select(&self, max_bytes: usize) -> (Vec<Tx>, u64) {
        let mut v: Vec<(&Hash, &Entry)> = self.txs.iter().collect();
        v.sort_by(|(_, a), (_, b)| {
            (b.fee as u128 * a.size as u128).cmp(&(a.fee as u128 * b.size as u128)).then(a.seq.cmp(&b.seq))
        });
        let (mut chosen, mut set, mut used, mut fees) = (Vec::new(), HashSet::new(), 0usize, 0u64);
        loop {
            let mut progress = false;
            for (id, e) in &v {
                if set.contains(*id) || used + e.size > max_bytes || !e.parents.iter().all(|p| set.contains(p)) {
                    continue;
                }
                set.insert(**id);
                used += e.size;
                fees += e.fee;
                chosen.push(e.tx.clone());
                progress = true;
            }
            if !progress {
                break;
            }
        }
        (chosen, fees)
    }

    /// Pooled outputs paying `owner` and not spent in the pool: `(outpoint, output)`.
    pub fn pending_outputs(&self, owner: &Hash) -> Vec<(OutPoint, Output)> {
        let mut v = Vec::new();
        for (txid, e) in &self.txs {
            for (k, o) in e.tx.outputs().iter().enumerate() {
                let op = OutPoint { txid: *txid, vout: k as u32 };
                if o.pkh == *owner && !self.spends.contains_key(&op) {
                    v.push((op, *o));
                }
            }
        }
        v.sort_by_key(|(op, _)| *op);
        v
    }

    /// Whether a pooled transaction spends `op`.
    pub fn is_spent(&self, op: &OutPoint) -> bool {
        self.spends.contains_key(op)
    }

    /// Pooled transactions that pay or spend from `owner` (the latter needs the UTXO set or the pool to
    /// resolve inputs): `(txid, received, sent, fee)`.
    pub fn activity(&self, chain: &Chain, owner: &Hash) -> Vec<(Hash, u64, u64, u64)> {
        let mut v = Vec::new();
        for (txid, e) in &self.txs {
            let received: u64 = e.tx.outputs().iter().filter(|o| o.pkh == *owner).map(|o| o.value).sum();
            let sent: u64 = inputs(&e.tx)
                .iter()
                .filter_map(|i| self.coin(chain, &i.prev).ok())
                .filter(|(o, _)| o.pkh == *owner)
                .map(|(o, _)| o.value)
                .sum();
            if received > 0 || sent > 0 {
                v.push((*txid, received, sent, e.fee));
            }
        }
        v.sort_by_key(|(id, ..)| self.txs[id].seq);
        v
    }
}
