//! Pool of transfers valid on the current tip. Inputs may spend the UTXO set or outputs of other pooled
//! transactions (chains of unconfirmed transactions, e.g. spending change at once); no two pooled
//! transactions spend the same output; blocks take parents before children.
//!
//! Spam bounds: a fee of at least `MIN_FEE_RATE` atoms per byte; when the pool is full, a transaction
//! paying a higher rate pushes out the lowest-rate ones (with what spends them, and judged with them, so
//! a well-paying child protects its parent); transactions waiting longer than `MAX_AGE` are dropped.
//!
//! Fee bumping: blocks take transactions by the rate of the package they complete (a transaction with
//! its unconfirmed ancestors), so a child paying well pulls a cheap parent in (child pays for parent).
//! A transaction that spends what a pooled one spends replaces it (and its descendants) when it pays
//! more in total, by at least its own size at the minimum rate, and a higher rate than each one it
//! conflicts with directly (replace by fee).
//!
//! Package relay: a transaction may come with unconfirmed parents that pay less than the minimum on their
//! own (`add_package`), when each, with what spends it, pays the minimum. A parent nothing pays for any
//! more (its child replaced, evicted or dropped) leaves the pool.

use requant_consensus::chain::Chain;
use requant_consensus::params::MAX_AMOUNT;
use requant_consensus::tx::{Hash, OutPoint, Output, Tx};
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
/// Most pooled transactions (with descendants) one replacement may evict.
pub const MAX_REPLACED: usize = 100;

/// Most transactions in a package (a child with its unconfirmed parents, see `Mempool::add_package`).
pub const MAX_PACKAGE: usize = 25;
/// Most bytes in a package.
pub const MAX_PACKAGE_BYTES: usize = 200_000;

/// What `Mempool::check` found about a transfer.
struct Checked {
    txid: Hash,
    size: usize,
    fee: u64,
    parents: Vec<Hash>,
    conflicts: Vec<Hash>,
}

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

    /// Pooled transactions in arrival order (parents before children), for saving the pool.
    pub fn ordered(&self) -> Vec<&Tx> {
        let mut v: Vec<&Entry> = self.txs.values().collect();
        v.sort_unstable_by_key(|e| e.seq);
        v.into_iter().map(|e| &e.tx).collect()
    }

    /// Changes whenever a transaction is added or removed (to save only when needed).
    pub fn version(&self) -> (u64, usize) {
        (self.seq, self.txs.len())
    }

    /// The fee rate (atoms per byte) that puts a new transaction within the first `bytes` of the pool in
    /// selection order (highest rate first): one above the rate at that point, or the minimum when the pool
    /// holds less.
    pub fn rate_for(&self, bytes: usize) -> u64 {
        let mut v: Vec<&Entry> = self.txs.values().collect();
        v.sort_by(|a, b| (b.fee as u128 * a.size as u128).cmp(&(a.fee as u128 * b.size as u128)));
        let mut used = 0usize;
        for e in v {
            used += e.size;
            if used > bytes {
                return (e.fee / e.size.max(1) as u64 + 1).max(MIN_FEE_RATE);
            }
        }
        MIN_FEE_RATE
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Pooled transactions, newest first: (txid, fee, size in bytes).
    pub fn list(&self) -> Vec<(Hash, u64, usize)> {
        let mut v: Vec<_> = self.txs.iter().map(|(id, e)| (e.seq, *id, e.fee, e.size)).collect();
        v.sort_unstable_by_key(|x| std::cmp::Reverse(x.0));
        v.into_iter().map(|(_, id, fee, size)| (id, fee, size)).collect()
    }

    /// Whether an input's time locks allow it in the next block on the chain's tip.
    fn unlocked_next(chain: &Chain, i: &requant_consensus::tx::Input) -> bool {
        let next = chain.height() + 1;
        if i.after_blocks == 0 {
            return next >= i.after_height;
        }
        chain.coin(&i.prev).is_some_and(|c| i.unlocked_at(next, c.height))
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

    /// Everything about a transfer that needs no signature check and changes nothing: its inputs exist (in
    /// the UTXO set, the pool or `package`), match their keys and are unlocked for the next block.
    fn check(&self, tx: &Tx, chain: &Chain, package: &HashMap<Hash, &Tx>) -> Result<Checked, Error> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err(Error::Duplicate);
        }
        let size = tx.encode().len();
        if size > MAX_TX_BYTES {
            return Err(Error::Invalid("transaction too large for the pool"));
        }
        tx.check_shape()?;
        let Tx::Transfer { inputs, outputs } = tx else { return Err(Error::Invalid("coinbase outside a block")) };
        requant_consensus::chain::check_activation(&chain.net, tx, chain.height() + 1)?;
        let mut total_in: u64 = 0;
        let mut parents = Vec::new();
        // pooled transactions spending the same outputs: replaced if this one pays enough (see `add`)
        let mut conflicts: Vec<Hash> = Vec::new();
        for i in inputs {
            if let Some(other) = self.spends.get(&i.prev) {
                if !conflicts.contains(other) {
                    conflicts.push(*other);
                }
            }
            let (out, parent) = match package.get(&i.prev.txid) {
                Some(p) => (
                    *p.outputs().get(i.prev.vout as usize).ok_or(Error::Invalid("missing or spent input"))?,
                    Some(i.prev.txid),
                ),
                None => self.coin(chain, &i.prev)?,
            };
            if i.owner()? != out.pkh {
                return Err(Error::Invalid("input key does not match the output"));
            }
            // only what the next block could contain: time locks passed (a relative lock counts from a
            // confirmed coin, so it cannot be met while the coin is still pooled)
            if !Self::unlocked_next(chain, i) {
                return Err(Error::Invalid("input time lock not yet passed"));
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
        Ok(Checked { txid, size, fee, parents, conflicts })
    }

    /// Admit a transfer; returns its txid.
    pub fn add(&mut self, tx: Tx, chain: &Chain) -> Result<Hash, Error> {
        // cheap checks and input lookups first; the signatures (the expensive part) last
        let Checked { txid, size, fee, parents, conflicts } = self.check(&tx, chain, &HashMap::new())?;
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
        let replaced = self.replacement(&conflicts, &anc, fee, size)?;
        tx.check_signatures(&chain.net.chain_id)?;
        for id in &replaced {
            self.remove(id);
        }
        self.make_room(size, fee, &anc)?;
        self.insert(txid, tx, fee, size, parents);
        self.trim_unpaid();
        Ok(txid)
    }

    /// Admit a package: a transaction with unconfirmed parents that may pay less than the minimum rate on
    /// their own (package relay, so a child can pay for a pre-signed parent). The package is listed parents
    /// first, and each transaction but the last is spent by a later one. Each transaction, with what spends
    /// it in the package, pays at least the minimum rate. Members already pooled are skipped; a package
    /// does not replace pooled transactions. Returns the txids admitted.
    pub fn add_package(&mut self, txs: Vec<Tx>, chain: &Chain) -> Result<Vec<Hash>, Error> {
        if txs.len() < 2 || txs.len() > MAX_PACKAGE {
            return Err(Error::Invalid("a package has 2 to 25 transactions"));
        }
        let ids: Vec<Hash> = txs.iter().map(|t| t.txid()).collect();
        if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
            return Err(Error::Invalid("a transaction twice in the package"));
        }
        if txs.iter().map(|t| t.encode().len()).sum::<usize>() > MAX_PACKAGE_BYTES {
            return Err(Error::Invalid("package too large"));
        }
        // spent[k]: the later members spending member k's outputs
        let spent: Vec<Vec<usize>> = (0..txs.len())
            .map(|k| (k + 1..txs.len()).filter(|&j| inputs(&txs[j]).iter().any(|i| i.prev.txid == ids[k])).collect())
            .collect();
        if spent[..txs.len() - 1].iter().any(|s| s.is_empty()) {
            return Err(Error::Invalid("not a transaction with its parents"));
        }
        let mut known: HashMap<Hash, &Tx> = HashMap::new();
        let mut checked: Vec<Option<Checked>> = Vec::new();
        let mut outpoints = HashSet::new();
        for (k, tx) in txs.iter().enumerate() {
            if self.txs.contains_key(&ids[k]) {
                checked.push(None);
                continue;
            }
            let c = self.check(tx, chain, &known)?;
            if !c.conflicts.is_empty() {
                return Err(Error::Invalid("package spends what a pooled transaction spends"));
            }
            if !inputs(tx).iter().all(|i| outpoints.insert(i.prev)) {
                return Err(Error::Invalid("package spends an output twice"));
            }
            known.insert(ids[k], tx);
            checked.push(Some(c));
        }
        if known.is_empty() {
            return Err(Error::Duplicate);
        }
        // each new member with its new descendants in the package pays the minimum rate (so the last one on
        // its own does)
        let paid = |k: usize| -> (u64, usize) {
            let mut seen = HashSet::from([k]);
            let mut stack = vec![k];
            while let Some(cur) = stack.pop() {
                for &j in &spent[cur] {
                    if seen.insert(j) {
                        stack.push(j);
                    }
                }
            }
            seen.iter().filter_map(|&j| checked[j].as_ref()).fold((0, 0), |(f, s), c| (f + c.fee, s + c.size))
        };
        for (k, c) in checked.iter().enumerate() {
            if c.is_some() {
                let (fee, size) = paid(k);
                if fee < size as u64 * MIN_FEE_RATE {
                    return Err(Error::Invalid("package fee below the minimum (1 atom per byte)"));
                }
            }
        }
        // pooled ancestors of the whole package
        let mut anc = HashSet::new();
        for c in checked.iter().flatten() {
            for p in c.parents.iter().filter(|p| !known.contains_key(*p)) {
                anc.insert(*p);
                self.ancestors(p, &mut anc);
            }
        }
        if anc.len() + known.len() > MAX_ANCESTORS + 1 {
            return Err(Error::Invalid("too many unconfirmed ancestors"));
        }
        for (k, tx) in txs.iter().enumerate() {
            if checked[k].is_some() {
                tx.check_signatures(&chain.net.chain_id)?;
            }
        }
        let (fee, size) = checked.iter().flatten().fold((0, 0), |(f, s), c| (f + c.fee, s + c.size));
        self.make_room(size, fee, &anc)?;
        let mut added = Vec::new();
        for (tx, c) in txs.into_iter().zip(checked) {
            if let Some(Checked { txid, size, fee, parents, .. }) = c {
                self.insert(txid, tx, fee, size, parents);
                added.push(txid);
            }
        }
        self.trim_unpaid();
        Ok(added)
    }

    fn insert(&mut self, txid: Hash, tx: Tx, fee: u64, size: usize, parents: Vec<Hash>) {
        for i in inputs(&tx) {
            self.spends.insert(i.prev, txid);
        }
        self.bytes += size;
        self.seq += 1;
        self.txs.insert(txid, Entry { tx, fee, size, parents, seq: self.seq, time: crate::node::now() });
    }

    /// Drop transactions paying below the minimum rate that nothing pooled pays for any more (a package
    /// parent whose child was replaced, evicted or dropped), with what spends them.
    fn trim_unpaid(&mut self) {
        loop {
            let low: Vec<Hash> =
                self.txs.iter().filter(|(_, e)| e.fee < e.size as u64 * MIN_FEE_RATE).map(|(id, _)| *id).collect();
            if low.is_empty() {
                return;
            }
            let children = self.children();
            let mut memo = HashMap::new();
            let unpaid: Vec<Hash> = low
                .into_iter()
                .filter(|id| {
                    let (fee, size) = self.with_descendants(id, &children, &mut memo);
                    fee < size as u64 * MIN_FEE_RATE
                })
                .collect();
            if unpaid.is_empty() {
                return;
            }
            for id in unpaid {
                for d in self.descendants(&id) {
                    self.remove(&d);
                }
            }
        }
    }

    /// What admitting a transaction paying `fee` for `size` bytes would evict: the pooled transactions it
    /// conflicts with and their descendants, if it may replace them (see the module documentation).
    fn replacement(
        &self,
        conflicts: &[Hash],
        ancestors: &HashSet<Hash>,
        fee: u64,
        size: usize,
    ) -> Result<Vec<Hash>, Error> {
        if conflicts.is_empty() {
            return Ok(Vec::new());
        }
        let mut replaced: Vec<Hash> = Vec::new();
        for c in conflicts {
            for d in self.descendants(c) {
                if !replaced.contains(&d) {
                    replaced.push(d);
                }
            }
        }
        if replaced.len() > MAX_REPLACED {
            return Err(Error::Invalid("replacement would evict too many transactions"));
        }
        // it cannot depend on what it replaces
        if replaced.iter().any(|r| ancestors.contains(r)) {
            return Err(Error::Invalid("replacement spends a transaction it replaces"));
        }
        let old: u64 = replaced.iter().map(|r| self.txs[r].fee).sum();
        if fee < old.saturating_add(size as u64 * MIN_FEE_RATE) {
            return Err(Error::Invalid("replacement must pay more than what it replaces, plus its own size"));
        }
        if conflicts.iter().any(|c| !lower_rate((self.txs[c].fee, self.txs[c].size), (fee, size))) {
            return Err(Error::Invalid("replacement must pay a higher fee rate than what it replaces"));
        }
        Ok(replaced)
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
            // a transaction is judged by the better of its own rate and that of it with its descendants,
            // so a well-paying child keeps its parent
            let children = self.children();
            let mut memo: HashMap<Hash, (u64, usize)> = HashMap::new();
            let scores: Vec<(Hash, (u64, usize), u64)> = self
                .txs
                .iter()
                .filter(|(id, _)| !ancestors.contains(*id))
                .map(|(id, e)| {
                    let own = (e.fee, e.size);
                    let with = self.with_descendants(id, &children, &mut memo);
                    (*id, if lower_rate(own, with) { with } else { own }, e.seq)
                })
                .collect();
            let victim = scores
                .into_iter()
                .min_by(|a, b| {
                    if lower_rate(a.1, b.1) {
                        std::cmp::Ordering::Less
                    } else if lower_rate(b.1, a.1) {
                        std::cmp::Ordering::Greater
                    } else {
                        b.2.cmp(&a.2) // equal rate: the newest goes first
                    }
                })
                .map(|(id, score, _)| (id, score.0, score.1));
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

    /// Pooled children of every pooled transaction.
    fn children(&self) -> HashMap<Hash, Vec<Hash>> {
        let mut m: HashMap<Hash, Vec<Hash>> = HashMap::new();
        for (id, e) in &self.txs {
            for p in &e.parents {
                m.entry(*p).or_default().push(*id);
            }
        }
        m
    }

    /// Fee and size of `id` with all its pooled descendants (each counted once).
    fn with_descendants(
        &self,
        id: &Hash,
        children: &HashMap<Hash, Vec<Hash>>,
        memo: &mut HashMap<Hash, (u64, usize)>,
    ) -> (u64, usize) {
        if let Some(v) = memo.get(id) {
            return *v;
        }
        let mut seen = HashSet::new();
        let mut stack = vec![*id];
        let (mut fee, mut size) = (0u64, 0usize);
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if let Some(e) = self.txs.get(&cur) {
                fee += e.fee;
                size += e.size;
            }
            stack.extend(children.get(&cur).into_iter().flatten().copied());
        }
        memo.insert(*id, (fee, size));
        (fee, size)
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
                .filter(|(_, e)| {
                    // spent or gone, or (after a reorganisation to a lower tip) locked again
                    inputs(&e.tx).iter().any(|i| self.coin(chain, &i.prev).is_err() || !Self::unlocked_next(chain, i))
                        || requant_consensus::chain::check_activation(&chain.net, &e.tx, chain.height() + 1).is_err()
                })
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
        self.trim_unpaid();
    }

    /// Transactions for a block, up to `max_bytes`, best package first: each transaction is ranked by the
    /// rate of itself with its ancestors not yet taken, and taken together with them, parents first (so a
    /// child paying well pulls a cheap parent in). Returns them with their total fee.
    pub fn select(&self, max_bytes: usize) -> (Vec<Tx>, u64) {
        use std::collections::BinaryHeap;
        // ranked by (fee, size) of the package, compared without division; ties: earlier arrival first
        #[derive(PartialEq, Eq)]
        struct Rank(u64, usize, u64, Hash, u64);
        impl Ord for Rank {
            fn cmp(&self, o: &Self) -> std::cmp::Ordering {
                (self.0 as u128 * o.1 as u128)
                    .cmp(&(o.0 as u128 * self.1 as u128))
                    .then(o.2.cmp(&self.2))
                    .then(self.4.cmp(&o.4))
            }
        }
        impl PartialOrd for Rank {
            fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(o))
            }
        }
        let children = self.children();
        let mut taken: HashSet<Hash> = HashSet::new();
        let mut skipped: HashSet<Hash> = HashSet::new();
        // the package of `id`: it with its ancestors not yet taken, parents first
        let package = |id: &Hash, taken: &HashSet<Hash>| -> Vec<Hash> {
            let mut anc = HashSet::new();
            self.ancestors(id, &mut anc);
            let mut v: Vec<Hash> = anc.into_iter().filter(|a| !taken.contains(a)).collect();
            v.push(*id);
            // parents before children: a transaction's depth is at least one more than any parent's
            let mut depth: HashMap<Hash, usize> = HashMap::new();
            fn depth_of(m: &Mempool, id: &Hash, memo: &mut HashMap<Hash, usize>) -> usize {
                if let Some(d) = memo.get(id) {
                    return *d;
                }
                let d =
                    m.txs.get(id).map_or(0, |e| e.parents.iter().map(|p| depth_of(m, p, memo) + 1).max().unwrap_or(0));
                memo.insert(*id, d);
                d
            }
            v.sort_by_key(|t| (depth_of(self, t, &mut depth), self.txs[t].seq));
            v
        };
        let score = |pkg: &[Hash]| -> (u64, usize) {
            pkg.iter().fold((0u64, 0usize), |(f, s), t| (f + self.txs[t].fee, s + self.txs[t].size))
        };
        let mut version: HashMap<Hash, u64> = HashMap::new();
        let mut heap = BinaryHeap::new();
        for (id, e) in &self.txs {
            let (f, s) = score(&package(id, &taken));
            heap.push(Rank(f, s, e.seq, *id, 0));
        }
        let (mut chosen, mut used, mut fees) = (Vec::new(), 0usize, 0u64);
        while let Some(Rank(_, size, _, id, ver)) = heap.pop() {
            if taken.contains(&id) || skipped.contains(&id) || version.get(&id).copied().unwrap_or(0) != ver {
                continue;
            }
            if used + size > max_bytes {
                skipped.insert(id);
                continue;
            }
            let pkg = package(&id, &taken);
            for t in &pkg {
                let e = &self.txs[t];
                taken.insert(*t);
                used += e.size;
                fees += e.fee;
                chosen.push(e.tx.clone());
            }
            // their descendants now have fewer ancestors left: rank them again
            let mut again: Vec<Hash> = Vec::new();
            let mut stack: Vec<Hash> = pkg.clone();
            while let Some(cur) = stack.pop() {
                for c in children.get(&cur).into_iter().flatten() {
                    if !taken.contains(c) && !again.contains(c) {
                        again.push(*c);
                        stack.push(*c);
                    }
                }
            }
            for c in again {
                let v = version.entry(c).or_insert(0);
                *v += 1;
                let (f, s) = score(&package(&c, &taken));
                heap.push(Rank(f, s, self.txs[&c].seq, c, *v));
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
