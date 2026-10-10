//! In-memory chain state (CHAIN.md §5–§8): block index, best chain by cumulative work, UTXO set with undo
//! data, reorganisation, epoch weights, and a reference miner for small networks.

use crate::block::{genesis, Block, Claim, Header, BLOCK_VERSION};
use crate::codec::{Reader, Writer};
use crate::params::{tagged, Network, MAX_AMOUNT, MAX_FUTURE_SECS, MTP_WINDOW};
use crate::pow::{dev_fund_share, next_target, reward};
use crate::tx::{Hash, OutPoint, Output, Tx};
use crate::u256::U256;
use crate::Error;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Coin {
    pub output: Output,
    pub height: u64,
    pub coinbase: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    /// Header, claim and standalone checks passed; transactions not yet connected.
    Checked,
    /// Connected at least once without error.
    Valid,
    /// Failed to connect; it and its descendants are never selected.
    Invalid,
}

/// Where block bodies dropped from memory are read back from (the node's block file). Bodies of best-chain
/// blocks deeper than the keep window are dropped once a source is set: the index (headers, work, status)
/// stays in memory, the transactions do not.
pub trait BodySource: Send + Sync {
    fn load(&self, id: &Hash) -> Option<Block>;
}

struct Entry {
    header: Header,
    /// The block while it is held in memory (recent and side-chain blocks); otherwise read from the source.
    block: Option<Arc<Block>>,
    height: u64,
    time: u64,
    /// Cumulative work up to and including this block.
    work: U256,
    /// Atoms issued by this block and all earlier ones (`generated(height + 1)`).
    issued: u64,
    status: Status,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Accepted {
    /// The block extends the best chain.
    NewTip,
    /// Stored on a side chain with less work.
    SideChain,
    /// The best chain switched to the block's branch after disconnecting `disconnected` blocks.
    Reorg { disconnected: usize },
}

pub struct Chain {
    pub net: Network,
    threads: usize,
    entries: HashMap<Hash, Entry>,
    /// Block ids of the best chain by height.
    active: Vec<Hash>,
    utxo: HashMap<OutPoint, Coin>,
    undo: HashMap<Hash, Vec<(OutPoint, Coin)>>,
    epochs: Vec<(Hash, Arc<tnet::Epoch>)>,
    /// Reason the last block marked invalid failed to connect.
    last_failure: &'static str,
    /// Blocks taken off the best chain by the last reorganisation (for returning their transactions to a pool).
    disconnected: Vec<Arc<Block>>,
    /// Node policy: refuse blocks forking more than this many blocks below the tip (no limit by default).
    max_reorg: u64,
    /// The reorganisation limit applies only once the tip has this much cumulative work.
    min_chain_work: U256,
    /// Where dropped bodies are read back from, how many recent best-chain blocks keep theirs, and the
    /// height up to which best-chain bodies have been dropped.
    bodies: Option<Arc<dyn BodySource>>,
    keep_bodies: u64,
    dropped_to: u64,
}

/// Rejection reason for a fork below the reorganisation limit: node policy, so peers are not punished for it.
pub const DEEP_FORK: &str = "fork deeper than the reorg limit";

/// Current and next epoch (512 MiB each for TNet v1).
const EPOCH_CACHE: usize = 2;

fn write_coin(w: &mut Writer, op: &OutPoint, c: &Coin) {
    w.raw(&op.txid);
    w.u32(op.vout);
    w.u64(c.output.value);
    w.raw(&c.output.pkh);
    w.u64(c.height);
    w.u8(c.coinbase as u8);
}

fn read_coin(r: &mut Reader) -> Result<(OutPoint, Coin), Error> {
    let op = OutPoint { txid: r.arr32()?, vout: r.u32()? };
    let output = Output { value: r.u64()?, pkh: r.arr32()? };
    Ok((op, Coin { output, height: r.u64()?, coinbase: r.u8()? != 0 }))
}

/// Kind-2 transfers only from the network's activation height (CHAIN.md §4.1).
pub fn check_activation(net: &Network, tx: &Tx, height: u64) -> Result<(), Error> {
    if tx.is_v2() && height < net.conditions_height {
        return Err(Error::Invalid("conditions and time locks are not active at this height"));
    }
    if tx.uses_contracts() && height < net.contracts_height {
        return Err(Error::Invalid("revocable outputs and anyone-can-pay are not active at this height"));
    }
    Ok(())
}

/// An input spending `coin` in a block at `height`: it satisfies the output (key or condition), the
/// coinbase is mature, and its time locks have passed. Signatures are checked separately.
pub fn check_input(net: &Network, inp: &crate::tx::Input, coin: &Coin, height: u64) -> Result<(), Error> {
    if inp.owner()? != coin.output.pkh {
        return Err(Error::Invalid("input key does not match the output"));
    }
    if coin.coinbase && height - coin.height < net.maturity {
        return Err(Error::Invalid("immature coinbase spend"));
    }
    if !inp.unlocked_at(height, coin.height) {
        return Err(Error::Invalid("input time lock not yet passed"));
    }
    Ok(())
}

impl Chain {
    /// The chain's state for a quick start: every known block's index entry (id, header, height, time, work,
    /// issued, status), the best chain, the UTXO set and the undo data. Bodies are not included (the node
    /// reads them from its block file). Restored by [`Chain::restore`].
    pub fn snapshot(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.raw(&self.net.chain_id);
        w.u64(self.entries.len() as u64);
        for (id, e) in &self.entries {
            w.raw(id);
            w.raw(&e.header.encode());
            w.u64(e.time);
            w.raw(&e.work.to_be_bytes());
            w.u64(e.issued);
            w.u8(match e.status {
                Status::Checked => 0,
                Status::Valid => 1,
                Status::Invalid => 2,
            });
        }
        w.u64(self.active.len() as u64);
        for id in &self.active {
            w.raw(id);
        }
        w.u64(self.utxo.len() as u64);
        for (op, c) in &self.utxo {
            write_coin(&mut w, op, c);
        }
        w.u64(self.undo.len() as u64);
        for (id, list) in &self.undo {
            w.raw(id);
            w.u64(list.len() as u64);
            for (op, c) in list {
                write_coin(&mut w, op, c);
            }
        }
        w.0
    }

    /// A chain from [`Chain::snapshot`] bytes: no body in memory but genesis (set a body source next).
    pub fn restore(net: Network, threads: usize, bytes: &[u8]) -> Result<Chain, Error> {
        let mut c = Chain::new(net, threads);
        let mut r = Reader::new(bytes);
        if r.arr32()? != c.net.chain_id {
            return Err(Error::Invalid("snapshot of another network"));
        }
        let genesis_id = c.tip();
        let n = r.u64()?;
        for _ in 0..n {
            let id = r.arr32()?;
            let header = Header::decode(&mut r)?;
            let time = r.u64()?;
            let work = U256::from_be_bytes(&r.arr32()?);
            let issued = r.u64()?;
            let status = match r.u8()? {
                0 => Status::Checked,
                1 => Status::Valid,
                2 => Status::Invalid,
                _ => return Err(Error::Decode("snapshot status")),
            };
            if id == genesis_id {
                continue;
            }
            c.entries.insert(id, Entry { header, block: None, height: header.height, time, work, issued, status });
        }
        let n = r.u64()?;
        let mut active = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let id = r.arr32()?;
            if !c.entries.contains_key(&id) {
                return Err(Error::Invalid("snapshot best chain refers to an unknown block"));
            }
            active.push(id);
        }
        if active.first() != Some(&genesis_id) {
            return Err(Error::Invalid("snapshot best chain does not start at genesis"));
        }
        c.active = active;
        for _ in 0..r.u64()? {
            let (op, coin) = read_coin(&mut r)?;
            c.utxo.insert(op, coin);
        }
        for _ in 0..r.u64()? {
            let id = r.arr32()?;
            let mut list = Vec::new();
            for _ in 0..r.u64()? {
                list.push(read_coin(&mut r)?);
            }
            c.undo.insert(id, list);
        }
        r.finish()?;
        c.dropped_to = c.height();
        Ok(c)
    }

    /// Blocks no other known block builds on, and the best tip: `(id, height, status, branch length)`, the
    /// branch length being how many of its blocks are off the best chain. Status: "active" (the best
    /// tip), "valid-fork", "unchecked" (stored, never connected), "invalid". Highest first.
    pub fn tips(&self) -> Vec<(Hash, u64, &'static str, u64)> {
        let parents: std::collections::HashSet<Hash> = self.entries.values().map(|e| e.header.prev).collect();
        let tip = self.tip();
        let mut v = Vec::new();
        for (id, e) in &self.entries {
            if parents.contains(id) && *id != tip {
                continue;
            }
            let (mut branch, mut cur) = (0u64, *id);
            while let Some(c) = self.entries.get(&cur) {
                if self.active_id(c.height) == Some(cur) {
                    break;
                }
                branch += 1;
                cur = c.header.prev;
            }
            let status = if *id == tip {
                "active"
            } else {
                match e.status {
                    Status::Valid => "valid-fork",
                    Status::Checked => "unchecked",
                    Status::Invalid => "invalid",
                }
            };
            v.push((*id, e.height, status, branch));
        }
        v.sort_by_key(|t| std::cmp::Reverse(t.1));
        v
    }

    /// Ids and headers of the best chain from height 1 on (for rebuilding the header chain at start).
    pub fn best_headers(&self) -> Vec<(Hash, Header)> {
        self.active[1..].iter().map(|id| (*id, self.entries[id].header)).collect()
    }

    pub fn new(net: Network, threads: usize) -> Chain {
        let g = genesis(&net);
        let id = g.id(&net);
        let entry = Entry {
            height: 0,
            time: g.header.time,
            work: U256::work(&g.header.target),
            issued: 0,
            status: Status::Valid,
            header: g.header,
            block: Some(Arc::new(g)),
        };
        let min_chain_work = net.min_chain_work;
        let mut c = Chain {
            net,
            threads: threads.max(1),
            entries: HashMap::new(),
            active: vec![id],
            utxo: HashMap::new(),
            undo: HashMap::new(),
            epochs: Vec::new(),
            last_failure: "",
            disconnected: Vec::new(),
            max_reorg: u64::MAX,
            min_chain_work,
            bodies: None,
            keep_bodies: u64::MAX,
            dropped_to: 0,
        };
        c.entries.insert(id, entry);
        c.undo.insert(id, Vec::new());
        c
    }

    /// Threads for verifying work claims (lowered while the machine is busy).
    pub fn set_threads(&mut self, threads: usize) {
        self.threads = threads.max(1);
    }

    pub fn tip(&self) -> Hash {
        *self.active.last().unwrap()
    }

    pub fn height(&self) -> u64 {
        self.active.len() as u64 - 1
    }

    pub fn tip_work(&self) -> U256 {
        self.entries[&self.tip()].work
    }

    /// A stored block: from memory, or read back from the body source.
    pub fn block(&self, id: &Hash) -> Option<Arc<Block>> {
        let e = self.entries.get(id)?;
        match &e.block {
            Some(b) => Some(b.clone()),
            None => self.bodies.as_ref()?.load(id).map(Arc::new),
        }
    }

    /// A known block's header (always in memory).
    pub fn header(&self, id: &Hash) -> Option<Header> {
        self.entries.get(id).map(|e| e.header)
    }

    /// The body of a block the chain knows, which must be readable (memory or source).
    fn body(&self, id: &Hash) -> Arc<Block> {
        self.block(id).expect("the body of a known block is in memory or in the block file")
    }

    /// Keep only the last `keep` best-chain bodies in memory, reading older ones back from `source`.
    pub fn set_body_source(&mut self, source: Arc<dyn BodySource>, keep: u64) {
        self.bodies = Some(source);
        self.keep_bodies = keep.max(1);
        self.drop_bodies();
    }

    /// Bodies held in memory (for statistics).
    pub fn bodies_in_memory(&self) -> usize {
        self.entries.values().filter(|e| e.block.is_some()).count()
    }

    /// Drop the bodies of best-chain blocks deeper than the keep window (genesis stays).
    fn drop_bodies(&mut self) {
        if self.bodies.is_none() {
            return;
        }
        let limit = self.height().saturating_sub(self.keep_bodies);
        while self.dropped_to < limit {
            self.dropped_to += 1;
            let id = self.active[self.dropped_to as usize];
            if let Some(e) = self.entries.get_mut(&id) {
                e.block = None;
            }
        }
    }

    pub fn active_id(&self, height: u64) -> Option<Hash> {
        self.active.get(height as usize).copied()
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.entries.contains_key(id)
    }

    pub fn coin(&self, op: &OutPoint) -> Option<Coin> {
        self.utxo.get(op).copied()
    }

    pub fn utxo_len(&self) -> usize {
        self.utxo.len()
    }

    /// The supply audit (linear scan): the UTXO set's total value and count, and a hash of the whole set in
    /// outpoint order (`H("requant/utxoset", ...)` chained over chunks of 1024 entries of `txid || LE32 vout ||
    /// LE64 value || pkh || LE64 height || coinbase`), so two nodes compare their state with one string.
    pub fn utxo_audit(&self) -> (u64, usize, Hash) {
        let mut set: Vec<(&OutPoint, &Coin)> = self.utxo.iter().collect();
        set.sort_unstable_by_key(|(op, _)| **op);
        let total = set.iter().map(|(_, c)| c.output.value).sum();
        let mut h = tagged("requant/utxoset", &[&(set.len() as u64).to_le_bytes()]);
        for chunk in set.chunks(1024) {
            let mut buf = Vec::with_capacity(chunk.len() * 89);
            for (op, c) in chunk {
                buf.extend_from_slice(&op.txid);
                buf.extend_from_slice(&op.vout.to_le_bytes());
                buf.extend_from_slice(&c.output.value.to_le_bytes());
                buf.extend_from_slice(&c.output.pkh);
                buf.extend_from_slice(&c.height.to_le_bytes());
                buf.push(c.coinbase as u8);
            }
            h = tagged("requant/utxoset", &[&h, &buf]);
        }
        (total, set.len(), h)
    }

    /// Addresses (key hashes) holding at least one unspent output (linear scan).
    pub fn holder_count(&self) -> usize {
        self.utxo.values().map(|c| c.output.pkh).collect::<std::collections::HashSet<_>>().len()
    }

    /// Unspent outputs paying to `pkh` (linear scan; for wallets and tests).
    pub fn coins_of(&self, owner: &Hash) -> Vec<(OutPoint, Coin)> {
        let mut v: Vec<_> = self.utxo.iter().filter(|(_, c)| c.output.pkh == *owner).map(|(o, c)| (*o, *c)).collect();
        v.sort_by_key(|(o, _)| *o);
        v
    }

    /// Block ids from the tip back to genesis at exponentially growing distances (sync locator).
    pub fn locator(&self) -> Vec<Hash> {
        let mut v = Vec::new();
        let mut h = self.height() as i64;
        let mut step = 1i64;
        while h > 0 {
            v.push(self.active[h as usize]);
            if v.len() >= 10 {
                step *= 2;
            }
            h -= step;
        }
        v.push(self.active[0]);
        v
    }

    /// Ids of active blocks after the first locator entry found on the active chain (at most `max`).
    pub fn blocks_after(&self, locator: &[Hash], max: usize) -> Vec<Hash> {
        let start = locator
            .iter()
            .find(|id| self.entries.contains_key(*id) && self.on_active(id))
            .map(|id| self.entries[id].height)
            .unwrap_or(0);
        self.active.iter().skip(start as usize + 1).take(max).copied().collect()
    }

    /// Fee of a transfer spendable in the next block on the tip (inputs unspent, keys matching, coinbase
    /// outputs mature); signatures and shape are checked by [`Tx::check_standalone`].
    pub fn check_spend(&self, tx: &Tx) -> Result<u64, Error> {
        let Tx::Transfer { inputs, outputs } = tx else { return Err(Error::Invalid("coinbase outside a block")) };
        let next = self.height() + 1;
        check_activation(&self.net, tx, next)?;
        let mut total_in: u64 = 0;
        for inp in inputs {
            let coin = self.utxo.get(&inp.prev).ok_or(Error::Invalid("missing or spent input"))?;
            check_input(&self.net, inp, coin, next)?;
            total_in = total_in
                .checked_add(coin.output.value)
                .filter(|&t| t <= MAX_AMOUNT)
                .ok_or(Error::Invalid("input total"))?;
        }
        let total_out: u64 = outputs.iter().map(|o| o.value).sum();
        total_in.checked_sub(total_out).ok_or(Error::Invalid("outputs exceed inputs"))
    }

    /// Blocks disconnected by the last reorganisation, handed over once.
    pub fn take_disconnected(&mut self) -> Vec<Arc<Block>> {
        std::mem::take(&mut self.disconnected)
    }

    /// Height of a known block.
    pub fn height_of(&self, id: &Hash) -> Option<u64> {
        self.entries.get(id).map(|e| e.height)
    }

    /// Atoms issued up to and including the tip.
    pub fn issued(&self) -> u64 {
        self.entries[&self.tip()].issued
    }

    fn ancestor(&self, from: &Hash, height: u64) -> Hash {
        let e = &self.entries[from];
        if self.active.get(e.height as usize) == Some(from) {
            return self.active[height as usize];
        }
        let mut id = *from;
        while self.entries[&id].height > height {
            id = self.entries[&id].header.prev;
        }
        id
    }

    fn median_time_past(&self, parent: &Hash) -> u64 {
        let mut times = Vec::with_capacity(MTP_WINDOW);
        let mut id = *parent;
        loop {
            let e = &self.entries[&id];
            times.push(e.time);
            if times.len() == MTP_WINDOW || e.height == 0 {
                break;
            }
            id = e.header.prev;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Seed of the epoch containing `height`, on the branch ending at `parent` (CHAIN.md §6).
    pub fn epoch_seed(&self, parent: &Hash, height: u64) -> Hash {
        epoch_seed(&self.net, height, |h| self.ancestor(parent, h))
    }

    /// Refuse blocks whose branch leaves the best chain more than `depth` blocks below the tip. This is a
    /// node policy, not a consensus rule: it bounds the work an attacker can make the node do with a cheap
    /// fork from old, low-difficulty history, at the price of manual recovery after a longer partition.
    pub fn set_max_reorg(&mut self, depth: u64) {
        self.max_reorg = depth;
    }

    /// Height where the branch ending at `id` joins the best chain, if within `limit` steps.
    fn fork_height(&self, id: &Hash, limit: u64) -> Option<u64> {
        let mut id = *id;
        for _ in 0..=limit.min(self.height() + 1) {
            if self.on_active(&id) {
                return Some(self.entries[&id].height);
            }
            id = self.entries[&id].header.prev;
        }
        None
    }

    /// Seeds of the epoch of the next block and, once its anchor block is in the best chain, of the epoch
    /// after it, so a node can derive weights before they are needed.
    pub fn upcoming_epoch_seeds(&self) -> Vec<Hash> {
        let next = self.height() + 1;
        let tip = self.tip();
        let mut v = vec![self.epoch_seed(&tip, next)];
        let following = (next / self.net.epoch_len + 1) * self.net.epoch_len;
        if self.height() >= following - self.net.lookback {
            v.push(self.epoch_seed(&tip, following));
        }
        v
    }

    /// Drop cached weights other than `keep` (512 MiB each for TNet v1): called before deriving new
    /// weights elsewhere, so the cache and the derivation never hold more than two epochs together.
    pub fn retain_epochs(&mut self, keep: &[Hash]) {
        self.epochs.retain(|(s, _)| keep.contains(s));
    }

    pub fn has_epoch(&self, seed: &Hash) -> bool {
        self.epochs.iter().any(|(s, _)| s == seed)
    }

    /// Add weights derived elsewhere (e.g. on a background thread) to the cache.
    pub fn insert_epoch(&mut self, seed: Hash, epoch: Arc<tnet::Epoch>) {
        if self.has_epoch(&seed) {
            return;
        }
        if self.epochs.len() == EPOCH_CACHE {
            self.epochs.remove(0);
        }
        self.epochs.push((seed, epoch));
    }

    /// Epoch weights for `seed`, derived on first use and kept in a small cache.
    pub fn epoch(&mut self, seed: &Hash) -> Arc<tnet::Epoch> {
        if let Some(k) = self.epochs.iter().position(|(s, _)| s == seed) {
            let item = self.epochs.remove(k);
            self.epochs.push(item);
        } else {
            if self.epochs.len() == EPOCH_CACHE {
                self.epochs.remove(0);
            }
            self.epochs.push((*seed, Arc::new(tnet::Epoch::from_seed(seed, self.net.tnet))));
        }
        self.epochs.last().unwrap().1.clone()
    }

    /// Header rules against the parent (CHAIN.md §5 items 1–4); `now` is the local clock.
    fn check_header(&mut self, block: &Block, now: u64, verify: Verify) -> Result<(), Error> {
        let trusted = verify == Verify::Stored;
        let h = &block.header;
        let parent = self.entries.get(&h.prev).ok_or(Error::UnknownParent)?;
        if parent.status == Status::Invalid {
            return Err(Error::Invalid("invalid parent"));
        }
        // the reorg limit protects a synced node only: before its tip has `min_chain_work`, a cheap chain seen
        // first must not lock it out of the real one
        if self.max_reorg != u64::MAX && self.tip_work() >= self.min_chain_work {
            let tip = self.height();
            match self.fork_height(&h.prev, self.max_reorg) {
                Some(f) if tip - f.min(tip) <= self.max_reorg => {}
                _ => return Err(Error::Invalid(DEEP_FORK)),
            }
        }
        let parent = &self.entries[&h.prev];
        if h.height != parent.height + 1 {
            return Err(Error::Invalid("height"));
        }
        let (p_height, p_time) = (parent.height, parent.time);
        if h.time <= self.median_time_past(&h.prev) {
            return Err(Error::Invalid("time not after median time past"));
        }
        if !trusted && h.time > now + MAX_FUTURE_SECS {
            return Err(Error::Invalid("time too far in the future"));
        }
        if h.target != next_target(&self.net, p_height, p_time) {
            return Err(Error::Invalid("target"));
        }
        if verify != Verify::Full {
            return Ok(());
        }
        // the cheap part of the claim (one hash) before deriving any epoch weights
        claim_hash_ok(&self.net, h, &block.claim)?;
        let seed = self.epoch_seed(&h.prev, h.height);
        let epoch = self.epoch(&seed);
        verify_claim(&self.net, &epoch, h, &block.claim, self.threads)
    }

    /// Validate and store a block, switching the best chain if it now has the most work.
    pub fn accept(&mut self, block: Block, now: u64) -> Result<Accepted, Error> {
        self.accept_inner(block, now, Verify::Full)
    }

    /// As [`Chain::accept`] for a block whose header and work claim were already verified (headers-first
    /// sync, [`crate::headers::HeaderChain`]): the claim is not recomputed; every other rule applies.
    pub fn accept_prevalidated(&mut self, block: Block, now: u64) -> Result<Accepted, Error> {
        self.accept_inner(block, now, Verify::ClaimChecked)
    }

    /// Re-accept a block this node verified before (from its own storage): the work claim and the clock
    /// are not checked; every other rule, including all transaction checks, still applies.
    pub fn accept_trusted(&mut self, block: Block) -> Result<Accepted, Error> {
        self.accept_inner(block, 0, Verify::Stored)
    }

    fn accept_inner(&mut self, block: Block, now: u64, verify: Verify) -> Result<Accepted, Error> {
        let id = block.id(&self.net);
        if self.entries.contains_key(&id) {
            return Err(Error::Duplicate);
        }
        // cheapest first: structure, parent and header context, the claim (real work), then signatures
        block.check_structure(&self.net)?;
        self.check_header(&block, now, verify)?;
        block.txs.iter().try_for_each(|t| t.check_signatures(&self.net.chain_id))?;
        let parent = &self.entries[&block.header.prev];
        let entry = Entry {
            height: block.header.height,
            time: block.header.time,
            work: parent.work.saturating_add(&U256::work(&block.header.target)),
            issued: parent.issued.saturating_add(reward(parent.issued)),
            status: Status::Checked,
            header: block.header,
            block: Some(Arc::new(block)),
        };
        self.entries.insert(id, entry);
        let before = self.tip();
        let disconnected = self.activate_best(Some(id));
        self.drop_bodies();
        if self.entries[&id].status == Status::Invalid {
            return Err(Error::Invalid(self.last_failure));
        }
        if !self.on_active(&id) && self.has_invalid_ancestor(&id) {
            return Err(Error::Invalid("invalid ancestor"));
        }
        Ok(if self.tip() == before || !self.on_active(&id) {
            Accepted::SideChain
        } else if disconnected == 0 {
            Accepted::NewTip
        } else {
            Accepted::Reorg { disconnected }
        })
    }

    fn on_active(&self, id: &Hash) -> bool {
        let h = self.entries[id].height as usize;
        self.active.get(h) == Some(id)
    }

    fn has_invalid_ancestor(&self, id: &Hash) -> bool {
        let mut id = *id;
        loop {
            let e = &self.entries[&id];
            if e.status == Status::Invalid {
                return true;
            }
            if self.on_active(&id) || e.height == 0 {
                return false;
            }
            id = e.header.prev;
        }
    }

    /// Move to the valid chain with the most work; returns the number of blocks disconnected from the old
    /// best chain on the way.
    /// `new` is the block just stored: the tip had the most work before it arrived, so only `new` can beat it
    /// (no scan of every block, which made syncing quadratic). After a failed reorganisation every block is
    /// considered again.
    fn activate_best(&mut self, new: Option<Hash>) -> usize {
        let mut disconnected_total = 0;
        let mut fast = new;
        loop {
            let tip_work = self.tip_work();
            let cand = match fast.take() {
                Some(id) => {
                    let e = &self.entries[&id];
                    if e.work > tip_work && e.status != Status::Invalid && !self.has_invalid_ancestor(&id) {
                        id
                    } else {
                        return disconnected_total;
                    }
                }
                None => {
                    let best = self
                        .entries
                        .iter()
                        .filter(|(_, e)| e.work > tip_work && e.status != Status::Invalid)
                        .map(|(id, e)| (e.work, std::cmp::Reverse(*id)))
                        .filter(|(_, id)| !self.has_invalid_ancestor(&id.0))
                        .max();
                    // equal work: the lowest block id, as in the header chain (CHAIN.md §5)
                    let Some((_, std::cmp::Reverse(cand))) = best else { return disconnected_total };
                    cand
                }
            };
            match self.reorg_to(&cand) {
                Ok(n) => {
                    disconnected_total += n;
                    if new.is_some() {
                        return disconnected_total;
                    }
                }
                Err((bad, reason)) => {
                    self.entries.get_mut(&bad).unwrap().status = Status::Invalid;
                    self.last_failure = reason;
                }
            }
        }
    }

    /// Switch the active chain to end at `target`; on a failing block restore the previous chain and
    /// return that block's id.
    fn reorg_to(&mut self, target: &Hash) -> Result<usize, (Hash, &'static str)> {
        let mut branch = Vec::new();
        let mut id = *target;
        while !self.on_active(&id) {
            branch.push(id);
            id = self.entries[&id].header.prev;
        }
        let fork_height = self.entries[&id].height;
        let old: Vec<Hash> = self.active[fork_height as usize + 1..].to_vec();
        for b in old.iter().rev() {
            self.disconnect(b);
        }
        for (k, b) in branch.iter().rev().enumerate() {
            if let Err(e) = self.connect(b) {
                let reason = match e {
                    Error::Invalid(s) | Error::Decode(s) => s,
                    _ => "connect failed",
                };
                for done in branch.iter().rev().take(k).rev() {
                    self.disconnect(done);
                }
                for b in &old {
                    self.connect(b).expect("previously valid block reconnects");
                }
                return Err((*b, reason));
            }
        }
        self.disconnected = old.iter().map(|id| self.body(id)).collect();
        Ok(old.len())
    }

    /// Apply a block's transactions to the UTXO set (CHAIN.md §5 items 6–7) and append it to `active`.
    fn connect(&mut self, id: &Hash) -> Result<(), Error> {
        let block = self.body(id);
        let height = block.header.height;
        let parent_issued = self.entries[&block.header.prev].issued;
        let mut spent: Vec<(OutPoint, Coin)> = Vec::new();
        let mut added: Vec<OutPoint> = Vec::new();
        let result: Result<(), Error> = (|| {
            let mut fees: u64 = 0;
            for tx in &block.txs[1..] {
                let Tx::Transfer { inputs, outputs } = tx else { unreachable!("checked standalone") };
                check_activation(&self.net, tx, height)?;
                let mut total_in: u64 = 0;
                for inp in inputs {
                    let coin = self.utxo.remove(&inp.prev).ok_or(Error::Invalid("missing or spent input"))?;
                    spent.push((inp.prev, coin));
                    check_input(&self.net, inp, &coin, height)?;
                    total_in = total_in
                        .checked_add(coin.output.value)
                        .filter(|&t| t <= MAX_AMOUNT)
                        .ok_or(Error::Invalid("input total"))?;
                }
                let total_out: u64 = outputs.iter().map(|o| o.value).sum();
                if total_out > total_in {
                    return Err(Error::Invalid("outputs exceed inputs"));
                }
                fees = fees
                    .checked_add(total_in - total_out)
                    .filter(|&f| f <= MAX_AMOUNT)
                    .ok_or(Error::Invalid("fees"))?;
                self.add_outputs(tx, height, false, &mut added);
            }
            let coinbase = &block.txs[0];
            let paid: u64 = coinbase.outputs().iter().map(|o| o.value).sum();
            if height > 0 && paid > reward(parent_issued) + fees {
                return Err(Error::Invalid("coinbase pays more than reward plus fees"));
            }
            let due = dev_fund_share(&self.net, height, reward(parent_issued));
            let to_fund: u64 = coinbase.outputs().iter().filter(|o| o.pkh == self.net.dev_fund).map(|o| o.value).sum();
            if to_fund < due {
                return Err(Error::Invalid("coinbase misses the development fund share"));
            }
            self.add_outputs(coinbase, height, true, &mut added);
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.undo.insert(*id, spent);
                self.active.push(*id);
                let e = self.entries.get_mut(id).unwrap();
                e.status = Status::Valid;
                Ok(())
            }
            Err(e) => {
                // restore what was spent first, then remove what was created: an output created and spent
                // inside this block is in both lists and must end up absent
                for (op, coin) in spent {
                    self.utxo.insert(op, coin);
                }
                for op in added {
                    self.utxo.remove(&op);
                }
                Err(e)
            }
        }
    }

    fn add_outputs(&mut self, tx: &Tx, height: u64, coinbase: bool, added: &mut Vec<OutPoint>) {
        let txid = tx.txid();
        for (v, o) in tx.outputs().iter().enumerate() {
            let op = OutPoint { txid, vout: v as u32 };
            self.utxo.insert(op, Coin { output: *o, height, coinbase });
            added.push(op);
        }
    }

    /// Undo the tip block.
    fn disconnect(&mut self, id: &Hash) {
        assert_eq!(self.tip(), *id, "disconnect only the tip");
        let block = self.body(id);
        // restore spent coins first, then remove the block's outputs: an output created and spent inside the
        // block appears in both and must end up absent (the reverse order would resurrect it)
        for (op, coin) in self.undo.remove(id).unwrap_or_default() {
            self.utxo.insert(op, coin);
        }
        for tx in &block.txs {
            let txid = tx.txid();
            for v in 0..tx.outputs().len() {
                self.utxo.remove(&OutPoint { txid, vout: v as u32 });
            }
        }
        self.active.pop();
    }

    /// A block on the tip paying `reward + fees` to `payee` (less the development fund share, paid to the fund), with `txs` (unchecked), dated
    /// `max(time, median time past + 1)`, and an empty claim to be filled by a miner.
    pub fn template(&self, payee: &Hash, txs: Vec<Tx>, time: u64) -> Block {
        self.template_on(&self.tip(), payee, txs, time)
    }

    /// As [`Chain::template`] on any known `parent` (fees are computed against the tip's UTXO set).
    pub fn template_on(&self, parent_id: &Hash, payee: &Hash, txs: Vec<Tx>, time: u64) -> Block {
        let mut fees = 0u64;
        for tx in &txs {
            if let Tx::Transfer { inputs, outputs } = tx {
                let total_in: u64 = inputs.iter().filter_map(|i| self.utxo.get(&i.prev)).map(|c| c.output.value).sum();
                let total_out: u64 = outputs.iter().map(|o| o.value).sum();
                fees += total_in.saturating_sub(total_out);
            }
        }
        self.template_with_fees(parent_id, payee, txs, fees, time)
    }

    /// As [`Chain::template_on`] with the transactions' total fee given by the caller (a pool that also
    /// knows inputs created by earlier transactions of the same block).
    pub fn template_with_fees(&self, parent_id: &Hash, payee: &Hash, txs: Vec<Tx>, fees: u64, time: u64) -> Block {
        let parent = &self.entries[parent_id];
        let height = parent.height + 1;
        let r = reward(parent.issued);
        let fund = dev_fund_share(&self.net, height, r);
        let mut outputs = vec![Output { value: r - fund + fees, pkh: *payee }];
        if fund > 0 {
            outputs.push(Output { value: fund, pkh: self.net.dev_fund });
        }
        let coinbase = Tx::Coinbase { height, extra: Vec::new(), outputs };
        let mut all = vec![coinbase];
        all.extend(txs);
        let header = Header {
            version: BLOCK_VERSION,
            height,
            prev: *parent_id,
            tx_root: crate::block::tx_root(&all),
            time: time.max(self.median_time_past(parent_id) + 1),
            target: next_target(&self.net, parent.height, parent.time),
        };
        Block { header, claim: Claim::empty(self.net.tnet.w), txs: all }
    }
}

/// How much of a block's header to verify.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verify {
    /// Everything, including the work claim.
    Full,
    /// Everything but the work claim, verified earlier on the header alone.
    ClaimChecked,
    /// Neither the clock nor the claim: the node's own stored blocks.
    Stored,
}

/// Seed of the epoch containing `height` (CHAIN.md §6); `ancestor_at(h)` gives the id of the block at
/// height `h` on the branch being extended.
pub fn epoch_seed(net: &Network, height: u64, ancestor_at: impl FnOnce(u64) -> Hash) -> Hash {
    let e = height / net.epoch_len;
    if e == 0 {
        return tagged("requant/epoch0", &[&net.chain_id]);
    }
    let anchor = ancestor_at(e * net.epoch_len - net.lookback);
    tagged("requant/epoch", &[&e.to_le_bytes(), &anchor])
}

/// The part of the claim check that needs no epoch weights: indices, piece length and one ticket hash against
/// the target. Run first, so a junk claim costs one hash instead of an epoch derivation and a row.
pub fn claim_hash_ok(net: &Network, h: &Header, c: &Claim) -> Result<(), Error> {
    let p = net.tnet;
    if c.i as usize >= p.b || c.c as usize >= p.tickets_per_row() || c.piece.len() != p.w {
        return Err(Error::Invalid("claim index"));
    }
    if !tnet::meets_target(
        &tnet::ticket_hash(&c.piece, &h.digest(&net.chain_id), c.nonce, c.i, c.c),
        &h.target.to_be_bytes(),
    ) {
        return Err(Error::Invalid("claim above target"));
    }
    Ok(())
}

/// Check a header's TNet work claim against its target with the epoch's weights (SPEC.md §7).
pub fn verify_claim(net: &Network, epoch: &tnet::Epoch, h: &Header, c: &Claim, threads: usize) -> Result<(), Error> {
    epoch.check(&h.digest(&net.chain_id), c.nonce, c.i, c.c, &c.piece, &h.target.to_be_bytes(), threads).map_err(|r| {
        match r {
            tnet::Reject::BadIndex => Error::Invalid("claim index"),
            tnet::Reject::AboveTarget => Error::Invalid("claim above target"),
            tnet::Reject::WrongPiece => Error::Invalid("claim piece does not match the network"),
        }
    })
}

/// Reference CPU miner: scan nonces from `start` for a ticket meeting the header's target. Practical only
/// for small work functions (regtest).
pub fn mine(net: &Network, epoch: &tnet::Epoch, header: &Header, start: u64, nonces: u64) -> Option<Claim> {
    let p = net.tnet;
    let hd = header.digest(&net.chain_id);
    let target = header.target.to_be_bytes();
    for nonce in start..start.saturating_add(nonces) {
        let seed = tnet::x0_seed(&hd, nonce);
        for i in 0..p.b {
            let row = epoch.forward_row(&seed, i, 1);
            for c in 0..p.tickets_per_row() {
                let piece = &row[c * p.w..(c + 1) * p.w];
                if tnet::meets_target(&tnet::ticket_hash(piece, &hd, nonce, i as u32, c as u32), &target) {
                    return Some(Claim { nonce, i: i as u32, c: c as u32, piece: piece.to_vec() });
                }
            }
        }
    }
    None
}
