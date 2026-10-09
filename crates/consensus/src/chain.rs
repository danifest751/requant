//! In-memory chain state (CHAIN.md §5–§8): block index, best chain by cumulative work, UTXO set with undo
//! data, reorganisation, epoch weights, and a reference miner for small networks.

use crate::block::{genesis, Block, Claim, Header, BLOCK_VERSION};
use crate::params::{tagged, Network, MAX_AMOUNT, MAX_FUTURE_SECS, MTP_WINDOW};
use crate::pow::{next_target, reward};
use crate::tx::{pkh, Hash, OutPoint, Output, Tx};
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

struct Entry {
    block: Arc<Block>,
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
}

const EPOCH_CACHE: usize = 3;

impl Chain {
    pub fn new(net: Network, threads: usize) -> Chain {
        let g = genesis(&net);
        let id = g.id(&net);
        let entry = Entry {
            height: 0,
            time: g.header.time,
            work: U256::work(&g.header.target),
            issued: 0,
            status: Status::Valid,
            block: Arc::new(g),
        };
        let mut c = Chain {
            net,
            threads: threads.max(1),
            entries: HashMap::new(),
            active: vec![id],
            utxo: HashMap::new(),
            undo: HashMap::new(),
            epochs: Vec::new(),
            last_failure: "",
        };
        c.entries.insert(id, entry);
        c.undo.insert(id, Vec::new());
        c
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

    pub fn block(&self, id: &Hash) -> Option<Arc<Block>> {
        self.entries.get(id).map(|e| e.block.clone())
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

    /// Unspent outputs paying to `pkh` (linear scan; for wallets and tests).
    pub fn coins_of(&self, owner: &Hash) -> Vec<(OutPoint, Coin)> {
        let mut v: Vec<_> = self.utxo.iter().filter(|(_, c)| c.output.pkh == *owner).map(|(o, c)| (*o, *c)).collect();
        v.sort_by_key(|(o, _)| *o);
        v
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
            id = self.entries[&id].block.header.prev;
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
            id = e.block.header.prev;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Seed of the epoch containing `height`, on the branch ending at `parent` (CHAIN.md §6).
    pub fn epoch_seed(&self, parent: &Hash, height: u64) -> Hash {
        let e = height / self.net.epoch_len;
        if e == 0 {
            return tagged("requant/epoch0", &[&self.net.chain_id]);
        }
        let anchor = self.ancestor(parent, e * self.net.epoch_len - self.net.lookback);
        tagged("requant/epoch", &[&e.to_le_bytes(), &anchor])
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
    fn check_header(&mut self, block: &Block, now: u64) -> Result<(), Error> {
        let h = &block.header;
        let parent = self.entries.get(&h.prev).ok_or(Error::UnknownParent)?;
        if parent.status == Status::Invalid {
            return Err(Error::Invalid("invalid parent"));
        }
        if h.height != parent.height + 1 {
            return Err(Error::Invalid("height"));
        }
        let (p_height, p_time) = (parent.height, parent.time);
        if h.time <= self.median_time_past(&h.prev) {
            return Err(Error::Invalid("time not after median time past"));
        }
        if h.time > now + MAX_FUTURE_SECS {
            return Err(Error::Invalid("time too far in the future"));
        }
        if h.target != next_target(&self.net, p_height, p_time) {
            return Err(Error::Invalid("target"));
        }
        let seed = self.epoch_seed(&h.prev, h.height);
        let epoch = self.epoch(&seed);
        let c = &block.claim;
        epoch
            .check(&h.digest(&self.net.chain_id), c.nonce, c.i, c.c, &c.piece, &h.target.to_be_bytes(), self.threads)
            .map_err(|r| match r {
                tnet::Reject::BadIndex => Error::Invalid("claim index"),
                tnet::Reject::AboveTarget => Error::Invalid("claim above target"),
                tnet::Reject::WrongPiece => Error::Invalid("claim piece does not match the network"),
            })
    }

    /// Validate and store a block, switching the best chain if it now has the most work.
    pub fn accept(&mut self, block: Block, now: u64) -> Result<Accepted, Error> {
        let id = block.id(&self.net);
        if self.entries.contains_key(&id) {
            return Err(Error::Duplicate);
        }
        block.check_standalone(&self.net)?;
        self.check_header(&block, now)?;
        let parent = &self.entries[&block.header.prev];
        let entry = Entry {
            height: block.header.height,
            time: block.header.time,
            work: parent.work.saturating_add(&U256::work(&block.header.target)),
            issued: parent.issued.saturating_add(reward(parent.issued)),
            status: Status::Checked,
            block: Arc::new(block),
        };
        self.entries.insert(id, entry);
        let before = self.tip();
        let disconnected = self.activate_best();
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
            id = e.block.header.prev;
        }
    }

    /// Move to the valid chain with the most work; returns the number of blocks disconnected from the old
    /// best chain on the way.
    fn activate_best(&mut self) -> usize {
        let mut disconnected_total = 0;
        loop {
            let tip_work = self.tip_work();
            let best = self
                .entries
                .iter()
                .filter(|(_, e)| e.work > tip_work && e.status != Status::Invalid)
                .map(|(id, e)| (e.work, *id))
                .filter(|(_, id)| !self.has_invalid_ancestor(id))
                .max();
            let Some((_, cand)) = best else { return disconnected_total };
            match self.reorg_to(&cand) {
                Ok(n) => disconnected_total += n,
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
            id = self.entries[&id].block.header.prev;
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
        Ok(old.len())
    }

    /// Apply a block's transactions to the UTXO set (CHAIN.md §5 items 6–7) and append it to `active`.
    fn connect(&mut self, id: &Hash) -> Result<(), Error> {
        let block = self.entries[id].block.clone();
        let height = block.header.height;
        let parent_issued = self.entries[&block.header.prev].issued;
        let mut spent: Vec<(OutPoint, Coin)> = Vec::new();
        let mut added: Vec<OutPoint> = Vec::new();
        let result: Result<(), Error> = (|| {
            let mut fees: u64 = 0;
            for tx in &block.txs[1..] {
                let Tx::Transfer { inputs, outputs } = tx else { unreachable!("checked standalone") };
                let mut total_in: u64 = 0;
                for inp in inputs {
                    let coin = self.utxo.remove(&inp.prev).ok_or(Error::Invalid("missing or spent input"))?;
                    spent.push((inp.prev, coin));
                    if pkh(&inp.pubkey) != coin.output.pkh {
                        return Err(Error::Invalid("input key does not match the output"));
                    }
                    if coin.coinbase && height - coin.height < self.net.maturity {
                        return Err(Error::Invalid("immature coinbase spend"));
                    }
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
                for op in added {
                    self.utxo.remove(&op);
                }
                for (op, coin) in spent {
                    self.utxo.insert(op, coin);
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
        let block = self.entries[id].block.clone();
        for tx in &block.txs {
            let txid = tx.txid();
            for v in 0..tx.outputs().len() {
                self.utxo.remove(&OutPoint { txid, vout: v as u32 });
            }
        }
        for (op, coin) in self.undo.remove(id).unwrap_or_default() {
            self.utxo.insert(op, coin);
        }
        self.active.pop();
    }

    /// A block on the tip paying `reward + fees` to `payee`, with `txs` (unchecked), dated
    /// `max(time, median time past + 1)`, and an empty claim to be filled by a miner.
    pub fn template(&self, payee: &Hash, txs: Vec<Tx>, time: u64) -> Block {
        self.template_on(&self.tip(), payee, txs, time)
    }

    /// As [`Chain::template`] on any known `parent` (fees are computed against the tip's UTXO set).
    pub fn template_on(&self, parent_id: &Hash, payee: &Hash, txs: Vec<Tx>, time: u64) -> Block {
        let parent = &self.entries[parent_id];
        let height = parent.height + 1;
        let mut fees = 0u64;
        for tx in &txs {
            if let Tx::Transfer { inputs, outputs } = tx {
                let total_in: u64 = inputs.iter().filter_map(|i| self.utxo.get(&i.prev)).map(|c| c.output.value).sum();
                let total_out: u64 = outputs.iter().map(|o| o.value).sum();
                fees += total_in.saturating_sub(total_out);
            }
        }
        let coinbase = Tx::Coinbase {
            height,
            extra: Vec::new(),
            outputs: vec![Output { value: reward(parent.issued) + fees, pkh: *payee }],
        };
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
