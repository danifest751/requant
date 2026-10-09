//! Header chain for headers-first sync: headers with their work claims, fully verified without block
//! bodies (link, height, median time past, clock, ASERT target, TNet claim). The block chain then downloads
//! bodies along the best header chain and accepts them without recomputing the claims
//! ([`crate::chain::Chain::accept_prevalidated`]). About 400 bytes per block.

use crate::block::{block_id, genesis, Claim, Header, BLOCK_VERSION};
use crate::chain::{epoch_seed, verify_claim};
use crate::params::{Network, MAX_FUTURE_SECS, MTP_WINDOW};
use crate::pow::next_target;
use crate::tx::Hash;
use crate::u256::U256;
use crate::Error;
use std::collections::HashMap;
use std::sync::Arc;

struct HEntry {
    header: Header,
    claim: Claim,
    /// Cumulative work up to and including this header.
    work: U256,
}

pub struct HeaderChain {
    pub net: Network,
    entries: HashMap<Hash, HEntry>,
    /// Ids of the best header chain by height.
    best: Vec<Hash>,
    threads: usize,
    max_reorg: u64,
}

impl HeaderChain {
    pub fn new(net: Network, threads: usize) -> HeaderChain {
        let g = genesis(&net);
        let id = g.id(&net);
        let mut entries = HashMap::new();
        entries.insert(id, HEntry { work: U256::work(&g.header.target), header: g.header, claim: g.claim });
        HeaderChain { net, entries, best: vec![id], threads: threads.max(1), max_reorg: u64::MAX }
    }

    /// Same policy as [`crate::chain::Chain::set_max_reorg`].
    pub fn set_max_reorg(&mut self, depth: u64) {
        self.max_reorg = depth;
    }

    pub fn height(&self) -> u64 {
        self.best.len() as u64 - 1
    }

    pub fn tip(&self) -> Hash {
        *self.best.last().unwrap()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.entries.contains_key(id)
    }

    /// A known header with its work claim.
    pub fn header(&self, id: &Hash) -> Option<(Header, Claim)> {
        self.entries.get(id).map(|e| (e.header, e.claim.clone()))
    }

    pub fn best_id(&self, height: u64) -> Option<Hash> {
        self.best.get(height as usize).copied()
    }

    /// Ids of the best header chain at heights `from..=to` (clipped to the tip).
    pub fn best_ids(&self, from: u64, to: u64) -> Vec<Hash> {
        let to = to.min(self.height());
        if from > to {
            return Vec::new();
        }
        self.best[from as usize..=to as usize].to_vec()
    }

    fn on_best(&self, id: &Hash) -> bool {
        self.entries.get(id).is_some_and(|e| self.best.get(e.header.height as usize) == Some(id))
    }

    fn ancestor(&self, from: &Hash, height: u64) -> Hash {
        if self.on_best(from) {
            return self.best[height as usize];
        }
        let mut id = *from;
        while self.entries[&id].header.height > height {
            id = self.entries[&id].header.prev;
        }
        id
    }

    fn median_time_past(&self, parent: &Hash) -> u64 {
        let mut times = Vec::with_capacity(MTP_WINDOW);
        let mut id = *parent;
        loop {
            let e = &self.entries[&id];
            times.push(e.header.time);
            if times.len() == MTP_WINDOW || e.header.height == 0 {
                break;
            }
            id = e.header.prev;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Block ids from the best header tip back to genesis at exponentially growing distances.
    pub fn locator(&self) -> Vec<Hash> {
        let mut v = Vec::new();
        let mut h = self.height() as i64;
        let mut step = 1i64;
        while h > 0 {
            v.push(self.best[h as usize]);
            if v.len() >= 10 {
                step *= 2;
            }
            h -= step;
        }
        v.push(self.best[0]);
        v
    }

    fn insert(&mut self, id: Hash, entry: HEntry) {
        let work = entry.work;
        self.entries.insert(id, entry);
        if work > self.entries[&self.tip()].work {
            self.reroute(id);
        }
    }

    /// Make the best chain end at `id`.
    fn reroute(&mut self, id: Hash) {
        let mut path = Vec::new();
        let mut cur = id;
        while !self.on_best(&cur) {
            path.push(cur);
            cur = self.entries[&cur].header.prev;
        }
        self.best.truncate(self.entries[&cur].header.height as usize + 1);
        self.best.extend(path.into_iter().rev());
    }

    /// Record the header of a block the block chain accepted (already fully verified). Ignored if known or
    /// if its parent is unknown.
    pub fn add_valid(&mut self, header: &Header, claim: &Claim) {
        let id = block_id(&header.digest(&self.net.chain_id), claim);
        if self.entries.contains_key(&id) {
            return;
        }
        let Some(parent) = self.entries.get(&header.prev) else { return };
        let work = parent.work.saturating_add(&U256::work(&header.target));
        self.insert(id, HEntry { header: *header, claim: claim.clone(), work });
    }

    /// Verify a header and its work claim against its parent (CHAIN.md §5 items 1–4) and add it. Returns
    /// `Ok(false)` if it was already known. `epoch_for` provides the TNet weights for an epoch seed.
    pub fn accept(
        &mut self,
        header: Header,
        claim: Claim,
        now: u64,
        epoch_for: &mut dyn FnMut(&Hash) -> Arc<tnet::Epoch>,
    ) -> Result<bool, Error> {
        let Some(seed) = self.check_context(&header, &claim, now)? else { return Ok(false) };
        verify_claim(&self.net, &epoch_for(&seed), &header, &claim, self.threads)?;
        Ok(self.insert_verified(header, claim))
    }

    /// Every check of [`HeaderChain::accept`] except the work claim; returns the epoch seed the claim must
    /// be verified with, or `None` if the header is already known. Lets a caller verify the claim (the
    /// expensive part) without holding a lock, then call [`HeaderChain::insert_verified`].
    pub fn check_context(&self, header: &Header, claim: &Claim, now: u64) -> Result<Option<Hash>, Error> {
        let id = block_id(&header.digest(&self.net.chain_id), claim);
        if self.entries.contains_key(&id) {
            return Ok(None);
        }
        if header.version != BLOCK_VERSION {
            return Err(Error::Invalid("block version"));
        }
        if claim.piece.len() != self.net.tnet.w {
            return Err(Error::Invalid("claim piece length"));
        }
        let parent = self.entries.get(&header.prev).ok_or(Error::UnknownParent)?;
        let (p_height, p_time) = (parent.header.height, parent.header.time);
        if header.height != p_height + 1 {
            return Err(Error::Invalid("height"));
        }
        if self.max_reorg != u64::MAX {
            let mut cur = header.prev;
            let mut steps = 0;
            while !self.on_best(&cur) && steps <= self.max_reorg {
                cur = self.entries[&cur].header.prev;
                steps += 1;
            }
            let fork = self.entries[&cur].header.height;
            if !self.on_best(&cur) || self.height().saturating_sub(fork) > self.max_reorg {
                return Err(Error::Invalid("fork deeper than the reorg limit"));
            }
        }
        if header.time <= self.median_time_past(&header.prev) {
            return Err(Error::Invalid("time not after median time past"));
        }
        if header.time > now + MAX_FUTURE_SECS {
            return Err(Error::Invalid("time too far in the future"));
        }
        if header.target != next_target(&self.net, p_height, p_time) {
            return Err(Error::Invalid("target"));
        }
        Ok(Some(epoch_seed(&self.net, header.height, |h| self.ancestor(&header.prev, h))))
    }

    /// Add a header whose context and claim were verified (see [`HeaderChain::check_context`]); `false` if
    /// it is known already or its parent disappeared meanwhile.
    pub fn insert_verified(&mut self, header: Header, claim: Claim) -> bool {
        let id = block_id(&header.digest(&self.net.chain_id), &claim);
        if self.entries.contains_key(&id) {
            return false;
        }
        let Some(parent) = self.entries.get(&header.prev) else { return false };
        let work = parent.work.saturating_add(&U256::work(&header.target));
        self.insert(id, HEntry { header, claim, work });
        true
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    /// Forget a header whose block turned out invalid, and everything built on it; the best chain moves to
    /// the remaining header with the most work.
    pub fn mark_invalid(&mut self, id: &Hash) {
        if self.entries.get(id).is_none_or(|e| e.header.height == 0) {
            return;
        }
        self.entries.remove(id);
        loop {
            let orphaned: Vec<Hash> = self
                .entries
                .iter()
                .filter(|(_, e)| e.header.height > 0 && !self.entries.contains_key(&e.header.prev))
                .map(|(k, _)| *k)
                .collect();
            if orphaned.is_empty() {
                break;
            }
            for k in orphaned {
                self.entries.remove(&k);
            }
        }
        let best =
            self.entries.iter().max_by(|a, b| a.1.work.cmp(&b.1.work).then(b.0.cmp(a.0))).map(|(k, _)| *k).unwrap();
        let mut path = vec![best];
        let mut cur = best;
        while self.entries[&cur].header.height > 0 {
            cur = self.entries[&cur].header.prev;
            path.push(cur);
        }
        path.reverse();
        self.best = path;
    }
}
