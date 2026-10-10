//! Node: chain, mempool, storage, transaction index and peer address book behind one lock; a reader thread
//! and a writer thread per peer; block-first sync by locator; block, transaction and address relay; a
//! connection manager keeping configured and discovered peers connected; an optional CPU miner.

use crate::addrbook::{routable, AddrBook};
use crate::index::TxIndex;
use crate::mempool::Mempool;
use crate::msg::{
    read_msg, write_msg, Msg, HEADERS_PROTOCOL, MAX_ADDR, MAX_HEADERS, MAX_INV, MIN_PROTOCOL, PROTOCOL,
    RELEASE_PROTOCOL,
};
use crate::store::Store;
use requant_consensus::block::tx_root;
use requant_consensus::block::Block;
use requant_consensus::block::{Claim, Header};
use requant_consensus::chain::{claim_hash_ok, mine, verify_claim, Accepted, Chain, DEEP_FORK};
use requant_consensus::codec::{Reader, Writer};
use requant_consensus::headers::HeaderChain;
use requant_consensus::params::Network;
use requant_consensus::tx::{Hash, Tx};
use requant_consensus::Error;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufReader, BufWriter};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_PEERS: usize = 32;
/// Outbound connections the manager tries to keep.
pub const TARGET_OUTBOUND: usize = 8;
pub const MAX_ORPHANS: usize = 256;
/// Orphan blocks (parent unknown) are kept up to this many bytes in total and this many per peer, and
/// only if they are at most `MAX_ORPHAN_AHEAD` blocks above the tip.
pub const MAX_ORPHAN_BYTES: usize = 16 << 20;
pub const MAX_ORPHANS_PER_PEER: usize = 64;
pub const MAX_ORPHAN_AHEAD: u64 = 4096;
/// Inbound connections accepted from one IP address (not applied to loopback on regtest).
pub const MAX_INBOUND_PER_IP: usize = 4;
const MAX_TEMPLATES: usize = 16;
/// A peer silent for this long is dropped (pings go out every `PING_EVERY`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const PING_EVERY: u64 = 120;
/// How long an address that sent invalid data is refused.
const BAN_SECS: u64 = 3600;
/// Bytes sent to peers by this process (see `State::uploaded`), and the upload period.
static UPLOADED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const UPLOAD_PERIOD: u64 = 30 * 86_400;

/// Best-chain blocks whose bodies stay in memory; older ones are read back from `blocks.dat` when needed.
pub const KEEP_BODIES: u64 = 2000;

/// Misbehaviour points that get a peer banned.
pub const BAN_SCORE: u32 = 100;
/// Messages a peer may send per second on average, and at once.
const MSG_RATE: f64 = 300.0;
const MSG_BURST: f64 = 1000.0;

/// Points for an error a peer caused, or `None` for errors that only end the connection (protocol
/// mismatch, a connection to ourselves). Invalid work is outright hostile; a bad transaction may be
/// relayed in good faith from an older node, so it costs little.
pub fn misbehaviour(why: &str) -> Option<u32> {
    match why {
        "invalid block" | "invalid header" | "malformed block" | "malformed headers" => Some(BAN_SCORE),
        "invalid release" => Some(50),
        "invalid transaction" | "malformed transaction" => Some(10),
        "message flood" => Some(1),
        w if w.starts_with("invalid") || w.starts_with("malformed") => Some(20),
        _ => None,
    }
}
/// Bytes served for one `GetData` request.
const MAX_GETDATA_BYTES: usize = 32 << 20;
/// Bytes queued for a peer that does not read them; beyond this the peer is disconnected.
const MAX_PEER_QUEUE: usize = 64 << 20;
/// A write to a peer blocked this long ends the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn random_u64() -> u64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(now());
    h.finish()
}

pub fn agent() -> String {
    format!("requantd/{VERSION}")
}

#[derive(Clone)]
pub struct Config {
    pub net: Network,
    pub datadir: PathBuf,
    pub listen: SocketAddr,
    pub rpc: Option<SocketAddr>,
    /// If set, RPC requests must carry `Authorization: Bearer <token>`.
    pub rpc_token: Option<String>,
    pub connect: Vec<String>,
    /// Mine on the CPU, paying this key hash (practical on regtest only).
    pub mine_to: Option<Hash>,
    /// Pause between mined blocks (regtest).
    pub mine_interval: Duration,
    /// Threads for verifying work claims.
    pub threads: usize,
    /// Refuse forks deeper than this below the tip (node policy; see `Chain::set_max_reorg`).
    pub max_reorg: u64,
    /// Period of the connection manager (reconnects, new outbound peers, pings).
    pub peer_interval: Duration,
    /// Dial discovered addresses (off: only `--connect` peers and inbound connections).
    pub discover: bool,
    /// Serve the read-only block explorer here.
    pub explorer: Option<SocketAddr>,
    /// Run a mining pool.
    pub pool: Option<crate::pool::PoolConfig>,
    /// Install newer signed releases automatically (see `release`).
    pub auto_update: bool,
    /// Key releases must be signed with (`release::RELEASE_KEY`; tests use their own).
    pub release_key: [u8; 32],
    /// Run the test-network faucet from this key (see `faucet`).
    pub faucet: Option<crate::faucet::FaucetConfig>,
    /// Where the watchman's events are sent (see `watch`).
    pub notify: crate::watch::NotifyConfig,
    /// Bytes the node may send to peers per 30 days; beyond, it serves only recent blocks.
    pub max_upload: Option<u64>,
}

/// Default reorg limit: one epoch (a day on the test network).
pub fn default_max_reorg(net: &Network) -> u64 {
    net.epoch_len.max(100)
}

pub struct Peer {
    tx: Sender<Msg>,
    /// Bytes queued and not yet written; past `MAX_PEER_QUEUE` the connection is closed.
    queued: Arc<AtomicUsize>,
    sock: TcpStream,
    pub addr: SocketAddr,
    pub outbound: bool,
    /// Where the peer accepts connections (outbound: `addr`; inbound: its IP and announced port).
    pub listen: Option<SocketAddr>,
    pub agent: String,
    pub height: u64,
    pub since: u64,
    /// Protocol version from the peer's greeting (0 until it arrives).
    pub protocol: u32,
    inflight: usize,
    /// Misbehaviour points; at `BAN_SCORE` the peer is banned (see `misbehaviour`).
    pub score: u32,
}

impl Peer {
    /// Queue a message for the writer thread; a peer that lets `MAX_PEER_QUEUE` bytes pile up is cut off.
    fn deliver(&self, m: Msg) {
        let size = m.approx_size();
        if self.queued.fetch_add(size, Ordering::Relaxed) + size > MAX_PEER_QUEUE {
            self.queued.fetch_sub(size, Ordering::Relaxed);
            let _ = self.sock.shutdown(std::net::Shutdown::Both);
            return;
        }
        if self.tx.send(m).is_err() {
            self.queued.fetch_sub(size, Ordering::Relaxed);
        }
    }
}

/// Headers-first download: blocks requested at once along the best header chain, per peer, and how long a
/// request may stay unanswered before it is given to another peer.
const DOWNLOAD_WINDOW: u64 = 512;
const PER_PEER_INFLIGHT: usize = 16;
const INFLIGHT_TIMEOUT: u64 = 60;

pub struct State {
    pub chain: Chain,
    /// Verified headers, ahead of `chain` while syncing.
    pub headers: HeaderChain,
    /// Block downloads in flight: block id -> (peer, request time).
    inflight: HashMap<Hash, (u64, u64)>,
    pub mempool: Mempool,
    pub index: TxIndex,
    /// The height the start-up snapshot restored (`None`: the block file was replayed from the start).
    pub restored: Option<u64>,
    pub book: AddrBook,
    store: Store,
    /// Where the bodies in `store` are, for the chain to read old ones back.
    bodies: Arc<crate::store::Bodies>,
    /// The start-up snapshot (see `snapshot`).
    snapshot_path: PathBuf,
    /// Orphans with the peer that sent them and their size.
    orphans: HashMap<Hash, (Block, Option<u64>, usize)>,
    orphan_bytes: usize,
    peers: HashMap<u64, Peer>,
    next_peer: u64,
    /// Work handed out by `getwork`, by header digest.
    templates: Vec<(Hash, Block)>,
    pub node_id: u64,
    listen_port: u16,
    bans: HashMap<IpAddr, u64>,
    bans_path: PathBuf,
    /// Where epoch weights files live (see `epochs`).
    epoch_dir: PathBuf,
    /// The mempool's file, and the pool version last written there.
    mempool_path: PathBuf,
    mempool_saved: (u64, usize),
    /// The newest verified release (see `release`), kept in `release_path`.
    pub release: Option<crate::release::Release>,
    release_path: PathBuf,
    pub auto_update: bool,
    pub release_key: [u8; 32],
    pub faucet: Option<crate::faucet::Faucet>,
    /// What the watchman found (see `watch`).
    pub events: crate::watch::Events,
    /// Verification threads as configured, and whether the machine is busy (then one thread; see `load`).
    pub base_threads: usize,
    pub busy: bool,
    /// Upload limit per 30 days (`--max-upload`), the period's start and what earlier runs sent in it.
    pub max_upload: Option<u64>,
    upload_path: PathBuf,
    upload_start: u64,
    upload_base: u64,
    allow_local: bool,
    pub started: u64,
    pub pool: Option<crate::pool::Pool>,
}

pub type Shared = Arc<Mutex<State>>;

pub struct Handle {
    pub shared: Shared,
    pub p2p: SocketAddr,
    pub rpc: Option<SocketAddr>,
    /// The pool's public JSON-RPC address, if a pool runs.
    pub pool: Option<SocketAddr>,
    pub stop: Arc<AtomicBool>,
}

impl State {
    fn broadcast(&self, m: &Msg, except: Option<u64>) {
        for (id, p) in &self.peers {
            if Some(*id) != except {
                p.deliver(m.clone());
            }
        }
    }

    fn send(&self, peer: u64, m: Msg) {
        if let Some(p) = self.peers.get(&peer) {
            p.deliver(m);
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn peers(&self) -> Vec<&Peer> {
        let mut v: Vec<&Peer> = self.peers.values().collect();
        v.sort_by_key(|p| p.since);
        v
    }

    pub fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.peers.values().map(|p| p.addr).collect()
    }

    /// Addresses we are connected to, as dialable addresses.
    fn connected(&self) -> HashSet<SocketAddr> {
        self.peers.values().filter_map(|p| p.listen).collect()
    }

    fn outbound_count(&self) -> usize {
        self.peers.values().filter(|p| p.outbound).count()
    }

    pub fn banned(&self, ip: &IpAddr) -> bool {
        self.bans.get(ip).is_some_and(|&t| t > now())
    }

    /// Bytes sent to peers in the current 30-day period.
    pub fn uploaded(&self) -> u64 {
        self.upload_base + UPLOADED.load(Ordering::Relaxed)
    }

    /// Whether the upload limit is reached (then old blocks are not served).
    pub fn upload_capped(&self) -> bool {
        self.max_upload.is_some_and(|m| self.uploaded() >= m)
    }

    fn load_upload(&mut self) {
        let t = now();
        let text = std::fs::read_to_string(&self.upload_path).unwrap_or_default();
        let mut f = text.split_whitespace().map(|x| x.parse::<u64>().ok());
        match (f.next().flatten(), f.next().flatten()) {
            (Some(start), Some(bytes)) if t.saturating_sub(start) < UPLOAD_PERIOD => {
                self.upload_start = start;
                self.upload_base = bytes;
            }
            _ => self.upload_start = t,
        }
    }

    /// Write the period's upload to `upload.txt`, starting a new period after 30 days.
    pub fn save_upload(&mut self) {
        let t = now();
        if t.saturating_sub(self.upload_start) >= UPLOAD_PERIOD {
            self.upload_start = t;
            self.upload_base = 0;
            UPLOADED.store(0, Ordering::Relaxed);
        }
        let _ = std::fs::write(&self.upload_path, format!("{} {}\n", self.upload_start, self.uploaded()));
    }

    /// Write the mempool to `mempool.dat` if it changed (each transaction as LE32 length and bytes, in arrival
    /// order; written to a temporary file, then renamed).
    /// The start-up snapshot of the current state, if any block is stored (cheap: taken under the lock and
    /// written by the caller after releasing it).
    pub fn snapshot_bytes(&self) -> Option<(PathBuf, Vec<u8>)> {
        let last = self.store.last()?;
        Some((self.snapshot_path.clone(), crate::snapshot::encode(&self.chain, &self.index, &self.bodies, last)))
    }

    pub fn save_mempool(&mut self) {
        if self.mempool.version() == self.mempool_saved {
            return;
        }
        let mut out = Vec::new();
        for tx in self.mempool.ordered() {
            let b = tx.encode();
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(&b);
        }
        let tmp = self.mempool_path.with_extension("tmp");
        if std::fs::write(&tmp, out).and_then(|_| std::fs::rename(&tmp, &self.mempool_path)).is_ok() {
            self.mempool_saved = self.mempool.version();
        }
    }

    /// Re-admit the saved mempool (each transaction checked again against the chain).
    fn load_mempool(&mut self) -> usize {
        let Ok(b) = std::fs::read(&self.mempool_path) else { return 0 };
        let (mut k, mut n) = (0usize, 0usize);
        while k + 4 <= b.len() {
            let len = u32::from_le_bytes(b[k..k + 4].try_into().unwrap()) as usize;
            let Some(raw) = b.get(k + 4..k + 4 + len) else { break };
            if let Ok(tx) = Tx::decode_exact(raw) {
                n += self.mempool.add(tx, &self.chain).is_ok() as usize;
            }
            k += 4 + len;
        }
        self.mempool_saved = self.mempool.version();
        n
    }

    /// Add misbehaviour points to a peer; at `BAN_SCORE` it is banned. Returns whether to disconnect.
    fn misbehave(&mut self, peer: u64, points: u32, why: &str) -> bool {
        let Some(p) = self.peers.get_mut(&peer) else { return true };
        p.score = p.score.saturating_add(points);
        if p.score < BAN_SCORE {
            return false;
        }
        let ip = p.addr.ip();
        eprintln!("peer {}: banned ({why}; misbehaviour {})", p.addr, p.score);
        self.ban(ip);
        true
    }

    fn ban(&mut self, ip: IpAddr) {
        if !ip.is_loopback() {
            let t = now();
            self.bans.insert(ip, t + BAN_SECS);
            self.bans.retain(|_, until| *until > t);
            // kept across restarts: "ip until" per line
            let text: String = self.bans.iter().map(|(ip, until)| format!("{ip} {until}\n")).collect();
            if let Err(e) = std::fs::write(&self.bans_path, text) {
                eprintln!("bans: {e}");
            }
        }
    }

    /// Accept a block from a peer (`from`) or a local miner; relay and persist it, then resolve orphans.
    /// `Err` means the peer sent something invalid.
    pub fn process_block(&mut self, block: Block, from: Option<u64>) -> Result<Option<Accepted>, Error> {
        let mut queue = vec![block];
        let mut first = None;
        while let Some(b) = queue.pop() {
            let id = b.id(&self.chain.net);
            let bytes = b.encode();
            self.inflight.remove(&id);
            // a block whose header (and work claim) the header chain verified is not re-verified
            let prevalidated = self.headers.contains(&id);
            let result = if prevalidated {
                self.chain.accept_prevalidated(b.clone(), now())
            } else {
                self.chain.accept(b.clone(), now())
            };
            match result {
                Ok(acc) => {
                    if first.is_none() {
                        first = Some(acc);
                    }
                    self.headers.add_valid(&b.header, &b.claim);
                    match self.store.append(&bytes) {
                        Ok(at) => self.bodies.insert(id, at, bytes.len()),
                        Err(e) => eprintln!("store: {e}"),
                    }
                    if let Accepted::Reorg { disconnected } = acc {
                        if disconnected >= 2 {
                            self.events.push(
                                crate::watch::Level::Warning,
                                format!(
                                    "reorganisation: {disconnected} blocks replaced, new tip at {}",
                                    self.chain.height()
                                ),
                            );
                        }
                    }
                    if acc != Accepted::SideChain {
                        self.mempool.revalidate(&self.chain);
                        // transactions of blocks a reorganisation took off the chain go back to the pool
                        for old in self.chain.take_disconnected() {
                            for tx in &old.txs[1..] {
                                let _ = self.mempool.add(tx.clone(), &self.chain);
                            }
                        }
                        self.index.sync(&self.chain);
                    }
                    // announce new blocks, not the history being downloaded
                    if self.chain.height() + 10 >= self.headers.height() {
                        self.broadcast(&Msg::Inv(vec![id]), from);
                    }
                    let children: Vec<Hash> =
                        self.orphans.iter().filter(|(_, o)| o.0.header.prev == id).map(|(k, _)| *k).collect();
                    for k in children {
                        let (b, _, size) = self.orphans.remove(&k).unwrap();
                        self.orphan_bytes -= size;
                        queue.push(b);
                    }
                }
                Err(Error::Duplicate) => {}
                Err(Error::UnknownParent) => {
                    // an orphan costs memory: only with a claim that meets its own (bounded) target
                    let net = &self.chain.net;
                    if b.header.target > net.pow_limit || claim_hash_ok(net, &b.header, &b.claim).is_err() {
                        if first.is_none() {
                            return Err(Error::Invalid("orphan without work"));
                        }
                        continue;
                    }
                    self.add_orphan(id, b, bytes.len(), from);
                    // with a verified header the parent is already being downloaded
                    if let (Some(p), false) = (from, prevalidated) {
                        if self.peers.get(&p).is_some_and(|x| x.protocol >= HEADERS_PROTOCOL) {
                            self.send(p, Msg::GetHeaders(self.headers.locator()));
                        } else {
                            self.send(p, Msg::GetBlocks(self.chain.locator()));
                        }
                    }
                }
                // a clock difference or our own reorg policy: not the sender's fault
                Err(Error::Invalid("time too far in the future")) | Err(Error::Invalid(DEEP_FORK)) => {}
                Err(e) => {
                    // a valid header with an invalid body is a dead branch, but only if the body is the one the
                    // header commits to: anyone can pair a good header with junk transactions
                    if prevalidated && tx_root(&b.txs) == b.header.tx_root {
                        self.headers.mark_invalid(&id);
                    }
                    if first.is_none() {
                        self.schedule_downloads();
                        return Err(e);
                    }
                }
            }
        }
        self.schedule_downloads();
        Ok(first)
    }

    /// Request bodies along the best header chain from peers that have them, round robin, at most
    /// `PER_PEER_INFLIGHT` per peer and `DOWNLOAD_WINDOW` blocks ahead of the block chain.
    pub fn schedule_downloads(&mut self) {
        let hh = self.headers.height();
        let mut fork = self.chain.height().min(hh);
        while fork > 0 && self.headers.best_id(fork) != self.chain.active_id(fork) {
            fork -= 1;
        }
        if hh <= fork {
            return;
        }
        let ids = self.headers.best_ids(fork + 1, (fork + DOWNLOAD_WINDOW).min(hh));
        let mut load: HashMap<u64, usize> = HashMap::new();
        for (p, _) in self.inflight.values() {
            *load.entry(*p).or_default() += 1;
        }
        let mut peers: Vec<(u64, u64)> =
            self.peers.iter().filter(|(_, p)| p.protocol > 0).map(|(id, p)| (*id, p.height)).collect();
        peers.sort_unstable();
        if peers.is_empty() {
            return;
        }
        let mut plan: HashMap<u64, Vec<Hash>> = HashMap::new();
        let mut rr = 0usize;
        for (k, id) in ids.iter().enumerate() {
            let height = fork + 1 + k as u64;
            if self.chain.contains(id) || self.inflight.contains_key(id) || self.orphans.contains_key(id) {
                continue;
            }
            let mut chosen = None;
            for t in 0..peers.len() {
                let (pid, ph) = peers[(rr + t) % peers.len()];
                if ph >= height && load.get(&pid).copied().unwrap_or(0) < PER_PEER_INFLIGHT {
                    chosen = Some(pid);
                    rr = (rr + t + 1) % peers.len();
                    break;
                }
            }
            let Some(pid) = chosen else { break };
            *load.entry(pid).or_default() += 1;
            self.inflight.insert(*id, (pid, now()));
            plan.entry(pid).or_default().push(*id);
        }
        for (pid, v) in plan {
            self.send(pid, Msg::GetData(v));
        }
    }

    /// Give unanswered block requests (and those of peers that left) to other peers.
    fn expire_downloads(&mut self) {
        let t = now();
        let peers = &self.peers;
        self.inflight.retain(|_, (p, at)| peers.contains_key(p) && t.saturating_sub(*at) < INFLIGHT_TIMEOUT);
        self.schedule_downloads();
    }

    /// Serve `GetHeaders`: headers and claims of best-chain blocks after the locator.
    fn headers_payload(&self, locator: &[Hash]) -> Vec<u8> {
        let ids = self.chain.blocks_after(locator, MAX_HEADERS);
        let mut w = Writer::default();
        w.varint(ids.len() as u64);
        for id in ids {
            let b = self.chain.block(&id).unwrap();
            w.raw(&b.header.encode());
            w.raw(&b.claim.encode());
        }
        w.0
    }

    /// Keep an orphan within the count, byte, per-peer and height limits (oldest-first eviction is not
    /// tracked; an arbitrary orphan of the same peer, or any orphan, makes room).
    fn add_orphan(&mut self, id: Hash, b: Block, size: usize, from: Option<u64>) {
        if b.header.height > self.chain.height() + MAX_ORPHAN_AHEAD || size > MAX_ORPHAN_BYTES {
            return;
        }
        let from_peer = |o: &(Block, Option<u64>, usize)| from.is_some() && o.1 == from;
        while self.orphans.values().filter(|o| from_peer(o)).count() >= MAX_ORPHANS_PER_PEER {
            let k = *self.orphans.iter().find(|(_, o)| from_peer(o)).unwrap().0;
            self.orphan_bytes -= self.orphans.remove(&k).unwrap().2;
        }
        while !self.orphans.is_empty()
            && (self.orphans.len() >= MAX_ORPHANS || self.orphan_bytes + size > MAX_ORPHAN_BYTES)
        {
            let k = *self.orphans.keys().next().unwrap();
            self.orphan_bytes -= self.orphans.remove(&k).unwrap().2;
        }
        self.orphan_bytes += size;
        self.orphans.insert(id, (b, from, size));
    }

    pub fn orphan_count(&self) -> (usize, usize) {
        (self.orphans.len(), self.orphan_bytes)
    }

    /// Admit a transaction and relay it.
    pub fn process_tx(&mut self, tx: Tx, from: Option<u64>) -> Result<Hash, Error> {
        let bytes = tx.encode();
        let txid = self.mempool.add(tx, &self.chain)?;
        self.broadcast(&Msg::Tx(bytes), from);
        Ok(txid)
    }

    /// A block template for `payee` with pooled transactions, remembered for `submit_work`.
    pub fn new_work(&mut self, payee: &Hash) -> (Block, Hash) {
        let (txs, fees) = self.mempool.select(900_000);
        let net = &self.chain.net;
        let time = if net.name == "regtest" {
            // on-schedule timestamps keep the regtest difficulty constant however fast blocks come
            net.genesis_time + net.spacing as u64 * (self.chain.height() + 1)
        } else {
            now()
        };
        let tip = self.chain.tip();
        let b = self.chain.template_with_fees(&tip, payee, txs, fees, time);
        let seed = self.chain.epoch_seed(&b.header.prev, b.header.height);
        let digest = b.header.digest(&self.chain.net.chain_id);
        if self.templates.len() == MAX_TEMPLATES {
            self.templates.remove(0);
        }
        self.templates.push((digest, b.clone()));
        (b, seed)
    }

    /// Complete remembered work with a claim and submit it.
    pub fn submit_work(
        &mut self,
        digest: &Hash,
        claim: requant_consensus::block::Claim,
    ) -> Result<Option<Accepted>, Error> {
        let mut b = self
            .templates
            .iter()
            .find(|(d, _)| d == digest)
            .map(|(_, b)| b.clone())
            .ok_or(Error::Invalid("unknown work"))?;
        b.claim = claim;
        self.process_block(b, None)
    }

    fn hello(&self) -> Msg {
        Msg::Hello {
            protocol: PROTOCOL,
            height: self.chain.height(),
            tip: self.chain.tip(),
            node_id: self.node_id,
            listen_port: self.listen_port,
            agent: agent(),
        }
    }

    /// Keep a verified release if it is newer than the one known; returns whether it was (to relay it).
    pub fn take_release(&mut self, r: crate::release::Release) -> bool {
        if self.release.as_ref().is_some_and(|have| have.version >= r.version) {
            return false;
        }
        if r.version > crate::release::own_version() {
            eprintln!(
                "update available: requantd {} (this node runs {VERSION}){}",
                r.version_string(),
                if self.auto_update { "; it will update itself" } else { "" }
            );
        }
        if let Err(e) = std::fs::write(&self.release_path, r.encode()) {
            eprintln!("release: {e}");
        }
        self.release = Some(r);
        true
    }

    /// Pass the known release to peers that understand it.
    pub fn relay_release(&self, except: Option<u64>) {
        let Some(r) = &self.release else { return };
        let m = Msg::Release(r.encode());
        for (id, p) in &self.peers {
            if Some(*id) != except && p.protocol >= RELEASE_PROTOCOL {
                p.deliver(m.clone());
            }
        }
    }

    fn on_message(&mut self, peer: u64, m: Msg) -> Result<(), &'static str> {
        match m {
            Msg::Hello { protocol, height, tip, node_id, listen_port, agent } => {
                if protocol < MIN_PROTOCOL {
                    return Err("protocol version");
                }
                let Some(p) = self.peers.get(&peer) else { return Ok(()) };
                let (addr, outbound) = (p.addr, p.outbound);
                if node_id == self.node_id {
                    if outbound {
                        self.book.remove(&addr);
                    }
                    return Err("connected to self");
                }
                let listen = if outbound {
                    Some(addr)
                } else {
                    (listen_port != 0).then(|| SocketAddr::new(addr.ip(), listen_port))
                };
                let p = self.peers.get_mut(&peer).unwrap();
                p.height = height;
                p.protocol = protocol;
                p.agent = agent.chars().filter(|c| !c.is_control()).take(64).collect();
                p.listen = listen;
                if outbound {
                    self.book.good(&addr, now());
                } else if let Some(l) = listen {
                    self.book.add(l);
                }
                self.send(peer, Msg::GetAddr);
                if protocol >= RELEASE_PROTOCOL {
                    if let Some(r) = &self.release {
                        self.send(peer, Msg::Release(r.encode()));
                    }
                }
                if protocol >= HEADERS_PROTOCOL {
                    if height > self.headers.height() || !self.headers.contains(&tip) {
                        self.send(peer, Msg::GetHeaders(self.headers.locator()));
                    }
                } else if height > self.chain.height() || !self.chain.contains(&tip) {
                    self.send(peer, Msg::GetBlocks(self.chain.locator()));
                }
            }
            Msg::GetHeaders(loc) => {
                let payload = self.headers_payload(&loc);
                self.send(peer, Msg::Headers(payload));
            }
            // handled in the reader loop (claims are verified without holding the lock)
            Msg::Headers(_) => {}
            Msg::GetAddr => {
                let mut v: Vec<SocketAddr> = self.peers.values().filter(|p| p.outbound).map(|p| p.addr).collect();
                for a in self.book.sample(MAX_ADDR) {
                    if v.len() >= MAX_ADDR {
                        break;
                    }
                    if !v.contains(&a) {
                        v.push(a);
                    }
                }
                v.retain(|a| routable(a, self.allow_local));
                v.truncate(MAX_ADDR);
                self.send(peer, Msg::Addr(v));
            }
            Msg::Addr(v) => {
                for a in v {
                    self.book.add(a);
                }
            }
            Msg::GetBlocks(loc) => {
                let ids = self.chain.blocks_after(&loc, MAX_INV);
                if !ids.is_empty() {
                    self.send(peer, Msg::Inv(ids));
                }
            }
            Msg::Inv(ids) => {
                // an announced block we already have still tells how far the peer is
                let known = ids.iter().filter_map(|id| self.chain.block(id)).map(|b| b.header.height).max();
                if let (Some(h), Some(p)) = (known, self.peers.get_mut(&peer)) {
                    p.height = p.height.max(h);
                }
                let want: Vec<Hash> =
                    ids.into_iter().filter(|id| !self.chain.contains(id) && !self.orphans.contains_key(id)).collect();
                if !want.is_empty() {
                    if let Some(p) = self.peers.get_mut(&peer) {
                        p.inflight += want.len();
                    }
                    self.send(peer, Msg::GetData(want));
                }
            }
            Msg::GetData(ids) => {
                // each id once, and at most MAX_GETDATA_BYTES per request (a peer asks again for the rest)
                let mut seen = HashSet::new();
                let mut sent = 0usize;
                for id in ids {
                    if sent >= MAX_GETDATA_BYTES || !seen.insert(id) {
                        continue;
                    }
                    if let Some(b) = self.chain.block(&id) {
                        // over the upload limit: only recent blocks (so the network keeps moving)
                        if self.upload_capped() && b.header.height + 100 < self.chain.height() {
                            continue;
                        }
                        let bytes = b.encode();
                        sent += bytes.len();
                        self.send(peer, Msg::Block(bytes));
                    } else if let Some(tx) = self.mempool.get(&id) {
                        let bytes = tx.encode();
                        sent += bytes.len();
                        self.send(peer, Msg::Tx(bytes));
                    }
                }
            }
            Msg::Block(bytes) => {
                let block = Block::decode(&bytes, &self.chain.net).map_err(|_| "malformed block")?;
                let h = block.header.height;
                self.process_block(block, Some(peer)).map_err(|_| "invalid block")?;
                let ours = self.chain.height();
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.inflight = p.inflight.saturating_sub(1);
                    p.height = p.height.max(h);
                    // block-by-block sync for peers without headers-first
                    if p.protocol < HEADERS_PROTOCOL && p.inflight == 0 && p.height > ours {
                        p.deliver(Msg::GetBlocks(self.chain.locator()));
                    }
                }
            }
            Msg::Tx(bytes) => {
                let tx = Tx::decode_exact(&bytes).map_err(|_| "malformed transaction")?;
                match self.process_tx(tx, Some(peer)) {
                    Err(Error::Invalid("bad signature")) | Err(Error::Invalid("bad public key")) => {
                        return Err("invalid transaction")
                    }
                    _ => {}
                }
            }
            Msg::Release(bytes) => {
                let r = crate::release::Release::decode(&bytes, &self.release_key).map_err(|_| "invalid release")?;
                if self.take_release(r) {
                    self.relay_release(Some(peer));
                }
            }
            Msg::Ping(n) => self.send(peer, Msg::Pong(n)),
            Msg::Pong(_) => {}
        }
        Ok(())
    }
}

fn magic(net: &Network) -> [u8; 4] {
    net.chain_id[..4].try_into().unwrap()
}

/// Register a connected peer and run its reader loop on a new thread.
fn spawn_peer(shared: Shared, stream: TcpStream, outbound: bool) -> io::Result<()> {
    let addr = stream.peer_addr()?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IDLE_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let (tx, rx) = channel::<Msg>();
    let queued = Arc::new(AtomicUsize::new(0));
    let (id, hello, magic) = {
        let mut st = shared.lock().unwrap();
        let same_ip = st.peers.values().filter(|p| !p.outbound && p.addr.ip() == addr.ip()).count();
        let per_ip_full = !outbound && same_ip >= MAX_INBOUND_PER_IP && !(st.allow_local && addr.ip().is_loopback());
        if st.peers.len() >= MAX_PEERS || st.banned(&addr.ip()) || per_ip_full {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
        let id = st.next_peer;
        st.next_peer += 1;
        let peer = Peer {
            tx: tx.clone(),
            queued: queued.clone(),
            sock: stream.try_clone()?,
            addr,
            outbound,
            listen: outbound.then_some(addr),
            agent: String::new(),
            height: 0,
            since: now(),
            protocol: 0,
            inflight: 0,
            score: 0,
        };
        st.peers.insert(id, peer);
        (id, st.hello(), magic(&st.chain.net))
    };
    let mut writer = BufWriter::new(stream.try_clone()?);
    std::thread::spawn(move || {
        for m in rx {
            let size = m.approx_size();
            let ok = write_msg(&mut writer, &magic, &m).is_ok();
            queued.fetch_sub(size, Ordering::Relaxed);
            UPLOADED.fetch_add(size as u64, Ordering::Relaxed);
            if !ok {
                // also ends the reader, which removes the peer
                let _ = writer.get_ref().shutdown(std::net::Shutdown::Both);
                break;
            }
        }
    });
    if let Some(p) = shared.lock().unwrap().peers.get(&id) {
        p.deliver(hello);
    }
    let reader_stream = stream.try_clone()?;
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader_stream);
        // messages per second: MSG_RATE on average, MSG_BURST at once
        let (mut tokens, mut last) = (MSG_BURST, std::time::Instant::now());
        while let Ok(m) = read_msg(&mut reader, &magic) {
            let t = std::time::Instant::now();
            tokens = (tokens + t.duration_since(last).as_secs_f64() * MSG_RATE).min(MSG_BURST);
            last = t;
            let flood = tokens < 1.0;
            if !flood {
                tokens -= 1.0;
            }
            let result = match m {
                Msg::Headers(bytes) => handle_headers(&shared, id, &bytes),
                m => shared.lock().unwrap().on_message(id, m),
            };
            let mut st = shared.lock().unwrap();
            let why = match result {
                Err(why) => Some(why),
                Ok(()) if flood => Some("message flood"),
                Ok(()) => None,
            };
            let Some(why) = why else { continue };
            let Some(points) = misbehaviour(why) else {
                // not the peer's fault, or nothing to keep talking about
                if why != "connected to self" {
                    eprintln!("peer {addr}: disconnecting ({why})");
                }
                break;
            };
            if st.misbehave(id, points, why) {
                break;
            }
        }
        shared.lock().unwrap().peers.remove(&id);
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    Ok(())
}

/// A `Headers` message: each header's context is checked under the lock, its work claim (the expensive
/// part, ~20 ms for TNet v1) is verified without it, then it is inserted. Continues the download.
fn handle_headers(shared: &Shared, peer: u64, bytes: &[u8]) -> Result<(), &'static str> {
    let net = shared.lock().unwrap().chain.net.clone();
    let mut r = Reader::new(bytes);
    let n = r.varint(MAX_HEADERS as u64).map_err(|_| "malformed headers")? as usize;
    let mut list = Vec::with_capacity(n);
    for _ in 0..n {
        let h = Header::decode(&mut r).map_err(|_| "malformed headers")?;
        let c = Claim::decode(&mut r, net.tnet.w).map_err(|_| "malformed headers")?;
        list.push((h, c));
    }
    r.finish().map_err(|_| "malformed headers")?;
    let mut last_height = 0;
    for (h, c) in list {
        let (seed, current, threads) = {
            let st = shared.lock().unwrap();
            match st.headers.check_context(&h, &c, now()) {
                Ok(None) => continue,
                Ok(Some(seed)) => {
                    let threads = st.headers.threads();
                    let current = st.chain.upcoming_epoch_seeds()[0];
                    (seed, current, threads)
                }
                Err(Error::UnknownParent) => {
                    // the peer's chain forks below what it was asked for: ask again from our headers
                    let loc = st.headers.locator();
                    st.send(peer, Msg::GetHeaders(loc));
                    return Ok(());
                }
                // a clock difference or our own reorg policy: not the peer's fault
                Err(Error::Invalid("time too far in the future")) | Err(Error::Invalid(DEEP_FORK)) => return Ok(()),
                Err(_) => return Err("invalid header"),
            }
        };
        // weights of a new epoch are derived without holding the node's lock, keeping the block chain's
        let epoch = epoch_for(shared, &seed, &[current]);
        verify_claim(&net, &epoch, &h, &c, threads).map_err(|_| "invalid header")?;
        last_height = h.height;
        shared.lock().unwrap().headers.insert_verified(h, c);
    }
    let mut st = shared.lock().unwrap();
    if let Some(p) = st.peers.get_mut(&peer) {
        p.height = p.height.max(last_height);
    }
    if n == MAX_HEADERS {
        let loc = st.headers.locator();
        st.send(peer, Msg::GetHeaders(loc));
    }
    st.schedule_downloads();
    Ok(())
}

/// Connect to `addr` (host:port) and run the peer.
pub fn connect(shared: &Shared, addr: &str) -> io::Result<()> {
    let sa = addr.to_socket_addrs()?.next().ok_or_else(|| io::Error::other("no address"))?;
    if shared.lock().unwrap().banned(&sa.ip()) {
        return Err(io::Error::other("address is banned"));
    }
    let stream = TcpStream::connect_timeout(&sa, Duration::from_secs(10))?;
    spawn_peer(shared.clone(), stream, true)
}

/// The supply audit as JSON: the UTXO set's total and count, the most the emission schedule allows by the tip
/// (`issued`), what miners left unclaimed, whether the set stays within the schedule, and the set's hash.
pub fn supply_audit(st: &State) -> serde_json::Value {
    let (total, count, hash) = st.chain.utxo_audit();
    let issued = st.chain.issued();
    serde_json::json!({
        "height": st.chain.height(),
        "tip": crate::rpc::hex(&st.chain.tip()),
        "utxos": count,
        "total_atoms": total,
        "issued_atoms": issued,
        "unclaimed_atoms": issued.saturating_sub(total),
        "ok": total <= issued,
        "utxo_hash": crate::rpc::hex(&hash),
    })
}

/// Bans still in force from `bans.txt` ("ip until" per line; a missing or bad file means none).
fn load_bans(path: &std::path::Path) -> HashMap<IpAddr, u64> {
    let t = now();
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (ip, until) = l.split_once(' ')?;
            Some((ip.parse().ok()?, until.trim().parse().ok()?))
        })
        .filter(|(_, until)| *until > t)
        .collect()
}

/// Open storage, replay it, and start listening, connecting, RPC and mining as configured.
pub fn start(cfg: Config) -> io::Result<Handle> {
    let dir = cfg.datadir.join(cfg.net.name);
    // a just-installed update that keeps failing is rolled back before anything else (see `release`)
    crate::release::startup_check(&dir.join("update"));
    // the work-function code as built here must agree with the reference before it judges any block
    if let Err(e) = tnet::self_test() {
        return Err(io::Error::other(format!(
            "TNet self-test failed: {e}; this build or this machine cannot verify blocks"
        )));
    }
    // REQUANT_KEEP_BODIES overrides the window (to exercise reading bodies back in tests)
    let keep = std::env::var("REQUANT_KEEP_BODIES").ok().and_then(|v| v.parse().ok()).unwrap_or(KEEP_BODIES);
    // the start-up snapshot, if it is sound and matches the block file; else everything is replayed
    let snapshot_path = dir.join("chainstate.bin");
    let mut from_snapshot = None;
    if snapshot_path.exists() {
        match crate::snapshot::load(&snapshot_path, &cfg.net, cfg.threads) {
            Ok(s) => match Store::open_after(&dir, Some(s.last))? {
                Some(opened) => from_snapshot = Some((s, opened)),
                None => eprintln!("snapshot: does not match the block file; replaying it"),
            },
            Err(e) => eprintln!("snapshot: {e}; replaying the block file"),
        }
    }
    let restored = from_snapshot.as_ref().map(|(s, _)| s.chain.height());
    let (store, records, bodies, mut chain, mut index) = match from_snapshot {
        Some((s, (store, records))) => {
            let bodies = Arc::new(store.bodies(cfg.net.clone())?);
            for (id, at, len) in s.bodies {
                bodies.insert(id, at, len as usize);
            }
            eprintln!("snapshot: height {}, {} more records to replay", s.chain.height(), records.len());
            (store, records, bodies, s.chain, s.index)
        }
        None => {
            let (store, records) = Store::open(&dir)?;
            let bodies = Arc::new(store.bodies(cfg.net.clone())?);
            (store, records, bodies, Chain::new(cfg.net.clone(), cfg.threads), TxIndex::default())
        }
    };
    chain.set_max_reorg(cfg.max_reorg);
    // only the recent bodies stay in memory, during the replay too
    chain.set_body_source(bodies.clone(), keep);
    let mut replayed = 0;
    for rec in records {
        let r = Block::decode(&rec.data, &cfg.net).map_err(|e| e.to_string()).and_then(|b| {
            // where each block's record is, for reading its body back once it leaves memory
            bodies.insert(b.id(&cfg.net), rec.offset, rec.data.len());
            chain.accept_trusted(b).map_err(|e| e.to_string())
        });
        match r {
            Ok(_) => replayed += 1,
            Err(e) => eprintln!("replay: skipping a stored block ({e})"),
        }
    }
    if replayed > 0 {
        eprintln!("replayed {replayed} blocks, height {}", chain.height());
    }
    index.sync(&chain);
    // the header chain from the block chain's own headers (verified when the blocks were), no body reads
    let mut headers = HeaderChain::new(cfg.net.clone(), cfg.threads);
    headers.set_max_reorg(cfg.max_reorg);
    for (id, header) in chain.best_headers() {
        headers.add_known(id, header);
    }
    let allow_local = cfg.net.name == "regtest";
    let listener = TcpListener::bind(cfg.listen)?;
    let p2p = listener.local_addr()?;
    let mut state = State {
        chain,
        headers,
        inflight: HashMap::new(),
        mempool: Mempool::default(),
        index,
        restored,
        book: AddrBook::load(Some(dir.join("peers.txt")), allow_local),
        store,
        bodies,
        snapshot_path,
        orphans: HashMap::new(),
        orphan_bytes: 0,
        peers: HashMap::new(),
        next_peer: 0,
        templates: Vec::new(),
        node_id: random_u64(),
        listen_port: p2p.port(),
        bans: load_bans(&dir.join("bans.txt")),
        bans_path: dir.join("bans.txt"),
        allow_local,
        started: now(),
        pool: cfg.pool.clone().map(|p| crate::pool::Pool::new(p, dir.join("pool.json"))),
        epoch_dir: dir.join("epochs"),
        mempool_path: dir.join("mempool.dat"),
        mempool_saved: (0, 0),
        release: crate::release::load(&dir.join("release.bin"), &cfg.release_key),
        release_path: dir.join("release.bin"),
        auto_update: cfg.auto_update,
        release_key: cfg.release_key,
        faucet: cfg.faucet.clone().map(|f| crate::faucet::Faucet::new(f, dir.join("faucet.json"))),
        events: crate::watch::Events::default(),
        base_threads: cfg.threads.max(1),
        busy: false,
        max_upload: cfg.max_upload,
        upload_path: dir.join("upload.txt"),
        upload_start: 0,
        upload_base: 0,
    };
    state.load_upload();
    let restored = state.load_mempool();
    if restored > 0 {
        eprintln!("mempool: {restored} transactions restored");
    }
    let shared: Shared = Arc::new(Mutex::new(state));
    let stop = Arc::new(AtomicBool::new(false));
    // the current epoch's weights before anything can ask for them (otherwise the first request derives
    // them under the node's lock, and a second copy could be derived at the same time)
    let current = shared.lock().unwrap().chain.upcoming_epoch_seeds()[0];
    epoch_for(&shared, &current, &[]);

    {
        let shared = shared.clone();
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let _ = spawn_peer(shared.clone(), s, false);
            }
        });
    }
    {
        let (shared, stop, configured) = (shared.clone(), stop.clone(), cfg.connect.clone());
        let (interval, discover) = (cfg.peer_interval, cfg.discover);
        std::thread::spawn(move || connection_manager(shared, configured, interval, discover, stop));
    }
    let rpc = match cfg.rpc {
        Some(a) => Some(crate::rpc::serve(shared.clone(), a, cfg.rpc_token.clone())?),
        None => None,
    };
    let pool = match &cfg.pool {
        Some(p) => {
            let at = crate::pool::serve(shared.clone(), p.listen)?;
            eprintln!("pool on {at}");
            Some(at)
        }
        None => None,
    };
    if let Some(a) = cfg.explorer {
        let at = crate::explorer::serve(shared.clone(), a)?;
        eprintln!("explorer on http://{at}");
    }
    {
        let (shared, stop) = (shared.clone(), stop.clone());
        std::thread::spawn(move || epoch_preparer(shared, stop));
    }
    {
        let (shared, stop, notify) = (shared.clone(), stop.clone(), cfg.notify.clone());
        std::thread::spawn(move || crate::watch::watch(shared, notify, stop));
    }
    if cfg.auto_update {
        let (shared, dir) = (shared.clone(), dir.join("update"));
        std::thread::spawn(move || crate::release::updater(shared, dir));
    }
    if let Some(payee) = cfg.mine_to {
        let (shared, stop, interval) = (shared.clone(), stop.clone(), cfg.mine_interval);
        std::thread::spawn(move || cpu_miner(shared, payee, stop, interval));
    }
    Ok(Handle { shared, p2p, rpc, pool, stop })
}

/// Keep `--connect` peers connected, fill outbound slots from the address book, ping peers, save the book.
fn connection_manager(
    shared: Shared,
    configured: Vec<String>,
    interval: Duration,
    discover: bool,
    stop: Arc<AtomicBool>,
) {
    let mut rng = random_u64() | 1;
    let mut warned: HashSet<String> = HashSet::new();
    let (mut last_ping, mut last_save, mut last_mempool) = (0u64, now(), now());
    // a snapshot at start (after a replay), then every 10 minutes or 100 blocks while the tip moves
    let (mut last_snapshot, mut snapshot_tip, mut snapshot_height) = (0u64, None, 0u64);
    while !stop.load(Ordering::Relaxed) {
        for addr in &configured {
            let target = addr.to_socket_addrs().ok().and_then(|mut a| a.next());
            if let Some(t) = target {
                shared.lock().unwrap().book.add(t);
            }
            let connected = target.is_some_and(|t| shared.lock().unwrap().connected().contains(&t));
            if !connected {
                match connect(&shared, addr) {
                    Ok(()) => {
                        warned.remove(addr);
                    }
                    Err(e) => {
                        if warned.insert(addr.clone()) {
                            eprintln!("connect {addr}: {e} (retrying)");
                        }
                    }
                }
            }
        }
        if discover {
            let (missing, candidates) = {
                let st = shared.lock().unwrap();
                let missing = TARGET_OUTBOUND.saturating_sub(st.outbound_count());
                (missing, if missing > 0 { st.book.candidates(&st.connected(), now()) } else { Vec::new() })
            };
            let mut candidates = candidates;
            for _ in 0..missing.min(candidates.len()) {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let a = candidates.swap_remove((rng % candidates.len() as u64) as usize);
                shared.lock().unwrap().book.attempt(&a, now());
                if connect(&shared, &a.to_string()).is_err() {
                    shared.lock().unwrap().book.failed(&a);
                }
            }
        }
        let t = now();
        shared.lock().unwrap().expire_downloads();
        if t >= last_ping + PING_EVERY {
            last_ping = t;
            shared.lock().unwrap().broadcast(&Msg::Ping(t), None);
        }
        if t >= last_save + 300 {
            last_save = t;
            let mut st = shared.lock().unwrap();
            st.book.save();
            st.save_upload();
        }
        if t >= last_mempool + 60 {
            last_mempool = t;
            shared.lock().unwrap().save_mempool();
        }
        let (tip, height) = {
            let st = shared.lock().unwrap();
            (st.chain.tip(), st.chain.height())
        };
        if snapshot_tip != Some(tip) && (t >= last_snapshot + 600 || height >= snapshot_height + 100) {
            last_snapshot = t;
            (snapshot_tip, snapshot_height) = (Some(tip), height);
            write_snapshot(&shared);
        }
        std::thread::sleep(interval);
    }
    let mut st = shared.lock().unwrap();
    st.book.save();
    st.save_mempool();
    drop(st);
    write_snapshot(&shared);
}

fn write_snapshot(shared: &Shared) {
    let snap = shared.lock().unwrap().snapshot_bytes();
    if let Some((path, bytes)) = snap {
        if let Err(e) = crate::snapshot::save(&path, &bytes) {
            eprintln!("snapshot: {e}");
        }
    }
}

/// Derive the weights of the current and the next epoch off the lock, as soon as their seeds are known,
/// so block verification never waits for a derivation (7 s per epoch for TNet v1).
/// One epoch derivation at a time: two threads deriving the same weights would hold 1 GiB for nothing.
static DERIVING: Mutex<()> = Mutex::new(());

/// Weights for `seed`: from the cache, or derived without holding the node's lock (one derivation at a
/// time; weights other than `keep` are dropped first, so memory stays at two epochs).
pub fn epoch_for(shared: &Shared, seed: &Hash, keep: &[Hash]) -> Arc<tnet::Epoch> {
    let cached = |shared: &Shared| {
        let mut st = shared.lock().unwrap();
        st.chain.has_epoch(seed).then(|| st.chain.epoch(seed))
    };
    if let Some(e) = cached(shared) {
        return e;
    }
    let _one = DERIVING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = cached(shared) {
        return e; // derived by another thread meanwhile
    }
    let (params, dir) = {
        let mut st = shared.lock().unwrap();
        let mut k = keep.to_vec();
        k.push(*seed);
        st.chain.retain_epochs(&k);
        (st.chain.net.tnet, st.epoch_dir.clone())
    };
    let t = std::time::Instant::now();
    // large weights go to a file the OS caches (see `epochs`); small ones (regtest) stay in memory unless
    // REQUANT_EPOCH_FILES=1 (to exercise the file path in tests)
    let on_disk =
        params.layers * params.n * params.n >= 64 << 20 || std::env::var("REQUANT_EPOCH_FILES").as_deref() == Ok("1");
    let epoch = Arc::new(match on_disk.then(|| crate::epochs::open_or_derive(&dir, seed, params, keep)) {
        Some(Ok(e)) => e,
        Some(Err(e)) => {
            eprintln!("epoch weights file in {}: {e}; keeping them in memory", dir.display());
            tnet::Epoch::from_seed(seed, params)
        }
        None => tnet::Epoch::from_seed(seed, params),
    });
    shared.lock().unwrap().chain.insert_epoch(*seed, epoch.clone());
    if params.n > 1024 {
        eprintln!("epoch weights prepared in {:.1} s", t.elapsed().as_secs_f64());
    }
    epoch
}

fn epoch_preparer(shared: Shared, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let upcoming = {
            let st = shared.lock().unwrap();
            st.chain.upcoming_epoch_seeds()
        };
        for seed in &upcoming {
            // keep only the current epoch while preparing the next
            epoch_for(&shared, seed, &upcoming[..1]);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Mine on the tip, restarting when it changes. Practical for small work functions only.
fn cpu_miner(shared: Shared, payee: Hash, stop: Arc<AtomicBool>, interval: Duration) {
    const CHUNK: u64 = 4;
    while !stop.load(Ordering::Relaxed) {
        let (block, epoch, net, tip) = {
            let mut st = shared.lock().unwrap();
            let (b, seed) = st.new_work(&payee);
            let epoch = st.chain.epoch(&seed);
            (b, epoch, st.chain.net.clone(), st.chain.tip())
        };
        let mut nonce = 0u64;
        loop {
            if stop.load(Ordering::Relaxed) || shared.lock().unwrap().chain.tip() != tip {
                break;
            }
            if let Some(claim) = mine(&net, &epoch, &block.header, nonce, CHUNK) {
                let mut b = block.clone();
                b.claim = claim;
                let _ = shared.lock().unwrap().process_block(b, None);
                std::thread::sleep(interval);
                break;
            }
            nonce += CHUNK;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misbehaviour_points() {
        // hostile work is an immediate ban; a relayed bad transaction is not
        assert_eq!(misbehaviour("invalid block"), Some(BAN_SCORE));
        assert_eq!(misbehaviour("invalid header"), Some(BAN_SCORE));
        assert_eq!(misbehaviour("invalid transaction"), Some(10));
        assert_eq!(misbehaviour("message flood"), Some(1));
        assert_eq!(misbehaviour("malformed addresses"), Some(20));
        // not the peer's fault: the connection just ends
        assert_eq!(misbehaviour("protocol version"), None);
        assert_eq!(misbehaviour("connected to self"), None);
    }
}
