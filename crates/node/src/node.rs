//! Node: chain, mempool, storage, transaction index and peer address book behind one lock; a reader thread
//! and a writer thread per peer; block-first sync by locator; block, transaction and address relay; a
//! connection manager keeping configured and discovered peers connected; an optional CPU miner.

use crate::addrbook::{routable, AddrBook};
use crate::index::TxIndex;
use crate::mempool::Mempool;
use crate::msg::{read_msg, write_msg, Msg, HEADERS_PROTOCOL, MAX_ADDR, MAX_HEADERS, MAX_INV, MIN_PROTOCOL, PROTOCOL};
use crate::store::Store;
use requant_consensus::block::Block;
use requant_consensus::block::{Claim, Header};
use requant_consensus::chain::{mine, verify_claim, Accepted, Chain};
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
use std::sync::atomic::{AtomicBool, Ordering};
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

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_u64() -> u64 {
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
}

/// Default reorg limit: one epoch (a day on the test network).
pub fn default_max_reorg(net: &Network) -> u64 {
    net.epoch_len.max(100)
}

pub struct Peer {
    tx: Sender<Msg>,
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
    pub book: AddrBook,
    store: Store,
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
                let _ = p.tx.send(m.clone());
            }
        }
    }

    fn send(&self, peer: u64, m: Msg) {
        if let Some(p) = self.peers.get(&peer) {
            let _ = p.tx.send(m);
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

    fn ban(&mut self, ip: IpAddr) {
        if !ip.is_loopback() {
            self.bans.insert(ip, now() + BAN_SECS);
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
                    if let Err(e) = self.store.append(&bytes) {
                        eprintln!("store: {e}");
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
                Err(Error::Invalid("time too far in the future")) => {}
                Err(e) => {
                    if prevalidated {
                        // a valid header with an invalid body: that branch is dead
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
                for id in ids {
                    if let Some(b) = self.chain.block(&id) {
                        self.send(peer, Msg::Block(b.encode()));
                    } else if let Some(tx) = self.mempool.get(&id) {
                        self.send(peer, Msg::Tx(tx.encode()));
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
                        let _ = p.tx.send(Msg::GetBlocks(self.chain.locator()));
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
    let (tx, rx) = channel::<Msg>();
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
            addr,
            outbound,
            listen: outbound.then_some(addr),
            agent: String::new(),
            height: 0,
            since: now(),
            protocol: 0,
            inflight: 0,
        };
        st.peers.insert(id, peer);
        (id, st.hello(), magic(&st.chain.net))
    };
    let mut writer = BufWriter::new(stream.try_clone()?);
    std::thread::spawn(move || {
        for m in rx {
            if write_msg(&mut writer, &magic, &m).is_err() {
                break;
            }
        }
    });
    let _ = tx.send(hello);
    let reader_stream = stream.try_clone()?;
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader_stream);
        while let Ok(m) = read_msg(&mut reader, &magic) {
            let result = match m {
                Msg::Headers(bytes) => handle_headers(&shared, id, &bytes),
                m => shared.lock().unwrap().on_message(id, m),
            };
            let mut st = shared.lock().unwrap();
            if let Err(why) = result {
                if why != "connected to self" {
                    eprintln!("peer {addr}: disconnecting ({why})");
                    if why.starts_with("invalid") || why.starts_with("malformed") {
                        st.ban(addr.ip());
                    }
                }
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
        let (epoch, threads) = {
            let mut st = shared.lock().unwrap();
            match st.headers.check_context(&h, &c, now()) {
                Ok(None) => continue,
                Ok(Some(seed)) => {
                    let threads = st.headers.threads();
                    (st.chain.epoch(&seed), threads)
                }
                Err(Error::UnknownParent) => {
                    // the peer's chain forks below what it was asked for: ask again from our headers
                    let loc = st.headers.locator();
                    st.send(peer, Msg::GetHeaders(loc));
                    return Ok(());
                }
                Err(Error::Invalid("time too far in the future")) => return Ok(()),
                Err(_) => return Err("invalid header"),
            }
        };
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

/// Open storage, replay it, and start listening, connecting, RPC and mining as configured.
pub fn start(cfg: Config) -> io::Result<Handle> {
    let dir = cfg.datadir.join(cfg.net.name);
    let (store, records) = Store::open(&dir)?;
    let mut chain = Chain::new(cfg.net.clone(), cfg.threads);
    chain.set_max_reorg(cfg.max_reorg);
    let mut replayed = 0;
    for rec in records {
        match Block::decode(&rec, &cfg.net)
            .map_err(|e| e.to_string())
            .and_then(|b| chain.accept_trusted(b).map_err(|e| e.to_string()))
        {
            Ok(_) => replayed += 1,
            Err(e) => eprintln!("replay: skipping a stored block ({e})"),
        }
    }
    if replayed > 0 {
        eprintln!("replayed {replayed} blocks, height {}", chain.height());
    }
    let mut index = TxIndex::default();
    index.sync(&chain);
    let mut headers = HeaderChain::new(cfg.net.clone(), cfg.threads);
    headers.set_max_reorg(cfg.max_reorg);
    for h in 1..=chain.height() {
        let b = chain.block(&chain.active_id(h).unwrap()).unwrap();
        headers.add_valid(&b.header, &b.claim);
    }
    let allow_local = cfg.net.name == "regtest";
    let listener = TcpListener::bind(cfg.listen)?;
    let p2p = listener.local_addr()?;
    let state = State {
        chain,
        headers,
        inflight: HashMap::new(),
        mempool: Mempool::default(),
        index,
        book: AddrBook::load(Some(dir.join("peers.txt")), allow_local),
        store,
        orphans: HashMap::new(),
        orphan_bytes: 0,
        peers: HashMap::new(),
        next_peer: 0,
        templates: Vec::new(),
        node_id: random_u64(),
        listen_port: p2p.port(),
        bans: HashMap::new(),
        allow_local,
        started: now(),
        pool: cfg.pool.clone().map(|p| crate::pool::Pool::new(p, dir.join("pool.json"))),
    };
    let shared: Shared = Arc::new(Mutex::new(state));
    let stop = Arc::new(AtomicBool::new(false));

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
    let (mut last_ping, mut last_save) = (0u64, now());
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
            shared.lock().unwrap().book.save();
        }
        std::thread::sleep(interval);
    }
    shared.lock().unwrap().book.save();
}

/// Derive the weights of the current and the next epoch off the lock, as soon as their seeds are known,
/// so block verification never waits for a derivation (7 s per epoch for TNet v1).
fn epoch_preparer(shared: Shared, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let (missing, params) = {
            let st = shared.lock().unwrap();
            let seeds: Vec<Hash> =
                st.chain.upcoming_epoch_seeds().into_iter().filter(|s| !st.chain.has_epoch(s)).collect();
            (seeds, st.chain.net.tnet)
        };
        for seed in missing {
            let t = std::time::Instant::now();
            let epoch = Arc::new(tnet::Epoch::from_seed(&seed, params));
            shared.lock().unwrap().chain.insert_epoch(seed, epoch);
            if params.n > 1024 {
                eprintln!("epoch weights prepared in {:.1} s", t.elapsed().as_secs_f64());
            }
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
