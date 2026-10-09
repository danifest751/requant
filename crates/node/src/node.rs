//! Node: chain + mempool + storage behind one lock, a thread per peer (reader) with a writer thread fed by
//! a channel, block-first sync by locator, block/transaction relay, and an optional CPU miner.

use crate::mempool::Mempool;
use crate::msg::{read_msg, write_msg, Msg, MAX_INV, PROTOCOL};
use crate::store::Store;
use requant_consensus::block::Block;
use requant_consensus::chain::{mine, Accepted, Chain};
use requant_consensus::params::Network;
use requant_consensus::tx::{Hash, Tx};
use requant_consensus::Error;
use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_PEERS: usize = 32;
pub const MAX_ORPHANS: usize = 256;
const MAX_TEMPLATES: usize = 16;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone)]
pub struct Config {
    pub net: Network,
    pub datadir: PathBuf,
    pub listen: SocketAddr,
    pub rpc: Option<SocketAddr>,
    pub connect: Vec<String>,
    /// Mine on the CPU, paying this key hash (practical on regtest only).
    pub mine_to: Option<Hash>,
    /// Pause between mined blocks (regtest).
    pub mine_interval: Duration,
    /// Threads for verifying work claims.
    pub threads: usize,
}

struct Peer {
    tx: Sender<Msg>,
    addr: SocketAddr,
    height: u64,
    inflight: usize,
}

pub struct State {
    pub chain: Chain,
    pub mempool: Mempool,
    store: Store,
    orphans: HashMap<Hash, Block>,
    peers: HashMap<u64, Peer>,
    next_peer: u64,
    /// Work handed out by `getwork`, by header digest.
    templates: Vec<(Hash, Block)>,
}

pub type Shared = Arc<Mutex<State>>;

pub struct Handle {
    pub shared: Shared,
    pub p2p: SocketAddr,
    pub rpc: Option<SocketAddr>,
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

    pub fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.peers.values().map(|p| p.addr).collect()
    }

    /// Accept a block from a peer (`from`) or a local miner; relay and persist it, then resolve orphans.
    /// `Err` means the peer sent something invalid.
    pub fn process_block(&mut self, block: Block, from: Option<u64>) -> Result<Option<Accepted>, Error> {
        let mut queue = vec![block];
        let mut first = None;
        while let Some(b) = queue.pop() {
            let id = b.id(&self.chain.net);
            let bytes = b.encode();
            match self.chain.accept(b.clone(), now()) {
                Ok(acc) => {
                    if first.is_none() {
                        first = Some(acc);
                    }
                    if let Err(e) = self.store.append(&bytes) {
                        eprintln!("store: {e}");
                    }
                    if acc != Accepted::SideChain {
                        self.mempool.revalidate(&self.chain);
                    }
                    self.broadcast(&Msg::Inv(vec![id]), from);
                    let children: Vec<Hash> =
                        self.orphans.iter().filter(|(_, o)| o.header.prev == id).map(|(k, _)| *k).collect();
                    for k in children {
                        queue.push(self.orphans.remove(&k).unwrap());
                    }
                }
                Err(Error::Duplicate) => {}
                Err(Error::UnknownParent) => {
                    if self.orphans.len() >= MAX_ORPHANS {
                        let k = *self.orphans.keys().next().unwrap();
                        self.orphans.remove(&k);
                    }
                    self.orphans.insert(id, b);
                    if let Some(p) = from {
                        self.send(p, Msg::GetBlocks(self.chain.locator()));
                    }
                }
                Err(Error::Invalid("time too far in the future")) => {}
                Err(e) => {
                    if first.is_none() {
                        return Err(e);
                    }
                }
            }
        }
        Ok(first)
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
        let txs = self.mempool.select(900_000);
        let net = &self.chain.net;
        let time = if net.name == "regtest" {
            // on-schedule timestamps keep the regtest difficulty constant however fast blocks come
            net.genesis_time + net.spacing as u64 * (self.chain.height() + 1)
        } else {
            now()
        };
        let b = self.chain.template(payee, txs, time);
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

    fn on_message(&mut self, peer: u64, m: Msg) -> Result<(), &'static str> {
        match m {
            Msg::Hello { protocol, height, tip } => {
                if protocol != PROTOCOL {
                    return Err("protocol version");
                }
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.height = height;
                }
                if height > self.chain.height() || !self.chain.contains(&tip) {
                    self.send(peer, Msg::GetBlocks(self.chain.locator()));
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
                    if p.inflight == 0 && p.height > ours {
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
fn spawn_peer(shared: Shared, stream: TcpStream) -> io::Result<()> {
    let addr = stream.peer_addr()?;
    stream.set_nodelay(true)?;
    let (tx, rx) = channel::<Msg>();
    let (id, hello, magic) = {
        let mut st = shared.lock().unwrap();
        if st.peers.len() >= MAX_PEERS {
            return Ok(());
        }
        let id = st.next_peer;
        st.next_peer += 1;
        st.peers.insert(id, Peer { tx: tx.clone(), addr, height: 0, inflight: 0 });
        let hello = Msg::Hello { protocol: PROTOCOL, height: st.chain.height(), tip: st.chain.tip() };
        (id, hello, magic(&st.chain.net))
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
            let mut st = shared.lock().unwrap();
            if let Err(why) = st.on_message(id, m) {
                eprintln!("peer {addr}: disconnecting ({why})");
                break;
            }
        }
        shared.lock().unwrap().peers.remove(&id);
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    Ok(())
}

/// Connect to `addr` (host:port) and run the peer.
pub fn connect(shared: &Shared, addr: &str) -> io::Result<()> {
    let sa = addr.to_socket_addrs()?.next().ok_or_else(|| io::Error::other("no address"))?;
    let stream = TcpStream::connect_timeout(&sa, Duration::from_secs(10))?;
    spawn_peer(shared.clone(), stream)
}

/// Open storage, replay it, and start listening, connecting, RPC and mining as configured.
pub fn start(cfg: Config) -> io::Result<Handle> {
    let (store, records) = Store::open(&cfg.datadir.join(cfg.net.name))?;
    let mut chain = Chain::new(cfg.net.clone(), cfg.threads);
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
    let state = State {
        chain,
        mempool: Mempool::default(),
        store,
        orphans: HashMap::new(),
        peers: HashMap::new(),
        next_peer: 0,
        templates: Vec::new(),
    };
    let shared: Shared = Arc::new(Mutex::new(state));
    let stop = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind(cfg.listen)?;
    let p2p = listener.local_addr()?;
    {
        let shared = shared.clone();
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let _ = spawn_peer(shared.clone(), s);
            }
        });
    }
    for addr in &cfg.connect {
        if let Err(e) = connect(&shared, addr) {
            eprintln!("connect {addr}: {e}");
        }
    }
    let rpc = match cfg.rpc {
        Some(a) => Some(crate::rpc::serve(shared.clone(), a)?),
        None => None,
    };
    if let Some(payee) = cfg.mine_to {
        let (shared, stop, interval) = (shared.clone(), stop.clone(), cfg.mine_interval);
        std::thread::spawn(move || cpu_miner(shared, payee, stop, interval));
    }
    Ok(Handle { shared, p2p, rpc, stop })
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
