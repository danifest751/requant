//! Read-only block explorer served by the node (`--explorer ADDR`): network summary, latest blocks, block,
//! transaction and address pages, search. Plain HTML, no scripts; every value shown comes from the node's
//! own state and is parsed before use, so nothing user-supplied is echoed.

use crate::node::{now, Shared};
use requant_consensus::address::{address, format_amount, parse_address};
use requant_consensus::block::Block;
use requant_consensus::tx::{Hash, Tx};
use requant_consensus::u256::U256;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

const LATEST: u64 = 25;
/// Requests served at once; more are refused.
const MAX_ACTIVE: usize = 32;
static ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const HASHRATE_WINDOW: u64 = 60;

pub fn serve(shared: Shared, addr: SocketAddr) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    std::thread::spawn(move || {
        use std::sync::atomic::Ordering::SeqCst;
        for s in listener.incoming().flatten() {
            if ACTIVE.fetch_add(1, SeqCst) >= MAX_ACTIVE {
                ACTIVE.fetch_sub(1, SeqCst);
                continue; // dropping the stream closes it
            }
            let shared = shared.clone();
            std::thread::spawn(move || {
                let _ = handle(&shared, s);
                ACTIVE.fetch_sub(1, SeqCst);
            });
        }
    });
    Ok(local)
}

fn handle(shared: &Shared, stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.by_ref().take(2048).read_line(&mut line)?;
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    // read the headers, keeping the host name (shown in the pool's connect command)
    let mut h = String::new();
    let mut host = String::from("this-host");
    for _ in 0..64 {
        h.clear();
        if reader.by_ref().take(4096).read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("host:") {
            let name = v.trim().rsplit_once(':').map(|(n, _)| n.to_string()).unwrap_or_else(|| v.trim().to_string());
            let clean: String =
                name.chars().filter(|c| c.is_ascii_alphanumeric() || ".-".contains(*c)).take(253).collect();
            if !clean.is_empty() {
                host = clean;
            }
        }
    }
    let (status, body) = route(shared, &path, &host);
    let mut stream = stream;
    if let Some(loc) = body.strip_prefix("REDIRECT ") {
        return write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<Hash> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..32).map(|k| u8::from_str_radix(&s[2 * k..2 * k + 2], 16).ok()).collect::<Option<Vec<u8>>>()?.try_into().ok()
}

fn short(h: &str) -> String {
    if h.len() > 20 {
        format!("{}…{}", &h[..10], &h[h.len() - 8..])
    } else {
        h.to_string()
    }
}

fn u256_f64(x: &U256) -> f64 {
    x.0.iter().enumerate().map(|(k, &l)| l as f64 * 2f64.powi(64 * k as i32)).sum()
}

fn si(x: f64) -> String {
    let units = [("", 1.0), ("k", 1e3), ("M", 1e6), ("G", 1e9), ("T", 1e12), ("P", 1e15)];
    let (u, d) = units.iter().rev().find(|(_, d)| x >= *d).copied().unwrap_or(("", 1.0));
    format!("{:.2} {u}", x / d)
}

/// `YYYY-MM-DD HH:MM:SS` UTC.
fn utc(t: u64) -> String {
    let (days, secs) = ((t / 86400) as i64, t % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

fn ago(t: u64) -> String {
    let d = now().saturating_sub(t);
    match d {
        0..=59 => format!("{d} s"),
        60..=3599 => format!("{} min", d / 60),
        3600..=86399 => format!("{} h {} min", d / 3600, d / 60 % 60),
        _ => format!("{} d", d / 86400),
    }
}

const STYLE: &str = r#"
:root{--bg:#f6f7f9;--fg:#0f172a;--mut:#64748b;--line:#e2e8f0;--card:#ffffff;--acc:#0d9488;--acc2:#6366f1;
--ok:#16a34a;--okbg:#dcfce7;--warn:#b45309;--warnbg:#fef3c7;--bad:#dc2626;--badbg:#fee2e2;--head:#ffffff;--shadow:0 1px 2px rgba(15,23,42,.06),0 4px 16px rgba(15,23,42,.04)}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--fg:#e2e8f0;--mut:#94a3b8;--line:#1e293b;--card:#111827;--acc:#2dd4bf;--acc2:#818cf8;
--ok:#4ade80;--okbg:rgba(74,222,128,.12);--warn:#fbbf24;--warnbg:rgba(251,191,36,.12);--bad:#f87171;--badbg:rgba(248,113,113,.12);--head:#0f172a;--shadow:0 1px 2px rgba(0,0,0,.4)}}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.top{background:var(--head);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.top .in{max-width:1180px;margin:0 auto;padding:10px 16px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;color:var(--fg);font-weight:700;font-size:18px}.brand:hover{text-decoration:none}
.logo{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--acc),var(--acc2));display:grid;place-items:center;color:#fff;font-weight:800;font-size:16px}
.tag{font-size:11px;font-weight:600;color:var(--acc);border:1px solid var(--acc);border-radius:999px;padding:1px 8px;letter-spacing:.04em;text-transform:uppercase}
nav{display:flex;gap:4px}nav a{color:var(--mut);padding:6px 10px;border-radius:8px;font-weight:500}nav a:hover,nav a.on{color:var(--fg);background:var(--bg);text-decoration:none}
form{flex:1;display:flex;min-width:220px}input{flex:1;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--fg);font-size:14px}
main{max-width:1180px;margin:0 auto;padding:20px 16px}
h1{font-size:24px;margin:4px 0 2px}h2{font-size:16px;margin:28px 0 10px;color:var(--fg)}
.sub{color:var(--mut);margin:0 0 16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
.card .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.card .v{font-size:22px;font-weight:700;margin-top:2px}
.card .h{color:var(--mut);font-size:12px}
.hero{border-radius:16px;padding:22px;color:#fff;background:linear-gradient(135deg,#0f766e,#4f46e5);box-shadow:var(--shadow);display:grid;gap:14px;grid-template-columns:1.2fr 1fr}
.hero .big{font-size:40px;font-weight:800;line-height:1.1}.hero .lbl{opacity:.85;font-size:13px;text-transform:uppercase;letter-spacing:.06em}
.hero .row{display:flex;gap:26px;flex-wrap:wrap;margin-top:10px}.hero .row b{display:block;font-size:20px}.hero .row span{opacity:.8;font-size:12px}
.connect{background:rgba(255,255,255,.12);border-radius:12px;padding:14px}.connect p{margin:0 0 8px;font-size:13px;opacity:.9}
code.cmd{display:block;user-select:all;cursor:copy;background:rgba(0,0,0,.28);color:#fff;border-radius:8px;padding:10px 12px;font:13px ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
@media (max-width:760px){.hero{grid-template-columns:1fr}}
.tbl{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow-x:auto;box-shadow:var(--shadow)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
tr:last-child td{border-bottom:none}tbody tr:hover{background:var(--bg)}th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.r,th.r{text-align:right}.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}.mut{color:var(--mut)}
.plus{color:var(--ok)}.minus{color:var(--bad)}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
.b-ok{color:var(--ok);background:var(--okbg)}.b-warn{color:var(--warn);background:var(--warnbg)}.b-bad{color:var(--bad);background:var(--badbg)}
.bar{height:6px;border-radius:999px;background:var(--line);overflow:hidden;min-width:80px}.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--acc),var(--acc2))}
details summary{cursor:pointer;list-style:none}details summary::-webkit-details-marker{display:none}details summary .chev{display:inline-block;transition:transform .15s;color:var(--mut);margin-right:6px}
details[open] summary .chev{transform:rotate(90deg)}
.wk{margin:8px 0 2px 22px;font-size:13px}.wk td{padding:6px 10px;border:none}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.on-dot{background:var(--ok)}.off-dot{background:var(--line)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:var(--shadow)}
dt{color:var(--mut)}dd{margin:0;word-break:break-all}
footer{color:var(--mut);font-size:13px;margin:32px 0 8px;text-align:center}
.empty{color:var(--mut);padding:18px;text-align:center}
.wrap{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow-x:auto;box-shadow:var(--shadow)}
.card b{display:block;font-size:20px;font-weight:700}.card span{color:var(--mut);font-size:12px}
"#;

fn page(title: &str, body: &str, refresh: bool) -> String {
    let meta = if refresh { "<meta http-equiv=\"refresh\" content=\"30\">" } else { "" };
    let on = |t: &str| if title == t { " class=\"on\"" } else { "" };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">{meta}\
<title>{title} · Requant</title><style>{STYLE}</style></head><body>\
<div class=\"top\"><div class=\"in\"><a class=\"brand\" href=\"/\"><span class=\"logo\">R</span>Requant</a><span class=\"tag\">testnet</span>\
<nav><a href=\"/\"{}>Explorer</a><a href=\"/pool\"{}>Pool</a></nav>\
<form action=\"/search\"><input name=\"q\" placeholder=\"Search block height, block id, txid or address\" aria-label=\"Search\"></form></div></div>\
<main>{body}<footer>Requant test network · test coins have no value · <a href=\"https://github.com/danifest751/requant\">source</a></footer></main></body></html>",
        on("Requant test network"),
        on("Mining pool")
    )
}

fn not_found(what: &str) -> (&'static str, String) {
    ("404 Not Found", page("Not found", &format!("<h2>{what} not found</h2>"), false))
}

fn route(shared: &Shared, path: &str, host: &str) -> (&'static str, String) {
    let path = path.split('#').next().unwrap_or("/");
    let (p, query) = path.split_once('?').unwrap_or((path, ""));
    let st = shared.lock().unwrap();
    let net = &st.chain.net;
    match p.trim_end_matches('/').split('/').collect::<Vec<_>>().as_slice() {
        [""] => ("200 OK", home(&st)),
        ["", "block", key] => {
            let id = key
                .parse::<u64>()
                .ok()
                .and_then(|h| st.chain.active_id(h))
                .or_else(|| unhex32(key).filter(|id| st.chain.contains(id)));
            match id {
                Some(id) => ("200 OK", block_page(&st, &id)),
                None => not_found("Block"),
            }
        }
        ["", "tx", key] => match unhex32(key) {
            Some(txid) => tx_page(&st, &txid).map(|b| ("200 OK", b)).unwrap_or_else(|| not_found("Transaction")),
            None => not_found("Transaction"),
        },
        ["", "address", a] => match parse_address(net, a) {
            Ok(owner) => ("200 OK", address_page(&st, &owner)),
            Err(_) => not_found("Address"),
        },
        ["", "pool"] => match crate::pool::stats(&st) {
            Some(s) => ("200 OK", pool_page(&s, host)),
            None => not_found("Pool (this node runs none)"),
        },
        ["", "search"] => {
            let q: String = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("q="))
                .unwrap_or("")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(100)
                .collect();
            let target = if q.parse::<u64>().is_ok() {
                Some(format!("/block/{q}"))
            } else if let Some(h) = unhex32(&q.to_ascii_lowercase()) {
                Some(if st.chain.contains(&h) { format!("/block/{}", hex(&h)) } else { format!("/tx/{}", hex(&h)) })
            } else if parse_address(net, &q).is_ok() {
                Some(format!("/address/{}", q.to_ascii_lowercase()))
            } else {
                None
            };
            match target {
                Some(t) => ("302 Found", format!("REDIRECT {t}")),
                None => not_found("Search result"),
            }
        }
        _ => not_found("Page"),
    }
}

fn miner_of(b: &Block, net: &requant_consensus::params::Network) -> String {
    b.txs.first().and_then(|t| t.outputs().first()).map(|o| address(net, &o.pkh)).unwrap_or_default()
}

fn home(st: &crate::node::State) -> String {
    let chain = &st.chain;
    let net = &chain.net;
    let tip_h = chain.height();
    let tip = chain.block(&chain.tip()).unwrap();
    let work = u256_f64(&U256::work(&tip.header.target));
    // hashrate from the last HASHRATE_WINDOW blocks: expected tickets / elapsed time
    let from = tip_h.saturating_sub(HASHRATE_WINDOW);
    let (mut tickets, t0) = (0f64, chain.block(&chain.active_id(from).unwrap()).unwrap().header.time);
    for h in from + 1..=tip_h {
        tickets += u256_f64(&U256::work(&chain.block(&chain.active_id(h).unwrap()).unwrap().header.target));
    }
    let span = tip.header.time.saturating_sub(t0).max(1) as f64;
    let rate = if tip_h > from { tickets / span } else { 0.0 };
    let avg = if tip_h > from { span / (tip_h - from) as f64 } else { 0.0 };
    let cards = [
        (format!("{tip_h}"), "height".to_string()),
        (format!("{}tickets/s", si(rate)), format!("network rate (last {} blocks)", tip_h - from)),
        (format!("{avg:.0} s"), "average block time (target 60 s)".into()),
        (si(work), "tickets per block (difficulty)".into()),
        (format!("{} RQT", format_amount(chain.issued()).split('.').next().unwrap_or("0")), "issued".into()),
        (format!("{}", st.mempool.len()), "unconfirmed transactions".into()),
        (format!("{}", st.peer_count()), "peers of this node".into()),
        (
            format!("{}", chain.height() / net.epoch_len),
            format!("epoch (TNet weights change every {} blocks)", net.epoch_len),
        ),
    ];
    let mut body = String::from("<div class=\"cards\">");
    for (v, l) in cards {
        body += &format!("<div class=\"card\"><div class=\"k\">{l}</div><div class=\"v\">{v}</div></div>");
    }
    body += "</div><h2>Latest blocks</h2><div class=\"wrap\"><table><tr><th>Height</th><th>Block</th><th>Time (UTC)</th><th>Age</th><th class=\"r\">Txs</th><th>Mined by</th></tr>";
    for h in (tip_h.saturating_sub(LATEST - 1)..=tip_h).rev() {
        let id = chain.active_id(h).unwrap();
        let b = chain.block(&id).unwrap();
        let miner = miner_of(&b, net);
        body += &format!(
            "<tr><td><a href=\"/block/{h}\">{h}</a></td><td class=\"mono\"><a href=\"/block/{}\">{}</a></td><td>{}</td><td class=\"mut\">{}</td><td class=\"r\">{}</td><td class=\"mono\"><a href=\"/address/{miner}\">{}</a></td></tr>",
            hex(&id),
            short(&hex(&id)),
            utc(b.header.time),
            ago(b.header.time),
            b.txs.len(),
            short(&miner)
        );
    }
    body += "</table></div>";
    page("Requant test network", &body, true)
}

fn block_page(st: &crate::node::State, id: &Hash) -> String {
    let chain = &st.chain;
    let net = &chain.net;
    let b = chain.block(id).unwrap();
    let h = b.header.height;
    let on_best = chain.active_id(h) == Some(*id);
    let conf = if on_best { format!("{}", chain.height() - h + 1) } else { "side chain".into() };
    let next = if on_best { chain.active_id(h + 1) } else { None };
    let mut body = format!("<h2>Block {h}</h2><dl>");
    let rows = [
        ("Id", format!("<span class=\"mono\">{}</span>", hex(id))),
        (
            "Previous",
            if h == 0 {
                "—".into()
            } else {
                format!("<a class=\"mono\" href=\"/block/{0}\">{0}</a>", hex(&b.header.prev))
            },
        ),
        ("Next", next.map(|n| format!("<a class=\"mono\" href=\"/block/{0}\">{0}</a>", hex(&n))).unwrap_or("—".into())),
        ("Time (UTC)", format!("{} <span class=\"mut\">({} ago)</span>", utc(b.header.time), ago(b.header.time))),
        ("Confirmations", conf),
        ("Target", format!("<span class=\"mono\">{}</span>", hex(&b.header.target.to_be_bytes()))),
        ("Tickets per block", si(u256_f64(&U256::work(&b.header.target)))),
        ("Work claim", format!("nonce {}, row {}, piece {}", b.claim.nonce, b.claim.i, b.claim.c)),
        ("Size", format!("{} bytes", b.encode().len())),
        ("Mined by", format!("<a class=\"mono\" href=\"/address/{0}\">{0}</a>", miner_of(&b, net))),
    ];
    for (k, v) in rows {
        body += &format!("<dt>{k}</dt><dd>{v}</dd>");
    }
    body += "</dl><h2>Transactions</h2><div class=\"wrap\"><table><tr><th>#</th><th>Txid</th><th>Kind</th><th class=\"r\">Outputs total (RQT)</th></tr>";
    for (k, tx) in b.txs.iter().enumerate() {
        let txid = hex(&tx.txid());
        let total: u64 = tx.outputs().iter().map(|o| o.value).sum();
        body += &format!(
            "<tr><td>{k}</td><td class=\"mono\"><a href=\"/tx/{txid}\">{}</a></td><td>{}</td><td class=\"r\">{}</td></tr>",
            short(&txid),
            if tx.is_coinbase() { "coinbase" } else { "transfer" },
            format_amount(total)
        );
    }
    body += "</table></div>";
    page(&format!("Block {h}"), &body, false)
}

fn tx_page(st: &crate::node::State, txid: &Hash) -> Option<String> {
    let chain = &st.chain;
    let net = &chain.net;
    let (tx, height) = match st.index.locate(txid) {
        Some(loc) => (chain.block(&loc.block)?.txs[loc.pos as usize].clone(), Some(loc.height)),
        None => (st.mempool.get(txid)?.clone(), None),
    };
    let status = match height {
        Some(h) => format!("in block <a href=\"/block/{h}\">{h}</a>, {} confirmations", chain.height() - h + 1),
        None => "unconfirmed (in the pool)".into(),
    };
    let mut body = format!(
        "<h2>Transaction</h2><dl><dt>Txid</dt><dd class=\"mono\">{}</dd><dt>Status</dt><dd>{status}</dd>",
        hex(txid)
    );
    let mut total_in = 0u64;
    let mut ins = String::new();
    match &tx {
        Tx::Coinbase { height, .. } => {
            ins += &format!("<tr><td colspan=\"3\">newly mined coins (coinbase of block {height})</td></tr>")
        }
        Tx::Transfer { inputs, .. } => {
            for i in inputs {
                let out = st.index.output(&i.prev).or_else(|| {
                    st.mempool.get(&i.prev.txid).and_then(|t| t.outputs().get(i.prev.vout as usize).copied())
                });
                total_in += out.map(|o| o.value).unwrap_or(0);
                let owner = out.map(|o| address(net, &o.pkh)).unwrap_or_default();
                ins += &format!(
                    "<tr><td class=\"mono\"><a href=\"/address/{owner}\">{}</a></td><td class=\"mono\"><a href=\"/tx/{1}\">{2}</a>:{3}</td><td class=\"r\">{4}</td></tr>",
                    short(&owner),
                    hex(&i.prev.txid),
                    short(&hex(&i.prev.txid)),
                    i.prev.vout,
                    out.map(|o| format_amount(o.value)).unwrap_or("?".into())
                );
            }
        }
    }
    let total_out: u64 = tx.outputs().iter().map(|o| o.value).sum();
    let fee = if tx.is_coinbase() { 0 } else { total_in.saturating_sub(total_out) };
    body += &format!(
        "<dt>Fee</dt><dd>{} RQT</dd><dt>Size</dt><dd>{} bytes</dd></dl>",
        format_amount(fee),
        tx.encode().len()
    );
    body += &format!("<h2>Inputs</h2><div class=\"wrap\"><table><tr><th>From</th><th>Spends</th><th class=\"r\">RQT</th></tr>{ins}</table></div>");
    body += "<h2>Outputs</h2><div class=\"wrap\"><table><tr><th>#</th><th>To</th><th class=\"r\">RQT</th></tr>";
    for (k, o) in tx.outputs().iter().enumerate() {
        let a = address(net, &o.pkh);
        let tag = if o.pkh == net.dev_fund { " <span class=\"mut\">(development fund)</span>" } else { "" };
        body += &format!(
            "<tr><td>{k}</td><td class=\"mono\"><a href=\"/address/{a}\">{a}</a>{tag}</td><td class=\"r\">{}</td></tr>",
            format_amount(o.value)
        );
    }
    body += "</table></div>";
    Some(page("Transaction", &body, false))
}

fn address_page(st: &crate::node::State, owner: &Hash) -> String {
    let chain = &st.chain;
    let net = &chain.net;
    let a = address(net, owner);
    let next = chain.height() + 1;
    let (mut spendable, mut immature) = (0u64, 0u64);
    let coins = chain.coins_of(owner);
    for (_, c) in &coins {
        if c.coinbase && next - c.height < net.maturity {
            immature += c.output.value;
        } else {
            spendable += c.output.value;
        }
    }
    let pending: i128 = st.mempool.activity(chain, owner).iter().map(|(_, r, s, _)| *r as i128 - *s as i128).sum();
    let tag = if *owner == net.dev_fund { "<p class=\"mut\">Development fund (CHAIN.md §8).</p>" } else { "" };
    let mut body = format!(
        "<h2>Address</h2><p class=\"mono\">{a}</p>{tag}<div class=\"cards\"><div class=\"card\"><b>{} RQT</b><span>spendable</span></div>\
<div class=\"card\"><b>{} RQT</b><span>immature (newly mined, {} blocks)</span></div><div class=\"card\"><b>{}{} RQT</b><span>unconfirmed change</span></div>\
<div class=\"card\"><b>{}</b><span>unspent outputs</span></div></div>",
        format_amount(spendable),
        format_amount(immature),
        net.maturity,
        if pending < 0 { "-" } else { "" },
        format_amount(pending.unsigned_abs() as u64),
        coins.len()
    );
    body += "<h2>History</h2><div class=\"wrap\"><table><tr><th>Height</th><th>Txid</th><th>Time (UTC)</th><th class=\"r\">Amount (RQT)</th></tr>";
    for (txid, r, s, _) in st.mempool.activity(chain, owner).into_iter().rev() {
        body += &row(&hex(&txid), "pending".into(), String::new(), r, s);
    }
    for e in st.index.history(owner, 200) {
        let time =
            chain.active_id(e.height).and_then(|id| chain.block(&id)).map(|b| utc(b.header.time)).unwrap_or_default();
        body += &row(&hex(&e.txid), format!("<a href=\"/block/{0}\">{0}</a>", e.height), time, e.received, e.sent);
    }
    body += "</table></div>";
    page("Address", &body, false)
}

fn badge(status: &str) -> String {
    let (cls, text) = match status {
        "credited" => ("b-ok", "credited"),
        "orphaned" => ("b-bad", "orphaned"),
        _ => ("b-warn", "maturing"),
    };
    format!("<span class=\"badge {cls}\">{text}</span>")
}

fn pool_page(s: &serde_json::Value, host: &str) -> String {
    let n = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
    let f = |v: &serde_json::Value| v.as_f64().unwrap_or(0.0);
    let min_payout = n(&s["min_payout_atoms"]).max(1);
    let endpoint = format!("{host}:{}", n(&s["port"]));
    let miners = s["miners"].as_array().cloned().unwrap_or_default();
    let devices: usize = miners.iter().map(|m| m["workers"].as_array().map(|w| w.len()).unwrap_or(0)).sum();
    let blocks = s["blocks"].as_array().cloned().unwrap_or_default();
    let mut body = format!(
        "<div class=\"hero\"><div><div class=\"lbl\">Pool rate · last 10 min</div><div class=\"big\">{}tickets/s</div>\
<div class=\"row\"><div><b>{}</b><span>addresses</span></div><div><b>{}</b><span>devices</span></div>\
<div><b>{}</b><span>blocks found</span></div><div><b>{} %</b><span>fee</span></div><div><b>{} RQT</b><span>min payout</span></div></div></div>\
<div class=\"connect\"><p>Connect a GPU (CPPminer, <span style=\"opacity:.8\">--worker names a device</span>):</p>\
<code class=\"cmd\">cppminer --algo tnet --rpc {endpoint} --payee YOUR_KEY_HASH --worker rig1</code>\
<p style=\"margin-top:10px\">PPLNS over the last shares · 2^{} tickets per share · paid automatically after {} confirmations, every 10 min</p></div></div>",
        si(f(&s["tickets_per_s"])),
        miners.len(),
        devices,
        n(&s["blocks_total"]),
        s["fee_percent"],
        format_amount(n(&s["min_payout_atoms"])).trim_end_matches('0').trim_end_matches('.'),
        s["share_bits"],
        n(&s["maturity"]),
    );
    body += "<h2>Miners</h2><div class=\"tbl\"><table><thead><tr><th>Address · devices</th><th class=\"r\">Rate</th><th class=\"r\">Shares</th>\
<th class=\"r\">Maturing</th><th class=\"r\">Balance</th><th>To payout</th><th class=\"r\">Paid</th></tr></thead><tbody>";
    if miners.is_empty() {
        body += "<tr><td colspan=\"7\" class=\"empty\">No miners yet — connect one with the command above.</td></tr>";
    }
    for m in &miners {
        let a = m["address"].as_str().unwrap_or("");
        let bal = n(&m["balance"]);
        let pct = (bal as f64 / min_payout as f64 * 100.0).min(100.0);
        let mut workers = String::new();
        for w in m["workers"].as_array().into_iter().flatten() {
            let active = now().saturating_sub(n(&w["last_share"])) < 600;
            workers += &format!(
                "<tr><td><span class=\"dot {}\"></span>{}</td><td class=\"r\">{}tickets/s</td><td class=\"r\">{} shares</td><td class=\"r mut\">{}</td><td class=\"mut\">{}</td></tr>",
                if active { "on-dot" } else { "off-dot" },
                w["name"].as_str().unwrap_or(""),
                si(f(&w["tickets_per_s"])),
                n(&w["shares"]),
                if n(&w["rejected"]) > 0 { format!("{} rejected", n(&w["rejected"])) } else { String::new() },
                if n(&w["last_share"]) > 0 { format!("last share {} ago", ago(n(&w["last_share"]))) } else { String::new() },
            );
        }
        body += &format!(
            "<tr><td><details><summary><span class=\"chev\">▸</span><a class=\"mono\" href=\"/address/{a}\">{}</a> <span class=\"mut\">· {} device(s)</span></summary>\
<table class=\"wk\">{workers}</table></details></td><td class=\"r\">{}tickets/s</td><td class=\"r\">{}</td><td class=\"r\">{}</td><td class=\"r\">{}</td>\
<td><div class=\"bar\" title=\"{pct:.0}% of the minimum payout\"><span style=\"width:{pct:.0}%\"></span></div></td><td class=\"r\">{}</td></tr>",
            short(a),
            m["workers"].as_array().map(|w| w.len()).unwrap_or(0),
            si(f(&m["tickets_per_s"])),
            n(&m["shares"]),
            format_amount(n(&m["immature"])),
            format_amount(bal),
            format_amount(n(&m["paid"])),
        );
    }
    body += "</tbody></table></div><h2>Blocks found by the pool</h2><div class=\"tbl\"><table><thead><tr><th>Height</th><th>Found</th><th>Status</th><th class=\"r\">Reward (RQT)</th></tr></thead><tbody>";
    if blocks.is_empty() {
        body += "<tr><td colspan=\"4\" class=\"empty\">No blocks yet.</td></tr>";
    }
    for b in blocks.iter().take(20) {
        body += &format!(
            "<tr><td><a href=\"/block/{0}\">{0}</a></td><td>{1} <span class=\"mut\">· {2} ago</span></td><td>{3}</td><td class=\"r\">{4}</td></tr>",
            n(&b["height"]),
            utc(n(&b["time"])),
            ago(n(&b["time"])),
            badge(b["status"].as_str().unwrap_or("")),
            format_amount(n(&b["reward"]))
        );
    }
    body += "</tbody></table></div><h2>Payouts</h2><div class=\"tbl\"><table><thead><tr><th>Transaction</th><th>Time (UTC)</th><th class=\"r\">Miners</th><th class=\"r\">Total (RQT)</th></tr></thead><tbody>";
    let payouts = s["payouts"].as_array().cloned().unwrap_or_default();
    if payouts.is_empty() {
        body += "<tr><td colspan=\"4\" class=\"empty\">No payouts yet: balances are paid once they reach the minimum and the blocks have matured.</td></tr>";
    }
    for p in &payouts {
        let t = p["txid"].as_str().unwrap_or("");
        body += &format!(
            "<tr><td class=\"mono\"><a href=\"/tx/{t}\">{}</a></td><td>{}</td><td class=\"r\">{}</td><td class=\"r\">{}</td></tr>",
            short(t),
            utc(n(&p["time"])),
            n(&p["outputs"]),
            format_amount(n(&p["total"]))
        );
    }
    body += "</tbody></table></div>";
    page("Mining pool", &body, true)
}

fn row(txid: &str, height: String, time: String, received: u64, sent: u64) -> String {
    let (cls, amount) = if received >= sent {
        ("plus", format!("+{}", format_amount(received - sent)))
    } else {
        ("minus", format!("-{}", format_amount(sent - received)))
    };
    format!(
        "<tr><td>{height}</td><td class=\"mono\"><a href=\"/tx/{txid}\">{}</a></td><td>{time}</td><td class=\"r {cls}\">{amount}</td></tr>",
        short(txid)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_units() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(1_791_567_240), "2026-10-09 17:34:00");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(si(3_430_000.0), "3.43 M");
        assert_eq!(short("0123456789abcdef0123456789"), "0123456789…23456789");
        assert!(unhex32("zz").is_none());
    }
}
