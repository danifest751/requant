//! Block explorer served by the node (`--explorer ADDR`): network summary, latest blocks, block,
//! transaction and address pages, search, the network and pool pages, `/health`, and the faucet form (its
//! one write: POST /faucet). Plain HTML, no scripts; values come from the node's own state and are parsed
//! before use, and text from outside (peer software names, faucet errors) is escaped.

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
    let method = line.split_whitespace().next().unwrap_or("GET").to_string();
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    // read the headers, keeping the host name (shown in the pool's connect command) and the body length
    let mut h = String::new();
    let mut host = String::from("this-host");
    let mut body_len = 0usize;
    for _ in 0..64 {
        h.clear();
        if reader.by_ref().take(4096).read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            body_len = v.trim().parse().unwrap_or(0);
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
    let mut stream = stream;
    if path == "/health" {
        let (status, body) = health(&shared.lock().unwrap());
        return write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    }
    let (status, body) = if method == "POST" && path == "/faucet" {
        // the form's one field: to=<address> (an address has only letters and digits)
        let mut form = vec![0u8; body_len.min(512)];
        reader.read_exact(&mut form)?;
        let to: String = String::from_utf8_lossy(&form)
            .split('&')
            .find_map(|kv| kv.strip_prefix("to="))
            .unwrap_or("")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(100)
            .collect();
        let ip = stream.peer_addr().map(|a| a.ip()).unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
        let mut st = shared.lock().unwrap();
        let outcome = match parse_address(&st.chain.net, &to) {
            Err(_) => Err("that is not a test-network address (trq1...)".to_string()),
            Ok(owner) => crate::faucet::request(&mut st, ip, owner),
        };
        ("200 OK", faucet_page(&st, Some(outcome)))
    } else {
        route(shared, &path, &host)
    };
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

/// A block is overdue after this many seconds (20 times the target spacing).
pub const STALE_AFTER: u64 = 1200;

/// `/health` for uptime monitors: 200 with `"ok"` while blocks arrive and peers are connected, 503 with
/// the reason otherwise.
fn health(st: &crate::node::State) -> (&'static str, String) {
    let tip = st.chain.block(&st.chain.tip()).unwrap();
    let age = now().saturating_sub(tip.header.time);
    let peers = st.peer_count();
    let problem = if peers == 0 {
        Some("no peers")
    } else if age > STALE_AFTER {
        Some("no new block for a long time")
    } else if st.headers.height() > st.chain.height() + 10 {
        Some("syncing")
    } else {
        None
    };
    let body = serde_json::json!({
        "status": problem.unwrap_or("ok"),
        "height": st.chain.height(),
        "tip_age_s": age,
        "peers": peers,
        "version": crate::node::VERSION,
        "update_available": st.release.as_ref().filter(|r| r.version > crate::release::own_version())
            .map(|r| r.version_string()),
    })
    .to_string();
    (if problem.is_some() { "503 Service Unavailable" } else { "200 OK" }, body)
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

/// Text from outside (a peer's software name) made safe inside HTML.
fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
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
tr.addr td{font-weight:600;border-bottom:none}tr.sub td{font-size:13px;padding-top:3px;padding-bottom:3px;border-bottom:none}tr.sub.last td{border-bottom:1px solid var(--line);padding-bottom:10px}
tr.sub td:first-child{padding-left:22px}.tree{color:var(--line);margin-right:8px;font-family:ui-monospace,monospace}tr.addr td .mut{font-weight:400}
.wrap{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow-x:auto;box-shadow:var(--shadow)}
.card b{display:block;font-size:20px;font-weight:700}.card span{color:var(--mut);font-size:12px}
.p-head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin:4px 0 16px}
.p-head h1{font-size:28px;margin:0}.p-head .sub{margin:2px 0 0}.crumb{color:var(--mut);font-size:13px}
.pills{display:flex;gap:6px;flex-wrap:wrap}.pill{font-size:12px;padding:4px 10px;border-radius:999px;background:var(--card);border:1px solid var(--line);color:var(--mut)}.pill b{color:var(--fg)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;box-shadow:var(--shadow)}
.kpi .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.kpi .v{font-size:22px;font-weight:750;margin-top:4px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.kpi .v small{font-size:13px;font-weight:500;opacity:.75;margin-left:4px}
.kpi .h{color:var(--mut);font-size:12px;margin-top:3px}.kpi .bar{margin-top:8px}
.kpi.main{background:linear-gradient(135deg,#0f766e,#4f46e5);color:#fff;border:0}.kpi.main .k,.kpi.main .h{color:rgba(255,255,255,.82)}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:var(--shadow)}
.panel h3{margin:0 0 10px;font-size:15px}.panel p{margin:0 0 8px;color:var(--mut);font-size:13px}
.grid2{display:grid;grid-template-columns:1.45fr 1fr;gap:14px;margin-top:14px}@media (max-width:860px){.grid2{grid-template-columns:1fr}}
.chart svg{width:100%;height:auto;display:block}.chart text{fill:var(--mut);font-size:11px}
.legend{display:flex;gap:16px;font-size:12px;color:var(--mut);margin-bottom:6px}.legend i{display:inline-block;width:12px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle}
.steps{counter-reset:s;list-style:none;padding:0;margin:0}.steps li{counter-increment:s;position:relative;padding:0 0 14px 34px;font-size:14px}
.steps li:before{content:counter(s);position:absolute;left:0;top:0;width:24px;height:24px;border-radius:50%;background:var(--acc);color:#fff;font-size:13px;font-weight:700;display:grid;place-items:center}
.dl{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}.btn{display:inline-block;padding:7px 12px;border-radius:9px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font-size:13px;font-weight:600}
.btn:hover{text-decoration:none;border-color:var(--acc)}.btn.pri{background:var(--acc);border-color:var(--acc);color:#fff}
code.cmd2{display:block;user-select:all;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:9px 11px;font:12.5px ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin-top:6px}
.lookup{display:flex;gap:8px;margin-top:8px;flex:none;min-width:0}.lookup input{flex:1}
.eff{font-weight:700}.eff.good{color:var(--ok)}.eff.mid{color:var(--warn)}.eff.bad{color:var(--bad)}
.prog{display:flex;align-items:center;gap:8px}.prog .bar{flex:1;min-width:70px}.share{display:flex;align-items:center;gap:8px}.share .bar{width:90px;min-width:90px}
.note{background:var(--warnbg);color:var(--warn);border-radius:12px;padding:12px 14px;margin:12px 0;font-size:14px}
"#;

fn page(title: &str, body: &str, refresh: bool) -> String {
    let meta = if refresh { "<meta http-equiv=\"refresh\" content=\"30\">" } else { "" };
    let on = |t: &str| if title == t { " class=\"on\"" } else { "" };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">{meta}\
<title>{title} · Requant</title><style>{STYLE}</style></head><body>\
<div class=\"top\"><div class=\"in\"><a class=\"brand\" href=\"/\"><span class=\"logo\">R</span>Requant</a><span class=\"tag\">testnet</span>\
<nav><a href=\"/\"{}>Explorer</a><a href=\"/network\"{}>Network</a><a href=\"/pool\"{}>Pool</a><a href=\"/faucet\"{}>Faucet</a></nav>\
<form action=\"/search\"><input name=\"q\" placeholder=\"Search block height, block id, txid or address\" aria-label=\"Search\"></form></div></div>\
<main>{body}<footer>Requant test network · test coins have no value · <a href=\"https://github.com/danifest751/requant\">source</a></footer></main></body></html>",
        on("Requant test network"),
        on("Network"),
        on("Mining pool"),
        on("Faucet")
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
        ["", "network"] => ("200 OK", network_page(&st)),
        ["", "faucet"] => ("200 OK", faucet_page(&st, None)),
        ["", "pool", "miner"] => {
            let q: String = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("addr="))
                .unwrap_or("")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(100)
                .collect();
            ("302 Found", format!("REDIRECT /pool/miner/{q}"))
        }
        ["", "pool", "miner", a] => {
            let owner = parse_address(net, a).ok().or_else(|| unhex32(a));
            match (owner, crate::pool::stats(&st)) {
                (Some(o), Some(s)) => match crate::pool::miner_stats(&st, &o) {
                    Some(m) => ("200 OK", miner_page(&m, host, s["port"].as_u64().unwrap_or(0))),
                    None => not_found("Pool (this node runs none)"),
                },
                (None, _) => not_found("Address"),
                (_, None) => not_found("Pool (this node runs none)"),
            }
        }
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
        (
            format!("{}", st.chain.holder_count()),
            format!("addresses holding coins ({} ever used)", st.index.address_count()),
        ),
        (
            format!("{}", st.index.tx_count()),
            format!("transactions ({} transfers)", st.index.tx_count().saturating_sub(tip_h as usize + 1)),
        ),
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

/// The faucet: a form for an address, and the outcome of a request.
fn faucet_page(st: &crate::node::State, outcome: Option<Result<Hash, String>>) -> String {
    let Some(f) = &st.faucet else {
        return page("Faucet", "<h1>Faucet</h1><p class=\"sub\">This node runs no faucet.</p>", false);
    };
    let net = &st.chain.net;
    let balance: u64 = crate::faucet::coins(st, &f.owner).iter().map(|c| c.1).sum();
    let mut body = format!(
        "<h1>Faucet</h1><p class=\"sub\">Test coins for trying the network: {} RQT per request, once a day per          address. Test coins have no value.</p>",
        format_amount(f.cfg.amount)
    );
    match outcome {
        Some(Ok(txid)) => {
            let t = hex(&txid);
            body += &format!(
                "<div class=\"card\"><span class=\"badge b-ok\">sent</span> {} RQT, transaction                  <a class=\"mono\" href=\"/tx/{t}\">{}</a>; spendable once it is in a block (about a minute).</div>",
                format_amount(f.cfg.amount),
                short(&t)
            )
        }
        Some(Err(e)) => {
            body += &format!("<div class=\"card\"><span class=\"badge b-bad\">not sent</span> {}</div>", esc(&e))
        }
        None => {}
    }
    body += "<form method=\"post\" action=\"/faucet\" style=\"display:flex;gap:8px;margin:16px 0;max-width:720px\">             <input name=\"to\" placeholder=\"Your test-network address (trq1...)\" aria-label=\"Address\" required>             <button style=\"padding:9px 16px;border-radius:10px;border:0;background:var(--acc);color:#fff;font-weight:600\">Send me coins</button></form>";
    let cards = [
        (format!("{} RQT", format_amount(balance)), "faucet balance".to_string()),
        (
            format!("{} / {} RQT", format_amount(f.given_today), format_amount(f.cfg.daily)),
            "given today / daily budget".to_string(),
        ),
    ];
    body += "<div class=\"cards\">";
    for (v, l) in cards {
        body += &format!("<div class=\"card\"><div class=\"k\">{l}</div><div class=\"v\">{v}</div></div>");
    }
    let fa = address(net, &f.owner);
    body += &format!(
        "</div><p class=\"mut\">Faucet address <a class=\"mono\" href=\"/address/{fa}\">{fa}</a>: send unused test coins back          here. No address yet? <code>requant-wallet keygen my.key</code> prints one.</p><h2>Recent</h2><div class=\"tbl\"><table>         <thead><tr><th>Time (UTC)</th><th>To</th><th>Transaction</th></tr></thead><tbody>"
    );
    if f.recent.is_empty() {
        body += "<tr><td colspan=\"3\" class=\"empty\">No requests yet.</td></tr>";
    }
    for (t, to, txid) in f.recent.iter().rev() {
        let (a, x) = (address(net, to), hex(txid));
        body += &format!(
            "<tr><td>{}</td><td class=\"mono\"><a href=\"/address/{a}\">{}</a></td><td class=\"mono\"><a href=\"/tx/{x}\">{}</a></td></tr>",
            utc(*t),
            short(&a),
            short(&x)
        );
    }
    body += "</tbody></table></div>";
    page("Faucet", &body, false)
}

/// This node's view of the network: its peers (software and height, not their addresses) and the
/// transactions waiting for a block.
fn network_page(st: &crate::node::State) -> String {
    let peers = st.peers();
    let outbound = peers.iter().filter(|p| p.outbound).count();
    let name = |a: &str| if a.is_empty() { "(greeting pending)".to_string() } else { esc(a) };
    let mut versions: Vec<(String, usize)> = Vec::new();
    for p in &peers {
        let a = name(&p.agent);
        match versions.iter_mut().find(|(v, _)| *v == a) {
            Some(e) => e.1 += 1,
            None => versions.push((a, 1)),
        }
    }
    versions.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let cards = [
        (format!("{}", peers.len()), format!("peers ({outbound} outbound, {} inbound)", peers.len() - outbound)),
        (format!("{}", st.chain.height()), "block height".to_string()),
        (format!("{}", st.headers.height()), "verified headers".to_string()),
        (format!("{}", st.mempool.len()), format!("unconfirmed transactions ({} bytes)", st.mempool.bytes())),
        (crate::node::agent(), format!("this node, up {}", ago(st.started))),
    ];
    let mut body = String::from(
        "<h1>Network</h1><p class=\"sub\">As seen by this node. Peer addresses are not shown.</p><div class=\"cards\">",
    );
    for (v, l) in cards {
        body += &format!("<div class=\"card\"><div class=\"k\">{l}</div><div class=\"v\">{v}</div></div>");
    }
    body += "</div><h2>Software of the peers</h2><div class=\"tbl\"><table><thead><tr><th>Version</th><th class=\"r\">Peers</th></tr></thead><tbody>";
    if versions.is_empty() {
        body += "<tr><td colspan=\"2\" class=\"empty\">No peers connected.</td></tr>";
    }
    for (v, n) in &versions {
        body += &format!("<tr><td class=\"mono\">{v}</td><td class=\"r\">{n}</td></tr>");
    }
    body += "</tbody></table></div><h2>Peers</h2><div class=\"tbl\"><table><thead><tr><th>Direction</th><th>Software</th><th class=\"r\">Height</th><th>Connected for</th></tr></thead><tbody>";
    let tip = st.chain.height();
    for p in &peers {
        let behind = if p.height + 2 < tip {
            format!(" <span class=\"mut\">({} behind)</span>", tip - p.height)
        } else {
            String::new()
        };
        body += &format!(
            "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"r\">{}{behind}</td><td class=\"mut\">{}</td></tr>",
            if p.outbound { "outbound" } else { "inbound" },
            name(&p.agent),
            p.height,
            ago(p.since)
        );
    }
    body += "</tbody></table></div><h2>Unconfirmed transactions</h2><div class=\"tbl\"><table><thead><tr><th>Transaction</th><th class=\"r\">Size (bytes)</th><th class=\"r\">Fee (RQT)</th><th class=\"r\">Fee per byte (atoms)</th></tr></thead><tbody>";
    let txs = st.mempool.list();
    if txs.is_empty() {
        body += "<tr><td colspan=\"4\" class=\"empty\">None: every known transaction is in a block.</td></tr>";
    }
    for (id, fee, size) in txs.iter().take(100) {
        let t = hex(id);
        body += &format!(
            "<tr><td class=\"mono\"><a href=\"/tx/{t}\">{}</a></td><td class=\"r\">{size}</td><td class=\"r\">{}</td><td class=\"r\">{}</td></tr>",
            short(&t),
            format_amount(*fee),
            fee / (*size).max(1) as u64
        );
    }
    body += "</tbody></table></div>";
    page("Network", &body, true)
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
        "confirmed" => ("b-ok", "confirmed"),
        "pending" => ("b-warn", "unconfirmed"),
        "returned" => ("b-bad", "returned"),
        _ => ("b-warn", "maturing"),
    };
    format!("<span class=\"badge {cls}\">{text}</span>")
}

/// A line chart of up to two series over time (inline SVG, no scripts): `(label, colour, points)`.
/// A chart series: label, colour, (time, value) points.
type Series<'a> = (&'a str, &'a str, Vec<(u64, f64)>);

fn chart(series: &[Series], unit: &str) -> String {
    let pts: Vec<&(u64, f64)> = series.iter().flat_map(|s| s.2.iter()).collect();
    if pts.len() < 2 || series.iter().all(|s| s.2.len() < 2) {
        return "<div class=\"empty\">Collecting data: the chart fills in over the next hours (one point every 5 minutes).</div>"
            .into();
    }
    let (w, h, l, r, t, b) = (720.0, 210.0, 58.0, 10.0, 10.0, 24.0);
    let t0 = pts.iter().map(|p| p.0).min().unwrap() as f64;
    let t1 = (pts.iter().map(|p| p.0).max().unwrap() as f64).max(t0 + 1.0);
    let top = pts.iter().map(|p| p.1).fold(0.0, f64::max).max(1.0) * 1.12;
    let x = |tt: u64| l + (tt as f64 - t0) / (t1 - t0) * (w - l - r);
    let y = |v: f64| t + (1.0 - v / top) * (h - t - b);
    let mut svg = format!("<svg viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"rate over time\">");
    for k in 0..=4 {
        let v = top * k as f64 / 4.0;
        let yy = y(v);
        svg += &format!(
            "<line x1=\"{l}\" x2=\"{}\" y1=\"{yy:.1}\" y2=\"{yy:.1}\" style=\"stroke:var(--line)\"/><text x=\"{}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>",
            w - r,
            l - 6.0,
            yy + 4.0,
            if k == 0 { "0".to_string() } else { format!("{}{unit}", si(v).replace(".00", "")) }
        );
    }
    let ticks = 6;
    for k in 0..=ticks {
        let tt = (t0 + (t1 - t0) * k as f64 / ticks as f64) as u64;
        let hm = &utc(tt)[11..16];
        svg += &format!("<text x=\"{:.1}\" y=\"{}\" text-anchor=\"middle\">{hm}</text>", x(tt), h - 6.0);
    }
    for (i, (_, colour, ps)) in series.iter().enumerate() {
        if ps.len() < 2 {
            continue;
        }
        let line: String = ps.iter().map(|(tt, v)| format!("{:.1},{:.1} ", x(*tt), y(*v))).collect();
        if i == 0 {
            // the first series gets a soft area under it
            svg += &format!(
                "<polygon points=\"{:.1},{:.1} {line}{:.1},{:.1}\" style=\"fill:{colour};opacity:.12\"/>",
                x(ps[0].0),
                y(0.0),
                x(ps[ps.len() - 1].0),
                y(0.0)
            );
        }
        let dash = if i == 0 { "" } else { "stroke-dasharray:5 4;" };
        svg += &format!("<polyline points=\"{line}\" style=\"fill:none;stroke:{colour};stroke-width:2;{dash}\"/>");
    }
    svg += "</svg>";
    let legend: String = series
        .iter()
        .map(|(label, colour, _)| format!("<span><i style=\"background:{colour}\"></i>{label}</span>"))
        .collect();
    format!("<div class=\"chart\"><div class=\"legend\">{legend}</div>{svg}</div>")
}

/// Effort as a percentage, coloured: under 100% the pool was lucky.
fn effort(e: Option<f64>) -> String {
    match e {
        Some(e) => {
            let class = if e < 1.0 {
                "good"
            } else if e < 2.0 {
                "mid"
            } else {
                "bad"
            };
            format!("<span class=\"eff {class}\">{:.0}%</span>", e * 100.0)
        }
        None => "<span class=\"mut\">—</span>".into(),
    }
}

fn kpi(k: &str, v: &str, h: &str, main: bool) -> String {
    format!(
        "<div class=\"kpi{}\"><div class=\"k\">{k}</div><div class=\"v\">{v}</div><div class=\"h\">{h}</div></div>",
        if main { " main" } else { "" }
    )
}

/// A value with its SI prefix and a small unit: `8.71<small>M tickets/s</small>`.
fn unit(v: f64, u: &str) -> String {
    let s = si(v);
    let (num, prefix) = s.split_once(' ').unwrap_or((&s, ""));
    format!("{num}<small>{prefix} {u}</small>")
}

/// RQT with two decimals, for large figures.
fn rqt2(atoms: u64) -> String {
    format!("{:.2}", atoms as f64 / 1e8)
}

fn rqt(atoms: u64) -> String {
    let s = format_amount(atoms);
    let t = s.trim_end_matches('0').trim_end_matches('.');
    if t.is_empty() {
        "0".into()
    } else {
        t.to_string()
    }
}

fn pool_page(s: &serde_json::Value, host: &str) -> String {
    let n = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
    let f = |v: &serde_json::Value| v.as_f64().unwrap_or(0.0);
    let endpoint = format!("{host}:{}", n(&s["port"]));
    let miners = s["miners"].as_array().cloned().unwrap_or_default();
    let active: Vec<&serde_json::Value> = miners.iter().filter(|m| f(&m["tickets_per_s"]) > 0.0).collect();
    let (rate, net) = (f(&s["tickets_per_s"]), f(&s["network_tickets_per_s"]));
    let share = if net > 0.0 { (rate / net * 100.0).min(100.0) } else { 0.0 };
    let last =
        s["last_block_time"].as_u64().map(|t| format!("last {} ago", ago(t))).unwrap_or_else(|| "none yet".into());
    let mut body = format!(
        "<div class=\"p-head\"><div><h1>Requant pool</h1><p class=\"sub\">Mine Requant (test network) with an NVIDIA GPU; rewards split by \
         shares and paid automatically.</p></div><div class=\"pills\"><span class=\"pill\"><b>PPLNS</b></span>\
         <span class=\"pill\">fee <b>{}%</b></span><span class=\"pill\">min payout <b>{} RQT</b></span>\
         <span class=\"pill\">payouts every <b>{} min</b></span><span class=\"pill\">maturity <b>{} blocks</b></span>\
         <span class=\"pill\">share <b>2^{} tickets</b></span></div></div>",
        s["fee_percent"],
        rqt(n(&s["min_payout_atoms"])),
        n(&s["payout_every_s"]).max(60) / 60,
        n(&s["maturity"]),
        s["share_bits"],
    );
    body += "<div class=\"kpis\">";
    body += &kpi("Pool rate", &unit(rate, "tickets/s"), &format!("{share:.1}% of the network"), true);
    body += &kpi(
        "Network rate",
        &unit(net, "tickets/s"),
        &format!("difficulty {}tickets / block", si(f(&s["difficulty"]))),
        false,
    );
    let (dev, addrs) = (n(&s["devices"]), miners.len());
    body += &kpi(
        "Miners",
        &format!("{}", active.len()),
        &format!(
            "{dev} device{} online · {addrs} address{} known",
            if dev == 1 { "" } else { "s" },
            if addrs == 1 { "" } else { "es" }
        ),
        false,
    );
    body += &kpi(
        "Blocks found",
        &format!("{}<small>in 24 h</small>", n(&s["blocks_24h"])),
        &format!("{} in total · {last}", n(&s["blocks_total"])),
        false,
    );
    body += &kpi(
        "Round effort",
        &format!("{:.0}%", f(&s["round_effort"]) * 100.0),
        &match s["effort_avg"].as_f64() {
            Some(a) => format!("average {:.0}% over recent blocks", a * 100.0),
            None => "of a block's expected shares".into(),
        },
        false,
    );
    body += &kpi(
        "Paid out",
        &format!("{}<small>RQT</small>", rqt2(n(&s["paid_total"]))),
        &format!("{} payouts", n(&s["payouts_total"])),
        false,
    );
    body += "</div>";

    // the day's rates, and how to start
    let hourly = s["hourly"].as_array().cloned().unwrap_or_default();
    let series = |k: usize| hourly.iter().filter_map(|h| Some((h[0].as_u64()?, h[k].as_f64()?))).collect::<Vec<_>>();
    body += &format!(
        "<div class=\"grid2\"><div class=\"panel\"><h3>Rate by the hour, last 24 hours</h3>{}\
         <p style=\"margin-top:8px\">From the blocks: the work of the blocks found each hour, the pool's and the whole \
         network's, in tickets per second.</p></div>",
        chart(&[("pool", "var(--acc)", series(1)), ("network", "var(--acc2)", series(2))], "")
    );
    body += &format!(
        "<div class=\"panel\"><h3>Start mining</h3><ol class=\"steps\">\
         <li><b>Get a wallet address.</b> <code>requant-wallet keygen my.key</code> prints your address and key hash \
         (<a href=\"https://github.com/danifest751/requant/releases/latest\">wallet download</a>).</li>\
         <li><b>Download CPPminer</b> (NVIDIA, RTX 20xx or newer):<div class=\"dl\">\
         <a class=\"btn pri\" href=\"https://github.com/danifest751/CPPminer/releases/latest\">Windows</a>\
         <a class=\"btn\" href=\"https://github.com/danifest751/CPPminer/releases/latest\">Linux</a></div></li>\
         <li><b>Run it</b> with your key hash; <code>--worker</code> names the device:\
         <code class=\"cmd2\">cppminer --algo tnet --rpc {endpoint} --payee YOUR_KEY_HASH --worker rig1</code></li>\
         </ol><h3 style=\"margin-top:4px\">Your statistics</h3>\
         <form class=\"lookup\" action=\"/pool/miner\"><input name=\"addr\" placeholder=\"Your address trq1... or key hash\" aria-label=\"Address\">\
         <button class=\"btn pri\">Show</button></form>\
         <p style=\"margin-top:10px\">No coins to try a transfer? The <a href=\"/faucet\">faucet</a> sends 10 RQT a day.</p></div></div>"
    );

    // network figures
    let nw = &s["network"];
    body += "<div class=\"kpis\" style=\"margin-top:14px\">";
    body += &kpi(
        "Addresses with coins",
        &format!("{}", n(&nw["addresses_holding"])),
        &format!("{} ever used", n(&nw["addresses_used"])),
        false,
    );
    body += &kpi(
        "Transactions",
        &format!("{}", n(&nw["transactions"])),
        &format!("{} transfers", n(&nw["transfers"])),
        false,
    );
    body += &kpi("Block height", &format!("{}", n(&nw["height"])), "test network", false);
    body += "</div>";

    // miners
    let min_payout = n(&s["min_payout_atoms"]).max(1);
    body += "<h2>Miners</h2><div class=\"tbl\"><table><thead><tr><th>Address · devices</th><th class=\"r\">Rate</th><th>Share of pool</th>\
<th class=\"r\">Maturing</th><th class=\"r\">Balance</th><th>To payout</th><th class=\"r\">Paid</th><th class=\"r\">Blocks</th></tr></thead><tbody>";
    if miners.is_empty() {
        body += "<tr><td colspan=\"8\" class=\"empty\">No miners yet: start one with the steps above.</td></tr>";
    }
    for m in &miners {
        let a = m["address"].as_str().unwrap_or("");
        let bal = n(&m["balance"]);
        let pct = (bal as f64 / min_payout as f64 * 100.0).min(100.0);
        let mr = f(&m["tickets_per_s"]);
        let sh = if rate > 0.0 { mr / rate * 100.0 } else { 0.0 };
        let devices = m["workers"].as_array().cloned().unwrap_or_default();
        body += &format!(
            "<tr class=\"addr\"><td><a class=\"mono\" href=\"/pool/miner/{a}\">{}</a> <span class=\"mut\">· {} device{}</span></td>\
<td class=\"r\">{}tickets/s</td><td><div class=\"share\"><div class=\"bar\"><span style=\"width:{sh:.0}%\"></span></div><span class=\"mut\">{sh:.1}%</span></div></td>\
<td class=\"r\">{}</td><td class=\"r\">{}</td><td><div class=\"bar\" title=\"{pct:.0}% of the minimum payout\"><span style=\"width:{pct:.0}%\"></span></div></td>\
<td class=\"r\">{}</td><td class=\"r\">{}</td></tr>",
            short(a),
            devices.len(),
            if devices.len() == 1 { "" } else { "s" },
            si(mr),
            rqt(n(&m["immature"])),
            rqt(bal),
            rqt(n(&m["paid"])),
            n(&m["blocks_found"]),
        );
        for (k, w) in devices.iter().enumerate() {
            let on = now().saturating_sub(n(&w["last_share"])) < 600;
            let rejected = n(&w["rejected"]);
            body += &format!(
                "<tr class=\"sub{}\"><td><span class=\"tree\">{}</span><span class=\"dot {}\"></span>{}</td><td class=\"r\">{}tickets/s</td>\
<td colspan=\"6\" class=\"mut\">{} shares · {}{}</td></tr>",
                if k + 1 == devices.len() { " last" } else { "" },
                if k + 1 == devices.len() { "└" } else { "├" },
                if on { "on-dot" } else { "off-dot" },
                esc(w["name"].as_str().unwrap_or("")),
                si(f(&w["tickets_per_s"])),
                n(&w["shares"]),
                if n(&w["last_share"]) > 0 { format!("last share {} ago", ago(n(&w["last_share"]))) } else { "no shares yet".into() },
                if rejected > 0 { format!(" · <span class=\"minus\">{rejected} rejected</span>") } else { String::new() },
            );
        }
    }

    // blocks
    let maturity = n(&s["maturity"]).max(1);
    body += "</tbody></table></div><h2>Blocks found by the pool</h2><div class=\"tbl\"><table><thead><tr><th>Height</th><th>Found</th>\
<th class=\"r\">Effort</th><th>Status</th><th class=\"r\">Reward (RQT)</th></tr></thead><tbody>";
    let blocks = s["blocks"].as_array().cloned().unwrap_or_default();
    if blocks.is_empty() {
        body += "<tr><td colspan=\"5\" class=\"empty\">No blocks yet.</td></tr>";
    }
    for b in blocks.iter().take(15) {
        let status = b["status"].as_str().unwrap_or("");
        let conf = n(&b["confirmations"]).min(maturity);
        let state = if status == "immature" {
            let pct = conf as f64 / maturity as f64 * 100.0;
            format!(
                "<div class=\"prog\"><div class=\"bar\"><span style=\"width:{pct:.0}%\"></span></div><span class=\"mut\">{conf}/{maturity}</span></div>"
            )
        } else {
            badge(status)
        };
        body += &format!(
            "<tr><td><a href=\"/block/{0}\">{0}</a></td><td>{1} <span class=\"mut\">· {2} ago</span></td><td class=\"r\">{3}</td><td>{4}</td><td class=\"r\">{5}</td></tr>",
            n(&b["height"]),
            utc(n(&b["time"])),
            ago(n(&b["time"])),
            effort(b["effort"].as_f64()),
            state,
            rqt(n(&b["reward"]))
        );
    }

    // payouts
    body += "</tbody></table></div><h2>Payouts</h2><div class=\"tbl\"><table><thead><tr><th>Transaction</th><th>Time (UTC)</th><th>Status</th>\
<th class=\"r\">Miners</th><th class=\"r\">Total (RQT)</th></tr></thead><tbody>";
    let payouts = s["payouts"].as_array().cloned().unwrap_or_default();
    if payouts.is_empty() {
        body += "<tr><td colspan=\"5\" class=\"empty\">No payouts yet: balances are paid once they reach the minimum and the blocks have matured.</td></tr>";
    }
    for p in payouts.iter().take(15) {
        let t = p["txid"].as_str().unwrap_or("");
        body += &format!(
            "<tr><td class=\"mono\"><a href=\"/tx/{t}\">{}</a></td><td>{} <span class=\"mut\">· {} ago</span></td><td>{}</td><td class=\"r\">{}</td><td class=\"r\">{}</td></tr>",
            short(t),
            utc(n(&p["time"])),
            ago(n(&p["time"])),
            badge(p["status"].as_str().unwrap_or("confirmed")),
            n(&p["outputs"]),
            rqt(n(&p["total"]))
        );
    }
    body += "</tbody></table></div>";
    page("Mining pool", &body, true)
}

/// One miner: rate and its history, devices, balance, maturing credits, payouts.
fn miner_page(m: &serde_json::Value, host: &str, port: u64) -> String {
    let n = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
    let f = |v: &serde_json::Value| v.as_f64().unwrap_or(0.0);
    let a = m["address"].as_str().unwrap_or("");
    let mut body = format!(
        "<div class=\"p-head\"><div><div class=\"crumb\"><a href=\"/pool\">Pool</a> / miner</div><h1>Miner</h1>\
         <p class=\"sub mono\">{a} · <a href=\"/address/{a}\">on the explorer</a></p></div></div>"
    );
    if m["known"] != true {
        body += &format!(
            "<div class=\"note\">This address has not mined in the pool yet. Start the miner with its key hash:\
             <code class=\"cmd2\">cppminer --algo tnet --rpc {host}:{port} --payee KEY_HASH_OF_THIS_ADDRESS --worker rig1</code></div>"
        );
    }
    let min_payout = n(&m["min_payout_atoms"]).max(1);
    let bal = n(&m["balance"]);
    let pct = (bal as f64 / min_payout as f64 * 100.0).min(100.0);
    let workers = m["workers"].as_array().cloned().unwrap_or_default();
    let online = workers.iter().filter(|w| now().saturating_sub(n(&w["last_share"])) < 600).count();
    body += "<div class=\"kpis\">";
    body += &kpi(
        "Rate",
        &unit(f(&m["tickets_per_s"]), "tickets/s"),
        &format!("{:.1}% of the pool", f(&m["share_of_pool"]) * 100.0),
        true,
    );
    body += &format!(
        "<div class=\"kpi\"><div class=\"k\">Balance</div><div class=\"v\">{}<small>RQT</small></div><div class=\"bar\"><span style=\"width:{pct:.0}%\"></span></div>\
         <div class=\"h\">{pct:.0}% of the {} RQT minimum; paid every {} min</div></div>",
        rqt2(bal),
        rqt(min_payout),
        n(&m["payout_every_s"]).max(60) / 60
    );
    body += &kpi(
        "Maturing",
        &format!("{}<small>RQT</small>", rqt2(n(&m["immature"]))),
        "credited once its blocks mature",
        false,
    );
    body += &kpi(
        "Paid",
        &format!("{}<small>RQT</small>", rqt2(n(&m["paid"]))),
        &format!("{} payouts", m["payouts"].as_array().map(|p| p.len()).unwrap_or(0)),
        false,
    );
    body += &kpi(
        "Devices",
        &format!("{online}<small>online</small>"),
        &format!("{} known · {} blocks found", workers.len(), n(&m["blocks_found"])),
        false,
    );
    body += "</div>";
    let hist: Vec<(u64, f64)> =
        m["history"].as_array().into_iter().flatten().filter_map(|h| Some((h[0].as_u64()?, h[1].as_f64()?))).collect();
    body += &format!(
        "<div class=\"panel\" style=\"margin-top:14px\"><h3>Rate, last 24 hours</h3>{}</div>",
        chart(&[("this address", "var(--acc)", hist)], "")
    );
    body += "<h2>Devices</h2><div class=\"tbl\"><table><thead><tr><th>Device</th><th class=\"r\">Rate</th><th class=\"r\">Shares</th>\
<th class=\"r\">Rejected</th><th>Last share</th></tr></thead><tbody>";
    if workers.is_empty() {
        body += "<tr><td colspan=\"5\" class=\"empty\">No devices in the last hour.</td></tr>";
    }
    for w in &workers {
        let on = now().saturating_sub(n(&w["last_share"])) < 600;
        let (sh, rj) = (n(&w["shares"]), n(&w["rejected"]));
        let rj_pct = if sh + rj > 0 { rj as f64 / (sh + rj) as f64 * 100.0 } else { 0.0 };
        body += &format!(
            "<tr><td><span class=\"dot {}\"></span>{}</td><td class=\"r\">{}tickets/s</td><td class=\"r\">{sh}</td><td class=\"r\">{rj} <span class=\"mut\">({rj_pct:.1}%)</span></td><td class=\"mut\">{}</td></tr>",
            if on { "on-dot" } else { "off-dot" },
            esc(w["name"].as_str().unwrap_or("")),
            si(f(&w["tickets_per_s"])),
            if n(&w["last_share"]) > 0 { format!("{} ago", ago(n(&w["last_share"]))) } else { "never".into() }
        );
    }
    body += "</tbody></table></div><h2>Payouts to this address</h2><div class=\"tbl\"><table><thead><tr><th>Transaction</th><th>Time (UTC)</th>\
<th>Status</th><th class=\"r\">Amount (RQT)</th></tr></thead><tbody>";
    let payouts = m["payouts"].as_array().cloned().unwrap_or_default();
    if payouts.is_empty() {
        body += "<tr><td colspan=\"4\" class=\"empty\">No payouts yet.</td></tr>";
    }
    for p in &payouts {
        let t = p["txid"].as_str().unwrap_or("");
        body += &format!(
            "<tr><td class=\"mono\"><a href=\"/tx/{t}\">{}</a></td><td>{} <span class=\"mut\">· {} ago</span></td><td>{}</td><td class=\"r\">{}</td></tr>",
            short(t),
            utc(n(&p["time"])),
            ago(n(&p["time"])),
            badge(p["status"].as_str().unwrap_or("confirmed")),
            rqt(n(&p["amount"]))
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
