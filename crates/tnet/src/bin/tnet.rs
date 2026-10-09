//! TNet v1 command-line tool.
//!
//! vectors n b L w mult epoch_hex hd_hex nonce i...      -> one JSON line per row (format of `vectors/`)
//! check   epoch_hex hd_hex nonce i c piece_hex bits     -> check a claimed ticket at the V1 parameters
//! bench   [n L threads reps]                            -> time to verify one ticket (L n^2 multiply-adds)

use std::time::Instant;
use tnet::sha256::sha256;
use tnet::*;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2).map(|k| u8::from_str_radix(&s[2 * k..2 * k + 2], 16).expect("hex")).collect()
}

fn hex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("expected 32-byte hex")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes(v: &[i8]) -> Vec<u8> {
    v.iter().map(|&x| x as u8).collect()
}

fn threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(1)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let num = |k: usize| a[k].parse::<u64>().expect("number");
    match a.first().map(|s| s.as_str()) {
        Some("vectors") if a.len() >= 10 => {
            let p = Params {
                n: num(1) as usize,
                b: num(2) as usize,
                layers: num(3) as usize,
                w: num(4) as usize,
                mult: num(5) as i32,
            };
            let (epoch, hd, nonce) = (hex32(&a[6]), hex32(&a[7]), num(8));
            let w_sha: Vec<String> = (0..p.layers as u32)
                .map(|l| format!("\"{}\"", hex(&sha256(&bytes(&layer_weights(&epoch, p.n, l))))))
                .collect();
            let e = Epoch::from_seed(&epoch, p);
            let seed = x0_seed(&hd, nonce);
            for arg in &a[9..] {
                let i: usize = arg.parse().expect("row");
                let row = e.forward_row(&seed, i, threads());
                let tickets: Vec<String> = (0..p.tickets_per_row())
                    .map(|c| {
                        format!(
                            "\"{}\"",
                            hex(&ticket_hash(&row[c * p.w..(c + 1) * p.w], &hd, nonce, i as u32, c as u32))
                        )
                    })
                    .collect();
                let row_field =
                    if p.n <= 1024 { format!(", \"row\": \"{}\"", hex(&bytes(&row))) } else { String::new() };
                println!(
                    "{{\"n\": {}, \"b\": {}, \"L\": {}, \"w\": {}, \"mult\": {}, \"epoch\": \"{}\", \"hd\": \"{}\", \
                     \"nonce\": {nonce}, \"i\": {i}, \"weights_sha256\": [{}], \"x0_sha256\": \"{}\", \"row_sha256\": \"{}\"{row_field}, \
                     \"tickets\": [{}]}}",
                    p.n,
                    p.b,
                    p.layers,
                    p.w,
                    p.mult,
                    hex(&epoch),
                    hex(&hd),
                    w_sha.join(", "),
                    hex(&sha256(&bytes(&x0_row(&seed, p.n, i)))),
                    hex(&sha256(&bytes(&row))),
                    tickets.join(", ")
                );
            }
        }
        Some("check") if a.len() == 8 => {
            let (epoch, hd, nonce) = (hex32(&a[1]), hex32(&a[2]), num(3));
            let (i, c) = (num(4) as u32, num(5) as u32);
            let piece: Vec<i8> = unhex(&a[6]).into_iter().map(|x| x as i8).collect();
            let target = target_from_bits(num(7) as u32);
            let lead = leading_zero_bits(&ticket_hash(&piece, &hd, nonce, i, c));
            let verdict = Epoch::from_seed(&epoch, V1).check(&hd, nonce, i, c, &piece, &target, threads());
            println!("{{\"lead\": {lead}, \"verdict\": \"{verdict:?}\"}}");
        }
        Some("bench") => {
            let n = a.get(1).map(|s| s.parse().unwrap()).unwrap_or(V1.n);
            let layers = a.get(2).map(|s| s.parse().unwrap()).unwrap_or(V1.layers);
            let threads = a.get(3).map(|s| s.parse().unwrap()).unwrap_or_else(threads);
            let reps: usize = a.get(4).map(|s| s.parse().unwrap()).unwrap_or(7);
            let p = Params { n, b: V1.b, layers, w: n.min(V1.w), mult: default_mult(n) };
            let t = Instant::now();
            let e = Epoch::from_seed(&[0x11; 32], p);
            let epoch_s = t.elapsed().as_secs_f64();
            let any = [0xff; 32];
            let mut ms: Vec<f64> = (0..reps)
                .map(|r| {
                    let t = Instant::now();
                    let piece = vec![0i8; p.w];
                    let _ = std::hint::black_box(e.check(&[0x22; 32], r as u64, r as u32, 0, &piece, &any, threads));
                    t.elapsed().as_secs_f64() * 1e3
                })
                .collect();
            ms.sort_by(|x, y| x.partial_cmp(y).unwrap());
            println!(
                "{{\"n\": {n}, \"L\": {layers}, \"threads\": {threads}, \"reps\": {reps}, \"epoch_s\": {epoch_s:.2}, \
                 \"verify_ms\": {:.2}, \"verify_ms_min\": {:.2}, \"verify_ms_max\": {:.2}}}",
                ms[reps / 2],
                ms[0],
                ms[reps - 1]
            );
        }
        _ => eprintln!(
            "usage: tnet vectors n b L w mult epoch hd nonce i... | check epoch hd nonce i c piece bits \
             | bench [n L threads reps]"
        ),
    }
}
