//! Check the committed vectors (`vectors/*.jsonl`). The frozen-parameter file derives 512 MiB of
//! weights; run it with `cargo test --release -- --ignored`.

use tnet::sha256::sha256;
use tnet::*;

/// The raw text after `"key": ` up to the next top-level `,` or `}` (enough for these flat files).
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\": ");
    let start = line.find(&pat).unwrap_or_else(|| panic!("missing {key}")) + pat.len();
    let rest = &line[start..];
    let end = if rest.starts_with('[') { rest.find(']').unwrap() + 1 } else { rest.find([',', '}']).unwrap() };
    &rest[..end]
}

fn num(line: &str, key: &str) -> u64 {
    field(line, key).parse().unwrap()
}

fn text(line: &str, key: &str) -> String {
    field(line, key).trim_matches('"').to_string()
}

fn list(line: &str, key: &str) -> Vec<String> {
    let f = field(line, key);
    f[1..f.len() - 1].split(',').map(|s| s.trim().trim_matches('"').to_string()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..32).map(|k| u8::from_str_radix(&s[2 * k..2 * k + 2], 16).unwrap()).collect();
    v.try_into().unwrap()
}

fn bytes(v: &[i8]) -> Vec<u8> {
    v.iter().map(|&x| x as u8).collect()
}

fn check_file(name: &str) {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let body = std::fs::read_to_string(&path).expect("vectors file");
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty());
    let first = lines[0];
    let p = Params {
        n: num(first, "n") as usize,
        b: num(first, "b") as usize,
        layers: num(first, "L") as usize,
        w: num(first, "w") as usize,
        mult: num(first, "mult") as i32,
    };
    let epoch_seed = hex32(&text(first, "epoch"));
    let w_sha: Vec<String> =
        (0..p.layers as u32).map(|l| hex(&sha256(&bytes(&layer_weights(&epoch_seed, p.n, l))))).collect();
    let e = Epoch::from_seed(&epoch_seed, p);
    for line in lines {
        let (hd, nonce, i) = (hex32(&text(line, "hd")), num(line, "nonce"), num(line, "i") as usize);
        assert_eq!(list(line, "weights_sha256"), w_sha);
        let seed = x0_seed(&hd, nonce);
        assert_eq!(text(line, "x0_sha256"), hex(&sha256(&bytes(&x0_row(&seed, p.n, i)))));
        let row = e.forward_row(&seed, i, 8);
        assert_eq!(text(line, "row_sha256"), hex(&sha256(&bytes(&row))));
        if line.contains("\"row\": ") {
            assert_eq!(text(line, "row"), hex(&bytes(&row)));
        }
        let tickets: Vec<String> = (0..p.tickets_per_row())
            .map(|c| hex(&ticket_hash(&row[c * p.w..(c + 1) * p.w], &hd, nonce, i as u32, c as u32)))
            .collect();
        assert_eq!(list(line, "tickets"), tickets);
    }
}

#[test]
fn small_vectors() {
    check_file("tnet-v1-small.jsonl");
}

#[test]
#[ignore = "derives 512 MiB of weights; run with --release -- --ignored"]
fn frozen_vectors() {
    check_file("tnet-v1-frozen.jsonl");
    // The GPU-found ticket of vectors/README.md.
    let line = std::fs::read_to_string(format!("{}/../../vectors/tnet-v1-frozen.jsonl", env!("CARGO_MANIFEST_DIR")))
        .unwrap()
        .lines()
        .find(|l| l.contains("\"i\": 255,"))
        .unwrap()
        .to_string();
    assert!(list(&line, "tickets")[23].starts_with("0001"), "15 leading zero bits");
}
