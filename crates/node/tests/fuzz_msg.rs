//! Mutated and random frames into the peer message decoder: never a panic, never an oversized allocation.

use requant_node::msg::{read_msg, write_msg, Msg};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

#[test]
fn message_decoder_never_panics() {
    let magic = *b"RQ01";
    let samples = vec![
        Msg::Hello {
            protocol: 3,
            height: 9,
            tip: [1; 32],
            node_id: 5,
            listen_port: 19333,
            agent: "requantd/0.10.0".into(),
        },
        Msg::GetBlocks(vec![[2; 32]; 3]),
        Msg::Inv(vec![[3; 32]; 4]),
        Msg::GetData(vec![[4; 32]]),
        Msg::GetHeaders(vec![[5; 32]; 2]),
        Msg::Headers(vec![1, 2, 3]),
        Msg::Addr(vec!["1.2.3.4:19333".parse().unwrap(), "[2001:db8::1]:1".parse().unwrap()]),
        Msg::GetAddr,
        Msg::Ping(7),
        Msg::Tx(vec![0; 40]),
        Msg::Release(vec![5, 0, b'h', b'e', b'l', b'l', b'o'].into_iter().chain([0; 64]).collect()),
    ];
    let frames: Vec<Vec<u8>> = samples
        .iter()
        .map(|m| {
            let mut b = Vec::new();
            write_msg(&mut b, &magic, m).unwrap();
            b
        })
        .collect();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for round in 0..30_000 {
        let mut f = frames[round % frames.len()].clone();
        for _ in 0..1 + rng.below(3) {
            let k = rng.below(f.len());
            match rng.below(3) {
                0 => f[k] ^= 1 << rng.below(8),
                1 => f[k] = rng.next() as u8,
                _ => f.truncate(k),
            }
            if f.is_empty() {
                break;
            }
        }
        // a frame with a valid header but a corrupted payload must still decode or fail cleanly
        let _ = read_msg(&mut &f[..], &magic);
        let n = rng.below(64);
        let random: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        let mut framed = magic.to_vec();
        framed.extend_from_slice(&random);
        let _ = read_msg(&mut &framed[..], &magic);
    }
}
