//! Пропускная способность конвейера на сегментах по умолчанию (8 МиБ, RS 8+6):
//! `cargo run --release --example throughput -- [МиБ]`

use std::time::Instant;

use store_core::file::{CodecParams, decode_segment, encode_segments};

fn main() {
    let mib: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(256);
    let mut data = vec![0u8; mib << 20];
    let mut x = 0x9e3779b97f4a7c15u64;
    for b in &mut data {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }

    let t = Instant::now();
    let segs: Vec<_> = encode_segments(&data[..], CodecParams::default(), &store_core::crypto::Key::random())
        .collect::<Result<_, _>>()
        .unwrap();
    let enc = t.elapsed();

    // худший случай чтения: все 6 потерь приходятся на data-шарды
    let t = Instant::now();
    let mut out = Vec::with_capacity(data.len());
    for s in &segs {
        let shards: Vec<_> = s
            .encoded
            .shards
            .iter()
            .enumerate()
            .map(|(i, sh)| (i >= 6).then_some(sh))
            .collect();
        out.extend(decode_segment(&s.encoded.stripe, &s.key, &shards, s.plain_len).unwrap());
    }
    let dec = t.elapsed();
    assert_eq!(out, data);

    let rate = |d: std::time::Duration| mib as f64 / d.as_secs_f64();
    println!(
        "{} сегментов; запись (CDC+шифр+RS): {:.0} МиБ/с; чтение с 6 потерянными data-шардами: {:.0} МиБ/с",
        segs.len(),
        rate(enc),
        rate(dec)
    );
}
