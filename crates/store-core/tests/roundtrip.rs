//! Критерий приёмки этапа 1: round-trip 10 000 случайных файлов.

use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use store_core::{
    chunk::ChunkParams,
    crypto::Key,
    file::{CodecParams, ManifestBuilder, decode_segment, encode_segments, open_meta},
    format::{Code, FileManifest, from_blob, to_blob},
};

/// Маленькие сегменты, чтобы файлы состояли из многих страйпов и тест шёл секунды.
const PARAMS: CodecParams = CodecParams {
    chunk: ChunkParams {
        min: 256,
        avg: 1024,
        max: 4096,
    },
    k: 8,
    m: 6,
    code: Code::Rs,
};

#[test]
fn ten_thousand_random_files() {
    let mut rng = StdRng::seed_from_u64(0x5707e);
    let meta_key = Key::random();
    let root = Key::random();
    let mut segments_total = 0;

    for n in 0..10_000 {
        let len = match rng.random_range(0..10) {
            0 => 0,
            1..=6 => rng.random_range(1..4096),
            _ => rng.random_range(4096..40_000),
        };
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);

        // запись: шарды «раскладываются по узлам», манифест уходит блобом
        let mut builder = ManifestBuilder::default();
        let mut stored = Vec::new();
        for seg in encode_segments(&data[..], PARAMS, &root) {
            let seg = seg.unwrap();
            builder.push(&seg);
            stored.push(seg.encoded.shards);
        }
        let manifest = builder.finish(0, &meta_key, format!("file-{n}"), n as i128, None);
        let manifest: FileManifest = from_blob(&to_blob(&manifest)).unwrap();
        segments_total += manifest.stripes.len();

        // чтение: у каждого страйпа теряется случайное число шардов, не больше m
        let meta = open_meta(&meta_key, &manifest).unwrap();
        assert_eq!(meta.name, format!("file-{n}"));
        let mut out = Vec::with_capacity(len);
        for (((stripe, key), shards), &plain_len) in manifest
            .stripes
            .iter()
            .zip(&meta.segment_keys)
            .zip(&stored)
            .zip(&meta.segment_lens)
        {
            let drop = rng.random_range(0..=6);
            let lost = rand::seq::index::sample(&mut rng, 14, drop).into_vec();
            let available: Vec<_> = (0..14).map(|i| (!lost.contains(&i)).then(|| &shards[i])).collect();
            out.extend(decode_segment(stripe, key, &available, plain_len as usize).unwrap());
        }
        assert_eq!(meta.size(), len as u64);
        assert_eq!(out, data, "файл {n}");
    }
    assert!(segments_total > 50_000, "мало многосегментных файлов: {segments_total}");
}

/// Clay: манифест несёт код, чтение и потеря шардов — как у RS (файлов меньше: Clay медленнее
/// и страйп не меньше α·64·k байт).
#[test]
fn clay_random_files() {
    let mut rng = StdRng::seed_from_u64(0xc1a7);
    let params = CodecParams {
        code: Code::Clay,
        ..PARAMS
    };
    let (meta_key, root) = (Key::random(), Key::random());
    for n in 0..30 {
        let mut data = vec![0u8; rng.random_range(0..20_000)];
        rng.fill_bytes(&mut data);
        let mut builder = ManifestBuilder::default();
        let mut stored = Vec::new();
        for seg in encode_segments(&data[..], params, &root) {
            let seg = seg.unwrap();
            assert_eq!(seg.encoded.stripe.code, Code::Clay);
            builder.push(&seg);
            stored.push(seg.encoded.shards);
        }
        let manifest = builder.finish(0, &meta_key, format!("file-{n}"), 0, None);
        let manifest: FileManifest = from_blob(&to_blob(&manifest)).unwrap();
        let meta = open_meta(&meta_key, &manifest).unwrap();
        let mut out = Vec::new();
        for (((stripe, key), shards), &plain_len) in manifest
            .stripes
            .iter()
            .zip(&meta.segment_keys)
            .zip(&stored)
            .zip(&meta.segment_lens)
        {
            assert_eq!(stripe.code, Code::Clay);
            let drop = rng.random_range(0..=6);
            let lost = rand::seq::index::sample(&mut rng, 14, drop).into_vec();
            let available: Vec<_> = (0..14).map(|i| (!lost.contains(&i)).then(|| &shards[i])).collect();
            out.extend(decode_segment(stripe, key, &available, plain_len as usize).unwrap());
        }
        assert_eq!(out, data, "файл {n}");
    }
}

#[test]
fn wrong_meta_key_rejected() {
    let mut b = ManifestBuilder::default();
    for seg in encode_segments(&b"hello"[..], PARAMS, &Key::random()) {
        b.push(&seg.unwrap());
    }
    let manifest = b.finish(0, &Key::random(), "a".into(), 0, None);
    assert!(open_meta(&Key::random(), &manifest).is_err());
}

#[test]
fn convergent_dedup_within_root() {
    let mut data = vec![0u8; 50_000];
    StdRng::seed_from_u64(7).fill_bytes(&mut data);
    let (a, b) = (Key::random(), Key::random());
    let enc = |root: &Key| -> Vec<_> { encode_segments(&data[..], PARAMS, root).map(Result::unwrap).collect() };
    let (x, y, z) = (enc(&a), enc(&a), enc(&b));
    assert!(x.len() > 1);
    for ((x, y), z) in x.iter().zip(&y).zip(&z) {
        assert_eq!(x.key, y.key);
        assert_eq!(x.encoded.stripe.stripe_id, y.encoded.stripe.stripe_id);
        assert_eq!(x.encoded.stripe.shards, y.encoded.stripe.shards);
        assert_eq!(x.encoded.shards, y.encoded.shards);
        assert_ne!(x.encoded.stripe.stripe_id, z.encoded.stripe.stripe_id);
        assert_ne!(x.encoded.stripe.shards, z.encoded.stripe.shards);
    }
}
