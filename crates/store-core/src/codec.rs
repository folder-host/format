//! RS-кодек страйпа поверх `reed-solomon-simd`.
//!
//! Данные страйпа: `len(u32 LE) ‖ ciphertext ‖ нули` длиной `k * shard_len`,
//! `shard_len` кратен 64. Кодирование детерминировано, поэтому ремонт
//! воспроизводит в точности те же хэши шардов, что записаны в манифесте.

use crate::{
    Error, Hash, Result,
    format::{Code, Stripe},
};

pub(crate) const LEN_PREFIX: usize = 4;
const SHARD_ALIGN: usize = 64;
/// Верхняя граница `shard_len`: страйп из манифеста (от владельца share или из корня от control
/// plane) не должен заставлять выделять гигабайты. Сегмент не больше 16 МиБ, поэтому честный
/// шард заметно меньше.
pub const MAX_SHARD_LEN: usize = 64 << 20;

#[derive(Debug, Clone)]
pub struct EncodedStripe {
    pub stripe: Stripe,
    /// k+m шардов, индекс = индекс в RS.
    pub shards: Vec<Vec<u8>>,
}

fn check_params(k: u8, m: u8) -> Result<()> {
    if k == 0 || m == 0 {
        return Err(Error::InvalidParams { k, m });
    }
    Ok(())
}

/// Геометрия страйпа из манифеста: шард чётной ненулевой длины не больше [`MAX_SHARD_LEN`],
/// и `k` data-шардов вмещают хотя бы префикс длины.
pub(crate) fn check_geometry(k: usize, shard_len: usize) -> Result<()> {
    if shard_len < 2 || !shard_len.is_multiple_of(2) {
        return Err(Error::CorruptStripe("shard_len нулевой или нечётный"));
    }
    if shard_len > MAX_SHARD_LEN {
        return Err(Error::CorruptStripe("shard_len больше предела"));
    }
    if k.saturating_mul(shard_len) < LEN_PREFIX {
        return Err(Error::CorruptStripe("k·shard_len меньше префикса длины"));
    }
    Ok(())
}

/// Шифротекст из собранных data-шардов: `len(u32 LE) ‖ ciphertext ‖ нули`, хэш по `stripe_id`.
pub(crate) fn unpad(stripe: &Stripe, data: &[u8]) -> Result<Vec<u8>> {
    let prefix: [u8; LEN_PREFIX] = data
        .get(..LEN_PREFIX)
        .and_then(|p| p.try_into().ok())
        .ok_or(Error::CorruptStripe("страйп короче префикса длины"))?;
    let len = u32::from_le_bytes(prefix) as usize;
    let ciphertext = data
        .get(LEN_PREFIX..LEN_PREFIX + len)
        .ok_or(Error::CorruptStripe("длина сегмента больше страйпа"))?;
    let actual = Hash::of(ciphertext);
    if actual != stripe.stripe_id {
        return Err(Error::HashMismatch {
            expected: stripe.stripe_id,
            actual,
        });
    }
    Ok(ciphertext.to_vec())
}

pub fn encode_stripe(ciphertext: &[u8], k: u8, m: u8) -> Result<EncodedStripe> {
    check_params(k, m)?;
    let len = u32::try_from(ciphertext.len()).map_err(|_| Error::CorruptStripe("сегмент больше 4 ГиБ"))?;
    let kk = k as usize;
    let shard_len = (LEN_PREFIX + ciphertext.len())
        .div_ceil(kk)
        .next_multiple_of(SHARD_ALIGN);
    check_geometry(kk, shard_len)?;

    let mut data = Vec::with_capacity(kk * shard_len);
    data.extend_from_slice(&len.to_le_bytes());
    data.extend_from_slice(ciphertext);
    data.resize(kk * shard_len, 0);

    let mut shards: Vec<Vec<u8>> = data.chunks_exact(shard_len).map(<[u8]>::to_vec).collect();
    shards.extend(reed_solomon_simd::encode(kk, m as usize, &shards)?);

    let stripe = Stripe {
        stripe_id: Hash::of(ciphertext),
        k,
        m,
        shard_len: shard_len as u32,
        shards: shards.iter().map(|s| Hash::of(s)).collect(),
        code: crate::format::Code::Rs,
    };
    Ok(EncodedStripe { stripe, shards })
}

/// Оставляет только шарды с верной длиной и хэшем из манифеста.
fn verified<'a, S: AsRef<[u8]>>(stripe: &Stripe, shards: &'a [Option<S>]) -> Result<Vec<(usize, &'a [u8])>> {
    check_params(stripe.k, stripe.m)?;
    let n = stripe.k as usize + stripe.m as usize;
    if stripe.shards.len() != n {
        return Err(Error::CorruptStripe("число хэшей шардов не равно k+m"));
    }
    if shards.len() != n {
        return Err(Error::CorruptStripe("ожидался слот на каждый из k+m шардов"));
    }
    check_geometry(stripe.k as usize, stripe.shard_len as usize)?;
    Ok(shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| Some((i, s.as_ref()?.as_ref())))
        .filter(|(i, s)| s.len() == stripe.shard_len as usize && Hash::of(s) == stripe.shards[*i])
        .collect())
}

/// Восстанавливает все k data-шардов из любых k целых.
fn recover_data(stripe: &Stripe, valid: &[(usize, &[u8])]) -> Result<Vec<Vec<u8>>> {
    let k = stripe.k as usize;
    if valid.len() < k {
        return Err(Error::NotEnoughShards {
            have: valid.len(),
            need: k,
        });
    }
    let mut data: Vec<Option<Vec<u8>>> = vec![None; k];
    for &(i, s) in valid.iter().filter(|(i, _)| *i < k) {
        data[i] = Some(s.to_vec());
    }
    if data.iter().any(Option::is_none) {
        let originals = valid.iter().filter(|(i, _)| *i < k).copied();
        let recovery = valid.iter().filter(|(i, _)| *i >= k).map(|&(i, s)| (i - k, s));
        for (i, s) in reed_solomon_simd::decode(k, stripe.m as usize, originals, recovery)? {
            data[i] = Some(s);
        }
    }
    Ok(data
        .into_iter()
        .map(|s| s.expect("RS вернул все недостающие data-шарды"))
        .collect())
}

/// Собирает шифротекст сегмента из любых k целых шардов; битые шарды пропускаются.
pub fn decode_stripe<S: AsRef<[u8]>>(stripe: &Stripe, shards: &[Option<S>]) -> Result<Vec<u8>> {
    if stripe.code == Code::Clay {
        return crate::clay::decode_stripe(stripe, shards);
    }
    let valid = verified(stripe, shards)?;
    let data = recover_data(stripe, &valid)?.concat();
    unpad(stripe, &data)
}

/// Отрезок data-шарда: `[off, off + len)` внутри шарда с индексом `shard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardRange {
    pub shard: usize,
    pub off: usize,
    pub len: usize,
}

/// Какие отрезки data-шардов покрывают `[ct_off, ct_off + ct_len)` шифротекста (с учётом префикса
/// `len: u32`). Отрезки идут по возрастанию шардов, их конкатенация — искомые байты.
/// Ошибка, если диапазон выходит за `k * shard_len` или параметры некорректны.
pub fn shard_ranges(shard_len: usize, k: usize, ct_off: usize, ct_len: usize) -> Result<Vec<ShardRange>> {
    if shard_len == 0 || k == 0 {
        return Err(Error::CorruptStripe("пустая геометрия страйпа"));
    }
    let start = ct_off
        .checked_add(LEN_PREFIX)
        .ok_or(Error::CorruptStripe("диапазон вне страйпа"))?;
    let end = start
        .checked_add(ct_len)
        .filter(|&e| e <= k * shard_len)
        .ok_or(Error::CorruptStripe("диапазон вне страйпа"))?;
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let shard = pos / shard_len;
        let off = pos % shard_len;
        let len = (shard_len - off).min(end - pos);
        out.push(ShardRange { shard, off, len });
        pos += len;
    }
    Ok(out)
}

/// Собирает байты шифротекста из кусков, полученных по `ranges` (в том же порядке).
pub fn assemble_ranges<P: AsRef<[u8]>>(ranges: &[ShardRange], parts: &[P]) -> Result<Vec<u8>> {
    if ranges.len() != parts.len() {
        return Err(Error::CorruptStripe("число кусков не равно числу отрезков"));
    }
    let mut out = Vec::with_capacity(ranges.iter().map(|r| r.len).sum());
    for (r, p) in ranges.iter().zip(parts) {
        if p.as_ref().len() != r.len {
            return Err(Error::CorruptStripe("длина куска не равна длине отрезка"));
        }
        out.extend_from_slice(p.as_ref());
    }
    Ok(out)
}

/// Выравнивание под-диапазонов для декодирования: RS-кодек работает независимо над блоками
/// по 64 байта одной и той же позиции во всех шардах, поэтому любой выровненный по 64 отрезок
/// `[a, b)` можно декодировать отдельно, взяв его у k любых шардов.
const RANGE_ALIGN: usize = SHARD_ALIGN;

/// Выровненный по 64 байта отрезок внутри шарда, накрывающий `[off, off + len)`.
/// Ошибка, если `shard_len` не кратен 64 (так хвостовой блок короче и раскладка другая;
/// страйпы, записанные клиентом, всегда кратны) или отрезок выходит за шард.
pub fn aligned_span(shard_len: usize, off: usize, len: usize) -> Result<(usize, usize)> {
    if shard_len == 0 || !shard_len.is_multiple_of(RANGE_ALIGN) {
        return Err(Error::CorruptStripe(
            "shard_len не кратен 64: под-диапазон не декодировать",
        ));
    }
    let end = off
        .checked_add(len)
        .filter(|&e| e <= shard_len && len > 0)
        .ok_or(Error::CorruptStripe("отрезок вне шарда"))?;
    Ok((off / RANGE_ALIGN * RANGE_ALIGN, end.next_multiple_of(RANGE_ALIGN)))
}

/// Восстанавливает байты `[off, off + len)` data-шарда `want` по выровненным отрезкам
/// ([`aligned_span`]) любых k других шардов (`pieces`: индекс шарда и его байты `[a, b)`).
pub fn recover_shard_range<S: AsRef<[u8]>>(
    k: usize,
    m: usize,
    shard_len: usize,
    want: usize,
    off: usize,
    len: usize,
    pieces: &[(usize, S)],
) -> Result<Vec<u8>> {
    check_params(k as u8, m as u8)?;
    let (a, b) = aligned_span(shard_len, off, len)?;
    if want >= k {
        return Err(Error::CorruptStripe("восстанавливается только data-шард"));
    }
    if pieces.iter().any(|(i, p)| *i >= k + m || p.as_ref().len() != b - a) {
        return Err(Error::CorruptStripe("отрезок шарда неверной длины"));
    }
    let skip = off - a;
    if let Some((_, p)) = pieces.iter().find(|(i, _)| *i == want) {
        return Ok(p.as_ref()[skip..skip + len].to_vec());
    }
    if pieces.len() < k {
        return Err(Error::NotEnoughShards {
            have: pieces.len(),
            need: k,
        });
    }
    let originals = pieces.iter().filter(|(i, _)| *i < k).map(|(i, p)| (*i, p.as_ref()));
    let recovery = pieces
        .iter()
        .filter(|(i, _)| *i >= k)
        .map(|(i, p)| (*i - k, p.as_ref()));
    let restored = reed_solomon_simd::decode(k, m, originals.take(k), recovery.take(k))?;
    let got = restored
        .into_iter()
        .find(|(i, _)| *i == want)
        .ok_or(Error::CorruptStripe("RS не вернул нужный шард"))?
        .1;
    Ok(got[skip..skip + len].to_vec())
}

/// Ремонт: пересобирает шарды с индексами `wanted` и проверяет их хэши по манифесту.
pub fn reconstruct<S: AsRef<[u8]>>(
    stripe: &Stripe,
    shards: &[Option<S>],
    wanted: &[usize],
) -> Result<Vec<(usize, Vec<u8>)>> {
    if stripe.code == Code::Clay {
        return crate::clay::reconstruct(stripe, shards, wanted);
    }
    let k = stripe.k as usize;
    let valid = verified(stripe, shards)?;
    let data = recover_data(stripe, &valid)?;
    let parity = if wanted.iter().any(|&i| i >= k) {
        reed_solomon_simd::encode(k, stripe.m as usize, &data)?
    } else {
        Vec::new()
    };
    wanted
        .iter()
        .map(|&i| {
            let shard = match i {
                i if i < k => data[i].clone(),
                i => parity
                    .get(i - k)
                    .cloned()
                    .ok_or(Error::CorruptStripe("индекс шарда вне k+m"))?,
            };
            let actual = Hash::of(&shard);
            if actual != stripe.shards[i] {
                return Err(Error::HashMismatch {
                    expected: stripe.shards[i],
                    actual,
                });
            }
            Ok((i, shard))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

    fn sample(len: usize, seed: u64) -> Vec<u8> {
        let mut v = vec![0u8; len];
        StdRng::seed_from_u64(seed).fill_bytes(&mut v);
        v
    }

    fn subset(shards: &[Vec<u8>], mask: u32) -> Vec<Option<&Vec<u8>>> {
        shards
            .iter()
            .enumerate()
            .map(|(i, s)| (mask >> i & 1 == 1).then_some(s))
            .collect()
    }

    /// Критерий этапа 1: восстановление из любых k из k+m — перебор всех C(14,8) = 3003 подмножеств.
    #[test]
    fn any_k_of_n_recovers() {
        let ct = sample(100_003, 1);
        let enc = encode_stripe(&ct, 8, 6).unwrap();
        let mut checked = 0;
        for mask in 0u32..1 << 14 {
            if mask.count_ones() == 8 {
                assert_eq!(decode_stripe(&enc.stripe, &subset(&enc.shards, mask)).unwrap(), ct);
                checked += 1;
            }
        }
        assert_eq!(checked, 3003);
    }

    #[test]
    fn fewer_than_k_fails() {
        let enc = encode_stripe(&sample(5000, 2), 8, 6).unwrap();
        let err = decode_stripe(&enc.stripe, &subset(&enc.shards, 0b0111_1111)).unwrap_err();
        assert!(matches!(err, Error::NotEnoughShards { have: 7, need: 8 }));
    }

    #[test]
    fn deterministic_hashes() {
        let ct = sample(77_777, 3);
        assert_eq!(
            encode_stripe(&ct, 8, 6).unwrap().stripe,
            encode_stripe(&ct, 8, 6).unwrap().stripe
        );
    }

    #[test]
    fn corrupted_shard_is_skipped() {
        let ct = sample(10_000, 4);
        let enc = encode_stripe(&ct, 8, 6).unwrap();
        let mut shards: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
        shards[0].as_mut().unwrap()[0] ^= 1; // битый data-шард
        shards[3] = None;
        assert_eq!(decode_stripe(&enc.stripe, &shards).unwrap(), ct);

        // битых и отсутствующих больше m — данных не хватает, а не тихая порча
        for s in &mut shards[4..10] {
            *s = None;
        }
        assert!(matches!(
            decode_stripe(&enc.stripe, &shards),
            Err(Error::NotEnoughShards { .. })
        ));
    }

    #[test]
    fn repair_reproduces_manifest_hashes() {
        let mut rng = StdRng::seed_from_u64(5);
        for _ in 0..50 {
            let ct = sample(rng.random_range(1..50_000), rng.random());
            let enc = encode_stripe(&ct, 8, 6).unwrap();
            let lost: Vec<usize> = rand::seq::index::sample(&mut rng, 14, 6).into_vec();
            let have: Vec<_> = (0..14).map(|i| (!lost.contains(&i)).then(|| &enc.shards[i])).collect();
            for (i, shard) in reconstruct(&enc.stripe, &have, &lost).unwrap() {
                assert_eq!(shard, enc.shards[i]);
            }
        }
    }

    #[test]
    fn odd_params_and_tiny_input() {
        for (k, m) in [(1, 1), (1, 5), (3, 2), (10, 4), (16, 16)] {
            for len in [0, 1, 63, 64, 65, 1000] {
                let ct = sample(len, len as u64);
                let enc = encode_stripe(&ct, k, m).unwrap();
                let all: Vec<_> = enc.shards.iter().map(Some).collect();
                assert_eq!(decode_stripe(&enc.stripe, &all).unwrap(), ct);
            }
        }
        assert!(encode_stripe(b"x", 0, 4).is_err());
        assert!(encode_stripe(b"x", 8, 0).is_err());
    }

    /// Подложная геометрия в манифесте (M11): `k·shard_len` меньше префикса длины, нулевой,
    /// нечётный или огромный `shard_len` — ошибка, а не паника и не гигантская аллокация.
    #[test]
    fn crafted_geometry_is_rejected() {
        let craft = |k: u8, m: u8, shard: &[u8], shard_len: u32| {
            let n = k as usize + m as usize;
            let shards: Vec<Vec<u8>> = vec![shard.to_vec(); n];
            let stripe = Stripe {
                stripe_id: Hash::of(b""),
                k,
                m,
                shard_len,
                shards: shards.iter().map(|s| Hash::of(s)).collect(),
                code: Code::Rs,
            };
            let have: Vec<Option<&Vec<u8>>> = shards.iter().map(Some).collect();
            (decode_stripe(&stripe, &have), reconstruct(&stripe, &have, &[0]))
        };
        for (k, shard, len) in [(1u8, &b""[..], 0u32), (1, b"ab", 2), (1, b"abc", 3), (2, b"\0", 1)] {
            let (d, r) = craft(k, 1, shard, len);
            assert!(matches!(d, Err(Error::CorruptStripe(_))), "k={k} len={len}: {d:?}");
            assert!(matches!(r, Err(Error::CorruptStripe(_))), "k={k} len={len}: {r:?}");
        }
        // наименьшая допустимая геометрия разбирается без паники: k·shard_len = 4
        let (d, _) = craft(2, 1, &[0, 0], 2);
        assert!(matches!(d, Err(Error::HashMismatch { .. }) | Ok(_)), "{d:?}");
        let (d, _) = craft(1, 1, b"", (MAX_SHARD_LEN + 2) as u32);
        assert!(matches!(d, Err(Error::CorruptStripe(_))), "{d:?}");
        assert!(encode_stripe(&[0u8; 8], 1, 1).is_ok());
    }

    /// Открытый вопрос из ТЗ: зависят ли parity-шарды от общего m.
    #[test]
    fn parity_depends_on_m() {
        let ct = sample(10_000, 6);
        let p4 = encode_stripe(&ct, 8, 4).unwrap().shards;
        let p6 = encode_stripe(&ct, 8, 6).unwrap().shards;
        // Ответ: зависят. Дописать parity без перекодирования нельзя —
        // m фиксируется при записи, изменение m = полное перекодирование страйпа.
        assert!((8..12).all(|i| p4[i] != p6[i]));
        assert_eq!(p4[..8], p6[..8]);
    }

    #[test]
    fn shard_subrange_recovers_from_parity() {
        let ct = sample(5000, 8);
        let (k, m) = (4usize, 3usize);
        let enc = encode_stripe(&ct, k as u8, m as u8).unwrap();
        let sl = enc.stripe.shard_len as usize;
        for (want, off, len) in [
            (0, 0, 1),
            (1, 5, 100),
            (2, 63, 2),
            (3, sl - 7, 7),
            (1, 64, 64),
            (0, 10, sl - 10),
        ] {
            let (a, b) = aligned_span(sl, off, len).unwrap();
            assert!(a % 64 == 0 && b % 64 == 0 && a <= off && off + len <= b);
            // без шарда want: часть data и parity
            let idx: Vec<usize> = (0..k + m).filter(|&i| i != want).skip(2).take(k).collect();
            assert!(idx.iter().any(|&i| i >= k));
            let pieces: Vec<(usize, &[u8])> = idx.iter().map(|&i| (i, &enc.shards[i][a..b])).collect();
            let got = recover_shard_range(k, m, sl, want, off, len, &pieces).unwrap();
            assert_eq!(got, &enc.shards[want][off..off + len], "{want} {off}+{len}");
        }
        assert!(aligned_span(sl, sl - 1, 2).is_err());
        assert!(aligned_span(100, 0, 1).is_err());
    }

    #[test]
    fn shard_range_geometry() {
        let ct = sample(1000, 7);
        let enc = encode_stripe(&ct, 4, 2).unwrap();
        let sl = enc.stripe.shard_len as usize;
        let k = 4;
        // граничные и сквозные диапазоны
        for (off, len) in [
            (0, 1),
            (0, sl - 4),
            (sl - 5, 2),
            (sl - 4, 1),
            (10, 990),
            (0, 1000),
            (999, 1),
            (5, 0),
        ] {
            let ranges = shard_ranges(sl, k, off, len).unwrap();
            assert!(ranges.iter().all(|r| r.shard < k && r.off + r.len <= sl && r.len > 0));
            let parts: Vec<&[u8]> = ranges
                .iter()
                .map(|r| &enc.shards[r.shard][r.off..r.off + r.len])
                .collect();
            assert_eq!(
                assemble_ranges(&ranges, &parts).unwrap(),
                &ct[off..off + len],
                "{off}+{len}"
            );
        }
        // префикс len сдвигает границу шарда: байт sl-4 шифротекста — первый байт шарда 1
        let r = shard_ranges(sl, k, sl - 4, 1).unwrap();
        assert_eq!(
            r,
            vec![ShardRange {
                shard: 1,
                off: 0,
                len: 1
            }]
        );
        assert!(shard_ranges(sl, k, 0, k * sl).is_err());
        assert!(shard_ranges(sl, k, usize::MAX, 2).is_err());
        assert!(assemble_ranges::<&[u8]>(&shard_ranges(sl, k, 0, 10).unwrap(), &[]).is_err());
    }
}
