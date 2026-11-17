//! Потоковый FastCDC (v2020, нормализация уровня 1).
//!
//! Конструкторы `fastcdc::v2020` ограничивают avg ≤ 4 МиБ, но таблица масок
//! покрывает размеры до 16 МиБ, поэтому цикл разрезания написан поверх
//! публичной функции [`fastcdc::v2020::cut_gear`] — так работают сегменты 4/8/16 МиБ.
//!
//! Таблица gear — секрет эпохи ключей данных ([`Chunker::keyed`]): с публичной таблицей границы
//! сегментов зависят только от содержимого, и у кого есть файл X, тот по вектору длин
//! сегментов в манифестах узнаёт, что X хранится. С таблицей из ключа длины известного файла
//! без ключа не предсказать. [`Chunker::new`] (публичная таблица) — для тестов и сравнений.

use std::io::Read;

use fastcdc::v2020::{Normalization, cut_gear, get_gear_with_seed, select_masks};

use crate::{Result, crypto::Key};

const GEAR_CONTEXT: &str = "store/chunk-gear/v1";

const MIB: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkParams {
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

impl ChunkParams {
    /// Параметры из ТЗ: 4–16 МиБ, цель 8 МиБ.
    pub const DEFAULT: Self = Self {
        min: 4 * MIB,
        avg: 8 * MIB,
        max: 16 * MIB,
    };

    /// Проверяет инварианты, которые `cut` предполагает молча.
    pub fn new(min: usize, avg: usize, max: usize) -> Self {
        assert!(avg.is_power_of_two(), "avg должен быть степенью двойки");
        assert!((256..=16 * MIB).contains(&avg), "avg вне таблицы масок FastCDC");
        assert!(64 <= min && min <= avg && avg <= max, "нужно 64 ≤ min ≤ avg ≤ max");
        assert!(
            min.is_multiple_of(2) && max.is_multiple_of(2),
            "min и max должны быть чётными"
        );
        Self { min, avg, max }
    }
}

impl Default for ChunkParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Итератор сегментов поверх `Read`; в памяти держит не больше `max` байт.
pub struct Chunker<R> {
    reader: R,
    params: ChunkParams,
    masks: [u64; 4],
    /// Таблица gear и её сдвинутая на бит копия (как `GEAR_LS` в fastcdc).
    gear: Box<[u64]>,
    gear_ls: Box<[u64]>,
    buf: Vec<u8>,
    eof: bool,
}

/// Таблица gear из ключа: 256 слов BLAKE3-XOF от `derive_key(GEAR_CONTEXT, key)`.
fn keyed_gear(key: &Key) -> (Box<[u64]>, Box<[u64]>) {
    let mut bytes = [0u8; 256 * 8];
    blake3::Hasher::new_derive_key(GEAR_CONTEXT)
        .update(&key.0)
        .finalize_xof()
        .fill(&mut bytes);
    let gear: Box<[u64]> = bytes
        .chunks_exact(8)
        .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
        .collect();
    let gear_ls = gear.iter().map(|g| g << 1).collect();
    (gear, gear_ls)
}

impl<R: Read> Chunker<R> {
    /// Нарезка с публичной таблицей gear fastcdc: границы зависят только от содержимого.
    pub fn new(reader: R, params: ChunkParams) -> Self {
        let (gear, gear_ls) = get_gear_with_seed(0);
        Self::with_gear(reader, params, gear.into(), gear_ls.into())
    }

    /// Нарезка с таблицей gear из секрета (корень ключей сегментов эпохи, `keyring::EpochKeys::segment`).
    pub fn keyed(reader: R, params: ChunkParams, key: &Key) -> Self {
        let (gear, gear_ls) = keyed_gear(key);
        Self::with_gear(reader, params, gear, gear_ls)
    }

    fn with_gear(reader: R, params: ChunkParams, gear: Box<[u64]>, gear_ls: Box<[u64]>) -> Self {
        let (mask_s, mask_l) = select_masks(params.avg, Normalization::Level1);
        Self {
            reader,
            params,
            masks: [mask_s, mask_l, mask_s << 1, mask_l << 1],
            gear,
            gear_ls,
            buf: Vec::with_capacity(params.max),
            eof: false,
        }
    }

    /// Дочитывает буфер до `max`. Хвост буфера обнуляется один раз на вызов, а не на каждое
    /// `read`: при мелких чтениях (по несколько байт) иначе выходит `O(max²)` обнуления.
    fn fill(&mut self) -> Result<()> {
        if self.eof || self.buf.len() >= self.params.max {
            return Ok(());
        }
        let mut filled = self.buf.len();
        self.buf.resize(self.params.max, 0);
        let res = loop {
            if filled >= self.params.max {
                break Ok(());
            }
            match self.reader.read(&mut self.buf[filled..]) {
                Ok(0) => {
                    self.eof = true;
                    break Ok(());
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e.into()),
            }
        };
        self.buf.truncate(filled);
        res
    }

    fn next_segment(&mut self) -> Result<Option<Vec<u8>>> {
        self.fill()?;
        if self.buf.is_empty() {
            return Ok(None);
        }
        let p = self.params;
        let [s, l, s_ls, l_ls] = self.masks;
        let (_, len) = cut_gear(
            &self.buf,
            p.min,
            p.avg,
            p.max,
            s,
            l,
            s_ls,
            l_ls,
            &self.gear,
            &self.gear_ls,
        );
        let rest = self.buf.split_off(len);
        let segment = std::mem::replace(&mut self.buf, rest);
        self.buf.reserve(p.max.saturating_sub(self.buf.len()));
        Ok(Some(segment))
    }
}

impl<R: Read> Iterator for Chunker<R> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_segment().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    fn chunks(data: &[u8], p: ChunkParams) -> Vec<Vec<u8>> {
        Chunker::new(data, p).collect::<Result<_>>().unwrap()
    }

    #[test]
    fn default_sizes_within_bounds() {
        let mut data = vec![0u8; 64 * MIB];
        StdRng::seed_from_u64(1).fill_bytes(&mut data);
        let cs = chunks(&data, ChunkParams::DEFAULT);
        assert_eq!(cs.concat(), data);
        for c in &cs[..cs.len() - 1] {
            assert!((4 * MIB..=16 * MIB).contains(&c.len()), "{}", c.len());
        }
    }

    #[test]
    fn boundaries_resync_after_insert() {
        let p = ChunkParams::new(1024, 4096, 16384);
        let mut data = vec![0u8; 1 << 20];
        StdRng::seed_from_u64(2).fill_bytes(&mut data);
        let before = chunks(&data, p);
        data.splice(1000..1000, *b"inserted");
        let after = chunks(&data, p);
        let same = after.iter().filter(|c| before.contains(c)).count();
        assert!(same >= before.len() - 3, "{same} из {}", before.len());
    }

    /// Читатель, отдающий по байту, не должен менять границы.
    #[test]
    fn short_reads_do_not_change_cuts() {
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.len().min(out.len()).min(7);
                out[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let p = ChunkParams::new(256, 1024, 4096);
        let mut data = vec![0u8; 100_000];
        StdRng::seed_from_u64(3).fill_bytes(&mut data);
        let a = chunks(&data, p);
        let b: Vec<_> = Chunker::new(Trickle(&data), p).collect::<Result<_>>().unwrap();
        assert_eq!(a, b);
    }

    /// Ключевание: разные ключи — разные границы (длины известного файла без ключа не
    /// предсказать), один ключ — те же границы; размеры в пределах параметров, данные целы.
    #[test]
    fn keyed_cuts_depend_on_key() {
        let p = ChunkParams::new(1024, 4096, 16384);
        let mut data = vec![0u8; 1 << 20];
        StdRng::seed_from_u64(4).fill_bytes(&mut data);
        let lens = |k: &Key| -> Vec<usize> { Chunker::keyed(&data[..], p, k).map(|c| c.unwrap().len()).collect() };
        let (a, b) = (Key([1; 32]), Key([2; 32]));
        assert_eq!(lens(&a), lens(&a));
        assert_ne!(lens(&a), lens(&b));
        let public: Vec<usize> = chunks(&data, p).iter().map(Vec::len).collect();
        assert_ne!(lens(&a), public);
        let cs: Vec<Vec<u8>> = Chunker::keyed(&data[..], p, &a).collect::<Result<_>>().unwrap();
        assert_eq!(cs.concat(), data);
        for c in &cs[..cs.len() - 1] {
            assert!((p.min..=p.max).contains(&c.len()), "{}", c.len());
        }
        // средний размер не уехал: таблица из ключа так же «случайна», как публичная
        let avg = data.len() / cs.len();
        assert!((2048..=8192).contains(&avg), "{avg}");
    }
}
