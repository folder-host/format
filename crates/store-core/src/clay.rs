//! Экспериментальный Clay-кодек страйпа (coupled-layer MSR; Vajha et al., FAST'18;
//! эталон — плагин Ceph `ErasureCodeClay`). Альтернатива [`crate::codec`] (RS k+m):
//! тот же формат данных и тот же [`Stripe`] в манифесте, но ремонт одного шарда читает
//! с каждого из `d = n-1` выживших только `β = α/q` из `α` под-чанков, т.е.
//! `d/(d-k+1)` шарда вместо `k`. Для 8+6: 13/6 ≈ 2.17 шарда против 8.
//!
//! # Устройство
//!
//! * `n = k+m`, `d = n-1` (единственный поддерживаемый вариант, см. ниже), `q = d-k+1 = m`,
//!   `t = ⌈n/q⌉`. Код укорачивается до `n' = q·t` узлов: `ν = n'-n` виртуальных data-узлов
//!   с нулевым содержимым, `k' = k+ν`. Для 8+6: `q=6, t=3, n'=18, k'=12, ν=4`.
//! * Узел `i` имеет координаты `(x, y) = (i mod q, i div q)`. Нумерация узлов как в Ceph:
//!   шарды `0..k` → узлы `0..k`, виртуальные → `k..k'`, parity-шарды `k..n` → узлы `k'..n'`.
//! * Шард режется на `α = q^t` под-чанков (плоскостей) длины `L`; плоскость `z` —
//!   вектор цифр `(z_0..z_{t-1})` по основанию `q`, `z_0` старшая.
//! * В каждой плоскости *несцепленные* символы `U(·, z)` образуют кодовое слово скалярного
//!   MDS `[n', k']` — систематический RS из `reed_solomon_simd` (оригиналы — узлы `0..k'`,
//!   recovery — `k'..n'`), символ = вектор из `L` байт.
//! * Хранятся *сцепленные* символы `C`. Если `z_y = x` («точка»), `C(x,y,z) = U(x,y,z)`.
//!   Иначе узел спарен с `(z_y, y)` в плоскости `z' = z|_{z_y ← x}`, и
//!   `C = U + γ·U*`, `C* = γ·U + U*` (матрица `[[1,γ],[γ,1]]`, det = `1+γ²`), побайтно в
//!   GF(2^8) с полиномом 0x11D, `γ = 2`. Обратное: `U = (C + γ·C*) / (1+γ²)`.
//! * Систематичность: data-шарды — это `C` data-узлов, а их мы задаём сами равными исходным
//!   байтам; parity-`C` находятся «декодированием» с parity, объявленными стёртыми.
//!
//! # Почему смешение полей корректно
//!
//! RS из `reed_solomon_simd` работает в GF(2^16) со своим представлением байтов, сцепление —
//! в GF(2^8). Нигде не требуется, чтобы оба шага были линейны над одним полем. Алгоритмы
//! используют только два факта:
//! 1. в каждой плоскости любые `k'` из `n'` значений `U(·, z)` однозначно задают остальные
//!    (MDS-свойство RS: восстановление из любых `k'` шардов), причём кодовое слово
//!    существует для любых значений оригиналов;
//! 2. каждая пара `(C, C*) ↔ (U, U*)` — биекция (обратима при `γ ≠ 1`), а из `C` и `U*`
//!    получается `U = C + γ·U*`, из `C` и `U` — `U* = (C + U)/γ` (нужно `γ ≠ 0`).
//!
//! Кодирование конструктивно: для не-стёртых узлов `U` вычисляется так, что прямое сцепление
//! возвращает заданные `C`; в каждой плоскости стёртые `U` достраиваются RS, т.е. плоскость —
//! кодовое слово; стёртые `C` получаются прямым сцеплением. Значит, результат — корректное
//! кодовое слово с заданными data-`C`. Декодирование и ремонт на каждом шаге вычисляют
//! значение, *однозначно* вынужденное этими двумя фактами из известных данных; поэтому для
//! настоящего кодового слова они возвращают ровно его символы (а кодовое слово по data-`C`
//! единственно — тот же довод, применённый к декодированию с parity, стёртыми). Отсюда
//! побайтное совпадение ремонта с исходным шардом и с хэшем в манифесте.
//!
//! # Декодирование (≤ m стираний)
//!
//! Берём ровно `k` целых шардов (+ν виртуальных), остальные `m` считаем стёртыми. Для
//! плоскости `z` «число пересечений» `IS(z)` = число стёртых узлов-точек в `z`. Плоскости
//! обрабатываются по возрастанию `IS`. В плоскости `z` для каждого целого узла: точка —
//! `U = C`; партнёр цел — `U` из пары `C, C*`; партнёр стёрт — он точка в `z`, а в `z'`
//! уже нет (там точка — наш целый узел), так что `IS(z') = IS(z)-1`, `U*` уже найден RS в
//! `z'`, и `U = C + γ·U*`. Затем RS достраивает `U` стёртых. В конце `C` стёртых узлов —
//! прямым сцеплением.
//!
//! # Ремонт узла `f = (x0, y0)` из всех `n'-1` остальных
//!
//! Плоскости ремонта `R = {z : z_{y0} = x0}`, `|R| = β = α/q`; каждый хелпер отдаёт свои `C`
//! в `R` (виртуальные — нули, их никто не передаёт). В `z ∈ R` для узлов с `y ≠ y0` партнёр
//! лежит в той же группе `y` и в плоскости из `R` — `U` вычисляется из пары. Неизвестны `U`
//! ровно `q = m` узлов группы `y0` — их достраивает RS. Для `z ∉ R` (`z_{y0} = x ≠ x0`)
//! партнёр `f` — хелпер `h = (x, y0)` в плоскости `z* ∈ R`: `U(f,z) = (C(h,z*) + U(h,z*))/γ`,
//! `C(f,z) = U(f,z) + γ·U(h,z*)`.
//!
//! # Ограничения и риски
//!
//! * Только `d = n-1`. Вариант `d < n-1` требует «отстранённых» (aloof) узлов и упорядочивания
//!   плоскостей при ремонте, как в Ceph; при этом и `q` меняется. В манифесте `d` не хранится,
//!   поэтому [`ClayParams::from_stripe`] выводит `d = k+m-1`.
//! * Ремонт требует **всех** `n-1` выживших; при меньшем числе [`repair`] возвращает
//!   [`Error::NotEnoughShards`], и вызывающий откатывается на [`reconstruct`] из `k` целых шардов.
//! * Ответы хелперов проверить по отдельности нельзя (в манифесте хэши целых шардов, а не
//!   под-чанков). Один битый хелпер → неверный итог → [`Error::HashMismatch`] на проверке
//!   итога → откат на полный decode (вычислить виновника без лишних данных нельзя).
//!   Если это станет проблемой — хранить в манифесте хэши под-чанков (α·n хэшей — дорого)
//!   или дерево Меркла по под-чанкам шарда.
//! * Под-чанк выравнивается на [`SUB_ALIGN`] = 64 байта (для `reed_solomon_simd` хватило бы 2,
//!   64 — ради SIMD-скорости), т.е. `shard_len` кратен `α·64 = 13824` для 8+6: мелкие
//!   сегменты раздуваются сильнее, чем в RS (минимум ~108 КиБ на страйп).
//!
//! # Версионирование (решение за интеграцией)
//!
//! В [`Stripe`] нет поля кода, формат здесь не меняется. Предложение: добавить в `Stripe`
//! тег кода `code: u8` (0 = RS/`codec`, 1 = Clay с `d = k+m-1`; при надобности — `d` отдельным
//! полем) с новой версией формата манифеста; старые манифесты без тега читаются как RS.
//! Альтернатива без смены формата — кодировать тег в старших битах `m`/`k` нельзя (ломает
//! проверки), поэтому только явное поле.

use crate::{Error, Hash, Result, format::Stripe};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

pub use crate::codec::EncodedStripe;

use crate::codec::{LEN_PREFIX, check_geometry, unpad};
/// Выравнивание под-чанка. `reed_solomon_simd` 3.x требует лишь чётную ненулевую длину
/// шарда; 64 — чтобы SIMD-движок работал без хвостов.
pub const SUB_ALIGN: usize = 64;
/// Предел `α`: выше — слишком мелкие под-чанки и огромный минимальный шард.
const MAX_ALPHA: usize = 4096;

// ---------------------------------------------------------------- GF(2^8), полином 0x11D

const GAMMA: u8 = 2;

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    r
}

/// `a^254 = a^{-1}` для `a ≠ 0`.
const fn gf_inv(a: u8) -> u8 {
    let mut r = 1u8;
    let mut i = 0;
    while i < 254 {
        r = gf_mul(r, a);
        i += 1;
    }
    r
}

const fn mul_table(c: u8) -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = gf_mul(i as u8, c);
        i += 1;
    }
    t
}

/// `1 / (1 + γ²)` — обратный определитель матрицы сцепления.
const DET_INV: u8 = gf_inv(1 ^ gf_mul(GAMMA, GAMMA));
static MUL_G: [u8; 256] = mul_table(GAMMA);
static MUL_INV_G: [u8; 256] = mul_table(gf_inv(GAMMA));
static MUL_S: [u8; 256] = mul_table(DET_INV);
static MUL_SG: [u8; 256] = mul_table(gf_mul(DET_INV, GAMMA));

/// `out = a + γ·b`. Это и прямое сцепление (`C = U + γ·U*`), и «отслаивание» (`U = C + γ·U*`).
fn xor_mul_g(out: &mut [u8], a: &[u8], b: &[u8]) {
    for ((o, &a), &b) in out.iter_mut().zip(a).zip(b) {
        *o = a ^ MUL_G[b as usize];
    }
}

/// `U = (C + γ·C*) / (1+γ²)`.
fn uncouple(out: &mut [u8], c: &[u8], cp: &[u8]) {
    for ((o, &a), &b) in out.iter_mut().zip(c).zip(cp) {
        *o = MUL_S[a as usize] ^ MUL_SG[b as usize];
    }
}

/// Ремонт вне `R`: `U(f) = (C_h + U_h)/γ`, `C(f) = U(f) + γ·U_h`.
fn repair_symbol(out: &mut [u8], c_h: &[u8], u_h: &[u8]) {
    for ((o, &c), &u) in out.iter_mut().zip(c_h).zip(u_h) {
        *o = MUL_INV_G[(c ^ u) as usize] ^ MUL_G[u as usize];
    }
}

// ---------------------------------------------------------------- параметры

/// Геометрия Clay-кода. `d = n-1`, `q = d-k+1`, `α = q^t`, `β = α/q`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClayParams {
    pub k: usize,
    pub m: usize,
    pub d: usize,
    pub q: usize,
    pub t: usize,
    /// Число виртуальных нулевых data-узлов (укорочение).
    pub nu: usize,
    /// Под-чанков на шард.
    pub alpha: usize,
    /// Под-чанков, которые отдаёт каждый хелпер при ремонте.
    pub beta: usize,
}

impl ClayParams {
    /// Поддерживается только `d = k+m-1` (все выжившие — хелперы).
    pub fn new(k: u8, m: u8, d: u8) -> Result<Self> {
        Self::build(k, m, Some(d as usize))
    }

    /// Параметры страйпа: в манифесте нет `d`, принимается `d = k+m-1`.
    pub fn from_stripe(stripe: &Stripe) -> Result<Self> {
        Self::build(stripe.k, stripe.m, None)
    }

    fn build(k8: u8, m8: u8, d: Option<usize>) -> Result<Self> {
        let bad = || Error::InvalidParams { k: k8, m: m8 };
        let (k, m) = (k8 as usize, m8 as usize);
        if k == 0 || m == 0 {
            return Err(bad());
        }
        let n = k + m;
        let d = d.unwrap_or(n - 1);
        if d != n - 1 {
            return Err(bad());
        }
        let q = d - k + 1;
        let t = n.div_ceil(q);
        let nu = q * t - n;
        let alpha = u32::try_from(t)
            .ok()
            .and_then(|t| q.checked_pow(t))
            .filter(|&a| a <= MAX_ALPHA)
            .ok_or_else(bad)?;
        if !ReedSolomonEncoder::supports(k + nu, m) {
            return Err(bad());
        }
        Ok(Self {
            k,
            m,
            d,
            q,
            t,
            nu,
            alpha,
            beta: alpha / q,
        })
    }

    /// Реальных шардов `k+m`.
    pub fn n(&self) -> usize {
        self.k + self.m
    }

    fn n_ext(&self) -> usize {
        self.q * self.t
    }

    fn k_ext(&self) -> usize {
        self.k + self.nu
    }

    /// Индекс шарда → индекс узла укороченного кода.
    fn node(&self, shard: usize) -> usize {
        if shard < self.k { shard } else { shard + self.nu }
    }

    fn pow(&self, y: usize) -> usize {
        self.q.pow((self.t - 1 - y) as u32)
    }

    fn digit(&self, z: usize, y: usize) -> usize {
        z / self.pow(y) % self.q
    }

    /// Плоскость `z` с заменой цифры `y` на `x`.
    fn with_digit(&self, z: usize, y: usize, x: usize) -> usize {
        let p = self.pow(y);
        z - self.digit(z, y) * p + x * p
    }

    /// Длина под-чанка для `shard_len`, если он допустим.
    fn sub_len(&self, shard_len: usize) -> Option<usize> {
        let l = shard_len / self.alpha;
        (shard_len.is_multiple_of(self.alpha) && l > 0 && l.is_multiple_of(2)).then_some(l)
    }

    /// Плоскости ремонта шарда `failed`: `{z : z_{y0} = x0}` по возрастанию, ровно `β` штук.
    fn repair_planes(&self, failed: usize) -> Vec<usize> {
        let f = self.node(failed);
        let (x0, y0) = (f % self.q, f / self.q);
        (0..self.alpha).filter(|&z| self.digit(z, y0) == x0).collect()
    }
}

// ---------------------------------------------------------------- вспомогательное

fn sub(v: &[u8], z: usize, l: usize) -> &[u8] {
    &v[z * l..(z + 1) * l]
}

fn sub_mut(v: &mut [u8], z: usize, l: usize) -> &mut [u8] {
    &mut v[z * l..(z + 1) * l]
}

/// `(&mut v[a], &v[b])`, `a ≠ b`.
fn pair_mut(v: &mut [Vec<u8>], a: usize, b: usize) -> (&mut [u8], &[u8]) {
    assert_ne!(a, b);
    if a < b {
        let (lo, hi) = v.split_at_mut(b);
        (lo[a].as_mut_slice(), hi[0].as_slice())
    } else {
        let (lo, hi) = v.split_at_mut(a);
        (hi[0].as_mut_slice(), lo[b].as_slice())
    }
}

/// Скалярный MDS `[k'+m, k']` одной плоскости поверх `reed_solomon_simd`.
struct Mds {
    k: usize,
    m: usize,
    l: usize,
    enc: ReedSolomonEncoder,
    dec: ReedSolomonDecoder,
}

impl Mds {
    fn new(k: usize, m: usize, l: usize) -> Result<Self> {
        Ok(Self {
            k,
            m,
            l,
            enc: ReedSolomonEncoder::new(k, m, l)?,
            dec: ReedSolomonDecoder::new(k, m, l)?,
        })
    }

    /// Достраивает под-чанк `z` стёртых узлов в `u` (≤ m стираний).
    fn fill(&mut self, u: &mut [Vec<u8>], erased: &[bool], z: usize) -> Result<()> {
        let (k, m, l) = (self.k, self.m, self.l);
        let r = z * l..(z + 1) * l;
        if erased[..k].iter().any(|&e| e) {
            for i in (0..k).filter(|&i| !erased[i]) {
                self.dec.add_original_shard(i, &u[i][r.clone()])?;
            }
            for j in (0..m).filter(|&j| !erased[k + j]) {
                self.dec.add_recovery_shard(j, &u[k + j][r.clone()])?;
            }
            let res = self.dec.decode()?;
            for (i, s) in res.restored_original_iter() {
                u[i][r.clone()].copy_from_slice(s);
            }
        }
        if erased[k..k + m].iter().any(|&e| e) {
            for ui in &u[..k] {
                self.enc.add_original_shard(&ui[r.clone()])?;
            }
            let res = self.enc.encode()?;
            for j in (0..m).filter(|&j| erased[k + j]) {
                let s = res.recovery(j).expect("encoder выдаёт все m recovery");
                u[k + j][r.clone()].copy_from_slice(s);
            }
        }
        Ok(())
    }
}

/// Достраивает `C` стёртых узлов (все `n'` узлов, ≤ m стёртых) по алгоритму с порядком
/// плоскостей по числу пересечений. Содержимое стёртых слотов `c` на входе игнорируется,
/// но они должны иметь длину `α·l`.
fn decode_layered(p: &ClayParams, l: usize, c: &mut [Vec<u8>], erased: &[bool]) -> Result<()> {
    let ne = p.n_ext();
    debug_assert_eq!(c.len(), ne);
    debug_assert_eq!(erased.len(), ne);
    let lost = erased.iter().filter(|&&e| e).count();
    if lost == 0 {
        return Ok(());
    }
    if lost > p.m {
        return Err(Error::NotEnoughShards {
            have: ne - lost - p.nu,
            need: p.k,
        });
    }
    let is = |z: usize| (0..ne).filter(|&i| erased[i] && p.digit(z, i / p.q) == i % p.q).count();
    let mut order: Vec<usize> = (0..p.alpha).collect();
    order.sort_by_key(|&z| is(z));

    let mut u = vec![vec![0u8; p.alpha * l]; ne];
    let mut mds = Mds::new(p.k_ext(), p.m, l)?;
    for &z in &order {
        for i in (0..ne).filter(|&i| !erased[i]) {
            let (x, y) = (i % p.q, i / p.q);
            let zy = p.digit(z, y);
            if zy == x {
                sub_mut(&mut u[i], z, l).copy_from_slice(sub(&c[i], z, l));
                continue;
            }
            let j = y * p.q + zy;
            let zp = p.with_digit(z, y, x);
            if !erased[j] {
                uncouple(sub_mut(&mut u[i], z, l), sub(&c[i], z, l), sub(&c[j], zp, l));
            } else {
                // j — стёртая точка в z; в zp он не точка, IS(zp) = IS(z)-1, U(j, zp) уже есть.
                let (ui, uj) = pair_mut(&mut u, i, j);
                xor_mul_g(sub_mut(ui, z, l), sub(&c[i], z, l), sub(uj, zp, l));
            }
        }
        mds.fill(&mut u, erased, z)?;
    }
    for e in (0..ne).filter(|&e| erased[e]) {
        let (x, y) = (e % p.q, e / p.q);
        for z in 0..p.alpha {
            let zy = p.digit(z, y);
            if zy == x {
                sub_mut(&mut c[e], z, l).copy_from_slice(sub(&u[e], z, l));
            } else {
                let j = y * p.q + zy;
                let zp = p.with_digit(z, y, x);
                xor_mul_g(sub_mut(&mut c[e], z, l), sub(&u[e], z, l), sub(&u[j], zp, l));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- API страйпа

/// Кодирует сегмент: данные `len(u32 LE) ‖ ciphertext ‖ нули` длиной `k·shard_len`,
/// `shard_len = α·L`, `L` кратен [`SUB_ALIGN`]. Шарды `0..k` — исходные байты.
pub fn encode_stripe(ciphertext: &[u8], k: u8, m: u8, d: u8) -> Result<EncodedStripe> {
    let p = ClayParams::new(k, m, d)?;
    let len = u32::try_from(ciphertext.len()).map_err(|_| Error::CorruptStripe("сегмент больше 4 ГиБ"))?;
    let l = (LEN_PREFIX + ciphertext.len())
        .div_ceil(p.k)
        .div_ceil(p.alpha)
        .next_multiple_of(SUB_ALIGN);
    let shard_len = l * p.alpha;
    check_geometry(p.k, shard_len)?;
    let shard_len32 = u32::try_from(shard_len).map_err(|_| Error::CorruptStripe("шард больше 4 ГиБ"))?;

    let mut data = Vec::with_capacity(p.k * shard_len);
    data.extend_from_slice(&len.to_le_bytes());
    data.extend_from_slice(ciphertext);
    data.resize(p.k * shard_len, 0);

    let mut c: Vec<Vec<u8>> = data.chunks_exact(shard_len).map(<[u8]>::to_vec).collect();
    drop(data);
    // виртуальные узлы — нули; слоты parity перезапишет decode_layered
    c.resize(p.n_ext(), vec![0u8; shard_len]);
    let erased: Vec<bool> = (0..p.n_ext()).map(|i| i >= p.k_ext()).collect();
    decode_layered(&p, l, &mut c, &erased)?;

    let shards: Vec<Vec<u8>> = (0..p.n()).map(|s| std::mem::take(&mut c[p.node(s)])).collect();
    let stripe = Stripe {
        stripe_id: Hash::of(ciphertext),
        k,
        m,
        shard_len: shard_len32,
        shards: shards.iter().map(|s| Hash::of(s)).collect(),
        code: crate::format::Code::Clay,
    };
    Ok(EncodedStripe { stripe, shards })
}

/// Параметры и длина под-чанка страйпа.
fn layout(stripe: &Stripe) -> Result<(ClayParams, usize)> {
    let p = ClayParams::from_stripe(stripe)?;
    if stripe.shards.len() != p.n() {
        return Err(Error::CorruptStripe("число хэшей шардов не равно k+m"));
    }
    // до `sub_len`: верхняя граница не даёт выделять память под подложный `shard_len`
    check_geometry(p.k, stripe.shard_len as usize)?;
    let l = p.sub_len(stripe.shard_len as usize).ok_or(Error::CorruptStripe(
        "shard_len не кратен α или под-чанк нечётной длины",
    ))?;
    Ok((p, l))
}

/// Параметры, длина под-чанка и целые шарды `(индекс, байты)`.
type Verified<'a> = (ClayParams, usize, Vec<(usize, &'a [u8])>);

/// Оставляет только шарды с верной длиной и хэшем из манифеста.
fn verified<'a, S: AsRef<[u8]>>(stripe: &Stripe, shards: &'a [Option<S>]) -> Result<Verified<'a>> {
    let (p, l) = layout(stripe)?;
    if shards.len() != p.n() {
        return Err(Error::CorruptStripe("ожидался слот на каждый из k+m шардов"));
    }
    let valid = shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| Some((i, s.as_ref()?.as_ref())))
        .filter(|(i, s)| s.len() == stripe.shard_len as usize && Hash::of(s) == stripe.shards[*i])
        .collect();
    Ok((p, l, valid))
}

/// `C` всех `n'` узлов из первых `k` целых шардов. Если все data-шарды целы и parity не
/// нужны, декодирование пропускается (слоты parity тогда — нули).
fn recover_nodes(p: &ClayParams, l: usize, valid: &[(usize, &[u8])], need_parity: bool) -> Result<Vec<Vec<u8>>> {
    if valid.len() < p.k {
        return Err(Error::NotEnoughShards {
            have: valid.len(),
            need: p.k,
        });
    }
    let ne = p.n_ext();
    let shard_len = p.alpha * l;
    let mut c: Vec<Vec<u8>> = vec![Vec::new(); ne];
    let mut erased = vec![true; ne];
    erased[p.k..p.k_ext()].fill(false);
    for &(s, bytes) in valid.iter().take(p.k) {
        let i = p.node(s);
        c[i] = bytes.to_vec();
        erased[i] = false;
    }
    for slot in c.iter_mut().filter(|s| s.is_empty()) {
        *slot = vec![0u8; shard_len];
    }
    let data_complete = erased[..p.k].iter().all(|&e| !e);
    if !data_complete || need_parity {
        decode_layered(p, l, &mut c, &erased)?;
    }
    Ok(c)
}

/// Собирает шифротекст сегмента из любых k целых шардов; битые шарды пропускаются.
pub fn decode_stripe<S: AsRef<[u8]>>(stripe: &Stripe, shards: &[Option<S>]) -> Result<Vec<u8>> {
    let (p, l, valid) = verified(stripe, shards)?;
    let c = recover_nodes(&p, l, &valid, false)?;
    let data = c[..p.k].concat();
    unpad(stripe, &data)
}

/// Полный ремонт (откат): пересобирает шарды `wanted` из любых k целых и проверяет хэши.
pub fn reconstruct<S: AsRef<[u8]>>(
    stripe: &Stripe,
    shards: &[Option<S>],
    wanted: &[usize],
) -> Result<Vec<(usize, Vec<u8>)>> {
    let (p, l, valid) = verified(stripe, shards)?;
    if wanted.iter().any(|&i| i >= p.n()) {
        return Err(Error::CorruptStripe("индекс шарда вне k+m"));
    }
    let c = recover_nodes(&p, l, &valid, wanted.iter().any(|&i| i >= p.k))?;
    wanted
        .iter()
        .map(|&i| {
            let shard = c[p.node(i)].clone();
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

/// План ремонта шарда `failed`: для каждого из `n-1` хелперов — номера под-чанков
/// (по возрастанию, `β` штук; у всех хелперов одинаковые). Пусто, если `failed ≥ n`.
pub fn repair_plan(p: &ClayParams, failed: usize) -> Vec<(usize, Vec<usize>)> {
    if failed >= p.n() {
        return Vec::new();
    }
    let planes = p.repair_planes(failed);
    (0..p.n())
        .filter(|&h| h != failed)
        .map(|h| (h, planes.clone()))
        .collect()
}

/// Что хелпер отдаёт для ремонта `failed`: `β` под-чанков своего шарда подряд в порядке
/// [`repair_plan`], итого `shard_len·β/α` байт. Ошибка при неверных `failed`/длине шарда
/// (запрос приходит по сети — паниковать нельзя).
pub fn helper_symbols(p: &ClayParams, shard: &[u8], failed: usize) -> Result<Vec<u8>> {
    if failed >= p.n() {
        return Err(Error::CorruptStripe("индекс шарда вне k+m"));
    }
    let l = p
        .sub_len(shard.len())
        .ok_or(Error::CorruptStripe("длина шарда не кратна α"))?;
    let mut out = Vec::with_capacity(p.beta * l);
    for z in p.repair_planes(failed) {
        out.extend_from_slice(sub(shard, z, l));
    }
    Ok(out)
}

/// Ремонт шарда `failed` по ответам [`helper_symbols`] всех `n-1` выживших. Итог
/// проверяется по хэшу манифеста. Ошибки: [`Error::NotEnoughShards`] — хелперов меньше
/// `n-1`; [`Error::HashMismatch`] — какой-то хелпер прислал битые данные. В обоих случаях —
/// откат на [`reconstruct`].
pub fn repair(stripe: &Stripe, failed: usize, helpers: &[(usize, Vec<u8>)]) -> Result<Vec<u8>> {
    let (p, l) = layout(stripe)?;
    let n = p.n();
    if failed >= n {
        return Err(Error::CorruptStripe("индекс шарда вне k+m"));
    }
    let blen = p.beta * l;
    let mut got: Vec<Option<&[u8]>> = vec![None; n];
    for (h, sym) in helpers {
        let h = *h;
        if h >= n || h == failed || got[h].is_some() {
            return Err(Error::CorruptStripe("неверный индекс хелпера"));
        }
        if sym.len() != blen {
            return Err(Error::CorruptStripe("длина ответа хелпера не равна β·L"));
        }
        got[h] = Some(sym.as_slice());
    }
    let have = got.iter().flatten().count();
    if have < n - 1 {
        return Err(Error::NotEnoughShards { have, need: n - 1 });
    }

    let f = p.node(failed);
    let (x0, y0) = (f % p.q, f / p.q);
    let planes = p.repair_planes(failed);
    debug_assert_eq!(planes.len(), p.beta);
    let mut ridx = vec![usize::MAX; p.alpha];
    for (r, &z) in planes.iter().enumerate() {
        ridx[z] = r;
    }

    let ne = p.n_ext();
    let zeros = vec![0u8; blen];
    // hc[i] — C узла i в плоскостях ремонта (компактно, индекс = позиция в `planes`)
    let mut hc: Vec<&[u8]> = vec![zeros.as_slice(); ne];
    for (s, sym) in got.iter().enumerate() {
        if let Some(sym) = *sym {
            hc[p.node(s)] = sym;
        }
    }

    let mut u = vec![vec![0u8; blen]; ne];
    let erased: Vec<bool> = (0..ne).map(|i| i / p.q == y0).collect();
    let mut mds = Mds::new(p.k_ext(), p.m, l)?;
    for (r, &z) in planes.iter().enumerate() {
        for i in (0..ne).filter(|&i| !erased[i]) {
            let (x, y) = (i % p.q, i / p.q);
            let zy = p.digit(z, y);
            if zy == x {
                sub_mut(&mut u[i], r, l).copy_from_slice(sub(hc[i], r, l));
            } else {
                // партнёр в группе y ≠ y0, его плоскость тоже в R
                let j = y * p.q + zy;
                let rp = ridx[p.with_digit(z, y, x)];
                uncouple(sub_mut(&mut u[i], r, l), sub(hc[i], r, l), sub(hc[j], rp, l));
            }
        }
        mds.fill(&mut u, &erased, r)?;
    }

    let mut out = vec![0u8; p.alpha * l];
    for z in 0..p.alpha {
        let zy0 = p.digit(z, y0);
        let dst = sub_mut(&mut out, z, l);
        if zy0 == x0 {
            dst.copy_from_slice(sub(&u[f], ridx[z], l));
        } else {
            let h = y0 * p.q + zy0;
            let rs = ridx[p.with_digit(z, y0, x0)];
            repair_symbol(dst, sub(hc[h], rs, l), sub(&u[h], rs, l));
        }
    }

    let actual = Hash::of(&out);
    if actual != stripe.shards[failed] {
        return Err(Error::HashMismatch {
            expected: stripe.shards[failed],
            actual,
        });
    }
    Ok(out)
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

    fn helpers_for(p: &ClayParams, shards: &[Vec<u8>], failed: usize) -> Vec<(usize, Vec<u8>)> {
        repair_plan(p, failed)
            .into_iter()
            .map(|(h, _)| (h, helper_symbols(p, &shards[h], failed).unwrap()))
            .collect()
    }

    #[test]
    fn params_8_6_13() {
        let p = ClayParams::new(8, 6, 13).unwrap();
        assert_eq!((p.q, p.t, p.nu, p.alpha, p.beta), (6, 3, 4, 216, 36));
        assert_eq!((p.n_ext(), p.k_ext()), (18, 12));
        assert!(ClayParams::new(8, 6, 12).is_err());
        assert!(ClayParams::new(0, 6, 5).is_err());
        assert!(ClayParams::new(8, 0, 7).is_err());
    }

    #[test]
    fn gf_arithmetic() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "{a}");
            assert_eq!(gf_mul(a, 1), a);
        }
        assert_eq!(gf_mul(0x80, 2), 0x1D);
        assert_ne!(DET_INV, 0);
        // uncouple ∘ couple = id на паре
        for (u, us) in [(0u8, 0u8), (1, 2), (0xAB, 0x37), (0xFF, 0xFF)] {
            let c = u ^ gf_mul(GAMMA, us);
            let cs = gf_mul(GAMMA, u) ^ us;
            let mut out = [0u8];
            uncouple(&mut out, &[c], &[cs]);
            assert_eq!(out[0], u);
            uncouple(&mut out, &[cs], &[c]);
            assert_eq!(out[0], us);
            repair_symbol(&mut out, &[cs], &[us]); // C(f) из C(h), U(h)
            assert_eq!(out[0], c);
        }
    }

    #[test]
    fn systematic() {
        let ct = sample(100_003, 1);
        let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
        let sl = enc.stripe.shard_len as usize;
        assert_eq!(sl % (216 * SUB_ALIGN), 0);
        let mut data = (ct.len() as u32).to_le_bytes().to_vec();
        data.extend_from_slice(&ct);
        data.resize(8 * sl, 0);
        for i in 0..8 {
            assert_eq!(enc.shards[i], data[i * sl..(i + 1) * sl], "data-шард {i}");
        }
        assert_eq!(enc.shards.len(), 14);
        assert!(enc.shards.iter().all(|s| s.len() == sl));
    }

    #[test]
    fn deterministic() {
        let ct = sample(77_777, 3);
        assert_eq!(
            encode_stripe(&ct, 8, 6, 13).unwrap().stripe,
            encode_stripe(&ct, 8, 6, 13).unwrap().stripe
        );
    }

    /// Случайная выборка k-подмножеств (полный перебор — в `any_k_of_n_exhaustive`).
    #[test]
    fn any_k_of_n_sampled() {
        let ct = sample(5_000, 2);
        let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
        let mut rng = StdRng::seed_from_u64(20);
        for _ in 0..300 {
            let mask = rand::seq::index::sample(&mut rng, 14, 8)
                .into_iter()
                .fold(0u32, |m, i| m | 1 << i);
            assert_eq!(
                decode_stripe(&enc.stripe, &subset(&enc.shards, mask)).unwrap(),
                ct,
                "{mask:#b}"
            );
        }
        // чисто parity-тяжёлое: 2 data + 6 parity
        let mask = 0b11_1111_1100_0000;
        assert_eq!(decode_stripe(&enc.stripe, &subset(&enc.shards, mask)).unwrap(), ct);
    }

    #[test]
    #[ignore = "долго: 3003 декодирования"]
    fn any_k_of_n_exhaustive() {
        let ct = sample(5_000, 2);
        let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
        let mut checked = 0;
        for mask in 0u32..1 << 14 {
            if mask.count_ones() == 8 {
                assert_eq!(
                    decode_stripe(&enc.stripe, &subset(&enc.shards, mask)).unwrap(),
                    ct,
                    "{mask:#b}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 3003);
    }

    #[test]
    fn fewer_than_k_fails() {
        let enc = encode_stripe(&sample(5000, 2), 8, 6, 13).unwrap();
        let err = decode_stripe(&enc.stripe, &subset(&enc.shards, 0b0111_1111)).unwrap_err();
        assert!(matches!(err, Error::NotEnoughShards { have: 7, need: 8 }));
    }

    #[test]
    fn corrupted_shard_is_skipped() {
        let ct = sample(10_000, 4);
        let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
        let mut shards: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
        shards[0].as_mut().unwrap()[0] ^= 1;
        shards[3] = None;
        assert_eq!(decode_stripe(&enc.stripe, &shards).unwrap(), ct);
        for s in &mut shards[4..10] {
            *s = None;
        }
        assert!(matches!(
            decode_stripe(&enc.stripe, &shards),
            Err(Error::NotEnoughShards { .. })
        ));
    }

    #[test]
    fn reconstruct_reproduces_manifest_hashes() {
        let mut rng = StdRng::seed_from_u64(5);
        for _ in 0..20 {
            let ct = sample(rng.random_range(1..50_000), rng.random());
            let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
            let lost: Vec<usize> = rand::seq::index::sample(&mut rng, 14, 6).into_vec();
            let have: Vec<_> = (0..14).map(|i| (!lost.contains(&i)).then(|| &enc.shards[i])).collect();
            for (i, shard) in reconstruct(&enc.stripe, &have, &lost).unwrap() {
                assert_eq!(shard, enc.shards[i]);
            }
        }
    }

    #[test]
    fn repair_plan_shape() {
        let p = ClayParams::new(8, 6, 13).unwrap();
        for f in 0..14 {
            let plan = repair_plan(&p, f);
            assert_eq!(plan.len(), 13);
            assert!(plan.iter().all(|(h, z)| *h != f && z.len() == 36));
            let mut hs: Vec<usize> = plan.iter().map(|(h, _)| *h).collect();
            hs.dedup();
            assert_eq!(hs.len(), 13);
            assert!(plan[0].1.windows(2).all(|w| w[0] < w[1]) && *plan[0].1.last().unwrap() < 216);
        }
        assert!(repair_plan(&p, 14).is_empty());
    }

    #[test]
    fn repair_every_index() {
        let p = ClayParams::new(8, 6, 13).unwrap();
        for (len, seed) in [(0, 10), (1000, 11), (100_003, 12)] {
            let ct = sample(len, seed);
            let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
            let sl = enc.stripe.shard_len as usize;
            for f in 0..14 {
                let helpers = helpers_for(&p, &enc.shards, f);
                for (_, sym) in &helpers {
                    assert_eq!(sym.len() * p.alpha, sl * p.beta);
                    assert_eq!(sym.len() * 6, sl);
                }
                let shard = repair(&enc.stripe, f, &helpers).unwrap();
                assert_eq!(shard, enc.shards[f], "len={len} f={f}");
            }
        }
    }

    #[test]
    fn repair_rejects_bad_or_missing_helpers() {
        let p = ClayParams::new(8, 6, 13).unwrap();
        let ct = sample(30_000, 13);
        let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
        for f in [0, 9] {
            let mut helpers = helpers_for(&p, &enc.shards, f);
            helpers[4].1[17] ^= 0x40;
            assert!(matches!(
                repair(&enc.stripe, f, &helpers),
                Err(Error::HashMismatch { .. })
            ));

            let mut helpers = helpers_for(&p, &enc.shards, f);
            helpers.pop();
            assert!(matches!(
                repair(&enc.stripe, f, &helpers),
                Err(Error::NotEnoughShards { have: 12, need: 13 })
            ));
            // откат: полный ремонт из k целых
            let have: Vec<_> = (0..14)
                .map(|i| (i != f && i % 3 != 0).then(|| &enc.shards[i]))
                .collect();
            assert_eq!(
                reconstruct(&enc.stripe, &have, &[f]).unwrap(),
                vec![(f, enc.shards[f].clone())]
            );

            let mut helpers = helpers_for(&p, &enc.shards, f);
            helpers[0].1.pop();
            assert!(repair(&enc.stripe, f, &helpers).is_err());
            let mut helpers = helpers_for(&p, &enc.shards, f);
            helpers[1].0 = helpers[0].0;
            assert!(repair(&enc.stripe, f, &helpers).is_err());
        }
        assert!(repair(&enc.stripe, 14, &[]).is_err());
        assert!(helper_symbols(&p, &enc.shards[0], 14).is_err());
        assert!(helper_symbols(&p, &enc.shards[0][1..], 1).is_err());
    }

    #[test]
    fn crafted_geometry_is_rejected() {
        // k=1, m=1: α=1, и `sub_len` пропустил бы shard_len = 2 при k·shard_len < 4
        for (k, m, shard_len) in [(1u8, 1u8, 0u32), (1, 1, 2), (1, 1, 3), (8, 6, u32::MAX - 1)] {
            let n = k as usize + m as usize;
            let stripe = Stripe {
                stripe_id: Hash::of(b""),
                k,
                m,
                shard_len,
                shards: vec![Hash::of(b"xx"); n],
                code: crate::format::Code::Clay,
            };
            let have: Vec<Option<Vec<u8>>> = vec![Some(b"xx".to_vec()); n];
            assert!(
                matches!(decode_stripe(&stripe, &have), Err(Error::CorruptStripe(_))),
                "{shard_len}"
            );
            assert!(matches!(
                reconstruct(&stripe, &have, &[0]),
                Err(Error::CorruptStripe(_))
            ));
            assert!(matches!(repair(&stripe, 0, &[]), Err(Error::CorruptStripe(_))));
        }
    }

    #[test]
    fn odd_params() {
        for (k, m) in [(1u8, 1u8), (1, 5), (2, 3), (3, 2), (4, 4), (10, 4), (12, 2), (16, 16)] {
            let p = ClayParams::new(k, m, k + m - 1).unwrap();
            let n = p.n();
            for len in [0, 1, 1000] {
                let ct = sample(len, len as u64 + k as u64);
                let enc = encode_stripe(&ct, k, m, k + m - 1).unwrap();
                let all: Vec<_> = enc.shards.iter().map(Some).collect();
                assert_eq!(decode_stripe(&enc.stripe, &all).unwrap(), ct);
                // последние k шардов
                let tail: Vec<_> = (0..n).map(|i| (i >= m as usize).then(|| &enc.shards[i])).collect();
                assert_eq!(decode_stripe(&enc.stripe, &tail).unwrap(), ct, "k={k} m={m}");
                for f in 0..n {
                    let helpers = helpers_for(&p, &enc.shards, f);
                    assert_eq!(
                        repair(&enc.stripe, f, &helpers).unwrap(),
                        enc.shards[f],
                        "k={k} m={m} f={f}"
                    );
                }
            }
        }
    }

    /// `cargo test -p store-core --release clay::tests::bench -- --ignored --nocapture`
    #[test]
    #[ignore = "бенчмарк"]
    fn bench_8mib() {
        use std::time::Instant;
        let ct = sample(8 << 20, 42);
        let mib = |bytes: usize, secs: f64| bytes as f64 / (1 << 20) as f64 / secs;

        let t = Instant::now();
        let enc = encode_stripe(&ct, 8, 6, 13).unwrap();
        let te = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let rs = crate::codec::encode_stripe(&ct, 8, 6).unwrap();
        let trs = t.elapsed().as_secs_f64();
        let sl = enc.stripe.shard_len as usize;
        println!(
            "encode: clay {:.1} МиБ/с, rs {:.1} МиБ/с (shard_len clay {sl}, rs {})",
            mib(ct.len(), te),
            mib(ct.len(), trs),
            rs.stripe.shard_len
        );

        let p = ClayParams::new(8, 6, 13).unwrap();
        for f in [0, 7, 8, 13] {
            let t = Instant::now();
            let helpers = helpers_for(&p, &enc.shards, f);
            let th = t.elapsed().as_secs_f64();
            let traffic: usize = helpers.iter().map(|(_, s)| s.len()).sum();
            let t = Instant::now();
            let shard = repair(&enc.stripe, f, &helpers).unwrap();
            let tr = t.elapsed().as_secs_f64();
            assert_eq!(shard, enc.shards[f]);
            println!(
                "repair f={f}: {:.1} МиБ/с восстановленного шарда ({:.1} мс), helper_symbols ×13 {:.1} мс, трафик {:.2} шарда",
                mib(sl, tr),
                tr * 1e3,
                th * 1e3,
                traffic as f64 / sl as f64
            );
        }

        let have = subset(&enc.shards, 0b11_1111_1100_0000);
        let t = Instant::now();
        assert_eq!(decode_stripe(&enc.stripe, &have).unwrap(), ct);
        let td = t.elapsed().as_secs_f64();
        let t = Instant::now();
        reconstruct(&enc.stripe, &have, &[0]).unwrap();
        let tf = t.elapsed().as_secs_f64();
        println!(
            "decode (2 data + 6 parity): {:.1} МиБ/с; полный ремонт 1 шарда (откат): {:.1} мс",
            mib(ct.len(), td),
            tf * 1e3
        );
    }
}
