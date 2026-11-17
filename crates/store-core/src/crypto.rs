//! Шифрование XChaCha20-Poly1305. Формат шифротекста: `nonce(24) ‖ ct ‖ tag(16)`.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const NONCE_LEN: usize = 24;
pub const OVERHEAD: usize = NONCE_LEN + 16;

/// Симметричный 256-битный ключ: ключ сегмента или ключ метаданных пользователя.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub fn random() -> Self {
        Self(random_bytes())
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("системный ГСЧ недоступен");
    b
}

/// Шифрует `plaintext`; `aad` связывает шифротекст с контекстом (домен, назначение).
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    seal_with_nonce(key, &random_bytes(), plaintext, aad)
}

fn seal_with_nonce(key: &Key, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&key.0.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("шифрование в памяти не падает");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &Key, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < OVERHEAD {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = ciphertext.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(&key.0.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

/// Ключ сегмента для convergent encryption: `BLAKE3-keyed(root, plaintext)`.
/// Один `root` (ключ пользователя) и один plaintext дают один ключ.
pub fn segment_key(root: &Key, plaintext: &[u8]) -> Key {
    Key(*blake3::keyed_hash(&root.0, plaintext).as_bytes())
}

// ---------------------------------------------------------------- шифрование сегмента

/// Размер чанка открытого текста сегмента.
pub const SEGMENT_CHUNK: usize = 64 * 1024;
const TAG_LEN: usize = 16;
/// Размер зашифрованного полного чанка.
pub const SEGMENT_CHUNK_CT: usize = SEGMENT_CHUNK + TAG_LEN;
const SEGMENT_AAD: &[u8; 16] = b"store/segment/v3";

/// Длина открытого текста после выравнивания Padmé (Nikitin и др., 2019): у длины `L`
/// обнуляются младшие `⌊log₂L⌋ − ⌊log₂⌊log₂L⌋⌋ − 1` бит с округлением вверх. Длина сегмента
/// для узлов выдаёт O(log log L) бит, накладные — не больше 2^−(⌊log₂⌊log₂L⌋⌋+1): ~12% у
/// крошечных, ~3% (шаг 128–512 КиБ) у сегментов 4–16 МиБ. Нули выравнивания шифруются вместе
/// с данными.
pub fn padded_len(plain_len: usize) -> usize {
    if plain_len < 2 {
        return plain_len;
    }
    let e = plain_len.ilog2();
    let s = e.ilog2() + 1;
    let mask = (1usize << (e - s)) - 1;
    (plain_len + mask) & !mask
}

/// Число чанков сегмента с открытым текстом `plain_len` (по длине после выравнивания).
pub fn chunk_count(plain_len: usize) -> usize {
    padded_len(plain_len).div_ceil(SEGMENT_CHUNK)
}

/// Длина шифротекста сегмента: выровненная длина + 16 байт на чанк.
pub fn ciphertext_len(plain_len: usize) -> usize {
    padded_len(plain_len) + TAG_LEN * chunk_count(plain_len)
}

fn chunk_nonce(key: &Key, index: u64) -> [u8; NONCE_LEN] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(&key.0);
    material[32..].copy_from_slice(&index.to_le_bytes());
    blake3::derive_key("store/segment-chunk-nonce/v1", &material)[..NONCE_LEN]
        .try_into()
        .expect("32 >= 24")
}

/// AAD чанка: версия, номер чанка и настоящая длина сегмента (выровненная из неё выводится):
/// чанки нельзя переставить, отбросить или выдать за сегмент другой длины.
fn chunk_aad(index: u64, plain_len: u64) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..16].copy_from_slice(SEGMENT_AAD);
    aad[16..24].copy_from_slice(&index.to_le_bytes());
    aad[24..].copy_from_slice(&plain_len.to_le_bytes());
    aad
}

/// Шифрует сегмент чанками по [`SEGMENT_CHUNK`], дополнив открытый текст нулями до
/// [`padded_len`]. Nonce чанка выводится из ключа и номера, в шифротексте не хранится:
/// `enc(chunk_0) ‖ tag ‖ enc(chunk_1) ‖ tag ‖ …`. Детерминировано: один `key` и `plaintext` —
/// один шифротекст. Ключ должен однозначно определяться открытым текстом (см. [`segment_key`]),
/// иначе nonce повторится.
pub fn encrypt_segment(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&key.0.into());
    let total = plaintext.len() as u64;
    let mut padded = plaintext.to_vec();
    padded.resize(padded_len(plaintext.len()), 0);
    let mut out = Vec::with_capacity(ciphertext_len(plaintext.len()));
    for (i, chunk) in padded.chunks(SEGMENT_CHUNK).enumerate() {
        let i = i as u64;
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&chunk_nonce(key, i)),
                Payload {
                    msg: chunk,
                    aad: &chunk_aad(i, total),
                },
            )
            .expect("шифрование в памяти не падает");
        out.extend_from_slice(&ct);
    }
    out
}

/// Расшифровывает сегмент целиком; `plain_len` — длина открытого текста (из `FileMeta`).
pub fn decrypt_segment(key: &Key, ciphertext: &[u8], plain_len: usize) -> Result<Vec<u8>> {
    // целый сегмент обязан закончиться последним чанком (защита от усечения)
    if ciphertext.len() != ciphertext_len(plain_len) {
        return Err(Error::Decrypt);
    }
    let mut plain = decrypt_chunks(key, ciphertext, 0, plain_len)?;
    plain.truncate(plain_len);
    Ok(plain)
}

/// Расшифровывает подряд идущие чанки: `ct_part` — кусок шифротекста от начала чанка
/// `first_chunk` до конца какого-то чанка (последний чанк сегмента может быть короче).
/// Возвращает открытый текст этих чанков вместе с нулями выравнивания в последнем —
/// вызывающий режет по `plain_len`. Усечение на границе чанка здесь не видно (вызывающий
/// сам знает, какие чанки запросил); целый сегмент проверяет [`decrypt_segment`].
pub fn decrypt_chunks(key: &Key, ct_part: &[u8], first_chunk: usize, plain_len: usize) -> Result<Vec<u8>> {
    let padded = padded_len(plain_len);
    let total_chunks = chunk_count(plain_len);
    let cipher = XChaCha20Poly1305::new(&key.0.into());
    let mut out = Vec::with_capacity(ct_part.len());
    let mut rest = ct_part;
    let mut index = first_chunk;
    while !rest.is_empty() {
        if index >= total_chunks {
            return Err(Error::Decrypt);
        }
        // полный чанк, кроме последнего в сегменте
        let want = if index + 1 == total_chunks {
            padded - index * SEGMENT_CHUNK + TAG_LEN
        } else {
            SEGMENT_CHUNK_CT
        };
        if rest.len() < want {
            return Err(Error::Decrypt);
        }
        let (ct, tail) = rest.split_at(want);
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&chunk_nonce(key, index as u64)),
                Payload {
                    msg: ct,
                    aad: &chunk_aad(index as u64, plain_len as u64),
                },
            )
            .map_err(|_| Error::Decrypt)?;
        out.extend_from_slice(&pt);
        rest = tail;
        index += 1;
    }
    Ok(out)
}

/// Ключ подписи аккаунта из 32-байтного мастер-ключа (см. `docs/keys.md`). Публичная часть
/// ключа от первого мастер-ключа — неизменный идентификатор пользователя `user`; после ротации
/// (`RotateAccount`) control plane принимает подпись ключа от нового мастер-ключа.
pub fn account_signing_key(master: &[u8; 32]) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&blake3::derive_key("store/account/sign/v1", master))
}

// ---------------------------------------------------------------- X25519: шифрование получателю

/// Открытый X25519-ключ из 32-байтного секрета (секрет «зажимается» при умножении, как в RFC 7748).
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// X25519-ключ устройства по его ed25519-ключу (ключу iroh): точка Эдвардса переводится в форму
/// Монтгомери. Секрет — [`device_x25519_secret`]. Один ключ для подписи и ECDH: схема
/// доказуемо стойкая для ed25519 + X25519 (Thormarker, eprint 2021/509).
pub fn device_x25519_public(device: &ed25519_dalek::VerifyingKey) -> [u8; 32] {
    device.to_montgomery().to_bytes()
}

/// Секрет X25519 устройства: скаляр ed25519 (первая половина SHA-512 от seed) до «зажима».
pub fn device_x25519_secret(device: &ed25519_dalek::SigningKey) -> [u8; 32] {
    device.to_scalar_bytes()
}

const SEAL_TO_CONTEXT: &str = "store/seal-to/v1";
const X25519_LEN: usize = 32;
/// Накладные [`seal_to`]: эфемерный ключ и шифротекст [`seal`].
pub const SEAL_TO_OVERHEAD: usize = X25519_LEN + OVERHEAD;

fn seal_to_key(eph: &[u8; 32], recipient: &[u8; 32], shared: &[u8; 32]) -> Key {
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(eph);
    material[32..64].copy_from_slice(recipient);
    material[64..].copy_from_slice(shared);
    Key(blake3::derive_key(SEAL_TO_CONTEXT, &material))
}

/// Шифрует `plaintext` для владельца X25519-ключа `recipient`: эфемерный ключ, ECDH и
/// `derive_key(eph ‖ recipient ‖ shared)` — ключ [`seal`]. Формат: `eph(32) ‖ seal(…)`.
/// Точка малого порядка вместо ключа получателя (нулевой общий секрет) — ошибка.
pub fn seal_to(recipient: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let eph_secret: [u8; 32] = random_bytes();
    let eph = x25519_public(&eph_secret);
    let shared = MontgomeryPoint(*recipient).mul_clamped(eph_secret).to_bytes();
    if shared == [0; 32] {
        return Err(Error::BadRecipient);
    }
    let mut out = eph.to_vec();
    out.extend_from_slice(&seal(&seal_to_key(&eph, recipient, &shared), plaintext, aad));
    Ok(out)
}

/// Обратное к [`seal_to`]: `secret` — X25519-секрет получателя.
pub fn open_to(secret: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < SEAL_TO_OVERHEAD {
        return Err(Error::Decrypt);
    }
    let (eph, ct) = ciphertext.split_at(X25519_LEN);
    let eph: [u8; 32] = eph.try_into().expect("длина проверена");
    let shared = MontgomeryPoint(eph).mul_clamped(*secret).to_bytes();
    if shared == [0; 32] {
        return Err(Error::Decrypt);
    }
    open(&seal_to_key(&eph, &x25519_public(secret), &shared), ct, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + i / 7) as u8).collect()
    }

    #[test]
    fn padme_buckets() {
        assert_eq!(padded_len(0), 0);
        assert_eq!(padded_len(1), 1);
        for n in [
            2usize,
            3,
            100,
            1000,
            65_536,
            1 << 20,
            4 << 20,
            8 << 20,
            (8 << 20) + 1,
            16 << 20,
        ] {
            let p = padded_len(n);
            assert!(p >= n);
            // накладные Padmé не больше ~12%
            assert!((p - n) as f64 <= n as f64 * 0.12 + 1.0, "{n} → {p}");
            // корзина: повторное выравнивание ничего не меняет
            assert_eq!(padded_len(p), p);
        }
        // у сегментов 4–16 МиБ шаг корзины 128–512 КиБ (накладные до ~3%)
        assert_eq!(padded_len((8 << 20) + 1) - (8 << 20), 256 << 10);
        // соседние длины попадают в одну корзину
        assert_eq!(padded_len(5_000_001), padded_len(5_000_002));
    }

    #[test]
    fn roundtrip_and_lengths() {
        let key = Key::random();
        for n in [
            0,
            1,
            SEGMENT_CHUNK - 1,
            SEGMENT_CHUNK,
            SEGMENT_CHUNK + 1,
            3 * SEGMENT_CHUNK,
            3 * SEGMENT_CHUNK + 5,
            (8 << 20) + 3,
        ] {
            let pt = data(n);
            let ct = encrypt_segment(&key, &pt);
            assert_eq!(ct.len(), ciphertext_len(n));
            assert_eq!(decrypt_segment(&key, &ct, n).unwrap(), pt);
            // детерминированность
            assert_eq!(ct, encrypt_segment(&key, &pt));
        }
    }

    #[test]
    fn partial_chunks() {
        let key = Key::random();
        let n = 4 * SEGMENT_CHUNK + 1234;
        let pt = data(n);
        let ct = encrypt_segment(&key, &pt);
        // чанки 1..3
        let part = &ct[SEGMENT_CHUNK_CT..3 * SEGMENT_CHUNK_CT];
        assert_eq!(
            decrypt_chunks(&key, part, 1, n).unwrap(),
            &pt[SEGMENT_CHUNK..3 * SEGMENT_CHUNK]
        );
        // хвост: последний чанк с нулями выравнивания
        let part = &ct[3 * SEGMENT_CHUNK_CT..];
        let tail = decrypt_chunks(&key, part, 3, n).unwrap();
        assert_eq!(&tail[..n - 3 * SEGMENT_CHUNK], &pt[3 * SEGMENT_CHUNK..]);
        assert!(tail[n - 3 * SEGMENT_CHUNK..].iter().all(|&b| b == 0));
        // не тот номер чанка
        assert!(decrypt_chunks(&key, &ct[SEGMENT_CHUNK_CT..2 * SEGMENT_CHUNK_CT], 2, n).is_err());
    }

    /// Шифрование устройству по его ключу iroh/ed25519: открывает только владелец секрета.
    #[test]
    fn seal_to_device_key() {
        let dev = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let pub_x = device_x25519_public(&dev.verifying_key());
        // X25519-секрет устройства соответствует его открытому ключу
        assert_eq!(x25519_public(&device_x25519_secret(&dev)), pub_x);
        let ct = seal_to(&pub_x, b"epoch secret", b"aad").unwrap();
        assert_eq!(ct.len(), SEAL_TO_OVERHEAD + 12);
        assert_eq!(
            open_to(&device_x25519_secret(&dev), &ct, b"aad").unwrap(),
            b"epoch secret"
        );
        assert!(open_to(&device_x25519_secret(&other), &ct, b"aad").is_err());
        assert!(open_to(&device_x25519_secret(&dev), &ct, b"other aad").is_err());
        let mut bad = ct.clone();
        bad[3] ^= 1;
        assert!(open_to(&device_x25519_secret(&dev), &bad, b"aad").is_err());
        assert!(open_to(&device_x25519_secret(&dev), &ct[..20], b"aad").is_err());
        // каждый раз новый эфемерный ключ
        assert_ne!(ct, seal_to(&pub_x, b"epoch secret", b"aad").unwrap());
        // точка малого порядка (ноль) вместо ключа получателя
        assert!(matches!(seal_to(&[0; 32], b"x", b""), Err(Error::BadRecipient)));
        // ключ из произвольного секрета (escrow)
        let secret = [9u8; 32];
        let ct = seal_to(&x25519_public(&secret), b"e", b"").unwrap();
        assert_eq!(open_to(&secret, &ct, b"").unwrap(), b"e");
    }

    #[test]
    fn rejects_tamper_truncate_wrong_len() {
        let key = Key::random();
        let n = 3 * SEGMENT_CHUNK + 10;
        let pt = data(n);
        let ct = encrypt_segment(&key, &pt);
        // подмена байта в каждом чанке
        for at in [0, SEGMENT_CHUNK_CT + 7, ct.len() - 3] {
            let mut bad = ct.clone();
            bad[at] ^= 1;
            assert!(decrypt_segment(&key, &bad, n).is_err());
        }
        // усечение: на границе чанка и внутри
        assert!(decrypt_segment(&key, &ct[..3 * SEGMENT_CHUNK_CT], n).is_err());
        assert!(decrypt_segment(&key, &ct[..ct.len() - 1], n).is_err());
        // неверная plain_len — в том числе в той же корзине Padmé (длина в AAD)
        assert_eq!(padded_len(n + 1), padded_len(n));
        assert!(decrypt_segment(&key, &ct, n + 1).is_err());
        assert!(decrypt_segment(&key, &ct, n - 1).is_err());
        assert!(decrypt_segment(&key, &ct, 2 * SEGMENT_CHUNK).is_err());
        // перестановка чанков
        let mut swapped = ct.clone();
        swapped[..SEGMENT_CHUNK_CT].copy_from_slice(&ct[SEGMENT_CHUNK_CT..2 * SEGMENT_CHUNK_CT]);
        swapped[SEGMENT_CHUNK_CT..2 * SEGMENT_CHUNK_CT].copy_from_slice(&ct[..SEGMENT_CHUNK_CT]);
        assert!(decrypt_segment(&key, &swapped, n).is_err());
        // другой ключ
        assert!(decrypt_segment(&Key::random(), &ct, n).is_err());
    }
}
