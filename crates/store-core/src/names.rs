//! Имена в каталогах шифруются детерминированно: одно имя — один шифротекст, поэтому
//! записи можно сортировать и искать, не расшифровывая весь каталог. Nonce — keyed BLAKE3
//! от имени (SIV-подобная схема), он же идентификатор имени ([`id`]) для поиска.
//!
//! `name_enc = nonce(24) ‖ XChaCha20-Poly1305(имя, AAD "store/name/v2") ‖ mac(16)`, где
//! `mac = BLAKE3-keyed(K_mac, вид ‖ хэш записи ‖ nonce ‖ шифротекст)`, а `K_mac` выводится из
//! ключа имён эпохи в отдельном домене. MAC привязывает имя к виду и хэшу записи: control
//! plane, собравший каталог из чужих `name_enc` с переставленными хэшами, не пройдёт проверку
//! (M1). Привязка — отдельным MAC, а не AAD шифра: nonce детерминирован именем, и один и тот же
//! nonce с разными AAD (новая версия файла — новый хэш) дал бы несколько тегов Poly1305 на
//! одном одноразовом ключе — по ним ключ Poly1305 восстанавливается, и теги подделываются.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use crate::{
    Hash,
    crypto::{self, Key},
    format::{DirEntry, Kind},
};

const AAD: &[u8] = b"store/name/v2";
const MAC_CONTEXT: &str = "store/name-mac/v2";
/// Длина идентификатора имени (nonce) в начале `name_enc`.
pub const ID_LEN: usize = 24;
const MAC_LEN: usize = 16;

/// Идентификатор имени в каталоге эпохи (начало `name_enc`): по нему ищут запись.
pub fn id(key: &Key, name: &str) -> [u8; ID_LEN] {
    let h = blake3::keyed_hash(&key.0, name.as_bytes());
    h.as_bytes()[..ID_LEN].try_into().expect("24 байта")
}

/// Порядок записи относительно идентификатора `id` (записи каталога отсортированы по
/// `name_enc`, а значит и по идентификатору: у разных имён он разный).
pub fn cmp_id(name_enc: &[u8], id: &[u8; ID_LEN]) -> std::cmp::Ordering {
    name_enc[..name_enc.len().min(ID_LEN)].cmp(&id[..])
}

fn kind_byte(kind: Kind) -> u8 {
    match kind {
        Kind::File => 0,
        Kind::Dir => 1,
    }
}

fn mac(key: &Key, core: &[u8], kind: Kind, hash: &Hash) -> blake3::Hash {
    let k = blake3::Hasher::new_derive_key(MAC_CONTEXT).update(&key.0).finalize();
    let mut h = blake3::Hasher::new_keyed(k.as_bytes());
    h.update(&[kind_byte(kind)]);
    h.update(hash.as_bytes());
    h.update(core);
    h.finalize()
}

/// `name_enc` записи `name` вида `kind` с хэшем `hash`.
pub fn encrypt(key: &Key, name: &str, kind: Kind, hash: &Hash) -> Vec<u8> {
    let nonce = id(key, name);
    let ct = XChaCha20Poly1305::new((&key.0).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: name.as_bytes(),
                aad: AAD,
            },
        )
        .expect("шифрование не падает");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    let tag = mac(key, &out, kind, hash);
    out.extend_from_slice(&tag.as_bytes()[..MAC_LEN]);
    out
}

/// Имя записи каталога; MAC проверяет, что имя записано для этих вида и хэша.
pub fn decrypt(key: &Key, entry: &DirEntry) -> crate::Result<String> {
    let enc = &entry.name_enc;
    let core_len = enc
        .len()
        .checked_sub(MAC_LEN)
        .filter(|&l| l >= ID_LEN)
        .ok_or(crate::Error::Decrypt)?;
    let (core, tag) = enc.split_at(core_len);
    let want = mac(key, core, entry.kind, &entry.hash);
    // сравнение за постоянное время: `blake3::Hash` сравнивается так
    let mut got = *want.as_bytes();
    got[..MAC_LEN].copy_from_slice(tag);
    if blake3::Hash::from(got) != want {
        return Err(crate::Error::Decrypt);
    }
    let plain = crypto::open(key, core, AAD)?;
    let name = String::from_utf8(plain).map_err(|_| crate::Error::Decrypt)?;
    // nonce обязан быть выведен из имени: иначе запись не нашлась бы поиском по `id`
    if core[..ID_LEN] != id(key, &name) {
        return Err(crate::Error::Decrypt);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name_enc: Vec<u8>, kind: Kind, hash: Hash) -> DirEntry {
        DirEntry {
            name_enc,
            kind,
            hash,
            extra: Vec::new(),
            id_enc: Vec::new(),
        }
    }

    #[test]
    fn deterministic_and_roundtrip() {
        let k = Key([7; 32]);
        let h = Hash::of(b"x");
        let f = Kind::File;
        assert_eq!(encrypt(&k, "отчёт.pdf", f, &h), encrypt(&k, "отчёт.pdf", f, &h));
        assert_ne!(encrypt(&k, "a", f, &h), encrypt(&k, "b", f, &h));
        assert_ne!(encrypt(&k, "a", f, &h), encrypt(&Key([8; 32]), "a", f, &h));
        let e = entry(encrypt(&k, "отчёт.pdf", f, &h), f, h);
        assert_eq!(decrypt(&k, &e).unwrap(), "отчёт.pdf");
        assert!(decrypt(&Key([8; 32]), &e).is_err());
        // идентификатор — начало шифротекста и не зависит от хэша
        assert_eq!(e.name_enc[..ID_LEN], id(&k, "отчёт.pdf"));
        assert_eq!(cmp_id(&e.name_enc, &id(&k, "отчёт.pdf")), std::cmp::Ordering::Equal);
        assert_eq!(encrypt(&k, "a", f, &Hash::of(b"y"))[..ID_LEN], id(&k, "a"));
    }

    /// Имя привязано к хэшу и виду записи: переставленный хэш или вид не расшифровываются.
    #[test]
    fn bound_to_hash_and_kind() {
        let k = Key([7; 32]);
        let (h1, h2) = (Hash::of(b"1"), Hash::of(b"2"));
        let enc = encrypt(&k, "a", Kind::File, &h1);
        assert!(decrypt(&k, &entry(enc.clone(), Kind::File, h1)).is_ok());
        assert!(decrypt(&k, &entry(enc.clone(), Kind::File, h2)).is_err());
        assert!(decrypt(&k, &entry(enc.clone(), Kind::Dir, h1)).is_err());
        let mut bad = enc.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(decrypt(&k, &entry(bad, Kind::File, h1)).is_err());
        assert!(decrypt(&k, &entry(enc[..ID_LEN].to_vec(), Kind::File, h1)).is_err());
    }
}
