//! Криптография share (docs/share.md §2): тело с именем и ключами файлов под ключом share `sk`,
//! вывод ключей ссылки из её секрета, доставка `sk` устройствам получателя и ссылка владельца
//! на путь (`owner_ref`).
//!
//! Узлам и control plane видны только хэши манифестов (`manifests`) и размеры; имя и ключи
//! файлов лежат в зашифрованном теле. Ключ файла `fk` ([`crate::file::file_key`]) раскрывает
//! `FileMeta` ровно одной версии одного файла.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Hash, Result,
    crypto::{self, Key},
};

const BODY_AAD: &[u8] = b"store/share-bundle/v1";
const KEY_AAD: &[u8] = b"store/share-key/v1";
const REF_AAD: &[u8] = b"store/share-ref/v1";
const LINK_KEY_CONTEXT: &str = "store/share/v1/key";
const LINK_AUTH_CONTEXT: &str = "store/share/v1/auth";

/// Запись тела: файл share. Для одного файла — одна запись с пустым `path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleEntry {
    /// Относительный путь внутри share, `/`-разделитель.
    pub path: String,
    /// Индекс в списке манифестов share.
    pub manifest: u32,
    /// Ключ файла `fk` этой версии манифеста.
    pub file_key: Key,
}

/// Зашифрованное тело share: показываемое имя и ключи файлов.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleBody {
    pub name: String,
    pub created_ms: u64,
    pub entries: Vec<BundleEntry>,
}

/// AAD тела: владелец, `id` и список манифестов (control plane не подменит ни то, ни другое).
fn body_aad(owner: &[u8; 32], id: &[u8; 32], manifests: &[Hash]) -> Vec<u8> {
    let mut aad = BODY_AAD.to_vec();
    aad.extend_from_slice(owner);
    aad.extend_from_slice(id);
    let mut h = blake3::Hasher::new();
    for m in manifests {
        h.update(m.as_bytes());
    }
    aad.extend_from_slice(h.finalize().as_bytes());
    aad
}

pub fn seal_body(sk: &Key, owner: &[u8; 32], id: &[u8; 32], manifests: &[Hash], body: &BundleBody) -> Vec<u8> {
    crypto::seal(
        sk,
        &postcard::to_stdvec(body).expect("сериализация в Vec не падает"),
        &body_aad(owner, id, manifests),
    )
}

pub fn open_body(sk: &Key, owner: &[u8; 32], id: &[u8; 32], manifests: &[Hash], sealed: &[u8]) -> Result<BundleBody> {
    let body: BundleBody = postcard::from_bytes(&crypto::open(sk, sealed, &body_aad(owner, id, manifests))?)?;
    if body.entries.iter().any(|e| e.manifest as usize >= manifests.len()) {
        return Err(Error::SegmentLenMismatch(
            "запись share ссылается на несуществующий манифест",
        ));
    }
    Ok(body)
}

/// Ключ share и ключ подписи ссылки из её 32-байтного секрета. `share_id` ссылки — публичная
/// часть ключа подписи: запрос к control plane подписывает тот, кто знает секрет.
pub fn link_keys(secret: &[u8; 32]) -> (Key, SigningKey) {
    (
        Key(blake3::derive_key(LINK_KEY_CONTEXT, secret)),
        SigningKey::from_bytes(&blake3::derive_key(LINK_AUTH_CONTEXT, secret)),
    )
}

fn key_aad(owner: &[u8; 32], recipient: &[u8; 32], id: &[u8; 32]) -> Vec<u8> {
    let mut aad = KEY_AAD.to_vec();
    aad.extend_from_slice(owner);
    aad.extend_from_slice(recipient);
    aad.extend_from_slice(id);
    aad
}

/// `sk`, зашифрованный на X25519-ключ одного устройства получателя (sealed box).
pub fn seal_sk(
    device_x25519: &[u8; 32],
    sk: &Key,
    owner: &[u8; 32],
    recipient: &[u8; 32],
    id: &[u8; 32],
) -> Result<Vec<u8>> {
    crypto::seal_to(device_x25519, &sk.0, &key_aad(owner, recipient, id))
}

/// Обратное к [`seal_sk`]: `secret` — X25519-секрет устройства ([`crypto::device_x25519_secret`]).
pub fn open_sk(secret: &[u8; 32], sealed: &[u8], owner: &[u8; 32], recipient: &[u8; 32], id: &[u8; 32]) -> Result<Key> {
    let plain = crypto::open_to(secret, sealed, &key_aad(owner, recipient, id))?;
    Ok(Key(plain.as_slice().try_into().map_err(|_| Error::Decrypt)?))
}

/// Что владелец помнит о своём share: путь в дереве и `sk` (чтобы обновить тело при смене
/// версии, не имея секрета ссылки).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerRef {
    pub path: String,
    pub sk: Key,
}

/// `owner_ref`: `epoch(8, LE) ‖ seal(ключ имён эпохи, OwnerRef, AAD ‖ id)`. Открыть могут
/// только устройства владельца.
pub fn seal_ref(names_key: &Key, epoch: u64, id: &[u8; 32], r: &OwnerRef) -> Vec<u8> {
    let mut aad = REF_AAD.to_vec();
    aad.extend_from_slice(id);
    let mut out = epoch.to_le_bytes().to_vec();
    out.extend_from_slice(&crypto::seal(
        names_key,
        &postcard::to_stdvec(r).expect("сериализация в Vec не падает"),
        &aad,
    ));
    out
}

/// Эпоха ключа имён, которым запечатан `owner_ref`.
pub fn ref_epoch(sealed: &[u8]) -> Result<u64> {
    let b: [u8; 8] = sealed
        .get(..8)
        .ok_or(Error::Decrypt)?
        .try_into()
        .map_err(|_| Error::Decrypt)?;
    Ok(u64::from_le_bytes(b))
}

pub fn open_ref(names_key: &Key, id: &[u8; 32], sealed: &[u8]) -> Result<OwnerRef> {
    let mut aad = REF_AAD.to_vec();
    aad.extend_from_slice(id);
    let body = sealed.get(8..).ok_or(Error::Decrypt)?;
    Ok(postcard::from_bytes(&crypto::open(names_key, body, &aad)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> BundleBody {
        BundleBody {
            name: "отчёт.pdf".into(),
            created_ms: 5,
            entries: vec![BundleEntry {
                path: String::new(),
                manifest: 0,
                file_key: Key::random(),
            }],
        }
    }

    #[test]
    fn body_bound_to_owner_id_and_manifests() {
        let (sk, owner, id) = (Key::random(), [1u8; 32], [2u8; 32]);
        let ms = [Hash::of(b"m")];
        let b = body();
        let sealed = seal_body(&sk, &owner, &id, &ms, &b);
        assert_eq!(open_body(&sk, &owner, &id, &ms, &sealed).unwrap(), b);
        assert!(
            open_body(&Key::random(), &owner, &id, &ms, &sealed).is_err(),
            "чужой sk"
        );
        assert!(open_body(&sk, &[9; 32], &id, &ms, &sealed).is_err(), "другой владелец");
        assert!(open_body(&sk, &owner, &[9; 32], &ms, &sealed).is_err(), "другой id");
        assert!(
            open_body(&sk, &owner, &id, &[Hash::of(b"x")], &sealed).is_err(),
            "подмена манифеста"
        );
    }

    #[test]
    fn link_keys_deterministic() {
        let (k1, a1) = link_keys(&[7; 32]);
        let (k2, a2) = link_keys(&[7; 32]);
        assert_eq!(k1, k2);
        assert_eq!(a1.to_bytes(), a2.to_bytes());
        assert_ne!(link_keys(&[8; 32]).0, k1);
        assert_ne!(k1.0, a1.to_bytes(), "ключ share и ключ подписи независимы");
    }

    #[test]
    fn sk_sealed_to_device_only() {
        let dev = SigningKey::from_bytes(&[3; 32]);
        let other = SigningKey::from_bytes(&[4; 32]);
        let sk = Key::random();
        let (owner, rcpt, id) = ([1; 32], [2; 32], [5; 32]);
        let x_pub = crypto::device_x25519_public(&dev.verifying_key());
        let sealed = seal_sk(&x_pub, &sk, &owner, &rcpt, &id).unwrap();
        assert_eq!(
            open_sk(&crypto::device_x25519_secret(&dev), &sealed, &owner, &rcpt, &id).unwrap(),
            sk
        );
        assert!(open_sk(&crypto::device_x25519_secret(&other), &sealed, &owner, &rcpt, &id).is_err());
        assert!(open_sk(&crypto::device_x25519_secret(&dev), &sealed, &owner, &[9; 32], &id).is_err());
    }

    #[test]
    fn owner_ref_roundtrip() {
        let names = Key::random();
        let id = [1; 32];
        let r = OwnerRef {
            path: "/docs/a.pdf".into(),
            sk: Key::random(),
        };
        let s = seal_ref(&names, 3, &id, &r);
        assert_eq!(ref_epoch(&s).unwrap(), 3);
        assert_eq!(open_ref(&names, &id, &s).unwrap(), r);
        assert!(open_ref(&names, &[2; 32], &s).is_err());
        assert!(open_ref(&Key::random(), &id, &s).is_err());
    }
}
