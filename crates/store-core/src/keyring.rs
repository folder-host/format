//! Эпохи ключей данных и их обёртки (см. `docs/keys.md`).
//!
//! Секрет эпохи `E_n` — 32 случайных байта. Из него выводятся корень ключей сегментов (он же
//! ключ таблицы gear нарезки, [`crate::chunk::Chunker::keyed`]), ключ метаданных
//! (`FileMeta`) и ключ имён каталогов. Мастер-ключ пользователя к данным отношения не имеет.
//!
//! В control plane секрет текущей эпохи лежит обёрнутым ([`wrap`]) для каждого активного
//! устройства (X25519 от его ed25519-ключа) и для escrow (X25519 от мастер-ключа), а прошлые
//! секреты — цепочкой ([`link`]): `E_k`, зашифрованный ключом из `E_{k+1}`. Кто знает `E_n`,
//! разворачивает цепочку назад до `E_0` ([`unchain`]); вперёд по ней пройти нельзя.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    crypto::{self, Key},
};

/// Длина обёртки секрета эпохи ([`wrap`]): эфемерный ключ, nonce, секрет и тег.
pub const WRAP_LEN: usize = crypto::SEAL_TO_OVERHEAD + 32;
/// Длина звена цепочки ([`link`]).
pub const LINK_LEN: usize = crypto::OVERHEAD + 32;

const WRAP_DOMAIN: &[u8] = b"store/keyring/v1/wrap";
const LINK_DOMAIN: &[u8] = b"store/keyring/v1/link";
const LINK_CONTEXT: &str = "store/epoch/link/v1";
const SEGMENT_CONTEXT: &str = "store/epoch/segment/v1";
const META_CONTEXT: &str = "store/epoch/meta/v1";
const NAMES_CONTEXT: &str = "store/epoch/names/v1";
const ESCROW_CONTEXT: &str = "store/account/escrow-x25519/v1";
const RECV_CONTEXT: &str = "store/epoch/recv/v1";
const INBOX_CONTEXT: &str = "store/space/inbox/v1";

/// Секрет эпохи ключей данных.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSecret(pub [u8; 32]);

impl EpochSecret {
    pub fn random() -> Self {
        Self(crypto::random_bytes())
    }
}

impl std::fmt::Debug for EpochSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochSecret(..)")
    }
}

/// Ключи данных одной эпохи.
#[derive(Clone)]
pub struct EpochKeys {
    pub epoch: u64,
    pub secret: EpochSecret,
    /// Корень детерминированных ключей сегментов и ключ таблицы gear.
    pub segment: Key,
    /// Шифрование `FileMeta` в манифестах.
    pub meta: Key,
    /// Детерминированное шифрование имён и атрибутов в каталогах.
    pub names: Key,
}

impl EpochKeys {
    pub fn derive(epoch: u64, secret: EpochSecret) -> Self {
        let d = |ctx: &str| Key(blake3::derive_key(ctx, &secret.0));
        Self {
            epoch,
            segment: d(SEGMENT_CONTEXT),
            meta: d(META_CONTEXT),
            names: d(NAMES_CONTEXT),
            secret,
        }
    }
}

impl std::fmt::Debug for EpochKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpochKeys({})", self.epoch)
    }
}

/// X25519-секрет escrow-получателя: выводится из мастер-ключа. Открытая часть
/// ([`escrow_public`]) лежит в связке, поэтому обернуть новую эпоху для escrow может любое
/// устройство, а развернуть — только знающий мастер-ключ.
pub fn escrow_secret(master: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(ESCROW_CONTEXT, master)
}

pub fn escrow_public(master: &[u8; 32]) -> [u8; 32] {
    crypto::x25519_public(&escrow_secret(master))
}

/// X25519-секрет ключа получения `recv` эпохи (docs/share.md §2.3): выводится из секрета эпохи
/// аккаунта, поэтому есть у каждого устройства, знающего эпоху. Открытая часть публикуется
/// (`RecvKey`), на неё оборачивают ключи пространств и share пользователю.
pub fn recv_secret(secret: &EpochSecret) -> [u8; 32] {
    blake3::derive_key(RECV_CONTEXT, &secret.0)
}

pub fn recv_public(secret: &EpochSecret) -> [u8; 32] {
    crypto::x25519_public(&recv_secret(secret))
}

/// X25519-секрет «входящих» эпохи пространства (docs/spaces.md §2.5): секрет знают участники,
/// открытую часть видит гость ссылки только для загрузки.
pub fn inbox_secret(secret: &EpochSecret) -> [u8; 32] {
    blake3::derive_key(INBOX_CONTEXT, &secret.0)
}

pub fn inbox_public(secret: &EpochSecret) -> [u8; 32] {
    crypto::x25519_public(&inbox_secret(secret))
}

fn wrap_aad(user: &VerifyingKey, epoch: u64, recipient: &[u8; 32]) -> Vec<u8> {
    let mut aad = WRAP_DOMAIN.to_vec();
    aad.extend_from_slice(user.as_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(recipient);
    aad
}

/// Обёртка секрета эпохи `epoch` пользователя `user` для X25519-ключа `recipient`
/// (устройства — [`crypto::device_x25519_public`], escrow — [`escrow_public`]).
pub fn wrap(user: &VerifyingKey, epoch: u64, recipient: &[u8; 32], secret: &EpochSecret) -> Result<Vec<u8>> {
    crypto::seal_to(recipient, &secret.0, &wrap_aad(user, epoch, recipient))
}

/// Разворачивает обёртку X25519-секретом получателя.
pub fn unwrap(user: &VerifyingKey, epoch: u64, x25519_secret: &[u8; 32], wrapped: &[u8]) -> Result<EpochSecret> {
    let recipient = crypto::x25519_public(x25519_secret);
    let plain = crypto::open_to(x25519_secret, wrapped, &wrap_aad(user, epoch, &recipient))?;
    Ok(EpochSecret(plain.as_slice().try_into().map_err(|_| Error::Decrypt)?))
}

fn link_aad(user: &VerifyingKey, epoch: u64) -> Vec<u8> {
    let mut aad = LINK_DOMAIN.to_vec();
    aad.extend_from_slice(user.as_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

fn link_key(next: &EpochSecret) -> Key {
    Key(blake3::derive_key(LINK_CONTEXT, &next.0))
}

/// Звено цепочки: секрет эпохи `epoch`, зашифрованный ключом из секрета эпохи `epoch + 1`.
pub fn link(user: &VerifyingKey, epoch: u64, secret: &EpochSecret, next: &EpochSecret) -> Vec<u8> {
    crypto::seal(&link_key(next), &secret.0, &link_aad(user, epoch))
}

/// Секрет эпохи `epoch` из звена и секрета эпохи `epoch + 1`.
pub fn open_link(user: &VerifyingKey, epoch: u64, next: &EpochSecret, link: &[u8]) -> Result<EpochSecret> {
    let plain = crypto::open(&link_key(next), link, &link_aad(user, epoch))?;
    Ok(EpochSecret(plain.as_slice().try_into().map_err(|_| Error::Decrypt)?))
}

/// Все секреты `E_0..=E_n` по секрету текущей эпохи `n = links.len()` и цепочке
/// (`links[k]` — звено эпохи `k`). Индекс результата — номер эпохи.
pub fn unchain(user: &VerifyingKey, current: &EpochSecret, links: &[Vec<u8>]) -> Result<Vec<EpochSecret>> {
    let mut out = vec![current.clone()];
    for (k, l) in links.iter().enumerate().rev() {
        let next = out.last().expect("не пусто");
        let prev = open_link(user, k as u64, next, l)?;
        out.push(prev);
    }
    out.reverse();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn user() -> VerifyingKey {
        SigningKey::from_bytes(&[1; 32]).verifying_key()
    }

    /// Обёртка секрета эпохи для устройства открывается только его ключом и только для той же
    /// эпохи и пользователя.
    #[test]
    fn wrap_for_device_roundtrip() {
        let dev = SigningKey::from_bytes(&[2; 32]);
        let other = SigningKey::from_bytes(&[3; 32]);
        let e = EpochSecret::random();
        let to = crypto::device_x25519_public(&dev.verifying_key());
        let w = wrap(&user(), 4, &to, &e).unwrap();
        assert_eq!(w.len(), WRAP_LEN);
        let sk = crypto::device_x25519_secret(&dev);
        assert_eq!(unwrap(&user(), 4, &sk, &w).unwrap(), e);
        assert!(unwrap(&user(), 5, &sk, &w).is_err(), "другая эпоха");
        let u2 = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert!(unwrap(&u2, 4, &sk, &w).is_err(), "другой пользователь");
        assert!(unwrap(&user(), 4, &crypto::device_x25519_secret(&other), &w).is_err());

        // escrow: ключ из мастер-ключа
        let master = [7u8; 32];
        let w = wrap(&user(), 0, &escrow_public(&master), &e).unwrap();
        assert_eq!(unwrap(&user(), 0, &escrow_secret(&master), &w).unwrap(), e);
        assert!(unwrap(&user(), 0, &escrow_secret(&[8; 32]), &w).is_err());
    }

    /// Цепочка: по последнему секрету восстанавливаются все прошлые; по прошлому — не следующий.
    #[test]
    fn chain_of_past_epochs() {
        let u = user();
        let secrets: Vec<EpochSecret> = (0..5).map(|_| EpochSecret::random()).collect();
        let links: Vec<Vec<u8>> = (0..4)
            .map(|k| link(&u, k as u64, &secrets[k], &secrets[k + 1]))
            .collect();
        assert!(links.iter().all(|l| l.len() == LINK_LEN));
        assert_eq!(unchain(&u, &secrets[4], &links).unwrap(), secrets);
        // с середины: E_2 даёт E_0..E_2
        assert_eq!(unchain(&u, &secrets[2], &links[..2]).unwrap(), secrets[..3]);
        // E_2 не открывает звено эпохи 3 (оно зашифровано E_4)
        assert!(open_link(&u, 3, &secrets[2], &links[3]).is_err());
        // звено привязано к номеру эпохи
        assert!(open_link(&u, 2, &secrets[4], &links[3]).is_err());
        // подменённое звено — ошибка, а не тихо неверный секрет
        let mut bad = links.clone();
        bad[1][30] ^= 1;
        assert!(unchain(&u, &secrets[4], &bad).is_err());
        // без звеньев — только текущий
        assert_eq!(unchain(&u, &secrets[0], &[]).unwrap(), secrets[..1]);
    }

    #[test]
    fn epoch_keys_differ() {
        let a = EpochKeys::derive(0, EpochSecret([1; 32]));
        let b = EpochKeys::derive(1, EpochSecret([2; 32]));
        assert!(a.meta != b.meta && a.names != b.names && a.segment != b.segment);
        assert!(a.meta != a.names && a.names != a.segment);
    }
}
