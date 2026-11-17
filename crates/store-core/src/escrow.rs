//! Escrow мастер-ключа: из пароля Argon2id выводит 64 байта — ключ шифрования мастер-ключа
//! и seed ключа `auth`, которым подписывается `GetEscrow`. Control plane хранит публичную
//! часть `auth` и шифротекст, пароля не знает. Соль — `BLAKE3("store/escrow-salt/v1" ‖ user)`:
//! подключающееся устройство должно вывести ключ до того, как получит запись.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, Key};
use crate::{Error, Result};

const AAD: &[u8] = b"store/escrow/v1";

/// Параметры Argon2id. ТЗ: не ниже m = 256 МиБ, t = 3. Часть протокола escrow: все
/// устройства пользователя считают одинаково.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Argon {
    fn default() -> Self {
        Self {
            m_kib: 256 * 1024,
            t: 3,
            p: 1,
        }
    }
}

impl Argon {
    /// Слабые параметры для тестов.
    pub const FAST: Self = Self {
        m_kib: 8 * 1024,
        t: 1,
        p: 1,
    };
}

/// Ключ шифрования мастер-ключа и ключ `auth` из пароля.
pub fn derive(password: &str, user: &VerifyingKey, argon: &Argon) -> (Key, SigningKey) {
    let salt = blake3::derive_key("store/escrow-salt/v1", user.as_bytes());
    let params = argon2::Params::new(argon.m_kib, argon.t, argon.p, Some(64)).expect("параметры Argon2");
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 64];
    a.hash_password_into(password.as_bytes(), &salt, &mut out)
        .expect("Argon2 с проверенными параметрами");
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&out[..32]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[32..]);
    (Key(enc), SigningKey::from_bytes(&seed))
}

/// Публичная часть `auth` и шифротекст мастер-ключа под паролем.
pub fn seal(master: &[u8; 32], password: &str, user: &VerifyingKey, argon: &Argon) -> (VerifyingKey, Vec<u8>) {
    let (enc, auth) = derive(password, user, argon);
    (auth.verifying_key(), crypto::seal(&enc, master, AAD))
}

/// Мастер-ключ из шифротекста `blob` и пароля; `auth` — публичная часть, записанная рядом с ним.
pub fn open(auth: &VerifyingKey, blob: &[u8], password: &str, user: &VerifyingKey, argon: &Argon) -> Result<[u8; 32]> {
    let (enc, derived) = derive(password, user, argon);
    if &derived.verifying_key() != auth {
        return Err(Error::BadPassword);
    }
    let plain = crypto::open(&enc, blob, AAD).map_err(|_| Error::BadPassword)?;
    plain.as_slice().try_into().map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let master = [9u8; 32];
        let user = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let (auth, blob) = seal(&master, "пароль", &user, &Argon::FAST);
        assert_eq!(open(&auth, &blob, "пароль", &user, &Argon::FAST).unwrap(), master);
        assert!(open(&auth, &blob, "парол", &user, &Argon::FAST).is_err());
        let other = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert!(open(&auth, &blob, "пароль", &other, &Argon::FAST).is_err());
    }
}
