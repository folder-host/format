//! Состояние выхода (`state.fhx`): всё, что нужно, чтобы восстановить файлы аккаунта из блобов
//! без control plane — корни аккаунта и пространств, связки ключей, escrow мастер-ключа и
//! адреса узлов. Клиент держит его в каталоге данных и обновляет при смене корня; `store export`
//! кладёт его рядом с выкачанными блобами, `fh-restore` открывает паролем или ключом устройства.
//!
//! Секретов в открытом виде нет: обёртки и звенья цепочки зашифрованы, корни подписаны. Но escrow
//! — шифротекст мастер-ключа под паролем: файл с ним позволяет перебирать пароль офлайн (control
//! plane escrow без подписи ключом из пароля не отдаёт). Поэтому файл хранится как сам пароль.
//!
//! Формат: `"FHEXIT\0\0" ‖ версия (1 байт) ‖ postcard(ExitState)`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::escrow::{self, Argon};
use crate::format::Root;
use crate::keyring::{self, EpochKeys, EpochSecret};
use crate::{Error, Result, crypto};

pub const MAGIC: &[u8; 8] = b"FHEXIT\0\0";
pub const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitState {
    /// Аккаунт (публичный ключ, неизменный).
    pub user: VerifyingKey,
    /// Когда снято, мс Unix.
    pub created_ms: u64,
    /// Последний виденный корень аккаунта; `None` — аккаунт ещё ничего не записал.
    pub root: Option<Root>,
    pub keyring: AccountKeyring,
    /// Escrow мастер-ключа, если устройство его знает (создало аккаунт или входило паролем).
    pub escrow: Option<Escrow>,
    pub spaces: Vec<SpaceState>,
    /// Узлы хранения на момент снятия: по ним `store export` достаёт блобы без control plane.
    pub nodes: Vec<NodeHint>,
}

/// Связка аккаунта (`store_proto::api::Keyring`) без лишнего.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeyring {
    pub epoch: u64,
    /// `E_n`, обёрнутый для escrow (X25519 от мастер-ключа).
    pub escrow_wrap: Option<Vec<u8>>,
    /// `E_n`, обёрнутый для устройств: (ed25519-ключ устройства, обёртка).
    pub device_wraps: Vec<([u8; 32], Vec<u8>)>,
    /// `links[k]` — `E_k` под ключом из `E_{k+1}`.
    pub links: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Escrow {
    pub argon: Argon,
    pub auth: VerifyingKey,
    pub blob: Vec<u8>,
}

/// Пространство, где аккаунт участник: корень и своя обёртка секрета текущей эпохи.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceState {
    pub id: VerifyingKey,
    pub root: Option<Root>,
    pub epoch: u64,
    /// Эпоха аккаунта, ключ получения которой открывает `wrap`.
    pub recv_epoch: u64,
    pub wrap: Vec<u8>,
    pub links: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHint {
    /// iroh `EndpointId` (ed25519).
    pub id: [u8; 32],
    /// Прямые адреса `ip:port`.
    pub addrs: Vec<String>,
}

/// Чем открыть состояние.
pub enum Unlock<'a> {
    /// Пароль аккаунта (нужен [`ExitState::escrow`]).
    Password(&'a str),
    /// Мастер-ключ (32 байта файла аккаунта после `user`).
    Master([u8; 32]),
    /// Ключ активного устройства (его обёртка в связке).
    Device(&'a SigningKey),
}

/// Ключи всех эпох аккаунта и пространств.
pub struct Keys {
    /// Индекс — номер эпохи.
    pub account: Vec<EpochKeys>,
    pub spaces: Vec<(VerifyingKey, Vec<EpochKeys>)>,
}

impl Keys {
    pub fn account_epoch(&self, epoch: u64) -> Result<&EpochKeys> {
        self.account.get(epoch as usize).ok_or(Error::Decrypt)
    }
}

fn derive_all(secrets: Vec<EpochSecret>) -> Vec<EpochKeys> {
    secrets
        .into_iter()
        .enumerate()
        .map(|(i, s)| EpochKeys::derive(i as u64, s))
        .collect()
}

impl ExitState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        postcard::to_io(self, &mut out).expect("запись в Vec не падает");
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let rest = bytes.strip_prefix(MAGIC.as_slice()).ok_or(Error::CorruptStripe("не состояние выхода"))?;
        let (&version, body) = rest.split_first().ok_or(Error::EmptyBlob)?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let (state, tail) = postcard::take_from_bytes(body)?;
        if !tail.is_empty() {
            return Err(Error::TrailingBytes(tail.len()));
        }
        Ok(state)
    }

    /// Секрет текущей эпохи аккаунта.
    fn current_secret(&self, unlock: &Unlock) -> Result<EpochSecret> {
        let kr = &self.keyring;
        let master = match unlock {
            Unlock::Device(sk) => {
                let me = sk.verifying_key().to_bytes();
                let (_, w) = kr.device_wraps.iter().find(|(d, _)| d == &me).ok_or(Error::Decrypt)?;
                return keyring::unwrap(&self.user, kr.epoch, &crypto::device_x25519_secret(sk), w);
            }
            Unlock::Master(m) => *m,
            Unlock::Password(p) => {
                let e = self.escrow.as_ref().ok_or(Error::BadPassword)?;
                escrow::open(&e.auth, &e.blob, p, &self.user, &e.argon)?
            }
        };
        let w = kr.escrow_wrap.as_ref().ok_or(Error::Decrypt)?;
        keyring::unwrap(&self.user, kr.epoch, &keyring::escrow_secret(&master), w)
    }

    /// Ключи всех эпох аккаунта и пространств. Пространство, обёртку которого не открыть,
    /// пропускается: восстанавливается то, что можно.
    pub fn unlock(&self, unlock: Unlock) -> Result<Keys> {
        let kr = &self.keyring;
        if kr.links.len() as u64 != kr.epoch {
            return Err(Error::CorruptStripe("длина цепочки не равна эпохе"));
        }
        let current = self.current_secret(&unlock)?;
        let account = derive_all(keyring::unchain(&self.user, &current, &kr.links)?);
        let mut spaces = Vec::new();
        for sp in &self.spaces {
            let Some(ak) = account.get(sp.recv_epoch as usize) else { continue };
            let recv = keyring::recv_secret(&ak.secret);
            let Ok(s) = keyring::unwrap(&sp.id, sp.epoch, &recv, &sp.wrap) else { continue };
            let Ok(all) = keyring::unchain(&sp.id, &s, &sp.links) else { continue };
            spaces.push((sp.id, derive_all(all)));
        }
        Ok(Keys { account, spaces })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn state(sk: &SigningKey, dev: &SigningKey, master: [u8; 32]) -> (ExitState, Vec<EpochSecret>) {
        let user = sk.verifying_key();
        let secrets: Vec<EpochSecret> = (0..3).map(|i| EpochSecret([i as u8 + 40; 32])).collect();
        let links = (0..2)
            .map(|k| keyring::link(&user, k as u64, &secrets[k], &secrets[k + 1]))
            .collect();
        let escrow_wrap = keyring::wrap(&user, 2, &keyring::escrow_public(&master), &secrets[2]).unwrap();
        let dev_wrap = keyring::wrap(
            &user,
            2,
            &crypto::device_x25519_public(&dev.verifying_key()),
            &secrets[2],
        )
        .unwrap();
        let (auth, blob) = escrow::seal(&master, "пароль", &user, &Argon::FAST);
        let space = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let s0 = EpochSecret([90; 32]);
        let space_wrap = keyring::wrap(&space, 0, &keyring::recv_public(&secrets[1]), &s0).unwrap();
        let st = ExitState {
            user,
            created_ms: 1,
            root: Some(Root::sign(dev, user, Hash::of(b"dir"), 5, 2)),
            keyring: AccountKeyring {
                epoch: 2,
                escrow_wrap: Some(escrow_wrap),
                device_wraps: vec![(dev.verifying_key().to_bytes(), dev_wrap)],
                links,
            },
            escrow: Some(Escrow {
                argon: Argon::FAST,
                auth,
                blob,
            }),
            spaces: vec![SpaceState {
                id: space,
                root: None,
                epoch: 0,
                recv_epoch: 1,
                wrap: space_wrap,
                links: vec![],
            }],
            nodes: vec![NodeHint {
                id: [3; 32],
                addrs: vec!["192.0.2.1:4433".into()],
            }],
        };
        (st, secrets)
    }

    /// Пароль, мастер-ключ и ключ устройства дают одни и те же ключи всех эпох и пространства.
    #[test]
    fn unlock_three_ways() {
        let sk = SigningKey::from_bytes(&[1; 32]);
        let dev = SigningKey::from_bytes(&[2; 32]);
        let master = [9; 32];
        let (st, secrets) = state(&sk, &dev, master);
        let st = ExitState::from_bytes(&st.to_bytes()).unwrap();
        for u in [Unlock::Password("пароль"), Unlock::Master(master), Unlock::Device(&dev)] {
            let keys = st.unlock(u).unwrap();
            assert_eq!(keys.account.len(), 3);
            for (k, s) in keys.account.iter().zip(&secrets) {
                assert_eq!(k.secret, *s);
            }
            assert_eq!(keys.spaces.len(), 1);
            assert_eq!(keys.spaces[0].1[0].secret, EpochSecret([90; 32]));
        }
        assert!(matches!(st.unlock(Unlock::Password("не тот")), Err(Error::BadPassword)));
        assert!(st.unlock(Unlock::Device(&SigningKey::from_bytes(&[5; 32]))).is_err());
        assert!(st.unlock(Unlock::Master([8; 32])).is_err());
    }

    #[test]
    fn rejects_foreign_bytes() {
        assert!(ExitState::from_bytes(b"FHEXIT\0\0\x02").is_err());
        assert!(ExitState::from_bytes(b"nope").is_err());
    }
}
