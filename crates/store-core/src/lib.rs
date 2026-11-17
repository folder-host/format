//! Ядро хранилища: форматы данных, сериализация, FastCDC, шифрование и RS-кодек.
//!
//! Конвейер записи: [`chunk::Chunker`] режет поток на сегменты →
//! [`file::encode_segment`] шифрует каждый ([`crypto::encrypt_segment`]) ключом, выведенным из
//! содержимого ([`crypto::segment_key`]) →
//! [`codec::encode_stripe`] кодирует шифротекст в k+m шардов
//! (экспериментальная альтернатива с дешёвым ремонтом — [`clay`]).
//! [`file`] собирает всё это в [`format::FileManifest`].

pub mod chunk;
pub mod clay;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod escrow;
pub mod exit;
pub mod file;
pub mod format;
pub mod hash;
pub mod keyring;
pub mod names;
pub mod share;

pub use error::{Error, Result};
pub use hash::Hash;
