use crate::hash::Hash;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("неподдерживаемая версия формата {0}")]
    UnsupportedVersion(u8),
    #[error("пустой блоб")]
    EmptyBlob,
    #[error("лишние {0} байт после значения в блобе")]
    TrailingBytes(usize),
    #[error("сериализация: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("ошибка расшифровки или подмена данных")]
    Decrypt,
    #[error("неверные параметры кодирования k={k}, m={m}")]
    InvalidParams { k: u8, m: u8 },
    #[error("недостаточно целых шардов: есть {have}, нужно {need}")]
    NotEnoughShards { have: usize, need: usize },
    #[error("хэш не совпал: ожидался {expected}, получен {actual}")]
    HashMismatch { expected: Hash, actual: Hash },
    #[error("повреждённый страйп: {0}")]
    CorruptStripe(&'static str),
    #[error("неверный открытый ключ получателя (точка малого порядка)")]
    BadRecipient,
    #[error("неверная подпись корня")]
    BadSignature,
    #[error("число ключей сегментов ({keys}) не совпадает с числом страйпов ({stripes})")]
    KeyCountMismatch { keys: usize, stripes: usize },
    #[error("длины сегментов не согласованы с манифестом: {0}")]
    SegmentLenMismatch(&'static str),
    #[error("reed-solomon: {0}")]
    ReedSolomon(#[from] reed_solomon_simd::Error),
    #[error("неверный пароль")]
    BadPassword,
    #[error("ввод-вывод: {0}")]
    Io(#[from] std::io::Error),
}
