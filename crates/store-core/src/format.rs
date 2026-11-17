//! Неизменяемые сущности (адресуются BLAKE3) и подписанный корень пользователя.
//!
//! Каждый блоб — `версия ‖ тело`. Сборка читает окно [`FORMAT_MIN`]`..=`[`FORMAT_VERSION`]
//! (текущий формат и предыдущий), пишет формат, разрешённый кластером: `format_target` из его
//! конфига ([`write_format`], [`to_blob_at`]). Подробно — docs/protocols.md, «Совместимость версий».
//!
//! Хэш блоба зависит от версии: блоб, разобранный и записанный заново, может получить другой
//! адрес. Поэтому адрес блоба берётся из ссылки на него, а не считается по разобранному значению.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Error, Hash, Result};

/// Наибольшая версия формата, которую знает сборка.
///
/// - 5 — первый выпуск (прод с 3 ноября);
/// - 6 — пачки по файлам ([`PACK_PIECES_FORMAT`], docs/share.md §2.4). Разметка блобов та же,
///   что у 5; версия поднята, чтобы новые пачки писались только после подъёма `format_target`,
///   когда их читают все узлы и клиенты, а сборки до 6 отказывали на них явно.
pub const FORMAT_VERSION: u8 = 6;
/// Старейшая читаемая версия: `FORMAT_VERSION − 1`.
pub const FORMAT_MIN: u8 = 5;
/// Формат записи, с которого клиент пишет пачку мелких файлов кусками: каждый файл шифруется
/// своим convergent-ключом, шифротекст пачки — конкатенация шифротекстов файлов
/// ([`crate::file::encode_pack`], [`PackLayout::Piece`]). Ниже — один сегмент с одним ключом
/// на всю пачку ([`PackLayout::Slice`]).
pub const PACK_PIECES_FORMAT: u8 = 6;
/// Версия, с которой считается [`Stripe::key`]. Ключ страйпа — имя тега на узлах и строка карты
/// позиций: смена [`FORMAT_VERSION`] не должна его менять. Константа не меняется никогда.
const STRIPE_KEY_FORMAT: u8 = 5;

// окно чтения шириной в одну версию: N и N−1, не больше (`docs/nas.md`, «Обновления»)
const _: () = assert!(FORMAT_VERSION >= FORMAT_MIN && FORMAT_VERSION - FORMAT_MIN <= 1);

fn encode_at<T: Serialize>(version: u8, value: &T) -> Vec<u8> {
    let mut out = vec![version];
    postcard::to_io(value, &mut out).expect("запись в Vec не падает");
    out
}

/// Блоб новейшего формата сборки. Для записи в кластер — [`to_blob_at`] с [`write_format`].
pub fn to_blob<T: Serialize>(value: &T) -> Vec<u8> {
    encode_at(FORMAT_VERSION, value)
}

/// Версия, которой сборка пишет новые блобы при `format_target` кластера: цель, ограниченная
/// тем, что сборка умеет. Сборка новее цели пишет старый формат, пока кластер не поднят.
pub fn write_format(target: u64) -> u8 {
    target.clamp(FORMAT_MIN as u64, FORMAT_VERSION as u64) as u8
}

/// Блоб версии `version` из окна чтения.
pub fn to_blob_at<T: Blob>(value: &T, version: u8) -> Vec<u8> {
    let mut out = vec![version];
    out.extend_from_slice(&value.encode_body(version));
    out
}

/// Тип, который хранится блобом. Разметка postcard не расширяется: тип, тело которого изменилось
/// в новой версии формата, переопределяет оба метода и читает и пишет прежнюю разметку для
/// `version = FORMAT_VERSION − 1`.
pub trait Blob: Serialize + DeserializeOwned {
    /// Тело версии `version` из окна чтения.
    fn decode_body(_version: u8, body: &[u8]) -> Result<Self> {
        // хвост после значения — не тот блоб: иначе разные байты (и адреса) давали бы одно значение
        let (value, tail) = postcard::take_from_bytes(body)?;
        if !tail.is_empty() {
            return Err(Error::TrailingBytes(tail.len()));
        }
        Ok(value)
    }

    /// Обратное к [`decode_body`](Self::decode_body).
    fn encode_body(&self, _version: u8) -> Vec<u8> {
        postcard::to_stdvec(self).expect("запись в Vec не падает")
    }
}

fn from_blob_in<T: Blob>(blob: &[u8], min: u8, max: u8) -> Result<T> {
    let (&version, body) = blob.split_first().ok_or(Error::EmptyBlob)?;
    if !(min..=max).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    T::decode_body(version, body)
}

pub fn from_blob<T: Blob>(blob: &[u8]) -> Result<T> {
    from_blob_in(blob, FORMAT_MIN, FORMAT_VERSION)
}

/// Код стирания страйпа.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Code {
    /// Reed-Solomon k+m ([`crate::codec`]).
    #[default]
    Rs,
    /// Clay (MSR) с d = k+m−1 ([`crate::clay`]): ремонт одного шарда по 1/m от каждого из
    /// остальных шардов.
    Clay,
}

/// Зашифрованный сегмент, закодированный кодом стирания k+m.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stripe {
    /// BLAKE3 шифротекста сегмента.
    pub stripe_id: Hash,
    pub k: u8,
    pub m: u8,
    pub shard_len: u32,
    /// k+m хэшей, индекс = индекс в коде (0..k — data, k.. — parity).
    pub shards: Vec<Hash>,
    pub code: Code,
}

impl Blob for Stripe {}

impl Stripe {
    /// Ключ страйпа (`stripe_key`, docs/quota.md §2): хэш сериализованного `Stripe` целиком.
    /// Различает страйпы с одинаковым `stripe_id` (тот же сегмент при других k/m). От версии
    /// формата не зависит ([`STRIPE_KEY_FORMAT`]).
    pub fn key(&self) -> Hash {
        Hash::of(&encode_at(STRIPE_KEY_FORMAT, self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Манифест файла. Размер и срез упакованного файла узлам не видны: они только в
/// зашифрованной [`FileMeta`] ([`FileMeta::size`]).
pub struct FileManifest {
    /// Эпоха ключей данных ([`crate::keyring`]), ключом метаданных которой зашифрован `meta`.
    /// Ключи сегментов лежат в самой `FileMeta`, поэтому файл читается ключами своей эпохи.
    pub epoch: u64,
    /// `соль(16) ‖ seal(fk, FileMeta)`: [`FileMeta`] зашифрован ключом файла `fk` этой версии,
    /// выведенным из ключа метаданных эпохи `epoch` и соли ([`crate::file::file_key`]).
    pub meta: Vec<u8>,
    pub stripes: Vec<Stripe>,
    /// Предыдущая версия файла.
    pub prev: Option<Hash>,
}

impl Blob for FileManifest {}

/// Открытая часть манифеста; в манифесте лежит только в зашифрованном виде.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    /// Unix-время модификации, наносекунды.
    pub mtime_ns: i128,
    /// Ключ i-го сегмента, параллельно `FileManifest::stripes`.
    pub segment_keys: Vec<crate::crypto::Key>,
    /// Длина открытого текста i-го сегмента, параллельно `segment_keys`; по ней находят страйпы для диапазона.
    pub segment_lens: Vec<u32>,
    /// Файл упакован в общий страйп (`stripes.len() == 1`), `(смещение, длина файла)`; для
    /// обычных файлов `None`. Смысл смещения — [`FileMeta::layout`].
    pub range: Option<(u64, u64)>,
}

/// Как лежат байты файла в его страйпах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackLayout {
    /// Обычный файл: сегменты по `segment_lens`, каждый своим ключом.
    Segments,
    /// Пачка формата 5: `segment_keys[0]` — ключ всего сегмента пачки, `segment_lens[0]` — его
    /// открытый текст, файл — `[offset, offset + len)` расшифрованного сегмента.
    Slice { offset: u64, len: u64 },
    /// Пачка формата 6 ([`PACK_PIECES_FORMAT`]): файл зашифрован отдельно ключом
    /// `segment_keys[0]` (`segment_lens[0] == len`), его шифротекст —
    /// `[ct_offset, ct_offset + ciphertext_len(len))` шифротекста страйпа.
    Piece { ct_offset: u64, len: u64 },
}

impl FileMeta {
    /// Размер файла: длина файла в пачке у упакованного, сумма длин сегментов у обычного.
    pub fn size(&self) -> u64 {
        self.range
            .map_or_else(|| self.segment_lens.iter().map(|&l| u64::from(l)).sum(), |r| r.1)
    }

    /// Раскладка файла. Вид пачки определяется самой `FileMeta`, а не версией блоба манифеста:
    /// перевыпуск старого манифеста в новом формате (обрезка версий, переименование, `save_share`)
    /// переносит `FileMeta` как есть.
    ///
    /// Кусок — когда длина сегмента равна длине файла. В пачке формата 5 так бывает, только
    /// если файл занимает весь сегмент с нуля (`offset == 0`, остальные файлы пусты); тогда оба
    /// прочтения совпадают: кусок `[0, ciphertext_len(len))` — весь шифротекст сегмента, ключ —
    /// ключ сегмента. Поэтому разбор однозначен без признака в `FileMeta`.
    pub fn layout(&self) -> PackLayout {
        match (self.range, self.segment_lens.first()) {
            (None, _) => PackLayout::Segments,
            (Some((ct_offset, len)), Some(&l)) if u64::from(l) == len => PackLayout::Piece { ct_offset, len },
            (Some((offset, len)), _) => PackLayout::Slice { offset, len },
        }
    }

    /// Ключ файла (`fk`) раскрывает соседей по пачке: пачка формата 5, ключ сегмента общий.
    /// Такой файл share и пространства отдают только перешифрованной копией (docs/share.md §2.4).
    pub fn key_reveals_neighbours(&self) -> bool {
        matches!(self.layout(), PackLayout::Slice { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// Имя, зашифрованное клиентом детерминированно ключом имён эпохи, с MAC над видом и хэшем
    /// записи (`store_client::names`): запись с переставленным хэшем клиент не откроет.
    pub name_enc: Vec<u8>,
    pub kind: Kind,
    pub hash: Hash,
    /// Атрибуты приложения, зашифрованные клиентом ключом имён (`seal`, AAD
    /// `store/dir-extra/v2 ‖ id имени ‖ вид ‖ хэш`); пусто — атрибутов нет. Узлам непрозрачны.
    pub extra: Vec<u8>,
    /// Стабильный идентификатор записи (16 случайных байт), зашифрованный ключом имён (`seal`, AAD
    /// `store/dir-id/v1`). Не меняется при переименовании, переносе и новой версии файла;
    /// шифруется, чтобы узлы не связывали версии каталога между собой (docs/ffi.md).
    pub id_enc: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dir {
    /// Эпоха ключей данных, ключом имён которой зашифрованы `name_enc`, `extra` и `id_enc` всех записей.
    /// Каталог, переписываемый в более новой эпохе, перешифровывается целиком.
    pub epoch: u64,
    /// Отсортированы по `name_enc`.
    pub entries: Vec<DirEntry>,
}

impl Blob for Dir {}

impl Dir {
    pub fn new(epoch: u64, mut entries: Vec<DirEntry>) -> Self {
        entries.sort_by(|a, b| a.name_enc.cmp(&b.name_enc));
        Self { epoch, entries }
    }

    pub fn is_sorted(&self) -> bool {
        self.entries.windows(2).all(|w| w[0].name_enc < w[1].name_enc)
    }
}

/// Единственная изменяемая сущность; живёт в Raft, обновляется CAS по `version`.
///
/// Подписывает корень устройство пользователя (`signer` — ed25519-ключ его iroh `Endpoint`);
/// что `signer` — активное устройство `user`, проверяет control plane при CAS. `epoch` —
/// эпоха ключей данных, в которой записан корневой каталог: control plane принимает только
/// текущую эпоху пользователя (запись в старой эпохе после отзыва устройства невозможна).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    pub user: VerifyingKey,
    pub dir: Hash,
    pub version: u64,
    pub epoch: u64,
    /// Этот коммит удаляет данные насовсем (очистка корзины, удаление внутри `/.trash`,
    /// удаление в режиме «только удаление»): control plane запоминает его версию, а узлы
    /// хранения снимают теги без позиций в дереве быстрым путём (docs/quota.md §5.1). Покрыт
    /// подписью: подменить признак нельзя.
    pub release: bool,
    pub signer: VerifyingKey,
    pub sig: Signature,
}

impl Blob for Root {}

const ROOT_DOMAIN: &[u8] = b"store/root/v3";

fn root_message(
    user: &VerifyingKey,
    signer: &VerifyingKey,
    dir: &Hash,
    version: u64,
    epoch: u64,
    release: bool,
) -> Vec<u8> {
    let mut msg = ROOT_DOMAIN.to_vec();
    msg.extend_from_slice(user.as_bytes());
    msg.extend_from_slice(signer.as_bytes());
    msg.extend_from_slice(dir.as_bytes());
    msg.extend_from_slice(&version.to_le_bytes());
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.push(u8::from(release));
    msg
}

impl Root {
    /// Обычный коммит (без удаления насовсем). `device` — ключ устройства, `user` — аккаунт,
    /// которому принадлежит корень.
    pub fn sign(device: &SigningKey, user: VerifyingKey, dir: Hash, version: u64, epoch: u64) -> Self {
        Self::sign_as(device, user, dir, version, epoch, false)
    }

    /// Коммит с признаком `release` (удаление насовсем, см. [`Root::release`]).
    pub fn sign_as(
        device: &SigningKey,
        user: VerifyingKey,
        dir: Hash,
        version: u64,
        epoch: u64,
        release: bool,
    ) -> Self {
        let signer = device.verifying_key();
        let sig = device.sign(&root_message(&user, &signer, &dir, version, epoch, release));
        Self {
            user,
            dir,
            version,
            epoch,
            release,
            signer,
            sig,
        }
    }

    /// Подпись `signer`; принадлежность `signer` аккаунту здесь не проверяется.
    pub fn verify(&self) -> Result<()> {
        self.signer
            .verify(
                &root_message(
                    &self.user,
                    &self.signer,
                    &self.dir,
                    self.version,
                    self.epoch,
                    self.release,
                ),
                &self.sig,
            )
            .map_err(|_| Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Признак удаления насовсем покрыт подписью: подмена ломает проверку.
    #[test]
    fn root_release_signed() {
        let d = SigningKey::from_bytes(&[7; 32]);
        let u = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let r = Root::sign_as(&d, u, Hash::of(b"dir"), 3, 0, true);
        assert!(r.release && r.verify().is_ok());
        assert!(!Root::sign(&d, u, Hash::of(b"dir"), 3, 0).release);
        let mut forged = r.clone();
        forged.release = false;
        assert!(forged.verify().is_err());
        let mut forged = Root::sign(&d, u, Hash::of(b"dir"), 3, 0);
        forged.release = true;
        assert!(forged.verify().is_err());
    }

    #[test]
    fn blob_version_checked() {
        let dir = Dir::default();
        let mut blob = to_blob(&dir);
        assert_eq!(blob[0], FORMAT_VERSION);
        assert_eq!(from_blob::<Dir>(&blob).unwrap(), dir);
        blob[0] = 99;
        assert!(matches!(from_blob::<Dir>(&blob), Err(Error::UnsupportedVersion(99))));
        assert!(matches!(from_blob::<Dir>(&[]), Err(Error::EmptyBlob)));
        // хвостовые байты — неканоничный блоб
        blob[0] = FORMAT_VERSION;
        blob.push(0);
        assert!(matches!(from_blob::<Dir>(&blob), Err(Error::TrailingBytes(1))));
    }

    /// Тип, разметка которого изменилась между версиями 4 и 5.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Grown {
        a: u32,
        b: u32,
    }

    impl Blob for Grown {
        fn decode_body(version: u8, body: &[u8]) -> Result<Self> {
            if version == 4 {
                let a: u32 = postcard::from_bytes(body)?;
                return Ok(Self { a, b: 0 });
            }
            Ok(postcard::from_bytes(body)?)
        }

        fn encode_body(&self, version: u8) -> Vec<u8> {
            if version == 4 {
                return postcard::to_stdvec(&self.a).unwrap();
            }
            postcard::to_stdvec(self).unwrap()
        }
    }

    /// Окно N−1..=N: читаются обе версии, старая — своей разметкой, вне окна — отказ.
    #[test]
    fn previous_format_reads_through_window() {
        let v = Grown { a: 7, b: 9 };
        let old = to_blob_at(&v, 4);
        let new = to_blob_at(&v, 5);
        assert_eq!((old[0], new[0]), (4, 5));
        assert_eq!(from_blob_in::<Grown>(&old, 4, 5).unwrap(), Grown { a: 7, b: 0 });
        assert_eq!(from_blob_in::<Grown>(&new, 4, 5).unwrap(), v);
        // следующая сборка окна 5..=6: блоб N−2 уже не читается
        assert!(matches!(
            from_blob_in::<Grown>(&old, 5, 6),
            Err(Error::UnsupportedVersion(4))
        ));
        // сборка 3..=4 не читает новый формат, а не разбирает его наугад
        assert!(matches!(
            from_blob_in::<Grown>(&new, 3, 4),
            Err(Error::UnsupportedVersion(5))
        ));
    }

    /// Запись следует цели кластера, но не выходит за пределы того, что знает сборка.
    #[test]
    fn write_format_clamped() {
        assert_eq!(write_format(FORMAT_VERSION as u64), FORMAT_VERSION);
        assert_eq!(
            write_format(FORMAT_VERSION as u64 + 1),
            FORMAT_VERSION,
            "цель новее сборки"
        );
        assert_eq!(write_format(0), FORMAT_MIN, "цель старше окна");
        let dir = Dir::default();
        assert_eq!(to_blob_at(&dir, write_format(FORMAT_VERSION as u64)), to_blob(&dir));
        assert_eq!(to_blob_at(&dir, write_format(5))[0], 5, "кластер до подъёма пишет 5");
    }

    /// Манифест обеих версий окна разбирается одинаково: разметка 5 и 6 совпадает, отличается
    /// только раскладка пачки внутри зашифрованной `FileMeta`.
    #[test]
    fn manifest_reads_both_versions() {
        let m = FileManifest {
            epoch: 3,
            meta: vec![1, 2, 3],
            stripes: vec![Stripe {
                stripe_id: Hash::of(b"s"),
                k: 2,
                m: 1,
                shard_len: 64,
                shards: vec![Hash::of(b"a"), Hash::of(b"b"), Hash::of(b"c")],
                code: Code::Rs,
            }],
            prev: Some(Hash::of(b"prev")),
        };
        for v in FORMAT_MIN..=FORMAT_VERSION {
            let blob = to_blob_at(&m, v);
            assert_eq!(blob[0], v);
            assert_eq!(from_blob::<FileManifest>(&blob).unwrap(), m, "версия {v}");
        }
        let mut future = to_blob(&m);
        future[0] = FORMAT_VERSION + 1;
        assert!(matches!(
            from_blob::<FileManifest>(&future),
            Err(Error::UnsupportedVersion(_))
        ));
    }

    /// Раскладка пачки по `FileMeta`: кусок (6), срез (5) и вырожденный срез 5 на весь сегмент.
    #[test]
    fn pack_layout_from_meta() {
        let meta = |lens: Vec<u32>, range| FileMeta {
            name: "f".into(),
            mtime_ns: 0,
            segment_keys: lens.iter().map(|_| crate::crypto::Key([0; 32])).collect(),
            segment_lens: lens,
            range,
        };
        assert_eq!(meta(vec![10, 20], None).layout(), PackLayout::Segments);
        let slice = meta(vec![100], Some((40, 10)));
        assert_eq!(slice.layout(), PackLayout::Slice { offset: 40, len: 10 });
        assert!(slice.key_reveals_neighbours());
        let piece = meta(vec![10], Some((4096, 10)));
        assert_eq!(
            piece.layout(),
            PackLayout::Piece {
                ct_offset: 4096,
                len: 10
            }
        );
        assert!(!piece.key_reveals_neighbours());
        assert_eq!((slice.size(), piece.size()), (10, 10));
        // срез 5 на весь сегмент читается как кусок с нуля — те же байты тем же ключом
        assert_eq!(
            meta(vec![10], Some((0, 10))).layout(),
            PackLayout::Piece { ct_offset: 0, len: 10 }
        );
    }

    /// Ключ страйпа — имя тега: не зависит от версии, которой пишутся блобы.
    #[test]
    fn stripe_key_is_pinned() {
        let s = Stripe {
            stripe_id: Hash::of(b"s"),
            k: 1,
            m: 1,
            shard_len: 1,
            shards: vec![Hash::of(b"a"), Hash::of(b"b")],
            code: Code::Rs,
        };
        let mut pinned = vec![5u8];
        postcard::to_io(&s, &mut pinned).unwrap();
        assert_eq!(s.key(), Hash::of(&pinned));
    }

    #[test]
    fn dir_sorted() {
        let e = |n: &[u8]| DirEntry {
            name_enc: n.to_vec(),
            kind: Kind::File,
            hash: Hash::of(n),
            extra: Vec::new(),
            id_enc: Vec::new(),
        };
        let d = Dir::new(3, vec![e(b"c"), e(b"a"), e(b"b")]);
        assert!(d.is_sorted());
        assert_eq!(from_blob::<Dir>(&to_blob(&d)).unwrap(), d);
    }

    #[test]
    fn root_signature() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let user = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let root = Root::sign(&key, user, Hash::of(b"dir"), 5, 2);
        root.verify().unwrap();
        assert_eq!((root.user, root.signer, root.epoch), (user, key.verifying_key(), 2));
        let decoded: Root = from_blob(&to_blob(&root)).unwrap();
        decoded.verify().unwrap();

        let mut bumped = root.clone();
        bumped.version = 6;
        assert!(bumped.verify().is_err());
        let mut swapped = root.clone();
        swapped.dir = Hash::of(b"other");
        assert!(swapped.verify().is_err());
        let mut epoch = root.clone();
        epoch.epoch = 3;
        assert!(epoch.verify().is_err());
        // корень другого пользователя той же подписью не выдать
        let mut other = root;
        other.user = key.verifying_key();
        assert!(other.verify().is_err());
    }
}
