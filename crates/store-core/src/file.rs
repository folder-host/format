//! Сборка файла: сегменты → шифрование → страйпы → манифест, и обратно.

use std::io::Read;

use crate::{
    Error, Hash, Result,
    chunk::{ChunkParams, Chunker},
    codec::{self, EncodedStripe},
    crypto::{self, Key},
    format::{Code, FileManifest, FileMeta, PackLayout, Stripe},
};

/// Домен AAD зашифрованной `FileMeta`; за ним — эпоха и соль (docs/share.md §2.1).
const META_AAD: &[u8] = b"store/file-meta/v2";
const FILE_KEY_CONTEXT: &[u8] = b"store/file-key/v1";
/// Длина случайной соли версии манифеста; она лежит в начале `FileManifest::meta`.
pub const KEY_SALT_LEN: usize = 16;

/// Ключ файла `fk` одной версии манифеста: `BLAKE3-keyed(ключ метаданных эпохи, контекст ‖ соль)`.
/// Отдать `fk` значит раскрыть `FileMeta` ровно этой версии: ни ключ метаданных эпохи, ни `fk`
/// других версий по нему не восстановить.
pub fn file_key(meta_key: &Key, salt: &[u8]) -> Key {
    let mut h = blake3::Hasher::new_keyed(&meta_key.0);
    h.update(FILE_KEY_CONTEXT);
    h.update(salt);
    Key(*h.finalize().as_bytes())
}

fn meta_aad(epoch: u64, salt: &[u8]) -> Vec<u8> {
    let mut aad = META_AAD.to_vec();
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(salt);
    aad
}

/// Собирает манифест: `meta = соль ‖ seal(fk, FileMeta, AAD)`, соль новая у каждой версии.
pub fn build_manifest(
    epoch: u64,
    meta_key: &Key,
    meta: &FileMeta,
    stripes: Vec<Stripe>,
    prev: Option<Hash>,
) -> FileManifest {
    let salt: [u8; KEY_SALT_LEN] = crypto::random_bytes();
    let fk = file_key(meta_key, &salt);
    seal_manifest(epoch, &salt, &fk, meta, stripes, prev)
}

/// Манифест с готовым ключом файла `fk` (не выведенным из ключа метаданных эпохи): так собирает
/// файл гость ссылки только для загрузки (docs/spaces.md §2.5) — ключа эпохи у него нет, `fk`
/// он запечатывает на ключ входящих, а участник читает `FileMeta` через [`open_meta_fk`].
/// `epoch` — только в AAD: эпоха ключа входящих, на который запечатан `fk`.
pub fn build_manifest_fk(
    epoch: u64,
    fk: &Key,
    meta: &FileMeta,
    stripes: Vec<Stripe>,
    prev: Option<Hash>,
) -> FileManifest {
    let salt: [u8; KEY_SALT_LEN] = crypto::random_bytes();
    seal_manifest(epoch, &salt, fk, meta, stripes, prev)
}

fn seal_manifest(
    epoch: u64,
    salt: &[u8; KEY_SALT_LEN],
    fk: &Key,
    meta: &FileMeta,
    stripes: Vec<Stripe>,
    prev: Option<Hash>,
) -> FileManifest {
    let mut sealed = salt.to_vec();
    sealed.extend_from_slice(&crypto::seal(
        fk,
        &postcard::to_stdvec(meta).expect("сериализация в Vec не падает"),
        &meta_aad(epoch, salt),
    ));
    FileManifest {
        epoch,
        meta: sealed,
        stripes,
        prev,
    }
}

/// Ключ файла этой версии манифеста по ключу метаданных его эпохи.
pub fn manifest_file_key(meta_key: &Key, manifest: &FileManifest) -> Result<Key> {
    let salt = manifest.meta.get(..KEY_SALT_LEN).ok_or(Error::Decrypt)?;
    Ok(file_key(meta_key, salt))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecParams {
    pub chunk: ChunkParams,
    pub k: u8,
    pub m: u8,
    pub code: Code,
}

impl Default for CodecParams {
    fn default() -> Self {
        Self {
            chunk: ChunkParams::DEFAULT,
            k: 8,
            m: 6,
            code: Code::Rs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncodedSegment {
    pub key: Key,
    pub plain_len: usize,
    pub encoded: EncodedStripe,
}

/// Кодирует один сегмент: детерминированный ключ из `segment_root` → шифрование → код `code`.
pub fn encode_segment(segment: &[u8], k: u8, m: u8, code: Code, segment_root: &Key) -> Result<EncodedSegment> {
    // k+m шардов индексируются байтом (размещение, `Stripe::shards`): не больше 255
    let n = u16::from(k) + u16::from(m);
    if k == 0 || m == 0 || n > u16::from(u8::MAX) {
        return Err(Error::InvalidParams { k, m });
    }
    let key = crypto::segment_key(segment_root, segment);
    let ct = crypto::encrypt_segment(&key, segment);
    let encoded = encode_ciphertext(&ct, k, m, code)?;
    Ok(EncodedSegment {
        key,
        plain_len: segment.len(),
        encoded,
    })
}

/// Код стирания над готовым шифротекстом сегмента: то же, что делает [`encode_segment`] после
/// шифрования. Детерминирован: приёмник шифротекста (`store-ingress`) без ключей пользователя
/// получает в точности те шарды и хэши, что посчитал телефон.
pub fn encode_ciphertext(ct: &[u8], k: u8, m: u8, code: Code) -> Result<EncodedStripe> {
    let n = u16::from(k) + u16::from(m);
    if k == 0 || m == 0 || n > u16::from(u8::MAX) {
        return Err(Error::InvalidParams { k, m });
    }
    match code {
        Code::Rs => codec::encode_stripe(ct, k, m),
        Code::Clay => crate::clay::encode_stripe(ct, k, m, (n - 1) as u8),
    }
}

/// Лениво кодирует поток: в памяти одновременно один сегмент и его шарды.
/// Ключ сегмента выводится из `segment_root` и содержимого (convergent encryption в пределах
/// одного корня): одинаковые сегменты дают одинаковые страйпы.
pub fn encode_segments<'a, R: Read + 'a>(
    reader: R,
    params: CodecParams,
    segment_root: &'a Key,
) -> impl Iterator<Item = Result<EncodedSegment>> + 'a {
    Chunker::keyed(reader, params.chunk, segment_root)
        .map(move |segment| encode_segment(&segment?, params.k, params.m, params.code, segment_root))
}

/// Собирает сегмент из любых k шардов; `plain_len` — длина открытого текста сегмента
/// (`FileMeta::segment_lens`).
pub fn decode_segment<S: AsRef<[u8]>>(
    stripe: &Stripe,
    key: &Key,
    shards: &[Option<S>],
    plain_len: usize,
) -> Result<Vec<u8>> {
    crypto::decrypt_segment(key, &codec::decode_stripe(stripe, shards)?, plain_len)
}

/// Склеивает мелкие файлы в один открытый текст сегмента; `ranges[i]` — `(offset, len)` файла `i`.
pub fn pack_segment(files: &[&[u8]]) -> (Vec<u8>, Vec<(u64, u64)>) {
    let mut plain = Vec::with_capacity(files.iter().map(|f| f.len()).sum());
    let mut ranges = Vec::with_capacity(files.len());
    for f in files {
        ranges.push((plain.len() as u64, f.len() as u64));
        plain.extend_from_slice(f);
    }
    (plain, ranges)
}

/// Вырезает `range` из расшифрованного сегмента; диапазон за пределами сегмента — ошибка.
pub fn cut_range(plain: &[u8], range: (u64, u64)) -> Result<&[u8]> {
    let end = range
        .0
        .checked_add(range.1)
        .filter(|&e| e <= plain.len() as u64)
        .ok_or(Error::SegmentLenMismatch("range выходит за пределы сегмента"))?;
    Ok(&plain[range.0 as usize..end as usize])
}

/// Файл пачки формата 6 ([`crate::format::PACK_PIECES_FORMAT`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedFile {
    /// Convergent-ключ файла: `segment_key(segment_root, файл)`.
    pub key: Key,
    /// Смещение шифротекста файла в шифротексте пачки.
    pub ct_offset: u64,
    pub plain_len: u64,
}

impl PackedFile {
    /// `FileMeta::range` файла: `(ct_offset, plain_len)` ([`PackLayout::Piece`]).
    pub fn range(&self) -> (u64, u64) {
        (self.ct_offset, self.plain_len)
    }
}

/// Пачка формата 6: каждый файл шифруется своим convergent-ключом (`encrypt_segment`), шифротекст
/// пачки — конкатенация шифротекстов файлов, страйп строится по ней (`stripe_id` — её BLAKE3).
/// Детерминирована: тот же набор файлов в том же порядке даёт тот же страйп, а тот же файл в
/// другой пачке — тот же шифротекст куска (но другой страйп). Ключ одного файла не открывает
/// соседей: у каждого свой ключ и свои nonce.
pub fn encode_pack(
    files: &[&[u8]],
    k: u8,
    m: u8,
    code: Code,
    segment_root: &Key,
) -> Result<(EncodedStripe, Vec<PackedFile>)> {
    let total: usize = files.iter().map(|f| crypto::ciphertext_len(f.len())).sum();
    let mut ct = Vec::with_capacity(total);
    let mut out = Vec::with_capacity(files.len());
    for f in files {
        let key = crypto::segment_key(segment_root, f);
        out.push(PackedFile {
            key: key.clone(),
            ct_offset: ct.len() as u64,
            plain_len: f.len() as u64,
        });
        ct.extend_from_slice(&crypto::encrypt_segment(&key, f));
    }
    Ok((encode_ciphertext(&ct, k, m, code)?, out))
}

/// Шифротекст куска `[ct_offset, ct_offset + ciphertext_len(plain_len))` в шифротексте страйпа;
/// кусок за его концом — ошибка.
pub fn piece_ct(ct: &[u8], ct_offset: u64, plain_len: usize) -> Result<&[u8]> {
    let len = crypto::ciphertext_len(plain_len) as u64;
    let end = ct_offset
        .checked_add(len)
        .filter(|&e| e <= ct.len() as u64)
        .ok_or(Error::SegmentLenMismatch("кусок выходит за пределы пачки"))?;
    Ok(&ct[ct_offset as usize..end as usize])
}

/// Файл пачки формата 6 из шардов её страйпа: собрать шифротекст пачки, расшифровать только свой
/// кусок ключом файла.
pub fn decode_piece<S: AsRef<[u8]>>(
    stripe: &Stripe,
    key: &Key,
    shards: &[Option<S>],
    ct_offset: u64,
    plain_len: usize,
) -> Result<Vec<u8>> {
    let ct = codec::decode_stripe(stripe, shards)?;
    crypto::decrypt_segment(key, piece_ct(&ct, ct_offset, plain_len)?, plain_len)
}

/// Расшифровывает сегмент упакованного файла и возвращает только его срез `range`.
pub fn decode_packed<S: AsRef<[u8]>>(
    stripe: &Stripe,
    key: &Key,
    shards: &[Option<S>],
    range: (u64, u64),
    plain_len: usize,
) -> Result<Vec<u8>> {
    let plain = decode_segment(stripe, key, shards, plain_len)?;
    Ok(cut_range(&plain, range)?.to_vec())
}

/// Накапливает страйпы по мере загрузки и выпускает манифест в конце.
#[derive(Debug, Default, Clone)]
pub struct ManifestBuilder {
    stripes: Vec<Stripe>,
    keys: Vec<Key>,
    lens: Vec<u32>,
}

impl ManifestBuilder {
    pub fn push(&mut self, segment: &EncodedSegment) {
        self.stripes.push(segment.encoded.stripe.clone());
        self.keys.push(segment.key.clone());
        self.lens.push(segment.plain_len as u32);
    }

    /// Сегмент, загруженный раньше (докачка): то же, что [`Self::push`], без шардов в памяти.
    pub fn push_parts(&mut self, stripe: Stripe, key: Key, plain_len: u32) {
        self.stripes.push(stripe);
        self.keys.push(key);
        self.lens.push(plain_len);
    }

    /// `epoch` — эпоха ключей данных, которой принадлежит `meta_key`.
    pub fn finish(self, epoch: u64, meta_key: &Key, name: String, mtime_ns: i128, prev: Option<Hash>) -> FileManifest {
        self.finish_range(epoch, meta_key, name, mtime_ns, prev, None)
    }

    /// С `range` файл — срез единственного сегмента (pack): размер файла — длина среза.
    /// Размер и `range` уходят только в зашифрованную `FileMeta`.
    pub fn finish_range(
        self,
        epoch: u64,
        meta_key: &Key,
        name: String,
        mtime_ns: i128,
        prev: Option<Hash>,
        range: Option<(u64, u64)>,
    ) -> FileManifest {
        let meta = FileMeta {
            name,
            mtime_ns,
            segment_keys: self.keys,
            segment_lens: self.lens,
            range,
        };
        build_manifest(epoch, meta_key, &meta, self.stripes, prev)
    }
}

/// `FileMeta` по ключу метаданных эпохи манифеста.
pub fn open_meta(meta_key: &Key, manifest: &FileManifest) -> Result<FileMeta> {
    open_meta_fk(&manifest_file_key(meta_key, manifest)?, manifest)
}

/// `FileMeta` по ключу файла `fk` этой версии (так читает получатель share).
pub fn open_meta_fk(fk: &Key, manifest: &FileManifest) -> Result<FileMeta> {
    let (salt, sealed) = manifest.meta.split_at_checked(KEY_SALT_LEN).ok_or(Error::Decrypt)?;
    let meta: FileMeta = postcard::from_bytes(&crypto::open(fk, sealed, &meta_aad(manifest.epoch, salt))?)?;
    if meta.segment_keys.len() != manifest.stripes.len() {
        return Err(Error::KeyCountMismatch {
            keys: meta.segment_keys.len(),
            stripes: manifest.stripes.len(),
        });
    }
    if meta.segment_lens.len() != manifest.stripes.len() {
        return Err(Error::SegmentLenMismatch("число длин не равно числу страйпов"));
    }
    if meta.range.is_some() && manifest.stripes.len() != 1 {
        return Err(Error::SegmentLenMismatch("упакованный файл должен иметь один сегмент"));
    }
    match meta.layout() {
        PackLayout::Segments => {}
        PackLayout::Slice { offset, len } => {
            if offset
                .checked_add(len)
                .is_none_or(|e| e > u64::from(meta.segment_lens[0]))
            {
                return Err(Error::SegmentLenMismatch("range выходит за пределы сегмента"));
            }
        }
        PackLayout::Piece { ct_offset, len } => {
            // шифротекст пачки целиком лежит в k data-шардах (за префиксом длины)
            let s = &manifest.stripes[0];
            let room = u64::from(s.k) * u64::from(s.shard_len);
            if ct_offset
                .checked_add(crypto::ciphertext_len(len as usize) as u64)
                .is_none_or(|e| e > room)
            {
                return Err(Error::SegmentLenMismatch("кусок выходит за пределы пачки"));
            }
        }
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_and_cut() {
        let files: [&[u8]; 4] = [b"alpha", b"", b"be", b"gamma-gamma"];
        let (plain, ranges) = pack_segment(&files);
        assert_eq!(plain, b"alphabegamma-gamma");
        for (f, &r) in files.iter().zip(&ranges) {
            assert_eq!(cut_range(&plain, r).unwrap(), *f);
        }
        assert!(cut_range(&plain, (plain.len() as u64 - 1, 2)).is_err());
        assert!(cut_range(&plain, (u64::MAX, 2)).is_err());

        // через шифрование, RS и манифест
        let root = Key::random();
        let seg = encode_segment(&plain, 8, 6, Code::Rs, &root).unwrap();
        let meta_key = Key::random();
        let mut b = ManifestBuilder::default();
        b.push(&seg);
        let m = b.finish_range(0, &meta_key, "f".into(), 1, None, Some(ranges[3]));
        // размер и срез узлам не видны: только в зашифрованной FileMeta
        let meta = open_meta(&meta_key, &m).unwrap();
        assert_eq!(meta.size(), files[3].len() as u64);
        let shards: Vec<Option<Vec<u8>>> = seg.encoded.shards.iter().cloned().map(Some).collect();
        let got = decode_packed(
            &m.stripes[0],
            &meta.segment_keys[0],
            &shards,
            meta.range.unwrap(),
            meta.segment_lens[0] as usize,
        )
        .unwrap();
        assert_eq!(got, files[3]);

        // range за пределами сегмента отвергается
        let mut b = ManifestBuilder::default();
        b.push(&seg);
        let bad = b.finish_range(0, &meta_key, "f".into(), 1, None, Some((plain.len() as u64 - 1, 2)));
        assert!(open_meta(&meta_key, &bad).is_err());
    }

    /// Пачка формата 6: каждый файл читается своим ключом из своего куска; ключ одного файла не
    /// расшифровывает ни кусок соседа, ни пачку целиком; манифест несёт кусок, а не срез.
    #[test]
    fn pack_pieces_keep_neighbours_closed() {
        let files: [&[u8]; 4] = [b"alpha", b"", &[7u8; 70_000], b"gamma-gamma"];
        let root = Key::random();
        let (enc, pieces) = encode_pack(&files, 8, 6, Code::Rs, &root).unwrap();
        assert_eq!(pieces.len(), files.len());
        let shards: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
        let ct = codec::decode_stripe(&enc.stripe, &shards).unwrap();
        // шифротекст пачки — конкатенация шифротекстов файлов, stripe_id — его хэш
        let mut concat = Vec::new();
        for (f, p) in files.iter().zip(&pieces) {
            assert_eq!(p.ct_offset, concat.len() as u64);
            assert_eq!(p.key, crypto::segment_key(&root, f), "convergent-ключ файла");
            concat.extend_from_slice(&crypto::encrypt_segment(&p.key, f));
        }
        assert_eq!(ct, concat);
        assert_eq!(enc.stripe.stripe_id, Hash::of(&concat));

        let meta_key = Key::random();
        let manifest = |p: &PackedFile| {
            let mut b = ManifestBuilder::default();
            b.push_parts(enc.stripe.clone(), p.key.clone(), p.plain_len as u32);
            b.finish_range(0, &meta_key, "f".into(), 1, None, Some(p.range()))
        };
        for (f, p) in files.iter().zip(&pieces) {
            let meta = open_meta(&meta_key, &manifest(p)).unwrap();
            assert_eq!(
                meta.layout(),
                PackLayout::Piece {
                    ct_offset: p.ct_offset,
                    len: p.plain_len
                }
            );
            assert_eq!(meta.size(), f.len() as u64);
            let got = decode_piece(&enc.stripe, &meta.segment_keys[0], &shards, p.ct_offset, f.len()).unwrap();
            assert_eq!(got, *f);
            // только свой кусок, без страйпа целиком
            let own = piece_ct(&ct, p.ct_offset, f.len()).unwrap();
            assert_eq!(crypto::decrypt_segment(&p.key, own, f.len()).unwrap(), *f);
        }
        // ключ файла 0 не открывает соседей и пачку целиком
        let (k0, n3) = (&pieces[0].key, &pieces[3]);
        assert!(
            crypto::decrypt_segment(k0, piece_ct(&ct, n3.ct_offset, files[3].len()).unwrap(), files[3].len()).is_err()
        );
        assert!(decode_piece(&enc.stripe, k0, &shards, n3.ct_offset, files[3].len()).is_err());
        let big = &pieces[2];
        assert!(
            crypto::decrypt_segment(
                k0,
                piece_ct(&ct, big.ct_offset, files[2].len()).unwrap(),
                files[2].len()
            )
            .is_err()
        );
        // ключи разных файлов различны, у одинаковых файлов в другой пачке — тот же кусок
        assert_ne!(pieces[0].key, pieces[3].key);
        let (enc2, pieces2) = encode_pack(&[files[3], &b"other"[..]], 8, 6, Code::Rs, &root).unwrap();
        assert_ne!(enc2.stripe.stripe_id, enc.stripe.stripe_id);
        let shards2: Vec<Option<Vec<u8>>> = enc2.shards.iter().cloned().map(Some).collect();
        let ct2 = codec::decode_stripe(&enc2.stripe, &shards2).unwrap();
        assert_eq!(
            piece_ct(&ct2, pieces2[0].ct_offset, files[3].len()).unwrap(),
            piece_ct(&ct, n3.ct_offset, files[3].len()).unwrap()
        );
        // пачка детерминирована
        assert_eq!(encode_pack(&files, 8, 6, Code::Rs, &root).unwrap().0.stripe, enc.stripe);

        // кусок за пределами пачки отвергается при разборе манифеста
        let mut b = ManifestBuilder::default();
        b.push_parts(enc.stripe.clone(), pieces[3].key.clone(), 11);
        let bad = b.finish_range(
            0,
            &meta_key,
            "f".into(),
            1,
            None,
            Some((u64::from(enc.stripe.shard_len) * 8, 11)),
        );
        assert!(open_meta(&meta_key, &bad).is_err());
    }

    /// Ключ файла свой у каждой версии: он открывает `FileMeta` только своего манифеста, а ни
    /// ключ другой версии, ни сам ключ метаданных эпохи (как ключ файла) — нет.
    #[test]
    fn file_key_is_per_version() {
        let meta_key = Key::random();
        let make = || {
            let seg = encode_segment(b"data", 8, 6, Code::Rs, &Key::random()).unwrap();
            let mut b = ManifestBuilder::default();
            b.push(&seg);
            b.finish(0, &meta_key, "f".into(), 1, None)
        };
        let (m1, m2) = (make(), make());
        let (k1, k2) = (
            manifest_file_key(&meta_key, &m1).unwrap(),
            manifest_file_key(&meta_key, &m2).unwrap(),
        );
        assert_ne!(k1, k2);
        assert_eq!(open_meta_fk(&k1, &m1).unwrap().name, "f");
        assert!(open_meta_fk(&k2, &m1).is_err());
        assert!(open_meta_fk(&meta_key, &m1).is_err());
        assert_eq!(open_meta(&meta_key, &m2).unwrap().name, "f");
        // соль в манифесте подменить нельзя: она входит в AAD и определяет ключ
        let mut bad = m1.clone();
        bad.meta[0] ^= 1;
        assert!(open_meta_fk(&k1, &bad).is_err());
        assert!(open_meta(&meta_key, &bad).is_err());
        // манифест короче соли не разбирается
        let mut short = m1;
        short.meta.truncate(KEY_SALT_LEN - 1);
        assert!(open_meta(&meta_key, &short).is_err());
    }
}
