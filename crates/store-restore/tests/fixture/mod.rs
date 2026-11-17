//! Builds a small account the way the client writes it, using only `store_core`: two key
//! epochs, nested folders, Unicode names, an empty file, a multi-segment file, both pack
//! layouts (format 5 slice, format 6 pieces), a version chain, the trash, a family space, a
//! stripe with exactly k shards left and a stripe with a corrupt shard.
//!
//! Writes `<out>/export/{state.fhx,blobs/}`, `<out>/expected/` (the plain files `fh-restore`
//! must produce) and `<out>/unlock/` (password, device key, account file). Used by `tests/vectors.rs` and by `examples/gen_vectors.rs`, which refreshes the
//! committed vectors.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use store_core::Hash;
use store_core::escrow::{self, Argon};
use store_core::exit::{AccountKeyring, Escrow, ExitState, NodeHint, SpaceState};
use store_core::file::{build_manifest, encode_pack, encode_segment, pack_segment};
use store_core::format::{Code, Dir, DirEntry, FileManifest, FileMeta, Kind, Root, Stripe, to_blob_at};
use store_core::keyring::{self, EpochKeys, EpochSecret};
use store_core::{crypto, names};

pub const PASSWORD: &str = "correct horse battery staple";
pub const USER_SEED: [u8; 32] = [1; 32];
pub const DEVICE_SEED: [u8; 32] = [2; 32];
pub const MASTER: [u8; 32] = [9; 32];
pub const SPACE_SEED: [u8; 32] = [7; 32];
const MTIME_NS: i128 = 1_763_000_000_000_000_000;

/// Deterministic pseudo-random bytes (xorshift), so expected files need no RNG.
pub fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[derive(Default)]
struct Blobs(BTreeMap<Hash, Vec<u8>>);

impl Blobs {
    fn put(&mut self, b: Vec<u8>) -> Hash {
        let h = Hash::of(&b);
        self.0.insert(h, b);
        h
    }

    fn stripe(&mut self, s: &store_core::codec::EncodedStripe) -> Stripe {
        for sh in &s.shards {
            self.put(sh.clone());
        }
        s.stripe.clone()
    }
}

struct W<'a> {
    blobs: Blobs,
    expected: BTreeMap<String, Vec<u8>>,
    keys: &'a [EpochKeys],
}

fn entry(k: &EpochKeys, name: &str, kind: Kind, hash: Hash) -> DirEntry {
    DirEntry {
        name_enc: names::encrypt(&k.names, name, kind, &hash),
        kind,
        hash,
        extra: Vec::new(),
        id_enc: crypto::seal(&k.names, &[0u8; 16], b"store/dir-id/v1"),
    }
}

impl W<'_> {
    fn manifest(&mut self, epoch: u64, version: u8, name: &str, segs: Vec<(Stripe, crypto::Key, u32)>, range: Option<(u64, u64)>, prev: Option<Hash>) -> Hash {
        let k = &self.keys[epoch as usize];
        let meta = FileMeta {
            name: name.into(),
            mtime_ns: MTIME_NS,
            segment_keys: segs.iter().map(|s| s.1.clone()).collect(),
            segment_lens: segs.iter().map(|s| s.2).collect(),
            range,
        };
        let m: FileManifest = build_manifest(epoch, &k.meta, &meta, segs.into_iter().map(|s| s.0).collect(), prev);
        self.blobs.put(to_blob_at(&m, version))
    }

    /// Plain file cut into segments of `seg` bytes (the client cuts by content; any cut is valid).
    fn file(&mut self, epoch: u64, path: &str, data: &[u8], seg: usize, prev: Option<Hash>) -> Hash {
        let k = &self.keys[epoch as usize];
        let mut segs = Vec::new();
        for part in data.chunks(seg.max(1)) {
            let e = encode_segment(part, 8, 6, Code::Rs, &k.segment).unwrap();
            let st = self.blobs.stripe(&e.encoded);
            segs.push((st, e.key, e.plain_len as u32));
        }
        self.expected.insert(path.into(), data.to_vec());
        let name = path.rsplit('/').next().unwrap();
        self.manifest(epoch, 6, name, segs, None, prev)
    }

    fn dir(&mut self, epoch: u64, entries: Vec<(&str, Kind, Hash)>) -> Hash {
        let k = &self.keys[epoch as usize];
        let d = Dir::new(epoch, entries.into_iter().map(|(n, kind, h)| entry(k, n, kind, h)).collect());
        self.blobs.put(to_blob_at(&d, if epoch == 0 { 5 } else { 6 }))
    }
}

fn secrets(seed: u8, n: usize) -> Vec<EpochSecret> {
    (0..n).map(|i| EpochSecret([seed + i as u8; 32])).collect()
}

fn links(user: &VerifyingKey, s: &[EpochSecret]) -> Vec<Vec<u8>> {
    (0..s.len() - 1).map(|k| keyring::link(user, k as u64, &s[k], &s[k + 1])).collect()
}

fn derive(s: &[EpochSecret]) -> Vec<EpochKeys> {
    s.iter().enumerate().map(|(i, s)| EpochKeys::derive(i as u64, s.clone())).collect()
}

pub fn space_id() -> VerifyingKey {
    SigningKey::from_bytes(&SPACE_SEED).verifying_key()
}

pub fn build(out: &Path) {
    let user_sk = SigningKey::from_bytes(&USER_SEED);
    let user = user_sk.verifying_key();
    let device = SigningKey::from_bytes(&DEVICE_SEED);
    let acc = secrets(40, 2);
    let acc_keys = derive(&acc);
    let mut w = W {
        blobs: Blobs::default(),
        expected: BTreeMap::new(),
        keys: &acc_keys,
    };

    // epoch 0: a folder nobody rewrote since
    let legacy = w.file(0, "account/old/legacy.txt", "written before the key rotation\n".as_bytes(), 1 << 20, None);
    let old = w.dir(0, vec![("legacy.txt", Kind::File, legacy)]);

    // epoch 1
    let hello = w.file(1, "account/hello.txt", b"Hello, folder.host\n", 1 << 20, None);
    let empty = w.file(1, "account/empty.bin", b"", 1 << 20, None);
    let report_data = bytes(1, 300_000);
    let report = w.file(1, "account/Документы/отчёт.pdf", &report_data, 128 * 1024, None);
    let v1 = w.file(1, "account/versions.txt", b"version 1\n", 1 << 20, None);
    let v2 = w.file(1, "account/versions.txt", b"version 2\n", 1 << 20, Some(v1));
    let v3 = w.file(1, "account/versions.txt", b"version 3, current\n", 1 << 20, Some(v2));
    let trashed = w.file(1, "account/.trash/deleted.txt", b"in the trash\n", 1 << 20, None);

    // format 6 pack: each file its own key, ciphertexts concatenated
    let k1 = &acc_keys[1];
    let pieces: Vec<(&str, Vec<u8>)> = vec![("a.txt", b"alpha\n".to_vec()), ("b.bin", bytes(2, 5000)), ("c.txt", b"gamma\n".to_vec())];
    let refs: Vec<&[u8]> = pieces.iter().map(|p| p.1.as_slice()).collect();
    let (enc, packed) = encode_pack(&refs, 8, 6, Code::Rs, &k1.segment).unwrap();
    let st = w.blobs.stripe(&enc);
    let mut pack6 = Vec::new();
    for ((name, data), pf) in pieces.iter().zip(&packed) {
        w.expected.insert(format!("account/pack6/{name}"), data.clone());
        let h = w.manifest(1, 6, name, vec![(st.clone(), pf.key.clone(), pf.plain_len as u32)], Some(pf.range()), None);
        pack6.push((*name, Kind::File, h));
    }
    let pack6 = w.dir(1, pack6);

    // format 5 pack: one segment, one key, files are slices of the plaintext
    let slices: Vec<(&str, &[u8])> = vec![("x.txt", b"slice x\n"), ("y.txt", b"slice y, longer\n")];
    let refs: Vec<&[u8]> = slices.iter().map(|p| p.1).collect();
    let (plain, ranges) = pack_segment(&refs);
    let e = encode_segment(&plain, 8, 6, Code::Rs, &k1.segment).unwrap();
    let st = w.blobs.stripe(&e.encoded);
    let mut pack5 = Vec::new();
    for ((name, data), r) in slices.iter().zip(&ranges) {
        w.expected.insert(format!("account/pack5/{name}"), data.to_vec());
        let h = w.manifest(1, 5, name, vec![(st.clone(), e.key.clone(), e.plain_len as u32)], Some(*r), None);
        pack5.push((*name, Kind::File, h));
    }
    let pack5 = w.dir(1, pack5);

    let docs = w.dir(1, vec![("отчёт.pdf", Kind::File, report)]);
    let trash = w.dir(1, vec![("deleted.txt", Kind::File, trashed)]);
    let root_dir = w.dir(
        1,
        vec![
            ("hello.txt", Kind::File, hello),
            ("empty.bin", Kind::File, empty),
            ("versions.txt", Kind::File, v3),
            ("Документы", Kind::Dir, docs),
            ("old", Kind::Dir, old),
            ("pack6", Kind::Dir, pack6),
            ("pack5", Kind::Dir, pack5),
            (".trash", Kind::Dir, trash),
        ],
    );
    let root = Root::sign(&device, user, root_dir, 42, 1);

    // family space, wrapped to the account's receive key of epoch 1
    let sid = space_id();
    let sp = secrets(90, 1);
    let sp_keys = derive(&sp);
    let mut sw = W {
        blobs: std::mem::take(&mut w.blobs),
        expected: std::mem::take(&mut w.expected),
        keys: &sp_keys,
    };
    let sid_hex: String = sid.as_bytes()[..8].iter().map(|b| format!("{b:02x}")).collect();
    let cat = sw.file(0, &format!("space-{sid_hex}/Фото/cat.jpg"), &bytes(3, 20_000), 1 << 20, None);
    let photos = sw.dir(0, vec![("cat.jpg", Kind::File, cat)]);
    let sroot_dir = sw.dir(0, vec![("Фото", Kind::Dir, photos)]);
    let sroot = Root::sign(&device, sid, sroot_dir, 3, 0);
    let mut blobs = sw.blobs;
    let expected = sw.expected;

    // damage: the report's first stripe loses data shards 0–3 and parity 8–9, keeping exactly
    // k = 8 (data 4–7, parity 10–13);
    // the 5000-byte pack piece's stripe gets one corrupt data shard
    let report_m: FileManifest = store_core::format::from_blob(&blobs.0[&report]).unwrap();
    for i in [0usize, 1, 2, 3, 8, 9] {
        blobs.0.remove(&report_m.stripes[0].shards[i]);
    }
    let pack_shard = enc.stripe.shards[1];
    blobs.0.get_mut(&pack_shard).unwrap()[0] ^= 0xff;

    let (auth, eblob) = escrow::seal(&MASTER, PASSWORD, &user, &Argon::FAST);
    let state = ExitState {
        user,
        created_ms: 1_763_000_000_000,
        root: Some(root),
        keyring: AccountKeyring {
            epoch: 1,
            escrow_wrap: Some(keyring::wrap(&user, 1, &keyring::escrow_public(&MASTER), &acc[1]).unwrap()),
            device_wraps: vec![(
                device.verifying_key().to_bytes(),
                keyring::wrap(&user, 1, &crypto::device_x25519_public(&device.verifying_key()), &acc[1]).unwrap(),
            )],
            links: links(&user, &acc),
        },
        escrow: Some(Escrow {
            argon: Argon::FAST,
            auth,
            blob: eblob,
        }),
        spaces: vec![SpaceState {
            id: sid,
            root: Some(sroot),
            epoch: 0,
            recv_epoch: 1,
            wrap: keyring::wrap(&sid, 0, &keyring::recv_public(&acc[1]), &sp[0]).unwrap(),
            links: Vec::new(),
        }],
        nodes: vec![NodeHint {
            id: [3; 32],
            addrs: vec!["192.0.2.1:4433".into()],
        }],
    };

    let _ = fs::remove_dir_all(out);
    let bdir = out.join("export/blobs");
    fs::create_dir_all(&bdir).unwrap();
    fs::write(out.join("export/state.fhx"), state.to_bytes()).unwrap();
    for (h, b) in &blobs.0 {
        fs::write(bdir.join(h.to_string()), b).unwrap();
    }
    for (p, data) in &expected {
        let path = out.join("expected").join(p);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    fs::create_dir_all(out.join("unlock")).unwrap();
    fs::write(out.join("unlock/password.txt"), PASSWORD).unwrap();
    fs::write(out.join("unlock/device.key"), DEVICE_SEED).unwrap();
    let mut account = USER_SEED.to_vec();
    account.extend_from_slice(&MASTER);
    fs::write(out.join("unlock/account.key"), account).unwrap();
}
