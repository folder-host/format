//! Restore tests: a fresh account built by `fixture`, and the committed vectors in `vectors/`.

mod fixture;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use store_core::exit::{ExitState, Unlock};
use store_restore::{BLOBS_DIR, DirSource, Options, Report, STATE_FILE, restore_all};

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            if rel.contains(".versions") {
                continue;
            }
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.insert(rel, fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn restore(dir: &Path, unlock: Unlock, opts: &Options, out: &Path) -> Report {
    let state = ExitState::from_bytes(&fs::read(dir.join("export").join(STATE_FILE)).unwrap()).unwrap();
    let keys = state.unlock(unlock).unwrap();
    restore_all(&state, &keys, &DirSource(dir.join("export").join(BLOBS_DIR)), out, opts)
}

fn check(dir: &Path) {
    let device = SigningKey::from_bytes(&fs::read(dir.join("unlock/device.key")).unwrap().try_into().unwrap());
    let password = fs::read_to_string(dir.join("unlock/password.txt")).unwrap();
    let master: [u8; 32] = fs::read(dir.join("unlock/account.key")).unwrap()[32..64].try_into().unwrap();
    let expected = tree(&dir.join("expected"));
    assert!(expected.len() == 12, "{:?}", expected.keys());
    for unlock in [Unlock::Password(&password), Unlock::Device(&device), Unlock::Master(master)] {
        let out = tempfile::tempdir().unwrap();
        let r = restore(dir, unlock, &Options::default(), out.path());
        assert!(r.failed.is_empty(), "{:?}", r.failed);
        // the report's stripe is short of 4 data shards, the pack stripe has a corrupt one (3 files)
        assert_eq!(r.rebuilt_stripes, 4);
        assert_eq!(tree(out.path()), expected);
    }
}

#[test]
fn fresh_account_restores_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    fixture::build(dir.path());
    check(dir.path());
}

#[test]
fn committed_vectors_restore() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    assert!(dir.join("export").join(STATE_FILE).exists(), "run `cargo run -p store-restore --example gen_vectors`");
    check(&dir);
}

#[test]
fn versions_and_trash_options() {
    let dir = tempfile::tempdir().unwrap();
    fixture::build(dir.path());
    let out = tempfile::tempdir().unwrap();
    let opts = Options {
        versions: true,
        skip_trash: true,
    };
    let r = restore(dir.path(), Unlock::Password(fixture::PASSWORD), &opts, out.path());
    assert!(r.failed.is_empty(), "{:?}", r.failed);
    assert_eq!(r.versions, 2);
    let v = out.path().join("account/.versions/versions.txt");
    assert_eq!(fs::read(v.join("1")).unwrap(), b"version 2\n");
    assert_eq!(fs::read(v.join("2")).unwrap(), b"version 1\n");
    assert!(!out.path().join("account/.trash").exists());
}

/// One shard fewer than k: that file fails, everything else is restored.
#[test]
fn below_k_fails_only_that_file() {
    let dir = tempfile::tempdir().unwrap();
    fixture::build(dir.path());
    let blobs = dir.path().join("export").join(BLOBS_DIR);
    let state = ExitState::from_bytes(&fs::read(dir.path().join("export").join(STATE_FILE)).unwrap()).unwrap();
    let keys = state.unlock(Unlock::Password(fixture::PASSWORD)).unwrap();
    // find the report: the only file with a stripe already down to k shards
    let src = DirSource(blobs.clone());
    let mut removed = false;
    for e in fs::read_dir(&blobs).unwrap() {
        let p = e.unwrap().path();
        let b = fs::read(&p).unwrap();
        let Ok(m) = store_core::format::from_blob::<store_core::format::FileManifest>(&b) else { continue };
        let Some(st) = m.stripes.first() else { continue };
        let have: Vec<_> = st.shards.iter().filter(|h| store_restore::BlobSource::get(&src, h).is_some()).collect();
        if have.len() == st.k as usize {
            fs::remove_file(blobs.join(have[0].to_string())).unwrap();
            removed = true;
            break;
        }
    }
    assert!(removed);
    let out = tempfile::tempdir().unwrap();
    let r = restore_all(&state, &keys, &src, out.path(), &Options::default());
    assert_eq!(r.failed.len(), 1, "{:?}", r.failed);
    assert!(r.failed[0].0.ends_with("отчёт.pdf"));
    assert!(!out.path().join("account/Документы/отчёт.pdf").exists());
    assert_eq!(fs::read(out.path().join("account/hello.txt")).unwrap(), b"Hello, folder.host\n");
}

#[test]
fn wrong_password_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    fixture::build(dir.path());
    let state = ExitState::from_bytes(&fs::read(dir.path().join("export").join(STATE_FILE)).unwrap()).unwrap();
    assert!(state.unlock(Unlock::Password("wrong")).is_err());
}
