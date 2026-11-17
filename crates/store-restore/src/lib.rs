//! Restore a folder.host account from raw blobs, without the control plane or any network.
//!
//! Input is an export directory:
//!
//! ```text
//! <export>/state.fhx        exit state (store_core::exit::ExitState)
//! <export>/blobs/<hex>      blobs, file name = lowercase hex BLAKE3 of the blob bytes
//! ```
//!
//! Every blob is verified against its address before use; shards are verified by the stripe,
//! missing or corrupt shards are rebuilt from any k good ones. The format is described in
//! `SPEC.md` next to this crate.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ed25519_dalek::VerifyingKey;
use store_core::exit::{ExitState, Keys};
use store_core::file::{decode_packed, decode_piece, decode_segment, open_meta};
use store_core::format::{Dir, FileManifest, FileMeta, Kind, PackLayout, Root, from_blob};
use store_core::keyring::EpochKeys;
use store_core::{Hash, names};

pub const STATE_FILE: &str = "state.fhx";
pub const BLOBS_DIR: &str = "blobs";

/// Where blobs come from.
pub trait BlobSource {
    /// Blob bytes by address; `None` if absent. Returned bytes need not be verified.
    fn get(&self, hash: &Hash) -> Option<Vec<u8>>;
}

/// `<dir>/<hex>` files.
pub struct DirSource(pub PathBuf);

impl BlobSource for DirSource {
    fn get(&self, hash: &Hash) -> Option<Vec<u8>> {
        fs::read(self.0.join(hash.to_string())).ok()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Also write previous versions of each file to `<out>/<tree>/.versions/<path>/<n>`
    /// (1 = the version before the current one).
    pub versions: bool,
    /// Skip the top-level `.trash` folder.
    pub skip_trash: bool,
}

#[derive(Debug, Default)]
pub struct Report {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub versions: u64,
    /// Stripes that were missing data shards and were rebuilt from parity.
    pub rebuilt_stripes: u64,
    /// `(path, error)` for everything that could not be restored.
    pub failed: Vec<(String, String)>,
}

impl Report {
    fn fail(&mut self, path: &str, e: impl std::fmt::Display) {
        self.failed.push((path.to_string(), e.to_string()));
    }
}

/// A blob, checked against its address.
fn verified<S: BlobSource + ?Sized>(src: &S, hash: &Hash) -> Result<Vec<u8>, String> {
    let bytes = src.get(hash).ok_or_else(|| format!("blob {hash} missing"))?;
    let actual = Hash::of(&bytes);
    if &actual != hash {
        return Err(format!("blob {hash} corrupt (hash {actual})"));
    }
    Ok(bytes)
}

fn epoch_of(epochs: &[EpochKeys], epoch: u64) -> Result<&EpochKeys, String> {
    epochs
        .get(epoch as usize)
        .ok_or_else(|| format!("no keys for epoch {epoch}"))
}

/// A directory entry name is used as a path component only if it cannot escape.
fn safe_name(name: &str) -> Result<&str, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return Err(format!("unsafe name {name:?}"));
    }
    Ok(name)
}

/// One tree (the account or a space) with its epoch keys.
struct Tree<'a, S: BlobSource + ?Sized> {
    src: &'a S,
    epochs: &'a [EpochKeys],
    opts: &'a Options,
    /// Directories seen on the current path: a cycle would recurse forever.
    stack: HashSet<Hash>,
}

impl<S: BlobSource + ?Sized> Tree<'_, S> {
    fn dir(&mut self, hash: Hash, out: &Path, rel: &str, versions_root: &Path, report: &mut Report) {
        if !self.stack.insert(hash) {
            report.fail(rel, "directory cycle");
            return;
        }
        if let Err(e) = self.dir_inner(hash, out, rel, versions_root, report) {
            report.fail(rel, e);
        }
        self.stack.remove(&hash);
    }

    fn dir_inner(&mut self, hash: Hash, out: &Path, rel: &str, versions_root: &Path, report: &mut Report) -> Result<(), String> {
        let dir: Dir = from_blob(&verified(self.src, &hash)?).map_err(|e| format!("directory {hash}: {e}"))?;
        let keys = epoch_of(self.epochs, dir.epoch)?;
        fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
        report.dirs += 1;
        for entry in &dir.entries {
            let name = match names::decrypt(&keys.names, entry) {
                Ok(n) => n,
                Err(e) => {
                    report.fail(&format!("{rel}/<entry {}>", entry.hash), format!("name: {e}"));
                    continue;
                }
            };
            let path = format!("{rel}/{name}");
            let name = match safe_name(&name) {
                Ok(n) => n,
                Err(e) => {
                    report.fail(&path, e);
                    continue;
                }
            };
            if rel.is_empty() && name == ".trash" && self.opts.skip_trash {
                continue;
            }
            match entry.kind {
                Kind::Dir => self.dir(entry.hash, &out.join(name), &path, versions_root, report),
                Kind::File => self.file(entry.hash, &out.join(name), &path, versions_root, report),
            }
        }
        Ok(())
    }

    fn file(&mut self, hash: Hash, out: &Path, rel: &str, versions_root: &Path, report: &mut Report) {
        let prev = match self.write_version(hash, out, report) {
            Ok((prev, size)) => {
                report.files += 1;
                report.bytes += size;
                prev
            }
            Err(e) => {
                report.fail(rel, e);
                return;
            }
        };
        if !self.opts.versions {
            return;
        }
        let mut next = prev;
        let mut n = 0u64;
        let mut seen = HashSet::from([hash]);
        while let Some(h) = next {
            if !seen.insert(h) {
                report.fail(rel, "version cycle");
                break;
            }
            n += 1;
            let path = versions_root.join(rel.trim_start_matches('/')).join(n.to_string());
            if let Some(parent) = path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                report.fail(rel, e);
                break;
            }
            match self.write_version(h, &path, report) {
                Ok((p, _)) => {
                    report.versions += 1;
                    next = p;
                }
                Err(e) => {
                    // a pruned older version is normal: the chain ends where blobs end
                    report.fail(&format!("{rel} (version {n})"), e);
                    break;
                }
            }
        }
    }

    /// Writes one version; returns its `prev` and size.
    fn write_version(&self, hash: Hash, out: &Path, report: &mut Report) -> Result<(Option<Hash>, u64), String> {
        let manifest: FileManifest = from_blob(&verified(self.src, &hash)?).map_err(|e| format!("manifest {hash}: {e}"))?;
        let keys = epoch_of(self.epochs, manifest.epoch)?;
        let meta = open_meta(&keys.meta, &manifest).map_err(|e| format!("metadata: {e}"))?;
        let tmp = out.with_extension("fh-partial");
        let res = self.write_body(&manifest, &meta, &tmp, report);
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        fs::rename(&tmp, out).map_err(|e| format!("{}: {e}", out.display()))?;
        if let Some(t) = mtime(meta.mtime_ns)
            && let Ok(f) = fs::File::options().write(true).open(out)
        {
            let _ = f.set_modified(t);
        }
        Ok((manifest.prev, meta.size()))
    }

    fn write_body(&self, manifest: &FileManifest, meta: &FileMeta, path: &Path, report: &mut Report) -> Result<(), String> {
        if meta.segment_keys.len() != manifest.stripes.len() || meta.segment_lens.len() != manifest.stripes.len() {
            return Err("metadata does not match stripes".into());
        }
        let mut f = fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let layout = meta.layout();
        for (i, stripe) in manifest.stripes.iter().enumerate() {
            let shards: Vec<Option<Vec<u8>>> = stripe.shards.iter().map(|h| self.src.get(h)).collect();
            let data_ok = stripe.shards[..stripe.k as usize]
                .iter()
                .zip(&shards)
                .all(|(h, s)| s.as_deref().is_some_and(|s| Hash::of(s) == *h));
            let key = &meta.segment_keys[i];
            let plain_len = meta.segment_lens[i] as usize;
            let bytes = match layout {
                PackLayout::Segments => decode_segment(stripe, key, &shards, plain_len),
                PackLayout::Slice { offset, len } => decode_packed(stripe, key, &shards, (offset, len), plain_len),
                PackLayout::Piece { ct_offset, len } => decode_piece(stripe, key, &shards, ct_offset, len as usize),
            }
            .map_err(|e| format!("stripe {}: {e}", stripe.stripe_id))?;
            if !data_ok {
                report.rebuilt_stripes += 1;
            }
            f.write_all(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        f.sync_all().map_err(|e| format!("{}: {e}", path.display()))
    }
}

fn mtime(ns: i128) -> Option<SystemTime> {
    let ns = u64::try_from(ns).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_nanos(ns))
}

/// Restores the tree under `root` into `out`. `owner` is the account or space the root must
/// belong to; the signature is checked, membership of the signer is not (that is what the
/// control plane vouched for).
pub fn restore_tree<S: BlobSource + ?Sized>(
    src: &S,
    owner: &VerifyingKey,
    root: &Root,
    epochs: &[EpochKeys],
    out: &Path,
    opts: &Options,
    report: &mut Report,
) {
    if &root.user != owner {
        report.fail("/", "root belongs to another account");
        return;
    }
    if let Err(e) = root.verify() {
        report.fail("/", e);
        return;
    }
    let mut tree = Tree {
        src,
        epochs,
        opts,
        stack: HashSet::new(),
    };
    tree.dir(root.dir, out, "", &out.join(".versions"), report);
}

fn short(id: &VerifyingKey) -> String {
    id.as_bytes()[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Restores the account into `<out>/account` and each space into `<out>/space-<id>`.
pub fn restore_all<S: BlobSource + ?Sized>(state: &ExitState, keys: &Keys, src: &S, out: &Path, opts: &Options) -> Report {
    let mut report = Report::default();
    match &state.root {
        Some(root) => restore_tree(src, &state.user, root, &keys.account, &out.join("account"), opts, &mut report),
        None => {
            let _ = fs::create_dir_all(out.join("account"));
        }
    }
    for sp in &state.spaces {
        let Some(root) = &sp.root else { continue };
        let dir = out.join(format!("space-{}", short(&sp.id)));
        match keys.spaces.iter().find(|(id, _)| id == &sp.id) {
            Some((_, epochs)) => restore_tree(src, &sp.id, root, epochs, &dir, opts, &mut report),
            None => report.fail(&dir.display().to_string(), "space keys could not be unwrapped"),
        }
    }
    report
}
