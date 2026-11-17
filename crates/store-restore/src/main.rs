//! `fh-restore <export-dir> <out-dir>`: restore files from a folder.host export, offline.

use std::io::BufRead;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use ed25519_dalek::SigningKey;
use store_core::exit::{ExitState, Unlock};
use store_restore::{BLOBS_DIR, DirSource, Options, STATE_FILE, restore_all};

/// Restore a folder.host account from an export directory (`state.fhx` + `blobs/`), without
/// the network. Unlock with the account password (default), the account file, or a device key.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Export directory: `state.fhx` and `blobs/`.
    export: PathBuf,
    /// Where to write files: `account/` and `space-<id>/` inside.
    out: PathBuf,
    /// Read the password from this file (first line) instead of stdin / FH_PASSWORD.
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// Account file (`user(32) ‖ master(32) …`) instead of the password.
    #[arg(long, conflicts_with = "password_file")]
    account_file: Option<PathBuf>,
    /// Device key file (32 bytes) of an active device instead of the password.
    #[arg(long, conflicts_with_all = ["password_file", "account_file"])]
    device_key: Option<PathBuf>,
    /// Also restore previous versions into `.versions/`.
    #[arg(long)]
    versions: bool,
    /// Do not restore the `.trash` folder.
    #[arg(long)]
    skip_trash: bool,
}

fn read_32(path: &PathBuf, at: usize) -> anyhow::Result<[u8; 32]> {
    let b = std::fs::read(path).with_context(|| path.display().to_string())?;
    b.get(at..at + 32)
        .and_then(|s| s.try_into().ok())
        .with_context(|| format!("{}: too short", path.display()))
}

fn password(cli: &Cli) -> anyhow::Result<String> {
    if let Some(p) = &cli.password_file {
        let s = std::fs::read_to_string(p).with_context(|| p.display().to_string())?;
        return Ok(s.lines().next().unwrap_or("").to_string());
    }
    if let Ok(p) = std::env::var("FH_PASSWORD") {
        return Ok(p);
    }
    eprint!("password: ");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let state_path = cli.export.join(STATE_FILE);
    let bytes = std::fs::read(&state_path).with_context(|| state_path.display().to_string())?;
    let state = ExitState::from_bytes(&bytes).context("state.fhx")?;
    let device;
    let pass;
    let unlock = if let Some(p) = &cli.device_key {
        device = SigningKey::from_bytes(&read_32(p, 0)?);
        Unlock::Device(&device)
    } else if let Some(p) = &cli.account_file {
        Unlock::Master(read_32(p, 32)?)
    } else {
        if state.escrow.is_none() {
            bail!("this export has no password escrow: use --account-file or --device-key");
        }
        pass = password(&cli)?;
        Unlock::Password(&pass)
    };
    let keys = state.unlock(unlock).context("unlock")?;
    let opts = Options {
        versions: cli.versions,
        skip_trash: cli.skip_trash,
    };
    let src = DirSource(cli.export.join(BLOBS_DIR));
    let r = restore_all(&state, &keys, &src, &cli.out, &opts);
    for (path, e) in &r.failed {
        eprintln!("FAILED {path}: {e}");
    }
    println!(
        "restored {} files ({} bytes), {} folders, {} older versions; {} stripes rebuilt from parity; {} failed",
        r.files,
        r.bytes,
        r.dirs,
        r.versions,
        r.rebuilt_stripes,
        r.failed.len()
    );
    if !r.failed.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
