//! Regenerates `vectors/`: `cargo run -p store-restore --example gen_vectors`.
//! Ciphertexts use random nonces and salts, so every run gives different blobs; the plain files
//! are the same. Commit the result only when the format changes.

#[path = "../tests/fixture/mod.rs"]
mod fixture;

fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    fixture::build(&dir);
    println!("wrote {}", dir.display());
}
