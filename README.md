# folder.host data format

This repository holds everything needed to read folder.host data without folder.host:

- [`SPEC.md`](crates/store-restore/SPEC.md) — the format: blobs, keys, encryption, erasure coding,
  directory and file manifests, the exit state, and the restore algorithm.
- [`store-core`](crates/store-core) — the reference implementation used by the folder.host
  client and storage nodes (same source, mirrored from the main repository).
- [`fh-restore`](crates/store-restore) — an offline restorer. It takes an export directory and
  your password (or a device key) and writes your files back. No network, no folder.host servers.
- [`vectors/`](crates/store-restore/vectors) — test vectors: an export, the files it must
  restore to, and the unlock material. CI restores them on every commit.

## Restoring

Export from a device that is signed in (works while storage nodes are reachable, even if the
folder.host control plane is not):

```sh
store export ~/folderhost-export
```

Then, anywhere:

```sh
cargo install --path crates/store-restore
fh-restore ~/folderhost-export ~/restored            # asks for the account password
fh-restore ~/folderhost-export ~/restored --device-key device.key
```

`~/restored/account/` is your tree, `~/restored/space-<id>/` are shared family spaces.
`--versions` also restores older versions, `--skip-trash` leaves out the trash.

The export's `state.fhx` contains the master key sealed under your password (Argon2id). Keep it
as private as the password.

## Writing your own decoder

Follow `SPEC.md` and check it against `vectors/`. Every stripe is Reed-Solomon 8+6
(`reed-solomon-simd` 3, GF(2^16), Leopard construction). If all 8 data shards of a stripe are intact,
no erasure decoding is needed.

Code comments are in Russian (the project's working language); the spec is in English.

## License

MIT OR Apache-2.0.
