# folder.host data format — restore specification

Status: describes blob format versions 5 and 6 (`FORMAT_MIN = 5`, `FORMAT_VERSION = 6`) as
implemented in `store-core` (format.rs, file.rs, crypto.rs, codec.rs, chunk.rs, keyring.rs,
hash.rs, names.rs, escrow.rs) and the client (`store-client`). The Rust code is normative; where
this document and the code disagree, the code wins and this document is a bug.

Goal: an independent implementer, given raw blobs (directory/manifest blobs and shard blobs), the
account's keyring, a root, and either the account password (escrow) or a device key, can decrypt
and restore every file, every retained version, and the trash.

Notation:

- `‖` — byte concatenation. `x_le` — little-endian fixed-width encoding (`u64_le` = 8 bytes).
- `BLAKE3(x)` — BLAKE3-256 hash.
- `BLAKE3_keyed(k, x)` — BLAKE3 keyed hash mode, 32-byte key.
- `derive_key(ctx, x)` — BLAKE3 KDF mode (`blake3::derive_key`), `ctx` an ASCII context string,
  32-byte output.
- `AEAD` — XChaCha20-Poly1305 (24-byte nonce, 16-byte tag, RFC 8439 ChaCha20-Poly1305 with
  HChaCha20 extension). `AEAD_enc(k, n, m, aad)` returns `ct ‖ tag` (`len(m) + 16` bytes).
- `X25519(s, P)` — RFC 7748 (scalar clamped before multiplication).
- All strings in this document shown as `"store/..."` are ASCII bytes without terminator.

Reference crate versions (Cargo.lock): blake3 1.8.7, chacha20poly1305 0.10.1,
curve25519-dalek 4.1.3, ed25519-dalek 2.2.0 (ed25519 2.2.3), postcard 1.1.3,
reed-solomon-simd 3.1.0, argon2 0.5.3, fastcdc 5.0.0, iroh-base 1.4.1.

---

## 1. Overview and object graph

```text
Root (mutable, signed, held by control plane Raft; one per account and one per space)
 └─ dir: Hash ──► Dir blob (epoch, entries sorted by name_enc)
                   ├─ DirEntry{kind: Dir,  hash} ──► Dir blob ...
                   └─ DirEntry{kind: File, hash} ──► FileManifest blob
                                                      ├─ meta: salt ‖ seal(fk, FileMeta)
                                                      ├─ stripes[i]: Stripe{stripe_id, k, m, shard_len, shards[k+m]}
                                                      │                └─ shards[j]: Hash ──► shard blob (raw bytes)
                                                      └─ prev: Option<Hash> ──► previous version FileManifest
```

- **Content addressing.** Every immutable object is addressed by `BLAKE3` of its complete stored
  bytes. For Dir and FileManifest that is the full blob *including* the leading version byte; for
  shards it is the raw shard bytes. Addresses are BLAKE3-256 as used by iroh-blobs (transfer is
  bao-verified). A reader MUST verify `BLAKE3(bytes) == reference` before parsing.
- **Do not recompute addresses from parsed values.** The same value re-encoded with a different
  version byte has a different address. The address of a blob is always taken from the reference
  that points to it.
- **Blob envelope** (Dir, FileManifest, and Root/Stripe where serialized as blobs):

  | Offset | Size | Field |
  | --- | --- | --- |
  | 0 | 1 | `version` (u8) |
  | 1 | rest | `postcard(value)` |

  Readers accept `FORMAT_MIN ..= FORMAT_VERSION` = `5 ..= 6`; anything else is
  `UnsupportedVersion`. Empty blob is an error.
- **What changed in 6.** Nothing in any blob's byte layout: postcard bodies of versions 5 and 6
  are identical for all types. Version 6 introduced *piece-packed* small files
  (`PackLayout::Piece`, §5.4). The version was bumped only so that writers emit pieces only after
  every reader supports them. **The layout of a packed file is determined from `FileMeta` alone
  (§5.4), never from the manifest's version byte** — a manifest re-emitted in version 6 may carry
  an old version-5 `Slice` FileMeta unchanged.
- **Trailing bytes.** Writers never emit bytes after the postcard value, and readers reject a
  blob that has any (`Error::TrailingBytes`): one value has exactly one encoding and address.
- **Root** is not stored on storage nodes; it is the single mutable object, kept by the control
  plane and updated by CAS on `version`. For restore it comes from outside (exit state, §11).

### 1.1 postcard encoding rules (postcard 1.x, serde)

| Rust type | Encoding |
| --- | --- |
| `u8` | 1 raw byte |
| `u16`, `u32`, `u64`, `usize` | unsigned LEB128 varint (7 bits per byte, low group first, MSB = continuation). Max 3/5/10/10 bytes. Writers emit minimal form; the decoder accepts overlong forms within the max length. |
| `i128` | zigzag (`(n << 1) ^ (n >> 127)`) then LEB128 varint of the `u128` (max 19 bytes) |
| `bool` | 1 byte, `0x00` false / `0x01` true; other values are errors |
| `[u8; N]`, tuples `(A, B)` | concatenation of elements, **no length prefix** |
| newtype struct (`Hash([u8;32])`, `Key([u8;32])`, `EpochSecret`) | encoded as the inner value (32 raw bytes) |
| struct | fields in declaration order, no names, no prefix |
| `Vec<T>`, `&[T]` | varint element count, then elements |
| `Vec<u8>` | varint byte length, then bytes |
| `String` | varint byte length, then UTF-8 bytes |
| `Option<T>` | `0x00` = None; `0x01` then `T` = Some |
| enum | varint variant index (declaration order, from 0), then variant payload |
| `ed25519_dalek::VerifyingKey` | `serialize_bytes`: varint length `0x20` then 32 bytes (**33 bytes total**). Decoder requires 32 bytes and a valid compressed Edwards point. |
| `ed25519_dalek::Signature` | `serialize_tuple(64)` of `u8`: **64 raw bytes, no prefix** |
| `iroh::EndpointId` (= `NodeId`, iroh-base `PublicKey`) | non-human-readable: `[u8;32]` → **32 raw bytes, no prefix** |

Enum tags used here: `Kind { File = 0, Dir = 1 }`, `Code { Rs = 0, Clay = 1 }`.

---

## 2. Data structures (postcard bodies)

### 2.1 `Root`

| Field | Type | Encoded size |
| --- | --- | --- |
| `user` | VerifyingKey — account id, or space id for a space tree | 33 |
| `dir` | Hash of the root Dir blob | 32 |
| `version` | u64 | varint |
| `epoch` | u64 — key epoch the root dir was written in | varint |
| `release` | bool — commit permanently deleted data | 1 |
| `signer` | VerifyingKey — device (iroh endpoint ed25519 key) | 33 |
| `sig` | Signature | 64 |

Signature: Ed25519 (RFC 8032) by `signer` over

```text
"store/root/v3" ‖ user(32) ‖ signer(32) ‖ dir(32) ‖ version_u64_le ‖ epoch_u64_le ‖ release(1 byte: 0|1)
```

A restorer SHOULD verify the signature. That `signer` is an active device of `user` can only be
checked by the control plane and cannot be verified offline.

### 2.2 `Dir`

| Field | Type |
| --- | --- |
| `epoch` | u64 — epoch whose **names key** encrypts all `name_enc`, `extra`, `id_enc` of this Dir |
| `entries` | Vec<DirEntry>, strictly ascending by `name_enc` (bytewise lexicographic) |

`DirEntry`:

| Field | Type | Meaning |
| --- | --- | --- |
| `name_enc` | Vec<u8> | encrypted name (§4.1) |
| `kind` | enum Kind | 0 File, 1 Dir |
| `hash` | Hash | File → FileManifest blob address; Dir → Dir blob address |
| `extra` | Vec<u8> | encrypted app attributes, empty = none (§4.2) |
| `id_enc` | Vec<u8> | encrypted stable 16-byte item id (§4.3) |

A Dir may have an epoch older than its parent's; untouched dirs stay in their epoch, a dir
rewritten in a newer epoch is re-encrypted entirely.

### 2.3 `FileManifest`

| Field | Type | Meaning |
| --- | --- | --- |
| `epoch` | u64 | epoch whose **meta key** derives the file key `fk` |
| `meta` | Vec<u8> | `salt(16) ‖ seal(fk, postcard(FileMeta), aad)` (§5.1) |
| `stripes` | Vec<Stripe> | one per segment (packed file: exactly one) |
| `prev` | Option<Hash> | previous version's FileManifest |

### 2.4 `Stripe`

| Field | Type | Meaning |
| --- | --- | --- |
| `stripe_id` | Hash | `BLAKE3(stripe ciphertext)` (the ciphertext before length prefix/padding, §7) |
| `k` | u8 | data shards |
| `m` | u8 | parity shards |
| `shard_len` | u32 (varint) | bytes per shard |
| `shards` | Vec<Hash> | `k+m` shard addresses; index 0..k data, k..k+m parity |
| `code` | enum Code | 0 = Rs (production), 1 = Clay (experimental MSR code, not used in production; out of scope) |

`Stripe::key()` (not needed for restore; node tag name / quota key): `BLAKE3(0x05 ‖ postcard(Stripe))`
— always with version byte 5 (`STRIPE_KEY_FORMAT`), independent of the current format.

### 2.5 `FileMeta` (plaintext, only ever stored encrypted)

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | String | file name at write time (informational; the directory name is authoritative) |
| `mtime_ns` | i128 | Unix mtime, nanoseconds |
| `segment_keys` | Vec<Key> | 32-byte key per stripe, parallel to `stripes` |
| `segment_lens` | Vec<u32> | plaintext length per segment, parallel to `stripes` |
| `range` | Option<(u64, u64)> | `None` for normal files; packed files `Some((offset, len))`, meaning per §5.4 |

### 2.6 Control-plane records (store-proto)

`Keyring` (account):

| Field | Type | Meaning |
| --- | --- | --- |
| `epoch` | u64 | current epoch `n` |
| `wraps` | Vec<(NodeId, Vec<u8>)> | `wrap(E_n)` for each active device (NodeId = 32 raw bytes) |
| `escrow_pub` | [u8; 32] | X25519 escrow public key |
| `escrow_wrap` | Option<Vec<u8>> | `wrap(E_n)` for escrow; None only during account key rotation |
| `links` | Vec<Vec<u8>> | `links[k]` = `E_k` under a key from `E_{k+1}`; `links.len() == epoch` |

`EscrowRecord`: `auth: VerifyingKey` (33), `blob: Vec<u8>`, `version: u64`.

`SpaceKeyring`: `epoch: u64`, `wraps: Vec<SpaceWrap>`, `links: Vec<Vec<u8>>` (same chain rules,
with the space id as `user`).

`SpaceWrap`: `user: VerifyingKey` (member account), `recv_epoch: u64` (epoch of the member's
account whose recv key was used), `wrap: Vec<u8>`.

`RecvKey`: `user: VerifyingKey`, `epoch: u64`, `public: [u8;32]`, `sig: Signature` — Ed25519 by
the account key over `"store/recv-key/v1" ‖ user ‖ epoch_u64_le ‖ public`. Not needed for
restore (the member derives the recv secret itself).

Space id (`SpaceId`) is a 32-byte ed25519 public key of a random keypair (secret discarded); it
is used as `Root.user` of the space tree and as `user` in all space keyring AADs.

Limits: `MAX_EPOCHS = 1024`, `MAX_WRAP = 256` bytes per wrap/link.

---

## 3. Primitives

### 3.1 `seal` / `open` (symmetric)

```text
seal(key, pt, aad) = nonce(24, random) ‖ AEAD_enc(key, nonce, pt, aad)       // len = len(pt) + 40
open(key, c, aad): len(c) < 40 → error; nonce = c[0..24]; AEAD_dec(key, nonce, c[24..], aad)
```

### 3.2 `seal_to` / `open_to` (to an X25519 public key)

```text
seal_to(R, pt, aad):
  e      = random 32 bytes;  E = X25519(e, 9)                // mul_base_clamped
  shared = X25519(e, R);     shared == 0^32 → error
  K      = derive_key("store/seal-to/v1", E(32) ‖ R(32) ‖ shared(32))
  out    = E(32) ‖ seal(K, pt, aad)                           // len = len(pt) + 72

open_to(s, c, aad):
  len(c) < 72 → error
  E = c[0..32]; shared = X25519(s, E); shared == 0^32 → error
  R = X25519(s, 9)
  K = derive_key("store/seal-to/v1", E ‖ R ‖ shared)
  open(K, c[32..], aad)
```

### 3.3 Device X25519 key from ed25519

- Public: the device's ed25519 public key converted to Montgomery form
  (`VerifyingKey::to_montgomery`, u = (1+y)/(1−y)).
- Secret: `SigningKey::to_scalar_bytes` = first 32 bytes of `SHA-512(ed25519 seed)` *before*
  clamping (X25519 clamps it).

The device ed25519 key is the iroh `Endpoint` secret key (32-byte seed).

### 3.4 Other derivations (all BLAKE3)

| Name | Definition |
| --- | --- |
| account signing key | ed25519 seed = `derive_key("store/account/sign/v1", master)`; for the *first* master key its public key equals `user` |
| escrow X25519 secret | `derive_key("store/account/escrow-x25519/v1", master)`; `escrow_pub = X25519(secret, 9)` |
| recv X25519 secret of epoch | `derive_key("store/epoch/recv/v1", E)` |
| space inbox X25519 secret | `derive_key("store/space/inbox/v1", S)` (upload-only links; not needed for restore) |
| link key | `derive_key("store/epoch/link/v1", E_{k+1})` |
| segment root | `derive_key("store/epoch/segment/v1", E)` |
| meta key | `derive_key("store/epoch/meta/v1", E)` |
| names key | `derive_key("store/epoch/names/v1", E)` |
| file key `fk` | `BLAKE3_keyed(meta_key, "store/file-key/v1" ‖ salt)` (keyed hash, *not* derive_key) |
| segment key | `BLAKE3_keyed(segment_root, segment_plaintext)` |
| chunk nonce | `derive_key("store/segment-chunk-nonce/v1", segment_key(32) ‖ chunk_index_u64_le)[0..24]` |
| name id / nonce | `BLAKE3_keyed(names_key, utf8(name))[0..24]` |
| name MAC key | `derive_key("store/name-mac/v2", names_key)` |
| gear table | 2048 bytes of BLAKE3 XOF of `derive_key`-mode hasher, context `"store/chunk-gear/v1"`, input `segment_root` |
| escrow salt | `derive_key("store/escrow-salt/v1", user(32))` |

---

## 4. Key hierarchy

```text
password ──Argon2id(salt = derive_key("store/escrow-salt/v1", user))──► out[64]
   out[0..32]  = escrow encryption key  ──open(·, EscrowRecord.blob, "store/escrow/v1")──► master (32)
   out[32..64] = ed25519 seed of `auth` (must equal EscrowRecord.auth; else wrong password)

master ──derive_key("store/account/escrow-x25519/v1")──► escrow X25519 secret
   └─ unwrap(Keyring.escrow_wrap) ──► E_n
device ed25519 key ──to_scalar_bytes──► device X25519 secret
   └─ unwrap(Keyring.wraps[this device]) ──► E_n           (alternative to the password path)

E_n ──links[n-1]──► E_{n-1} ──links[n-2]──► … ──links[0]──► E_0
E_k ──► EpochKeys{segment, meta, names}  (+ recv secret for spaces)

Space: E_{recv_epoch} of member account ──recv secret──► unwrap(SpaceWrap.wrap) ──► S_n
       S_n ──space links──► S_0..S_n ──► EpochKeys of the space tree (same derivation)
```

### 4.1 Escrow (password → master key)

- Argon2id, version 0x13, no secret, no associated data, output length 64,
  `hash_password_into(password_utf8, salt, out)`.
- Parameters (`Argon`): default `m = 262144 KiB (256 MiB)`, `t = 3`, `p = 1`. These are part of
  the protocol; the parameters in use are carried alongside the escrow (exit state, §11).
- Salt: `derive_key("store/escrow-salt/v1", user_pubkey_32)` — 32 bytes.
- `EscrowRecord.blob = seal(out[0..32], master, "store/escrow/v1")` — 72 bytes.
- Check: `ed25519_public(seed = out[32..64]) == EscrowRecord.auth`, else wrong password. Then
  `open`; plaintext must be exactly 32 bytes.
- After account rotation the escrow holds the new master `M'`; `user` (salt input) never changes.

### 4.2 Keyring wrap and chain

```text
wrap_aad(user, epoch, R) = "store/keyring/v1/wrap" ‖ user(32) ‖ epoch_u64_le ‖ R(32)
wrap(user, epoch, R, E)  = seal_to(R, E(32), wrap_aad(user, epoch, R))              // 104 bytes
unwrap(user, epoch, s, w) = open_to(s, w, wrap_aad(user, epoch, X25519(s, 9)))      // must be 32 bytes

link_aad(user, k)        = "store/keyring/v1/link" ‖ user(32) ‖ k_u64_le
link_k                   = seal(derive_key("store/epoch/link/v1", E_{k+1}), E_k, link_aad(user, k))   // 72 bytes
```

`unchain(user, E_n, links)`: for `k = n-1 down to 0`: `E_k = open(derive_key("store/epoch/link/v1",
E_{k+1}), links[k], link_aad(user, k))`. Result indexed by epoch number.

Getting `E_n` (client `open_current`):

1. If `Keyring.wraps` has an entry for this device's NodeId: `unwrap(user, Keyring.epoch,
   device_x25519_secret, w)`.
2. Else for each known master (`master`, `next_master`): if `escrow_wrap` is Some and
   `escrow_pub == X25519(escrow_secret(master), 9)`: `unwrap(user, Keyring.epoch,
   escrow_secret(master), escrow_wrap)`.

`user` in every account AAD is the immutable account id (public key of the account key derived
from the first master key).

### 4.3 EpochKeys

```text
segment = derive_key("store/epoch/segment/v1", E)   // convergent segment-key root and gear-table key
meta    = derive_key("store/epoch/meta/v1",    E)   // derives fk for FileMeta
names   = derive_key("store/epoch/names/v1",   E)   // names, extra, id_enc
```

Every Dir and FileManifest carries its own `epoch`; read each with the keys of that epoch.
Segment keys are stored in FileMeta, so file content never needs the segment root on read.

### 4.4 Spaces (shared spaces, family)

A space is a separate tree: its own `Root` (with `Root.user = space id`) and its own
`SpaceKeyring`. To read it as member `U` (client `open_space_secret`):

```text
w       = SpaceKeyring.wraps.find(user == U)
A       = account epoch keys of U for epoch w.recv_epoch      // from U's own chain
recv_s  = derive_key("store/epoch/recv/v1", A.secret)
S_n     = unwrap(space_id, SpaceKeyring.epoch, recv_s, w.wrap)
S_0..S_n = unchain(space_id, S_n, SpaceKeyring.links)
EpochKeys(k, S_k) — same derivation as §4.3
```

All Dir/FileManifest blobs of a space tree use the space epoch keys.

---

## 5. Files

### 5.1 FileMeta sealing

```text
salt = manifest.meta[0..16]            (len < 16 → error)
fk   = BLAKE3_keyed(EpochKeys(manifest.epoch).meta, "store/file-key/v1" ‖ salt)
aad  = "store/file-meta/v2" ‖ manifest.epoch_u64_le ‖ salt
FileMeta = postcard_decode(open(fk, manifest.meta[16..], aad))
```

The salt is random per manifest (per version). Validation after decoding (`open_meta_fk`):

- `len(segment_keys) == len(stripes)` and `len(segment_lens) == len(stripes)`;
- `range.is_some()` ⇒ `len(stripes) == 1`;
- layout checks of §5.4.

Every manifest reachable from a tree is sealed with the meta key of `manifest.epoch` (inbox
uploads and share copies are re-sealed this way when placed into a tree).

### 5.2 Normal files

`range == None` → `PackLayout::Segments`. Content =
`concat_i decrypt_segment(segment_keys[i], stripe_ciphertext(stripes[i]), segment_lens[i])`.
File size = `Σ segment_lens`. An empty file has zero stripes and size 0.

### 5.3 Versions

`prev` points to the manifest of the version this one replaced (newest → oldest). The chain may
end at a `None` or at a manifest that no longer exists (versions are pruned by re-issuing
manifests with a shortened chain; inside `/.fh` overwrites never set `prev`). Each version is an
independent manifest with its own epoch, salt and fk.

### 5.4 Packed small files — `FileMeta::layout()` (exact rule)

Applies when `range = Some((a, len))`; then `len(stripes) == 1`.

```text
layout(meta):
  match (meta.range, meta.segment_lens.first()):
    (None, _)                                  → Segments
    (Some((ct_offset, len)), Some(l)) if l == len → Piece { ct_offset, len }
    (Some((offset, len)), _)                   → Slice { offset, len }
```

- **Piece** (format 6). Each file of the pack was encrypted on its own with its own convergent
  key (`segment_keys[0]`) via §6; the stripe ciphertext is the concatenation of the files'
  ciphertexts. `segment_lens[0] == len`. The file's ciphertext is
  `stripe_ct[ct_offset .. ct_offset + ciphertext_len(len)]`, decrypted with
  `decrypt_segment(segment_keys[0], piece, len)` (chunk indices restart at 0 and AAD length is
  `len`). Validation: `ct_offset + ciphertext_len(len) ≤ k · shard_len`. The key does not reveal
  neighbours.
- **Slice** (format 5). The whole pack is one segment encrypted with one key `segment_keys[0]`,
  plaintext length `segment_lens[0]`. File = `plain[offset .. offset + len]`. Validation:
  `offset + len ≤ segment_lens[0]`. The key reveals the whole pack.
- Ambiguity is harmless: a v5 slice with `offset == 0` covering the whole segment reads
  identically as a piece at `ct_offset = 0`.
- File size = `len` (`FileMeta::size()`).

Writers pack files below `pack_threshold` (1 MiB) into packs up to `pack_target` (8 MiB); with
write format ≥ 6 as pieces, otherwise as a slice.

---

## 6. Segment encryption

Constants: `SEGMENT_CHUNK = 65536`, tag 16, full chunk ciphertext `65552`,
`SEGMENT_AAD = "store/segment/v3"` (16 bytes).

### 6.1 Padmé padding

```text
padded_len(L):
  if L < 2: return L
  e    = floor(log2 L)
  s    = floor(log2 e) + 1
  mask = 2^(e - s) - 1
  return (L + mask) & ~mask
chunk_count(L)    = ceil(padded_len(L) / 65536)
ciphertext_len(L) = padded_len(L) + 16 · chunk_count(L)
```

Plaintext is zero-extended to `padded_len(L)`; the zeros are encrypted with the data.

### 6.2 Chunked AEAD

```text
for i in 0 .. chunk_count(L):
  chunk_i = padded[i·65536 .. min((i+1)·65536, padded_len)]
  nonce_i = derive_key("store/segment-chunk-nonce/v1", key(32) ‖ i_u64_le)[0..24]
  aad_i   = "store/segment/v3" ‖ i_u64_le ‖ L_u64_le                  // 32 bytes, L = real (unpadded) length
  ct     ‖= AEAD_enc(key, nonce_i, chunk_i, aad_i)                    // nonces are not stored
```

Chunk `i` starts at ciphertext offset `i · 65552`; the last chunk is
`padded_len − i·65536 + 16` bytes. `decrypt_segment(key, ct, L)`: require
`len(ct) == ciphertext_len(L)` exactly; decrypt each chunk; truncate to `L`. Any chunk failure is
an error. `L = 0` gives an empty ciphertext (no tag; nothing to authenticate).

Encryption is deterministic: one key and plaintext give one ciphertext. Safety relies on
`key = BLAKE3_keyed(segment_root, plaintext)` (convergent within one epoch / one tree).

---

## 7. Erasure coding (Code::Rs)

### 7.1 Stripe data layout

```text
data = len_u32_le(ciphertext) ‖ ciphertext ‖ zero padding      // total k · shard_len bytes
shard_len = round_up( ceil((4 + len(ciphertext)) / k), 64 )
data shard j (0 ≤ j < k) = data[j·shard_len .. (j+1)·shard_len]
parity shards = reed_solomon_simd::encode(k, m, data_shards)    // m shards, each shard_len bytes
stripe_id = BLAKE3(ciphertext);  shards[j] = BLAKE3(shard_j)
```

`ciphertext` is a segment ciphertext (§6), or for a v6 pack the concatenation of piece
ciphertexts. Typical parameters (`CodecParams::default`, cluster `config`): `k = 8, m = 6`.
Writers enforce `k ≥ 1, m ≥ 1, k + m ≤ 255`. Parity depends on `m` (changing `m` = full re-encode).

Shard blobs are raw `shard_len` bytes, no envelope.

### 7.2 Reed–Solomon code

Parity bytes must match `reed-solomon-simd` 3.x (`encode`/`decode` top-level functions,
`DefaultRate`, default engine; the system relies on output being identical across the
library's SIMD/scalar engines, since nodes on different CPUs re-create shards that must match the
manifest hashes):

- GF(2^16), field polynomial `0x1002D`, Cantor basis, FFT/Leopard-RS construction (fork of
  `reed-solomon-16`, based on Leopard-RS by C. A. Taylor). Not a Vandermonde/Cauchy RS — generic
  RS libraries will not reproduce the parity.
- In-shard element layout: shards are processed in 64-byte blocks; in each block bytes 0..32 are
  the low bytes and 32..64 the high bytes of 32 consecutive GF(2^16) elements. Writers always use
  `shard_len % 64 == 0`, which the library documents as compatible across all its versions.
- Rate selection (`use_high_rate`): with `ko = k.next_power_of_two()`, `mo = m.next_power_of_two()`:
  `ko < mo` → low rate; `ko > mo` → high rate; `ko == mo` → high rate if `k ≤ m`, else low rate.
  For 8+6: `ko = mo = 8`, `k > m` → **low rate**. Decode must use the same rate (the library's
  `decode` applies the same rule).
- Recovery shard index `r` in the library = stripe shard index `k + r`.

An implementer without a port of reed-solomon-simd can still restore whenever all `k` data shards
are intact (no RS math needed, §7.3). Parity is needed only to replace missing data shards.

### 7.3 Decoding

```text
decode_stripe(stripe, slots[k+m]):
  require k ≥ 1, m ≥ 1, len(stripe.shards) == k+m
  require shard_len even, 2 ≤ shard_len ≤ 64 MiB, k·shard_len ≥ 4
  valid = { j : slots[j] present ∧ len == shard_len ∧ BLAKE3(slots[j]) == stripe.shards[j] }
  |valid| < k → NotEnoughShards
  if all data shards 0..k valid: data = concat(shard_0..shard_{k-1})
  else: recover missing data shards with RS decode from any k valid shards; data = concat
  L  = u32_le(data[0..4]); ct = data[4 .. 4+L]   (out of range → CorruptStripe)
  require BLAKE3(ct) == stripe.stripe_id
  return ct
```

Corrupt shards (wrong length or hash) are silently skipped. `code == Clay` stripes are not
decodable by this procedure (experimental, not used in production).

Range reads (not required for restore): byte `x` of the ciphertext is at data offset `4 + x`,
i.e. shard `(4+x) / shard_len`, offset `(4+x) % shard_len`. Any 64-aligned sub-range of a shard
can be RS-recovered independently from the same sub-range of any k shards.

---

## 8. Chunking (writers only)

Not needed for restore. FastCDC v2020 (crate fastcdc 5.0.0), normalization level 1,
`min = 4 MiB, avg = 8 MiB, max = 16 MiB`, streaming loop over `fastcdc::v2020::cut_gear` with
masks from `select_masks(avg, Level1)` (`[mask_s, mask_l, mask_s<<1, mask_l<<1]`). Gear table is
keyed per epoch: 256 `u64` little-endian words from 2048 bytes of BLAKE3 XOF
(`Hasher::new_derive_key("store/chunk-gear/v1").update(segment_root).finalize_xof()`),
`gear_ls[i] = gear[i] << 1`. An empty stream yields no segments. Dedup of stripes therefore
works only within one epoch of one tree.

---

## 9. Directory entries

### 9.1 `name_enc`

```text
key   = EpochKeys(dir.epoch).names
nonce = BLAKE3_keyed(key, utf8(name))[0..24]                   // also the "name id"
core  = nonce(24) ‖ AEAD_enc(key, nonce, utf8(name), "store/name/v2")   // len(name)+16 after nonce
Kmac  = derive_key("store/name-mac/v2", key)
mac   = BLAKE3_keyed(Kmac, kind_byte ‖ entry.hash(32) ‖ core)[0..16]    // kind_byte: File 0, Dir 1
name_enc = core ‖ mac                                           // total len(name) + 56
```

Decryption (`names::decrypt`):

1. `len(name_enc) − 16 ≥ 24`, else error. Split `core ‖ tag(16)`.
2. Recompute `mac` over `entry.kind`, `entry.hash`, `core`; compare (constant time). Mismatch →
   the directory was tampered with (entry hash/kind swapped); reject the entry.
3. `name = open(key, core, "store/name/v2")` (core is `nonce ‖ ct ‖ tag`), must be UTF-8.
4. Require `core[0..24] == BLAKE3_keyed(key, name)[0..24]`.

Client additionally rejects (skips) names that are empty, `.`, `..`, or contain `/` or `\0`.

Sorting: entries are strictly ascending by `name_enc` bytes. Since `name_enc` begins with the
24-byte name id (unique per name in an epoch), this is the order of name ids; lookup by name is a
binary search on `id(key, name)`.

### 9.2 `extra` (restorers may ignore)

Empty → no attributes. Otherwise
`open(names_key, extra, "store/dir-extra/v2" ‖ name_enc[0..24] ‖ kind_byte ‖ hash(32))`.
Plaintext is application bytes, optionally prefixed by library system attributes:
`"\0fh\x01" ‖ u16_le n ‖ n bytes JSON ‖ app bytes` (docs/ffi.md; e.g.
`{"v":1,"role":"media_root"}`). Max 4096 app bytes.

### 9.3 `id_enc` (restorers may ignore)

`open(names_key, id_enc, "store/dir-id/v1")` → 16 random bytes (`ItemId`), stable across rename,
move and new versions. `id_enc` is 56 bytes.

### 9.4 Reserved names in the root directory

| Name | Contents | Restore |
| --- | --- | --- |
| `.trash` | `/.trash/<YYYY-MM-DD>/<ms>-<i>-<name>` — deleted/overwritten entries (day in UTC, `ms` Unix milliseconds of deletion, `i` index in the batch, `name` last path component). Original directory is not recorded. Entries keep `kind`, `hash`, `extra`, id. | optional |
| `.shares` | `/.shares/<hex id>` — re-sealed manifest copies backing shares (same stripes) | skip |
| `.fh` | media library derivatives (thumbnails, index, upload log); no trash, no versions | skip |

---

## 10. Restore algorithm

```text
input:  root (Root), keyring (Keyring), credentials (password + escrow record + Argon params,
        or device ed25519 seed), blob source get(hash) → bytes | missing,
        optionally spaces: [(space Root, SpaceKeyring)]

unlock_account():
  if device seed: E_n = unwrap(user, kr.epoch, device_x25519_secret, kr.wraps[device_id])
  else:
    (enc, auth_seed) = Argon2id(password, derive_key("store/escrow-salt/v1", user), params) split 32/32
    assert ed25519_pub(auth_seed) == escrow.auth            // else wrong password
    master = open(enc, escrow.blob, "store/escrow/v1")
    assert kr.escrow_wrap is Some and kr.escrow_pub == X25519(escrow_secret(master), 9)
    E_n = unwrap(user, kr.epoch, escrow_secret(master), kr.escrow_wrap)
  E[0..=n] = unchain(user, E_n, kr.links)
  K[e] = EpochKeys(e, E[e]) for all e

unlock_space(sroot, skr):
  w = skr.wraps.find(user == account user)
  S_n = unwrap(space_id, skr.epoch, derive_key("store/epoch/recv/v1", E[w.recv_epoch]), w.wrap)
  S = unchain(space_id, S_n, skr.links); KS[e] = EpochKeys(e, S[e])

fetch(hash, T):                       // T ∈ {Dir, FileManifest}
  b = get(hash); require BLAKE3(b) == hash; require b[0] ∈ {5, 6}; return postcard_decode<T>(b[1..])

walk(dir_hash, path, keys):
  d = fetch(dir_hash, Dir); kn = keys[d.epoch].names
  for e in d.entries:
    name = names_decrypt(kn, e)  — on failure: report path/entry, skip
    if !valid_name(name): skip
    if path == "/" and name ∈ {".shares", ".fh"}: skip (optional)
    if e.kind == Dir: walk(e.hash, path/name, keys)
    else: restore_file(e.hash, path/name, keys)

restore_file(h, path, keys):
  for (v, mh) in versions(h):                 // v = 0 current, follow prev; stop on None or missing
    man  = fetch(mh, FileManifest)
    meta = open_meta(keys[man.epoch].meta, man)    // §5.1 incl. validation
    out  = match meta.layout():
      Segments:        concat_i decrypt_segment(meta.segment_keys[i], stripe_ct(man.stripes[i]), meta.segment_lens[i])
      Slice{off,len}:  decrypt_segment(meta.segment_keys[0], stripe_ct(man.stripes[0]), meta.segment_lens[0])[off..off+len]
      Piece{o,len}:    decrypt_segment(meta.segment_keys[0], stripe_ct(man.stripes[0])[o .. o+ciphertext_len(len)], len)
    write out to path (v == 0) or a versions area (v > 0); set mtime = meta.mtime_ns

stripe_ct(s):
  slots[j] = get(s.shards[j]) for j in 0..k+m      // fetch data shards first; parity only if needed
  return decode_stripe(s, slots)                    // §7.3; NotEnoughShards → file unrecoverable, report

main:
  optionally verify root.sig (§2.1)
  unlock_account(); walk(root.dir, "/", K)          // includes /.trash (deleted files)
  for each space: unlock_space; verify sroot.sig; walk(sroot.dir, "/<space>/", KS)
```

Notes:

- Cache decoded stripes by `stripe_id`/stripe key: pack stripes and deduplicated segments are
  shared between files and versions.
- Errors are per object: a missing or corrupt blob, failed MAC/AEAD, or fewer than `k` valid
  shards affects only the subtree/file/version referencing it. Never output unauthenticated
  plaintext.
- A manifest whose epoch is not in `0..=n` cannot be decrypted (should not happen; report).
- Hash collisions across trees are benign; objects are immutable.

---

## 11. Exit state file (`state.fhx`) and export directory

The root and the keyrings live in the control plane. To restore without it, a client saves them
in an **exit state** (`store_core::exit::ExitState`). `store export <dir>` writes an
**export directory**:

```text
<dir>/state.fhx      exit state
<dir>/blobs/<hex>    every reachable blob; file name = lowercase hex BLAKE3 of the bytes
```

`fh-restore <dir> <out>` reads only this directory and needs no network.

### 11.1 Layout

`"FHEXIT\0\0"` (8 bytes) ‖ version `0x01` ‖ `postcard(ExitState)`, nothing after it.

```text
ExitState {
  user:       VerifyingKey            // account id
  created_ms: u64
  root:       Option<Root>            // latest account root seen by the device
  keyring:    AccountKeyring {
                epoch:        u64     // n
                escrow_wrap:  Option<Vec<u8>>          // wrap(E_n → escrow X25519), §2
                device_wraps: Vec<([u8;32], Vec<u8>)>  // (device ed25519 key, wrap(E_n → device X25519))
                links:        Vec<Vec<u8>>             // links[k] = E_k under key from E_{k+1}; len == n
              }
  escrow:     Option<Escrow { argon: Argon { m_kib: u32, t: u32, p: u32 }, auth: VerifyingKey, blob: Vec<u8> }>
  spaces:     Vec<SpaceState {
                id: VerifyingKey, root: Option<Root>, epoch: u64,
                recv_epoch: u64,      // account epoch whose receive key opens `wrap`
                wrap: Vec<u8>,        // wrap(S_epoch → recv_public(E_recv_epoch)), AAD user = space id
                links: Vec<Vec<u8>>
              }>
  nodes:      Vec<NodeHint { id: [u8;32], addrs: Vec<String> }>   // storage nodes at export time
}
```

`[u8;32]` is 32 raw bytes (serde tuple); `VerifyingKey` is `0x20` ‖ 32 bytes (§1.1).

### 11.2 Unlocking

1. Obtain `E_n`, one of:
   - **password**: `master = escrow_open(escrow, password)` (§2), then
     `E_n = unwrap(user, n, escrow_secret(master), escrow_wrap)`;
   - **account file** (`user(32) ‖ master(32) …`): same from `master`;
   - **device key** (32-byte ed25519 seed of an active device): find its entry in `device_wraps`,
     `E_n = unwrap(user, n, device_x25519_secret(seed), wrap)`.
2. `E_0..E_n = unchain(user, E_n, links)`; derive `EpochKeys` for each (§2).
3. Each space: `S_epoch = unwrap(space.id, space.epoch, recv_secret(E_recv_epoch), wrap)`, then
   unchain with `space.id`. A space that does not open is skipped.
4. Verify each `Root` signature and that `root.user` is the account (or the space id).

### 11.3 Security

No secret is in the clear, but `escrow.blob` is the master key sealed under the password: a copy
of `state.fhx` lets an attacker try passwords offline at the Argon2id cost. The control plane
never hands out escrow without a signature by the password-derived `auth` key. Keep the file as
private as the password. Exports from devices without the escrow have `escrow = None` and open
only with the account file or a device key.

### 11.4 Output of `fh-restore`

`<out>/account/…` is the account tree, `<out>/space-<first 8 bytes of id, hex>/…` are the spaces;
`--versions` adds `<tree>/.versions/<path>/<n>` (n = 1 is the version before the current one),
`--skip-trash` omits the top-level `.trash`. A file is written only if it decrypts and
authenticates completely. Everything that fails is listed, and the exit code is then 2.

### 11.5 Test vectors

`vectors/` holds an export (`export/`), the plain files it must restore to (`expected/`) and
the unlock material (`unlock/password.txt`, `unlock/device.key`, `unlock/account.key`; Argon2id
`m = 8 MiB, t = 1, p = 1` for speed). Its content:

- two account epochs, a folder written in epoch 0 and not rewritten;
- Unicode names, an empty file, a 300 000-byte file in three segments;
- a format-6 piece pack (3 files) and a format-5 slice pack (2 files; the manifest is version 5);
- a version chain of three, the trash, and a family space;
- the first stripe of the large file has data shards 0–3 and parity 8–9 removed (exactly `k`
  left), and one data shard of the piece pack is corrupt.

`cargo test -p store-restore` restores them three ways (password, device key, account file)
and compares the result byte for byte.

---

## 12. Versioning and compatibility policy

- One-byte blob version. A build reads exactly the window `FORMAT_VERSION − 1 ..= FORMAT_VERSION`
  (currently 5..=6) and writes `clamp(cluster format_target, FORMAT_MIN, FORMAT_VERSION)`. A
  build never guesses at a blob outside its window; it fails with `UnsupportedVersion`.
- No migration: old blobs stay in their version until rewritten. A future build whose window no
  longer includes 5 will not read version-5 blobs, so a long-term restorer should support every
  version ever issued (5 and 6 today).
- postcard layouts are not extensible. A type whose body changes in a new version implements a
  version-specific decoder (`Blob::decode_body(version, body)`); for 5 and 6 all bodies are
  identical.
- Semantic changes that are not layout changes (e.g. Piece vs Slice) are signalled inside the
  encrypted data (`FileMeta::layout`), not by the version byte.
- Every cryptographic construction is bound to a versioned domain string (`.../v1`, `/v2`, `/v3`
  above). A change of construction introduces a new domain string; old strings are never reused
  with a different meaning.
- `Stripe::key` is pinned to version byte 5 forever.
- Code (`Code` enum) and erasure parameters are per stripe; readers must honour each stripe's
  own `k`, `m`, `shard_len`, `code`.
