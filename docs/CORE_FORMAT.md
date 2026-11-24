# cpcp Core Format v1

> Status: Core format version 1, validated by the M1 implementation and independent recovery tests

This document defines the implemented cpcp core repository format. It is versioned independently of `docs/DESIGN.md`, which remains the architecture and behavior baseline. Any incompatible format change requires a new format version and explicit migration tooling.

## 1. Encoding rules

- Multi-byte integers are unsigned little-endian unless stated otherwise.
- Digests and keys contain 32 bytes.
- UUID and epoch fields contain 16 bytes.
- Native C++ structure layout is never serialized.
- Snapshot and spool plaintext frames are limited to 1,048,576 bytes.
- Ciphertext frames include the libsodium authentication overhead.

## 2. Key hierarchy

A repository master key contains 32 random bytes. Subkeys use libsodium `crypto_kdf_derive_from_key` with subkey ID 1 and these eight-byte contexts:

| Purpose | Context |
| --- | --- |
| Chunk encryption | `chunk001` |
| Snapshot encryption | `snap0001` |
| Journal and spool encryption | `jrnl0001` |
| Content IDs | `idkey001` |
| Configuration authentication | `conf0001` |
| Validation-cache authentication | `cach0001` |

The C++ `SecureKey` prototype allocates with `sodium_malloc`, requests page locking, prohibits copying, and releases with `sodium_free`.

For independent implementations, `crypto_kdf_derive_from_key` is BLAKE2b with an empty message, the 32-byte master key as keyed input, a 16-byte salt consisting of `uint64_le(subkey_id) || eight_zero_bytes`, and a 16-byte personalization consisting of the eight-byte context followed by eight zero bytes. This is compatible with Python `hashlib.blake2b(key=master, salt=salt, person=personal, digest_size=32)`.

For key bytes `00 01 02 ... 1f`, subkey ID 1, and context `idkey001`, the derived key is:

```text
68b7471eeec2a59d44d871efd9e30befb1236067a008d1d0c525bbabed504dd2
```

## 3. Content identities

Chunk identity is:

```text
HMAC-SHA-256(
  K_id,
  "cpcp.chunk.v1" || uint64_le(plaintext_length) || plaintext
)
```

File identity is a second-level commitment:

```text
HMAC-SHA-256(
  K_id,
  "cpcp.file.v1" || uint64_le(file_length) || uint64_le(chunk_count) ||
  repeated(chunk_id || uint32_le(plaintext_chunk_length))
)
```

Stored ciphertext lengths are manifest metadata and are not part of file identity. Each chunk must still authenticate and match its own chunk ID.

Fixed-size continuation validation requires:

- all non-final chunks to have exactly the configured chunk size;
- every chunk to be nonempty and no larger than the configured size;
- derived offsets to remain within file length;
- final chunk count and total plaintext length to match the file header exactly.

Empty files use zero chunks and the defined empty-descriptor HMAC.

### Independent vectors

For key bytes `00 01 02 ... 1f`:

```text
chunk_id("hello")
  = 1d2ad3fb87be975582421b6449e6a4d7941c6ef4afd13ef46d68a9aadcde25ce

chunk_id("world")
  = 4a0157b363763d273f1068b949d1c3876b44d14e3bbe2236ce8bfb6a717fb688

file_id(length=10, chunks=[hello/5, world/5])
  = e7a49e51fb17276070548aec8d9a0bd46e6568e0b4a88e78aa6ec07685bc278b
```

These values are generated independently with Python `hmac` and `hashlib`.

## 4. Bounded authenticated objects

Single objects use XChaCha20-Poly1305 with a random 24-byte nonce and ciphertext carrying the 16-byte authentication tag. Decryption returns plaintext only after authentication succeeds.

Independent PyNaCl vector:

```text
key        = bytes 00..1f
nonce      = bytes 00..17
AAD        = "cpcp.test.aad"
plaintext  = "hello"
ciphertext = f6a76313ff339409fedcbd0044b1fc36a2669517b5
```

SHA-256 binds snapshot summaries to complete main ciphertext. The test vector for `abc` is:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## 5. Snapshot stream AAD

Snapshot streams use `crypto_secretstream_xchacha20poly1305` with a fresh 24-byte stream header. Every frame supplies this AAD:

```text
"cpcp.snapshot.v1"
|| repository_uuid[16]
|| storage_epoch[16]
|| snapshot_uuid[16]
|| lineage_uuid[16]
|| generation_le[8]
|| frame_index_le[8]
|| record_type_u8[1]
```

Session spools use the same field layout with domain `cpcp.spool.v1`; snapshot UUID and lineage UUID fields carry session and spool UUIDs respectively in the experimental prototype.

Record types are:

| Value | Type |
| --- | --- |
| 1 | Context |
| 2 | Snapshot header |
| 3 | Root |
| 4 | File header |
| 5 | Chunk batch |
| 6 | File end |
| 7 | Policy skip |
| 8 | Failure |
| 9 | Directory |
| 10 | Symbolic link |
| 11 | Ownership metadata |
| 255 | Final summary |

The final summary uses `TAG_FINAL`; all other records use `TAG_MESSAGE`. Missing FINAL, data after FINAL, unexpected record tags, frame reordering, wrong context, and oversized frames are errors.

### Snapshot main outer context

`CPSN` snapshots include the complete decryption context before the secretstream header:

```text
"CPSN"[4]
version_u16_le = 1
repository_uuid[16]
storage_epoch[16]
snapshot_uuid[16]
lineage_uuid[16]
generation_u64_le
session_uuid[16]
secretstream_header[24]
frames[]
```

This self-describing envelope permits `repo repair-summary` to reconstruct lineage and session metadata without relying on the damaged summary.

### Authenticated summary envelope

`CPSM` summaries include the same authenticated context, a random nonce, and a bounded encrypted JSON payload:

```text
"CPSM"[4]
version_u16_le = 1
reserved_u16_le = 0
repository_uuid[16]
storage_epoch[16]
snapshot_uuid[16]
lineage_uuid[16]
generation_u64_le
session_uuid[16]
nonce[24]
ciphertext_length_u32_le
ciphertext[ciphertext_length]
```

Summary AAD is `"cpcp.summary.v1" || repository_uuid || storage_epoch || snapshot_uuid || lineage_uuid || generation_u64_le`. The inner payload repeats all context fields, including the session UUID, and both representations must match. The summary stores the main ciphertext's SHA-256 digest and exact stored length.

## 6. Encrypted session spool disk format

```text
"CPSP"[4]
version_u16_le = 1
secretstream_header[24]
repeated {
  frame_index_u64_le
  record_type_u8
  ciphertext_length_u32_le
  ciphertext[ciphertext_length]
}
```

The final record is `final_summary`. The writer flushes and closes the file after FINAL. The reader enforces frame-length bounds and requires physical EOF immediately after FINAL. A torn header or ciphertext returns an integrity error. Source paths and metadata appear only inside authenticated encrypted frames.

## 7. Validation and feature-specific formats

Validation covers independent content-ID and AEAD vectors, key separation, continuation validation, AAD binding, tampering, reordering, FINAL handling, spool confidentiality, native spool reads and writes, full C++ backup/restore, recovery paths, independent Python recovery of C++-written repositories, and a multi-gigabyte synthetic manifest streaming stress test.

Core version 1 includes strict bounded JSON record batches, authenticated configuration replicas and password slots, self-describing chunk envelopes, snapshot context records, authenticated summary sidecars, maintenance transition records, and idempotent snapshot finalization.

Journal and resume formats, validation-cache formats, retention metadata, and packed objects remain separately versioned feature work rather than hidden changes to this core format.

## 8. Selection-policy and tag extensions

Snapshots written with selection-failure support retain the v1 envelope and add these authenticated fields:

- Summary and snapshot-header `selection_policy` / `selection`: `unsupported` is `skip` or `fail`; `one_file_system` is a boolean.
- Summary and final-record `stats.selection`: decimal-string `policy_skipped_entries` and `failed_entries` counters.
- Final-record `status`: `complete` or `partial`, exactly matching the summary.

A `cpcp.failure.v1` record uses record type 8 and contains `root`, `path`, and `reason`. A partial snapshot must contain at least one failure record; a complete snapshot must contain none. Failure and policy-skip paths remain root-relative. Counts must equal the corresponding record totals.

The selection fields are optional when reading older v1 snapshots. Their absence denotes the original `unsupported=skip`, one-filesystem policy without authenticated selection counters. New writers always emit them. Readers reject unknown policies, inconsistent final status, and mismatched counts.

A failed required entry prevents publication unless the caller explicitly allows a partial snapshot. A published partial snapshot remains partial when selected by `latest`; restoration requires explicit approval, while `latest-complete` selects the newest complete generation.

An optional snapshot `tag` is stored in both the summary and main header and checked during repair or idempotent finalization. Null and an absent field denote no tag; an empty tag is not emitted by writers.
