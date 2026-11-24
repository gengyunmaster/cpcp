# cpcp Recovery Journal v1

> Status: Implemented journal v1 and resumable backup sessions

Journal v1 is an independently versioned, append-only recovery hint. It is not snapshot or verification evidence. Source paths, source identities, chunk descriptors, and session state appear only inside authenticated encrypted records.

## 1. File envelope

A journal is stored as `sessions/<session-uuid>.journal`.

```text
"CPJR"[4]
version_u16_le = 1
repository_uuid[16]
session_uuid[16]
records[]
```

Records start at byte offset 38. Each record has:

```text
sequence_u64_le
record_type_u8
ciphertext_length_u32_le
crc32_u32_le
nonce[24]
ciphertext[ciphertext_length]
```

The plaintext JSON record is limited to 1,048,576 bytes. Ciphertext length includes the 16-byte XChaCha20-Poly1305 authentication tag. Readers check lengths before allocation.

The plaintext document contains schema `cpcp.journal-record.v1`, session UUID, decimal-string sequence, numeric record type, and a `payload` value. These values must agree with the outer record context.

## 2. Authentication and chaining

AAD for record decryption is:

```text
"cpcp.journal.record.v1"
|| repository_uuid[16]
|| session_uuid[16]
|| sequence_u64_le
|| record_type_u8
|| previous_chain[32]
```

The previous chain is all zero for sequence zero. Sequence numbers are contiguous and start at zero.

The record chain is:

```text
HMAC-SHA-256(
  K_journal,
  "cpcp.journal.chain.v1" || AAD || nonce || ciphertext
)
```

CRC32 covers the sequence, type, ciphertext-length fields, nonce, and ciphertext. It detects accidental tearing; it is not an adversarial integrity mechanism. AEAD, sequence validation, payload context validation, and the preceding-chain value provide authenticated recovery ordering.

Record type assignments are:

| Value | Meaning |
| ---: | --- |
| 1 | Session identity and snapshot reservation |
| 2 | Directory |
| 3 | File begin and opened-handle identity |
| 4 | Bounded chunk-descriptor group |
| 5 | Completed file and descriptor-spool identity |
| 6 | Policy skip |
| 7 | Required-entry failure |
| 8 | Restart-files transition |
| 9 | Explicit root remapping |
| 10 | Main snapshot publication |
| 11 | Committed summary |
| 12 | Symbolic link |

## 3. Checkpoints and recovery

Writers may buffer ordinary records. A checkpoint flushes the journal file after the corresponding object checks or publications. Descriptor groups contain at most 64 chunks, and file-completion records are checkpoints. A crash can lose uncheckpointed records and cause repeated work without invalidating existing snapshots.

Readers process the chain from the beginning. A physically torn final record, a checksum failure confined to the final record, or an unauthenticated final record is discarded. Under the backup-writer lock, resume truncates the file to the last valid record boundary, flushes that truncation, and appends after the recovered chain. Corruption with valid records after it is an integrity error and is never hidden by truncation.

A journal record is never accepted as proof of current source or repository health. Resume must re-establish source identity and obtain current-invocation or policy-approved repository evidence for every referenced object.

## 4. Validation

Tests cover chained append/replay, checkpoint recovery, ciphertext confidentiality for source paths, torn tails, replacement of an unauthenticated final record, rejection of corruption before the final record, wrong session contexts, and native read/write truncation.

## 5. Session payloads and resume invariants

The session record reserves the snapshot UUID, generation, lineage, session UUID, storage epoch, root UUIDs, selection policy, optional tag, and optional parent UUID. Tags are also authenticated in the main snapshot header and summary, and are compared during idempotent recovery. A resumed session authenticates this reservation before allocating or publishing anything. A conflicting active parent or a later generation blocks resume rather than renumbering implicitly.

A file-begin record carries the root-relative path, file sequence, and opened-handle source identity. Chunk records carry a bounded `cpcp.chunk-batch.v1` value and new/deduplicated counters. A file-complete record carries the authenticated file header, source identity, descriptor-spool UUID, and counters. Descriptor spools use the existing encrypted `CPSP` format under `sessions/`.

Resume uses disk-backed keyed path indexes for completed and currently observed paths. A completed file is skipped only when its size, normalized modification time, mode, device, and file identity still match. A partial file is rebuilt from journaled descriptor groups and resumed at its chunk boundary after every descriptor obtains current or policy-approved repository evidence. Missing objects require a source reread through `--restart-files`; journal data alone cannot recreate them.

`--restart-files` and every root remap are explicit journal transitions. They invalidate earlier file completions for the affected roots without deleting published chunks. Remapping uses a root UUID and a caller-supplied canonical directory, never a similar directory name. A final reverse pass ensures that every required journaled file and directory was observed during the current source scan.

Main snapshot and summary publication are idempotent. An existing main object is fully authenticated and checked for context, roots, selection policy, and final statistics before reuse. An existing summary must match the session and main digest exactly. Session completion is journaled only after summary publication; journal and owned spool files are removed afterward. Discard authenticates the session under maintenance locks and removes only session-owned files.
