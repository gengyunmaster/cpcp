# cpcp Recovery Journal v1

> Status: Implemented journal primitive; session integration is subsequent feature work

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

## 3. Checkpoints and recovery

Writers may buffer ordinary records. A checkpoint flushes the journal file after the corresponding object checks or publications. Descriptor groups contain at most 64 chunks, and file-completion records are checkpoints. A crash can lose uncheckpointed records and cause repeated work without invalidating existing snapshots.

Readers process the chain from the beginning. A physically torn final record, a checksum failure confined to the final record, or an unauthenticated final record is discarded. Under the backup-writer lock, resume truncates the file to the last valid record boundary, flushes that truncation, and appends after the recovered chain. Corruption with valid records after it is an integrity error and is never hidden by truncation.

A journal record is never accepted as proof of current source or repository health. Resume must re-establish source identity and obtain current-invocation or policy-approved repository evidence for every referenced object.

## 4. Validation

Tests cover chained append/replay, checkpoint recovery, ciphertext confidentiality for source paths, torn tails, replacement of an unauthenticated final record, rejection of corruption before the final record, wrong session contexts, and native read/write truncation. Full backup resume, root remapping, idempotent publication, status, and discard tests belong to the session integration milestone.
