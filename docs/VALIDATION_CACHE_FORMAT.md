# cpcp Validation Cache v1

> Status: Implemented authenticated cross-session validation evidence

Validation caches are disposable historical evidence, never freshness proofs. A cache can be deleted or ignored without changing repository correctness. Every reused object still receives the mandatory current no-follow type and exact-stored-length check.

## 1. File format

The current-epoch cache is `cache/validation-<storage-epoch>.cache`.

```text
"CPCV"[4]
version_u16_le = 1
reserved_u16_le = 0
repository_uuid[16]
storage_epoch[16]
entry_count_u64_le
entries[entry_count]
```

Each fixed-size 84-byte entry contains:

```text
chunk_id[32]
stored_length_u64_le
object_format_version_u32_le
verified_at_seconds_i64_le
authentication_tag[32]
```

Entries are sorted by chunk ID for binary-search lookup. `verified_at` is Unix wall-clock time for diagnostics, not a freshness guarantee. The format has no whole-file freshness claim and does not prevent replay of valid old entries.

The authentication tag is:

```text
HMAC-SHA-256(
  K_cache,
  "cpcp.validation-entry.v1"
  || repository_uuid
  || storage_epoch
  || chunk_id
  || stored_length_u64_le
  || object_format_version_u32_le
  || verified_at_seconds_i64_le
)
```

A wrong repository or epoch header disables the cache. Malformed lengths, lookup failures, wrong stored lengths or object versions, and invalid authentication tags make the affected evidence unusable; they never bypass full validation.

## 2. Producing and consuming evidence

Only `repo verify --deep --refresh-validation-cache` writes entries. A distinct object must have been read, decrypted, and matched to its content ID during that invocation. Objects merely accepted from a base snapshot or an earlier cache are not re-stamped as current verification.

Refresh takes the separate exclusive cache-writer lock while retaining the shared lifecycle lock, writes and flushes a temporary file, atomically replaces the current-epoch cache, synchronizes its directory, and validates the written entries. Cache-write failure produces a partial result without invalidating successful repository verification. Read-only repository mode forbids refresh.

Backup may accept an authenticated entry under the current repository UUID and storage epoch. `--revalidate-all` ignores this evidence and fully reads each distinct referenced object once. Within an invocation, only an actually fully validated object can short-circuit later full reads; historical acceptance cannot.

Epoch rotation namespaces old evidence under the previous epoch and prevents its automatic use. Copying or rolling back files does not rotate the epoch; operational guidance still requires deep verification and explicit rotation after storage replacement.

## 3. Validation

Tests cover refresh, valid historical reuse, mandatory full revalidation, cache deletion, invalid per-entry authentication, wrong epochs, and the rule that historical acceptance is not recorded as current deep verification. Native tests also verify that read-only checks do not change repository files or directory timestamps.
