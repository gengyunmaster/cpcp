# cpcp Design and Architecture

> **Status:** Draft for review
>
> **License:** MIT
>
> **Audience:** Contributors, reviewers, and users evaluating cpcp for important data

This document defines the product boundaries, safety semantics, repository model, and engineering direction for cpcp. It is the primary reference for implementation decisions. Details that affect interoperability must be moved into a versioned repository-format specification before the format is frozen.

## 1. Product definition

cpcp is an open-source, cross-platform command-line tool for encrypted, content-addressed backup repositories on local filesystems. It is intended for Windows, Linux, and macOS, with particular attention to backups between separate physical disks and to interrupted transfers.

A repository stores:

- encrypted, immutable content objects;
- encrypted snapshots containing paths, file metadata, and content references;
- encrypted recovery journals for interrupted backup sessions;
- a small plaintext configuration containing only the information needed to locate and unlock the repository.

The central workflow is:

```text
initialize a repository
  -> add a directory tree to a new snapshot
  -> resume an interrupted session if necessary
  -> compare source files with a snapshot
  -> verify repository integrity
  -> restore selected files or an entire snapshot
```

cpcp is a backup tool, not a synchronization tool. Adding data creates a new snapshot rather than replacing the previous history.

## 2. Design priorities

The priorities are ordered deliberately:

1. **Do not silently lose or corrupt data.** Fail visibly rather than reporting an unusable backup as successful.
2. **Make interruption safe.** A process crash, cancellation, or temporary disconnect must not require modifying existing backup objects.
3. **Make restoration trustworthy.** Authenticate encrypted objects and verify reconstructed content before publishing restored files.
4. **Protect confidentiality and detect tampering.** Use reviewed cryptographic libraries and an explicit, versioned format.
5. **Keep the recovery path simple.** Prefer a small number of immutable objects and clear invariants over clever state management.
6. **Provide stable automation interfaces.** Exit codes, output streams, JSON schemas, and repository formats are public contracts.
7. **Optimize only after correctness is testable.** Deduplication, incremental scans, compression, and resumability must not weaken verification semantics.

Performance is important, especially for failing disks, but it never justifies silently skipping the checks required for a claimed result.

## 3. Scope and boundaries

### 3.1 Initial capabilities

The first usable release should support:

- password-protected repository initialization;
- fixed-size, content-addressed chunks;
- automatic deduplication within one repository;
- encrypted snapshots for regular files and directories;
- chunk-granular backup resumption;
- source-to-snapshot comparison with explicitly different assurance levels;
- structural and deep repository verification;
- safe restoration of file content and a defined baseline of metadata;
- human-readable and JSON output;
- local filesystem repositories on Windows, Linux, and macOS.

### 3.2 Non-goals

cpcp does not attempt to provide:

- absolute protection against data loss or storage-device failure;
- availability when an attacker or failing device deletes repository data;
- strong rollback detection without trust state stored outside the repository;
- protection against malware or an attacker controlling the machine running cpcp;
- application-consistent backups of live databases, virtual machines, or other actively changing data without an operating-system or application snapshot;
- lossless restoration of every platform-specific metadata feature across different operating systems;
- real-time synchronization, a filesystem mount, or a graphical interface in the initial releases;
- redundancy across devices or compliance with a 3-2-1 backup strategy by itself;
- deniability, concealed repository existence, or protection against all traffic and access-pattern analysis.

### 3.3 Operational position

Until cpcp has substantial real-world use and independent security review, it must not be the only copy of important data. A self-developed backup tool is not a substitute for an independent backup implementation, an additional device, or restoration drills.

A disk showing repeated disconnects or read errors should be imaged with a recovery-oriented tool such as GNU ddrescue before experimental backup software is run against it. cpcp must not claim to repair a failing source device.

## 4. Terminology and assurance levels

Precise terms prevent the interface from promising more than was checked.

| Term | Meaning |
| --- | --- |
| Repository | A directory containing cpcp configuration, objects, snapshots, and temporary state |
| Chunk | A fixed-size plaintext segment of a file, stored as at most one encrypted content object per repository |
| Content ID | A keyed cryptographic digest of plaintext content, used for addressing and deduplication |
| Object | An encrypted chunk, snapshot, or other versioned repository payload |
| Snapshot | An authenticated, immutable manifest describing one backup attempt or completed backup |
| Session | One resumable backup operation and its journal |
| Published | Atomically made visible under its final repository name after the required write protocol |
| Verified | Read back and successfully subjected to the checks explicitly named by the command |
| Verification evidence | A current-session validation result or authenticated historical result accepted under the selected policy |
| Storage epoch | A random logical storage generation used to invalidate historical verification evidence after explicit storage replacement or recovery |
| Provisional snapshot data | Records parsed from individually authenticated frames but not yet committed by the stream's authenticated final record |
| Complete snapshot | A snapshot in which every planned entry was captured without a detected source or repository error |
| Partial snapshot | An explicitly marked snapshot containing only the successfully captured subset and an authenticated failure report |

Verification is always scoped. Authenticating a snapshot does not authenticate every chunk it references, and comparing a source file hash with a snapshot does not prove that the repository can still reconstruct that file.

## 5. Threat and fault model

### 5.1 Adversaries and failures considered

| Case | Intended behavior |
| --- | --- |
| An attacker reads the repository | File contents, paths, and supported metadata remain confidential; offline password guessing remains possible |
| An attacker modifies objects or configuration | Authentication failure or another integrity error is reported when the affected data is checked |
| An attacker deletes, reorders, truncates, or rolls back repository state | Detect missing or inconsistent data where possible; deletion, denial of service, and complete rollback cannot always be prevented |
| cpcp is cancelled or crashes | Existing snapshots remain unchanged; incomplete work remains temporary or unpublished |
| The operating system crashes or power is lost | The commit protocol aims to preserve previously published snapshots, assuming the filesystem and device honor their durability and atomicity contracts |
| A source or repository disk disconnects | Stop with a classified error; resume from verified chunk boundaries when safe |
| A stored object develops bit rot | A subsequent read or deep verification detects it; undetected corruption cannot be guaranteed impossible |
| A source file changes during backup | Detect changes through opened-handle metadata where possible; otherwise document the remaining consistency limitation |
| A source device returns incorrect bytes without an error | cpcp cannot establish that those bytes differ from the intended data without an independent trustworthy copy or checksum |

### 5.2 Explicit limits

Authenticated encryption detects modification; it does not create availability, redundancy, or freshness. An attacker who can replace the entire repository with an older valid copy can also present an older valid password configuration and snapshot history. Detecting that attack requires an external trust anchor, such as a separately stored repository generation and snapshot hash.

Similarly, a successful `fsync`, read-back, or rename is evidence within the operating-system and storage contracts, not proof that every device will survive arbitrary hardware failure. cpcp must describe these assumptions rather than advertise unconditional durability.

### 5.3 Information leakage

Even with encrypted payloads, a local repository normally reveals:

- its existence and approximate total size;
- the number and sizes of stored objects;
- object creation and modification times exposed by the host filesystem;
- access timing and approximate working-set behavior;
- equality of chunks within the same repository, intentionally enabling deduplication.

Content IDs are keyed so that an offline reader cannot simply hash a known candidate file and compare it with a public digest. Optional size padding and stronger access-pattern protections are future considerations, not initial guarantees.

## 6. Correctness invariants and command success

### 6.1 Repository invariants

The implementation and tests must enforce these invariants within the stated fault model:

- **R1: immutable published objects.** cpcp never modifies a published chunk or snapshot in place.
- **R2: evidence-backed references.** Before a snapshot is published, every distinct referenced chunk must either have passed the chunk validation protocol during the current session or be covered by prior authenticated verification evidence accepted by the selected policy. Every object without acceptable evidence must be fully validated before use.
- **R3: atomic snapshot publication.** A snapshot becomes visible under its final name only after its complete encrypted stream, including its authenticated final frame, has been written and verified.
- **R4: interruption containment.** An interrupted operation must not alter an existing snapshot. New temporary files, journals, or unreachable objects may remain and can be dealt with safely.
- **R5: optimistic state is disposable.** Journals, validation caches, scan indexes, and lock metadata are performance aids. Losing them may cause more work but must not turn invalid data into a valid backup. A cache entry is evidence of an earlier check, never proof of current storage health.
- **R6: verified restoration.** cpcp does not publish a restored file under its final name until its complete reconstructed plaintext passes the expected content verification.
- **R7: guarded deletion.** Garbage collection requires an exclusive repository lock and a two-phase deletion protocol.

These are software invariants, not assertions that a storage device can never corrupt a published object. Repository health must be established by verification at a particular time.

### 6.2 Backup success semantics

By default, `backup add` returns success only when it publishes a **complete snapshot** containing every planned source entry.

If some entries fail:

- already published chunks remain valid and reusable;
- no snapshot is published by default;
- the session remains resumable when its source identity can still be established;
- the command returns the partial-failure exit code and reports every failed path.

An explicit `--allow-partial` option permits publication of a snapshot marked `partial`. A partial snapshot must contain an authenticated list of omitted or failed entries, must be visibly identified by listing and restore commands, and still results in a nonzero partial-failure exit code.

A successful backup is not a new deep verification of the entire repository. Its report must state the verification policy, the number of distinct objects validated in the current session, and the number accepted from prior evidence.

A crash after snapshot publication but before the command prints its result can leave the outcome unknown to the caller. The repository must nevertheless be valid, and `snapshot list` must allow the user to determine whether publication occurred.

### 6.3 No silent fallback

If the apparently newest snapshot is malformed, fails authentication, has a duplicate generation, has an incomplete encrypted stream, or has invalid references, commands must report an integrity error. They must not silently select an older snapshot and present the repository as healthy.

Read-only commands may still support an explicit diagnostic mode for inspecting older valid snapshots, but that mode must display the integrity failure prominently.

### 6.4 Verification evidence and caching

The standard backup policy accepts these forms of evidence for a distinct chunk:

1. successful writing and validation during the current session;
2. successful full validation of an existing object during the current session;
3. prior introduction into an authenticated snapshot under the same repository UUID and storage epoch, relying inductively on R2;
4. an acceptable authenticated cross-session validation-cache entry under the same repository UUID and storage epoch.

An object found only in temporary space, a journal, or an unreachable orphaned object has no snapshot-based evidence and must be fully validated before reuse. A new reference to an already established object is not the same as introducing an unverified object into the repository.

An **in-memory per-session validation cache is mandatory**. Every distinct object is validated at most once per session, even when many files reference it. The cache key includes at least the repository UUID, storage epoch, chunk ID, and object format version. It contains no DEKs or plaintext.

Cross-session validation caches are optional, authenticated, and disposable. A cache entry records at least:

- schema and verifier versions;
- repository UUID and storage epoch;
- chunk ID and object format version;
- verification time;
- an authentication tag from a dedicated cache-authentication key.

Invalid entries must never be used. Deleting the entire cache only causes revalidation. Authentication prevents an attacker without the key from creating new entries, but does not prevent replay of old valid entries.

`verified_at` is an informational wall-clock timestamp, not a freshness proof. A storage epoch is a random logical generation changed by an explicit storage-replacement or recovery operation; it is not a trustworthy device serial number and cannot detect an attacker rolling back both configuration and cache. Epoch mismatch invalidates prior evidence and causes revalidation. Cache expiration is a verification policy, not a guarantee that an unexpired object remains healthy.

`backup add --revalidate-all` ignores prior snapshots and cross-session caches and fully reads and validates every distinct chunk referenced by the new snapshot once in the current session. `backup add --full-source-read` independently disables metadata-only incremental source skipping. These flags provide explicit full-read fallbacks without an ambiguous `--paranoid` assurance claim. Neither option proves correct source-device reads, physical persistence, or continued health after the command finishes.

### 6.5 Incremental complexity

Under the standard policy and after incremental source scanning is implemented, source-content reads are proportional to changed content, and repository-object reads are proportional to new objects or objects lacking acceptable evidence. Metadata scanning of the source tree remains necessary unless a trusted external change journal is introduced.

The initial snapshot design still writes every entry in every snapshot. Snapshot encryption and metadata output therefore remain O(total entry count), even when unchanged file content is neither reread nor revalidated. Reducing that metadata cost requires reusable manifest segments or a persistent authenticated index and is not claimed by the initial format.

## 7. Repository model

### 7.1 Layout

The initial layout is:

```text
<repository>/
  cpcp.config.json
  lock
  chunks/
    ab/cd/<64-lowercase-hex-content-id>
  snapshots/
    <zero-padded-generation>-<uuid>.snap
  sessions/
    <session-uuid>.journal
  cache/
    validation-<storage-epoch>.cache
  tmp/
    <session-uuid>-<sequence>.part
  trash/
```

`trash/` is used once deletion and garbage collection are implemented. It is not required for the first append-only release. `cache/` is disposable and may be absent or removed between invocations; prior snapshot evidence remains available without it.

There is no mutable `current` pointer. The latest snapshot is derived from authenticated snapshot metadata, not trusted from a filename alone.

### 7.2 Discovery and locking

Repository discovery order is:

1. `--repo <directory>`;
2. `CPCP_REPO`;
3. upward discovery of `cpcp.config.json` from the current directory;
4. a runtime error if no repository is found.

Mutating operations use an exclusive operating-system-backed lock. Read-only operations use a shared lock where supported so that garbage collection cannot race restoration or verification. The lock file may contain diagnostic information, but correctness must depend on the operating system lock rather than a stale PID value.

### 7.3 Plaintext configuration

`cpcp.config.json` contains:

- a magic value and repository-format version;
- a randomly generated repository UUID;
- a random storage epoch used to namespace verification evidence;
- creation time and cpcp version for diagnostics;
- the fixed chunk size and content-ID algorithm;
- the authenticated-encryption suite;
- password key slots, each with its own Argon2id parameters, salt, wrapped master key, and nonce;
- future recovery-key slots using the same versioned envelope model;
- a configuration authentication tag covering the canonical security-relevant configuration, including the storage epoch and key slots.

The chunk size, repository UUID, and content-ID algorithm are immutable after initialization. The storage epoch changes only through an explicit storage-replacement or recovery operation that updates the authenticated configuration and invalidates prior verification evidence. Epoch rotation does not change object encryption and does not require rewrapping every key slot. A format migration creates a new format version rather than silently changing these assumptions.

Configuration is plaintext because some of it is needed before a password can be processed, but it is not trusted. Parsing must enforce file-size, nesting, numeric-range, and KDF resource limits before expensive allocation or password derivation.

The master-key wrapping AAD binds the repository UUID, format version, key-slot identifier and type, KDF algorithm, KDF parameters, and salt. After unlocking the master key, cpcp verifies the configuration authentication tag with a dedicated derived key before trusting the storage epoch, chunking parameters, or other bound fields. These values must be encoded with a specified canonical binary encoding; cryptographic authentication must not depend on JSON whitespace or property order.

No separate key-check ciphertext is needed. Successful authenticated unwrapping of the master key already validates the password and bound configuration fields. A wrong password and a tampered key slot may be indistinguishable and are reported as an authentication failure without claiming which occurred.

Replacing the entire configuration with an older valid copy remains a rollback attack and is outside what local authentication alone can prevent.

## 8. Cryptographic design

### 8.1 Algorithm choice

Version 1 uses libsodium for the cryptographic implementation:

- **Argon2id** for password-based key derivation;
- **XChaCha20-Poly1305** for bounded single-message authenticated encryption;
- **`crypto_secretstream_xchacha20poly1305`** for framed snapshot streams;
- **HMAC-SHA-256** with domain separation for content IDs, configuration authentication, validation-cache authentication, and context-bound stream-key derivation;
- **libsodium subkey derivation** with distinct contexts for master-key purposes;
- **the operating-system CSPRNG through libsodium** for keys, salts, nonces, and identifiers.

This deliberately replaces the initial AES-256-GCM proposal. XChaCha20-Poly1305 uses 192-bit nonces, making random nonces substantially easier to manage in a long-lived repository containing many independently encrypted objects. It also allows cpcp to use one audited library for password derivation, authenticated encryption, random generation, and secure-memory operations.

The format records algorithm identifiers explicitly. A future AES-based suite would require a new version and interoperability tests; it must not be introduced by changing the meaning of an existing identifier.

cpcp must never implement cryptographic primitives itself. Random-generator failure is fatal. Nonce generation and key generation must use the library APIs directly, and every nonce and wrapped key must be treated as repository-format data requiring validation.

### 8.2 Key hierarchy

```text
password
  -> Argon2id(slot salt and parameters)
  -> KEK
  -> XChaCha20-Poly1305 unwrap
  -> random 256-bit repository master key (MK)

MK
  -> subkey derivation, wrapping context -> K_wrap
  -> subkey derivation, content-ID context -> K_id
  -> subkey derivation, configuration-authentication context -> K_config
  -> subkey derivation, validation-cache-authentication context -> K_cache

Each bounded encrypted object
  -> fresh random 256-bit data-encryption key (DEK)
  -> DEK wrapped with K_wrap
  -> payload encrypted with the DEK and a fresh random 192-bit nonce

Each snapshot stream
  -> fresh random 256-bit DEK wrapped with K_wrap
  -> HMAC-SHA-256-based context KDF(DEK, canonical snapshot context)
  -> context-bound stream key
  -> crypto_secretstream_xchacha20poly1305 with a fresh random stream header
```

`repo passwd` replaces the password slot used to authenticate the command by default. It generates a new salt, KEK, and wrapping nonce while preserving the same MK and all other key slots. Adding another password or removing a different slot requires a separate explicit key-slot operation; it is never a hidden side effect of `passwd`.

The updated configuration, including its new configuration authentication tag, is atomically published so that a crash leaves either the old or new valid configuration. After a successful replacement, the old password no longer unlocks the updated configuration unless another slot still uses it.

This is not cryptographic revocation. A running process may retain the unlocked MK, and anyone possessing an old configuration copy can use its old password slot to recover the same MK and decrypt current objects. A compromised old password or MK therefore requires master-key rotation, initially by creating a new repository with new keys and re-encrypting the data. Password-change documentation must state this limitation explicitly.

Key slots allow later recovery-key support without changing the data-encryption design. Recovery keys must be high-entropy random values, displayed only when explicitly requested, and intended for offline storage.

Argon2id parameters are stored per slot. Defaults should be calibrated against documented time and memory targets during initialization, with a conservative minimum and an upper resource limit. cpcp must not silently lower the selected parameters on failure.

### 8.3 Content IDs and domain separation

Content IDs are calculated over uncompressed plaintext:

```text
chunk_id = HMAC-SHA-256(
  K_id,
  "cpcp.chunk.v1" || uint64_le(plaintext_length) || plaintext
)

file_content_id = HMAC-SHA-256(
  K_id,
  "cpcp.file.v1" || uint64_le(file_length) || complete_file_plaintext
)
```

The exact byte encoding is part of the repository-format specification. File IDs are computed incrementally while source bytes are read; a second source read is not required solely for this hash.

Chunk IDs provide deduplication and an expected plaintext identity. They do not authenticate an existing stored object merely because its filename matches. Validation requires reading, authenticating, decompressing when applicable, and hashing the reconstructed plaintext.

### 8.4 Authenticated context

For bounded single-message objects, every payload and wrapped DEK uses AAD that binds at least:

- repository UUID;
- object type and format version;
- object identity, such as chunk ID or snapshot UUID;
- storage epoch for epoch-specific objects such as snapshots and validation caches;
- snapshot generation and parent identity where applicable;
- journal session UUID and record sequence where applicable;
- plaintext length and content-encoding flags where applicable.

`crypto_secretstream_xchacha20poly1305` does not accept external AAD for individual messages. Snapshot streams therefore bind the same canonical context through three mechanisms:

1. the wrapped DEK uses the canonical context in its wrapping AAD;
2. the secretstream key is derived from the DEK and the canonical context with the specified HMAC-SHA-256-based KDF;
3. the first stream message contains the canonical context, which must exactly match the expected values.

Writing context into an unauthenticated header alone is not context binding. The exact KDF and canonical context encoding are part of the format specification. Secretstream supplies chained frame authentication and a `FINAL` tag; the final application record additionally commits to the frame count, logical plaintext length, and whole-manifest commitment. Missing `FINAL`, extra frames after `FINAL`, count mismatches, or commitment mismatches are integrity failures.

This design prevents valid objects from being transplanted into a different repository or context without detection. It does not prevent deletion or rollback of an entire valid state.

### 8.5 Password handling and key memory

Passwords must never be accepted through a command-line argument or logged. Supported sources are:

- hidden terminal input for interactive use;
- `--password-file <path>` with documented newline handling and permission checks where the platform supports them;
- `--password-fd <fd>` for scripted input without a temporary file.

A general `CPCP_PASSWORD` environment variable is intentionally omitted because environment exposure is difficult to reason about across platforms. `CPCP_PASSWORD_FILE` may be supported as an explicit configuration convenience.

Secret key material uses a move-only secure buffer with guaranteed library-backed zeroization on destruction. `std::string` must not hold passwords or keys. Locking pages and disabling core dumps are best-effort hardening measures, not portable guarantees. Logs, errors, JSON output, crash reports, and tests must not disclose secret material.

## 9. Object and snapshot formats

### 9.1 Common encrypted envelope

Chunks, snapshots, and journal records use versioned envelopes with:

- a fixed binary magic and version;
- explicit flags and bounded length fields;
- a wrapped DEK and its nonce and authentication tag;
- the context required to reconstruct authenticated context exactly;
- either a single-message payload nonce, ciphertext, and authentication tag, or a secretstream header followed by bounded encrypted frames.

Headers need not be secret, but every security-relevant header field must be authenticated directly or through the context-bound stream key. Parsers must reject inconsistent lengths, unsupported versions, excessive allocations, trailing data, and non-canonical values where the format requires canonical encoding.

A frame length must be checked against the format limit before allocation or reading the frame body. Snapshot parsing must not allocate space proportional to the total snapshot or referenced file size. The disk format uses fixed-width integer fields with an explicitly defined byte order. Native C++ struct layout must never be written directly to disk.

### 9.2 Chunk objects

A chunk object contains the encrypted representation of one plaintext chunk. Compression, when added later, is applied before encryption and recorded in authenticated flags. Content IDs always refer to the original uncompressed bytes.

A chunk is valid for a specific expected ID only when all of the following succeed:

1. structural parsing and length checks;
2. DEK unwrap authentication;
3. payload authentication and decryption;
4. decompression, if indicated, with output limits;
5. plaintext length validation;
6. recomputation and comparison of the keyed chunk content ID.

A matching filename or a valid authentication tag alone is insufficient to establish this full chain. Authentication proves that the ciphertext was produced under the key; recomputing the content ID binds it to the expected plaintext.

### 9.3 Snapshot objects

Snapshots are framed `crypto_secretstream_xchacha20poly1305` streams, not single-message AEAD objects. A whole-snapshot ciphertext is never buffered solely to obtain one authentication tag. Each frame has a format-defined maximum plaintext and ciphertext size and carries a bounded set of logical records.

The logical stream contains, in order:

1. a canonical context record;
2. a small snapshot-header record;
3. root records;
4. bounded entry-batch records;
5. bounded failure-batch records for a partial snapshot;
6. a final summary record carrying `TAG_FINAL`, frame count, logical plaintext length, and the whole-manifest commitment.

The initial record payloads use strict JSON to ease review and debugging, but each batch is parsed independently with bounded memory. A snapshot is not one large JSON document and must not be loaded into a JSON DOM. A later binary record representation requires a new format or payload version and migration tooling.

A frame is passed to the record parser only after its own secretstream authentication succeeds. Parsed records remain **provisional** until the final frame, whole-manifest commitment, and semantic validation complete. Before that point, they must not select a snapshot for normal use, publish another snapshot, restore files, or cause other external side effects. Implementations may process or spool provisional records only through bounded, explicitly temporary state.

This gives snapshot parsing O(frame size + batch size + operation-specific index) memory rather than O(total snapshot size). Secretstream authenticates frame order and continuation; the final application commitment binds the complete logical manifest. The exact commitment algorithm is part of the format specification.

A snapshot header contains:

- schema and format versions;
- repository UUID, storage epoch, snapshot UUID, and generation;
- parent UUID and parent encrypted-object hash when a parent exists;
- creation time, tool version, and optional user tag;
- `complete` or `partial` status;
- the verification policy and counts of objects validated in the current session or accepted from prior evidence;
- summary statistics, repeated and authenticated in the final summary record.

Each root record contains:

- a snapshot-local root index;
- a stable root UUID;
- a unique display label safe for use as one destination path component;
- the original absolute source path and platform information.

Entries describe directories and regular files. Each regular-file entry contains:

- root index and repository-relative path;
- type, plaintext size, and supported metadata;
- file content ID;
- an ordered chunk list with plaintext offsets and lengths;
- source-capture status and any explicit warnings.

Directory entries and roots are represented explicitly. Chunk lists must have contiguous, monotonically increasing offsets whose total length equals the file size. Empty files have an empty chunk list and a well-defined file content ID.

Parent hashes provide lineage and detection of inconsistent history when parents are retained. They are not an external freshness anchor. Retention and pruning rules must define how missing historical parents are interpreted rather than treating every pruned ancestor as corruption.

### 9.4 Paths

Snapshot paths use a portable, UTF-8 representation with `/` separators and preserve the original Unicode code points without normalization. Paths must be relative to a declared root and must not contain absolute prefixes, drive substitutions, `..` components, or empty components.

On POSIX systems, initial releases may reject filenames that cannot be represented as valid UTF-8, but must do so explicitly and never substitute lossy names. Restoration must additionally detect target-platform reserved names, invalid characters, case collisions, and path-length failures.

### 9.5 Recovery journals

Journals allow a backup session to resume without rereading every successfully processed source chunk. They contain sensitive source paths and identities and therefore use authenticated encryption per record.

Each record includes:

- session UUID and monotonically increasing sequence number;
- record type and format version;
- source-root and file identity;
- chunk offset, plaintext length, and content ID for completed chunks;
- a chain value linking the preceding record;
- a checksum for recognizing a physically torn tail in addition to cryptographic authentication.

CRC checksums are only accidental-truncation detection, not adversarial authentication. Sequence numbers, AAD, and chaining provide the authenticated record context.

A journal is a hint, not proof. Resume must validate its schema, session identity, source identity, and referenced objects. A malformed or inconsistent journal may be discarded, causing a fresh scan; it must never cause unverified data to be published.

File ID, size, and modification time are useful change detectors but are not cryptographic proof that a resumed source file is unchanged. Users requiring a fresh end-to-end source comparison must be able to discard resumable state and perform a full read.

## 10. Write, interruption, and resume protocols

### 10.1 Publishing a new immutable object

All new immutable objects follow the same sequence on the repository filesystem:

```text
write a uniquely named file under tmp/
  -> flush file data and metadata to storage
  -> close and reopen or otherwise read back the complete object
  -> authenticate, decode, and verify the chunk content ID or snapshot FINAL and manifest commitment
  -> publish with an atomic no-replace operation
  -> flush every affected parent directory
  -> record publication in the journal when applicable
```

Directory creation and fanout directories are included in the durability protocol. Publishing must not overwrite an existing object. Platform-specific implementations are hidden behind one `PublishImmutable` operation with clearly documented no-replace semantics.

If the final name already exists, cpcp must run full chunk validation before reusing it. If validation fails, the backup reports an integrity error and does not publish a snapshot that references the object.

Read-back may still be served from caches and therefore cannot prove that hardware persisted the bytes. Cache-eviction hints may be offered as hardening, but direct-I/O complexity and claims of physical certainty are not part of the initial implementation.

A flush or write failure invalidates the current temporary object. Retrying the same flush after an error is not sufficient; the implementation must follow platform semantics and rewrite the temporary object when required.

### 10.2 Platform durability contract

The repository-format specification and the platform durability contract are separate normative artifacts. Before native storage backends are considered reliable, M0 must produce `docs/PLATFORM_DURABILITY.md` with one entry for each operation, operating system, filesystem, and tested storage class.

Each entry must record:

| Field | Required content |
| --- | --- |
| Operation | Temporary-file flush, immutable publication, directory-entry persistence, configuration replacement, read-back, or disconnect handling |
| Environment | Operating-system and kernel version, filesystem, mount options where relevant, and local/USB/network storage class |
| API sequence | Exact native calls, flags, handle types, ordering, and error handling |
| Assumed contract | Atomicity, no-replace, flush, directory-entry, and error semantics required from the platform |
| Verification method | Simulator scenario, native conformance test, forced crash, or manual power-loss procedure |
| Observed result | Tested result and date, clearly distinguished from an untested assumption |
| Limitations | Filesystems, devices, and failure modes for which no equivalent guarantee is claimed |

Initial platform requirements are design intent, not measured results:

- **Linux:** specify file and parent-directory `fsync` requirements, select an atomic no-replace publication mechanism supported by the target filesystem, and test at least the declared supported local filesystems. Do not infer identical behavior on every mount or network filesystem.
- **macOS:** specify where `F_FULLFSYNC` is required and test atomic publication and directory-entry behavior explicitly on APFS. POSIX-looking APIs alone are not evidence of equivalent durability.
- **Windows:** specify `FlushFileBuffers` and atomic no-replace or replacement sequences with their write-through behavior. Do not invent an equivalent of POSIX directory `fsync`; record exactly which NTFS guarantees are relied upon and which directory-entry persistence questions remain.

A simulator verifies that cpcp invokes operations in the required order and handles their modeled failures. It cannot establish real filesystem or device durability. Native conformance tests and documented crash tests remain necessary. Unsupported or untested configurations must not be described as providing the same durability assurance as tested ones.

### 10.3 Backup workflow

`backup add` performs the following steps:

1. Discover and lock the repository, parse bounded configuration, and unlock the master key.
2. Build an explicit plan from the requested roots and exclusion rules. Do not follow symbolic links by default.
3. Open each source file before reading identity metadata from that same handle to reduce path-replacement races.
4. Stream fixed-size chunks, computing chunk IDs and the whole-file content ID from the bytes actually read.
5. For each chunk, obtain current-session or acceptable prior verification evidence under the selected policy. Fully validate every existing object without acceptable evidence; otherwise encrypt and publish a new object using the immutable-object protocol.
6. Append and flush the corresponding journal record after the chunk has been published, validated for reuse, or accepted under the standard prior-evidence policy. Record which assurance was used.
7. After finishing the file, compare source identity and change indicators from the open handle. A detected change invalidates that file capture and causes a bounded retry or a reported failure.
8. Construct a snapshot only from file captures that completed without detected errors.
9. Publish the complete snapshot, or a marked partial snapshot only when `--allow-partial` was supplied.
10. Flush the snapshot directory, mark the session finished, and remove session state according to the same crash-safe discipline.

Pre- and post-read metadata comparisons improve detection but do not make a changing file inherently consistent. For important active data, users should quiesce the application or use an operating-system snapshot. cpcp must not describe such backups as application-consistent.

### 10.4 Resume behavior

The unit of retransmission is one chunk. An unfinished temporary chunk is discarded; a previously published chunk can be validated and reused.

Resume must:

- identify the exact session and original source roots;
- reject ambiguous sessions rather than guessing;
- re-establish source file identity before trusting skipped ranges;
- establish current-session or acceptable prior verification evidence for every distinct object required by the new snapshot, according to the selected policy;
- seek to known chunk boundaries when the journal and source checks permit it;
- restart a file or the full scan when identity checks are inconclusive.

Chunk-level resume avoids serializing cipher and hash states and bounds the work lost at an interruption. The goal is to avoid unnecessary source reads, not to guarantee that every source byte is read exactly once under all failure conditions.

### 10.5 Cancellation

`Ctrl-C` sets an atomic notification flag through a platform-appropriate mechanism. The main loop stops at a chunk boundary, leaves previously published objects intact, preserves useful journal state, removes the active temporary file when safe, and returns exit code 130.

Signal handlers and console-control handlers must not perform allocation, logging, filesystem operations, or cryptographic work.

### 10.6 Garbage collection

When deletion is introduced:

1. acquire the exclusive repository lock;
2. authenticate all retained snapshots and compute the complete reachable set;
3. move unreachable objects to `trash/` without deleting them;
4. flush affected directories;
5. delete only after a grace period and a subsequent explicit collection step;
6. never collect objects associated with an active or incomplete session unless reachability rules prove them safe to remove.

Verification never changes chunks or snapshots and must not silently move objects to `trash/` or rename damaged data. The only permitted write is an explicitly requested disposable validation-cache update. Recovery and quarantine operations require separate explicit commands and dry-run output.

## 11. Checking, verification, and restoration

### 11.1 Source comparison: `backup check`

`backup check` answers a deliberately scoped question about source paths relative to one selected snapshot.

Three modes are available:

| Mode | Operations | Meaning of a match |
| --- | --- | --- |
| Default metadata check | Compare type, size, and modification time | Source metadata matches the snapshot; content and repository health were not established |
| `--content` | Stream the source and compare its file content ID | The bytes read from the source match the plaintext identity recorded in the snapshot |
| `--content --verify-repo` | Also authenticate and validate every chunk needed for the matched files | The source matches and the required repository objects passed full content validation at check time |

Results use explicit statuses such as:

- `metadata-match`;
- `content-match`;
- `verified`;
- `changed`;
- `missing`;
- `unreadable`;
- `unsupported`;
- `repository-damaged`.

The human output and JSON report must state the selected snapshot, its complete or partial status, and the exact verification scope. A metadata match must never be displayed as proof of a safe or restorable backup.

`--full` is avoided as a mode name because it is ambiguous about whether source content, repository objects, or both were checked.

### 11.2 Repository verification: `repo verify`

The default verification level checks:

- configuration and key-slot consistency after authentication;
- complete snapshot stream authentication, including `FINAL`, whole-manifest commitment, and schema validity;
- duplicate or inconsistent generations;
- available parent-link consistency;
- presence and basic structural validity of referenced chunks;
- session and temporary-state classification without modifying it.

`repo verify --deep` additionally reads, authenticates, decodes, and recomputes content IDs for every distinct chunk reachable from retained snapshots, bypassing prior validation evidence. Its report states exactly which snapshots and objects were checked. Orphan detection is reported separately from corruption.

Verification never changes chunks or snapshots. It is read-only by default. `--refresh-validation-cache` explicitly records successful results in the disposable cache for the current storage epoch; cache failure does not invalidate an otherwise successful verification and is reported separately.

Any integrity failure returns exit code 4. Verification never repairs, deletes, or quarantines data implicitly.

Deep verification detects corruption observed while it runs; it cannot guarantee that storage will remain healthy afterward. Periodic verification and independent restore tests are therefore operational requirements, not optional marketing features.

### 11.3 Restoration

**Snapshot selection.** `latest` resolves to the highest valid authenticated generation, including a partial snapshot. Inspection commands may display that snapshot with a prominent partial marker. `snapshot restore` refuses any partial snapshot unless `--allow-partial` is explicitly supplied, whether it was selected by generation or by `latest`. It never falls back to an older complete snapshot implicitly.

`latest-complete` is an explicit selector for the highest complete generation. A malformed, unauthenticated, or incomplete newest stream produces an integrity error rather than fallback for either selector. Check commands may compare against a partial snapshot, but their reports must identify it and must not claim whole-root completeness.

**Root-qualified mapping.** `snapshot show` lists every root's snapshot-local index, stable UUID, display label, and original absolute path. Selective multi-root restoration uses `--root <index-or-label> --path <relative-path>`. A bare relative path is accepted only for a single-root snapshot; cpcp does not guess based on the currently unique result of a path lookup.

By default, restored entries are placed under `DEST/<root-label>/<relative-path>` for both full and selective restores. `--strip-root` removes the label component only when the resulting mapping is explicitly selected and collision-free. Original absolute source paths are metadata, never default restore destinations.

`snapshot restore` uses a per-file safe publication protocol:

```text
create a temporary file on the destination filesystem
  -> authenticate and decrypt every required chunk
  -> reconstruct plaintext at the specified offsets
  -> verify the reconstructed whole-file content ID
  -> flush and close the temporary file
  -> apply supported file metadata
  -> atomically publish to the final path only if overwrite policy permits it
```

The default is to refuse overwriting existing paths. `--overwrite` requires confirmation or `--yes`, and `--dry-run` reports planned changes without writing them.

Restoration must constrain every output to the selected destination, reject traversal and absolute paths, and avoid following attacker-controlled symbolic links during path creation. Handle-relative traversal or an equivalent platform mechanism is preferred over repeated path-string checks.

Directory metadata is applied after child entries where necessary. A partial restore or unsupported metadata is reported clearly; a whole directory-tree restore is not claimed to be atomic.

`--strict-metadata` upgrades metadata restoration warnings to the partial-failure exit code. Content verification has no disable switch.

## 12. Metadata policy

### 12.1 Principles

The metadata policy is **record what is supported, restore what is meaningful, and report every loss**.

cpcp does not promise universal metadata preservation. Filesystem metadata differs in availability and semantics, and some values cannot be restored portably. Embedded metadata such as EXIF remains part of the encrypted file content and is preserved whenever the content is preserved.

### 12.2 Initial baseline

| Metadata | Initial policy |
| --- | --- |
| Path and entry type | Required for supported entries |
| File size | Required and authenticated through the manifest |
| Modification time | Store with available precision and restore on all supported platforms |
| POSIX permission bits | Record on POSIX; restore where permitted; do not pretend equivalent Windows semantics exist |
| Windows read-only attribute | Record and restore on Windows; report cross-platform mapping limitations |
| UID, GID, and ownership names | Optional recorded fields; restoration may require elevated privileges and is not part of the baseline promise |
| Access time | Not part of the default assurance level because reading during backup may itself change it |
| Birth time | Record when readily available; restoration is platform-dependent and often impossible |
| Change time | Diagnostic metadata only; not generally restorable |
| ACLs and extended attributes | Later platform-specific work with explicit warnings |
| Hard-link identity | Later work; identical content may still be deduplicated without restoring hard-link topology |
| Symbolic links | Not followed initially; explicit backup and restore support comes after regular files are stable |
| NTFS alternate data streams, macOS resource forks, sparse layout | Later work; file content support must not be conflated with preserving these features |

### 12.3 Timestamp encoding

Every persisted timestamp uses Unix time semantics and a normalized two-field representation:

```text
seconds:     signed 64-bit integer
nanoseconds: unsigned 32-bit integer in the range 0..999,999,999
```

The represented UTC instant is `seconds + nanoseconds / 1,000,000,000` relative to `1970-01-01T00:00:00Z`. Leap seconds are not separately encoded. This representation avoids the approximately 1678–2262 range limit of a single signed 64-bit total-nanoseconds value and covers the valid NTFS range.

Negative timestamps have one canonical representation. For example, half a second before the epoch is `seconds = -1, nanoseconds = 500000000`. An unavailable timestamp uses an explicit presence marker or `null`; zero always means the epoch and never means unknown.

Conversions from NTFS 100-nanosecond ticks and APFS or ext4 nanosecond timestamps must be exact when the source value is representable. The source epoch and conversion arithmetic are fixed in the format specification. Human-readable output uses RFC 3339 with up to nine fractional digits, but display formatting is not the disk encoding.

When a target filesystem cannot represent a value or its precision, cpcp preserves an exact value where possible and otherwise rounds down to the nearest representable target tick according to the normalized timestamp definition. Strict metadata mode reports the adjustment. Local time zones and locale calendars never affect the stored value.

Wall-clock timestamps in validation caches are informational and do not establish freshness. Monotonic clocks may drive timeouts within a running process but are never serialized as persistent timestamps.

## 13. Command-line interface

### 13.1 General rules

The command structure is:

```text
cpcp <resource> <action> [arguments] [options]
```

All commands, documentation, output schemas, and diagnostics are in English. Localization is not a project goal.

Common behavior:

- `--help`, `help`, and `--version` are supported;
- `--` ends option parsing;
- stdout contains command results only;
- stderr contains diagnostics, progress, warnings, and errors;
- non-TTY output disables color automatically;
- `NO_COLOR`, `--plain`, and `--no-color` disable decoration;
- `--json` produces one valid, versioned JSON result on stdout and never starts an interactive prompt;
- `--quiet` suppresses nonessential progress, not errors or integrity warnings;
- scripts can rely on documented exit codes and JSON schema names.

Configuration precedence is:

```text
command line > environment > repository configuration > built-in default
```

Recognized environment variables are limited and documented: initially `CPCP_REPO`, `CPCP_PASSWORD_FILE`, `NO_COLOR`, and `CI`. `CI` implies non-interactive behavior and stable, uncolored output.

### 13.2 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The requested operation completed at the stated assurance level |
| 1 | General runtime or I/O failure |
| 2 | Command usage, argument, or option error |
| 3 | Completed with a reportable partial result: failed backup entries, source differences, unreadable paths, or strict-metadata failures |
| 4 | Authentication-validated data is inconsistent, corrupt, or fails integrity verification |
| 5 | Repository unlocking or authentication failed, including a wrong password or tampered key-slot configuration |
| 130 | User interruption |

If several conditions apply, integrity failure takes precedence over a partial result. Exit code 2 is reserved for invocation errors; a missing repository or unreadable source is a runtime error, not a usage error.

### 13.3 Command examples

```bash
# Create and unlock repositories
cpcp repo init /mnt/backup/cpcp
cpcp repo init /mnt/backup/cpcp --password-file /run/user/1000/cpcp-password
cpcp repo passwd

# Backup and resume
cpcp backup add ~/Documents ~/Photos --repo /mnt/backup/cpcp --tag weekly
cpcp backup add /data --dry-run
cpcp backup add /data --allow-partial --json
cpcp backup add /data --full-source-read --revalidate-all
cpcp backup status --json
cpcp backup resume <session-id>
cpcp backup resume <session-id> --restart-files

# Compare sources with a snapshot
cpcp backup check ~/Documents
cpcp backup check ~/Documents --content
cpcp backup check ~/Documents --content --verify-repo --json
cpcp backup check ~/Documents/a.txt --snapshot 7 --content

# Inspect snapshots
cpcp snapshot list --json
cpcp snapshot show 7
cpcp snapshot diff 6 7 --json

# Restore without implicit overwriting or partial-snapshot fallback
cpcp snapshot restore latest --to ./restored --dry-run
cpcp snapshot restore latest-complete --to ./restored
cpcp snapshot restore latest --to ./restored --allow-partial
cpcp snapshot restore 7 --root 0 --path Documents/a.txt --to ./restored
cpcp snapshot restore 7 --to ./restored --strict-metadata
cpcp snapshot restore 7 --to ./restored --overwrite --yes

# Verify and maintain
cpcp repo verify --json
cpcp repo verify --deep --json
cpcp repo verify --deep --refresh-validation-cache --json
cpcp repo stats --json
cpcp snapshot forget 3 --dry-run
cpcp snapshot forget 3 --yes
cpcp repo gc --dry-run
cpcp repo gc --yes
```

Commands beyond the initial milestone are shown to establish naming and compatibility direction, not to imply that all features will be implemented at once.

### 13.4 JSON contracts

Every machine-readable document includes a schema identifier such as:

```json
{
  "schema": "cpcp.check.v1",
  "snapshot": 7,
  "mode": "content+repository",
  "summary": {
    "total": 1,
    "verified": 1
  },
  "files": [
    {
      "root": 0,
      "path": "Documents/a.txt",
      "status": "verified"
    }
  ]
}
```

Schemas, field meanings, exit codes, and stream behavior are compatibility contracts. Progress never appears in stdout. Sensitive source paths may appear in requested check reports, but passwords, key material, and secret-bearing configuration values never do.

## 14. Implementation architecture

### 14.1 Language and build direction

cpcp uses modern standard C++ with no unnecessary compiler extensions. The initial target is **C++23**, using features such as `std::expected` only when all supported CI toolchains provide them reliably. Newer standardized features may be adopted deliberately as the toolchain baseline advances; novelty alone is not a reason to use a feature.

The build uses CMake and a locked dependency manifest, initially vcpkg with a recorded baseline. Supported compiler and operating-system versions must be explicit in build documentation and CI.

Likely dependencies are:

| Dependency | Purpose |
| --- | --- |
| libsodium | Password derivation, bounded and streamed authenticated encryption, content and configuration authentication, random generation, secure memory |
| CLI11 | Command-line parsing |
| nlohmann/json | Bounded configuration, snapshot record batches, and report serialization |
| Catch2 | Unit and component tests |
| zstd | Optional per-chunk compression in a later milestone |

Dependency additions require a concrete need, license review, and version locking. A dependency is not introduced merely because it is common.

### 14.2 Module boundaries

```text
src/
  main.cpp
  cli/
    command dispatch, option mapping, output schemas, exit-code mapping
  application/
    backup planning and execution, check, restore, verify, snapshot services
  domain/
    repository model, snapshot model, content IDs, error taxonomy, invariants
  repository/
    object envelopes, framed snapshot streams, config, journals, validation caches,
    commit protocol, locking, garbage collection
  crypto/
    libsodium-backed key derivation, wrapping, encryption, hashing, secure buffers
  platform/
    native handles, durable writes, atomic publication, directory sync, terminal input
  storage/
    narrow storage contract shared by native and simulated implementations
tests/
  unit/
  integration/
  simulation/
  fault_injection/
  fuzz/
  compatibility/
tools/
  reference-recoverer/
    independent read-only Python recovery implementation
```

The CLI maps arguments to application requests and formats results. It does not implement repository or cryptographic logic.

Pure planning and validation logic is separated from execution. Native and simulated I/O share the same narrow interfaces so that tests can fail individual operations and model persistence boundaries without changing production protocols.

A future storage interface must not weaken local-filesystem guarantees. Remote backends have different atomicity, consistency, and listing semantics and require their own design rather than an assumed drop-in replacement.

### 14.3 Simulated storage and persistence

M0 includes a deterministic simulated filesystem before the production commit protocol is considered complete. It implements only the narrow operations used by cpcp; it is not a general POSIX reimplementation.

The simulator maintains separate volatile and durable views and supports configurable models for:

- visibility and persistence of file data, metadata, and directory entries;
- atomic no-replace publication and mutable configuration replacement;
- persistence reordering and crashes between adjacent protocol operations;
- torn writes, short reads and writes, and failed or ignored flushes;
- EIO, ENOSPC, permission loss, read-only state, and source or repository disconnects;
- source-file mutation and stale identity metadata;
- independent source and repository devices with different failure schedules.

Small operation sequences can be exhaustively enumerated. Larger schedules use recorded random seeds and must be exactly reproducible. Assertions check R1–R7 after every modeled crash and recovery step, and any counterexample is minimized or preserved as a regression test.

These checks establish properties only under the simulator's stated persistence model. They do not validate native API assumptions, filesystem conformance, hardware behavior, operating-system locking, or real path races. Native tests remain mandatory.

### 14.4 Independent reference recoverer

M1 includes a narrow, read-only Python reference recoverer under `tools/reference-recoverer/`. It is implemented from the published format specification and uses an audited libsodium binding rather than cpcp's C++ reader.

Its initial scope is limited to:

- bounded configuration parsing and repository unlocking;
- framed snapshot authentication through `FINAL` and manifest commitment validation;
- chunk authentication, content-ID verification, and whole-file reconstruction;
- regular files, directories, and baseline metadata;
- safe destination mapping and refusal to overwrite by default.

It never writes to a repository, updates validation caches, resumes sessions, or performs garbage collection. It is not a dependency of the normal cpcp build or installation.

The recoverer exposes under-specified format details and reduces dependence on a bug-compatible C++ writer and reader. Two implementations by the same author are not an independent security audit and do not prove the specification complete. Python also has weaker secret-memory and zeroization control than the C++ implementation; those limitations must be documented for users handling production keys.

Cross-implementation tests must cover C++-written repositories restored by Python and specification-generated golden vectors consumed by both readers.

### 14.5 Error model

Expected failures use typed results such as `std::expected` with a stable error taxonomy:

- usage;
- authentication;
- retryable I/O;
- permanent I/O;
- unsupported entry or metadata;
- source changed;
- integrity;
- conflict or lock busy;
- cancellation;
- internal error.

Retry policy is driven by error category and bounded attempts. Integrity failures are never retried as though they were transient disconnects. Exceptions may be used for genuinely exceptional failures and resource management, but never cross C API boundaries. The top-level entry point converts remaining exceptions into concise diagnostics and documented exit codes.

Every I/O error preserves the operation, path where safe, native error code, and retry classification. Error messages should tell the user what failed and the next useful action without exposing secrets.

### 14.6 Native I/O and resource ownership

`std::filesystem::path` is used for path composition and native path representation. Critical data paths use native handles and platform APIs where standard streams cannot provide required durability, no-follow, or error semantics.

Implementation rules include:

- RAII for files, directory handles, locks, mappings, and temporary objects;
- move-only ownership for unique resources and secret buffers;
- 64-bit offsets and sizes with checked conversion at API boundaries;
- loops for short reads and writes and documented interruption handling;
- metadata obtained from an opened handle where possible;
- explicit symbolic-link policy at every traversal and restore operation;
- temporary and final objects on the same filesystem for atomic publication;
- no shell command construction for core operations;
- no direct serialization of native structs or uninitialized padding.

Destructors perform only safe, non-throwing cleanup. Commit and rollback state transitions are explicit.

### 14.7 Code style and reviewability

Names should describe domain concepts such as `SnapshotPublisher`, `ChunkValidator`, and `BackupSession` rather than generic helpers. Functions should have one clear responsibility, and security-critical state transitions should be visible in one place.

Comments are normally unnecessary when names and structure are clear. They are appropriate for non-obvious durability requirements, platform workarounds, cryptographic invariants, and surprising behavior that cannot be expressed directly in the code.

Platform conditionals belong in the platform layer. Cryptographic, repository, and application logic must not accumulate scattered operating-system branches.

## 15. Verification strategy

Tests provide evidence for behavior under the fault model; they do not prove that arbitrary hardware can never lose data.

### 15.1 Format and cryptographic tests

- Published library test vectors and known-answer tests for every selected primitive and encoding, including secretstream.
- Golden repository objects and framed snapshots for each format version.
- Wrong-password, wrong-repository, wrong-storage-epoch, wrong-object-type, and wrong-context authentication failures.
- Bit flips, truncation, trailing bytes, oversized frame lengths, and invalid nonces, stream headers, or wrapped keys.
- Chunk swapping, snapshot-frame reordering or duplication, and cross-repository transplantation.
- Confirmation that bounded single-message objects release no plaintext before their authentication tag succeeds.
- Confirmation that a snapshot frame reaches the record parser only after its own authentication succeeds and that parsed records remain provisional until `FINAL`, the frame count, logical length, whole-manifest commitment, and semantic checks all succeed.
- Missing `FINAL`, extra frames after `FINAL`, and final-commitment mismatches must produce integrity errors without snapshot selection, restoration, or other external side effects.
- Synthetic snapshots with very large entry counts must demonstrate bounded memory rather than whole-snapshot ciphertext or JSON DOM allocation.
- Timestamp golden vectors cover the NTFS epoch and range, pre-Unix-epoch normalization, nanosecond boundaries, exact 100-nanosecond conversion, and target-precision rounding.
- Compatibility tests proving that newer builds can read every supported historical format.

### 15.2 Deduplication and comparison tests

- Identical files at multiple paths share objects while retaining independent metadata.
- Changed prefixes, inserted bytes, empty files, and chunk-boundary sizes produce correct references.
- A pre-existing damaged object without acceptable prior evidence fails deduplication validation and cannot enter a new valid snapshot.
- An attacker-created placeholder without acceptable prior evidence cannot cause backup success.
- Instrumentation proves that each distinct object receives at most one full validation per session, including under `--revalidate-all`.
- Standard backups report exactly when prior snapshot or cache evidence is used; `--revalidate-all` bypasses that evidence and detects a currently damaged referenced object.
- Forged, malformed, or wrong-epoch cache entries are never used; deleting the cache causes revalidation without changing repository correctness. Valid replayed entries are treated only as historical evidence, never as current-health proof.
- `--full-source-read` and `--revalidate-all` operate independently and produce accurate verification-scope reports.
- Metadata-only source matches are reported as `metadata-match`, never as content or repository verification.
- Content matching without repository checks is reported as `content-match`, never as `verified`.
- Missing referenced chunks cause `repository-damaged` and exit code 4.

### 15.3 Simulated persistence and fault injection

The M0 simulated filesystem is the primary protocol test environment. It exposes volatile and durable state independently and injects failures at every protocol boundary:

- source open, read, metadata queries, mutation, and disconnect;
- destination create, short write, flush, close, read-back, publish, and directory sync;
- persistence reordering and crashes between every adjacent pair of modelled operations;
- disk full, permission loss, stale handle, lock failure, and ignored flush;
- torn journal records, lost journals, duplicate records, and stale sessions;
- lost, malformed, stale, or wrong-epoch validation caches.

Small sequences are exhaustively enumerated; larger randomized schedules record their seeds and are reproducible. R1–R7 are checked mechanically after every modeled crash and recovery step. Counterexamples become permanent regression cases.

The core scenario is:

```text
begin backup
  -> fail, reorder persistence, or terminate at a seeded step
  -> reopen and verify the repository
  -> resume or restart
  -> compare restored bytes with the original stable source
```

Real subprocess termination tests complement simulation because destructor-only cleanup does not simulate `kill -9` or power loss. Native filesystem conformance tests separately check that the model's atomicity and persistence assumptions match each declared platform. Passing the simulator is not evidence that arbitrary real hardware honors those assumptions.

### 15.4 Filesystem and restoration tests

Use randomized directory trees containing empty files, large files, Unicode names, deep paths, and supported metadata. Test destination traversal, absolute paths, reserved names, case collisions, symbolic-link replacement races, overwrite refusal, and metadata failures.

Multi-root tests include identical root basenames and identical relative paths in different roots. Root-qualified selection, stable root identity, default label mapping, ambiguous bare-path rejection, and collision-free `--strip-root` behavior must all be covered.

Cross-platform tests must compare against the documented support matrix rather than assume every source attribute has a target equivalent. Native durability conformance tests record exact API sequences, filesystem versions, assumptions, and observed results in the platform durability contract; untested platforms are not promoted to equivalent assurance.

Tests for files larger than 4 GiB and offsets beyond 32-bit boundaries are mandatory. Sparse-file efficiency may be deferred, but correctness may not.

### 15.5 CLI and automation tests

Run the built executable as a subprocess and assert:

- help and version behavior;
- every documented exit code;
- stdout and stderr separation;
- JSON validity and schema compatibility;
- no interactive prompt in non-TTY, JSON, or CI modes;
- no ANSI sequences in redirected output;
- dry-run operations cause no filesystem mutation, including validation-cache updates;
- destructive operations and partial-snapshot restores require explicit approval;
- `latest` resolves to a partial snapshot without fallback, restore refuses it without `--allow-partial`, and `latest-complete` selects complete history explicitly;
- ambiguous multi-root paths are rejected and root-qualified restores map to the documented destination;
- default verification performs no writes, while `--refresh-validation-cache` changes only the disposable cache;
- `repo passwd` replaces only the authenticated slot, leaves other slots working, rejects the old password with the updated configuration, and survives crash tests with either a complete old or complete new configuration;
- cancellation returns 130 and leaves a resumable or safely restartable state.

### 15.6 Cross-implementation recovery

- Restore C++-written version 1 repositories with the Python reference recoverer and compare content and supported metadata.
- Consume specification-generated golden configuration, chunk, and framed-snapshot vectors with both implementations.
- Verify wrong-context, missing-`FINAL`, corruption, and traversal cases across both readers.
- Exercise large framed snapshots with bounded memory in the reference recoverer.
- Hash repository contents before and after reference recovery to confirm that the read-only tool performs no repository mutation.
- Treat a disagreement as a specification or implementation defect to resolve explicitly, never as permission for one reader to imitate undocumented behavior of the other.

### 15.7 CI and analysis

CI covers Windows, Linux, and macOS with supported Debug and Release builds. Sanitizer jobs run on platforms and compilers where they are supported:

- AddressSanitizer and UndefinedBehaviorSanitizer in compatible jobs;
- ThreadSanitizer separately for concurrency-sensitive code;
- static analysis such as clang-tidy;
- fuzzing for configuration, envelopes, snapshots, journals, and restore-path validation;
- warnings as errors for project code, with narrowly justified external-dependency exceptions.

CI configurations must not imply that all sanitizers run simultaneously or on every operating system.

## 16. Compatibility and open-source responsibilities

### 16.1 Public contracts

The following require explicit versioning and migration planning:

- repository configuration, object, framed-snapshot, and validation-cache formats;
- snapshot and journal record schemas;
- platform durability assumptions and supported filesystem contracts;
- command and option names;
- exit codes;
- JSON output schemas;
- environment variables;
- stdout and stderr behavior.

The repository format is the strongest compatibility commitment because user data may remain in it for years. Writers reject unsupported newer versions instead of guessing. Readers support every format version claimed by the release, and migrations never destroy the only copy of the old format.

### 16.2 Release discipline

- Keep the MIT license and third-party license notices with distributed artifacts.
- Maintain a security-policy document and a responsible vulnerability-reporting channel.
- Record dependency versions and produce checksums for release artifacts.
- Work toward reproducible builds and authenticated source tags and releases.
- State prominently whether a release has received independent security review.
- Recommend retaining an independent backup and performing restoration drills.

Security reviewers need a precise threat model, format specification, and set of invariants. Ambiguous claims such as “fully secure” or “never loses data” must not appear in project materials.

## 17. Delivery milestones

### M0: reviewed foundations and simulated persistence

- Finalize the threat model, command-success semantics, verification-evidence policy, and version 1 repository-format specification.
- Specify framed snapshots, canonical context derivation, final commitments, timestamp encoding, root identity, and bounded record batches byte for byte.
- Write the initial platform durability contract with explicit assumptions and a native conformance-test plan.
- Establish CMake, locked dependencies, narrow platform/storage interfaces, typed errors, and the test harness.
- Build the deterministic simulated filesystem with volatile and durable views, reorderable persistence, crash points, and reproducible failure schedules before accepting the production commit protocol.
- Implement bounded config parsing, password unlocking, secure key storage, bounded encrypted objects, and framed streams with known-answer tests.

### M1: narrow end-to-end backup and independent recovery

- Regular files and directories on local filesystems.
- Fixed-size chunks, evidence-backed deduplication, full validation of objects lacking acceptable evidence, and a mandatory per-session validation cache.
- `--revalidate-all` for current-session validation of every distinct referenced chunk.
- Framed, encrypted complete snapshots with bounded streaming parsers and no whole-snapshot DOM.
- `repo init`, `backup add`, `snapshot list`, `snapshot show`, `snapshot restore`, and `repo verify`.
- Atomic publication, cancellation, exhaustive small-model crash checks, seeded simulation, and native filesystem conformance tests.
- Baseline path, size, normalized timestamp, and selected permission metadata.
- The read-only Python reference recoverer, cross-implementation restoration tests, and specification-generated golden vectors.

This milestone deliberately favors a complete, testable vertical slice over a broad command surface.

### M2: interruption recovery and meaningful checks

- Encrypted journals, `backup status`, and `backup resume`.
- Partial snapshots through explicit `--allow-partial`, including partial-aware `latest`, `latest-complete`, and restore approval behavior.
- `backup check` metadata, content, and repository-verification modes.
- Deep reachable-chunk verification, explicit validation-cache refresh, and large-file integration tests.

### M3: repository lifecycle and practical performance

- Password-slot replacement semantics, additional key-slot management, and recovery keys.
- Authenticated cross-session validation caches and explicit storage-epoch rotation.
- Exclusion rules, optional zstd compression, statistics, and snapshot differences.
- Snapshot deletion, two-phase garbage collection, and retention rules.
- Incremental source scans with explicit trade-offs and `--full-source-read` as the full-read alternative.
- Expanded metadata and symbolic-link support.

Incremental scans that reuse old chunk lists from size and mtime alone must be labeled as an optimization, not equivalent to rereading source content. Reports must distinguish current-session validation from prior evidence and avoid claiming O(changed data) for full snapshot metadata output.

### M4: advanced capabilities

Each item requires a separate design review:

- content-defined chunking;
- reusable manifest segments or authenticated indexes that reduce full-snapshot metadata rewriting;
- external rollback anchors and signed repository checkpoints;
- operating-system snapshots such as VSS;
- hard-link topology, ACLs, extended attributes, alternate streams, and resource forks;
- object quarantine and salvage tools;
- size padding;
- remote storage backends with backend-specific consistency protocols;
- alternative binary snapshot record payloads for size or parsing performance.

## 18. Initial decisions and remaining questions

### 18.1 Decisions adopted

- Snapshots and chunks are immutable after publication.
- Snapshot publication, not chunk creation, defines backup success.
- R2 accepts current-session validation or policy-approved authenticated prior evidence; objects lacking evidence require full validation.
- A per-session validation cache is mandatory, while cross-session caches are authenticated, epoch-scoped, disposable, and historical rather than freshness proofs.
- `--full-source-read` and `--revalidate-all` provide separate full-read controls; no ambiguous `--paranoid` guarantee is defined.
- Snapshot metadata output remains O(total entry count) until reusable manifest segments or indexes are introduced.
- Snapshots use bounded, context-bound secretstream frames and independently parsed record batches; records remain provisional until authenticated `FINAL` and whole-manifest checks.
- Metadata matching, source-content matching, and repository verification are separate assurance levels.
- Partial snapshots require an explicit option and remain visibly partial. `latest` includes them, restore requires `--allow-partial`, and `latest-complete` is explicit.
- Multi-root restores use root-qualified paths and documented root-label destination mapping.
- `repo passwd` replaces the authenticated password slot by default but does not revoke an old MK or old configuration copy.
- Persisted timestamps use signed seconds since the Unix epoch plus normalized unsigned nanoseconds, not one bounded total-nanosecond integer.
- The platform durability contract is separate from the repository format and distinguishes assumptions from native test results.
- Simulated persistence and deterministic fault injection begin in M0; the narrow read-only Python reference recoverer arrives in M1.
- There is no mutable latest-snapshot pointer and no separate key-check object.
- XChaCha20-Poly1305, secretstream, and Argon2id are the initial cryptographic suite.
- Journals and caches are disposable optimization state.
- Verification never performs implicit repairs; validation-cache refresh is explicit.
- Restore verifies complete file content before final publication.
- Initial implementation targets regular files and directories before platform-specific edge cases.
- C++23 and a small, locked dependency set are the initial engineering baseline.

### 18.2 Questions to resolve before freezing format version 1

- Benchmark 4 MiB, 8 MiB, and 16 MiB chunks for representative source and repository devices.
- Specify canonical context and AAD encodings, integer byte order, the snapshot stream-key KDF, whole-manifest commitment, frame sizes, and record-batch limits byte for byte.
- Select Argon2id calibration targets and upper resource limits for supported platforms.
- Define exact Unicode and non-UTF-8 filename behavior, root-label collision handling, and restore-target mapping for each supported host.
- Define snapshot lineage behavior when retention removes intermediate or parent snapshots.
- Specify journal checkpointing and the safest behavior when resumed source identity is inconclusive.
- Specify the validation-cache encoding, authentication and expiration policy, storage-epoch rotation workflow, and cache behavior during recovery.
- Determine how long validated objects and partial sessions are retained before garbage collection.
- Populate the platform durability contract with native conformance results and declare supported filesystem and storage-class combinations.
- Establish the minimum supported compiler, CMake, Python, and operating-system versions from the CI matrix.

These questions must be resolved through explicit specifications and tests, not left as accidental consequences of implementation details.

## 19. Operating recommendations

Users should:

- follow a 3-2-1 strategy with at least one independent copy;
- avoid developing or testing first against the only copy of irreplaceable data;
- image a failing source disk before repeated backup attempts;
- keep recovery passwords or keys offline and test that they work;
- run scoped deep verification periodically and after storage errors;
- perform actual restore tests on a separate destination;
- monitor storage health without treating SMART status as a guarantee;
- read the verification scope in command reports before treating a backup as trustworthy.

The desired cpcp behavior is conservative: **a smaller, clearly reported result is preferable to an apparently successful backup that cannot be restored.**
