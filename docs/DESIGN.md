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
- **R2: verified references.** Before a snapshot is published, every newly referenced chunk must have passed the chunk validation protocol during that backup session, including chunks reused through deduplication.
- **R3: atomic snapshot publication.** A snapshot becomes visible under its final name only after its complete encrypted object has been written and verified.
- **R4: interruption containment.** An interrupted operation must not alter an existing snapshot. New temporary files, journals, or unreachable objects may remain and can be dealt with safely.
- **R5: optimistic state is never authoritative.** Journals, caches, scan indexes, and lock metadata are performance aids. Their loss may cause more work but must not turn invalid data into a valid backup.
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

A crash after snapshot publication but before the command prints its result can leave the outcome unknown to the caller. The repository must nevertheless be valid, and `snapshot list` must allow the user to determine whether publication occurred.

### 6.3 No silent fallback

If the apparently newest snapshot is malformed, fails authentication, has a duplicate generation, or has invalid references, commands must report an integrity error. They must not silently select an older snapshot and present the repository as healthy.

Read-only commands may still support an explicit diagnostic mode for inspecting older valid snapshots, but that mode must display the integrity failure prominently.

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
  tmp/
    <session-uuid>-<sequence>.part
  trash/
```

`trash/` is used once deletion and garbage collection are implemented. It is not required for the first append-only release.

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
- creation time and cpcp version for diagnostics;
- the fixed chunk size and content-ID algorithm;
- the authenticated-encryption suite;
- password key slots, each with its own Argon2id parameters, salt, wrapped master key, and nonce;
- future recovery-key slots using the same versioned envelope model.

The chunk size, repository UUID, and content-ID algorithm are immutable after initialization. A format migration creates a new format version rather than silently changing these assumptions.

Configuration is plaintext because some of it is needed before a password can be processed, but it is not trusted. Parsing must enforce file-size, nesting, numeric-range, and KDF resource limits before expensive allocation or password derivation.

The master-key wrapping AAD binds the repository UUID, format version, key-slot identifier and type, KDF algorithm, KDF parameters, and salt. These values must be encoded with a specified canonical binary encoding; cryptographic authentication must not depend on JSON whitespace or property order.

No separate key-check ciphertext is needed. Successful authenticated unwrapping of the master key already validates the password and bound configuration fields. A wrong password and a tampered key slot may be indistinguishable and are reported as an authentication failure without claiming which occurred.

Replacing the entire configuration with an older valid copy remains a rollback attack and is outside what local authentication alone can prevent.

## 8. Cryptographic design

### 8.1 Algorithm choice

Version 1 uses libsodium for the cryptographic implementation:

- **Argon2id** for password-based key derivation;
- **XChaCha20-Poly1305** for authenticated encryption;
- **HMAC-SHA-256** with domain separation for chunk and file content IDs;
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

Each encrypted object
  -> fresh random 256-bit data-encryption key (DEK)
  -> DEK wrapped with K_wrap
  -> payload encrypted with the DEK and a fresh random 192-bit nonce
```

A password change only creates a new wrapping of the same MK. It does not rewrite chunks or snapshots.

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

Every payload and wrapped DEK uses AAD that binds at least:

- repository UUID;
- object type and format version;
- object identity, such as chunk ID or snapshot UUID;
- snapshot generation and parent identity where applicable;
- journal session UUID and record sequence where applicable;
- plaintext length and content-encoding flags where applicable.

This prevents valid objects from being transplanted into a different repository or context without detection. It does not prevent deletion or rollback of an entire valid state.

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
- a payload nonce;
- ciphertext and its authentication tag;
- the context required to reconstruct AAD exactly.

Headers need not be secret, but every security-relevant header field must be authenticated. Parsers must reject inconsistent lengths, unsupported versions, excessive allocations, trailing data, and non-canonical values where the format requires canonical encoding.

The disk format uses fixed-width integer fields with an explicitly defined byte order. Native C++ struct layout must never be written directly to disk.

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

Snapshots use the common encrypted envelope. The initial plaintext payload is strict, size-bounded JSON to ease review and debugging. A later binary representation requires a new format or payload version and migration tooling.

A snapshot contains:

- schema and format versions;
- repository UUID, snapshot UUID, and generation;
- parent UUID and parent encrypted-object hash when a parent exists;
- creation time, tool version, and optional user tag;
- `complete` or `partial` status;
- source roots and their platform information;
- entries for directories and regular files;
- an authenticated failure list for partial snapshots;
- summary statistics.

Each regular-file entry contains:

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
  -> authenticate, decode, and verify the expected plaintext identity
  -> publish with an atomic no-replace operation
  -> flush every affected parent directory
  -> record publication in the journal when applicable
```

Directory creation and fanout directories are included in the durability protocol. Publishing must not overwrite an existing object. Platform-specific implementations are hidden behind one `PublishImmutable` operation with clearly documented no-replace semantics.

If the final name already exists, cpcp must run full chunk validation before reusing it. If validation fails, the backup reports an integrity error and does not publish a snapshot that references the object.

Read-back may still be served from caches and therefore cannot prove that hardware persisted the bytes. Cache-eviction hints may be offered as hardening, but direct-I/O complexity and claims of physical certainty are not part of the initial implementation.

A flush or write failure invalidates the current temporary object. Retrying the same flush after an error is not sufficient; the implementation must follow platform semantics and rewrite the temporary object when required.

### 10.2 Backup workflow

`backup add` performs the following steps:

1. Discover and lock the repository, parse bounded configuration, and unlock the master key.
2. Build an explicit plan from the requested roots and exclusion rules. Do not follow symbolic links by default.
3. Open each source file before reading identity metadata from that same handle to reduce path-replacement races.
4. Stream fixed-size chunks, computing chunk IDs and the whole-file content ID from the bytes actually read.
5. For each chunk, either fully validate an existing deduplication target or encrypt and publish a new object using the immutable-object protocol.
6. Append and flush the corresponding journal record only after the chunk has been published or validated for reuse.
7. After finishing the file, compare source identity and change indicators from the open handle. A detected change invalidates that file capture and causes a bounded retry or a reported failure.
8. Construct a snapshot only from file captures that completed without detected errors.
9. Publish the complete snapshot, or a marked partial snapshot only when `--allow-partial` was supplied.
10. Flush the snapshot directory, mark the session finished, and remove session state according to the same crash-safe discipline.

Pre- and post-read metadata comparisons improve detection but do not make a changing file inherently consistent. For important active data, users should quiesce the application or use an operating-system snapshot. cpcp must not describe such backups as application-consistent.

### 10.3 Resume behavior

The unit of retransmission is one chunk. An unfinished temporary chunk is discarded; a previously published chunk can be validated and reused.

Resume must:

- identify the exact session and original source roots;
- reject ambiguous sessions rather than guessing;
- re-establish source file identity before trusting skipped ranges;
- validate every reused object required by the new snapshot;
- seek to known chunk boundaries when the journal and source checks permit it;
- restart a file or the full scan when identity checks are inconclusive.

Chunk-level resume avoids serializing cipher and hash states and bounds the work lost at an interruption. The goal is to avoid unnecessary source reads, not to guarantee that every source byte is read exactly once under all failure conditions.

### 10.4 Cancellation

`Ctrl-C` sets an atomic notification flag through a platform-appropriate mechanism. The main loop stops at a chunk boundary, leaves previously published objects intact, preserves useful journal state, removes the active temporary file when safe, and returns exit code 130.

Signal handlers and console-control handlers must not perform allocation, logging, filesystem operations, or cryptographic work.

### 10.5 Garbage collection

When deletion is introduced:

1. acquire the exclusive repository lock;
2. authenticate all retained snapshots and compute the complete reachable set;
3. move unreachable objects to `trash/` without deleting them;
4. flush affected directories;
5. delete only after a grace period and a subsequent explicit collection step;
6. never collect objects associated with an active or incomplete session unless reachability rules prove them safe to remove.

Verification is read-only. It must not silently move objects to `trash/` or rename damaged data. Recovery and quarantine operations require separate explicit commands and dry-run output.

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
- snapshot envelope authentication and schema validity;
- duplicate or inconsistent generations;
- available parent-link consistency;
- presence and basic structural validity of referenced chunks;
- session and temporary-state classification without modifying it.

`repo verify --deep` additionally reads, authenticates, decodes, and recomputes content IDs for every chunk reachable from retained snapshots. Its report states exactly which snapshots and objects were checked. Orphan detection is reported separately from corruption.

Any integrity failure returns exit code 4. Verification never repairs, deletes, or quarantines data implicitly.

Deep verification detects corruption observed while it runs; it cannot guarantee that storage will remain healthy afterward. Periodic verification and independent restore tests are therefore operational requirements, not optional marketing features.

### 11.3 Restoration

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

Timestamps use signed, fixed-width values with defined units and explicit unavailable markers. Restoring with lower target-filesystem precision is allowed when reported under strict metadata checking.

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

# Restore without implicit overwriting
cpcp snapshot restore latest --to ./restored --dry-run
cpcp snapshot restore 7 Documents/a.txt --to ./restored
cpcp snapshot restore 7 --to ./restored --strict-metadata
cpcp snapshot restore 7 --to ./restored --overwrite --yes

# Verify and maintain
cpcp repo verify --json
cpcp repo verify --deep --json
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
| libsodium | Password derivation, authenticated encryption, content authentication primitives, random generation, secure memory |
| CLI11 | Command-line parsing |
| nlohmann/json | Bounded configuration, snapshot, and report serialization |
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
    object envelopes, config, journals, commit protocol, locking, garbage collection
  crypto/
    libsodium-backed key derivation, wrapping, encryption, hashing, secure buffers
  platform/
    native handles, durable writes, atomic publication, directory sync, terminal input
  storage/
    local-filesystem object access and future backend boundaries
tests/
  unit/
  integration/
  fault_injection/
  fuzz/
  compatibility/
```

The CLI maps arguments to application requests and formats results. It does not implement repository or cryptographic logic.

Pure planning and validation logic is separated from execution. Native I/O and failure injection share narrow interfaces so that tests can fail individual operations without changing production protocols.

A future storage interface must not weaken local-filesystem guarantees. Remote backends have different atomicity, consistency, and listing semantics and require their own design rather than an assumed drop-in replacement.

### 14.3 Error model

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

### 14.4 Native I/O and resource ownership

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

### 14.5 Code style and reviewability

Names should describe domain concepts such as `SnapshotPublisher`, `ChunkValidator`, and `BackupSession` rather than generic helpers. Functions should have one clear responsibility, and security-critical state transitions should be visible in one place.

Comments are normally unnecessary when names and structure are clear. They are appropriate for non-obvious durability requirements, platform workarounds, cryptographic invariants, and surprising behavior that cannot be expressed directly in the code.

Platform conditionals belong in the platform layer. Cryptographic, repository, and application logic must not accumulate scattered operating-system branches.

## 15. Verification strategy

Tests provide evidence for behavior under the fault model; they do not prove that arbitrary hardware can never lose data.

### 15.1 Format and cryptographic tests

- Published library test vectors and known-answer tests for every selected primitive and encoding.
- Golden repository objects for each format version.
- Wrong-password, wrong-repository, wrong-object-type, and wrong-context authentication failures.
- Bit flips, truncation, trailing bytes, oversized lengths, and invalid nonces or wrapped keys.
- Chunk swapping, reordering, duplication, and cross-repository transplantation.
- Confirmation that no plaintext is released from an object before authentication succeeds.
- Compatibility tests proving that newer builds can read every supported historical format.

### 15.2 Deduplication and comparison tests

- Identical files at multiple paths share objects while retaining independent metadata.
- Changed prefixes, inserted bytes, empty files, and chunk-boundary sizes produce correct references.
- A pre-existing damaged object with the expected filename fails deduplication validation and cannot enter a new valid snapshot.
- An attacker-created placeholder with the expected filename cannot cause backup success.
- Metadata-only source matches are reported as `metadata-match`, never as content or repository verification.
- Content matching without repository checks is reported as `content-match`, never as `verified`.
- Missing referenced chunks cause `repository-damaged` and exit code 4.

### 15.3 Fault-injection tests

Inject failures at every protocol boundary:

- source open, read, and metadata queries;
- destination create, short write, flush, close, read-back, publish, and directory sync;
- disk full, permission loss, disconnect, stale handle, and lock failure;
- process termination before and after every publication step;
- torn journal records, lost journals, duplicate records, and stale sessions.

The core scenario is:

```text
begin backup
  -> fail or terminate at a seeded step
  -> reopen and verify the repository
  -> resume or restart
  -> compare restored bytes with the original stable source
```

Randomized schedules must record their seeds and be reproducible. Real subprocess termination tests complement in-process fault injection because destructor-only cleanup does not simulate `kill -9` or power loss.

### 15.4 Filesystem and restoration tests

Use randomized directory trees containing empty files, large files, Unicode names, deep paths, and supported metadata. Test destination traversal, absolute paths, reserved names, case collisions, symbolic-link replacement races, overwrite refusal, and metadata failures.

Cross-platform tests must compare against the documented support matrix rather than assume every source attribute has a target equivalent.

Tests for files larger than 4 GiB and offsets beyond 32-bit boundaries are mandatory. Sparse-file efficiency may be deferred, but correctness may not.

### 15.5 CLI and automation tests

Run the built executable as a subprocess and assert:

- help and version behavior;
- every documented exit code;
- stdout and stderr separation;
- JSON validity and schema compatibility;
- no interactive prompt in non-TTY, JSON, or CI modes;
- no ANSI sequences in redirected output;
- dry-run operations cause no filesystem mutation;
- destructive operations require explicit approval;
- cancellation returns 130 and leaves a resumable or safely restartable state.

### 15.6 CI and analysis

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

- repository configuration and object formats;
- snapshot and journal schemas;
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

### M0: reviewed foundations

- Finalize the threat model, command-success semantics, and version 1 repository-format specification.
- Establish CMake, locked dependencies, platform abstractions, typed errors, and the test harness.
- Implement bounded config parsing, password unlocking, secure key storage, and encrypted envelopes with known-answer tests.

### M1: narrow end-to-end backup

- Regular files and directories on local filesystems.
- Fixed-size chunks, deduplication with mandatory existing-object validation, and encrypted complete snapshots.
- `repo init`, `backup add`, `snapshot list`, `snapshot show`, `snapshot restore`, and `repo verify`.
- Atomic publication, cancellation, and deterministic crash-injection tests.
- Baseline path, size, mtime, and selected permission metadata.

This milestone deliberately favors a complete, testable vertical slice over a broad command surface.

### M2: interruption recovery and meaningful checks

- Encrypted journals, `backup status`, and `backup resume`.
- Partial snapshots through explicit `--allow-partial`.
- `backup check` metadata, content, and repository-verification modes.
- Deep reachable-chunk verification and large-file integration tests.

### M3: repository lifecycle and practical performance

- Password change and recovery-key slots.
- Exclusion rules, optional zstd compression, statistics, and snapshot differences.
- Snapshot deletion, two-phase garbage collection, and retention rules.
- Incremental source scans with explicit trade-offs and a full-read alternative.
- Expanded metadata and symbolic-link support.

Incremental scans that reuse old chunk lists from size and mtime alone must be labeled as an optimization, not equivalent to rereading source content.

### M4: advanced capabilities

Each item requires a separate design review:

- content-defined chunking;
- external rollback anchors and signed repository checkpoints;
- operating-system snapshots such as VSS;
- hard-link topology, ACLs, extended attributes, alternate streams, and resource forks;
- object quarantine and salvage tools;
- size padding;
- remote storage backends with backend-specific consistency protocols;
- binary snapshot payloads for very large repositories.

## 18. Initial decisions and remaining questions

### 18.1 Decisions adopted

- Snapshots and chunks are immutable after publication.
- Snapshot publication, not chunk creation, defines backup success.
- Existing deduplication targets require full validation before reuse.
- Metadata matching, source-content matching, and repository verification are separate assurance levels.
- Partial snapshots require an explicit option and remain visibly partial.
- There is no mutable latest-snapshot pointer and no separate key-check object.
- XChaCha20-Poly1305 and Argon2id are the initial cryptographic suite.
- Journals and caches are disposable optimization state.
- Verification never performs implicit repairs.
- Restore verifies complete file content before final publication.
- Initial implementation targets regular files and directories before platform-specific edge cases.
- C++23 and a small, locked dependency set are the initial engineering baseline.

### 18.2 Questions to resolve before freezing format version 1

- Benchmark 4 MiB, 8 MiB, and 16 MiB chunks for representative source and repository devices.
- Specify canonical AAD encodings, integer byte order, object-length limits, and snapshot size limits byte for byte.
- Select Argon2id calibration targets and upper resource limits for supported platforms.
- Define exact Unicode and non-UTF-8 filename behavior for each supported host and restore target.
- Define snapshot lineage behavior when retention removes intermediate or parent snapshots.
- Specify journal checkpointing and the safest behavior when resumed source identity is inconclusive.
- Determine how long validated objects and partial sessions are retained before garbage collection.
- Establish the minimum supported compiler, CMake, and operating-system versions from the CI matrix.

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
