# cpcp Design and Architecture

> **Status:** Accepted design baseline
>
> **License:** MIT
>
> **Audience:** Contributors, reviewers, and users evaluating cpcp for important data

This document is the authoritative architecture and behavior baseline for implementation. Changes require design review and must update related protocols, commands, tests, and milestones together. Byte-level interoperability details must be moved into versioned format specifications before each corresponding format is frozen.

## 1. Product definition

cpcp is an open-source, cross-platform command-line tool for encrypted, content-addressed backup repositories on local filesystems. It is intended for Windows, Linux, and macOS, with particular attention to backups between separate physical disks and to interrupted transfers.

A repository stores:

- encrypted, immutable content objects;
- encrypted snapshots containing paths, file metadata, and content references;
- encrypted recovery journals for interrupted backup sessions;
- redundant plaintext configuration replicas containing authenticated format parameters and key slots needed to interpret and unlock the repository.

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
| Snapshot | A logical main manifest stream and authenticated summary describing one backup attempt or completed backup |
| Session | One resumable backup operation and its journal |
| Published | Committed for normal use by the object protocol; for snapshots, summary publication rather than the main stream's final name is the commit point |
| Verified | Read back and successfully subjected to the checks explicitly named by the command |
| Verification evidence | A current-invocation validation result or authenticated historical result accepted under the selected policy |
| Storage epoch | A random logical storage generation used to invalidate historical verification evidence after explicit storage replacement or recovery |
| Provisional snapshot data | Records parsed from individually authenticated frames but not yet committed by the stream's authenticated final record |
| Complete snapshot | A snapshot that captured every entry required by its authenticated selection policy without a detected required-entry or repository error |
| Partial snapshot | An explicitly marked snapshot containing the successfully captured required subset and an authenticated failure report |

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
- **R2: evidence-backed, present references.** Before a snapshot is published, every distinct referenced chunk must pass a current metadata check proving that its final path is a regular non-symlink object with the exact expected stored length. It must also either have passed full chunk validation during the current invocation or be covered by prior authenticated verification evidence accepted by the selected policy. Existence and size checks are mandatory; full content revalidation depends on policy.
- **R3: atomic snapshot publication.** Both the complete main stream, including its authenticated final frame, and the bounded summary sidecar must be written and verified. The main object is published first; publishing the summary is the snapshot commit point. A main stream without an active summary is unpublished temporary state.
- **R4: interruption containment.** An interrupted backup must not alter an existing published snapshot. New temporary files, journals, or unreachable objects may remain and can be dealt with safely. Maintenance operations such as quarantine, configuration replacement, and GC follow explicit persistent state machines whose partial states are recoverable and never misrepresented as successful.
- **R5: optimistic state is disposable.** Journals, validation caches, scan indexes, and lock metadata are performance aids. Losing them may cause more work but must not turn invalid data into a valid backup. A cache entry is evidence of an earlier check, never proof of current storage health.
- **R6: verified restoration.** cpcp does not publish a restored file under its final name until its complete reconstructed plaintext passes the expected content verification.
- **R7: guarded deletion.** Garbage collection requires an exclusive repository lock and a two-phase deletion protocol.

These are software invariants, not assertions that a storage device can never corrupt a published object. Repository health must be established by verification at a particular time.

### 6.2 Backup success semantics

By default, `backup add` returns success only when it publishes a **complete snapshot** containing every entry required by the authenticated source-selection policy. “Complete” means complete under that policy; it does not mean that unsupported or explicitly excluded source entries were captured. The summary and command report must make policy-skipped entries and exclusions visible.

If an entry required by policy fails:

- already published chunks remain valid and reusable;
- no snapshot is published by default;
- the session remains resumable when resume support is available and source identity can still be established; earlier milestones without journals leave safely restartable state;
- the command returns the partial-failure exit code and reports every failed path.

An explicit `--allow-partial` option permits publication of a snapshot marked `partial`. A partial snapshot must contain an authenticated list of omitted or failed entries, must be visibly identified by listing and restore commands, and still results in a nonzero partial-failure exit code.

A successful backup is not a new deep verification of the entire repository. Its report must state the verification policy, the number of distinct objects validated in the current invocation, and the number accepted from prior evidence.

A crash after snapshot publication but before the command prints its result can leave the outcome unknown to the caller. The repository must nevertheless be valid, and `snapshot list` must allow the user to determine whether publication occurred.

### 6.3 No silent fallback

If a required check reveals that the apparently newest snapshot or summary is malformed, fails authentication, has a duplicate generation, has an incomplete encrypted stream, or has invalid references, the command must report an integrity error. It must not silently select an older snapshot and present the repository as healthy. A summary-only listing does not prove main-stream health and must state that scope; an operation that requires the main stream must fully validate it before use.

Read-only commands may still support an explicit diagnostic mode for inspecting older valid snapshots, but that mode must display the integrity failure prominently.

### 6.4 Verification evidence and caching

The standard backup policy accepts these forms of evidence for a distinct chunk:

1. successful writing and validation during the current invocation;
2. successful full validation of an existing object during the current invocation;
3. prior introduction into the explicitly selected, fully authenticated base snapshot under the same repository UUID and storage epoch, relying inductively on R2 and a derived evidence index validated against the base summary's chunk-set commitment;
4. an acceptable authenticated cross-session validation-cache entry under the same repository UUID and storage epoch.

An object found only in temporary space, a journal, or an unreachable orphaned object has no snapshot-based evidence and must be fully validated before reuse. A new reference to an already established object is not the same as introducing an unverified object into the repository. Prior-evidence acceptance always includes a current no-follow metadata check against the stored object length carried in the chunk descriptor; a missing, truncated, wrong-type, or wrong-sized object is an integrity failure.

An **in-memory per-invocation object-check cache is mandatory**. Every distinct object receives at most one full validation and at most one current metadata check per invocation, even when many files reference it. The cache key includes at least the repository UUID, storage epoch, chunk ID, stored length, and object format version. It contains no key material or plaintext and is lost when the process exits.

Cross-session validation caches are optional, authenticated, and disposable. A cache entry records at least:

- schema and verifier versions;
- repository UUID and storage epoch;
- chunk ID, stored object length, and object format version;
- verification time;
- an authentication tag from a dedicated cache-authentication key.

Invalid entries must never be used. Deleting the entire cache only causes revalidation. Authentication prevents an attacker without the key from creating new entries, but does not prevent replay of old valid entries.

`verified_at` is an informational wall-clock timestamp, not a freshness proof. A storage epoch is a random logical generation changed by `repo rotate-epoch` after storage replacement or recovery; it is not a trustworthy device serial number and cannot detect an attacker rolling back both configuration and cache. Copying with `cp`, rsync, or ddrescue does not change the epoch automatically. After such a copy, users must run deep verification and explicitly rotate the epoch before trusting old evidence for new backups. Epoch mismatch makes old snapshots valid historical objects but invalidates their prior evidence and causes revalidation. Cache expiration is a verification policy, not a guarantee that an unexpired object remains healthy.

`backup add --revalidate-all` ignores prior snapshots and cross-session caches and fully reads and validates every distinct chunk referenced by the new snapshot once in the current invocation. `backup add --full-source-read` independently disables metadata-only incremental source skipping. These flags provide explicit full-read fallbacks without an ambiguous `--paranoid` assurance claim. Neither option proves correct source-device reads, physical persistence, or continued health after the command finishes.

### 6.5 Incremental complexity

Under the standard policy and after incremental source scanning is implemented, source-content reads are proportional to changed content, and full repository-object content reads are proportional to new objects or objects lacking acceptable evidence. These statements exclude mandatory metadata work.

Every distinct reference in the new snapshot receives a current metadata existence, type, and stored-length check, so repository metadata operations remain O(total distinct referenced chunks). Accepting base-snapshot evidence also requires one full authenticated base-manifest pass and a disk-backed evidence index, which is O(base snapshot metadata). Secretstream requires a full selected-manifest validation pass before check, entry browsing, or selective restore can act on its records.

Incremental source scans reuse a parent file's descriptor spool only when its type, size, normalized mtime, and mode still match. This is explicitly an optimization, not a fresh content comparison. Reused descriptors are copied into the new session's encrypted spool, and every repository object still obtains evidence under the selected policy. Snapshot statistics expose `source_reused_files`; `--full-source-read` disables this optimization independently of `--revalidate-all`.

Authenticated sidecars make snapshot listing and `latest` selection proportional to snapshot count rather than total manifest size. The initial design still writes every entry in every snapshot, so snapshot metadata output remains O(total entry count). cpcp does not claim end-to-end O(changed data) backup. Reusable manifest segments or persistent authenticated indexes are future optimizations.

### 6.6 Source selection and unsupported entries

The selection policy is authenticated in every snapshot. It distinguishes **policy-skipped** entries from **required entries that failed**.

Initial defaults are:

- regular files and directories are selected;
- symbolic links, FIFOs, sockets, device nodes, Windows junctions and unsupported reparse points are skipped with warnings before any attempt to open them;
- cloud placeholders or offline-only files that would trigger recall are skipped unless an explicit future recall option is enabled;
- filenames that cannot be represented without loss are policy-skipped with escaped diagnostics;
- traversal stays on each root's filesystem by default; `--cross-file-systems` opts into mounted or virtual filesystems;
- the target repository is always excluded by identity when it lies inside a source tree, and selecting the repository itself as a source root is an error;
- unsupported entries are never opened merely to discover their type, preventing FIFO blocks and unintended cloud downloads.

`--unsupported=skip` is the default and produces a complete-under-policy snapshot when all required entries succeed. Every skip is recorded with a reason and reported in the command summary. `--unsupported=fail` makes such entries required; failure then follows the normal no-publication or `--allow-partial` rules.

`--exclude <glob>` adds an authenticated root-relative exclusion. Patterns are limited to 512 bytes and support `*` and `?`; `*` may cross directory separators. A matching directory is not traversed. Explicit exclusions remain policy skips even under `--unsupported=fail`, and resume does not duplicate their records. `backup check` reports them as `skipped` rather than verified entries.

A selected regular file that cannot be read because of permissions, locking, I/O errors, or detected mutation is a failed required entry, not an unsupported skip. Explicit user exclusion rules are also policy skips and must be distinguished from unsupported types.

`backup check` reports policy-skipped source entries explicitly and never counts them as verified. Restore and snapshot-inspection commands display the selection policy so that a complete-under-policy snapshot cannot be mistaken for a capture of every object in the original tree.

## 7. Repository model

### 7.1 Layout

The initial layout is:

```text
<repository>/
  cpcp.config.json
  cpcp.config.backup.json
  lock
  chunks/
    ab/cd/<64-lowercase-hex-content-id>
  snapshots/
    <zero-padded-generation>-<uuid>.snap
    <zero-padded-generation>-<uuid>.summary
  sessions/
    <session-uuid>.journal
    <session-uuid>.spool
  cache/
    validation-<storage-epoch>.cache
  tmp/
    <session-uuid>-<sequence>.part
  quarantine/
  trash/
```

`trash/` is used once deletion and garbage collection are implemented. It is not required for the first append-only release. `cache/` is disposable and may be absent or removed between invocations; prior snapshot evidence remains available without it.

There is no mutable `current` pointer. The latest snapshot is derived from authenticated snapshot metadata, not trusted from a filename alone.

`repo probe` is read-only by default. `--write-test` explicitly authorizes creation, flushing, publication, and removal of uniquely named probe files in the target directory; no pre-existing user file is modified. `repo init` accepts only a newly created or empty target directory, performs capability checks before publishing any repository identity, and writes the configuration replicas only after the required directory structure and locking primitives are usable. A failed initialization is not a valid repository and must not be opened or populated with user data until explicitly reinitialized.

### 7.2 Discovery and locking

Repository discovery order is:

1. `--repo <directory>`;
2. `CPCP_REPO`;
3. upward discovery from the current directory only when `--discover-repo` is explicitly supplied;
4. a runtime error if no repository is found.

Discovery recognizes either configuration replica. The selected repository path is shown in verbose output and included in JSON diagnostics so that an unexpected parent repository is not used invisibly.

Locking has separate lifecycle and backup-writer scopes. Normal backup holds a shared lifecycle lock plus the exclusive backup-writer lock: only one backup writer is allowed, but snapshots, restore, status, and verification can read concurrently. Read-only operations hold a shared lifecycle lock, which excludes GC, quarantine, configuration replacement, and epoch rotation but not normal append-only backup. Destructive maintenance and GC require exclusive lifecycle and backup-writer locks.

Validation-cache refresh uses a separate exclusive cache-writer lock and atomic replacement. It never upgrades the shared lifecycle lock; lost or stale disposable cache updates cause extra verification, not repository corruption.

Lock files may contain diagnostics, but correctness depends on operating-system locks rather than stale PID values. Filesystems without reliable required lock semantics are rejected for mutating repository operations. Lock acquisition has a bounded configurable wait and reports lock-busy instead of hanging indefinitely.

For read-only media, read-only commands first attempt the shared lock without creating or modifying repository files. If that is unsupported, `--repo-read-only` permits lockless reading with an explicit warning that the caller must exclude concurrent writers and GC. This mode never repairs configuration, refreshes caches, rotates epochs, or modifies the repository; restore writes only to the destination. The reference recoverer is always repository-read-only and applies the same concurrent-writer warning.

### 7.3 Plaintext configuration

`cpcp.config.json` and `cpcp.config.backup.json` contain the same versioned configuration:

- a magic value, repository-format version, and authenticated configuration revision;
- a randomly generated repository UUID;
- a random storage epoch used to namespace verification evidence;
- creation time and cpcp version for diagnostics;
- the fixed chunk size and content-ID algorithm;
- the authenticated-encryption suite and an authenticated feature-version map for independently versioned journals, caches, retention metadata, and packed objects;
- password key slots, each with its own Argon2id parameters, salt, wrapped master key, and nonce;
- future recovery-key slots using the same versioned envelope model;
- a configuration authentication tag covering the canonical security-relevant configuration, including the storage epoch and key slots.

The chunk size, repository UUID, and content-ID algorithm are immutable after initialization. The storage epoch changes only through an explicit storage-replacement or recovery operation that updates the authenticated configuration and invalidates prior verification evidence. Epoch rotation does not change object encryption and does not require rewrapping every key slot. A format migration creates a new format version rather than silently changing these assumptions.

Configuration is plaintext because some of it is needed before a password can be processed, but it is not trusted. Parsing must enforce file-size, nesting, numeric-range, and KDF resource limits before expensive allocation or password derivation.

Initialization writes two independently flushed and atomically published replicas. Every configuration update increments the authenticated revision and updates both through temporary files and directory synchronization. A crash may leave different valid revisions; cpcp selects the highest valid revision, reports the mismatch, and never claims that replication is atomic across both files. If exactly one replica is missing, unreadable, or fails authentication, the remaining valid replica can be used with a prominent warning. `repo verify` checks both, and `repo repair-config` restores the missing or invalid replica from an explicitly selected valid one. `repo export-header` exports an authenticated configuration copy for offline disaster recovery. `repo import-header <file> --repo <directory>` restores it when both normal replicas are unavailable: it authenticates the configuration after unlocking, checks repository identity and feature support, refuses to overwrite a conflicting valid configuration without explicit approval and revision comparison, and writes both replicas through the normal protocol. Exported headers enable offline password guessing just like repository configuration and must be protected accordingly.

Redundancy protects against a single lost or damaged file, not deletion of both replicas or rollback to an older valid configuration.

The master-key wrapping AAD binds the repository UUID, format version, key-slot identifier and type, KDF algorithm, KDF parameters, and salt. After unlocking the master key, cpcp verifies the configuration authentication tag with a dedicated derived key before trusting the storage epoch, chunking parameters, or other bound fields. These values must be encoded with a specified canonical binary encoding; cryptographic authentication must not depend on JSON whitespace or property order.

No separate key-check ciphertext is needed. Successful authenticated unwrapping of the master key already validates the password and bound configuration fields. A wrong password and a tampered key slot may be indistinguishable and are reported as an authentication failure without claiming which occurred.

Replacing the entire configuration with an older valid copy remains a rollback attack and is outside what local authentication alone can prevent.

## 8. Cryptographic design

### 8.1 Algorithm choice

Version 1 uses libsodium for the cryptographic implementation:

- **Argon2id** for password-based key derivation;
- **XChaCha20-Poly1305** for bounded single-message authenticated encryption;
- **`crypto_secretstream_xchacha20poly1305`** for framed snapshot streams;
- **HMAC-SHA-256** with domain separation for content IDs and configuration or validation-cache authentication;
- **SHA-256** for ciphertext digests that bind snapshot summaries to their framed payload objects;
- **libsodium subkey derivation** with distinct contexts for master-key purposes;
- **the operating-system CSPRNG through libsodium** for keys, salts, nonces, and identifiers.

XChaCha20-Poly1305 uses 192-bit nonces, making random nonces substantially easier to manage in a long-lived repository containing many independently encrypted objects. It also allows cpcp to use one audited library for password derivation, authenticated encryption, random generation, and secure-memory operations.

The format records algorithm identifiers explicitly. A future AES-based suite would require a new version and interoperability tests; it must not be introduced by changing the meaning of an existing identifier.

cpcp must never implement cryptographic primitives itself. Random-generator failure is fatal. Nonce generation and key generation must use the library APIs directly, and every nonce and wrapped master key must be treated as repository-format data requiring validation.

Objects do not carry individually wrapped DEKs. Domain-separated subkeys and XChaCha20-Poly1305's large random nonces already provide the required object encryption boundary. Per-object key wrapping would add format and recovery complexity without providing revocation or limiting the impact of an MK compromise.

### 8.2 Key hierarchy

```text
password
  -> Argon2id(slot salt and parameters)
  -> KEK
  -> XChaCha20-Poly1305 unwrap
  -> random 256-bit repository master key (MK)

MK
  -> subkey derivation, chunk-encryption context -> K_chunk
  -> subkey derivation, snapshot-encryption context -> K_snapshot
  -> subkey derivation, journal-encryption context -> K_journal
  -> subkey derivation, content-ID context -> K_id
  -> subkey derivation, configuration-authentication context -> K_config
  -> subkey derivation, validation-cache-authentication context -> K_cache

Each bounded chunk or summary object
  -> purpose-specific subkey, fresh random 192-bit nonce, and canonical AAD

Each snapshot stream
  -> K_snapshot with a fresh random secretstream header
  -> canonical object and frame context supplied as AAD to every frame
```

`repo passwd` replaces the password slot used to authenticate the command by default. It generates a new salt, KEK, and wrapping nonce while preserving the same MK and all other key slots. Adding another password or removing a different slot requires a separate explicit key-slot operation; it is never a hidden side effect of `passwd`.

Each updated configuration replica, including its new configuration authentication tag, is atomically replaced so that a crash leaves complete old or new files, possibly at different revisions. Replica selection follows §7.3 and reports any mismatch. After successful replacement of both replicas, the old password no longer unlocks the updated configuration unless another slot still uses it.

This is not cryptographic revocation. A running process may retain the unlocked MK, and anyone possessing an old configuration copy can use its old password slot to recover the same MK and decrypt current objects. A compromised old password or MK therefore requires master-key rotation, initially by creating a new repository with new keys and re-encrypting the data. Password-change documentation must state this limitation explicitly.

Key slots allow later recovery-key support without changing the data-encryption design. Recovery keys must be high-entropy random values, displayed only when explicitly requested, and intended for offline storage.

Every key-slot mutation must leave at least one verified usable slot capable of unwrapping the same MK. Adding a slot validates its wrapped MK before either configuration replica changes. Removing the authenticated or last remaining slot is refused unless another slot has been positively verified. As with password changes, removing a slot does not revoke copies of older configurations.

Argon2id parameters are stored per slot. Defaults should be calibrated against documented time and memory targets during initialization, with a conservative minimum and an upper resource limit. cpcp must not silently lower the selected parameters on failure. Parameters calibrated on a high-memory machine may be unusable on another machine; unlocking then fails with the required resources and remedy. Users can choose conservative values with `repo init --kdf-memory` and `--kdf-iterations`, or deliberately rewrap a slot with different parameters through `repo passwd` on a machine that can unlock it. No unauthenticated runtime override can downgrade the KDF.

### 8.3 Content IDs and domain separation

Content IDs are calculated over uncompressed plaintext or canonical plaintext descriptors:

```text
chunk_id = HMAC-SHA-256(
  K_id,
  "cpcp.chunk.v1" || uint64_le(plaintext_length) || plaintext
)

file_content_id = HMAC-SHA-256(
  K_id,
  "cpcp.file.v1" || uint64_le(file_length) || uint64_le(chunk_count) ||
  repeated(chunk_id || uint32_le(plaintext_chunk_length))
)
```

The exact byte encoding is part of the repository-format specification. `file_length` is the number of bytes actually captured, not a pre-read size hint. The file ID is a second-level commitment to the ordered chunk descriptors; each referenced chunk still requires its own plaintext identity validation before restoration.

This construction avoids serializing library-specific HMAC state. During the initial backup, chunk IDs are generated from the source stream and retained in the session journal or disk-backed entry spool. On resume, already committed descriptors can be reused after their required source and repository checks, and the final file ID is calculated from the complete descriptor sequence without rereading the source prefix. During restore, the authenticated file header supplies the expected length and chunk count, so the file ID can be calculated incrementally as chunk descriptors arrive.

Chunk IDs provide deduplication and an expected plaintext identity. They do not authenticate an existing stored object merely because its filename matches. Full validation requires reading, authenticating, decompressing when applicable, and hashing the reconstructed plaintext.

### 8.4 Authenticated context

For bounded single-message objects, the payload uses AAD that binds at least:

- repository UUID;
- object type and format version;
- object identity, such as chunk ID or snapshot UUID;
- the object's own storage epoch for epoch-specific objects such as snapshots and validation caches;
- snapshot generation and parent identity where applicable;
- journal session UUID and record sequence where applicable;
- plaintext length and content-encoding flags where applicable.

`crypto_secretstream_xchacha20poly1305_push()` and `pull()` accept per-message additional data. Every snapshot frame therefore supplies the canonical snapshot context, frame index, and record type directly as AAD. The first frame also contains the canonical context as a semantic cross-check. No custom context-to-key KDF is needed.

The object's authenticated epoch is a historical property of that object. Readers construct expected AAD from the object's declared context and authenticate it; they do not require it to equal the current configuration epoch. A valid old-epoch snapshot remains readable and restorable after verification, but its verification evidence is not accepted for a new snapshot under the current epoch.

Secretstream supplies chained frame authentication and a `FINAL` tag. The final application record carries the frame count, logical plaintext length, final status, and summary statistics. Missing `FINAL`, extra frames after `FINAL`, count mismatches, or semantic-summary mismatches are integrity failures. The bounded snapshot summary sidecar additionally authenticates the complete main ciphertext's SHA-256 digest and stored length, binding the two objects without another custom manifest commitment.

This design prevents valid objects from being transplanted into a different repository or context without detection. It does not prevent deletion or rollback of an entire valid state.

### 8.5 Password handling and key memory

Passwords must never be accepted through a command-line argument or logged. Supported sources are:

- hidden terminal input for interactive use;
- `--password-file <path>` with documented newline handling and permission checks where the platform supports them;
- `--password-fd <fd>` for scripted input without a temporary file.

A general `CPCP_PASSWORD` environment variable is intentionally omitted because environment exposure is difficult to reason about across platforms. `CPCP_PASSWORD_FILE` may be supported as an explicit configuration convenience.

`--password-fd` has platform-specific semantics. On POSIX it is an inherited file descriptor. On Windows it is a C runtime descriptor backed by an explicitly inheritable OS handle, not a numeric `HANDLE` value; the parent is responsible for handle inheritance and the integration tests must cover it. Unsupported inheritance configurations fail rather than hanging or reading from an unintended stream.

Secret key material uses a move-only secure buffer with guaranteed library-backed zeroization on destruction. `std::string` must not hold passwords or keys. Locking pages and disabling core dumps are best-effort hardening measures, not portable guarantees. Logs, errors, JSON output, crash reports, and tests must not disclose secret material.

## 9. Object and snapshot formats

### 9.1 Common encrypted envelope

Chunks, snapshot summaries, snapshot streams, and journal records use versioned envelopes with:

- a fixed binary magic and version;
- explicit flags and bounded length fields;
- the context required to reconstruct AAD exactly;
- either a single-message payload nonce, ciphertext, and authentication tag, or a secretstream header followed by bounded encrypted frames.

Headers need not be secret, but every security-relevant header field must be covered by AAD or another explicitly defined authentication mechanism. Parsers must reject inconsistent lengths, unsupported versions, excessive allocations, trailing data, and non-canonical values where the format requires canonical encoding.

A frame length must be checked against the format limit before allocation or reading the frame body. Snapshot parsing must not allocate space proportional to the total snapshot or referenced file size. The disk format uses fixed-width integer fields with an explicitly defined byte order. Native C++ struct layout must never be written directly to disk.

### 9.2 Chunk objects

A chunk object contains the encrypted representation of one plaintext chunk. Compression, when added later, is applied before encryption and recorded in authenticated flags. Content IDs always refer to the original uncompressed bytes.

A chunk is valid for a specific expected ID only when all of the following succeed:

1. structural parsing and length checks;
2. payload authentication and decryption with the chunk subkey and expected AAD;
3. decompression, if indicated, with output limits;
4. plaintext length validation;
5. recomputation and comparison of the keyed chunk content ID.

A matching filename or a valid authentication tag alone is insufficient to establish this full chain. Authentication proves that the ciphertext was produced under the key; recomputing the content ID binds it to the expected plaintext.

### 9.3 Snapshot streams and authenticated summaries

A logical snapshot consists of two immutable objects with the same snapshot UUID:

- a framed `<generation>-<uuid>.snap` stream with bounded frames and the complete manifest;
- a bounded single-message `<generation>-<uuid>.summary` object containing authenticated selection metadata and a digest of the main stream.

The summary includes repository UUID, the snapshot's own storage epoch, snapshot UUID and generation, originating session UUID, lineage UUID, parent UUID and parent summary ciphertext digest when a parent exists, creation time, complete or partial status, selection-policy summary, root descriptors, entry and chunk counts, verification counts, the main object's stored length, and its SHA-256 ciphertext digest. It also contains a deterministic commitment to the sorted distinct chunk reference set, used to validate a derived prior-evidence index. Constructing that commitment and the backup evidence index may require external sorting in the session spool, not unbounded memory. Exact encodings are part of the format specification.

The main snapshot is a `crypto_secretstream_xchacha20poly1305` stream. Each frame has format-defined maximum plaintext and ciphertext sizes and carries bounded logical records. Its record order is:

1. a canonical context record;
2. a small fixed-identity snapshot-header record;
3. root records;
4. directory and regular-file records, including continuation batches;
5. policy-skipped entry batches and failure batches;
6. a final summary record carrying `TAG_FINAL`, complete or partial status, verification counts, statistics, frame count, and logical plaintext length.

Fields known only after processing, such as status and verification counts, occur in the final record rather than the stream header. The sidecar repeats the values needed for selection and is written only after the complete main stream has been verified. Publishing the sidecar is the snapshot's commit point; a main stream without its sidecar is unpublished temporary state.

The initial record payloads use bounded JSON batches. Batch-level compression flags are present in version 1, with `none` required initially and zstd permitted once implemented. Content IDs use a canonical compact string encoding inside manifests and lowercase hex for external object names and CLI output.

C++ parsing uses a bounded SAX-style reader with explicit depth, string, number, record, and batch limits. Duplicate object keys, invalid UTF-8, non-canonical numbers, and unexpected trailing values are rejected. A whole-snapshot JSON DOM is prohibited. The Python recoverer applies equivalent duplicate-key, depth, and size checks rather than relying on default `json.loads()` behavior.

A frame reaches the record parser only after its own secretstream authentication with the expected frame AAD succeeds. Parsed records remain **provisional** until `FINAL`, final semantics, and the sidecar's main ciphertext digest have all been validated. Before that point they must not restore files, publish another snapshot, or produce a successful user-facing listing. Commands may use a bounded disk spool or a second validated pass to avoid unbounded result buffering.

Authenticated summaries make `snapshot list` and `latest` O(snapshot count) in small sidecar reads, with main-object existence and length checks. Listing output states that only summary-level checks were performed. Full manifest validation is still required before `backup check`, selective restore, or entry browsing. A corrupt newest main stream or summary produces an integrity error on operations that require it; no older snapshot is selected silently.

Each root record contains a snapshot-local root index, stable root UUID, unique display label, original absolute source path, and platform information. The format defines a maximum root count and summary size so that the sidecar remains bounded; an operation exceeding those limits is rejected before snapshot publication.

A regular file is represented by a sequence rather than one unbounded entry:

- a `file-header` record containing root index, relative path, type, captured size, chunk count, file content ID, supported metadata, and capture status;
- zero or more bounded `chunk-batch` records identified by file-entry sequence and monotonically increasing batch number;
- a `file-end` record repeating the chunk count and file content ID.

Each chunk descriptor contains `chunk_id`, plaintext chunk length, and stored object length. Offsets are derived from the fixed chunking rules and preceding descriptor lengths instead of being repeated in JSON. Readers enforce ordering, expected batch numbers, derived offsets, total plaintext length, and final chunk count while streaming. A multi-terabyte file therefore does not require one large manifest entry or an in-memory chunk list.

Empty files have a file header and end record with zero chunks and a well-defined file content ID. Directory entries and roots are explicit. Policy-skipped and failed entries are also authenticated records, with the distinction defined by the source-selection policy.

Parent summary hashes provide lineage and bind each parent to its authenticated main-stream digest. A child inherits its parent's lineage UUID; a parentless snapshot, including the first snapshot or one created with `--no-parent`, creates a fresh lineage UUID and has no parent hash. Parent links are not an external freshness anchor. Retention and pruning rules must define how missing historical parents are interpreted rather than treating every pruned ancestor as corruption.

Main and summary objects must authenticate the same repository UUID, snapshot UUID, generation, and lineage UUID, and those values must match their filenames. A mismatch, duplicate active generation, or ambiguous lineage is an integrity error rather than a reason to guess which object is authoritative.

### 9.4 Paths

Snapshot paths use a portable, UTF-8 representation with `/` separators and preserve the original Unicode code points without normalization. Paths must be relative to a declared root and must not contain absolute prefixes, drive substitutions, `..` components, or empty components.

On POSIX systems, initial releases may reject filenames that cannot be represented as valid UTF-8, but must do so explicitly and never substitute lossy names. Restoration must additionally detect target-platform reserved names, invalid characters, case collisions, and path-length failures.

### 9.5 Session spools and recovery journals

Session spools contain source paths, metadata, failures, and chunk descriptors and therefore receive the same confidentiality protection as journals. Spool batches are bounded, authenticated, and encrypted with `K_journal`, with repository UUID, session UUID, spool version, and batch sequence in AAD. Plaintext session spools are prohibited. Before resume support exists, a leftover spool is discarded under the writer lock and the backup restarts; later resume validates it as untrusted recovery state rather than treating it as repository evidence.

Journals allow a backup session to resume without rereading every successfully processed source chunk. They contain sensitive source paths and identities and therefore use authenticated encryption per record.

Each record includes:

- session UUID and monotonically increasing sequence number;
- record type and format version;
- source-root and file identity;
- chunk offset, plaintext length, content ID, and stored object length for completed chunks;
- a chain value linking the preceding record;
- a checksum for recognizing a physically torn tail in addition to cryptographic authentication.

CRC checksums are only accidental-truncation detection, not adversarial authentication. Sequence numbers, AAD, and chaining provide the authenticated record context.

A journal is a recovery hint, not verification evidence. Its record of an earlier successful validation does not survive as a current-invocation guarantee after a process restart. On resume, objects not covered by the selected base snapshot or an accepted cross-session cache must be fully read and validated again even when their source chunks are skipped. Thus resumption always saves source-device work, but without prior repository evidence it can still reread all previously written repository chunks.

Journal records may be buffered and flushed in bounded groups or at file checkpoints. A crash can lose recent journal records and cause repeated work; correctness still depends on object and snapshot publication. Each durable checkpoint includes the last complete record sequence, and torn or unauthenticated trailing records are discarded without trusting them.

File ID, size, and modification time are useful change detectors but are not cryptographic proof that a resumed source file is unchanged. Users requiring a fresh end-to-end source comparison must be able to discard resumable state and perform a full read.

## 10. Write, interruption, and resume protocols

### 10.1 Publishing a new immutable object

All new immutable objects follow the same sequence on the repository filesystem:

```text
write a uniquely named file under tmp/
  -> flush file data and metadata to storage
  -> close and reopen or otherwise read back the complete object
  -> authenticate, decode, and verify the chunk content ID or snapshot FINAL and final semantics
  -> record the verified main snapshot ciphertext digest when applicable
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

`repo probe` and `repo init` perform capability checks before creating a repository. Required capabilities include suitable 64-bit files, bounded path operations, reliable file flushing, atomic no-replace publication, the declared directory-entry durability contract, and locks for mutation. Optional capabilities such as stable file identity and high-resolution timestamps determine whether optimized resume is available.

The implementation must not assume hard links or a particular `renameat2`, `link+unlink`, or Windows API emulation on every target. FAT and exFAT in particular may lack required atomicity, lock, directory-durability, file-identity, or timestamp properties. Initialization refuses a filesystem that cannot meet the core durability contract; an optional resume capability may be disabled with a clear warning rather than silently trusted. Physical allocation and cluster waste are reported by `repo stats`, especially for small objects on large-cluster filesystems. POSIX allocation uses `st_blocks * 512`; Windows currently uses logical file length as an explicit lower-bound approximation rather than claiming physical cluster accounting.

### 10.3 Backup workflow

`backup add` normally selects the highest valid active summary as its parent and base, including a partial base, and fully validates that base manifest before using prior evidence. `--base <snapshot>` selects an explicit base; `--no-parent` is mutually exclusive and starts without one. A partial base is valid lineage but is never treated as evidence for entries it omitted. An old-epoch base remains a valid parent while its evidence is rejected under the current epoch. A corrupt newest active base blocks default backup until it is explicitly quarantined; `--no-parent` chooses a new lineage but does not bypass active-inventory validation or generation-allocation safety.

Every new snapshot receives one generation above the highest valid active generation. With the default latest parent this equals `parent generation + 1`; an explicitly older base or `--no-parent` still uses the global next generation and never reuses an active number. Snapshot and lineage UUIDs are random, and publication remains no-replace. Duplicate generations, unreadable active summaries, or filename identity mismatches block allocation until explicitly resolved.

`backup add` performs the following steps:

1. Discover and lock the repository, parse bounded configuration replicas, and unlock the master key.
2. Stream the source scan under an explicit selection policy without constructing an in-memory whole-tree plan. Build a bounded-memory, disk-backed session spool for entries, failures, and chunk descriptors. If prior evidence comes from a base snapshot, fully authenticate that base once and build a disposable disk-backed evidence index whose chunk-set commitment matches its summary.
3. Open each selected source file before reading identity metadata from that same handle to reduce path-replacement races. Never open an entry already identified as a non-regular type.
4. Stream fixed-size chunks, computing chunk IDs from the bytes actually read and retaining descriptors in the journal or spool.
5. For each source chunk, inspect the final object path without following links. If it is absent, encrypt and publish a new object even when historical evidence exists; this is the explicit recreation path after quarantine. If it is present with the wrong type or stored length, report integrity failure. If metadata matches, use current-invocation or acceptable prior evidence, fully validating the existing object whenever evidence is unavailable. Reused descriptors without available source bytes cannot recreate a missing object and therefore fail the backup.
6. Checkpoint journal records in bounded groups after the corresponding chunk publications or checks. Record the assurance used for diagnostics without treating the journal itself as evidence after restart.
7. After finishing the file, compare source identity and change indicators from the open handle. A detected change invalidates that file capture and causes a bounded retry or a reported failure.
8. Finalize each file's second-level content ID from its descriptor sequence. Write file-header, continuation, and file-end records to the disk-backed spool; memory remains bounded even for very large files or directory trees.
9. After scanning, determine final status and counts. Stream the spool into a temporary main snapshot, append the authenticated final record, verify the complete main object, and publish it without replacement.
10. Create the bounded authenticated summary containing the main ciphertext digest and reference-set commitment, publish it as the snapshot commit point, flush affected directories, and finish the session.

Pre- and post-read metadata comparisons improve detection but do not make a changing file inherently consistent. For important active data, users should quiesce the application or use an operating-system snapshot. cpcp must not describe such backups as application-consistent.

Snapshot finalization is idempotent within a session. The session records its snapshot UUID and generation before main-stream creation. On resume after a crash before main publication, finalization repeats with a fresh temporary file and no-replace publication. If the expected main object is already present, cpcp fully verifies it against the session spool and recomputes its ciphertext digest instead of treating the name collision as a generic error. It then publishes the matching summary once.

If the summary is already present, cpcp authenticates it, verifies that it binds the same session, UUID, generation, and main digest, and treats the backup as already committed without creating another snapshot. A mismatched main or summary is never overwritten; it requires explicit quarantine or a fresh snapshot UUID. Session completion records and journal deletion occur only after this committed-or-unpublished outcome is unambiguous.

Before journals are introduced, the journal-specific steps are omitted and the encrypted spool supports only the current invocation; an interrupted M1a backup restarts rather than claiming resume.

### 10.4 Resume behavior

The unit of retransmission is one chunk. An unfinished temporary chunk is discarded; a previously published chunk can be validated and reused.

Resume must:

- identify the exact session and original source roots;
- reject ambiguous sessions rather than guessing;
- re-establish source file identity before trusting skipped ranges;
- establish current-invocation or acceptable prior verification evidence for every distinct object required by the new snapshot, according to the selected policy;
- seek to known chunk boundaries only when the journal and source checks permit it;
- relocate a reconnected repository through `--repo` and changed source mount points through explicit `--remap-root <root-uuid>=<new-path>` mappings, never by guessing from a similar directory name;
- restart affected files when device identity changes or a remap makes prior identity evidence inconclusive;
- restart a file or the full scan when identity checks are inconclusive.

Chunk-level resume avoids serializing cipher and hash states and bounds the work lost at an interruption. The goal is to avoid unnecessary source reads, not to guarantee that every source byte is read exactly once under all failure conditions.

`backup discard <session-id>` explicitly abandons resumable state. It requires an inactive session, writer locking, and confirmation or `--yes`; it removes only the session journal, encrypted spool, and owned temporary files. Published chunks and snapshots remain untouched and later GC treats them by normal reachability rules. Discarding a session cannot be used to bypass an integrity failure.

### 10.5 Cancellation

`Ctrl-C` sets an atomic notification flag through a platform-appropriate mechanism. The main loop normally stops at a chunk boundary, leaves previously published objects intact, preserves useful journal state when available, removes the active temporary file when safe, and returns exit code 130. Before journals are introduced, cancellation leaves safely restartable temporary state rather than claiming resumability.

A blocking kernel read, write, or flush may never reach that boundary. Windows implementations use overlapped operations and `CancelIoEx` where supported. POSIX local-file I/O has no universal reliable cancellation or timeout contract; worker isolation, mount or device timeouts, and a final process-termination fallback are platform-specific measures. `--io-timeout` applies only where the native operation supports it and its limitations are documented. A second interrupt may request immediate process termination without cleanup because the publication protocol already makes temporary remnants safe. cpcp must not promise cancellation of an uninterruptible kernel sleep.

Signal handlers and console-control handlers must not perform allocation, logging, filesystem operations, or cryptographic work.

### 10.6 Damage containment and forward recovery

A failed object validation never triggers automatic deletion or renaming during `backup add`. The command reports the object and exits with an integrity error. This avoids turning a transient read error into destructive repair.

M1b provides an explicit `repo quarantine <object>` operation:

- require authentication, exclusive lifecycle and writer locks, `--dry-run` or `--yes`, and a stable object selector such as `chunk:<id>` or `snapshot:<id>`;
- report every retained snapshot known to reference the object;
- for a logical snapshot selector, quarantine its summary first to withdraw publication and then move its associated main stream; crash recovery resumes that sequence and never leaves a quarantined main stream actively selected;
- move the object unchanged into `quarantine/` with the immutable publication and directory-sync protocol;
- record the reason, original and quarantine locations, and transition state in a versioned authenticated maintenance record flushed before the first move; recovery completes the withdrawal sequence rather than rolling objects back automatically;
- leave historical snapshots that referenced it explicitly damaged rather than pretending they are healthy.

For a corrupt or maliciously placed chunk, quarantine frees the final content-addressed name. A subsequent backup with the correct source can fully validate or recreate the chunk and then publish a new snapshot. For a corrupt newest snapshot or summary, quarantine removes it from normal selection while preserving its bytes for diagnosis.

`backup add --no-parent` starts a new authenticated lineage with no parent and no base-snapshot evidence. It does not bypass chunk validation, existence checks, or integrity errors. This provides a forward path when no trustworthy parent can be read; all referenced objects without independent current evidence are fully validated.

A damaged summary may be rebuilt with `repo repair-summary <snapshot>` only after the complete main stream independently passes authentication, final-record, and semantic checks. The command recomputes the main ciphertext digest, quarantines any existing invalid summary as a declared side effect, and publishes the replacement with no-replace semantics; it never overwrites a summary or rewrites the main stream. A damaged main stream cannot be repaired from its summary.

Garbage collection refuses to run if any active retained snapshot or summary is unreadable, if reference enumeration is incomplete, or if `quarantine/` is nonempty. Quarantined data is preserved until a separate explicit purge operation with its own retention and confirmation rules. GC must never “repair” a damaged repository by dropping references it could not enumerate.

### 10.7 Snapshot retirement and garbage collection

`snapshot diff` fully authenticates both selected manifests and compares their union through disk-backed keyed path indexes. It reports `added`, `missing`, `type-changed`, `changed`, and `unchanged`, with separate content-identity and metadata reasons. Reverse traversal emits only `missing` entries so each path appears once. Differences return exit code 3; unchanged files alone return success.

`snapshot forget` retires a logical snapshot without deleting chunks. With exclusive lifecycle and writer locks and explicit confirmation, it persists a maintenance transition record, withdraws the summary first, and moves the summary and main stream into `trash/` for the configured grace period. The retired pair leaves normal `latest`, parent, and retained-reference selection only after summary withdrawal. Missing-parent interpretation and retention behavior must follow the independently versioned retention rules.

Garbage collection then operates on the active retained set:

1. acquire the exclusive repository lock;
2. authenticate all retained snapshots and compute the complete reachable set;
3. move unreachable objects to `trash/` without deleting them;
4. flush affected directories;
5. delete only after a grace period and a subsequent explicit collection step;
6. never collect objects associated with an active or incomplete session unless reachability rules prove them safe to remove.

Verification never changes chunks or snapshots and must not silently move objects to `trash/` or rename damaged data. The only permitted write is an explicitly requested disposable validation-cache update. Recovery and quarantine operations require separate explicit commands and dry-run output.

### 10.8 Throughput and small-object limits

Direct content-addressed objects are deliberately simple but expensive for millions of tiny files: each new object can require a temporary file, file flush, read-back validation, atomic publication, directory synchronization, and a directory entry. Large-cluster filesystems can also waste substantial physical space. M1 is a correctness milestone and does not claim acceptable million-small-file throughput.

Journal group checkpoints reduce logging flushes without weakening object correctness. They do not eliminate required object durability operations, and a directory flush is not treated as a substitute for flushing file contents.

Small-object packing requires a separately versioned pack object, authenticated offset index, chunk locators that distinguish direct and packed storage, crash-safe publication, and GC compaction or pack-retention rules. It is designed and benchmarked after the direct-object vertical slice rather than silently changing v1 chunk addressing. Existing direct objects remain readable. Read-back verification remains enabled; M0 and M1 benchmarks measure its CPU and I/O cost and page-cache behavior rather than disguising cached reads as physical-durability proof.

## 11. Checking, verification, and restoration

### 11.1 Source comparison: `backup check`

`backup check` answers a deliberately scoped question about source paths relative to one selected snapshot, defaulting to `latest` when no snapshot is specified.

Three modes are available:

| Mode | Operations | Meaning of a match |
| --- | --- | --- |
| Default metadata check | Compare type, size, and modification time | Source metadata matches the snapshot; content and repository health were not established |
| `--content` | Stream the source and compare its file content ID | The bytes read from the source match the plaintext identity recorded in the snapshot |
| `--content --verify-repo` | Also authenticate and validate every chunk needed for the matched files | The source matches and the required repository objects passed full content validation at check time |

Results use explicit statuses such as:

- `added` for a source entry absent from the snapshot;
- `missing` for a snapshot entry absent from the source;
- `type-changed`;
- `changed`;
- `metadata-match`;
- `content-match`;
- `verified`;
- `skipped` for an authenticated policy exclusion;
- `unreadable`;
- `unsupported`;
- `unknown` when a required comparison input such as a timestamp is unavailable, with a reason rather than a false match;
- `repository-damaged`.

Recursive comparison uses the union of source and snapshot entries so that added and deleted paths are both detected. By default, a source absolute path is mapped through the snapshot's original root paths. To validate a restored or relocated tree, `backup check <local-directory> --root index:<n>` treats that directory as the selected snapshot root; `--path <relative-path>` can narrow the comparison. This mapping is explicit and does not depend on the original absolute path still existing.

Content checks use the same second-level file ID as backup and restore. A bounded disk-backed descriptor spool may be used for large files; no whole-file or whole-tree report DOM is required. Disposable path indexes use externally sorted fixed-size records keyed by HMAC over the root UUID and relative path; they contain comparison metadata but no plaintext paths. Added, missing, type-changed, unreadable, unsupported, unknown, or policy-skipped entries produce exit code 3 when they are part of the requested comparison.

The human output and JSON report must state the selected snapshot, its complete or partial status, root mapping, and exact verification scope. A metadata match must never be displayed as proof of a safe or restorable backup. In the initial implementation, `--content --verify-repo` validates every chunk referenced by the selected snapshot before scanning the source, which is stronger than validating only matched files; its report includes the selected snapshot's chunk-reference count. Disposable comparison indexes are created outside the repository so read-only checks never create, remove, or timestamp repository files or directories.

`--full` is avoided as a mode name because it is ambiguous about whether source content, repository objects, or both were checked.

### 11.2 Repository verification: `repo verify`

The default verification level checks:

- both configuration replicas, authenticated revision selection, and key-slot consistency after authentication;
- complete snapshot stream authentication through `FINAL`, final-record semantics, sidecar ciphertext-digest validation, and schema validity;
- duplicate or inconsistent generations;
- available parent-link consistency;
- no-follow presence, regular-file type, exact stored-length, and basic structural checks for referenced chunks;
- session and temporary-state classification without modifying it.

`repo verify --deep` additionally reads, authenticates, decodes, and recomputes content IDs for every distinct chunk reachable from retained snapshots, bypassing prior validation evidence. Its report states exactly which snapshots and objects were checked. Orphan detection is reported separately from corruption.

Verification never changes chunks or snapshots. It is read-only by default. `--refresh-validation-cache` explicitly records successful results in the disposable cache for the current storage epoch; cache failure does not invalidate an otherwise successful content verification but produces a partial-result exit code and a separate diagnostic.

Chunk, snapshot, or summary integrity failures return exit code 4; configuration or key-slot authentication failures while unlocking return exit code 5. If one configuration replica is unusable but the other is valid, verification reports degraded redundancy with exit code 3 rather than pretending both replicas are healthy. Verification never repairs, deletes, or quarantines data implicitly.

Quarantine inventory is reported explicitly. Quarantined historical bytes alone are not a new active-object integrity failure, but any active snapshot reference left missing by damage or quarantine is an integrity failure.

Deep verification detects corruption observed while it runs; it cannot guarantee that storage will remain healthy afterward. Periodic verification and independent restore tests are therefore operational requirements, not optional marketing features.

### 11.3 Restoration

**Snapshot selection.** `latest` resolves to the highest valid authenticated generation, including a partial snapshot. Inspection commands may display that snapshot with a prominent partial marker. `snapshot restore` refuses any partial snapshot unless `--allow-partial` is explicitly supplied, whether it was selected by generation or by `latest`. It never falls back to an older complete snapshot implicitly.

`latest-complete` is an explicit selector for the highest complete generation. A malformed, unauthenticated, or incomplete newest stream produces an integrity error rather than fallback for either selector. Check commands may compare against a partial snapshot, but their reports must identify it and must not claim whole-root completeness.

**Root-qualified mapping.** `snapshot show` lists every root's snapshot-local index, stable UUID, display label, and original absolute path. Selective multi-root restoration uses an unambiguous selector such as `--root index:0` or `--root label:Documents` together with `--path <relative-path>`. Labels may contain digits because the selector prefix, not the label content, determines the namespace. A bare relative path is accepted only for a single-root snapshot; cpcp does not guess based on the currently unique result of a path lookup.

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

The default is to refuse overwriting existing paths. `--overwrite` requires confirmation or `--yes`, and `--dry-run` reports planned changes without writing them. A dry-run validates the selected manifest and destination plan but does not imply that every referenced chunk has passed deep content verification; its report states this scope.

Restoration must constrain every output to the selected destination, reject traversal and absolute paths, and avoid following attacker-controlled symbolic links during path creation. Handle-relative traversal or an equivalent platform mechanism is preferred over repeated path-string checks.

Invalid target names, reserved Windows names, and case collisions fail explicitly by default. An opt-in `--sanitize-names` mode may deterministically escape or rename affected components so that content remains recoverable cross-platform. It must write a machine-readable original-to-restored path map, avoid collisions and overwrites, and report that original names were not preserved. Silent lossy renaming is prohibited.

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

Temporary restored files start with the most restrictive practical permissions. The process umask may further restrict initial creation but is never used to compute the stored mode; cpcp applies the final supported mode explicitly after content verification. Directory modes are finalized after their children.

setuid and setgid bits are stripped by default during restore with an explicit warning, and `--strict-metadata` upgrades that warning to the partial-failure result. Restoring them requires an explicit `--restore-privileged-bits` option and sufficient privileges, preventing an untrusted snapshot or destination race from unexpectedly creating privileged executables.

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
- `--json` produces one bounded, valid, versioned JSON result on stdout and never starts an interactive prompt;
- `--ndjson` emits versioned newline-delimited JSON events for potentially large check, listing, or find results, ending with a final summary record when the operation completes;
- `--quiet` suppresses nonessential progress, not errors or integrity warnings;
- scripts can rely on documented exit codes and JSON schema names.

Configuration precedence is:

```text
command line > environment > built-in default
```

Recognized environment variables are limited and documented: initially `CPCP_REPO`, `CPCP_PASSWORD_FILE`, `NO_COLOR`, and `CI`. `CI` implies non-interactive behavior and stable, uncolored output. Repository configuration supplies authenticated format parameters, not implicit runtime preference overrides; any future preferences require a separately documented configuration layer.

### 13.2 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The requested operation completed at the stated assurance level |
| 1 | General runtime or I/O failure |
| 2 | Command usage, argument, or option error |
| 3 | Completed with a reportable partial result: failed backup entries, source differences, unreadable paths, strict-metadata failures, degraded configuration redundancy, or a disposable cache-update failure |
| 4 | A chunk, snapshot, summary, or other repository payload fails AEAD authentication, ciphertext-digest, final-frame, reference, or semantic integrity validation |
| 5 | Password, key-slot, wrapped-master-key, or authenticated-configuration validation fails while unlocking the repository |
| 130 | User interruption |

If several conditions apply, integrity failure takes precedence over a partial result. Exit code 2 is reserved for invocation errors; a missing repository or unreadable source is a runtime error, not a usage error.

### 13.3 Command examples

```bash
# Probe, initialize, and protect repository headers
cpcp repo probe /mnt/backup --json
cpcp repo probe /mnt/backup --write-test --iterations 20 --size 1048576 --json
cpcp repo init /mnt/backup/cpcp --chunk-size 8MiB
cpcp repo init /mnt/backup/cpcp --kdf-memory 256MiB --kdf-iterations 3 \
  --password-file /run/user/1000/cpcp-password
cpcp repo export-header /mnt/other-disk/cpcp-header.json
cpcp repo import-header /mnt/other-disk/cpcp-header.json --repo /mnt/recovered/repo
cpcp repo repair-config --yes
cpcp repo passwd

# Backup and resume
cpcp backup add ~/Documents ~/Photos --repo /mnt/backup/cpcp --tag weekly
cpcp backup add /data --dry-run
cpcp backup add /data --unsupported=fail --allow-partial --json
cpcp backup add /data --full-source-read --revalidate-all
cpcp backup add /data --no-parent
cpcp backup add /data --base 7
cpcp backup status --json
cpcp backup resume <session-id>
cpcp backup resume <session-id> --restart-files
cpcp backup resume <session-id> --repo /media/reconnected/repo \
  --remap-root <root-uuid>=/media/reconnected/data
cpcp backup discard <session-id> --yes

# Compare original or restored sources with a snapshot
cpcp backup check ~/Documents
cpcp backup check ~/Documents --content
cpcp backup check ~/Documents --content --verify-repo --ndjson
cpcp backup check ./restored/Documents --root index:0 --content --verify-repo

# Inspect snapshot roots and entries
cpcp snapshot list --json
cpcp snapshot show 7
cpcp snapshot ls 7 --root index:0
cpcp snapshot find 7 '*.jpg' --ndjson
cpcp snapshot diff 6 7 --json

# Restore without implicit overwriting or partial-snapshot fallback
# Root 0 is ~/Documents here, so a.txt maps to restored/Documents/a.txt.
cpcp snapshot restore latest --to ./restored --dry-run
cpcp snapshot restore latest-complete --to ./restored
cpcp snapshot restore latest --to ./restored --allow-partial
cpcp snapshot restore 7 --root index:0 --path a.txt --to ./restored
cpcp snapshot restore 7 --to ./restored --strict-metadata
cpcp snapshot restore 7 --to ./restored --sanitize-names
cpcp snapshot restore 7 --to ./restored --overwrite --yes

# Verify, isolate damage, and maintain the repository
cpcp snapshot restore latest --repo-read-only --to ./restored
cpcp repo verify --json
cpcp repo verify --deep --json
cpcp repo verify --deep --refresh-validation-cache --json
cpcp repo quarantine chunk:<id> --dry-run
cpcp repo quarantine chunk:<id> --yes
cpcp repo repair-summary 7 --yes
cpcp repo rotate-epoch
cpcp repo key add-password
cpcp repo key remove <slot-id> --yes
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
      "path": "a.txt",
      "size_bytes": "1700",
      "status": "verified"
    }
  ]
}
```

Schemas, field meanings, exit codes, and stream behavior are compatibility contracts. Progress never appears in stdout. Sensitive source paths may appear in requested check reports, but passwords, key material, and secret-bearing configuration values never do.

Commands with potentially unbounded per-file results support `--ndjson`. Each line is an independent versioned JSON value; a header identifies the operation, entry lines carry results, and a final summary is emitted only on completion. Consumers must use the process exit code and final summary rather than treating an interrupted NDJSON prefix as a complete report. `--json` remains the bounded single-document interface and must fail with guidance to use `--ndjson` rather than allocate an unbounded report DOM. The initial snapshot-entry document limit is 4096 entries. `snapshot ls` filters by an optional root and path prefix; `snapshot find` additionally matches the complete root-relative path with `*` and `?` glob wildcards, where `*` may cross directory separators. Both fully authenticate the selected manifest before emitting an entry.

JSON consumers differ in integer precision. Signed and unsigned 64-bit values such as byte sizes, offsets, timestamp seconds, and large counters are represented as canonical decimal strings in public JSON and NDJSON schemas unless a field is explicitly constrained to the exact safe-integer range. This avoids JavaScript precision loss beyond 2^53.

## 14. Implementation architecture

### 14.1 Language and build direction

cpcp uses modern standard C++ with no unnecessary compiler extensions. The initial target is **C++23**, adopting newer standardized features deliberately as the toolchain baseline advances; novelty alone is not a reason to use a feature.

Domain and application interfaces use a project-defined `Result<T>` alias and stable `Error` type. The alias maps to `std::expected` when every supported toolchain provides it reliably and otherwise to a locked compatible implementation such as `tl::expected`. Repository logic does not depend directly on one vendor's expected API.

The build uses CMake and a locked dependency manifest, initially vcpkg with a recorded baseline. Supported compiler and operating-system versions must be explicit in build documentation and CI.

Likely dependencies are:

| Dependency | Purpose |
| --- | --- |
| libsodium | Password derivation, bounded and streamed authenticated encryption, content and configuration authentication, random generation, secure memory |
| CLI11 | Command-line parsing |
| nlohmann/json | Bounded configuration, snapshot record batches, and report serialization |
| Catch2 | Unit and component tests |
| zstd | Optional chunk and snapshot-batch compression in a later milestone |
| tl::expected | Conditional `Result<T>` fallback only when the supported toolchain baseline lacks reliable `std::expected` |

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

M1 includes a narrow, read-only Python reference recoverer under `tools/reference-recoverer/`. It is implemented from the published format specification and uses an audited libsodium binding rather than cpcp's C++ reader. PyNaCl is the initial candidate and exposes the required secretstream push/pull AAD parameters; M0 locks a tested version and verifies Argon2id, HMAC, SHA-256, and secretstream capabilities with vectors. If the maintained binding lacks a required operation, cpcp must not replace it with an unaudited cryptographic implementation or ad hoc `ctypes` wrapper.

Its initial scope is limited to:

- bounded configuration parsing and repository unlocking;
- framed snapshot authentication through `FINAL`, final semantics, and summary ciphertext-digest validation;
- chunk authentication, content-ID verification, and whole-file reconstruction;
- regular files, directories, and baseline metadata;
- safe destination mapping and refusal to overwrite by default.

It never writes to a repository, updates validation caches, resumes sessions, or performs garbage collection. It is not a dependency of the normal cpcp build or installation.

The recoverer exposes under-specified format details and reduces dependence on a bug-compatible C++ writer and reader. Two implementations by the same author are not an independent security audit and do not prove the specification complete. Python also has weaker secret-memory and zeroization control than the C++ implementation; those limitations must be documented for users handling production keys.

Cross-implementation tests must cover C++-written repositories restored by Python and specification-generated golden vectors consumed by both readers.

### 14.5 Error model

Expected failures use the project `Result<T>` alias with a stable error taxonomy:

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

M0 includes a dedicated Windows safe-traversal evaluation. It must determine whether supported component-relative APIs, reparse-point-safe component-wise handles, or a documented native API such as `NtCreateFile` with a root directory handle are appropriate. The choice requires adversarial path tests and must not be left until restore implementation.

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

### 14.7 Concurrency and bounded pipelines

M1 uses a single-threaded correctness-first execution model. A later bounded pipeline may overlap source reads, hashing, compression, encryption, and independent direct-object writes, but it must preserve fixed queue limits and explicit ownership. Secretstream frames remain sequentially produced and authenticated; parallel workers never share a mutable stream state.

Each object publication has one owner responsible for its commit transition. The per-invocation object-check cache, session spool, journal checkpoints, cancellation state, and progress counters require explicit thread ownership or synchronization; lock-free optimism is not accepted without a separate proof and stress tests. Worker failure is propagated to the session without publishing a snapshot from incomplete queues.

`--jobs` and pipeline implementation follow profiling and simulator coverage. ThreadSanitizer tests exercise the actual concurrency model rather than serving as a substitute for protocol reasoning.

The initial bounded pipeline accepts 1–8 workers and parallelizes only pure zstd chunk compression. Each batch holds at most `jobs × chunk_size` source and encoded bytes. Worker tasks have no repository, journal, or mutable-cache access. The owning backup thread consumes results in source order and remains solely responsible for content IDs, object publication, file identity, snapshot frames, journal checkpoints, and statistics. This deliberately does not claim parallel disk writes or lock-free deduplication.

### 14.8 Code style and reviewability

Names should describe domain concepts such as `SnapshotPublisher`, `ChunkValidator`, and `BackupSession` rather than generic helpers. Functions should have one clear responsibility, and security-critical state transitions should be visible in one place.

Comments are normally unnecessary when names and structure are clear. They are appropriate for non-obvious durability requirements, platform workarounds, cryptographic invariants, and surprising behavior that cannot be expressed directly in the code.

Platform conditionals belong in the platform layer. Cryptographic, repository, and application logic must not accumulate scattered operating-system branches.

## 15. Verification strategy

Tests provide evidence for behavior under the fault model; they do not prove that arbitrary hardware can never lose data.

### 15.1 Format and cryptographic tests

- Published library test vectors and known-answer tests for every selected primitive and encoding, including secretstream.
- Golden repository objects and framed snapshots for each format version.
- Wrong-password, wrong-repository, tampered-object-epoch, wrong-object-type, wrong-frame-index, and wrong-context authentication failures; a valid old-epoch snapshot remains readable but supplies no current-epoch evidence.
- Bit flips, truncation, trailing bytes, oversized frame lengths, and invalid nonces, stream headers, or wrapped master keys.
- Chunk swapping, snapshot-frame reordering or duplication, and cross-repository transplantation.
- Confirmation that bounded single-message objects release no plaintext before their authentication tag succeeds.
- Confirmation that a snapshot frame reaches the record parser only after its own authentication succeeds and that parsed records remain provisional until `FINAL`, the frame count, logical length, final semantics, and summary ciphertext digest all succeed.
- Missing `FINAL`, extra frames after `FINAL`, final-semantic mismatches, and summary ciphertext-digest mismatches must produce integrity errors without snapshot selection, restoration, or other external side effects.
- Synthetic snapshots with very large entry counts must demonstrate bounded memory rather than whole-snapshot ciphertext or JSON DOM allocation.
- Second-level file ID vectors cover reordered chunks, changed chunk boundaries, empty files, and resume from descriptor spools without serialized HMAC state or source-prefix rereads.
- Multi-terabyte synthetic file entries use continuation batches with derived offsets and require neither an unbounded manifest record nor an in-memory chunk list.
- Writer tests prove bounded memory through disk-backed spools and place status and verification counts only in final records and summaries.
- A main stream without a summary is unpublished until idempotent finalization verifies the existing session main and publishes its matching summary once; a summary without its matching main is an integrity error. An already published matching summary makes resume report completion without duplication.
- Strict parser tests reject duplicate keys, excessive depth, oversized strings and numbers, invalid UTF-8, and trailing values in both implementations.
- Session-spool tests verify bounded authenticated encryption, no plaintext source paths, tamper rejection, pre-journal restart behavior, and safe idempotent finalization after spool recovery.
- Timestamp golden vectors cover the NTFS epoch and range, pre-Unix-epoch normalization, nanosecond boundaries, exact 100-nanosecond conversion, and target-precision rounding.
- Compatibility tests proving that newer builds can read every supported historical format.

### 15.2 Deduplication and comparison tests

- Identical files at multiple paths share objects while retaining independent metadata.
- Changed prefixes, inserted bytes, empty files, and chunk-boundary sizes produce correct references.
- A pre-existing damaged object without acceptable prior evidence fails deduplication validation and cannot enter a new valid snapshot.
- An attacker-created placeholder without acceptable prior evidence cannot cause backup success.
- Instrumentation proves that each distinct object receives at most one full validation and one metadata check per invocation, including under `--revalidate-all`.
- Standard backups report exactly when prior base-snapshot or cache evidence is used; `--revalidate-all` bypasses that evidence and detects a currently damaged referenced object.
- Prior evidence never bypasses the current metadata check: deleted, truncated, wrong-sized, symlink-replaced, or wrong-type objects produce integrity failures.
- After explicit quarantine, an absent chunk with available correct source bytes is recreated and fully validated even when its ID remains in base evidence; absent source bytes cannot satisfy that reference.
- Forged, malformed, or wrong-epoch cache entries are never used; deleting the cache causes revalidation without changing repository correctness. Valid replayed entries are treated only as historical evidence, never as current-health proof.
- `--full-source-read` and `--revalidate-all` operate independently and produce accurate verification-scope reports.
- Explicit older bases and `--no-parent` allocate the global next generation without collision; partial bases provide no evidence for omitted entries, and ambiguous active generations block allocation.
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
- lost, malformed, stale, or wrong-epoch validation caches;
- interruption between main snapshot and summary publication, between configuration-replica updates, and during quarantine moves;
- corrupt-chunk quarantine and recreation, corrupt-parent quarantine followed by `--no-parent`, and mandatory GC abort when snapshot enumeration or quarantine state is unsafe.

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

Use randomized directory trees containing empty files, large files, Unicode names, deep paths, and supported metadata. Test destination traversal, absolute paths, reserved names, case collisions, symbolic-link replacement races, overwrite refusal, privileged-bit stripping, and metadata failures.

Instrumented source tests prove that FIFOs, sockets, device nodes, unsupported reparse points, symlinks, and cloud placeholders are classified without opening them. Test complete-under-policy snapshots, `--unsupported=fail`, default filesystem boundaries, and mandatory target-repository self-exclusion.

Opt-in name sanitization tests verify deterministic collision-free output and a complete original-to-restored path map; default cross-platform restore never renames silently.

Multi-root tests include identical root basenames and identical relative paths in different roots. Root-qualified selection, stable root identity, default label mapping, ambiguous bare-path rejection, and collision-free `--strip-root` behavior must all be covered.

Cross-platform tests must compare against the documented support matrix rather than assume every source attribute has a target equivalent. Native durability conformance tests record exact API sequences, filesystem versions, assumptions, and observed results in the platform durability contract; untested platforms are not promoted to equivalent assurance.

Tests for files larger than 4 GiB and offsets beyond 32-bit boundaries are mandatory. Sparse-file efficiency may be deferred, but correctness may not.

### 15.5 CLI and automation tests

Run the built executable as a subprocess and assert:

- help and version behavior;
- every documented exit code;
- stdout and stderr separation;
- JSON validity and schema compatibility, canonical decimal strings for 64-bit public values, NDJSON line framing, and absence of a final NDJSON summary after interruption;
- no interactive prompt in non-TTY, JSON, or CI modes;
- no ANSI sequences in redirected output;
- dry-run operations cause no filesystem mutation, including validation-cache updates;
- destructive operations and partial-snapshot restores require explicit approval;
- `latest` resolves to a partial snapshot without fallback, restore refuses it without `--allow-partial`, and `latest-complete` selects complete history explicitly;
- ambiguous multi-root paths are rejected and root-qualified restores map to the documented destination;
- recursive checks report added, missing, type-changed, and policy-skipped entries, and an explicitly mapped restored directory is compared against the selected root;
- read-only commands never modify the repository, and lockless `--repo-read-only` mode emits its concurrency warning while still enforcing all integrity checks;
- default verification performs no writes, while `--refresh-validation-cache` changes only the disposable cache under its separate writer lock;
- configuration-replica crashes leave independently complete old or new replicas, select the highest valid revision with a mismatch warning, and permit explicit repair; authenticated header import restores both replicas without silently overwriting a conflicting valid configuration;
- key-slot mutations verify at least one remaining usable slot, reject last-slot removal, and validate a newly added slot before either replica changes;
- quarantine preserves bytes, allows correct-source chunk recreation or `--no-parent` recovery, refuses unsafe implicit repair, and blocks GC while damage or quarantine state is unresolved;
- `repo passwd` replaces only the authenticated slot, leaves other slots working, rejects the old password after both replicas are updated, and survives mixed-replica crash tests;
- cancellation returns 130 and leaves a resumable or safely restartable state, with native timeout or cancellation limitations tested and reported rather than hidden.

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

- repository configuration replicas, direct objects, framed snapshots, authenticated summaries, encrypted session spools, maintenance transition records, and validation-cache formats;
- snapshot continuation, summary, and journal record schemas;
- platform durability assumptions and supported filesystem contracts;
- command and option names;
- exit codes;
- JSON and NDJSON output schemas;
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

### M0: draft specifications, prototypes, and simulated persistence

- Draft the threat model, command-success semantics, verification-evidence policy, and experimental core repository format without declaring it frozen.
- Prototype framed AAD, snapshot summaries, continuation records, second-level file IDs, and disk-backed spools with known-answer vectors.
- Benchmark direct-object write/read-back costs and candidate chunk sizes on representative devices, including small-file and large-manifest cases.
- Confirm the locked PyNaCl binding's secretstream AAD and password-KDF capabilities, and evaluate Windows safe component traversal before those designs are accepted.
- Write the initial platform durability contract, capability-probe design, and native conformance-test plan.
- Establish CMake, locked dependencies, narrow platform/storage interfaces, `Result<T>`, and the test harness.
- Build the deterministic simulated filesystem with volatile and durable views, reorderable persistence, crash points, and reproducible failure schedules before accepting the production commit protocol.

Experimental repositories use a distinct pre-release format version and may be discarded between milestones; no long-term compatibility promise applies before the core v1 freeze.

### M1a: experimental end-to-end vertical slice

- Regular files and directories under the authenticated selection policy, including safe unsupported-type skips and repository-self exclusion.
- Fixed-size direct chunks, current metadata checks, evidence-backed deduplication, full validation of objects lacking evidence, and a per-invocation object-check cache.
- Second-level file IDs, framed main snapshots, bounded authenticated summaries, chunk-list continuation records, and disk-backed writer spools.
- Redundant authenticated configuration replicas and `repo export-header` / `repo import-header`.
- `repo probe`, `repo init`, `backup add`, `snapshot list`, `snapshot show`, `snapshot restore`, and basic `repo verify` against explicit snapshots.
- `--revalidate-all` for full current-invocation validation of every distinct referenced chunk.
- Safe cancellation without journals, native atomic publication, simulator regression tests, and baseline metadata.
- Read-only repository restore and the explicit root-mapping model.

### M1b: recovery paths, cross-implementation validation, and core v1 freeze

- `repo quarantine`, `repo repair-summary`, `repo repair-config`, and `backup add --no-parent` with preservation and GC-abort semantics.
- The read-only Python reference recoverer, cross-implementation restoration tests, and specification-generated golden vectors.
- Native filesystem capability and conformance tests on the declared support matrix, including read-only media behavior.
- Large-file continuation tests, multi-gigabyte synthetic manifests with bounded memory, strict duplicate-key and depth tests, and direct-object performance reports.
- Resolve all core-format questions in §18.2. Freeze configuration, chunk, main-snapshot, summary, encrypted-session-spool, and maintenance-transition v1 only after both readers consume the user-data vectors and the C++ recovery state machines exercise spool and maintenance records.

Journal, validation-cache, retention, and packed-object formats have independent feature versions and do not block the core v1 freeze.

### M2: interruption recovery and meaningful checks

- Encrypted journals, bounded group checkpoints, `backup status`, `backup resume`, explicit root remapping, and `backup discard`.
- Partial snapshots through explicit `--allow-partial`, including partial-aware `latest`, `latest-complete`, and restore approval behavior.
- `backup check` added, missing, type-changed, content, and repository-verification modes, including restored-tree root mapping.
- `snapshot ls`, `snapshot find`, bounded JSON, and streaming NDJSON reports.
- Deep reachable-chunk verification, explicit validation-cache refresh, and large-file integration tests.

### M3: repository lifecycle and practical performance

- Password-slot replacement, additional key-slot management, and recovery keys.
- Authenticated cross-session validation caches and `repo rotate-epoch`.
- Exclusion rules, zstd chunk and snapshot-batch compression, statistics, and snapshot differences.
- Snapshot deletion, two-phase garbage collection, quarantine purging, and retention rules.
- Incremental source scans with explicit trade-offs and `--full-source-read` as the full-read alternative.
- Bounded concurrency and `--jobs` after profiling and simulator coverage.
- A separately versioned small-object pack format if benchmarks justify it, with authenticated indexes and GC compaction.
- Expanded metadata, symbolic links, and opt-in cross-platform name sanitization.

Incremental scans that reuse old chunk lists from size and mtime alone must be labeled as an optimization, not equivalent to rereading source content. Reports distinguish current-invocation validation from prior evidence and include the mandatory O(total references) metadata checks and full-manifest costs.

### M4: advanced capabilities

Each item requires a separate design review:

- content-defined chunking;
- reusable manifest segments or authenticated indexes that reduce full-snapshot metadata rewriting;
- external rollback anchors and signed repository checkpoints;
- operating-system snapshots such as VSS and explicit cloud-recall policies;
- hard-link topology, ACLs, extended attributes, alternate streams, and resource forks;
- damaged-object salvage and advanced recovery tools;
- size padding;
- remote storage backends with backend-specific consistency protocols;
- alternative binary snapshot record payloads for size or parsing performance.

## 18. Initial decisions and remaining questions

### 18.1 Decisions adopted

- Published chunks and snapshot objects are immutable; explicit quarantine preserves bytes while changing their active location.
- Publishing the authenticated snapshot summary, not creating a chunk or main stream, defines snapshot commit.
- Snapshot finalization is idempotent by session UUID; an existing valid main is verified and summarized once, and an already committed summary is never duplicated.
- Default parent and base selection is explicit, partial and old-epoch bases have defined evidence rules, and generation allocation refuses ambiguity rather than guessing.
- Encrypted session spools never expose source paths or metadata in plaintext temporary files.
- File identity is a second-level HMAC over ordered chunk descriptors, allowing chunk-granular resume without serializing native HMAC state.
- R2 combines current existence, type, and stored-length checks with current-invocation validation or policy-approved prior evidence.
- Base-snapshot evidence comes from one explicitly selected authenticated base and a derived index checked against its summary commitment.
- Per-invocation object checks are cached once per distinct object; cross-session caches are authenticated, epoch-scoped, disposable, and never freshness proofs.
- `--full-source-read` and `--revalidate-all` provide separate full-read controls; no ambiguous `--paranoid` guarantee is defined.
- Standard backups still perform O(total distinct references) metadata checks and O(base manifest) evidence work; end-to-end O(changed data) is not claimed.
- Main snapshots use bounded secretstream frames with native per-frame AAD; summaries bind the main ciphertext digest and enable efficient listing and `latest` selection.
- Large files use chunk-list continuation records, and both snapshot writing and parsing use bounded memory with disk-backed spools.
- No per-object DEK wrapping or custom secretstream context KDF is used.
- Damage recovery uses explicit quarantine, summary rebuilding, and `--no-parent`; GC aborts when references cannot be enumerated safely.
- Complete snapshots are complete under an authenticated selection policy; unsupported skips and required failures are distinct.
- The target repository is automatically excluded from its own source tree, and non-regular entries are not opened to discover their behavior.
- Redundant authenticated configuration replicas and offline header export/import reduce the configuration single point of failure.
- Every key-slot mutation leaves at least one positively verified slot that unwraps the same MK; last-slot removal is forbidden.
- Read-only recovery can operate without repository writes or locks under an explicit concurrency warning.
- Metadata matching, source-content matching, and repository verification are separate assurance levels.
- Partial snapshots require an explicit option and remain visibly partial. `latest` includes them, restore requires `--allow-partial`, and `latest-complete` is explicit.
- Multi-root operations use prefixed root selectors and documented destination mapping; restored trees can be checked against a selected root.
- `repo passwd` replaces the authenticated password slot by default but does not revoke an old MK or old configuration copy.
- Persisted timestamps use signed seconds since the Unix epoch plus normalized unsigned nanoseconds.
- Filesystem capabilities are probed at initialization; unsupported core durability semantics are rejected rather than silently degraded.
- Direct-object small-file limits are documented; packed objects require a separate format and GC design.
- Simulated persistence begins in M0, an experimental vertical slice is split into M1a and M1b, and core v1 freezes only after reference recovery and native validation.
- There is no mutable latest-snapshot pointer and no separate key-check object.
- Verification never performs implicit repairs; validation-cache refresh is explicit and separately locked.
- Restore verifies complete file content before final publication.
- C++23, a project `Result<T>` abstraction, and a small locked dependency set are the engineering baseline.

### 18.2 Questions to resolve before freezing core format version 1

- Benchmark candidate chunk sizes and direct-object read-back costs on representative source and repository devices.
- Specify canonical AAD encodings, integer byte order, frame AAD, frame sizes, record batches, continuation semantics, final records, summary ciphertext digests, and chunk-set commitments byte for byte.
- Specify encrypted-spool and maintenance-transition records, session-bound idempotent finalization, lineage and parent-summary hashes, and generation allocation byte for byte.
- Select Argon2id calibration targets, explicit override options, and upper resource limits for supported platforms.
- Define exact Unicode and non-UTF-8 filename behavior, root-label collision handling, and restore-target mapping for each supported host.
- Specify configuration revisions, replica selection and repair, offline header export, and the authenticated storage-epoch field.
- Define old-epoch snapshot readability and evidence invalidation vectors.
- Lock and test the Python binding version against all required crypto and framed-stream vectors.
- Populate the platform durability contract with native conformance results and declare supported filesystem and storage-class combinations.
- Establish the minimum supported compiler, CMake, Python, libsodium, and operating-system versions from the CI matrix.

### 18.3 Feature-specific questions with independent format versions

Before journal v1: specify checkpointing, root remapping, source identity after reconnection, and behavior when resumed identity is inconclusive.

Before validation-cache v1: specify encoding, authentication, expiration, concurrent replacement, and epoch-rotation interaction.

Before retention and GC: specify snapshot lineage after pruning, quarantine retention and purge, incomplete-session references, and packed-object reachability.

Before packed objects: specify authenticated indexes, chunk locators, publication, compaction, crash recovery, and migration from direct objects.

These questions must be resolved through explicit specifications and tests, not left as accidental consequences of implementation details.

## 19. Operating recommendations

Users should:

- follow a 3-2-1 strategy with at least one independent copy;
- avoid developing or testing first against the only copy of irreplaceable data;
- image a failing source disk before repeated backup attempts;
- keep recovery passwords or keys offline and test that they work;
- export an authenticated repository header to an independent device and check both configuration replicas;
- after copying or imaging a repository, run deep verification and explicitly rotate its storage epoch before relying on prior validation evidence for new backups;
- run scoped deep verification periodically and after storage errors;
- perform actual restore tests on a separate destination;
- monitor storage health without treating SMART status as a guarantee;
- read the verification scope in command reports before treating a backup as trustworthy.

The desired cpcp behavior is conservative: **a smaller, clearly reported result is preferable to an apparently successful backup that cannot be restored.**
