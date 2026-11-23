# cpcp Key Slots and Storage Epochs

> Status: Implemented multi-slot configuration v2 and epoch rotation

## 1. Compatibility and feature versioning

Original repositories have one password slot and use the `cpcp.config.v1` authentication encoding. They remain readable without migration. Any key-slot mutation or epoch rotation sets `feature_versions.key_slots = 1` and uses `cpcp.config.v2`. The configuration format version and object-encryption master key do not change.

Every slot has a unique ID, type (`password` or `recovery`), Argon2id parameters, salt, and wrapped master key. At most 64 slots are accepted. Per-slot KDF parameters are authenticated and are never lowered implicitly. The top-level initial KDF object remains for compatibility; slots carry their own parameters in multi-slot configurations.

Master-key wrapping AAD remains:

```text
"cpcp.master-key.v1" || repository_uuid || format_version_u32_le
|| text(slot_id) || text(slot_type) || "argon2id"
|| memory_kib_u64_le || iterations_u64_le || salt
```

`text` is a length-prefixed UTF-8 value. A new slot is unwrapped and checked against the same master key before either configuration replica changes.

## 2. Multi-slot authentication encoding

The v2 tag is HMAC-SHA-256 with K_config over:

```text
"cpcp.config.v2"
|| format_version_u32_le || revision_u64_le
|| repository_uuid || storage_epoch
|| created_seconds_i64_le || created_nanoseconds_u32_le
|| chunk_size_u32_le || text(cipher_suite) || text(hash_algorithm)
|| feature_count_u64_le
|| repeated(text(feature_name) || feature_version_u64_le)
|| slot_count_u64_le
|| repeated(
     text(slot_id) || text(slot_type) || "argon2id"
     || memory_kib_u64_le || iterations_u64_le || salt
     || nonce || blob(wrapped_master_ciphertext)
   )
```

Feature names are sorted lexicographically. `blob` carries a 32-bit length prefix. Unlock tries each supported slot, then verifies the configuration tag before trusting any configuration value.

Updates increment the authenticated revision. Two complete temporary replicas are flushed and atomically replaced independently, followed by directory synchronization. Mixed valid revisions select the highest readable revision and report degraded redundancy.

## 3. Slot operations

- `repo passwd` replaces only the slot used to authenticate the command, preserving its ID, KDF parameters, and the master key.
- `repo key add-password` adds a distinct password slot.
- `repo key add-recovery-key --show-key` creates a random 32-byte recovery secret and displays it once as 64 lowercase hexadecimal characters. Recovery slots accept either those raw 32 bytes or their hexadecimal text representation.
- `repo key remove` requires confirmation. It refuses the authenticated slot and refuses to leave no usable slot.
- `repo key list` reports IDs, types, and KDF parameters without exposing wrapped keys or secrets.

Changing or removing a slot is not cryptographic revocation. Old configuration copies still contain the old wrapping of the same master key. Compromise requires a new repository and re-encryption with a new master key.

## 4. Storage epochs

`repo rotate-epoch` authenticates under maintenance locks, assigns a random storage epoch, increments the configuration revision, and updates both replicas. Object encryption does not change. Existing snapshots authenticate using their own historical epoch and remain readable.

Validation caches are epoch-namespaced, so old evidence is not accepted automatically after rotation. Users must still deep-verify after copying or replacing storage; an epoch is not a device identifier or rollback anchor.

## 5. Validation

C++ tests cover password replacement, multiple passwords, raw and hexadecimal recovery keys, removal restrictions, master-key stability, epoch rotation, and continued deep verification. The independent Python recoverer implements the same v1/v2 configuration authentication and restores C++ snapshots using a recovery key after epoch rotation.
