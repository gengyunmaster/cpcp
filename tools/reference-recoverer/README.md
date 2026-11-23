# Independent Reference Recoverer

`cpcp_recover.py` is a read-only Python implementation of the cpcp repository reader. It does not link to or invoke the C++ implementation.

## Usage

```bash
python3 tools/reference-recoverer/cpcp_recover.py \
  --repo /path/to/repository \
  --to /path/to/restore-destination \
  --password-file /path/to/password-file
```

Use `--generation N` to select a specific snapshot instead of the latest one.

The recoverer:

- unlocks Argon2id password slots and validates configuration authentication;
- validates snapshot summaries, full secretstream manifests, file identities, and chunk metadata before writing output;
- decrypts chunks with XChaCha20-Poly1305 and verifies every chunk ID;
- reconstructs regular files and baseline mode and mtime metadata;
- never modifies the repository, resumes sessions, updates caches, or performs garbage collection.

Passwords and master keys are handled by Python and its libsodium bindings. Python does not provide the C++ implementation's explicit move-only ownership and guaranteed zeroization guarantees. Use a protected password file and an appropriate recovery environment. An incorrect password returns 5; repository or snapshot integrity failures return 4; usage errors return 2; other runtime failures return 1.

The implementation is a format review and disaster-recovery aid, not an independent security audit. Two implementations by the same author can share specification misunderstandings, so cross-implementation vectors alone do not establish correctness or security.
