# cpcp

cpcp is an open-source encrypted, content-addressed backup CLI written in modern C++. It supports local repositories on Windows, Linux, and macOS, with particular attention to interrupted transfers and recoverability.

The M1 implementation provides authenticated repository configuration, encrypted chunks and snapshots, deduplication, recovery paths, and an independent Python reference recoverer. It has not received an independent security audit. Do not use cpcp as the only copy of important data.

## Implemented capabilities

- C++23 CMake build with locked vcpkg dependencies and Debug/Release CI
- Argon2id password slots and authenticated configuration replicas
- Header export/import and configuration repair
- Fixed-size XChaCha20-Poly1305 chunks with read-back and content-ID validation
- Second-level file identities and streaming continuation records
- Encrypted snapshot streams, authenticated summaries, and bounded external chunk-set commitments
- Deduplicated `backup add` with source mutation detection and unsupported-entry policies
- `snapshot list`, `show`, and full or selective `restore`
- Structural and deep `repo verify`
- Quarantine, `repair-summary`, `repair-config`, and `--no-parent` recovery
- Deterministic volatile/durable filesystem simulation and seeded failures
- Independent Python reference recovery and cross-implementation vectors
- Native durability probes and a MinGW cross-compilation check

See `docs/DESIGN.md`, `docs/CORE_FORMAT.md`, and `docs/PLATFORM_DURABILITY.md`.

## Build

Requirements:

- CMake 3.25 or newer
- Ninja
- A compiler with reliable C++23 support
- vcpkg and its platform build prerequisites

Set `VCPKG_ROOT` to a vcpkg checkout, then run:

```bash
export VCPKG_ROOT=/path/to/vcpkg
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

For an optimized build:

```bash
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The manifest and builtin baseline in `vcpkg.json` lock all project dependencies.

CI runs Debug and Release builds on Ubuntu, Windows, and macOS, MinGW-static Windows builds, independent recovery tests, and dedicated Address/Undefined Behavior Sanitizer and Thread Sanitizer jobs. Sanitizer presets are also available locally:

```bash
cmake --preset asan -DVCPKG_TARGET_TRIPLET=x64-linux
cmake --build --preset asan
ctest --preset asan
cmake --preset tsan -DVCPKG_TARGET_TRIPLET=x64-linux
cmake --build --preset tsan
ctest --preset tsan
```

## Basic workflow

Create a password file readable only by its owner, then initialize a repository:

```bash
build/dev/cpcp repo init /path/to/repository \
  --password-file /path/to/password-file \
  --kdf-memory 64MiB --kdf-iterations 3 --chunk-size 8MiB
```

Back up a directory and create another deduplicated snapshot:

```bash
build/dev/cpcp backup add /path/to/source \
  --repo /path/to/repository --password-file /path/to/password-file
```

Inspect and verify snapshots:

```bash
build/dev/cpcp snapshot list \
  --repo /path/to/repository --password-file /path/to/password-file --json
build/dev/cpcp snapshot show 1 \
  --repo /path/to/repository --password-file /path/to/password-file
build/dev/cpcp repo verify --deep \
  --repo /path/to/repository --password-file /path/to/password-file
```

Restore a complete snapshot or one root-relative file:

```bash
build/dev/cpcp snapshot restore latest --to /path/to/restored \
  --repo /path/to/repository --password-file /path/to/password-file
build/dev/cpcp snapshot restore 1 --root index:0 --path sub/file.txt \
  --to /path/to/restored --repo /path/to/repository \
  --password-file /path/to/password-file
```

Restore refuses to overwrite existing paths unless both `--overwrite` and `--yes` are supplied.

## Filesystem probe

```bash
build/dev/cpcp repo probe /path/to/directory --json
build/dev/cpcp repo probe /path/to/directory \
  --write-test --iterations 20 --size 1048576 --json
```

The default probe is read-only. `--write-test` explicitly authorizes uniquely named temporary probe files in the target directory.

## Independent recovery and vectors

Install the locked dependency from `tools/requirements.txt`, then run:

```bash
python3 tools/verify_crypto_vectors.py
python3 tools/test_reference_recoverer.py --cpcp build/dev/cpcp
```

The reference recoverer is read-only and lives in `tools/reference-recoverer/`. Its interface and security limitations are documented there.

CTest can enable it explicitly on supported platforms:

```bash
cmake --preset dev -DCPCP_ENABLE_REFERENCE_TESTS=ON -DCPCP_PYTHONPATH=/path/to/pynacl
cmake --build --preset dev
ctest --preset dev
```

For an optional multi-gigabyte synthetic manifest streaming stress test:

```bash
cmake --preset dev -DCPCP_ENABLE_STRESS_TESTS=ON
cmake --build --preset dev
ctest --preset dev -R multi-gigabyte
```

The stress option is disabled in routine CI because of its I/O cost.

## License

MIT. See `LICENSE`.
