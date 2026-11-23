# cpcp

cpcp is an experimental open-source encrypted backup CLI written in modern C++. The project currently implements M0 engineering foundations; it does not yet provide production backup and restore commands.

Do not use cpcp as the only copy of important data.

## Current foundations

- C++23 CMake build with locked vcpkg dependencies
- CLI help, version, and filesystem capability probes
- Typed `Result<T>` error propagation
- Deterministic volatile/durable filesystem simulation and seeded failures
- Secure key storage, subkey derivation, and resumable content IDs
- XChaCha20-Poly1305 objects and AAD-bound secretstream frames
- Streaming file continuation validation
- Encrypted disk-backed session spools
- Native file flush, read-back, no-replace publication, and directory-sync probes
- Unit, integration, simulation, and independent cryptographic vectors

See `docs/DESIGN.md`, `docs/EXPERIMENTAL_FORMAT.md`, and `docs/PLATFORM_DURABILITY.md`.

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

The manifest and builtin baseline in `vcpkg.json` lock all project dependencies.

## Probe a filesystem

```bash
build/dev/cpcp --version
build/dev/cpcp repo probe /path/to/directory --json
build/dev/cpcp repo probe /path/to/directory \
  --write-test --iterations 20 --size 1048576 --json
```

The default probe is read-only. `--write-test` explicitly authorizes uniquely named temporary probe files in the target directory.

## Independent vectors

With Python and the locked dependency from `tools/requirements.txt` installed:

```bash
python3 tools/verify_crypto_vectors.py
```

## License

MIT. See `LICENSE`.
