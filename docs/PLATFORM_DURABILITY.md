# Platform Durability Contract

> Status: M0 experimental contract and conformance record

This document distinguishes implementation intent from observed results. Passing an API call is not proof of physical durability. No entry implies protection against a device that ignores flush commands or corrupts data silently.

## 1. Required operation contracts

| Operation | Required behavior | Current implementation |
| --- | --- | --- |
| Create temporary file | New regular file, no symlink following, owner-only initial permissions where supported | POSIX `open(O_CREAT\|O_EXCL\|O_NOFOLLOW, 0600)`; Windows `CreateFileW(CREATE_NEW)` |
| Write | Loop over short writes, retry interrupted POSIX calls, fail on zero progress | POSIX `write`; Windows `WriteFile` |
| File flush | Request persistence of file data and required metadata before publication | Linux `fsync`; macOS `F_FULLFSYNC`; Windows `FlushFileBuffers` |
| Read-back | Read the complete object and compare or authenticate before publication | Native sequential reads with exact-length and trailing-data checks |
| Publish immutable object | Atomic within one filesystem and never replace an existing destination | Linux `renameat2(RENAME_NOREPLACE)`; macOS `renamex_np(RENAME_EXCL)`; Windows `MoveFileExW(WRITE_THROUGH)` without replacement |
| Directory synchronization | Request persistence of affected directory entries after publication | POSIX directory `fsync`; macOS `F_FULLFSYNC`; Windows currently reports unsupported |
| Configuration replacement | Complete old or new configuration, never a torn active file | Protocol and replica conformance tests remain M1 work |
| Locking | Reliable lifecycle and writer exclusion for mutation | Not implemented in M0; required before repository mutation |

Unsupported operations return errors. The implementation must not replace no-replace publication with overwriting `rename`, and must not treat a directory flush as a substitute for flushing file contents.

## 2. Automated native probe

Read-only inspection:

```bash
cpcp repo probe /path/to/directory --json
```

Explicit temporary-file write testing:

```bash
cpcp repo probe /path/to/directory \
  --write-test --iterations 20 --size 1048576 --json
```

The write test creates only uniquely named `cpcp-probe-*` files. For each iteration it performs create, write, file flush, close, full read-back, byte comparison, no-replace publication, directory synchronization, and cleanup. It returns exit code 1 when a required check fails.

The probe does not test power loss, USB disconnects, concurrent locks, configuration replacement, or physical media health. Read-back may hit the operating-system page cache.

## 3. Observed Linux result

| Field | Value |
| --- | --- |
| Date | 2026-11-23 |
| Host platform | Ubuntu 24.04 userspace, Linux 6.8.0-147-generic, x86-64 |
| Compiler | GCC 13.3.0 |
| Filesystem | ext4 on `/dev/sda1`, local build environment |
| API sequence | As implemented in `src/platform/binary_file.cpp` |
| Result | All read-only and write-test checks passed |
| Limitations | No forced power loss, USB bridge, external HDD, network filesystem, or physical-media verification |

Twenty write-test iterations with a 1,048,576-byte payload produced these aggregate nanosecond timings:

| Stage | Aggregate ns |
| --- | ---: |
| Write | 26,373,342 |
| File flush | 191,770,490 |
| Read-back and comparison | 66,715,660 |
| No-replace publication | 3,646,206 |
| Directory synchronization | 81,301,547 |

These measurements describe this run only. They are not performance targets and do not establish hardware durability.

Additional five-iteration Release probes compared candidate chunk-sized payloads. Values below are aggregate nanoseconds for all five iterations:

| Payload | Write | Flush | Read-back | Publish | Directory sync |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 MiB | 23,124,701 | 64,511,716 | 33,487,703 | 672,438 | 13,302,138 |
| 8 MiB | 34,999,383 | 85,778,771 | 46,594,539 | 517,227 | 12,203,655 |
| 16 MiB | 71,966,779 | 133,484,678 | 96,436,258 | 427,436 | 12,417,798 |

This small virtualized-disk sample is insufficient to choose a production chunk size. Physical source and repository devices, small files, memory pressure, and CDC trade-offs remain M1b benchmark inputs.

## 4. Platform matrix

| Platform and filesystem | File flush | No-replace publication | Directory sync | Forced crash | Status |
| --- | --- | --- | --- | --- | --- |
| Linux ext4, build environment | Passed | Passed | Passed | Not run | Experimental native probe passed |
| Linux XFS/Btrfs | Not run | Not run | Not run | Not run | Unverified |
| Linux FAT/exFAT | Not run | Not run | Not run | Not run | Unverified; initialization must reject unmet capabilities |
| macOS APFS | Code path only | Code path only | Code path only | Not run | Unverified |
| Windows NTFS | Code path only | Code path only | Unsupported | Not run | Not suitable for strict repository mutation yet |
| Network filesystems | Not run | Not run | Not run | Not run | Unsupported until independently verified |

## 6. Windows safe restore traversal evaluation

String normalization alone is not a sufficient traversal defense. Windows restore must consider junctions and reparse points, directory replacement races, case collisions, 8.3 aliases, trailing spaces or dots, reserved device names, alternate data stream separators, and `\\?\` or `\\.\` path namespaces.

Three implementation approaches were evaluated:

- Repeated `CreateFileW` path checks are portable but leave time-of-check/time-of-use gaps unless each component is opened with `FILE_FLAG_OPEN_REPARSE_POINT`, its attributes and identity are verified, and parent directories are pinned against replacement. Public Win32 APIs do not provide a general parent-handle-relative create equivalent to POSIX `openat`.
- Component-wise directory handles with reparse-point inspection use documented APIs but still require adversarial tests for parent replacement and sharing semantics. This is the first M1 prototype path, not an assumed guarantee.
- `NtCreateFile` with `RootDirectory` provides the desired handle-relative model but relies on native API contracts. It may be adopted only behind `platform::SafeDirectory`, with a documented Windows version matrix, dynamic API availability checks, and adversarial conformance tests.

Until one approach passes those tests, cpcp must not claim strong hostile-destination traversal protection on Windows. A conservative restore into a newly created destination with no concurrent untrusted writers is an acceptable explicitly documented fallback; silently following a reparse point is not.

## 7. Conformance requirements before format freeze

- Run native tests on every declared filesystem and record OS, kernel, mount options, and storage class.
- Exercise failure after each write, flush, publication, and directory-sync step.
- Add real subprocess termination and reproducible simulated persistence schedules.
- Document forced power-loss methodology and results separately from automated tests.
- Implement and test configuration replacement, lock scopes, cancellation, and read-only media behavior.
- Treat untested configurations as unverified rather than assigning them Linux ext4's result.
