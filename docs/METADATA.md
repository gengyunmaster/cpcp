# cpcp Entry Types and Extended Metadata

> Status: Implemented symbolic links and opt-in ownership restoration

## 1. Symbolic links

Record type 10 uses schema `cpcp.symlink.v1` and contains `root`, `path`, `target`, normalized `mtime`, and `mode`. Journal record type 12 carries the same payload. Selection policy field `symlinks` defaults to false for older snapshots and is true for new writers.

Backup never follows a symlink or opens its target. It stores the target exactly as a portable string and calculates a keyed target identity using HMAC-SHA-256 with K_id over `"cpcp.symlink.v1" || target_bytes`. This identity supports source checks and snapshot diffs without reading target contents. Non-UTF-8 targets are explicitly policy-skipped.

Restore creates a temporary symlink, applies supported no-follow timestamps, and publishes with no-replace or the explicitly approved overwrite policy. POSIX uses `utimensat(AT_SYMLINK_NOFOLLOW)`. Windows symlink timestamp restoration is not claimed. No privileged-bit or ownership operation is applied implicitly to a link.

## 2. Ownership

Record type 11 uses schema `cpcp.ownership.v1` and contains `root`, `path`, decimal-string `uid` and `gid`, plus the authenticated file `mode`. Regular-file ownership comes from the opened source handle on POSIX. Windows does not synthesize POSIX ownership.

The file-completion journal payload includes optional ownership, and parent descriptor spools retain ownership for incremental backups. This prevents resume or incremental reuse from silently dropping it.

Restore ignores ownership records by default. `--restore-ownership` opts into `lchown` on POSIX; unsupported or failed ownership restoration is a metadata warning, upgraded by `--strict-metadata`. No ownership operation follows a symlink.

## 3. Privileged bits

setuid and setgid are stripped by default, with one explicit warning per affected file. `--strict-metadata` turns this downgrade into a partial failure. `--restore-privileged-bits` opts into restoring them. If ownership restoration is also requested, the authenticated mode is reapplied after `lchown`, because ownership changes may clear these bits.

ACLs, extended attributes, alternate data streams, resource forks, and hard-link topology remain outside this milestone.
