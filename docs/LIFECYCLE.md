# cpcp Retention and Garbage Collection

> Status: Implemented conservative retirement, two-phase GC, and quarantine expiry

## 1. Retirement

`snapshot forget <generation> --yes` withdraws the summary first and then moves the main stream into `trash/`. Chunks are untouched. `--dry-run` reports the pair without changing the repository. An authenticated maintenance transition is written before movement.

Retirement is idempotent across the summary/main interruption window: a subsequent invocation locates either object in its active or trash location and completes only the remaining move. Retired objects leave latest/parent selection and retained-reference enumeration. Missing historical parents after pruning are not, by themselves, treated as payload corruption.

## 2. GC safety and phases

`repo gc` requires exclusive lifecycle and backup-writer locks. Before moving or deleting anything it requires:

- an empty quarantine, including resolved maintenance records;
- no active or incomplete session files;
- every active summary and complete main manifest to authenticate and enumerate successfully;
- a complete reachable chunk set.

Any failure aborts collection. GC never treats incomplete reference enumeration as permission to delete.

Unreachable direct chunks move into `trash/` rather than being deleted immediately. Only a later explicit `repo gc --grace-seconds <n>` deletes trash entries whose timestamps satisfy the grace period. Zero is allowed for deliberate tests and operator-selected immediate cleanup. Dry-run performs all safety validation but does not move, delete, or create repository objects.

## 3. Quarantine expiry

`repo purge-quarantine` is a separate command with its own confirmation and grace period. It deletes expired quarantined bytes and maintenance records. It is required after resolved damage or retirement before GC can proceed. Active snapshots left damaged by quarantine still fail verification and block collection.

## 4. Validation

Tests cover dry-run non-mutation, retirement, reachable-object preservation, movement of unreachable objects, subsequent grace expiry, nonempty quarantine refusal, and active-session refusal. The implementation intentionally blocks on any session rather than attempting to prove which unpublished objects are safe to collect.
