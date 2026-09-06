# Architecture

MnemoPort separates the product-facing experience from the migration authority:

```text
host Skill -> mnemo CLI -> source adapter -> Canonical Asset -> .mnemo
                                              |
target files <- transaction/ledger <- plan <- target adapter
```

The thin Skill teaches the current AI host when to run read-only inventory, how to explain a plan, and when explicit user approval is required. It contains no product path guesses, parser logic, credentials, or shell-generated target commands.

The Rust core owns deterministic schemas, path and content policy, package verification, conflict decisions, immutable plans, target preconditions, transactional writes, and rollback. Product adapters own only documented discovery roots, scope semantics, canonical conversion, and target-native rendering.

## Workflow phases

1. `doctor` resolves platform tuples without creating product directories.
2. `inventory` reports supported and inventory-only assets without asset bodies.
3. `export` extracts supported assets, removes credential values, signs, compresses, and encrypts one `.mnemo` file.
4. `inspect` decrypts and verifies the package without target writes.
5. `plan` renders against the exact target tuple and snapshots current target hashes.
6. `apply` rebuilds the plan, rejects drift, then commits local files with journals and backups.
7. `verify` independently rebuilds L0 target bytes and checks current target hashes.
8. `report` reads operation and journal evidence from the local ledger.
9. `undo` restores only unchanged post-apply targets.

If a process stops between a synced `prepared` journal and its final `committed` journal, `doctor` and `recovery list` classify the target from exact before/current/after hashes. `recovery rollback` restores a verified backup or closes a transaction whose target never changed. A third state is reported as manual review and never changed automatically.

Product discovery is also split by effect. `detect` only resolves files and executables. The explicit `probe` path runs a bounded adapter-owned `--version` command in a disposable home and records entrypoint-specific version evidence. It does not initialize migrated components, and its success cannot be promoted to asset-level discovery evidence.

For same-tool moves between devices, `handoff` packages a user-selected new-session capsule using the same signing and encryption path. The destination receives a Markdown sidecar; MnemoPort never injects a private session database.

Plans are target-device artifacts. A cross-device package is created on source device A, while the plan is created on target device B so its preconditions describe the actual destination.

JSON commands return `0` only when the requested scope is fully complete, `2` when the safe portion completed with manual/conditional work, `3` for conflicts or target drift, `4` for a safety refusal, `5` for unavailable dependency/trust state, `6` for incompatible input, and `70` for an internal failure.

## Crates

- `mnemo-cli`: stable command surface and JSON response envelope.
- `mnemo-core`: workflow orchestration, package graph, planning, conflict handling.
- `mnemo-schema`: product tuples, Canonical Assets, plans, dispositions, readiness.
- `mnemo-package`: canonical tar/zstd payload, Ed25519 signatures, age encryption.
- `mnemo-security`: hashing, portable path policy, secret/PII scan and quarantine signals.
- `mnemo-store`: XDG paths, device identity, SQLite ledger, backups, journals, undo.
- `adapters/*`: Claude Code, Codex, Qoder, and Cursor source/target behavior.

## Atomicity boundary

Local file writes are Phase A and have strong byte-for-byte rollback. Backups are hash-verified again before undo or interrupted-process recovery. Network installs, OAuth, plugin marketplaces, and MCP execution are Phase B external actions and cannot share a universal atomicity promise. The alpha does not execute Phase B actions; it reports intent/manual work instead.
