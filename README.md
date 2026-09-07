# MnemoPort

[English](README.md) | [简体中文](README.zh-CN.md)

MnemoPort is an open-source portability layer for personal AI assets. It moves file-backed instructions, Skills, prompts, and credential-free MCP definitions between Codex, Claude Code, Qoder, and Cursor—or between two devices running the same tool.

```text
Tool X on device A  ->  encrypted .mnemo package  ->  Tool X on device B
Tool X              ->  canonical asset model    ->  Tool Y
```

MnemoPort is an alpha available as prerelease binaries or from source. Its Rust CLI, signed and encrypted package format, transactional apply/undo, four offline adapters, four thin host Skills, and all 16 Core source→target smoke directions are implemented and tested. Native auto-memory stores, account/cloud data, plugin network installation, and broad preference migration remain deliberately non-automatic.

The latest binary tag is `v0.1.0-alpha.1`. Portable multi-workspace mapping and
the authoritative `plugin-inventory` command documented below are currently on
`main` and will enter the next prerelease; install from source to use them now.

MnemoPort is model-provider independent. It does not call an LLM API and never needs an OpenAI, Anthropic, DeepSeek, or other model-provider API key. It runs locally under the AI coding tool the user already authenticated. Package encryption uses either a destination-owned age identity or the user-chosen `MNEMOPORT_PASSPHRASE`; neither is a model credential.

## Supported hosts and assets

The alpha supports `claude-code`, `codex`, `qoder`, and `cursor` as both source and target hosts. All 4 × 4 Core directions, including X→X, are exercised in the repository test matrix.

| Asset | Current `main` behavior |
|---|---|
| Instructions/rules | File-backed user/project sources; exact X→X paths where stable, safe target-native mapping across tools |
| Skills | Complete file trees rooted by `SKILL.md`; symlinks rejected, active/non-text content quarantined and never auto-applied |
| Prompts/commands | File-backed Markdown; mapped to commands or thin Skills where appropriate |
| MCP | JSON/TOML definitions; command, args, URL, and secret-reference names only; secret values are discarded |
| Preferences/settings | Inventory only until a portable-key allowlist exists for the exact product tuple |
| Auto memory | Inventory/manual unless a documented, version-gated file mapping exists; internal databases are never written |
| Plugins/extensions/CLI dependencies | Not installed automatically; caches, binaries, and executable payloads are never copied or run |
| Sessions/auth/trust/cache | Excluded; use a new-session Handoff capsule instead of database injection |

Support is capability-aware, not an assertion that every asset can be losslessly represented in every host. A safe partial result is reported explicitly rather than silently dropped. See the exact roots, target surfaces, and exclusions in [Compatibility](docs/compatibility.md).

## Requirements

- Linux, macOS, or Windows.
- [Rust](https://www.rust-lang.org/tools/install) 1.85 or newer, including Cargo.
- Git for cloning and updating the source checkout.
- No model-provider API key.

## Install a release binary

Download the archive and adjacent `.sha256` file for your platform from [GitHub Releases](https://github.com/muzishuiji/mnemoport/releases). For Linux x86-64:

```bash
version=v0.1.0-alpha.1
curl -LO "https://github.com/muzishuiji/mnemoport/releases/download/$version/mnemoport-x86_64-unknown-linux-gnu.tar.gz"
curl -LO "https://github.com/muzishuiji/mnemoport/releases/download/$version/mnemoport-x86_64-unknown-linux-gnu.tar.gz.sha256"
sha256sum --check mnemoport-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf mnemoport-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 mnemo "$HOME/.local/bin/mnemo"
mnemo --version
```

The other archives are `mnemoport-aarch64-apple-darwin.tar.gz` for Apple Silicon macOS and `mnemoport-x86_64-pc-windows-msvc.zip` for Windows x86-64. Verify the checksum before extracting, then place `mnemo` or `mnemo.exe` in a directory on `PATH`. See [release security](docs/release-security.md) to verify GitHub provenance.

The recipient-encryption, trust-lifecycle, and explicit multi-workspace commands documented below are implemented on `main` after `v0.1.0-alpha.1`; install from source until they appear in the next prerelease.

## Install the CLI from source

Clone the repository and install the `mnemo` binary with Cargo:

```bash
git clone https://github.com/muzishuiji/mnemoport.git
cd mnemoport
cargo install --locked --path crates/mnemo-cli
mnemo --version
mnemo doctor
```

Cargo normally installs binaries in `$HOME/.cargo/bin` on Linux/macOS and `%USERPROFILE%\.cargo\bin` on Windows. If `mnemo` is not found after installation, add that directory to `PATH` and open a new shell.

Upgrade an existing source installation:

```bash
git pull --ff-only
cargo install --force --locked --path crates/mnemo-cli
mnemo --version
```

Remove only the CLI binary:

```bash
cargo uninstall mnemo-cli
```

Uninstalling the binary does not remove migrated assets, installed host Skills, or MnemoPort's local audit/rollback state.

MnemoPort normally stores its own config, ledger, cache, signing identity, and rollback journals in the operating system's native application directories. Set `MNEMOPORT_STATE_ROOT` to an absolute directory to place those files under its `config`, `data`, and `cache` subdirectories instead. This is useful for portable or isolated execution; it does not redirect any Claude Code, Codex, Qoder, or Cursor assets.

## Install the thin host Skill

The CLI is the migration authority. A small host-specific Skill teaches the current AI tool how to invoke it safely. Install it for one or more hosts:

```bash
mnemo integration install --host claude-code --scope user
mnemo integration install --host codex --scope user
mnemo integration install --host qoder --scope user
mnemo integration install --host cursor --scope user
```

User-scope installation can run from any directory. Use `--scope project` while the shell is inside the intended project to install only for that project. Check or remove an integration with the same host and scope:

```bash
mnemo integration status --host codex --scope user --json
mnemo integration uninstall --host codex --scope user --json
```

The command reports the exact installed path. Installation refuses to overwrite an existing Skill. Uninstall succeeds only when MnemoPort's local ledger proves ownership and the installed file's hash is unchanged; user-edited or unmanaged files are preserved.

After installation, ask the target AI tool in natural language, for example:

> Migrate the supported Claude Code assets on this device into Codex. Inventory and show me the immutable plan first; do not apply until I approve its token.

The Skill is an orchestration aid, not a requirement: every workflow below can also be run directly in a terminal.

## How migration works

The safe workflow is always:

```text
doctor/detect -> inventory -> export -> inspect -> plan -> trust -> apply -> verify
                                                              |          |
                                                              |          +-> report / undo
                                                              +-> explicit user approval
```

`inventory`, `export`, and `inspect` do not write target product state. `plan` is created on the target device because it snapshots that destination's exact paths and hashes. `apply` accepts only the approval token for that immutable plan, rechecks the package and target, and refuses to continue if either drifted.

`--invoked-by` records which AI host is running the command. The source host may be offline or out of quota, so it may differ during `inventory/export`. During `plan/apply`, `--invoked-by` must equal `--to` or the plan's target.

### Same-device cross-tool migration (X→Y)

The usual flow starts in the target tool. This example migrates supported Claude Code assets into Codex while Codex is the active host:

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'

mnemo doctor --json
mnemo inventory --from claude-code --invoked-by codex --json
mnemo export --from claude-code --invoked-by codex --output claude-assets.mnemo --json
mnemo inspect claude-assets.mnemo --json
mnemo plan --input claude-assets.mnemo --to codex --invoked-by codex --output migration-plan.json --json
mnemo trust add --input claude-assets.mnemo --label same-device --json
```

Read the plan output, including `writable_files`, `skipped_assets`, every operation, conflict, and `approval_token`. Apply only after reviewing that exact result:

```bash
mnemo apply --input claude-assets.mnemo --plan migration-plan.json --approve <approval-token> --invoked-by codex --json
mnemo verify --input claude-assets.mnemo --plan migration-plan.json --json
```

The default verification level is L0. After L0 passes, request version-gated native discovery where an exact safe recipe exists:

```bash
mnemo verify --input claude-assets.mnemo --plan migration-plan.json --level l1 --json
```

L1 reports one structured result per migrated asset kind. The current release can automatically discover Codex CLI `0.144.1` MCP entries and Qoder CLI `1.1.42` Skills on Linux; other tuples and asset kinds return an explicit `manual`, `unsupported_version`, or `unavailable` status and exit code `2`.

Do not reuse a stale plan. If target files change after planning, create a new output filename and run `plan` again.

### Cross-device or same-tool migration (X→X)

Recipient encryption is the recommended cross-device flow because device A receives only device B's public key—no shared secret is sent back to the source. First, on target device B, generate a private identity outside a repository and copy only the public `recipient` from the JSON output:

```bash
mnemo recipient generate --output "$HOME/.config/mnemoport/device-b.agekey" --json
export MNEMOPORT_IDENTITY_FILE="$HOME/.config/mnemoport/device-b.agekey"
mnemo recipient show --json
```

Keep the `.agekey` file private and backed up. MnemoPort creates it without overwriting an existing file and with private file permissions where the operating system supports them. Send the `age1...` recipient to source device A. Qoder is only an example; replace both host identifiers with any supported source and target:

```bash
mnemo inventory --from qoder --invoked-by qoder --json
mnemo export --from qoder --invoked-by qoder --output qoder-assets.mnemo --recipient 'age1...' --json
```

Transfer `qoder-assets.mnemo` to target device B. With `MNEMOPORT_IDENTITY_FILE` still set there, use the normal destination workflow:

```bash
mnemo inspect qoder-assets.mnemo --json
mnemo plan --input qoder-assets.mnemo --to qoder --invoked-by qoder --output migration-plan.json --json
mnemo trust add --input qoder-assets.mnemo --label device-a --json
```

After reviewing the destination-specific plan:

```bash
mnemo apply --input qoder-assets.mnemo --plan migration-plan.json --approve <approval-token> --invoked-by qoder --json
mnemo verify --input qoder-assets.mnemo --plan migration-plan.json --json
```

Changing `--to qoder` to another supported host makes this a cross-device X→Y migration. X→X preserves exact native locations where the versioned adapter contract says that is safe; it still does not copy auth, sessions, caches, or undocumented databases.

As an alternative, omit `--recipient` and set the same 12+ character `MNEMOPORT_PASSPHRASE` on both devices. The passphrase is never stored in the package. Recipient and plaintext modes are mutually exclusive.

### Multiple workspaces in one package

For a multi-root IDE or several repositories, repeat `--workspace LABEL=PATH` during inventory/export. The package contains stable labels and ids, never source absolute paths:

```bash
mnemo inventory --from cursor --workspace frontend=./frontend --workspace backend=./backend --json
mnemo export --from cursor --workspace frontend=./frontend --workspace backend=./backend \
  --output workspaces.mnemo --recipient 'age1...' --json
```

On the destination, run `inspect`, create a target-local JSON map from each returned `workspace_id` to a distinct existing absolute directory, and pass it only when planning:

```bash
mnemo inspect workspaces.mnemo --json
mnemo plan --input workspaces.mnemo --to codex --workspace-map workspace-map.json \
  --output migration-plan.json --json
mnemo apply --input workspaces.mnemo --plan migration-plan.json --approve <approval-token> --json
mnemo verify --input workspaces.mnemo --plan migration-plan.json --json
```

The canonical map is bound into the immutable plan; apply and verify revalidate it from that plan. Missing/extra ids, relative or duplicate targets, unavailable directories, and leaf symlinks are rejected before writes. See [portable workspace mapping](docs/workspace-mapping.md) for the map schema, invariants, and current L1 boundary.

### Signing trust lifecycle

Trust is local to the destination and separate from encryption. Verify a new source fingerprint through a trusted channel before `trust add`. If a source device is retired or lost, revoke its exact full fingerprint; prefixes are rejected:

```bash
mnemo trust list --json
mnemo trust revoke sha256:<64-lowercase-hex> --json
```

For a planned device-key rotation, obtain and inspect a package signed by the replacement device, then atomically add the replacement and revoke the old signer:

```bash
mnemo trust rotate --from sha256:<old-64-lowercase-hex> --input replacement.mnemo --label device-a-new --json
```

Rotation changes only signer trust. It does not rotate or expose the destination age decryption identity.

### Windows PowerShell passphrase

```powershell
$env:MNEMOPORT_PASSPHRASE = "choose-at-least-12-characters"
mnemo inspect .\assets.mnemo --json
```

MnemoPort reads the passphrase only from the current process environment. It does not parse a repository `.env` file. Keep passphrases and model credentials out of the repository; `.env` and `.env.*` are ignored as a defense in depth.

### Reports and rollback

`apply` returns a `migration_id`. Use it to inspect local audit evidence or undo the migration:

```bash
mnemo report <migration-id> --json
mnemo undo <migration-id> --json
```

Undo restores the pre-migration bytes only when the files still match the state MnemoPort wrote. If a target was edited afterward, undo refuses instead of discarding that work.

### Interrupted-process recovery

Every file replacement writes and syncs its rollback backup and `prepared` journal before replacing the target. `mnemo doctor --json` also detects a `committed` journal whose ledger acknowledgement was interrupted. Inspect either kind without writing:

```bash
mnemo recovery list --json
```

Each candidate is classified from exact before/current/after hashes as `mark-rolled-back`, `restore-backup`, or `manual-review`. Explicitly close or restore one unambiguous transaction with:

```bash
mnemo recovery rollback <transaction-id> --json
```

Recovery verifies the journal location and rollback backup hash. It refuses `manual-review` when the target matches neither recorded state, so an external edit is never guessed away. Ledger transaction and managed-file ownership updates commit atomically; undo restores the previous owner for a managed update or removes ownership created by the undone migration.

### Explicit product probe

`detect` is filesystem-only. When you explicitly want version-level L1 evidence from installed products, run:

```bash
mnemo probe --json
mnemo probe --platform cursor --json
```

The probe invokes only the adapter-owned `--version` argument, without a shell or asset-derived input. It clears credential-bearing environment variables, supplies a disposable home, captures at most 8 KiB, terminates the child after five seconds, deletes the disposable directory, and never initializes migrated Skills, MCP servers, or plugins. Results are entrypoint-specific; missing CLI, unsupported Desktop/GUI entrypoints, failures, and timeouts produce explicit statuses and exit code `2`.

This is version-level L1 evidence, not proof that a particular migrated asset was discovered. Asset-level L1 is requested separately with `mnemo verify --level l1`; every automatic recipe uses fixed arguments, a disposable private copy of only the required target state, a timeout, bounded output, and a structured parser. It never starts migrated MCP servers, Skills, plugins, or hooks. The child process is not placed in an OS network namespace, so run probes only for an installed executable you trust. See [Product probes](docs/product-probes.md) for the exact boundary and compatibility matrix.

### Authoritative plugin and extension inventory

P1-C adds an explicit read-only inventory command. It normalizes reinstall intent
from vendor-owned interfaces without copying caches or extension binaries and
without loading any plugin component:

```bash
mnemo plugin-inventory --from claude-code --json
mnemo plugin-inventory --from codex --json
mnemo plugin-inventory --from qoder --json
mnemo plugin-inventory --from cursor --json
```

The admitted Linux tuples are Claude Code CLI `2.1.259` via
`plugin list --json`, Codex CLI `0.144.1` via `plugin list --json`, and Cursor
IDE `3.17.21` via `--list-extensions --show-versions`. Cursor Agent has no
installed-plugin list in the observed entrypoint; Qoder's official CLI list and
Desktop/IDE UI do not yet expose an admitted structured export. Those reports
remain explicit `manual`/`unavailable`, and a mixed result exits `2` even when
another entrypoint was collected successfully.

Cursor supports explicit `--profile NAME` and `--extensions-dir PATH`; all
products support `--workspace PATH`. Local paths and raw vendor output are
removed from the result. No plugin is packaged or installed in this phase. See
[Authoritative plugin and extension inventory](docs/plugin-inventory.md) for
the exact tuple matrix, normalized fields, safety boundary, and status meanings.

### New-session Handoff capsule

Handoff carries a user-reviewed task summary into a fresh session without copying a product session database. Create JSON conforming to [`handoff.schema.json`](schemas/handoff.schema.json), then package it on the source device:

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'
mnemo handoff --input handoff.json --output handoff.mnemo --json
```

For recipient encryption, replace the environment variable with `--recipient 'age1...'` and select the corresponding identity on the target. Then use the normal `inspect` → `plan` → `trust` → `apply` flow. The target receives a Markdown sidecar under its project; no internal session identifier, chat database, or authentication state is injected.

## Command reference

| Command | Writes product state? | Purpose |
|---|---:|---|
| `mnemo doctor [--json]` | No | Resolve MnemoPort state and detected product tuples |
| `mnemo detect [--platform HOST] [--json]` | No | Detect one or all supported hosts without launching them |
| `mnemo probe [--platform HOST] [--json]` | Disposable probe state only | Run bounded, version-level L1 probes for safe entrypoints |
| `mnemo plugin-inventory --from HOST [--workspace PATH] [--json]` | No MnemoPort target write; vendor may create incidental local state | Normalize installed plugin/extension intent for exact version tuples |
| `mnemo inventory --from HOST [--workspace LABEL=PATH]` | No | List supported assets and manual-only candidates without bodies |
| `mnemo export --from HOST --output FILE [--workspace LABEL=PATH]` | No | Extract, redact/quarantine, sign, compress, and encrypt a new package |
| `mnemo inspect FILE` | No | Decrypt, verify, and summarize a package |
| `mnemo plan --input FILE --to HOST --output PLAN [--workspace-map MAP]` | No | Create a new immutable plan against the current target |
| `mnemo trust add --input FILE` | MnemoPort state only | Trust the verified signing identity of one source device |
| `mnemo trust list` | No | List locally trusted signer fingerprints |
| `mnemo trust revoke FINGERPRINT` | MnemoPort state only | Revoke exactly one full signer fingerprint |
| `mnemo trust rotate --from FINGERPRINT --input FILE` | MnemoPort state only | Atomically trust a replacement package signer and revoke the old signer |
| `mnemo recipient generate --output FILE` | MnemoPort identity file only | Create a destination-owned age identity and return its public recipient |
| `mnemo recipient show [--identity FILE]` | No | Derive the public recipient without exposing the private identity |
| `mnemo apply --input FILE --plan PLAN --approve TOKEN` | Yes | Revalidate and transactionally write approved target files |
| `mnemo verify --input FILE --plan PLAN [--level l0\|l1]` | Disposable L1 probe state only | Compare target hashes; optionally request exact-tuple native asset discovery |
| `mnemo report ID` | No | Read operation status and journal count |
| `mnemo undo MIGRATION_ID` | Yes | Restore unchanged targets from local backups |
| `mnemo recovery list` | No | Classify prepared journals left by an interruption |
| `mnemo recovery rollback TRANSACTION_ID` | Yes | Safely close or restore one unambiguous prepared transaction |
| `mnemo integration install/status/uninstall` | Host Skill only | Manage the thin integration with ownership checks |
| `mnemo handoff --input JSON --output FILE [--recipient AGE_RECIPIENT]` | No | Package a user-selected new-session capsule |

Use `mnemo <command> --help` for all flags. Add `--json` for the stable response envelope used by Skills and scripts.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Requested scope completed fully |
| `2` | Safe portion completed; some assets require manual/conditional handling |
| `3` | Conflict, approval mismatch, or target/package drift; inspect and re-plan |
| `4` | Refused by a local safety policy |
| `5` | Required local dependency or signer trust is unavailable |
| `6` | Invalid, incompatible, or unsupported input/package/schema/version |
| `70` | Unexpected internal failure |

Exit `2` is a successful partial outcome, not permission to treat skipped items as migrated.

## Product roots and overrides

MnemoPort reads only adapter-approved roots and the current workspace. Useful explicit overrides for isolated testing or non-default installations are:

| Host | Override | Default user root |
|---|---|---|
| Claude Code | `CLAUDE_CONFIG_DIR` | `~/.claude` |
| Codex | `CODEX_HOME` | `~/.codex` plus current `~/.agents` Skills |
| Qoder | `QODER_CONFIG_DIR` | `~/.qoder` |
| Cursor | `CURSOR_AGENT_CONFIG_DIR`, `CURSOR_USER_DATA_DIR` | `~/.cursor` plus selected platform user-data location |

Overrides select roots; they do not expand the asset allowlist. Run `mnemo doctor --json` and `mnemo detect --json` to see what the current machine resolves. Product behavior is version-, OS-, and entrypoint-specific; Cursor Agent and Cursor IDE, for example, are not treated as the same capability tuple.

## Safety guarantees and limits

- Normal source inventory and extraction are offline-static and never launch the source product; only explicit `plugin-inventory` and probe/L1 commands invoke admitted read-only vendor interfaces.
- `.mnemo` content is deterministic, zstd-compressed, Ed25519-signed, and age-encrypted by default.
- Paths, symlinks, archive sizes, signatures, hashes, object closure, and target preconditions are verified.
- Explicit source workspace paths stay local; exact target mappings are validated and bound into the plan identity.
- Apply uses synced local backups, durable journals, and an atomic SQLite transaction/ownership update, with strong rollback for local files.
- Existing unrelated target content is preserved; conflicts are never silently overwritten.
- Authentication values, cookies, keychains, internal databases, trust decisions, and caches do not migrate.
- Scripts, hooks, plugins, and MCP servers are not executed during inventory, inspect, plan, or the default L0 verification.
- `--allow-plaintext` is an explicit escape hatch for intentional non-sensitive fixtures. It should not be used for real personal assets.

The alpha does not perform network plugin/extension installation, CLI dependency installation, OAuth/account export, MCP server execution, native auto-memory import, or broad editor-profile synchronization. It records or inventories these surfaces only when the adapter can do so safely. Prepared and committed-but-unacknowledged crash recovery, atomic managed ownership, version-level probes, authoritative plugin inventory for the exact tuples above, and the two exact-tuple asset-level L1 recipes are implemented. Native claims outside those narrow matrices remain manual. Release artifact and provenance claims apply only after the tagged workflow succeeds.

## Troubleshooting

- **`mnemo: command not found`:** add Cargo's binary directory to `PATH`, then open a new shell.
- **Encrypted package cannot be opened:** for recipient encryption, pass `--identity <path>` or set `MNEMOPORT_IDENTITY_FILE` on the destination. For passphrase encryption, set the same 12+ character `MNEMOPORT_PASSPHRASE` on both devices.
- **Exit code 2:** inspect `skipped_assets` and manual operations. The safe subset completed, but the whole requested scope did not.
- **Signer is not trusted:** run `inspect`, verify the displayed fingerprint through a trusted channel, then run `mnemo trust add --input <package>`.
- **Plan drift or approval mismatch:** discard the plan, choose a new plan output filename, and run `plan` again against the current target.
- **Output already exists:** MnemoPort does not overwrite package or plan files. Choose a new output path.
- **Integration uninstall is refused:** the file is modified or lacks MnemoPort ownership proof. Preserve it and remove it manually only after reviewing its contents.
- **`doctor` reports recovery candidates:** run `recovery list`, review the hashes and disposition, then explicitly roll back only an unambiguous transaction. Preserve `manual-review` targets for investigation.
- **Need detailed local diagnostics:** rerun without `--json`; JSON mode intentionally emits stable, sanitized diagnostics.

For security issues and sensitive-data handling, read [SECURITY.md](SECURITY.md).

## Development and verification

From a clean checkout:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

CI runs formatting, Clippy, and the full test suite on Linux, macOS, and Windows with Rust 1.85 and Stable, plus RustSec and `cargo-deny` dependency-policy jobs. Fixture tests provide Core L0 evidence; they do not upgrade an untested native product version, GUI, remote, or cloud entrypoint to supported.

## Documentation

- [Architecture](docs/architecture.md)
- [Compatibility and exact product boundaries](docs/compatibility.md)
- [Machine-readable compatibility evidence](docs/compatibility.json)
- [Package format](docs/package-format.md)
- [Portable workspace mapping](docs/workspace-mapping.md)
- [Product probes and evidence boundary](docs/product-probes.md)
- [Release and supply-chain security](docs/release-security.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

MnemoPort is available under the [MIT License](LICENSE).
