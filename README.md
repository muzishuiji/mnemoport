# MnemoPort

MnemoPort is an open-source portability layer for personal AI assets. It moves file-backed instructions, Skills, prompts, and credential-free MCP definitions between Codex, Claude Code, Qoder, and Cursor—or between two devices running the same tool.

```text
Tool X on device A  ->  encrypted .mnemo package  ->  Tool X on device B
Tool X              ->  canonical asset model    ->  Tool Y
```

MnemoPort is a source-installable alpha. Its Rust CLI, signed and encrypted package format, transactional apply/undo, four offline adapters, four thin host Skills, and all 16 Core source→target smoke directions are implemented and tested. Native auto-memory stores, account/cloud data, plugin network installation, and broad preference migration remain deliberately non-automatic.

MnemoPort is model-provider independent. It does not call an LLM API and never needs an OpenAI, Anthropic, DeepSeek, or other model-provider API key. It runs locally under the AI coding tool the user already authenticated. `MNEMOPORT_PASSPHRASE` is only a user-chosen encryption passphrase for a `.mnemo` package; it is not a model credential.

## Supported hosts and assets

The alpha supports `claude-code`, `codex`, `qoder`, and `cursor` as both source and target hosts. All 4 × 4 Core directions, including X→X, are exercised in the repository test matrix.

| Asset | Current alpha behavior |
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

## Install the CLI

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

Do not reuse a stale plan. If target files change after planning, create a new output filename and run `plan` again.

### Cross-device or same-tool migration (X→X)

On source device A, export an encrypted package. Qoder is only an example; replace both host identifiers with any supported source and target:

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'
mnemo inventory --from qoder --invoked-by qoder --json
mnemo export --from qoder --invoked-by qoder --output qoder-assets.mnemo --json
```

Transfer only `qoder-assets.mnemo` through a channel you trust. On target device B, set the same passphrase through the shell or a secret manager:

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'
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

Every file replacement writes and syncs its rollback backup and `prepared` journal before replacing the target. `mnemo doctor --json` reports any prepared transactions left by a process or machine interruption. Inspect them without writing:

```bash
mnemo recovery list --json
```

Each candidate is classified from exact before/current/after hashes as `mark-rolled-back`, `restore-backup`, or `manual-review`. Explicitly close or restore one unambiguous transaction with:

```bash
mnemo recovery rollback <transaction-id> --json
```

Recovery verifies the journal location and rollback backup hash. It refuses `manual-review` when the target matches neither recorded state, so an external edit is never guessed away.

### Explicit product probe

`detect` is filesystem-only. When you explicitly want version-level L1 evidence from installed products, run:

```bash
mnemo probe --json
mnemo probe --platform cursor --json
```

The probe invokes only the adapter-owned `--version` argument, without a shell or asset-derived input. It clears credential-bearing environment variables, supplies a disposable home, captures at most 8 KiB, terminates the child after five seconds, deletes the disposable directory, and never initializes migrated Skills, MCP servers, or plugins. Results are entrypoint-specific; missing CLI, unsupported Desktop/GUI entrypoints, failures, and timeouts produce explicit statuses and exit code `2`.

This is version-level L1 evidence, not proof that a particular migrated asset was discovered. The child process is not placed in an OS network namespace, so run it only for an installed executable you trust. See [Product probes](docs/product-probes.md) for the exact boundary.

### New-session Handoff capsule

Handoff carries a user-reviewed task summary into a fresh session without copying a product session database. Create JSON conforming to [`handoff.schema.json`](schemas/handoff.schema.json), then package it on the source device:

```bash
export MNEMOPORT_PASSPHRASE='choose-at-least-12-characters'
mnemo handoff --input handoff.json --output handoff.mnemo --json
```

On the target, use the normal `inspect` → `plan` → `trust` → `apply` flow. The target receives a Markdown sidecar under its project; no internal session identifier, chat database, or authentication state is injected.

## Command reference

| Command | Writes product state? | Purpose |
|---|---:|---|
| `mnemo doctor [--json]` | No | Resolve MnemoPort state and detected product tuples |
| `mnemo detect [--platform HOST] [--json]` | No | Detect one or all supported hosts without launching them |
| `mnemo probe [--platform HOST] [--json]` | Disposable probe state only | Run bounded, version-level L1 probes for safe entrypoints |
| `mnemo inventory --from HOST` | No | List supported assets and manual-only candidates without bodies |
| `mnemo export --from HOST --output FILE` | No | Extract, redact/quarantine, sign, compress, and encrypt a new package |
| `mnemo inspect FILE` | No | Decrypt, verify, and summarize a package |
| `mnemo plan --input FILE --to HOST --output PLAN` | No | Create a new immutable plan against the current target |
| `mnemo trust add --input FILE` | MnemoPort state only | Trust the verified signing identity of one source device |
| `mnemo trust list` | No | List locally trusted signer fingerprints |
| `mnemo apply --input FILE --plan PLAN --approve TOKEN` | Yes | Revalidate and transactionally write approved target files |
| `mnemo verify --input FILE --plan PLAN` | No | Rebuild expected L0 bytes and compare target hashes |
| `mnemo report ID` | No | Read operation status and journal count |
| `mnemo undo MIGRATION_ID` | Yes | Restore unchanged targets from local backups |
| `mnemo recovery list` | No | Classify prepared journals left by an interruption |
| `mnemo recovery rollback TRANSACTION_ID` | Yes | Safely close or restore one unambiguous prepared transaction |
| `mnemo integration install/status/uninstall` | Host Skill only | Manage the thin integration with ownership checks |
| `mnemo handoff --input JSON --output FILE` | No | Package a user-selected new-session capsule |

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

- Source inventory and extraction are read-only and never launch the source product.
- `.mnemo` content is deterministic, zstd-compressed, Ed25519-signed, and age-encrypted by default.
- Paths, symlinks, archive sizes, signatures, hashes, object closure, and target preconditions are verified.
- Apply uses synced local backups, durable journals, a SQLite audit ledger, and strong rollback for local files.
- Existing unrelated target content is preserved; conflicts are never silently overwritten.
- Authentication values, cookies, keychains, internal databases, trust decisions, and caches do not migrate.
- Scripts, hooks, plugins, and MCP servers are not executed during inventory, inspect, plan, or the default L0 verification.
- `--allow-plaintext` is an explicit escape hatch for intentional non-sensitive fixtures. It should not be used for real personal assets.

The alpha does not yet perform network plugin/extension installation, CLI dependency installation, OAuth/account export, MCP server execution, native auto-memory import, or broad editor-profile synchronization. It records or inventories these surfaces only when the adapter can do so safely. Prepared-journal crash recovery and version-level L1 probes are implemented; asset-level native discovery, later ledger crash points, and a first public binary tag remain release gates. The repository contains SBOM/provenance automation, but those claims apply to artifacts only after their tagged workflow succeeds.

## Troubleshooting

- **`mnemo: command not found`:** add Cargo's binary directory to `PATH`, then open a new shell.
- **Encrypted package asks for a passphrase:** set `MNEMOPORT_PASSPHRASE` to the same 12+ character value on source and target. The value is not stored in the package.
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
- [Product probes and evidence boundary](docs/product-probes.md)
- [Release and supply-chain security](docs/release-security.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

MnemoPort is available under the [MIT License](LICENSE).
