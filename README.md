# MnemoPort

MnemoPort is an open-source portability layer for personal AI assets. It moves file-backed instructions, Skills, prompts, and credential-free MCP definitions between Codex, Claude Code, Qoder, and Cursor—or between two devices running the same tool.

```text
Tool X on device A  ->  encrypted .mnemo package  ->  Tool X on device B
Tool X              ->  canonical asset model    ->  Tool Y
```

The project is an implementation-stage alpha. The Rust CLI, signed/encrypted package, transactional apply/undo, four offline adapters, four thin host Skills, and the 16-direction Core smoke matrix are implemented and tested. Native auto-memory stores, account/cloud data, plugin network installation, and full preference allowlists remain deliberately non-automatic.

## What it migrates today

| Asset | Current alpha behavior |
|---|---|
| Instructions/rules | File-backed user/project sources; exact X→X paths where stable, safe target-native mapping across tools |
| Skills | Complete file trees rooted by `SKILL.md`; symlinks rejected, active/non-text content quarantined and never auto-applied |
| Prompts/commands | File-backed Markdown; mapped to commands or thin Skills where appropriate |
| MCP | JSON/TOML definitions; command, args, URL and secret reference names only; secret values are discarded |
| Preferences/settings | Inventory only until each portable-key allowlist is implemented |
| Auto memory | Inventory/manual unless a documented, version-gated file mapping is available; internal databases are never written |
| Plugins/extensions/CLI dependencies | Not extracted automatically yet; the canonical intent boundary exists, while caches and binaries are never copied or executed |
| Sessions/auth/trust/cache | Excluded; use a new-session handoff rather than database injection |

## Install from source

Rust 1.85 or newer is required.

```bash
cargo install --locked --path crates/mnemo-cli
mnemo doctor --json
```

Install the thin Skill into a supported host:

```bash
mnemo integration install --host codex --scope user --json
mnemo integration status --host codex --scope user --json
```

The installer refuses to overwrite an existing Skill. Uninstall removes only a file that MnemoPort recorded as managed and whose hash is unchanged.

## Cross-device workflow

On source device A:

```bash
mnemo inventory --from qoder --invoked-by qoder --json
export MNEMOPORT_PASSPHRASE='set-this-through-your-secret-manager'
mnemo export --from qoder --invoked-by qoder --output qoder-assets.mnemo --json
```

Transfer the single `.mnemo` file through a channel you trust. On target device B:

```bash
export MNEMOPORT_PASSPHRASE='set-this-through-your-secret-manager'
mnemo inspect qoder-assets.mnemo --json
mnemo plan --input qoder-assets.mnemo --to codex --invoked-by codex --output migration-plan.json --json
mnemo trust add --input qoder-assets.mnemo --label device-a --json
```

Read the returned writes, skipped items, conflicts, and approval token. Only after approving that exact plan:

```bash
mnemo apply --input qoder-assets.mnemo --plan migration-plan.json --approve <token> --invoked-by codex --json
mnemo verify --input qoder-assets.mnemo --plan migration-plan.json --json
mnemo report <migration-id> --json
mnemo undo <migration-id> --json
```

Passphrases are never accepted as command arguments. Encryption is the default; `--allow-plaintext` is an explicit escape hatch for intentional non-sensitive fixtures. Existing target content is preserved by default, and any post-plan drift invalidates apply.

To carry only the current task into a new session, create a JSON capsule conforming to [`handoff.schema.json`](schemas/handoff.schema.json), then package it on device A:

```bash
mnemo handoff --input handoff.json --output handoff.mnemo --json
```

On device B, use the normal `inspect` → `plan` → `trust` → `apply` flow. The target receives a Markdown handoff sidecar; no product session database or internal session identifier is copied.

## Safety model

- Source inventory and extraction are read-only and never launch the source product.
- `.mnemo` content is deterministic, zstd-compressed, Ed25519-signed, and age-encrypted by default.
- Paths, symlinks, archive sizes, signatures, hashes, and target preconditions are verified.
- Apply uses synced local backups, durable journals, a SQLite audit ledger, and strong rollback for local files.
- Authentication values, cookies, keychains, internal databases, trust decisions, and caches do not migrate.
- Scripts, hooks, plugins, and MCP servers are not executed during inventory, inspect, or plan.

See [architecture](docs/architecture.md), [compatibility](docs/compatibility.md), [machine-readable compatibility evidence](docs/compatibility.json), [package format](docs/package-format.md), [security policy](SECURITY.md), and [contributing](CONTRIBUTING.md).

## License

MnemoPort is available under the [MIT License](LICENSE).
