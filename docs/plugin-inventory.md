# Authoritative plugin and extension inventory

`mnemo plugin-inventory` is the P1-C read-only discovery surface. It asks an
installed product for its installed plugin or extension list, normalizes only
portable reinstall intent, and returns an explicit result for every detected
entrypoint. It does not install, remove, enable, load, copy, package, or execute
any plugin component.

“Read-only” describes the requested vendor operation and MnemoPort's own target
behavior. Because the trusted vendor executable reads live source state, the
vendor may still create incidental logs, locks, or cache metadata. This command
is therefore explicit local-assisted discovery, not the zero-process,
offline-static guarantee of normal `inventory` and `export`.

```bash
mnemo plugin-inventory --from claude-code --json
mnemo plugin-inventory --from codex --json
mnemo plugin-inventory --from qoder --json
mnemo plugin-inventory --from cursor --json
```

Claude project/local scopes are resolved from the current directory. Select a
different source workspace explicitly with `--workspace PATH`. Cursor IDE also
accepts an explicit named profile and extension root:

```bash
mnemo plugin-inventory --from cursor \
  --workspace /path/to/project \
  --profile work \
  --extensions-dir /path/to/extensions \
  --json
```

`--profile` and `--extensions-dir` are rejected for non-Cursor products. Paths
are used only for the local invocation and are removed from the report.

## Exact admitted matrix

The current allowlist is intentionally narrow. A result from one version, OS,
or entrypoint is never inherited by another.

| Product tuple | Authoritative command | Result |
|---|---|---|
| Claude Code CLI `2.1.259`, Linux | `claude plugin list --json` | Installed Claude plugins, including marketplace-qualified ID, resolved version, scope, and enabled state |
| Codex CLI `0.144.1`, Linux | `codex plugin list --json` | Installed Codex plugins, including plugin ID, marketplace, resolved version, enabled state, and installation/authentication policy |
| Cursor IDE launcher `3.17.21`, Linux | `cursor --list-extensions --show-versions` | VS Code-compatible IDE extension ID/version tuples only |
| Cursor Agent `2026.09.02-c22c1a3` | No installed-plugin list in this entrypoint | `manual` |
| Qoder CLI | Official `plugins list` exists, but no admitted structured output contract | `manual` when the CLI is available; `unavailable` otherwise |
| Qoder Desktop/IDE | Official Plugins UI has no machine-readable export admitted by MnemoPort | `manual` |

The command returns exit `0` only when every detected entrypoint is collected.
Mixed products such as Cursor can return a collected IDE extension report and a
manual Agent-plugin report together; this intentionally produces exit `2`.
An empty `intents` array is authoritative only when `status` is `collected`.

The distinctions follow the vendor contracts: [Claude Code's plugin list](https://code.claude.com/docs/en/plugins-reference)
documents version, source marketplace, enable state, and installation scopes;
[Codex plugins](https://learn.chatgpt.com/en/docs/plugins) are available in the
CLI and desktop app but not the IDE extension; [Qoder's CLI reference](https://docs.qoder.com/cli/plugins-reference)
documents `plugins list` without a stable JSON contract; and [Cursor plugins](https://prod.cursor.com/docs/plugins)
separate Agent Plugins and Cursor Plugins. The Cursor IDE extension command is
gated by the exact locally observed launcher version and its built-in help,
rather than generalized from the Agent-plugin documentation.

## Canonical intent

Each collected item preserves:

- `ecosystem` and `subtype`, so Claude plugins, Codex plugins, Qoder plugins,
  Cursor Agent Plugins, Cursor Plugins, and Cursor IDE extensions never collide;
- stable `identifier`, optional `requested_version`, observed
  `resolved_version`, sanitized `source`, vendor `scope`, and `entrypoint`;
- enabled state and vendor install/auth policy when the source exposes them;
- `inventory_evidence` containing the exact product version, fixed sanitized
  argument vector, full-output SHA-256 hash, and whether the parser consumed
  JSON or a version-gated line protocol;
- a prospective `compensation` class. P1-C records this field but never invokes
  it.

The legacy v1 `version` and `source` fields remain readable. New inventory uses
`resolved_version` and the expanded typed fields. See
[`canonical-asset.schema.json`](../schemas/canonical-asset.schema.json) and
[`plugin-inventory-report.schema.json`](../schemas/plugin-inventory-report.schema.json).

## Execution and privacy boundary

- Invocation is explicit; normal `inventory` and `export` remain offline-static.
- MnemoPort performs no target mutation, but does not claim the vendor process
  produces zero incidental local writes while reading its live configuration.
- MnemoPort executes a detected vendor binary directly with fixed arguments,
  closed stdin, a five-second timeout, and a 1 MiB output ceiling.
- Credential-bearing environment variables are not forwarded. Only local path
  and OS runtime variables needed to resolve the installed product state are
  retained.
- `--available` is never used, so marketplace browsing is not requested.
- Raw stdout, stderr, cache paths, install paths, executable paths, configuration
  roots, and extension binaries are not returned or retained. The normalized
  report carries only a hash of complete stdout.
- Parser mismatch, duplicates, non-UTF-8, non-zero exit, timeout, or oversized
  output fails closed and returns no partial intent list.
- The child is not placed in an operating-system network namespace. MnemoPort
  does not request network access, but it cannot claim that a trusted vendor
  executable is technically unable to access the network.
- `migrated_components_started` is always `false`; plugin contents and MCP
  servers inside plugins are never initialized.

This feature is inventory only. Exporting these intents into `.mnemo`, target
compatibility mapping, official installation, separate external approval, and
compensating removal belong to the later P1 external-action phase.
