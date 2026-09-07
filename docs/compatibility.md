# Compatibility

Support is keyed by product, version, operating system, and entrypoint. A capability observed in one tuple is not inherited by another.

| Platform | Offline source roots | Automatic target surface | Explicit exclusions |
|---|---|---|---|
| Claude Code CLI | `CLAUDE_CONFIG_DIR`/`~/.claude`, selected workspace | `CLAUDE.md`, `.claude/rules`, `.claude/skills`, commands, project `.mcp.json` | Auth/account JSON, project trust, sessions, shell snapshots, plugin caches, Hooks/Agents activation |
| Codex CLI/App | `CODEX_HOME`/`~/.codex`, `~/.agents`, selected workspace | `AGENTS.md`, `.agents/skills`, managed MCP blocks in `config.toml` | `auth.json`, memories/session/state SQLite, WAL/SHM, approvals, logs, plugin cache, IDE plugin activation |
| Qoder CLI/Desktop | `QODER_CONFIG_DIR`/`~/.qoder`, selected workspace | `AGENTS.md`, `.qoder/rules`, `.qoder/skills`, commands, project `.mcp.json` | Electron App Data, login state, unknown memory stores, Hooks/Agents activation, plugin cache |
| Cursor Agent/IDE | `~/.cursor`, `~/.agents`, selected workspace | `.cursor/rules/*.mdc`, `.cursor/skills`, `.agents/skills`, `.cursor/mcp.json` | `state.vscdb`, cookies/OAuth, User Rules/Memory internals, chat/remote history, extension binaries |

## Entrypoint cautions

- Claude validation is CLI-first. Third-party model credentials are runtime configuration and never migration assets.
- Codex user Skills use the current `~/.agents/skills` root; the legacy `$CODEX_HOME/skills` root is source-compatible and retains provenance.
- `/usr/bin/qoder` may resolve to the desktop application, not Qoder CLI. MnemoPort canonicalizes the executable before classifying it.
- Cursor Agent and Cursor IDE are separate tuples. File-backed project assets can overlap, while UI state, history, extensions, and cloud state do not.

## Verification levels

- L0: parse, schema, hash, target file and package integrity. Implemented as the default gate.
- L1: target product discovery without starting migrated MCP/plugin code. Adapter-specific probes are version-gated.
- L2: sandboxed component initialization or model marker. Requires separate authorization because it can execute code or consume quota.
- L3: business-function call. Test-only and never a default migration step.

The repository test suite exercises all 16 source→target directions for Instructions, Skills, credential-free MCP definitions, and Handoff capsules through a signed package and transactional target write. Unsupported scope mappings must produce an explicit manual result. This matrix is a Core L0 smoke gate, not a claim that every conditional asset is supported in every product entrypoint.

The exact fixture evidence is published as [machine-readable compatibility data](compatibility.json). Native product discovery (L1) and component execution (L2) remain separate, versioned claims; fixture success never upgrades an untested product version or GUI/remote entrypoint.

## Plugin and extension inventory

`mnemo plugin-inventory` is a separate explicit local-assisted read. On Linux,
the currently admitted exact tuples are Claude Code CLI `2.1.259`, Codex CLI
`0.144.1`, and Cursor IDE launcher `3.17.21`. Claude and Codex use their JSON
plugin list; Cursor IDE contributes only its ID/version extension list. Cursor
Agent plugins, Cursor Plugins from Customize, and Qoder CLI/Desktop/IDE plugins
remain explicit manual cells because the observed entrypoints do not expose an
admitted structured installed-state export. No cache, binary, install path, or
raw command output is retained, and nothing is installed. See
[Authoritative plugin and extension inventory](plugin-inventory.md).

The same file records the latest Linux observations. Version probing recognized Claude Code CLI `2.1.259`, Codex CLI `0.144.1`, Qoder CLI `1.1.42`, Cursor Agent `2026.09.02-c22c1a3`, and the Cursor IDE command launcher `3.17.21`; Qoder Desktop remained a separate unsupported entrypoint. Actual end-to-end native discovery verified only Codex CLI `0.144.1` MCP and Qoder CLI `1.1.42` Skill recipes. A later 2026-09-08 read-only inventory collected zero Claude plugins, ten Codex plugins, and four Cursor IDE extensions on the local test host; Cursor Agent remained manual and the then-current Qoder CLI executable was unavailable. Counts describe that one test host, not a portable product default. Instructions and all other product/asset cells remain explicit manual outcomes; different versions, operating systems, entrypoints, or roots do not inherit those claims. See [Product probes](product-probes.md).
