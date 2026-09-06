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

The same file records the latest Linux version-level L1 observation produced by `mnemo probe`. Claude Code CLI, Codex CLI, Cursor Agent, and the Cursor IDE command launcher returned recognized versions. Qoder CLI was not installed on that host, while Qoder Desktop was detected and deliberately not executed. These observations identify exact entrypoints only; see [Product probes](product-probes.md).
