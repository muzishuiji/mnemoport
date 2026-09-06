# Product probes

`mnemo detect` never starts a product. `mnemo probe` is a separate, explicit local-assisted operation that produces version-level evidence for an exact platform, OS, and entrypoint tuple. After L0 file verification succeeds, `mnemo verify --level l1` can request asset-level native discovery for the same exact tuple.

## Safety contract

- The adapter supplies the executable and the single literal argument `--version`; package contents, filenames, migrated configuration, and user prompts cannot contribute arguments.
- MnemoPort invokes the executable directly, never through a shell.
- The child receives a disposable `HOME`, `USERPROFILE`, and XDG roots. The parent does not forward tokens, API keys, proxy credentials, or product configuration variables. `PATH` and the minimum Windows runtime variables are retained so packaged launchers can start.
- Standard input is closed. Captured output is bounded to 8 KiB and is used only to extract a short version token; raw output is not returned in the report.
- A five-second timeout terminates the child, and the disposable home is removed afterward.
- No migrated Skill, MCP server, plugin, hook, agent, or model request is initialized.

The probe does not establish an operating-system network sandbox. A trusted vendor executable is expected to treat `--version` as local metadata, but MnemoPort does not claim that arbitrary or replaced executables are unable to access the network. Asset-level L1 discovery requires a separate adapter recipe and is not inferred from version success.

## Entrypoint policy

| Product entrypoint | Version probe |
|---|---|
| Claude Code CLI | allowed |
| Codex CLI | allowed |
| Qoder CLI (`qodercli` or a classified CLI launcher) | allowed |
| Qoder Desktop/unknown dispatcher | not executed |
| Cursor Agent | allowed |
| Cursor IDE command launcher | allowed |

Qoder detection deliberately reports the CLI and Desktop as separate tuples. A Desktop installation cannot satisfy a CLI capability, and a Qoder dispatcher is classified by its resolved target before it is considered executable.

## Status meanings

| Status | Meaning |
|---|---|
| `verified` | The command exited successfully and a bounded version token was recognized |
| `unavailable` | No executable was found for this tuple |
| `unsupported_entrypoint` | The entrypoint is detected but is outside the automatic command allowlist |
| `failed` | Spawn, exit status, or version parsing failed |
| `timed_out` | The process exceeded five seconds and was terminated |

Any result other than `verified` makes the command return exit code `2`. Even `verified` upgrades only the version-level tuple evidence to `probe`; it does not upgrade Instructions, Skills, MCP, plugins, GUI, remote, or cloud capabilities.

## Asset-level discovery gate

An asset-level L1 recipe is admitted separately for each `product version × OS × entrypoint × asset kind`. Before it can become automatic, the recipe must have all of the following:

- fixed vendor-owned arguments and a bounded parser for structured or version-gated output;
- a fixture proving the product reports the exact migrated marker or identifier;
- before/after filesystem evidence defining every permitted write;
- proof that migrated MCP servers, plugins, hooks, agents, and scripts are not started;
- credentials and provider environment removed unless the recipe is explicitly classified as account-assisted;
- timeout, output limits, sanitized diagnostics, and a negative control that cannot pass from directory presence alone.

A command named `list` is not automatically safe. If it performs health checks, synchronizes a marketplace, starts an MCP server, invokes a model, or requires account state, that step is L2/account-assisted and requires separate authorization. Products without a safe authoritative discovery surface remain at L0 with an explicit manual result.

## Implemented asset-level recipes

The automatic allowlist in `v0.1.0-alpha.1` is intentionally narrow:

| Exact tuple | Asset | Fixed command | Isolated input | Pass condition |
|---|---|---|---|---|
| Codex CLI `0.144.1`, Linux | MCP | `codex mcp list --json` | A private disposable clone of target `config.toml` and workspace `.codex/config.toml` | Structured JSON contains every expected migrated MCP name |
| Qoder CLI `1.1.42`, Linux | Skill | `qodercli skills list --all` | A private disposable config/workspace containing only migrated `SKILL.md` files | Version-gated text contains each Skill name and a `Location:` under the disposable root |

Both commands run without a shell or standard input. The environment is cleared except for the fixed product roots, disposable OS data/cache/temp roots, `PATH`, and required Windows runtime variables. Codex has a 10-second timeout and Qoder a 20-second timeout. Combined stdout/stderr is terminated above 64 KiB; reports contain only stable diagnostics and counts. Temporary roots are deleted when verification returns. The parser cannot pass from target-directory presence alone, and `migrated_components_started` is always `false`.

Codex is not pointed at the live target during the native check because the observed CLI may create incidental temporary state even for a list command. Qoder likewise created machine/log/security state during direct testing, so only its isolated clone is used. The recipes never copy authentication stores or provider credentials into that clone.

## Asset-level status matrix

The following statuses apply only to migrated asset kinds present in the immutable plan:

| Product | Instructions | Skills | MCP |
|---|---|---|---|
| Claude Code CLI | `manual` | `manual` | `manual` |
| Codex CLI `0.144.1` on Linux | `manual` | `manual` | `verified` through the recipe above |
| Qoder CLI `1.1.42` on Linux | `manual` | `verified` through the recipe above | `manual` |
| Cursor Agent/IDE | `manual` | `manual` | `manual` |

For Codex MCP or Qoder Skill, a missing executable reports `unavailable`; a different version, OS, entrypoint, or config root reports `unsupported_version`. Asset kinds without an admitted recipe report `manual`. A parser mismatch, non-zero exit, timeout, or output-limit termination reports `failed`. Any non-`verified` asset result makes `verify --level l1` return exit code `2`, while preserving the successful L0 result.

These are discovery claims, not execution claims. Claude Code MCP listing is manual because the available command may perform server health checks. Cursor's native MCP/tool surfaces and fast-moving Skills/Agent Plugins remain manual because the observed commands cross into component initialization or lack a stable exact-version discovery contract. No product's plugin marketplace, extension installer, auto-memory database, session store, or account state is touched.

## Reproduced observations

On 2026-09-06, Linux end-to-end fixtures were exported, planned, applied, and checked through the actual installed vendor commands. Codex CLI `0.144.1` discovered one migrated MCP entry and Qoder CLI `1.1.42` discovered one migrated Skill; each result reported `expected_assets: 1`, `discovered_assets: 1`, `isolated_copy: true`, and `migrated_components_started: false`. All other cells remained explicit manual outcomes. The machine-readable snapshot is in [`compatibility.json`](compatibility.json).
