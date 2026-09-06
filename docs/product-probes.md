# Product probes

`mnemo detect` never starts a product. `mnemo probe` is a separate, explicit local-assisted operation that produces version-level L1 evidence for an exact platform, OS, and entrypoint tuple.

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
