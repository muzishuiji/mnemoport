---
name: mnemoport
description: Migrate, export, inspect, plan, install, or undo portable AI assets between Claude Code, Codex, Qoder, and Cursor, including same-tool, cross-device, multi-workspace, and plugin-inventory work. Use when the user asks to move or synchronize instructions, skills, prompts, preferences, MCP definitions, plugins, or extensions.
---

# MnemoPort for Claude Code

Treat Claude Code CLI as the current host. Use the `mnemo` CLI as the authority for paths, parsing, package security, conflict handling, writes, and rollback. Do not use Anthropic web login as part of migration.

1. Run `mnemo doctor --json` and explain unavailable platform roots without guessing replacements.
2. For a local source, run `mnemo inventory --from <platform> --invoked-by claude-code --json` first. Report every skipped/manual category; an empty result is not proof that nothing exists.
   - When the user selects several repositories or IDE roots, choose stable non-sensitive labels and repeat `--workspace <label>=<source-path>` on both inventory and export. Do not serialize or report source absolute paths as portable metadata.
   - When plugins or IDE extensions are in scope, explain that the trusted vendor list may create incidental local state, then separately run `mnemo plugin-inventory --from <platform> --workspace <source-path> --json`. Treat `collected` as source-side reinstall intent only. Report `manual`, `unavailable`, `unsupported_version`, and `failed` per entrypoint; never claim those entries were packaged, installed, or target-verified.
3. For cross-device export, prefer a destination-generated public recipient: on B run `mnemo recipient generate --output <private.agekey> --json`, retain the private file only on B, and give A only the returned `age1...` value. On A export with `mnemo export --from <platform> --invoked-by claude-code --output <name>.mnemo --recipient <age1...> --json`. If recipient mode is unavailable, omit it and have the user inject `MNEMOPORT_PASSPHRASE` through their terminal or secret manager. Never ask for a private age identity, passphrase, or token in chat or a command argument. Use `--allow-plaintext` only after an explicit request and warning.
4. On target device B, select its private identity with `--identity <private.agekey>` or `MNEMOPORT_IDENTITY_FILE`, inspect first, then plan: `mnemo inspect <name>.mnemo --json`, followed by `mnemo plan --input <name>.mnemo --to claude-code --invoked-by claude-code --output mnemo-plan.json --json`.
   - If `inspect` reports workspaces, create a target-local Workspace Map whose keys exactly match those ids and whose values are distinct existing absolute destination directories. Pass it to plan as `--workspace-map <map.json>`. Never guess an ambiguous destination, reuse a source path from package content, or pass another map to apply/verify; those commands use the mapping bound into the approved plan.
5. For a new source device, show the signer fingerprint and ask whether to trust it. Only after confirmation run `mnemo trust add --input <name>.mnemo --label <device> --json`.
6. Summarize exact writes, no-ops, conflicts, reauthentication, quarantine, and unsupported assets. Do not treat the printed approval token as permission by itself. Wait for the user to approve this displayed plan.
7. After approval, run `mnemo apply --input <name>.mnemo --plan mnemo-plan.json --approve <token> --invoked-by claude-code --json`, then `mnemo verify --input <name>.mnemo --plan mnemo-plan.json --json`. Report the migration id and L0 verification result.
8. Use `mnemo report <migration-id> --json` for local audit evidence. Use `mnemo undo <migration-id> --json` only when requested. Retired or lost source signers can be removed only by an explicit `mnemo trust revoke <full-fingerprint>` or planned `trust rotate`; never infer revocation. If MnemoPort reports target drift, stop and preserve the user's newer edits.

Exit code 2 means the safe portion completed but manual, quarantine, reauthentication, or conditional work remains; parse the JSON body and report those items rather than treating it as a crash.

Never copy an entire product configuration directory. Never migrate auth files, keychains, cookies, internal databases, sessions, trust decisions, caches, or telemetry. Do not launch migrated scripts, plugins, hooks, MCP servers, or network installers during inventory, package inspection, or planning. Secret references may migrate; secret values may not.
