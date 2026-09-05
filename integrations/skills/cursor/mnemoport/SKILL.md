---
name: mnemoport
description: Migrate, export, inspect, plan, install, or undo portable AI assets between Cursor, Codex, Claude Code, and Qoder, including same-tool cross-device moves. Use when the user asks to move or synchronize instructions, skills, prompts, preferences, or MCP definitions.
---

# MnemoPort for Cursor

Treat Cursor Agent and Cursor IDE as separate entrypoints and keep the current host explicit. Use the `mnemo` CLI as the authority for paths, parsing, package security, conflict handling, writes, and rollback.

1. Run `mnemo doctor --json` and explain unavailable platform roots without guessing replacements.
2. For a local source, run `mnemo inventory --from <platform> --invoked-by cursor --json` first. Report every skipped/manual category; an empty result is not proof that nothing exists.
3. On source device A, export with `mnemo export --from <platform> --invoked-by cursor --output <name>.mnemo --json`. Encrypted export is the default. Never ask the user to paste a passphrase or token into chat or a command argument; have them inject `MNEMOPORT_PASSPHRASE` through their terminal or secret manager. Use `--allow-plaintext` only after an explicit request and warning.
4. On target device B, inspect first, then plan: `mnemo inspect <name>.mnemo --json`, followed by `mnemo plan --input <name>.mnemo --to cursor --invoked-by cursor --output mnemo-plan.json --json`.
5. For a new source device, show the signer fingerprint and ask whether to trust it. Only after confirmation run `mnemo trust add --input <name>.mnemo --label <device> --json`.
6. Summarize exact writes, no-ops, conflicts, reauthentication, quarantine, and unsupported assets. Do not treat the printed approval token as permission by itself. Wait for the user to approve this displayed plan.
7. After approval, run `mnemo apply --input <name>.mnemo --plan mnemo-plan.json --approve <token> --invoked-by cursor --json`, then `mnemo verify --input <name>.mnemo --plan mnemo-plan.json --json`. Report the migration id and L0 verification result.
8. Use `mnemo report <migration-id> --json` for local audit evidence. Use `mnemo undo <migration-id> --json` only when requested. If MnemoPort reports target drift, stop and preserve the user's newer edits.

Exit code 2 means the safe portion completed but manual, quarantine, reauthentication, or conditional work remains; parse the JSON body and report those items rather than treating it as a crash.

Never copy `state.vscdb`, User Rules/Memory internals, chat history, extension binaries, cookies, auth state, or an entire Cursor User Data directory. Do not launch migrated scripts, plugins, hooks, MCP servers, or network installers during inventory, package inspection, or planning. Secret references may migrate; secret values may not.
