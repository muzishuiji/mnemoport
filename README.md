# MnemoPort

MnemoPort is an open-source portability layer for personal AI assets.

Its goal is to help users move their instructions, memories, skills, MCP server definitions, plugins, prompts, preferences, and active work between AI tools and devices without being locked into one application's local format or usage quota.

## Project status

MnemoPort is currently in the architecture and specification phase. The initial target platforms are:

- Codex
- Claude Code
- Qoder
- QwenWork
- WorkBuddy

The planned user experience covers both cross-tool and cross-device workflows:

```text
Tool X on device A  ->  portable .mnemo package  ->  Tool X on device B
Tool X              ->  canonical asset model   ->  Tool Y
```

The source application does not need remaining model quota. Local extraction is designed to be read-only, and credentials are excluded by default.

## Design principles

- Local-first and auditable
- Read-only source adapters
- Explicit planning before target writes
- Raw source preservation plus normalized assets
- No silent credential, token, cookie, or keychain migration
- Idempotent application, verification, backups, and rollback
- Honest capability reporting: exact, transformed, reinstalled, manual, skipped, or unsupported

## License

MnemoPort is available under the [MIT License](LICENSE).

## Contributing

The public contributor workflow will be expanded as the first executable specification lands. In the meantime, see [CONTRIBUTING.md](CONTRIBUTING.md).

