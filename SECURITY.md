# Security Policy

MnemoPort handles configuration, memories, prompts, executable skills, plugins, and integration definitions. Treat all imported assets as potentially sensitive and all executable assets as potentially untrusted.

## Reporting a vulnerability

Please do not open a public issue for an unpatched vulnerability or include real user data, tokens, or credentials in a report.

Until a dedicated security contact is published, contact the repository owner privately through the GitHub account associated with this repository. A formal disclosure address will be added before the first release.

## Security boundaries

- MnemoPort must remain model-provider independent: it must not require, read, or use model-provider API keys to inventory, export, plan, apply, verify, or undo a migration.
- Authentication tokens, cookies, keychain entries, API key values, and historical approvals must not be migrated by default.
- Source adapters must not modify the source application's state during normal extraction.
- Imported paths must be normalized and checked against path traversal.
- Packages must be verified before extraction into an isolated staging directory.
- Target changes must be planned, backed up, verified, and recoverable.
- Skills, hooks, plugins, and CLI dependencies must be surfaced for review before execution or installation.
