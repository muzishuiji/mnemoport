# MnemoPort contributor instructions

- Preserve the local-first security boundary: source discovery is read-only unless an assisted mode is explicitly selected.
- Never add real credentials, cookies, OAuth state, private remotes, user paths, or raw product databases to fixtures.
- Adapters return typed proposed operations; only the core transaction layer may mutate target files.
- Every compatibility claim must identify platform, version, OS, entrypoint, asset kind, direction, and evidence level.
- Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features` before handing off code changes.
- Keep `.private/` ignored. Public documentation must not expose machine-specific research details.

