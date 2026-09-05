# Contributing to MnemoPort

Thank you for your interest in MnemoPort.

The project is an implementation-stage alpha with a frozen v1 package/schema baseline. Before submitting a substantial implementation, please open an issue describing:

- the source and target platform involved;
- the asset types and scopes being handled;
- whether the behavior relies on a documented interface or version-specific probing;
- how secrets, existing target state, verification, and rollback are handled;
- which sanitized fixtures and tests will cover the change.

## Contribution requirements

- Never commit real credentials, authentication state, private conversations, or unredacted user data.
- Treat source adapters as read-only.
- Do not claim migration success without target-side verification.
- Preserve unknown configuration fields whenever possible.
- Keep version-specific platform behavior isolated inside its adapter.
- Add tests for malformed input, conflicts, repeated application, and rollback.
- Clearly label undocumented or reverse-engineered behavior.
- Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features`.

By contributing, you agree that your contributions will be licensed under the project's MIT License.
