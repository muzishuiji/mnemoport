# Release and supply-chain security

MnemoPort's ordinary CI checks formatting, Clippy, tests, RustSec advisories, dependency licenses, dependency sources, and wildcard version requirements. `deny.toml` is the reviewed policy for `cargo-deny`; exceptions must be narrow, versioned, and explain their reason.

The Release workflow can be exercised manually without publishing. A tag matching the workspace version exactly (`vMAJOR.MINOR.PATCH`) builds locked release binaries for Linux x86-64, macOS Apple Silicon, and Windows x86-64. A mismatched tag fails before any build begins. A tagged run publishes compressed binaries, SHA-256 checksum files, and a CycloneDX JSON SBOM.

GitHub's OIDC-backed artifact attestation signs build provenance and the SBOM relationship with an ephemeral Sigstore certificate. MnemoPort does not store a long-lived release signing private key in the repository or Actions secrets.

Verify a downloaded checksum with the platform SHA-256 tool, then verify GitHub provenance:

```bash
gh attestation verify mnemoport-x86_64-unknown-linux-gnu.tar.gz \
  --repo muzishuiji/mnemoport
```

Attestation proves which repository workflow produced the artifact. It does not replace review of the tag, source commit, dependency policy, or compatibility report.
