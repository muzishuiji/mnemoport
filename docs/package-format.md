# `.mnemo` package format v1

An unencrypted v1 payload is a deterministic zstd-compressed POSIX tar archive. Encrypted packages wrap the complete signed payload with age passphrase encryption.

```text
manifest.json
signature.ed25519
objects/assets/<asset-id>.json
objects/blobs/sha256/<digest>
```

`manifest.json` contains the format/minimum-reader versions, required and optional features, a content-derived package id, ordered object path/hash/size descriptors, the object-tree root hash, and the Ed25519 public key. `signature.ed25519` authenticates the exact canonical manifest bytes. Tar owners and timestamps are normalized, entries are bytewise ordered, and the package id contains no random UUID, so identical assets signed by the same key produce identical plaintext package bytes.

Import performs the reverse pipeline: decrypt, bounded decompress, reject non-regular/traversing/duplicate/undeclared entries, parse the canonical manifest, verify the signature, verify every object hash and size, then reconstruct Canonical Assets and referenced blobs. Nothing is extracted directly to a target path.

Encryption is intentionally outside the signature envelope: decryption yields a self-contained signed package, and any ciphertext modification is rejected by age authentication before package parsing.

The current reader limit is 100,000 entries and 512 MiB uncompressed data. Unsupported required features fail closed.
