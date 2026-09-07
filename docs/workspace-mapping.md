# Portable workspace mapping

MnemoPort can preserve several project roots in one migration without disclosing source-device paths. This is useful for multi-root IDE users and for moving the same AI tool between devices.

## Source selection

Repeat `--workspace LABEL=PATH` on `inventory` or `export`:

```bash
mnemo inventory --from cursor \
  --workspace frontend=/source/projects/frontend \
  --workspace backend=/source/projects/backend \
  --json

mnemo export --from cursor \
  --workspace frontend=/source/projects/frontend \
  --workspace backend=/source/projects/backend \
  --output workspaces.mnemo \
  --recipient 'age1...' \
  --json
```

Paths may be relative at the CLI boundary but must resolve to distinct existing directories. Labels are trimmed, unique within the package, 1–64 characters, and cannot contain control characters, `/`, `\`, or `=`. A workspace id is deterministically derived from the normalized label. Choose stable, non-sensitive labels; changing a label intentionally creates a different portable identity.

Only the descriptor and id cross the package boundary. Workspace/project assets receive the id in their provenance and are re-keyed with it. Repeated user/device assets found while scanning several roots are included once. Neither source path nor target path is placed in a Canonical Asset.

## Destination map

Run `inspect` on the destination and use the returned `workspaces` labels and ids to create a local map:

```json
{
  "schema_version": "1.0",
  "mappings": {
    "sha256:<frontend-workspace-id>": "/destination/projects/frontend",
    "sha256:<backend-workspace-id>": "/destination/projects/backend"
  }
}
```

Then create the plan:

```bash
mnemo inspect workspaces.mnemo --json
mnemo plan \
  --input workspaces.mnemo \
  --to codex \
  --workspace-map workspace-map.json \
  --output migration-plan.json \
  --json
```

The map must contain exactly the ids declared by the package. Every destination must be absolute, unique, already exist, be a directory, and not itself be a symbolic link. MnemoPort canonicalizes the paths before planning. Missing/extra ids, duplicate destinations, relative paths, unavailable directories, and leaf symlinks fail before any target write.

The canonical mappings are bound into `plan_id`. They are local target information and can contain private paths, so protect the plan like other migration state. `apply` and `verify` read the mappings from the saved plan, revalidate every directory, rebuild the target result, and reject drift; they do not accept a replacement map.

## Compatibility behavior

An export without `--workspace` keeps the original single-current-workspace behavior and does not require a map. Once explicit workspace descriptors are present—even if there is only one—the exact target map is mandatory. This avoids silently collapsing several source roots into the process current directory.

L0 verifies every mapped target by byte hash. Multi-workspace asset-level L1 recipes are currently reported as `manual` with `multi_workspace_asset_recipe_not_yet_admitted`; single-workspace exact-version recipes remain unchanged. This is an explicit safety boundary until each vendor discovery command has been validated independently for multiple target roots.
