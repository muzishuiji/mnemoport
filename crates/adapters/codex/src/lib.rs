//! OpenAI Codex adapter.

use mnemo_adapter_common::{
    AdapterError, CollectionMode, ExtractedAsset, InventoryItem, PlatformAdapter, RenderedFile,
    TargetRoot, collect_skills, collect_text_if_present, collect_toml_mcp_if_present,
    detected_tuple, find_executable, inventory_only_if_present, merge_mcp_toml, portable_name,
    render_file_tree, render_handoff, render_text_file, resolve_root, user_home,
};
use mnemo_schema::{AssetKind, Entrypoint, Platform, ProductTuple, ScopeLevel};
use std::path::{Path, PathBuf};

/// Codex platform adapter.
#[derive(Debug, Default)]
pub struct CodexAdapter;

impl PlatformAdapter for CodexAdapter {
    fn platform(&self) -> Platform {
        Platform::Codex
    }

    fn detect(&self) -> Result<Vec<ProductTuple>, AdapterError> {
        let root = resolve_root("CODEX_HOME", ".codex")?;
        Ok(vec![detected_tuple(
            Platform::Codex,
            Entrypoint::Cli,
            find_executable("codex"),
            root,
        )])
    }

    fn inventory(&self, mode: CollectionMode) -> Result<Vec<InventoryItem>, AdapterError> {
        let codex_root = resolve_root("CODEX_HOME", ".codex")?.path;
        let home = user_home()?;
        let workspace = current_directory()?;
        Ok(collect_from_roots(&codex_root, &home, &workspace, mode)?.inventory)
    }

    fn extract(&self, mode: CollectionMode) -> Result<Vec<ExtractedAsset>, AdapterError> {
        let codex_root = resolve_root("CODEX_HOME", ".codex")?.path;
        let home = user_home()?;
        let workspace = current_directory()?;
        Ok(collect_from_roots(&codex_root, &home, &workspace, mode)?.extracted)
    }
}

/// Isolated result used by inventory and extraction fixture tests.
#[derive(Debug, Default)]
pub struct CodexSnapshot {
    /// Metadata-only inventory.
    pub inventory: Vec<InventoryItem>,
    /// Canonical extracted assets and object bodies.
    pub extracted: Vec<ExtractedAsset>,
}

/// Collect documented offline-static Codex assets from explicit roots without
/// opening local databases, sessions, auth state, logs, caches, or memories.
pub fn collect_from_roots(
    codex_root: &Path,
    user_home_root: &Path,
    workspace_root: &Path,
    _mode: CollectionMode,
) -> Result<CodexSnapshot, AdapterError> {
    let mut snapshot = CodexSnapshot::default();
    for relative in ["AGENTS.override.md", "AGENTS.md"] {
        collect_text_if_present(
            Platform::Codex,
            codex_root,
            relative,
            AssetKind::Instruction,
            ScopeLevel::User,
            &mut snapshot.inventory,
            &mut snapshot.extracted,
        )?;
        collect_text_if_present(
            Platform::Codex,
            workspace_root,
            relative,
            AssetKind::Instruction,
            ScopeLevel::Workspace,
            &mut snapshot.inventory,
            &mut snapshot.extracted,
        )?;
    }
    collect_skills(
        Platform::Codex,
        codex_root,
        "skills",
        ScopeLevel::User,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_skills(
        Platform::Codex,
        user_home_root,
        ".agents/skills",
        ScopeLevel::User,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_skills(
        Platform::Codex,
        workspace_root,
        ".agents/skills",
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    inventory_only_if_present(
        codex_root,
        "config.toml",
        AssetKind::Preference,
        ScopeLevel::User,
        &mut snapshot.inventory,
    )?;
    collect_toml_mcp_if_present(
        Platform::Codex,
        codex_root,
        "config.toml",
        ScopeLevel::User,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    inventory_only_if_present(
        workspace_root,
        ".codex/config.toml",
        AssetKind::Preference,
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
    )?;
    collect_toml_mcp_if_present(
        Platform::Codex,
        workspace_root,
        ".codex/config.toml",
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    snapshot.inventory.sort_by(|left, right| {
        (left.scope as u8, &left.locator).cmp(&(right.scope as u8, &right.locator))
    });
    snapshot.extracted.sort_by(|left, right| {
        (left.asset.scope as u8, &left.asset.provenance.locator)
            .cmp(&(right.asset.scope as u8, &right.asset.provenance.locator))
    });
    Ok(snapshot)
}

/// Render one supported canonical asset to documented Codex roots.
/// Structured config and MCP merges are handled separately.
pub fn render_target(extracted: &ExtractedAsset) -> Result<Vec<RenderedFile>, AdapterError> {
    let workspace_scope = matches!(
        extracted.asset.scope,
        ScopeLevel::Workspace | ScopeLevel::Project
    );
    let name = portable_name(&extracted.asset.title, &extracted.asset.asset_id);
    match extracted.asset.kind {
        AssetKind::Instruction => {
            let root = if workspace_scope {
                TargetRoot::Workspace
            } else if extracted.asset.scope == ScopeLevel::User {
                TargetRoot::ProductConfig
            } else {
                return manual_scope_error(extracted);
            };
            Ok(vec![render_text_file(extracted, root, "AGENTS.md")?])
        }
        AssetKind::Skill => {
            if workspace_scope {
                render_file_tree(
                    extracted,
                    TargetRoot::Workspace,
                    &format!(".agents/skills/{name}"),
                )
            } else if extracted.asset.scope == ScopeLevel::User {
                render_file_tree(
                    extracted,
                    TargetRoot::UserHome,
                    &format!(".agents/skills/{name}"),
                )
            } else {
                manual_scope_error(extracted)
            }
        }
        AssetKind::Prompt => {
            let root = if workspace_scope {
                TargetRoot::Workspace
            } else if extracted.asset.scope == ScopeLevel::User {
                TargetRoot::UserHome
            } else {
                return manual_scope_error(extracted);
            };
            let directory = format!(".agents/skills/{name}");
            let mnemo_prompt = format!(
                "---\nname: {name}\ndescription: Migrated prompt\n---\n\n{}",
                match &extracted.asset.payload {
                    mnemo_schema::AssetPayload::Text(text) => text,
                    _ => return manual_payload_error(extracted),
                }
            );
            Ok(vec![RenderedFile {
                root,
                relative_path: format!("{directory}/SKILL.md"),
                bytes: mnemo_prompt.into_bytes(),
                asset_id: extracted.asset.asset_id.clone(),
            }])
        }
        AssetKind::Handoff => Ok(vec![render_handoff(extracted)?]),
        _ => manual_payload_error(extracted),
    }
}

/// Merge one MCP server into user or project Codex TOML with a managed block.
pub fn render_mcp_target(
    extracted: &ExtractedAsset,
    existing: Option<&[u8]>,
) -> Result<RenderedFile, AdapterError> {
    let (root, relative_path) = match extracted.asset.scope {
        ScopeLevel::User => (TargetRoot::ProductConfig, "config.toml"),
        ScopeLevel::Workspace | ScopeLevel::Project => {
            (TargetRoot::Workspace, ".codex/config.toml")
        }
        _ => return manual_scope_error(extracted),
    };
    Ok(RenderedFile {
        root,
        relative_path: relative_path.to_owned(),
        bytes: merge_mcp_toml(existing, extracted)?,
        asset_id: extracted.asset.asset_id.clone(),
    })
}

fn manual_scope_error<T>(extracted: &ExtractedAsset) -> Result<T, AdapterError> {
    Err(AdapterError::InvalidData {
        path: PathBuf::from(&extracted.asset.provenance.locator),
        message: "Codex target scope requires manual mapping".to_owned(),
    })
}

fn manual_payload_error<T>(extracted: &ExtractedAsset) -> Result<T, AdapterError> {
    Err(AdapterError::InvalidData {
        path: PathBuf::from(&extracted.asset.provenance.locator),
        message: "asset requires Codex structured/manual target handling".to_owned(),
    })
}

fn current_directory() -> Result<PathBuf, AdapterError> {
    std::env::current_dir().map_err(|source| AdapterError::Io {
        path: PathBuf::from("."),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::collect_from_roots;
    use mnemo_adapter_common::CollectionMode;
    use mnemo_schema::{AssetKind, ScopeLevel};

    #[test]
    fn prefers_current_agents_skill_root_but_preserves_legacy_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let codex = temp.path().join("codex");
        let home = temp.path().join("home");
        let project = temp.path().join("repo");
        std::fs::create_dir_all(codex.join("skills/legacy"))?;
        std::fs::create_dir_all(home.join(".agents/skills/current"))?;
        std::fs::create_dir_all(project.join(".agents/skills/project"))?;
        std::fs::write(codex.join("AGENTS.md"), "user rules")?;
        std::fs::write(codex.join("skills/legacy/SKILL.md"), "# Legacy")?;
        std::fs::write(home.join(".agents/skills/current/SKILL.md"), "# Current")?;
        std::fs::write(project.join("AGENTS.md"), "project rules")?;
        std::fs::write(project.join(".agents/skills/project/SKILL.md"), "# Project")?;
        std::fs::write(codex.join("auth.json"), "excluded")?;
        std::fs::write(codex.join("state.sqlite"), "excluded")?;

        let snapshot = collect_from_roots(&codex, &home, &project, CollectionMode::OfflineStatic)?;
        assert_eq!(snapshot.inventory.len(), 5);
        assert!(
            snapshot
                .inventory
                .iter()
                .all(|item| !item.locator.contains("auth") && !item.locator.contains("sqlite"))
        );
        assert!(snapshot.extracted.iter().any(|item| {
            item.asset.kind == AssetKind::Skill && item.asset.scope == ScopeLevel::Workspace
        }));
        Ok(())
    }
}
