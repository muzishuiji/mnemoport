//! Claude Code adapter.

use mnemo_adapter_common::{
    AdapterError, CollectionMode, ExtractedAsset, InventoryItem, PlatformAdapter, RenderedFile,
    TargetRoot, collect_json_mcp_if_present, collect_markdown_tree, collect_skills,
    collect_text_if_present, detected_tuple, find_executable, inventory_only_if_present,
    merge_mcp_json, portable_name, render_file_tree, render_handoff, render_text_file,
    resolve_root,
};
use mnemo_schema::{AssetKind, Entrypoint, Platform, ProductTuple, ScopeLevel};
use std::path::{Path, PathBuf};

/// Claude Code platform adapter.
#[derive(Debug, Default)]
pub struct ClaudeCodeAdapter;

impl PlatformAdapter for ClaudeCodeAdapter {
    fn platform(&self) -> Platform {
        Platform::ClaudeCode
    }

    fn detect(&self) -> Result<Vec<ProductTuple>, AdapterError> {
        let root = resolve_root("CLAUDE_CONFIG_DIR", ".claude")?;
        Ok(vec![detected_tuple(
            Platform::ClaudeCode,
            Entrypoint::Cli,
            find_executable("claude"),
            root,
        )])
    }

    fn inventory(&self, mode: CollectionMode) -> Result<Vec<InventoryItem>, AdapterError> {
        let config = resolve_root("CLAUDE_CONFIG_DIR", ".claude")?.path;
        let workspace = current_directory()?;
        Ok(collect_from_roots(&config, &workspace, mode)?.inventory)
    }

    fn extract(&self, mode: CollectionMode) -> Result<Vec<ExtractedAsset>, AdapterError> {
        let config = resolve_root("CLAUDE_CONFIG_DIR", ".claude")?.path;
        let workspace = current_directory()?;
        Ok(collect_from_roots(&config, &workspace, mode)?.extracted)
    }
}

/// Isolated result used by inventory and extraction fixture tests.
#[derive(Debug, Default)]
pub struct ClaudeSnapshot {
    /// Metadata-only inventory.
    pub inventory: Vec<InventoryItem>,
    /// Canonical extracted assets and object bodies.
    pub extracted: Vec<ExtractedAsset>,
}

/// Collect documented offline-static Claude Code file assets from explicit
/// roots. The function never launches Claude Code and never writes either root.
pub fn collect_from_roots(
    config_root: &Path,
    workspace_root: &Path,
    mode: CollectionMode,
) -> Result<ClaudeSnapshot, AdapterError> {
    if mode != CollectionMode::OfflineStatic {
        // M3 deliberately has no assisted side effect; stronger modes include
        // all offline assets and will gain probes in a later milestone.
    }
    let mut snapshot = ClaudeSnapshot::default();
    collect_scope(
        config_root,
        ScopeLevel::User,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
        false,
    )?;
    collect_scope(
        workspace_root,
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
        true,
    )?;
    snapshot
        .inventory
        .sort_by(|left, right| left.locator.cmp(&right.locator));
    snapshot.extracted.sort_by(|left, right| {
        left.asset
            .provenance
            .locator
            .cmp(&right.asset.provenance.locator)
    });
    Ok(snapshot)
}

/// Render one supported canonical asset to documented Claude Code file roots.
/// Preferences and MCP require structured merge and are intentionally deferred
/// to the config phase instead of being copied as opaque text.
pub fn render_target(extracted: &ExtractedAsset) -> Result<Vec<RenderedFile>, AdapterError> {
    let (root, prefix) = match extracted.asset.scope {
        ScopeLevel::User => (TargetRoot::ProductConfig, ""),
        ScopeLevel::Workspace | ScopeLevel::Project => (TargetRoot::Workspace, ".claude/"),
        _ => {
            return Err(AdapterError::InvalidData {
                path: PathBuf::from(&extracted.asset.provenance.locator),
                message: "Claude target scope requires manual mapping".to_owned(),
            });
        }
    };
    let name = portable_name(&extracted.asset.title, &extracted.asset.asset_id);
    match extracted.asset.kind {
        AssetKind::Instruction => {
            let relative = if extracted.asset.provenance.platform == Platform::ClaudeCode
                && is_exact_instruction_path(&extracted.asset.provenance.locator)
            {
                extracted.asset.provenance.locator.clone()
            } else {
                format!("{prefix}rules/mnemoport/{name}.md")
            };
            Ok(vec![render_text_file(extracted, root, relative)?])
        }
        AssetKind::Prompt => Ok(vec![render_text_file(
            extracted,
            root,
            format!("{prefix}commands/{name}.md"),
        )?]),
        AssetKind::Skill => render_file_tree(extracted, root, &format!("{prefix}skills/{name}")),
        AssetKind::Handoff => Ok(vec![render_handoff(extracted)?]),
        _ => Err(AdapterError::InvalidData {
            path: PathBuf::from(&extracted.asset.provenance.locator),
            message: "asset requires Claude structured/manual target handling".to_owned(),
        }),
    }
}

/// Merge one project-scoped MCP definition into `.mcp.json`. User-scoped
/// servers use Claude's official CLI in the external-action phase.
pub fn render_mcp_target(
    extracted: &ExtractedAsset,
    existing: Option<&[u8]>,
) -> Result<RenderedFile, AdapterError> {
    if !matches!(
        extracted.asset.scope,
        ScopeLevel::Workspace | ScopeLevel::Project
    ) {
        return manual_error(extracted, "user MCP requires claude mcp add");
    }
    Ok(RenderedFile {
        root: TargetRoot::Workspace,
        relative_path: ".mcp.json".to_owned(),
        bytes: merge_mcp_json(existing, extracted)?,
        asset_id: extracted.asset.asset_id.clone(),
    })
}

fn manual_error<T>(extracted: &ExtractedAsset, message: &str) -> Result<T, AdapterError> {
    Err(AdapterError::InvalidData {
        path: PathBuf::from(&extracted.asset.provenance.locator),
        message: message.to_owned(),
    })
}

fn is_exact_instruction_path(locator: &str) -> bool {
    matches!(
        locator,
        "CLAUDE.md" | "CLAUDE.local.md" | ".claude/CLAUDE.md"
    ) || locator.starts_with("rules/")
        || locator.starts_with(".claude/rules/")
}

fn collect_scope(
    root: &Path,
    scope: ScopeLevel,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
    workspace: bool,
) -> Result<(), AdapterError> {
    let instructions = if workspace {
        ["CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md"].as_slice()
    } else {
        ["CLAUDE.md"].as_slice()
    };
    for relative in instructions {
        collect_text_if_present(
            Platform::ClaudeCode,
            root,
            relative,
            AssetKind::Instruction,
            scope,
            inventory,
            extracted,
        )?;
    }
    let prefix = if workspace { ".claude/" } else { "" };
    collect_markdown_tree(
        Platform::ClaudeCode,
        root,
        &format!("{prefix}rules"),
        AssetKind::Instruction,
        scope,
        inventory,
        extracted,
    )?;
    collect_markdown_tree(
        Platform::ClaudeCode,
        root,
        &format!("{prefix}commands"),
        AssetKind::Prompt,
        scope,
        inventory,
        extracted,
    )?;
    collect_skills(
        Platform::ClaudeCode,
        root,
        &format!("{prefix}skills"),
        scope,
        inventory,
        extracted,
    )?;
    let settings = format!("{prefix}settings.json");
    inventory_only_if_present(root, &settings, AssetKind::Preference, scope, inventory)?;
    if workspace {
        collect_json_mcp_if_present(
            Platform::ClaudeCode,
            root,
            ".mcp.json",
            scope,
            inventory,
            extracted,
        )?;
    }
    Ok(())
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
    use mnemo_schema::{AssetKind, AssetPayload, ScopeLevel};

    #[test]
    fn collects_user_and_project_assets_without_auth_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let config = temp.path().join("claude-home");
        let project = temp.path().join("repo");
        std::fs::create_dir_all(config.join("skills/user-skill"))?;
        std::fs::create_dir_all(project.join(".claude/skills/project-skill"))?;
        std::fs::write(config.join("CLAUDE.md"), "user persona")?;
        std::fs::write(config.join("skills/user-skill/SKILL.md"), "# User Skill")?;
        std::fs::write(config.join("auth.json"), "must not migrate")?;
        std::fs::write(project.join("CLAUDE.md"), "project rule")?;
        std::fs::write(
            project.join(".claude/skills/project-skill/SKILL.md"),
            "# Project Skill",
        )?;

        let snapshot = collect_from_roots(&config, &project, CollectionMode::OfflineStatic)?;
        assert_eq!(snapshot.inventory.len(), 4);
        assert!(
            snapshot
                .inventory
                .iter()
                .all(|item| !item.locator.contains("auth"))
        );
        assert!(snapshot.extracted.iter().any(|item| {
            item.asset.kind == AssetKind::Skill && item.asset.scope == ScopeLevel::Workspace
        }));
        assert!(snapshot.extracted.iter().any(|item| {
            matches!(&item.asset.payload, AssetPayload::Text(text) if text == "project rule")
        }));
        Ok(())
    }
}
