//! Cursor IDE and Agent adapter.

use mnemo_adapter_common::{
    AdapterError, CollectionMode, ExtractedAsset, InventoryItem, PlatformAdapter, RenderedFile,
    RootCandidate, TargetRoot, collect_json_mcp_if_present, collect_markdown_tree, collect_skills,
    collect_text_if_present, detected_tuple, find_executable, merge_mcp_json, portable_name,
    render_file_tree, render_handoff, resolve_root, user_home,
};
use mnemo_schema::{AssetKind, Entrypoint, Platform, ProductTuple, ScopeLevel};
use std::path::{Path, PathBuf};

/// Cursor platform adapter.
#[derive(Debug, Default)]
pub struct CursorAdapter;

impl PlatformAdapter for CursorAdapter {
    fn platform(&self) -> Platform {
        Platform::Cursor
    }

    fn detect(&self) -> Result<Vec<ProductTuple>, AdapterError> {
        let agent_root = resolve_root("CURSOR_AGENT_CONFIG_DIR", ".cursor")?;
        let mut tuples = vec![detected_tuple(
            Platform::Cursor,
            Entrypoint::Agent,
            find_executable("cursor-agent"),
            agent_root,
        )];
        let ide_root = cursor_ide_root()?;
        tuples.push(detected_tuple(
            Platform::Cursor,
            Entrypoint::IdeEditor,
            find_executable("cursor"),
            ide_root,
        ));
        Ok(tuples)
    }

    fn inventory(&self, mode: CollectionMode) -> Result<Vec<InventoryItem>, AdapterError> {
        let workspace = current_directory()?;
        self.inventory_at(mode, &workspace)
    }

    fn inventory_at(
        &self,
        mode: CollectionMode,
        workspace: &Path,
    ) -> Result<Vec<InventoryItem>, AdapterError> {
        let config = resolve_root("CURSOR_AGENT_CONFIG_DIR", ".cursor")?.path;
        let home = user_home()?;
        Ok(collect_from_roots(&config, &home, workspace, mode)?.inventory)
    }

    fn extract(&self, mode: CollectionMode) -> Result<Vec<ExtractedAsset>, AdapterError> {
        let workspace = current_directory()?;
        self.extract_at(mode, &workspace)
    }

    fn extract_at(
        &self,
        mode: CollectionMode,
        workspace: &Path,
    ) -> Result<Vec<ExtractedAsset>, AdapterError> {
        let config = resolve_root("CURSOR_AGENT_CONFIG_DIR", ".cursor")?.path;
        let home = user_home()?;
        Ok(collect_from_roots(&config, &home, workspace, mode)?.extracted)
    }
}

/// Offline Cursor Agent/project source snapshot.
#[derive(Debug, Default)]
pub struct CursorSnapshot {
    /// Metadata-only inventory.
    pub inventory: Vec<InventoryItem>,
    /// Canonical assets and referenced object bytes.
    pub extracted: Vec<ExtractedAsset>,
}

/// Collect documented file-backed Cursor assets. IDE databases, User Rules UI,
/// cookies, chat history and remote state are outside this offline contract.
pub fn collect_from_roots(
    cursor_config_root: &Path,
    user_home_root: &Path,
    workspace_root: &Path,
    _mode: CollectionMode,
) -> Result<CursorSnapshot, AdapterError> {
    let mut snapshot = CursorSnapshot::default();
    collect_skills(
        Platform::Cursor,
        cursor_config_root,
        "skills",
        ScopeLevel::User,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_skills(
        Platform::Cursor,
        user_home_root,
        ".agents/skills",
        ScopeLevel::User,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_text_if_present(
        Platform::Cursor,
        workspace_root,
        ".cursorrules",
        AssetKind::Instruction,
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_markdown_tree(
        Platform::Cursor,
        workspace_root,
        ".cursor/rules",
        AssetKind::Instruction,
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_skills(
        Platform::Cursor,
        workspace_root,
        ".cursor/skills",
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_skills(
        Platform::Cursor,
        workspace_root,
        ".agents/skills",
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_json_mcp_if_present(
        Platform::Cursor,
        workspace_root,
        ".cursor/mcp.json",
        ScopeLevel::Workspace,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
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

/// Render portable Instructions and Skills for Cursor Agent/IDE project roots.
pub fn render_target(extracted: &ExtractedAsset) -> Result<Vec<RenderedFile>, AdapterError> {
    let name = portable_name(&extracted.asset.title, &extracted.asset.asset_id);
    match extracted.asset.kind {
        AssetKind::Instruction
            if matches!(
                extracted.asset.scope,
                ScopeLevel::Workspace | ScopeLevel::Project
            ) =>
        {
            let mnemo_schema::AssetPayload::Text(body) = &extracted.asset.payload else {
                return manual_error(extracted, "expected text instruction");
            };
            if extracted.asset.provenance.platform == Platform::Cursor
                && (extracted.asset.provenance.locator == ".cursorrules"
                    || extracted
                        .asset
                        .provenance
                        .locator
                        .starts_with(".cursor/rules/"))
            {
                return Ok(vec![RenderedFile {
                    root: TargetRoot::Workspace,
                    relative_path: extracted.asset.provenance.locator.clone(),
                    bytes: body.as_bytes().to_vec(),
                    asset_id: extracted.asset.asset_id.clone(),
                }]);
            }
            let rendered = format!(
                "---\ndescription: Migrated by MnemoPort\nalwaysApply: true\n---\n\n{body}"
            );
            Ok(vec![RenderedFile {
                root: TargetRoot::Workspace,
                relative_path: format!(".cursor/rules/mnemoport/{name}.mdc"),
                bytes: rendered.into_bytes(),
                asset_id: extracted.asset.asset_id.clone(),
            }])
        }
        AssetKind::Skill => {
            let (root, directory) = match extracted.asset.scope {
                ScopeLevel::User => (TargetRoot::UserHome, format!(".cursor/skills/{name}")),
                ScopeLevel::Workspace | ScopeLevel::Project => {
                    (TargetRoot::Workspace, format!(".cursor/skills/{name}"))
                }
                _ => return manual_error(extracted, "Cursor target scope requires manual mapping"),
            };
            render_file_tree(extracted, root, &directory)
        }
        AssetKind::Prompt => {
            let root = if extracted.asset.scope == ScopeLevel::User {
                TargetRoot::UserHome
            } else {
                TargetRoot::Workspace
            };
            let prefix = ".cursor/skills";
            let mnemo_schema::AssetPayload::Text(text) = &extracted.asset.payload else {
                return manual_error(extracted, "expected text prompt");
            };
            Ok(vec![RenderedFile {
                root,
                relative_path: format!("{prefix}/{name}/SKILL.md"),
                bytes: format!("---\nname: {name}\ndescription: Migrated prompt\n---\n\n{text}")
                    .into_bytes(),
                asset_id: extracted.asset.asset_id.clone(),
            }])
        }
        AssetKind::Handoff => Ok(vec![render_handoff(extracted)?]),
        _ => manual_error(
            extracted,
            "asset requires Cursor structured/manual handling",
        ),
    }
}

/// Merge one MCP definition into Cursor Agent's documented JSON root.
pub fn render_mcp_target(
    extracted: &ExtractedAsset,
    existing: Option<&[u8]>,
) -> Result<RenderedFile, AdapterError> {
    let (root, relative_path) = match extracted.asset.scope {
        ScopeLevel::User => (TargetRoot::ProductConfig, "mcp.json"),
        ScopeLevel::Workspace | ScopeLevel::Project => (TargetRoot::Workspace, ".cursor/mcp.json"),
        _ => return manual_error(extracted, "Cursor MCP scope requires manual mapping"),
    };
    Ok(RenderedFile {
        root,
        relative_path: relative_path.to_owned(),
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

fn current_directory() -> Result<PathBuf, AdapterError> {
    std::env::current_dir().map_err(|source| AdapterError::Io {
        path: PathBuf::from("."),
        source,
    })
}

fn cursor_ide_root() -> Result<RootCandidate, AdapterError> {
    if let Some(path) = std::env::var_os("CURSOR_USER_DATA_DIR").filter(|value| !value.is_empty()) {
        let path = std::path::PathBuf::from(path);
        return Ok(RootCandidate {
            exists: path.exists(),
            path,
            basis: "environment:CURSOR_USER_DATA_DIR".to_owned(),
        });
    }
    let home = user_home()?;
    let path = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Cursor")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map_or_else(|| home.join("AppData/Roaming"), std::path::PathBuf::from)
            .join("Cursor")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map_or_else(|| home.join(".config"), std::path::PathBuf::from)
            .join("Cursor")
    };
    Ok(RootCandidate {
        exists: path.exists(),
        path,
        basis: "official-default".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::collect_from_roots;
    use mnemo_adapter_common::CollectionMode;
    use mnemo_schema::AssetKind;

    #[test]
    fn collects_mdc_and_both_documented_skill_roots() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let config = temp.path().join("cursor");
        let home = temp.path().join("home");
        let project = temp.path().join("repo");
        std::fs::create_dir_all(config.join("skills/cursor-user"))?;
        std::fs::create_dir_all(home.join(".agents/skills/shared-user"))?;
        std::fs::create_dir_all(project.join(".cursor/rules"))?;
        std::fs::create_dir_all(project.join(".agents/skills/project"))?;
        std::fs::write(config.join("skills/cursor-user/SKILL.md"), "# Cursor")?;
        std::fs::write(home.join(".agents/skills/shared-user/SKILL.md"), "# Shared")?;
        std::fs::write(project.join(".cursor/rules/api.mdc"), "API rule")?;
        std::fs::write(project.join(".agents/skills/project/SKILL.md"), "# Project")?;
        let snapshot = collect_from_roots(&config, &home, &project, CollectionMode::OfflineStatic)?;
        assert_eq!(snapshot.inventory.len(), 4);
        assert!(snapshot.extracted.iter().any(|asset| {
            asset.asset.kind == AssetKind::Instruction
                && asset.asset.provenance.locator.ends_with("api.mdc")
        }));
        Ok(())
    }
}
