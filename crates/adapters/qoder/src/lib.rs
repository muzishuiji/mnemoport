//! Qoder adapter.

use mnemo_adapter_common::{
    AdapterError, CollectionMode, ExtractedAsset, InventoryItem, PlatformAdapter, RenderedFile,
    TargetRoot, collect_json_mcp_if_present, collect_markdown_tree, collect_skills,
    collect_text_if_present, detected_tuple, find_executable, inventory_only_if_present,
    merge_mcp_json, portable_name, render_file_tree, render_handoff, render_text_file,
    resolve_root, user_home,
};
use mnemo_schema::{AssetKind, Entrypoint, Platform, ProductTuple, ScopeLevel};
use std::path::{Path, PathBuf};

/// Qoder platform adapter.
#[derive(Debug, Default)]
pub struct QoderAdapter;

impl PlatformAdapter for QoderAdapter {
    fn platform(&self) -> Platform {
        Platform::Qoder
    }

    fn detect(&self) -> Result<Vec<ProductTuple>, AdapterError> {
        let root = resolve_root("QODER_CONFIG_DIR", ".qoder")?;
        let dispatcher = find_executable("qoder");
        let dispatcher_entrypoint = dispatcher.as_deref().map_or(Entrypoint::Unknown, |path| {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            classify_entrypoint(&canonical)
        });
        let cli = find_qoder_cli(&root.path)?.or_else(|| {
            (dispatcher_entrypoint == Entrypoint::Cli)
                .then(|| dispatcher.clone())
                .flatten()
        });
        let mut tuples = vec![detected_tuple(
            Platform::Qoder,
            Entrypoint::Cli,
            cli,
            root.clone(),
        )];
        if dispatcher_entrypoint != Entrypoint::Cli && dispatcher.is_some() {
            tuples.push(detected_tuple(
                Platform::Qoder,
                dispatcher_entrypoint,
                dispatcher,
                root,
            ));
        }
        Ok(tuples)
    }

    fn inventory(&self, mode: CollectionMode) -> Result<Vec<InventoryItem>, AdapterError> {
        let config = resolve_root("QODER_CONFIG_DIR", ".qoder")?.path;
        let workspace = current_directory()?;
        Ok(collect_from_roots(&config, &workspace, mode)?.inventory)
    }

    fn extract(&self, mode: CollectionMode) -> Result<Vec<ExtractedAsset>, AdapterError> {
        let config = resolve_root("QODER_CONFIG_DIR", ".qoder")?.path;
        let workspace = current_directory()?;
        Ok(collect_from_roots(&config, &workspace, mode)?.extracted)
    }
}

/// Offline Qoder source snapshot.
#[derive(Debug, Default)]
pub struct QoderSnapshot {
    /// Metadata-only inventory.
    pub inventory: Vec<InventoryItem>,
    /// Canonical assets and referenced object bytes.
    pub extracted: Vec<ExtractedAsset>,
}

/// Collect Qoder CLI/Core file assets from explicit roots without reading
/// Electron application data or launching Qoder.
pub fn collect_from_roots(
    config_root: &Path,
    workspace_root: &Path,
    _mode: CollectionMode,
) -> Result<QoderSnapshot, AdapterError> {
    let mut snapshot = QoderSnapshot::default();
    collect_scope(
        config_root,
        ScopeLevel::User,
        false,
        &mut snapshot.inventory,
        &mut snapshot.extracted,
    )?;
    collect_scope(
        workspace_root,
        ScopeLevel::Workspace,
        true,
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

/// Render Instructions, Skills and Prompts to documented Qoder roots.
pub fn render_target(extracted: &ExtractedAsset) -> Result<Vec<RenderedFile>, AdapterError> {
    let (root, prefix) = match extracted.asset.scope {
        ScopeLevel::User => (TargetRoot::ProductConfig, ""),
        ScopeLevel::Workspace | ScopeLevel::Project => (TargetRoot::Workspace, ".qoder/"),
        _ => return manual_error(extracted, "Qoder target scope requires manual mapping"),
    };
    let name = portable_name(&extracted.asset.title, &extracted.asset.asset_id);
    match extracted.asset.kind {
        AssetKind::Instruction => {
            let relative = if extracted.asset.provenance.platform == Platform::Qoder
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
        _ => manual_error(extracted, "asset requires Qoder structured/manual handling"),
    }
}

/// Merge a project MCP definition into Qoder's documented `.mcp.json`.
pub fn render_mcp_target(
    extracted: &ExtractedAsset,
    existing: Option<&[u8]>,
) -> Result<RenderedFile, AdapterError> {
    if !matches!(
        extracted.asset.scope,
        ScopeLevel::Workspace | ScopeLevel::Project
    ) {
        return manual_error(extracted, "user MCP requires Qoder's official interface");
    }
    Ok(RenderedFile {
        root: TargetRoot::Workspace,
        relative_path: ".mcp.json".to_owned(),
        bytes: merge_mcp_json(existing, extracted)?,
        asset_id: extracted.asset.asset_id.clone(),
    })
}

fn collect_scope(
    root: &Path,
    scope: ScopeLevel,
    workspace: bool,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
) -> Result<(), AdapterError> {
    let instructions: &[&str] = if workspace {
        &["AGENTS.md", "AGENTS.local.md"]
    } else {
        &["AGENTS.md"]
    };
    for relative in instructions {
        collect_text_if_present(
            Platform::Qoder,
            root,
            relative,
            AssetKind::Instruction,
            scope,
            inventory,
            extracted,
        )?;
    }
    let prefix = if workspace { ".qoder/" } else { "" };
    collect_markdown_tree(
        Platform::Qoder,
        root,
        &format!("{prefix}rules"),
        AssetKind::Instruction,
        scope,
        inventory,
        extracted,
    )?;
    collect_markdown_tree(
        Platform::Qoder,
        root,
        &format!("{prefix}commands"),
        AssetKind::Prompt,
        scope,
        inventory,
        extracted,
    )?;
    collect_skills(
        Platform::Qoder,
        root,
        &format!("{prefix}skills"),
        scope,
        inventory,
        extracted,
    )?;
    inventory_only_if_present(
        root,
        &format!("{prefix}settings.json"),
        AssetKind::Preference,
        scope,
        inventory,
    )?;
    if workspace {
        collect_json_mcp_if_present(
            Platform::Qoder,
            root,
            ".mcp.json",
            scope,
            inventory,
            extracted,
        )?;
    }
    Ok(())
}

fn is_exact_instruction_path(locator: &str) -> bool {
    matches!(locator, "AGENTS.md" | "AGENTS.local.md")
        || locator.starts_with("rules/")
        || locator.starts_with(".qoder/rules/")
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

fn find_qoder_cli(config_root: &Path) -> Result<Option<PathBuf>, AdapterError> {
    if let Some(path) = find_executable("qodercli") {
        return Ok(Some(path));
    }
    let home = user_home()?;
    for candidate in [
        executable_candidate(&home.join(".local/bin/qodercli")),
        executable_candidate(&config_root.join("bin/qodercli/qodercli")),
    ] {
        if is_executable_candidate(&candidate) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn executable_candidate(path: &Path) -> PathBuf {
    if cfg!(windows) {
        path.with_extension("exe")
    } else {
        path.to_path_buf()
    }
}

fn is_executable_candidate(path: &Path) -> bool {
    path.metadata().is_ok_and(|metadata| {
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    })
}

fn classify_entrypoint(path: &Path) -> Entrypoint {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized.contains("node_modules")
        || normalized.contains("/.npm/")
        || normalized.contains("/.local/bin/")
    {
        Entrypoint::Cli
    } else if normalized.contains("/opt/qoder/")
        || normalized.contains("/applications/qoder.app/")
        || (normalized.contains("/programs/qoder/") && normalized.ends_with("/qoder.exe"))
    {
        Entrypoint::DesktopApp
    } else {
        Entrypoint::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_entrypoint, collect_from_roots};
    use mnemo_adapter_common::CollectionMode;
    use mnemo_schema::{AssetKind, Entrypoint};
    use std::path::Path;

    #[test]
    fn distinguishes_desktop_from_npm_cli() {
        assert_eq!(
            classify_entrypoint(Path::new("/opt/Qoder/qoder")),
            Entrypoint::DesktopApp
        );
        assert_eq!(
            classify_entrypoint(Path::new(
                "/usr/lib/node_modules/@qoder-ai/qodercli/bin/qoder"
            )),
            Entrypoint::Cli
        );
        assert_eq!(
            classify_entrypoint(Path::new(
                r"C:\Users\fixture\node_modules\@qoder-ai\qodercli\bin\qoder.exe"
            )),
            Entrypoint::Cli
        );
        assert_eq!(
            classify_entrypoint(Path::new(
                r"C:\Users\fixture\AppData\Local\Programs\Qoder\Qoder.exe"
            )),
            Entrypoint::DesktopApp
        );
    }

    #[test]
    fn ambiguous_binary_is_not_claimed_as_cli() {
        assert_eq!(
            classify_entrypoint(Path::new("/usr/bin/qoder")),
            Entrypoint::Unknown
        );
    }

    #[test]
    fn excludes_app_data_and_collects_qoder_core() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let config = temp.path().join("qoder");
        let project = temp.path().join("repo");
        std::fs::create_dir_all(config.join("skills/user"))?;
        std::fs::create_dir_all(project.join(".qoder/commands"))?;
        std::fs::write(config.join("AGENTS.md"), "user instruction")?;
        std::fs::write(config.join("skills/user/SKILL.md"), "# User")?;
        std::fs::write(project.join("AGENTS.md"), "project instruction")?;
        std::fs::write(project.join(".qoder/commands/check.md"), "check it")?;
        std::fs::write(config.join("cookies.sqlite"), "excluded")?;
        let snapshot = collect_from_roots(&config, &project, CollectionMode::OfflineStatic)?;
        assert_eq!(snapshot.inventory.len(), 4);
        assert!(
            snapshot
                .inventory
                .iter()
                .all(|item| !item.locator.contains("cookie"))
        );
        assert!(
            snapshot
                .extracted
                .iter()
                .any(|item| item.asset.kind == AssetKind::Prompt)
        );
        Ok(())
    }
}
