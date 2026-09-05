//! Cross-platform and cross-device Core Tier migration matrix.

use ed25519_dalek::SigningKey;
use mnemo_adapter_common::{CollectionMode, ExtractedAsset};
use mnemo_schema::{AssetKind, Entrypoint, EvidenceLevel, Platform, ProductTuple};
use std::path::Path;

#[test]
fn all_sixteen_core_directions_survive_cross_device_package()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempfile::tempdir()?;
    for source in Platform::all() {
        let source_assets = source_fixture(source, fixture.path())?;
        assert_eq!(source_assets.len(), 4, "source {}", source.as_str());
        let package = mnemo_core::package_assets(
            &source_assets,
            &SigningKey::from_bytes(&[source as u8 + 11; 32]),
        )?;
        let verified = mnemo_package::verify(&package.bytes)?;
        let transported = mnemo_core::unpack_assets(&verified)?;
        for target in Platform::all() {
            let destination = tempfile::tempdir()?;
            let transaction_root = destination.path().join("transactions");
            let roots = mnemo_core::TargetRoots {
                product_config: destination.path().join("product-config"),
                user_home: destination.path().join("home"),
                workspace: destination.path().join("workspace"),
            };
            let prepared =
                mnemo_core::prepare_migration(target_tuple(target), &roots, &transported)?;
            for file in &prepared.files {
                apply_prepared(&transaction_root, file)?;
            }
            assert!(
                prepared.files.len() >= 3,
                "{} -> {} rendered no core closure",
                source.as_str(),
                target.as_str()
            );
            let mcp = transported
                .iter()
                .find(|asset| asset.asset.kind == AssetKind::Mcp)
                .ok_or("source MCP asset missing")?;
            let mcp_skipped = prepared
                .skipped
                .iter()
                .any(|item| item.asset_id == mcp.asset.asset_id);
            let expected_manual = source == Platform::Codex
                && matches!(target, Platform::ClaudeCode | Platform::Qoder);
            assert_eq!(
                mcp_skipped,
                expected_manual,
                "{} -> {} MCP disposition mismatch",
                source.as_str(),
                target.as_str()
            );
        }
    }
    Ok(())
}

fn source_fixture(
    platform: Platform,
    base: &Path,
) -> Result<Vec<ExtractedAsset>, Box<dyn std::error::Error>> {
    let platform_root = base.join(platform.as_str());
    let config = platform_root.join("config");
    let home = platform_root.join("home");
    let project = platform_root.join("project");
    std::fs::create_dir_all(&config)?;
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&project)?;
    let mut assets = match platform {
        Platform::ClaudeCode => {
            std::fs::create_dir_all(project.join(".claude/skills/portable"))?;
            std::fs::write(project.join("CLAUDE.md"), "claude instruction\n")?;
            std::fs::write(
                project.join(".claude/skills/portable/SKILL.md"),
                "# Portable Claude skill\n",
            )?;
            write_json_mcp(&project.join(".mcp.json"))?;
            mnemo_adapter_claude_code::collect_from_roots(
                &config,
                &project,
                CollectionMode::OfflineStatic,
            )?
            .extracted
        }
        Platform::Codex => {
            std::fs::create_dir_all(project.join(".agents/skills/portable"))?;
            std::fs::write(project.join("AGENTS.md"), "codex instruction\n")?;
            std::fs::write(
                project.join(".agents/skills/portable/SKILL.md"),
                "# Portable Codex skill\n",
            )?;
            std::fs::write(
                config.join("config.toml"),
                "[mcp_servers.fixture]\ncommand = \"fixture-server\"\nargs = [\"--safe\"]\nenv = { DOCS_TOKEN = \"discard-me\" }\n",
            )?;
            mnemo_adapter_codex::collect_from_roots(
                &config,
                &home,
                &project,
                CollectionMode::OfflineStatic,
            )?
            .extracted
        }
        Platform::Qoder => {
            std::fs::create_dir_all(project.join(".qoder/skills/portable"))?;
            std::fs::write(project.join("AGENTS.md"), "qoder instruction\n")?;
            std::fs::write(
                project.join(".qoder/skills/portable/SKILL.md"),
                "# Portable Qoder skill\n",
            )?;
            write_json_mcp(&project.join(".mcp.json"))?;
            mnemo_adapter_qoder::collect_from_roots(
                &config,
                &project,
                CollectionMode::OfflineStatic,
            )?
            .extracted
        }
        Platform::Cursor => {
            std::fs::create_dir_all(project.join(".cursor/rules"))?;
            std::fs::create_dir_all(project.join(".cursor/skills/portable"))?;
            std::fs::write(project.join(".cursor/rules/portable.mdc"), "cursor rule\n")?;
            std::fs::write(
                project.join(".cursor/skills/portable/SKILL.md"),
                "# Portable Cursor skill\n",
            )?;
            write_json_mcp(&project.join(".cursor/mcp.json"))?;
            mnemo_adapter_cursor::collect_from_roots(
                &config,
                &home,
                &project,
                CollectionMode::OfflineStatic,
            )?
            .extracted
        }
    };
    assets.push(mnemo_core::create_handoff(&mnemo_schema::HandoffCapsule {
        schema_version: "1.0".to_owned(),
        source: platform,
        goal: "Continue the portable migration".to_owned(),
        latest_request: Some("Validate the destination".to_owned()),
        constraints: vec!["Do not expose secrets".to_owned()],
        decisions: vec!["Use target-first planning".to_owned()],
        completed: vec!["Source inventory".to_owned()],
        pending: vec!["Target verification".to_owned()],
        workspace: Some("fixture".to_owned()),
        git_head: Some("0123456789abcdef".to_owned()),
        git_dirty: Some(false),
        validation: vec!["L0 package verified".to_owned()],
        risks: Vec::new(),
    })?);
    Ok(assets
        .into_iter()
        .filter(|asset| {
            matches!(
                asset.asset.kind,
                AssetKind::Instruction | AssetKind::Skill | AssetKind::Mcp | AssetKind::Handoff
            )
        })
        .collect())
}

fn write_json_mcp(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(
        path,
        r#"{"mcpServers":{"fixture":{"command":"fixture-server","args":["--safe"],"env":{"DOCS_TOKEN":"discard-me"}}}}"#,
    )?;
    Ok(())
}

fn target_tuple(platform: Platform) -> ProductTuple {
    ProductTuple {
        platform,
        version: Some("fixture-contract-v0.1".to_owned()),
        os: std::env::consts::OS.to_owned(),
        entrypoint: Entrypoint::Cli,
        executable: None,
        config_root: None,
        evidence: EvidenceLevel::Observed,
    }
}

fn apply_prepared(
    transaction_root: &Path,
    file: &mnemo_core::PreparedFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let journal = mnemo_store::apply_file(&file.target_path, &file.bytes, transaction_root, None)?;
    assert_eq!(std::fs::read(&file.target_path)?, file.bytes);
    assert_eq!(journal.after_hash, mnemo_security::sha256_id(&file.bytes));
    Ok(())
}
