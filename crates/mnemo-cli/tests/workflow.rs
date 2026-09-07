//! Black-box CLI workflow using isolated source, target and XDG state roots.

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

#[test]
fn help_and_version_are_successful_control_flow() -> Result<(), Box<dyn std::error::Error>> {
    for argument in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_mnemo"))
            .arg(argument)
            .output()?;
        assert!(output.status.success(), "{argument} must exit successfully");
        assert!(!output.stdout.is_empty());
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn recipient_encryption_and_signer_trust_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let source_state = temp.path().join("source-state");
    let replacement_state = temp.path().join("replacement-state");
    let target_state = temp.path().join("target-state");
    let target_config = temp.path().join("target-codex");
    std::fs::create_dir_all(&workspace)?;
    std::fs::create_dir_all(&target_config)?;
    std::fs::write(workspace.join("AGENTS.md"), "Keep migrations reversible.\n")?;

    let identity = temp.path().join("target.agekey");
    let generated_output = run(
        &workspace,
        &target_state,
        &[
            "recipient",
            "generate",
            "--output",
            identity.to_str().ok_or("identity path is not UTF-8")?,
            "--json",
        ],
        &[],
    )?;
    assert!(!String::from_utf8_lossy(&generated_output.stdout).contains("AGE-SECRET-KEY-"));
    let generated = success_json(&generated_output)?;
    let recipient = generated["data"]["recipient"]
        .as_str()
        .ok_or("recipient missing")?;
    assert!(recipient.starts_with("age1"));
    let identity_body = std::fs::read_to_string(&identity)?;
    assert!(identity_body.contains("AGE-SECRET-KEY-"));
    assert!(
        !String::from_utf8_lossy(
            &run(
                &workspace,
                &target_state,
                &[
                    "recipient",
                    "show",
                    "--identity",
                    identity.to_str().ok_or("identity path is not UTF-8")?,
                    "--json",
                ],
                &[],
            )?
            .stdout
        )
        .contains("AGE-SECRET-KEY-")
    );

    let package = temp.path().join("recipient.mnemo");
    let exported = success_json(&run(
        &workspace,
        &source_state,
        &[
            "export",
            "--from",
            "codex",
            "--output",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--recipient",
            recipient,
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?)?;
    assert_eq!(exported["data"]["encryption"], "age-x25519");
    let encrypted_bytes = std::fs::read(&package)?;
    assert!(
        !encrypted_bytes
            .windows(b"AGE-SECRET-KEY-".len())
            .any(|window| window == b"AGE-SECRET-KEY-")
    );

    let wrong_identity = temp.path().join("wrong.agekey");
    success_json(&run(
        &workspace,
        &target_state,
        &[
            "recipient",
            "generate",
            "--output",
            wrong_identity
                .to_str()
                .ok_or("identity path is not UTF-8")?,
            "--json",
        ],
        &[],
    )?)?;
    let rejected = run(
        &workspace,
        &target_state,
        &[
            "inspect",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--identity",
            wrong_identity
                .to_str()
                .ok_or("identity path is not UTF-8")?,
            "--json",
        ],
        &[],
    )?;
    assert_eq!(rejected.status.code(), Some(6));

    let inspected = success_json(&run(
        &workspace,
        &target_state,
        &[
            "inspect",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--identity",
            identity.to_str().ok_or("identity path is not UTF-8")?,
            "--json",
        ],
        &[],
    )?)?;
    assert_eq!(inspected["data"]["encrypted"], true);
    let trusted = success_json(&run(
        &workspace,
        &target_state,
        &[
            "trust",
            "add",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--identity",
            identity.to_str().ok_or("identity path is not UTF-8")?,
            "--label",
            "old device",
            "--json",
        ],
        &[],
    )?)?;
    let old_fingerprint = trusted["data"]["fingerprint"]
        .as_str()
        .ok_or("old fingerprint missing")?;
    let ambiguous_revoke = run(
        &workspace,
        &target_state,
        &["trust", "revoke", &old_fingerprint[..24], "--json"],
        &[],
    )?;
    assert_eq!(ambiguous_revoke.status.code(), Some(6));

    let replacement_package = temp.path().join("replacement.mnemo");
    success_json(&run(
        &workspace,
        &replacement_state,
        &[
            "export",
            "--from",
            "codex",
            "--output",
            replacement_package
                .to_str()
                .ok_or("replacement package path is not UTF-8")?,
            "--allow-plaintext",
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?)?;
    let rotated = success_json(&run(
        &workspace,
        &target_state,
        &[
            "trust",
            "rotate",
            "--from",
            old_fingerprint,
            "--input",
            replacement_package
                .to_str()
                .ok_or("replacement package path is not UTF-8")?,
            "--label",
            "new device",
            "--json",
        ],
        &[],
    )?)?;
    assert_eq!(rotated["data"]["revoked"]["fingerprint"], old_fingerprint);
    let replacement_fingerprint = rotated["data"]["trusted"]["fingerprint"]
        .as_str()
        .ok_or("replacement fingerprint missing")?;
    assert_ne!(replacement_fingerprint, old_fingerprint);

    let revoked = success_json(&run(
        &workspace,
        &target_state,
        &["trust", "revoke", replacement_fingerprint, "--json"],
        &[],
    )?)?;
    assert_eq!(revoked["data"]["fingerprint"], replacement_fingerprint);
    let trust_list = success_json(&run(
        &workspace,
        &target_state,
        &["trust", "list", "--json"],
        &[],
    )?)?;
    assert_eq!(trust_list["data"].as_array().map(Vec::len), Some(0));
    let missing_revoke = run(
        &workspace,
        &target_state,
        &["trust", "revoke", replacement_fingerprint, "--json"],
        &[],
    )?;
    assert_eq!(missing_revoke.status.code(), Some(5));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn encrypted_cross_device_export_plan_apply_and_undo() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let source_workspace = temp.path().join("source-workspace");
    let source_config = temp.path().join("source-qoder");
    let source_state = temp.path().join("source-state");
    let target_workspace = temp.path().join("target-workspace");
    let target_config = temp.path().join("target-codex");
    let target_state = temp.path().join("target-state");
    std::fs::create_dir_all(source_workspace.join(".qoder/skills/portable"))?;
    std::fs::create_dir_all(&source_config)?;
    std::fs::create_dir_all(&target_workspace)?;
    // macOS exposes the temporary root through `/var`, while child process
    // current directories resolve to `/private/var`. Compare ownership using
    // the same canonical locator the CLI records.
    let target_workspace = target_workspace.canonicalize()?;
    std::fs::write(
        source_workspace.join("AGENTS.md"),
        "Preserve API compatibility.\n",
    )?;
    std::fs::write(
        source_workspace.join(".qoder/skills/portable/SKILL.md"),
        "# Portable\nRun compatibility checks.\n",
    )?;
    let package = temp.path().join("transfer.mnemo");
    let plan = temp.path().join("plan.json");
    let passphrase = "fixture-passphrase-28-characters";

    let export = run(
        &source_workspace,
        &source_state,
        &[
            "export",
            "--from",
            "qoder",
            "--output",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--json",
        ],
        &[
            ("QODER_CONFIG_DIR", &source_config),
            ("MNEMOPORT_PASSPHRASE", Path::new(passphrase)),
        ],
    )?;
    let export_json = success_json(&export)?;
    assert_eq!(export_json["data"]["encrypted"], true);
    assert_eq!(export_json["data"]["assets"], 2);

    let inspect = run(
        &target_workspace,
        &target_state,
        &[
            "inspect",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--json",
        ],
        &[("MNEMOPORT_PASSPHRASE", Path::new(passphrase))],
    )?;
    let inspect_json = success_json(&inspect)?;
    assert_eq!(inspect_json["data"]["encrypted"], true);

    let planned = run(
        &target_workspace,
        &target_state,
        &[
            "plan",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--to",
            "codex",
            "--output",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--json",
        ],
        &[
            ("CODEX_HOME", &target_config),
            ("MNEMOPORT_PASSPHRASE", Path::new(passphrase)),
        ],
    )?;
    let plan_json = success_json(&planned)?;
    assert!(
        plan_json["data"]["plan"]
            .get("workspace_mappings")
            .is_none()
    );
    assert!(
        plan_json["data"]["plan"]["operations"]
            .as_array()
            .ok_or("plan operations missing")?
            .iter()
            .all(|operation| operation["effect"].get("workspace_id").is_none())
    );
    let token = plan_json["data"]["approval_token"]
        .as_str()
        .ok_or("approval token missing")?;

    let trusted = run(
        &target_workspace,
        &target_state,
        &[
            "trust",
            "add",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--label",
            "fixture-source-device",
            "--json",
        ],
        &[("MNEMOPORT_PASSPHRASE", Path::new(passphrase))],
    )?;
    let trust_json = success_json(&trusted)?;
    assert_eq!(trust_json["data"]["label"], "fixture-source-device");

    let applied = run(
        &target_workspace,
        &target_state,
        &[
            "apply",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--approve",
            token,
            "--json",
        ],
        &[
            ("CODEX_HOME", &target_config),
            ("MNEMOPORT_PASSPHRASE", Path::new(passphrase)),
        ],
    )?;
    let apply_json = success_json(&applied)?;
    let migration_id = apply_json["data"]["migration_id"]
        .as_str()
        .ok_or("migration id missing")?;
    assert_eq!(
        std::fs::read_to_string(target_workspace.join("AGENTS.md"))?,
        "Preserve API compatibility.\n"
    );
    assert!(
        target_workspace
            .join(".agents/skills/portable/SKILL.md")
            .is_file()
    );
    let ledger = mnemo_store::Ledger::open_read_only(&target_state.join("data/ledger.sqlite"))?;
    for managed_path in [
        target_workspace.join("AGENTS.md"),
        target_workspace.join(".agents/skills/portable/SKILL.md"),
    ] {
        let managed = ledger
            .managed_object(&managed_path.to_string_lossy())?
            .ok_or("migrated target is missing ownership evidence")?;
        assert_eq!(managed.owner_id, migration_id);
    }

    let verified = run(
        &target_workspace,
        &target_state,
        &[
            "verify",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--json",
        ],
        &[
            ("CODEX_HOME", &target_config),
            ("MNEMOPORT_PASSPHRASE", Path::new(passphrase)),
        ],
    )?;
    let verify_json = success_json(&verified)?;
    assert_eq!(verify_json["data"]["level"], "l0");
    assert_eq!(verify_json["data"]["files_verified"], 2);
    assert_eq!(verify_json["data"]["signer_trusted"], true);

    let l1 = run(
        &target_workspace,
        &target_state,
        &[
            "verify",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--level",
            "l1",
            "--json",
        ],
        &[
            ("CODEX_HOME", &target_config),
            ("MNEMOPORT_PASSPHRASE", Path::new(passphrase)),
        ],
    )?;
    assert_eq!(l1.status.code(), Some(2));
    let l1_json: Value = serde_json::from_slice(&l1.stdout)?;
    assert_eq!(l1_json["data"]["level"], "l1");
    assert_eq!(
        l1_json["data"]["asset_discovery"]
            .as_array()
            .ok_or("asset discovery report missing")?
            .len(),
        2
    );
    assert!(
        l1_json["data"]["asset_discovery"]
            .as_array()
            .ok_or("asset discovery report missing")?
            .iter()
            .all(|item| item["status"] == "manual")
    );

    let reported = run(
        &target_workspace,
        &target_state,
        &["report", migration_id, "--json"],
        &[],
    )?;
    let report_json = success_json(&reported)?;
    assert_eq!(report_json["data"]["kind"], "apply");
    assert_eq!(report_json["data"]["status"], "succeeded");
    assert_eq!(report_json["data"]["journal_count"], 2);

    let undone = run(
        &target_workspace,
        &target_state,
        &["undo", migration_id, "--json"],
        &[("CODEX_HOME", &target_config)],
    )?;
    let undo_json = success_json(&undone)?;
    assert_eq!(undo_json["data"]["restored_transactions"], 2);
    assert!(!target_workspace.join("AGENTS.md").exists());
    assert!(
        !target_workspace
            .join(".agents/skills/portable/SKILL.md")
            .exists()
    );
    let ledger = mnemo_store::Ledger::open_read_only(&target_state.join("data/ledger.sqlite"))?;
    assert!(
        ledger
            .managed_object(&target_workspace.join("AGENTS.md").to_string_lossy())?
            .is_none()
    );
    assert!(
        ledger
            .managed_object(
                &target_workspace
                    .join(".agents/skills/portable/SKILL.md")
                    .to_string_lossy()
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn integration_uninstall_refuses_modified_user_content() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let state = temp.path().join("state");
    std::fs::create_dir_all(&workspace)?;
    let installed = run(
        &workspace,
        &state,
        &[
            "integration",
            "install",
            "--host",
            "cursor",
            "--scope",
            "project",
            "--json",
        ],
        &[],
    )?;
    let installed_json = success_json(&installed)?;
    assert_eq!(installed_json["data"]["status"], "installed");
    let skill = workspace.join(".cursor/skills/mnemoport/SKILL.md");
    let original = std::fs::read(&skill)?;
    std::fs::write(&skill, b"user changed this file")?;

    let refused = run(
        &workspace,
        &state,
        &[
            "integration",
            "uninstall",
            "--host",
            "cursor",
            "--scope",
            "project",
            "--json",
        ],
        &[],
    )?;
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&skill)?, b"user changed this file");

    std::fs::write(&skill, original)?;
    let removed = run(
        &workspace,
        &state,
        &[
            "integration",
            "uninstall",
            "--host",
            "cursor",
            "--scope",
            "project",
            "--json",
        ],
        &[],
    )?;
    assert_eq!(
        success_json(&removed)?["data"]["status"],
        "uninstalled-reinstallable"
    );
    assert!(!skill.exists());
    Ok(())
}

#[test]
fn every_host_integration_resolves_user_scope_and_manages_project_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let state = temp.path().join("state");
    for host in ["claude-code", "codex", "qoder", "cursor"] {
        let workspace = temp.path().join(format!("workspace-{host}"));
        std::fs::create_dir_all(&workspace)?;
        let user_status = success_json(&run(
            &workspace,
            &state,
            &[
                "integration",
                "status",
                "--host",
                host,
                "--scope",
                "user",
                "--json",
            ],
            &[],
        )?)?;
        assert_eq!(user_status["data"]["host"], host);
        assert_eq!(user_status["data"]["scope"], "user");
        let user_path = user_status["data"]["path"]
            .as_str()
            .ok_or("user integration path missing")?;
        assert!(Path::new(user_path).ends_with(integration_suffix(host)?));

        let installed = success_json(&run(
            &workspace,
            &state,
            &[
                "integration",
                "install",
                "--host",
                host,
                "--scope",
                "project",
                "--json",
            ],
            &[],
        )?)?;
        assert_eq!(installed["data"]["host"], host);
        assert_eq!(installed["data"]["scope"], "project");
        assert_eq!(installed["data"]["status"], "installed");
        let path = installed["data"]["path"]
            .as_str()
            .ok_or("project integration path missing")?;
        assert!(Path::new(path).is_file(), "missing {host} project Skill");

        let status = success_json(&run(
            &workspace,
            &state,
            &[
                "integration",
                "status",
                "--host",
                host,
                "--scope",
                "project",
                "--json",
            ],
            &[],
        )?)?;
        assert_eq!(status["data"]["status"], "present-unmodified");

        let removed = success_json(&run(
            &workspace,
            &state,
            &[
                "integration",
                "uninstall",
                "--host",
                host,
                "--scope",
                "project",
                "--json",
            ],
            &[],
        )?)?;
        assert_eq!(removed["data"]["status"], "uninstalled-reinstallable");
        assert!(
            !Path::new(path).exists(),
            "left {host} project Skill behind"
        );
    }
    Ok(())
}

fn integration_suffix(host: &str) -> Result<&Path, Box<dyn std::error::Error>> {
    match host {
        "claude-code" => Ok(Path::new(".claude/skills/mnemoport/SKILL.md")),
        "codex" => Ok(Path::new(".agents/skills/mnemoport/SKILL.md")),
        "qoder" => Ok(Path::new(".qoder/skills/mnemoport/SKILL.md")),
        "cursor" => Ok(Path::new(".cursor/skills/mnemoport/SKILL.md")),
        _ => Err(format!("unsupported fixture host: {host}").into()),
    }
}

#[test]
fn json_failures_have_stable_diagnostics_and_exit_codes() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let state = temp.path().join("state");
    std::fs::create_dir_all(&workspace)?;
    let output = run(
        &workspace,
        &state,
        &["inspect", "missing.mnemo", "--json"],
        &[],
    )?;
    assert_eq!(output.status.code(), Some(6));
    let response: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(response["phase"], "inspect");
    assert_eq!(
        response["diagnostics"][0]["code"],
        "invalid_or_unsupported_input"
    );
    assert_eq!(response["data"], Value::Null);
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn inventory_uses_partial_exit_for_manual_assets() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let state = temp.path().join("state");
    let qoder = temp.path().join("qoder");
    std::fs::create_dir_all(&workspace)?;
    std::fs::create_dir_all(&qoder)?;
    std::fs::write(qoder.join("settings.json"), "{}")?;
    let output = run(
        &workspace,
        &state,
        &[
            "inventory",
            "--from",
            "qoder",
            "--invoked-by",
            "codex",
            "--json",
        ],
        &[("QODER_CONFIG_DIR", &qoder)],
    )?;
    assert_eq!(output.status.code(), Some(2));
    let response: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(response["data"][0]["kind"], "preference");
    assert_eq!(response["data"][0]["requires_assisted"], true);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn multi_workspace_package_maps_and_installs_each_root_without_source_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let source_alpha = temp.path().join("source-alpha-private");
    let source_beta = temp.path().join("source-beta-private");
    let source_config = temp.path().join("source-codex");
    let source_state = temp.path().join("source-state");
    let target_alpha = temp.path().join("target-alpha");
    let target_beta = temp.path().join("target-beta");
    let target_config = temp.path().join("target-codex");
    let target_state = temp.path().join("target-state");
    for directory in [
        &source_alpha,
        &source_beta,
        &source_config,
        &target_alpha,
        &target_beta,
        &target_config,
    ] {
        std::fs::create_dir_all(directory)?;
    }
    let source_alpha = source_alpha.canonicalize()?;
    let source_beta = source_beta.canonicalize()?;
    let target_alpha = target_alpha.canonicalize()?;
    let target_beta = target_beta.canonicalize()?;
    std::fs::write(source_alpha.join("AGENTS.md"), "Alpha instructions.\n")?;
    std::fs::write(source_beta.join("AGENTS.md"), "Beta instructions.\n")?;
    std::fs::create_dir_all(source_alpha.join(".git"))?;
    let remote_canary = "remote-password-canary-7f41";
    std::fs::write(
        source_alpha.join(".git/config"),
        format!(
            "[remote \"origin\"]\nurl = https://user:{remote_canary}@example.invalid/repo.git\n"
        ),
    )?;
    let package = temp.path().join("multi.mnemo");
    let plan = temp.path().join("multi-plan.json");
    let alpha_spec = format!("alpha={}", source_alpha.display());
    let beta_spec = format!("beta={}", source_beta.display());
    let exported = success_json(&run(
        temp.path(),
        &source_state,
        &[
            "export",
            "--from",
            "codex",
            "--workspace",
            &alpha_spec,
            "--workspace",
            &beta_spec,
            "--output",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--allow-plaintext",
            "--json",
        ],
        &[("CODEX_HOME", &source_config)],
    )?)?;
    assert_eq!(exported["data"]["assets"], 2);
    let descriptors = exported["data"]["workspaces"]
        .as_array()
        .ok_or("workspace descriptors missing")?;
    assert_eq!(descriptors.len(), 2);
    let id_for = |label: &str| -> Result<String, Box<dyn std::error::Error>> {
        Ok(descriptors
            .iter()
            .find(|descriptor| descriptor["label"] == label)
            .and_then(|descriptor| descriptor["workspace_id"].as_str())
            .ok_or("workspace id missing")?
            .to_owned())
    };
    let alpha_id = id_for("alpha")?;
    let beta_id = id_for("beta")?;

    let verified_package = mnemo_package::verify(&std::fs::read(&package)?)?;
    assert!(
        verified_package
            .manifest
            .header
            .required_features
            .contains(&"portable-workspaces".to_owned())
    );
    for bytes in verified_package.objects.values() {
        let body = String::from_utf8_lossy(bytes);
        assert!(!body.contains(source_alpha.to_string_lossy().as_ref()));
        assert!(!body.contains(source_beta.to_string_lossy().as_ref()));
        assert!(!body.contains(remote_canary));
    }

    let missing_map = run(
        temp.path(),
        &target_state,
        &[
            "plan",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--to",
            "codex",
            "--output",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?;
    assert_eq!(missing_map.status.code(), Some(6));

    let workspace_map = temp.path().join("workspace-map.json");
    std::fs::write(
        &workspace_map,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "1.0",
            "mappings": {
                alpha_id.clone(): target_alpha.to_string_lossy(),
                beta_id.clone(): target_beta.to_string_lossy()
            }
        }))?,
    )?;
    let planned = success_json(&run(
        temp.path(),
        &target_state,
        &[
            "plan",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--to",
            "codex",
            "--workspace-map",
            workspace_map.to_str().ok_or("map path is not UTF-8")?,
            "--output",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?)?;
    assert_eq!(
        planned["data"]["plan"]["workspace_mappings"][&alpha_id],
        target_alpha.to_string_lossy().as_ref()
    );
    assert_eq!(
        planned["data"]["plan"]["workspace_mappings"][&beta_id],
        target_beta.to_string_lossy().as_ref()
    );
    let token = planned["data"]["approval_token"]
        .as_str()
        .ok_or("approval token missing")?;

    success_json(&run(
        temp.path(),
        &target_state,
        &[
            "trust",
            "add",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--json",
        ],
        &[],
    )?)?;
    let tampered_plan = temp.path().join("tampered-plan.json");
    let mut tampered: Value = serde_json::from_slice(&std::fs::read(&plan)?)?;
    tampered["workspace_mappings"][&alpha_id] =
        Value::String(target_beta.to_string_lossy().into_owned());
    std::fs::write(&tampered_plan, serde_json::to_vec_pretty(&tampered)?)?;
    let rejected_tamper = run(
        temp.path(),
        &target_state,
        &[
            "apply",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            tampered_plan
                .to_str()
                .ok_or("tampered plan path is not UTF-8")?,
            "--approve",
            token,
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?;
    assert_eq!(rejected_tamper.status.code(), Some(6));
    assert!(!target_alpha.join("AGENTS.md").exists());
    assert!(!target_beta.join("AGENTS.md").exists());
    std::fs::write(target_alpha.join("AGENTS.md"), "External target edit.\n")?;
    let drifted = run(
        temp.path(),
        &target_state,
        &[
            "apply",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--approve",
            token,
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?;
    assert_eq!(drifted.status.code(), Some(3));
    assert_eq!(
        std::fs::read_to_string(target_alpha.join("AGENTS.md"))?,
        "External target edit.\n"
    );
    assert!(!target_beta.join("AGENTS.md").exists());
    std::fs::remove_file(target_alpha.join("AGENTS.md"))?;
    success_json(&run(
        temp.path(),
        &target_state,
        &[
            "apply",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--approve",
            token,
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?)?;
    assert_eq!(
        std::fs::read_to_string(target_alpha.join("AGENTS.md"))?,
        "Alpha instructions.\n"
    );
    assert_eq!(
        std::fs::read_to_string(target_beta.join("AGENTS.md"))?,
        "Beta instructions.\n"
    );
    let verified = success_json(&run(
        temp.path(),
        &target_state,
        &[
            "verify",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--json",
        ],
        &[("CODEX_HOME", &target_config)],
    )?)?;
    assert_eq!(verified["data"]["files_verified"], 2);
    Ok(())
}

#[test]
fn recovery_list_is_read_only_when_no_prepared_journals_exist()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let state = temp.path().join("state");
    std::fs::create_dir_all(&workspace)?;
    let output = run(&workspace, &state, &["recovery", "list", "--json"], &[])?;
    let response = success_json(&output)?;
    assert_eq!(response["phase"], "recovery-list");
    assert_eq!(response["data"], serde_json::json!([]));
    assert!(!state.join("data/transactions").exists());
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn handoff_package_installs_only_a_new_session_sidecar() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let source_workspace = temp.path().join("source");
    let target_workspace = temp.path().join("target");
    let source_state = temp.path().join("source-state");
    let target_state = temp.path().join("target-state");
    std::fs::create_dir_all(&source_workspace)?;
    std::fs::create_dir_all(&target_workspace)?;
    let capsule = temp.path().join("handoff.json");
    std::fs::write(
        &capsule,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "1.0",
            "source": "claude-code",
            "goal": "Continue MnemoPort",
            "latest_request": "Run target validation",
            "constraints": ["Never copy session databases"],
            "decisions": ["Use a new-session sidecar"],
            "completed": ["Package verified"],
            "pending": ["Review target plan"],
            "workspace": "fixture",
            "git_head": "0123456789abcdef",
            "git_dirty": false,
            "validation": ["L0"],
            "risks": []
        }))?,
    )?;
    let package = temp.path().join("handoff.mnemo");
    success_json(&run(
        &source_workspace,
        &source_state,
        &[
            "handoff",
            "--input",
            capsule.to_str().ok_or("capsule path is not UTF-8")?,
            "--output",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--allow-plaintext",
            "--json",
        ],
        &[],
    )?)?;
    let plan = temp.path().join("handoff-plan.json");
    let planned = success_json(&run(
        &target_workspace,
        &target_state,
        &[
            "plan",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--to",
            "cursor",
            "--output",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--json",
        ],
        &[],
    )?)?;
    let token = planned["data"]["approval_token"]
        .as_str()
        .ok_or("approval token missing")?;
    success_json(&run(
        &target_workspace,
        &target_state,
        &[
            "trust",
            "add",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--json",
        ],
        &[],
    )?)?;
    success_json(&run(
        &target_workspace,
        &target_state,
        &[
            "apply",
            "--input",
            package.to_str().ok_or("package path is not UTF-8")?,
            "--plan",
            plan.to_str().ok_or("plan path is not UTF-8")?,
            "--approve",
            token,
            "--json",
        ],
        &[],
    )?)?;
    let sidecars = std::fs::read_dir(target_workspace.join(".mnemoport/handoffs"))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sidecars.len(), 1);
    let body = std::fs::read_to_string(sidecars[0].path())?;
    assert!(body.contains("Continue MnemoPort"));
    assert!(body.contains("Never copy session databases"));
    assert!(!target_workspace.join("state.vscdb").exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn authoritative_plugin_inventory_is_bounded_normalized_and_secret_free()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let state = temp.path().join("state");
    let bin = temp.path().join("bin");
    std::fs::create_dir_all(&workspace)?;
    std::fs::create_dir_all(&bin)?;
    let executable = bin.join("claude");
    std::fs::write(
        &executable,
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  test -z "$MNEMOPORT_FAKE_SECRET" || exit 90
  printf '%s\n' '2.1.259 (Claude Code)'
  exit 0
fi
test "$1" = "plugin" || exit 91
test "$2" = "list" || exit 92
test "$3" = "--json" || exit 93
test -z "$MNEMOPORT_FAKE_SECRET" || exit 94
printf '%s\n' '[{"id":"reviewer@fixture-market","version":"1.2.3","scope":"user","enabled":true,"installPath":"/private/source/plugin-cache"}]'
"#,
    )?;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
    let secret_canary = temp.path().join("must-not-reach-vendor-command");
    let output = run(
        &workspace,
        &state,
        &["plugin-inventory", "--from", "claude-code", "--json"],
        &[("PATH", &bin), ("MNEMOPORT_FAKE_SECRET", &secret_canary)],
    )?;
    let report = success_json(&output)?;
    assert_eq!(report["phase"], "plugin-inventory");
    assert_eq!(report["data"][0]["status"], "collected");
    assert_eq!(report["data"][0]["vendor_command_executed"], true);
    assert_eq!(report["data"][0]["migrated_components_started"], false);
    assert_eq!(
        report["data"][0]["intents"][0]["identifier"],
        "reviewer@fixture-market"
    );
    assert_eq!(report["data"][0]["intents"][0]["resolved_version"], "1.2.3");
    let serialized = serde_json::to_string(&report)?;
    assert!(!serialized.contains("/private/source/plugin-cache"));
    assert!(!serialized.contains("must-not-reach-vendor-command"));
    assert!(!serialized.contains(temp.path().to_string_lossy().as_ref()));
    Ok(())
}

fn run(
    current_dir: &Path,
    state_root: &Path,
    arguments: &[&str],
    environment: &[(&str, &Path)],
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mnemo"));
    command.current_dir(current_dir).args(arguments);
    command.env("HOME", state_root.join("home"));
    command.env("USERPROFILE", state_root.join("home"));
    command.env("MNEMOPORT_STATE_ROOT", state_root);
    command.env("XDG_DATA_HOME", state_root.join("data"));
    command.env("XDG_CONFIG_HOME", state_root.join("config"));
    command.env("XDG_CACHE_HOME", state_root.join("cache"));
    for (name, value) in environment {
        command.env(name, value);
    }
    Ok(command.output()?)
}

fn success_json(output: &Output) -> Result<Value, Box<dyn std::error::Error>> {
    if !output.status.success() {
        return Err(format!(
            "command failed with {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
