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

fn run(
    current_dir: &Path,
    state_root: &Path,
    arguments: &[&str],
    environment: &[(&str, &Path)],
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mnemo"));
    command.current_dir(current_dir).args(arguments);
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
