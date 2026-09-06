//! MnemoPort command-line interface.

use age::secrecy::SecretString;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use mnemo_adapter_common::CollectionMode;
use mnemo_schema::{CommandResponse, Diagnostic, MigrationPlan, PlanOperationKind, Platform};
use mnemo_store::{Ledger, ManagedObjectRecord, OperationStatus, TransactionStatus};
use serde::Serialize;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "mnemo", version, about = "Portable AI assets, safely")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect MnemoPort and supported product roots without writing them.
    Doctor {
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Detect one or all supported AI products without launching them.
    Detect {
        /// Optional platform identifier.
        #[arg(long, value_parser = parse_platform)]
        platform: Option<Platform>,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// List supported file-backed assets without including their bodies.
    Inventory {
        /// Source platform.
        #[arg(long = "from", value_parser = parse_platform)]
        from: Platform,
        /// Host that invoked MnemoPort; recorded explicitly to prevent host ambiguity.
        #[arg(long, value_parser = parse_platform)]
        invoked_by: Option<Platform>,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Export supported assets to a signed `.mnemo` package.
    Export {
        /// Source platform.
        #[arg(long = "from", value_parser = parse_platform)]
        from: Platform,
        /// Host that invoked MnemoPort; it may differ from the source platform.
        #[arg(long, value_parser = parse_platform)]
        invoked_by: Option<Platform>,
        /// New package path. Existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
        /// Explicitly permit an unencrypted signed package.
        #[arg(long)]
        allow_plaintext: bool,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Verify and summarize a `.mnemo` package without writing target state.
    Inspect {
        /// Package path.
        input: PathBuf,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Build an immutable, target-specific migration plan without writing it.
    Plan {
        /// Verified source package.
        #[arg(long)]
        input: PathBuf,
        /// Target platform on this device.
        #[arg(long = "to", value_parser = parse_platform)]
        to: Platform,
        /// Current AI host; when supplied it must equal the target platform.
        #[arg(long, value_parser = parse_platform)]
        invoked_by: Option<Platform>,
        /// New plan JSON path.
        #[arg(long)]
        output: PathBuf,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Apply an unchanged plan transactionally.
    Apply {
        /// Verified source package used to rebuild target bytes.
        #[arg(long)]
        input: PathBuf,
        /// Plan generated on this target device.
        #[arg(long)]
        plan: PathBuf,
        /// Approval token printed by `mnemo plan`.
        #[arg(long)]
        approve: String,
        /// Current AI host; when supplied it must equal the planned target.
        #[arg(long, value_parser = parse_platform)]
        invoked_by: Option<Platform>,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Verify package, plan identity, and current target file hashes without writing.
    Verify {
        /// Verified source package used by the migration.
        #[arg(long)]
        input: PathBuf,
        /// Immutable target plan used by apply.
        #[arg(long)]
        plan: PathBuf,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Undo one completed migration if targets have not been externally edited.
    Undo {
        /// Migration operation id returned by `mnemo apply`.
        migration_id: String,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Read one local operation and its journal count.
    Report {
        /// Operation or migration id.
        operation_id: String,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Inspect or explicitly roll back interrupted prepared file transactions.
    Recovery {
        /// Recovery action.
        #[command(subcommand)]
        action: RecoveryAction,
    },
    /// Install, inspect, or remove the thin host Skill.
    Integration {
        /// Integration action.
        #[command(subcommand)]
        action: IntegrationAction,
    },
    /// Manage explicit trust for package signing identities.
    Trust {
        /// Trust action.
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Package a user-selected new-session Handoff capsule.
    Handoff {
        /// JSON file matching the Handoff schema; never an internal session DB.
        #[arg(long)]
        input: PathBuf,
        /// New encrypted `.mnemo` output.
        #[arg(long)]
        output: PathBuf,
        /// Explicitly allow an unencrypted non-sensitive fixture.
        #[arg(long)]
        allow_plaintext: bool,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryAction {
    /// List prepared transactions and hash-derived safe dispositions without writing.
    List {
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Roll back one prepared transaction if its target matches a recorded state.
    Rollback {
        /// Canonical transaction UUID reported by doctor or recovery list.
        transaction_id: String,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TrustAction {
    /// Trust the signer of one verified package.
    Add {
        /// Package whose signer should be trusted.
        #[arg(long)]
        input: PathBuf,
        /// Optional human label for the source device.
        #[arg(long)]
        label: Option<String>,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// List trusted signer fingerprints and public keys.
    List {
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum IntegrationAction {
    /// Install the host-specific thin Skill without overwriting user files.
    Install {
        /// Host platform.
        #[arg(long, value_parser = parse_platform)]
        host: Platform,
        /// User or project installation scope.
        #[arg(long, value_enum, default_value_t = IntegrationScope::User)]
        scope: IntegrationScope,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Check whether the expected Skill file is present and unchanged.
    Status {
        /// Host platform.
        #[arg(long, value_parser = parse_platform)]
        host: Platform,
        /// User or project installation scope.
        #[arg(long, value_enum, default_value_t = IntegrationScope::User)]
        scope: IntegrationScope,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
    /// Remove only a Skill file proven to be managed and unchanged.
    Uninstall {
        /// Host platform.
        #[arg(long, value_parser = parse_platform)]
        host: Platform,
        /// User or project installation scope.
        #[arg(long, value_enum, default_value_t = IntegrationScope::User)]
        scope: IntegrationScope,
        /// Emit the stable JSON response envelope.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum IntegrationScope {
    User,
    Project,
}

#[derive(Debug, Serialize)]
struct ExportReport {
    output: PathBuf,
    package_id: String,
    assets: usize,
    quarantined_assets: usize,
    encrypted: bool,
    signer_fingerprint: String,
}

#[derive(Debug, Serialize)]
struct InspectReport {
    package_id: String,
    format_version: String,
    assets: usize,
    object_count: usize,
    signer_fingerprint: String,
    encrypted: bool,
}

#[derive(Debug, Serialize)]
struct PlanReport {
    plan: MigrationPlan,
    output: PathBuf,
    approval_token: String,
    writable_files: usize,
    skipped_assets: Vec<mnemo_core::SkippedAsset>,
    signer_fingerprint: String,
}

#[derive(Debug, Serialize)]
struct ApplyReport {
    migration_id: String,
    plan_id: String,
    applied: usize,
    noops: usize,
    manual_or_conflicted: usize,
}

#[derive(Debug, Serialize)]
struct UndoReport {
    migration_id: String,
    restored_transactions: usize,
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    package_id: String,
    plan_id: String,
    signer_fingerprint: String,
    signer_trusted: bool,
    files_verified: usize,
    skipped_assets: usize,
    level: &'static str,
}

#[derive(Debug, Serialize)]
struct OperationReport {
    operation_id: String,
    kind: String,
    status: String,
    created_at_ms: i64,
    finished_at_ms: Option<i64>,
    journal_count: usize,
}

#[derive(Debug, Serialize)]
struct IntegrationReport {
    host: Platform,
    scope: String,
    path: PathBuf,
    status: String,
    expected_hash: String,
    actual_hash: Option<String>,
}

fn parse_platform(value: &str) -> Result<Platform, String> {
    value.parse()
}

fn main() -> ExitCode {
    let json_requested = std::env::args_os().any(|argument| argument == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            if json_requested {
                emit_failure("parse", "invalid_arguments", 6);
            } else {
                let _ = error.print();
            }
            return ExitCode::from(6);
        }
    };
    let phase = command_phase(&cli.command);
    match run(cli) {
        Ok(exit_code) => ExitCode::from(exit_code),
        Err(error) => {
            let (exit_code, diagnostic) = classify_error(&error);
            if json_requested {
                emit_failure(phase, diagnostic, exit_code);
            } else {
                eprintln!("{error:#}");
            }
            ExitCode::from(exit_code)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> Result<u8> {
    let mut outcome = 0_u8;
    match cli.command {
        Command::Doctor { json } => {
            let report = mnemo_core::doctor().context("doctor failed")?;
            emit(json, "doctor", report)?;
        }
        Command::Detect { platform, json } => {
            let report = mnemo_core::detect(platform).context("detection failed")?;
            emit(json, "detect", report)?;
        }
        Command::Inventory {
            from,
            invoked_by: _,
            json,
        } => {
            let inventory = mnemo_core::inventory(from, CollectionMode::OfflineStatic)
                .context("inventory failed")?;
            if inventory.iter().any(|item| item.requires_assisted) {
                outcome = 2;
            }
            emit(json, "inventory", inventory)?;
        }
        Command::Export {
            from,
            invoked_by: _,
            output,
            allow_plaintext,
            json,
        } => {
            let should_encrypt = !allow_plaintext;
            let assets = mnemo_core::extract(from, CollectionMode::OfflineStatic)
                .context("asset extraction failed")?;
            let quarantined_assets = assets
                .iter()
                .filter(|asset| asset.asset.sensitivity == mnemo_schema::Sensitivity::Quarantined)
                .count();
            if quarantined_assets > 0 {
                outcome = 2;
            }
            let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
            let key = mnemo_store::load_or_create_signing_key(&state.data)
                .context("device signing identity unavailable")?;
            let package = mnemo_core::package_assets(&assets, &key)?;
            let bytes = if should_encrypt {
                let passphrase = passphrase_from_environment()?;
                mnemo_package::encrypt_with_passphrase(&package.bytes, &passphrase)?
            } else {
                package.bytes.clone()
            };
            write_new_private(&output, &bytes)?;
            let report = ExportReport {
                output,
                package_id: package.manifest.package_id,
                assets: assets.len(),
                quarantined_assets,
                encrypted: should_encrypt,
                signer_fingerprint: mnemo_core::signer_fingerprint(
                    &package.manifest.signer_public_key,
                ),
            };
            emit(json, "export", report)?;
        }
        Command::Inspect { input, json } => {
            let (verified, encrypted) = open_package(&input)?;
            let assets = mnemo_core::unpack_assets(&verified)?;
            let report = InspectReport {
                package_id: verified.manifest.package_id.clone(),
                format_version: verified.manifest.header.format_version.clone(),
                assets: assets.len(),
                object_count: verified.manifest.objects.len(),
                signer_fingerprint: mnemo_core::signer_fingerprint(
                    &verified.manifest.signer_public_key,
                ),
                encrypted,
            };
            emit(json, "inspect", report)?;
        }
        Command::Plan {
            input,
            to,
            invoked_by,
            output,
            json,
        } => {
            validate_target_host(invoked_by, to)?;
            let (verified, _) = open_package(&input)?;
            let assets = mnemo_core::unpack_assets(&verified)?;
            let workspace = std::env::current_dir()?;
            let (target, roots) = mnemo_core::resolve_target_roots(to, &workspace)?;
            let prepared = mnemo_core::prepare_migration(target, &roots, &assets)?;
            if !prepared.skipped.is_empty()
                || prepared
                    .plan
                    .operations
                    .iter()
                    .any(|operation| operation.kind == PlanOperationKind::ManualStep)
            {
                outcome = 2;
            }
            let bytes = serde_json::to_vec_pretty(&prepared.plan)?;
            write_new_private(&output, &bytes)?;
            let report = PlanReport {
                signer_fingerprint: mnemo_core::signer_fingerprint(
                    &verified.manifest.signer_public_key,
                ),
                approval_token: approval_token(&prepared.plan.plan_id),
                writable_files: prepared.files.len(),
                skipped_assets: prepared.skipped,
                plan: prepared.plan,
                output,
            };
            emit(json, "plan", report)?;
        }
        Command::Apply {
            input,
            plan,
            approve,
            invoked_by,
            json,
        } => {
            let saved: MigrationPlan = serde_json::from_slice(
                &fs::read(&plan).with_context(|| format!("cannot read {}", plan.display()))?,
            )
            .context("invalid migration plan JSON")?;
            if approve != approval_token(&saved.plan_id) {
                anyhow::bail!("approval token does not match this plan");
            }
            validate_target_host(invoked_by, saved.target.platform)?;
            let (verified, _) = open_package(&input)?;
            require_trusted_signer(&verified.manifest.signer_public_key)?;
            let assets = mnemo_core::unpack_assets(&verified)?;
            let workspace = std::env::current_dir()?;
            let (target, roots) =
                mnemo_core::resolve_target_roots(saved.target.platform, &workspace)?;
            let prepared = mnemo_core::prepare_migration(target, &roots, &assets)?;
            if prepared.plan != saved {
                anyhow::bail!(
                    "target or package drifted after planning; discard the plan and run mnemo plan again"
                );
            }
            let report = apply_prepared(&prepared)?;
            if report.manual_or_conflicted > 0 {
                outcome = 2;
            }
            emit(json, "apply", report)?;
        }
        Command::Verify { input, plan, json } => {
            let report = verify_migration(&input, &plan)?;
            if report.skipped_assets > 0 {
                outcome = 2;
            }
            emit(json, "verify", report)?;
        }
        Command::Undo { migration_id, json } => {
            let report = undo_migration(&migration_id)?;
            emit(json, "undo", report)?;
        }
        Command::Report { operation_id, json } => {
            emit(json, "report", operation_report(&operation_id)?)?;
        }
        Command::Recovery { action } => match action {
            RecoveryAction::List { json } => {
                let state =
                    mnemo_store::resolve_state_paths().context("state paths unavailable")?;
                emit(
                    json,
                    "recovery-list",
                    mnemo_store::scan_recovery_candidates(&state.transactions)?,
                )?;
            }
            RecoveryAction::Rollback {
                transaction_id,
                json,
            } => {
                let state =
                    mnemo_store::resolve_state_paths().context("state paths unavailable")?;
                emit(
                    json,
                    "recovery-rollback",
                    mnemo_store::rollback_prepared_transaction(
                        &state.transactions,
                        &transaction_id,
                    )?,
                )?;
            }
        },
        Command::Integration { action } => match action {
            IntegrationAction::Install { host, scope, json } => {
                emit(
                    json,
                    "integration-install",
                    install_integration(host, scope)?,
                )?;
            }
            IntegrationAction::Status { host, scope, json } => {
                emit(json, "integration-status", integration_status(host, scope)?)?;
            }
            IntegrationAction::Uninstall { host, scope, json } => {
                emit(
                    json,
                    "integration-uninstall",
                    uninstall_integration(host, scope)?,
                )?;
            }
        },
        Command::Trust { action } => match action {
            TrustAction::Add { input, label, json } => {
                let (verified, _) = open_package(&input)?;
                let state =
                    mnemo_store::resolve_state_paths().context("state paths unavailable")?;
                let ledger = Ledger::open(&state.data.join("ledger.sqlite"))?;
                let record =
                    ledger.trust_key(&verified.manifest.signer_public_key, label.as_deref())?;
                emit(json, "trust-add", record)?;
            }
            TrustAction::List { json } => {
                let state =
                    mnemo_store::resolve_state_paths().context("state paths unavailable")?;
                let ledger = Ledger::open(&state.data.join("ledger.sqlite"))?;
                emit(json, "trust-list", ledger.trusted_keys()?)?;
            }
        },
        Command::Handoff {
            input,
            output,
            allow_plaintext,
            json,
        } => {
            let capsule: mnemo_schema::HandoffCapsule = serde_json::from_slice(
                &fs::read(&input)
                    .with_context(|| format!("cannot read handoff input {}", input.display()))?,
            )
            .context("invalid Handoff JSON")?;
            let asset = mnemo_core::create_handoff(&capsule)?;
            let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
            let key = mnemo_store::load_or_create_signing_key(&state.data)?;
            let package = mnemo_core::package_assets(&[asset], &key)?;
            let bytes = if allow_plaintext {
                package.bytes.clone()
            } else {
                mnemo_package::encrypt_with_passphrase(
                    &package.bytes,
                    &passphrase_from_environment()?,
                )?
            };
            write_new_private(&output, &bytes)?;
            emit(
                json,
                "handoff",
                ExportReport {
                    output,
                    package_id: package.manifest.package_id,
                    assets: 1,
                    quarantined_assets: 0,
                    encrypted: !allow_plaintext,
                    signer_fingerprint: mnemo_core::signer_fingerprint(
                        &package.manifest.signer_public_key,
                    ),
                },
            )?;
        }
    }
    Ok(outcome)
}

fn command_phase(command: &Command) -> &'static str {
    match command {
        Command::Doctor { .. } => "doctor",
        Command::Detect { .. } => "detect",
        Command::Inventory { .. } => "inventory",
        Command::Export { .. } => "export",
        Command::Inspect { .. } => "inspect",
        Command::Plan { .. } => "plan",
        Command::Apply { .. } => "apply",
        Command::Verify { .. } => "verify",
        Command::Undo { .. } => "undo",
        Command::Report { .. } => "report",
        Command::Recovery { .. } => "recovery",
        Command::Integration { .. } => "integration",
        Command::Trust { .. } => "trust",
        Command::Handoff { .. } => "handoff",
    }
}

fn verify_migration(input: &Path, plan: &Path) -> Result<VerifyReport> {
    let saved: MigrationPlan = serde_json::from_slice(
        &fs::read(plan).with_context(|| format!("cannot read {}", plan.display()))?,
    )
    .context("invalid migration plan JSON")?;
    let mut identity = saved.clone();
    identity.plan_id.clear();
    let expected_plan_id = mnemo_security::sha256_id(&serde_json::to_vec(&identity)?);
    if expected_plan_id != saved.plan_id {
        anyhow::bail!("invalid migration plan identity");
    }
    let (verified, _) = open_package(input)?;
    let assets = mnemo_core::unpack_assets(&verified)?;
    let workspace = std::env::current_dir()?;
    let (target, roots) = mnemo_core::resolve_target_roots(saved.target.platform, &workspace)?;
    let prepared = mnemo_core::prepare_migration(target, &roots, &assets)?;
    if prepared.plan.source_root_hash != saved.source_root_hash
        || prepared.plan.target != saved.target
        || prepared.plan.adapter_version != saved.adapter_version
    {
        anyhow::bail!("package or target tuple drifted from the saved migration plan");
    }
    for file in &prepared.files {
        let actual = fs::read(&file.target_path)
            .ok()
            .map(|bytes| mnemo_security::sha256_id(&bytes));
        if actual.as_deref() != Some(file.desired_hash.as_str()) {
            anyhow::bail!("target drift detected during L0 verification");
        }
    }
    let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
    let ledger_path = state.data.join("ledger.sqlite");
    let signer_trusted = if ledger_path.exists() {
        Ledger::open(&ledger_path)?.is_key_trusted(&verified.manifest.signer_public_key)?
    } else {
        false
    };
    Ok(VerifyReport {
        package_id: verified.manifest.package_id,
        plan_id: saved.plan_id,
        signer_fingerprint: mnemo_core::signer_fingerprint(&verified.manifest.signer_public_key),
        signer_trusted,
        files_verified: prepared.files.len(),
        skipped_assets: prepared.skipped.len(),
        level: "l0",
    })
}

fn operation_report(operation_id: &str) -> Result<OperationReport> {
    let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
    let ledger_path = state.data.join("ledger.sqlite");
    if !ledger_path.exists() {
        anyhow::bail!("operation ledger is unavailable");
    }
    let ledger = Ledger::open(&ledger_path)?;
    let operation = ledger
        .operation(operation_id)?
        .with_context(|| format!("operation not found: {operation_id}"))?;
    let journal_count = ledger.transaction_journals(operation_id)?.len();
    Ok(OperationReport {
        operation_id: operation.id,
        kind: operation.kind,
        status: operation.status,
        created_at_ms: operation.created_at_ms,
        finished_at_ms: operation.finished_at_ms,
        journal_count,
    })
}

fn classify_error(error: &anyhow::Error) -> (u8, &'static str) {
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("precondition")
        || message.contains("drift")
        || message.contains("collision")
        || message.contains("does not match target")
        || message.contains("approval token")
        || message.contains("overwrite")
        || message.contains("modified integration")
    {
        (3, "conflict_or_target_drift")
    } else if message.contains("credential-like")
        || message.contains("unsafe")
        || message.contains("symlink")
        || message.contains("security")
    {
        (4, "safety_policy_refused")
    } else if message.contains("not trusted")
        || message.contains("state paths unavailable")
        || message.contains("dependency")
        || message.contains("unavailable")
    {
        (5, "dependency_or_trust_unavailable")
    } else if message.contains("invalid")
        || message.contains("unsupported")
        || message.contains("parse")
        || message.contains("cannot read")
        || message.contains("decrypt")
        || message.contains("verification")
        || message.contains("package")
        || message.contains("schema")
    {
        (6, "invalid_or_unsupported_input")
    } else {
        (70, "internal_error")
    }
}

fn validate_target_host(invoked_by: Option<Platform>, target: Platform) -> Result<()> {
    if invoked_by.is_some_and(|host| host != target) {
        anyhow::bail!(
            "invoking host does not match target platform; run the target host Skill or correct --to"
        );
    }
    Ok(())
}

fn emit_failure(phase: &str, code: &str, exit_code: u8) {
    let message = match exit_code {
        3 => "Operation needs replanning, conflict resolution, or matching approval.",
        4 => "Operation was refused by the local safety policy.",
        5 => "A required local dependency, credential reference, or trust decision is unavailable.",
        6 => "Input, package, schema, or version is invalid or unsupported.",
        _ => "Operation failed unexpectedly; rerun without --json for local diagnostics.",
    };
    let response = CommandResponse::failure(phase, Diagnostic::new(code, message));
    if let Ok(encoded) = serde_json::to_string_pretty(&response) {
        println!("{encoded}");
    }
}

fn require_trusted_signer(public_key: &str) -> Result<()> {
    let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
    let ledger = Ledger::open(&state.data.join("ledger.sqlite"))?;
    if !ledger.is_key_trusted(public_key)? {
        anyhow::bail!(
            "package signature is valid but the signer is not trusted; inspect it and run mnemo trust add --input <package> before apply"
        );
    }
    Ok(())
}

fn install_integration(host: Platform, scope: IntegrationScope) -> Result<IntegrationReport> {
    let path = integration_path(host, scope)?;
    let content = integration_template(host).as_bytes();
    let expected_hash = mnemo_security::sha256_id(content);
    if path.exists() {
        let actual_hash = mnemo_security::sha256_id(&fs::read(&path)?);
        if actual_hash == expected_hash {
            return Ok(IntegrationReport {
                host,
                scope: integration_scope_name(scope).to_owned(),
                path,
                status: "present-unmodified".to_owned(),
                expected_hash,
                actual_hash: Some(actual_hash),
            });
        }
        anyhow::bail!("refusing to overwrite existing Skill at {}", path.display());
    }
    let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
    let ledger = Ledger::open(&state.data.join("ledger.sqlite"))?;
    let operation_id = ledger.begin_operation(
        "integration-install",
        &serde_json::json!({"host": host, "path": path}),
    )?;
    let journal = mnemo_store::apply_file(&path, content, &state.transactions, None)?;
    ledger.record_transaction(&operation_id, &journal)?;
    ledger.record_managed_object(&ManagedObjectRecord {
        target_locator: path.to_string_lossy().into_owned(),
        owner_id: operation_id.clone(),
        installed_hash: expected_hash.clone(),
        source_asset_id: format!(
            "integration:{}:{}",
            host.as_str(),
            env!("CARGO_PKG_VERSION")
        ),
    })?;
    ledger.finish_operation(&operation_id, OperationStatus::Succeeded)?;
    Ok(IntegrationReport {
        host,
        scope: integration_scope_name(scope).to_owned(),
        path,
        status: "installed".to_owned(),
        expected_hash: expected_hash.clone(),
        actual_hash: Some(expected_hash),
    })
}

fn integration_status(host: Platform, scope: IntegrationScope) -> Result<IntegrationReport> {
    let path = integration_path(host, scope)?;
    let expected_hash = mnemo_security::sha256_id(integration_template(host).as_bytes());
    let actual_hash = fs::read(&path)
        .ok()
        .map(|bytes| mnemo_security::sha256_id(&bytes));
    let status = match actual_hash.as_deref() {
        None => "absent",
        Some(actual) if actual == expected_hash => "present-unmodified",
        Some(_) => "present-modified-or-unmanaged",
    };
    Ok(IntegrationReport {
        host,
        scope: integration_scope_name(scope).to_owned(),
        path,
        status: status.to_owned(),
        expected_hash,
        actual_hash,
    })
}

fn uninstall_integration(host: Platform, scope: IntegrationScope) -> Result<IntegrationReport> {
    let status = integration_status(host, scope)?;
    let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
    let ledger = Ledger::open(&state.data.join("ledger.sqlite"))?;
    let locator = status.path.to_string_lossy().into_owned();
    let managed = ledger
        .managed_object(&locator)?
        .context("refusing to remove an integration without MnemoPort ownership proof")?;
    let actual_hash = status
        .actual_hash
        .as_deref()
        .context("managed integration file is already absent")?;
    if actual_hash != managed.installed_hash || actual_hash != status.expected_hash {
        anyhow::bail!(
            "refusing to remove modified integration at {}",
            status.path.display()
        );
    }
    fs::remove_file(&status.path)?;
    ledger.remove_managed_object(&locator)?;
    Ok(IntegrationReport {
        status: "uninstalled-reinstallable".to_owned(),
        actual_hash: None,
        ..status
    })
}

fn integration_path(host: Platform, scope: IntegrationScope) -> Result<PathBuf> {
    let workspace = std::env::current_dir()?;
    let path = match (host, scope) {
        (Platform::ClaudeCode, IntegrationScope::User) => {
            mnemo_adapter_common::resolve_root("CLAUDE_CONFIG_DIR", ".claude")?
                .path
                .join("skills/mnemoport/SKILL.md")
        }
        (Platform::ClaudeCode, IntegrationScope::Project) => {
            workspace.join(".claude/skills/mnemoport/SKILL.md")
        }
        (Platform::Codex, IntegrationScope::User) => {
            mnemo_adapter_common::user_home()?.join(".agents/skills/mnemoport/SKILL.md")
        }
        (Platform::Codex, IntegrationScope::Project) => {
            workspace.join(".agents/skills/mnemoport/SKILL.md")
        }
        (Platform::Qoder, IntegrationScope::User) => {
            mnemo_adapter_common::resolve_root("QODER_CONFIG_DIR", ".qoder")?
                .path
                .join("skills/mnemoport/SKILL.md")
        }
        (Platform::Qoder, IntegrationScope::Project) => {
            workspace.join(".qoder/skills/mnemoport/SKILL.md")
        }
        (Platform::Cursor, IntegrationScope::User) => {
            mnemo_adapter_common::user_home()?.join(".cursor/skills/mnemoport/SKILL.md")
        }
        (Platform::Cursor, IntegrationScope::Project) => {
            workspace.join(".cursor/skills/mnemoport/SKILL.md")
        }
    };
    Ok(path)
}

const fn integration_template(host: Platform) -> &'static str {
    match host {
        Platform::ClaudeCode => {
            include_str!("../../../integrations/skills/claude-code/mnemoport/SKILL.md")
        }
        Platform::Codex => include_str!("../../../integrations/skills/codex/mnemoport/SKILL.md"),
        Platform::Qoder => include_str!("../../../integrations/skills/qoder/mnemoport/SKILL.md"),
        Platform::Cursor => include_str!("../../../integrations/skills/cursor/mnemoport/SKILL.md"),
    }
}

const fn integration_scope_name(scope: IntegrationScope) -> &'static str {
    match scope {
        IntegrationScope::User => "user",
        IntegrationScope::Project => "project",
    }
}

fn approval_token(plan_id: &str) -> String {
    plan_id
        .strip_prefix("sha256:")
        .unwrap_or(plan_id)
        .chars()
        .take(16)
        .collect()
}

fn apply_prepared(prepared: &mnemo_core::PreparedMigration) -> Result<ApplyReport> {
    let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
    let ledger = Ledger::open(&state.data.join("ledger.sqlite"))?;
    let migration_id = ledger.begin_operation(
        "apply",
        &serde_json::json!({"plan_id": prepared.plan.plan_id}),
    )?;
    let mut committed = Vec::new();
    let mut applied = 0;
    let mut noops = 0;
    let mut manual = 0;
    for operation in &prepared.plan.operations {
        match operation.kind {
            PlanOperationKind::Noop => noops += 1,
            PlanOperationKind::WriteFile => {
                if operation.approval == mnemo_schema::ApprovalClass::UserResolution {
                    manual += 1;
                    continue;
                }
                let file = prepared
                    .files
                    .iter()
                    .find(|file| {
                        operation.preconditions.first().is_some_and(|condition| {
                            condition.locator == file.target_path.to_string_lossy()
                        })
                    })
                    .context("plan file payload is unavailable")?;
                let expected = operation
                    .preconditions
                    .first()
                    .and_then(|condition| condition.expected_hash.as_deref());
                match mnemo_store::apply_file(
                    &file.target_path,
                    &file.bytes,
                    &state.transactions,
                    expected,
                ) {
                    Ok(journal) => {
                        committed.push(journal);
                        if let Err(error) = ledger.record_transaction(
                            &migration_id,
                            committed.last().context("committed journal disappeared")?,
                        ) {
                            let rollback_ok = rollback_all(&ledger, &mut committed);
                            let _ = ledger.finish_operation(
                                &migration_id,
                                if rollback_ok {
                                    OperationStatus::RolledBack
                                } else {
                                    OperationStatus::Failed
                                },
                            );
                            return Err(error).context(
                                "ledger record failed; committed Phase A files were rolled back",
                            );
                        }
                        applied += 1;
                    }
                    Err(error) => {
                        let rollback_ok = rollback_all(&ledger, &mut committed);
                        ledger.finish_operation(
                            &migration_id,
                            if rollback_ok {
                                OperationStatus::RolledBack
                            } else {
                                OperationStatus::Failed
                            },
                        )?;
                        return Err(error)
                            .context("apply failed; committed Phase A files were rolled back");
                    }
                }
            }
            _ => manual += 1,
        }
    }
    if let Err(error) = ledger.finish_operation(&migration_id, OperationStatus::Succeeded) {
        let _ = rollback_all(&ledger, &mut committed);
        return Err(error).context("ledger finalization failed; Phase A rollback was attempted");
    }
    Ok(ApplyReport {
        migration_id,
        plan_id: prepared.plan.plan_id.clone(),
        applied,
        noops,
        manual_or_conflicted: manual + prepared.skipped.len(),
    })
}

fn rollback_all(ledger: &Ledger, journals: &mut [mnemo_store::FileTransactionJournal]) -> bool {
    let mut success = true;
    for journal in journals.iter_mut().rev() {
        if mnemo_store::undo_file(journal, false).is_ok() {
            if ledger
                .set_transaction_status(&journal.id, TransactionStatus::RolledBack)
                .is_err()
            {
                success = false;
            }
        } else {
            success = false;
        }
    }
    success
}

fn undo_migration(migration_id: &str) -> Result<UndoReport> {
    let state = mnemo_store::resolve_state_paths().context("state paths unavailable")?;
    let ledger = Ledger::open(&state.data.join("ledger.sqlite"))?;
    let mut journal_paths = ledger.transaction_journals(migration_id)?;
    if journal_paths.is_empty() {
        anyhow::bail!("migration has no recorded transactions: {migration_id}");
    }
    journal_paths.reverse();
    let mut restored = 0;
    for path in journal_paths {
        let mut journal = mnemo_store::load_journal(&path)?;
        mnemo_store::undo_file(&mut journal, false)
            .with_context(|| format!("undo stopped safely at {}", journal.target.display()))?;
        ledger.set_transaction_status(&journal.id, TransactionStatus::RolledBack)?;
        restored += 1;
    }
    ledger.finish_operation(migration_id, OperationStatus::RolledBack)?;
    Ok(UndoReport {
        migration_id: migration_id.to_owned(),
        restored_transactions: restored,
    })
}

fn passphrase_from_environment() -> Result<SecretString> {
    let passphrase = std::env::var("MNEMOPORT_PASSPHRASE").context(
        "encrypted package requires MNEMOPORT_PASSPHRASE from a secret-aware process environment; use --allow-plaintext only for an intentional non-sensitive export",
    )?;
    if passphrase.len() < 12 {
        anyhow::bail!("MNEMOPORT_PASSPHRASE must be at least 12 characters");
    }
    Ok(SecretString::from(passphrase))
}

fn open_package(path: &Path) -> Result<(mnemo_package::VerifiedPackage, bool)> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    match mnemo_package::verify(&bytes) {
        Ok(package) => return Ok((package, false)),
        Err(error) if !bytes.starts_with(b"age-encryption.org/v1") => {
            return Err(error).context("package verification failed");
        }
        Err(_) => {}
    }
    let passphrase = passphrase_from_environment()
        .context("package is not plaintext; encrypted inspection needs the passphrase")?;
    let decrypted = mnemo_package::decrypt_with_passphrase(&bytes, passphrase)
        .context("package decryption failed")?;
    Ok((
        mnemo_package::verify(&decrypted).context("decrypted package verification failed")?,
        true,
    ))
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite or cannot create {}", path.display()))?;
    set_private_permissions(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_private_permissions(_file: &File) -> Result<()> {
    Ok(())
}

fn emit<T>(json: bool, phase: &str, data: T) -> Result<()>
where
    T: serde::Serialize + std::fmt::Debug,
{
    if json {
        let response = CommandResponse::success(phase, data);
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("{data:#?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mnemo_schema::Platform;

    #[test]
    fn invoking_host_must_match_target_when_supplied() {
        assert!(super::validate_target_host(Some(Platform::Codex), Platform::Codex).is_ok());
        assert!(super::validate_target_host(None, Platform::Codex).is_ok());
        assert!(super::validate_target_host(Some(Platform::Cursor), Platform::Codex).is_err());
    }
}
