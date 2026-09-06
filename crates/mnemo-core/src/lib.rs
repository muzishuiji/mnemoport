//! MnemoPort workflow orchestration.

use mnemo_adapter_claude_code::ClaudeCodeAdapter;
use mnemo_adapter_codex::CodexAdapter;
use mnemo_adapter_common::{AdapterError, PlatformAdapter};
use mnemo_adapter_common::{
    CanonicalAssetInput, CollectionMode, ExtractedAsset, InventoryItem, RenderedFile, TargetRoot,
    make_asset, user_home,
};
use mnemo_adapter_cursor::CursorAdapter;
use mnemo_adapter_qoder::QoderAdapter;
use mnemo_package::{PackageBuilder, PackageError, SignedPackage, VerifiedPackage};
use mnemo_schema::{
    ApplyPhase, ApprovalClass, AssetKind, AssetPayload, AssetProbe, AssetProbeMethod,
    AssetProbeStatus, Entrypoint, MigrationPlan, PlanOperation, PlanOperationKind,
    PlanPrecondition, Platform, ProbeStatus, ProductProbe, ProductTuple, RollbackGuarantee,
    Sensitivity,
};
use mnemo_security::{FindingSeverity, scan_and_redact, sha256_id, validate_portable_path};
use mnemo_store::{
    Ledger, RecoveryCandidate, StatePaths, resolve_state_paths,
    scan_recovery_candidates_with_ledger,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Build metadata and read-only environment status.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// MnemoPort package version.
    pub version: &'static str,
    /// Host operating system.
    pub os: &'static str,
    /// Host CPU architecture.
    pub arch: &'static str,
    /// Resolved state paths; no directory is created by doctor.
    pub state_paths: Option<StatePaths>,
    /// Read-only platform detections.
    pub detections: Vec<ProductTuple>,
    /// Prepared file transactions left by an interrupted process.
    pub recovery_candidates: Vec<RecoveryCandidate>,
}

/// Core orchestration error.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Platform discovery failed.
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    /// A plan cannot be canonicalized.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Package construction or verification failed.
    #[error(transparent)]
    Package(#[from] PackageError),
    /// Local state or transaction recovery inspection failed.
    #[error(transparent)]
    Store(#[from] mnemo_store::StoreError),
    /// Local read-only verification or disposable staging I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Package object graph is incomplete or inconsistent.
    #[error("invalid migration bundle: {0}")]
    InvalidBundle(String),
}

/// How an existing user-owned target should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// Do not change the existing target; emit a manual step.
    Preserve,
    /// Replace it after explicit conflict approval.
    Overwrite,
    /// Write a deterministic sibling and preserve the original.
    SideBySide,
}

/// State observed at a proposed target locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetObservation {
    /// Adapter-approved target locator.
    pub locator: String,
    /// Current target hash, absent if it does not exist.
    pub current_hash: Option<String>,
    /// Hash MnemoPort last installed here, if the ledger owns it.
    pub managed_hash: Option<String>,
}

/// Result of deterministic conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictDecision {
    /// Operation to emit.
    pub kind: PlanOperationKind,
    /// Final target locator.
    pub locator: String,
    /// Approval needed for this decision.
    pub approval: ApprovalClass,
    /// Stable explanatory code.
    pub reason: &'static str,
}

/// Resolved roots for a target platform on one device.
#[derive(Debug, Clone)]
pub struct TargetRoots {
    /// Product configuration root.
    pub product_config: PathBuf,
    /// User home root.
    pub user_home: PathBuf,
    /// Selected target workspace.
    pub workspace: PathBuf,
}

/// One fully rendered target file. Bytes are omitted from JSON reports and only
/// live in the local prepared transaction.
#[derive(Debug, Clone, Serialize)]
pub struct PreparedFile {
    /// Source or combined asset identity.
    pub asset_id: String,
    /// Canonical kind used by asset-level verification routing.
    pub asset_kind: AssetKind,
    /// Logical root.
    pub root: String,
    /// Portable path relative to the logical root.
    pub relative_path: String,
    /// Resolved target path.
    pub target_path: PathBuf,
    /// Desired content hash.
    pub desired_hash: String,
    /// Desired file bytes, deliberately absent from serialized plans/reports.
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

/// An asset deliberately omitted from automatic target rendering.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedAsset {
    /// Canonical asset id.
    pub asset_id: String,
    /// Stable source locator.
    pub locator: String,
    /// Sanitized explanation.
    pub reason: String,
}

/// Prepared target plan paired with ephemeral bytes and explicit omissions.
#[derive(Debug, Clone, Serialize)]
pub struct PreparedMigration {
    /// Immutable plan.
    pub plan: MigrationPlan,
    /// Rendered files referenced by plan effects.
    pub files: Vec<PreparedFile>,
    /// Unsupported/manual items.
    pub skipped: Vec<SkippedAsset>,
}

/// Resolve file conflicts without modifying the target.
#[must_use]
pub fn resolve_file_conflict(
    desired_hash: &str,
    observation: &TargetObservation,
    policy: ConflictPolicy,
) -> ConflictDecision {
    match observation.current_hash.as_deref() {
        None => ConflictDecision {
            kind: PlanOperationKind::WriteFile,
            locator: observation.locator.clone(),
            approval: ApprovalClass::Write,
            reason: "target_absent",
        },
        Some(current) if current == desired_hash => ConflictDecision {
            kind: PlanOperationKind::Noop,
            locator: observation.locator.clone(),
            approval: ApprovalClass::None,
            reason: "already_converged",
        },
        Some(current) if observation.managed_hash.as_deref() == Some(current) => ConflictDecision {
            kind: PlanOperationKind::WriteFile,
            locator: observation.locator.clone(),
            approval: ApprovalClass::Write,
            reason: "managed_update",
        },
        Some(_) if policy == ConflictPolicy::Overwrite => ConflictDecision {
            kind: PlanOperationKind::WriteFile,
            locator: observation.locator.clone(),
            approval: ApprovalClass::UserResolution,
            reason: "user_owned_overwrite",
        },
        Some(_) if policy == ConflictPolicy::SideBySide => ConflictDecision {
            kind: PlanOperationKind::WriteFile,
            locator: side_by_side_locator(&observation.locator, desired_hash),
            approval: ApprovalClass::Write,
            reason: "user_owned_side_by_side",
        },
        Some(_) => ConflictDecision {
            kind: PlanOperationKind::ManualStep,
            locator: observation.locator.clone(),
            approval: ApprovalClass::UserResolution,
            reason: "user_owned_preserved",
        },
    }
}

/// Input to the generic deterministic plan finalizer. Platform adapters own
/// locator and effect construction; the core owns conflict and id semantics.
#[derive(Debug, Clone)]
pub struct FilePlanCandidate {
    /// Canonical source asset id.
    pub asset_id: String,
    /// Desired content hash.
    pub desired_hash: String,
    /// Structured adapter effect.
    pub effect: Value,
    /// Structured verification recipe.
    pub verification: Value,
    /// Current target observation.
    pub target: TargetObservation,
    /// Conflict policy chosen for this invocation.
    pub conflict_policy: ConflictPolicy,
}

/// Build an immutable, content-addressed Phase A plan.
pub fn build_file_plan(
    source_root_hash: impl Into<String>,
    target: ProductTuple,
    adapter_version: impl Into<String>,
    capability_snapshot_hash: impl Into<String>,
    candidates: Vec<FilePlanCandidate>,
) -> Result<MigrationPlan, CoreError> {
    let mut operations = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let decision = resolve_file_conflict(
            &candidate.desired_hash,
            &candidate.target,
            candidate.conflict_policy,
        );
        let preconditions = vec![PlanPrecondition {
            locator: candidate.target.locator,
            expected_hash: candidate.target.current_hash,
        }];
        let id_material = serde_json::to_vec(&(
            &candidate.asset_id,
            decision.kind,
            &decision.locator,
            &candidate.desired_hash,
        ))?;
        operations.push(PlanOperation {
            operation_id: sha256_id(&id_material),
            kind: decision.kind,
            phase: ApplyPhase::TransactionalCore,
            asset_id: candidate.asset_id,
            preconditions,
            effect: candidate.effect,
            verification: candidate.verification,
            rollback: RollbackGuarantee::Strong,
            approval: decision.approval,
        });
    }
    let mut plan = MigrationPlan {
        schema_version: "1.0".to_owned(),
        plan_id: String::new(),
        source_root_hash: source_root_hash.into(),
        target,
        adapter_version: adapter_version.into(),
        capability_snapshot_hash: capability_snapshot_hash.into(),
        operations,
    };
    plan.plan_id = sha256_id(&serde_json::to_vec(&plan)?);
    Ok(plan)
}

/// Resolve target roots using documented product discovery plus an explicit
/// workspace. No directory is created.
pub fn resolve_target_roots(
    target: Platform,
    workspace: &Path,
) -> Result<(ProductTuple, TargetRoots), CoreError> {
    let tuple = detect(Some(target))?
        .into_iter()
        .find(|candidate| candidate.config_root.is_some())
        .ok_or_else(|| {
            CoreError::InvalidBundle(format!("target {} root unavailable", target.as_str()))
        })?;
    let product_config = tuple
        .config_root
        .clone()
        .ok_or_else(|| CoreError::InvalidBundle("target config root unavailable".to_owned()))?;
    Ok((
        tuple,
        TargetRoots {
            product_config,
            user_home: user_home()?,
            workspace: workspace.to_path_buf(),
        },
    ))
}

/// Render and plan supported assets for an exact target tuple. Existing target
/// files are read only to establish preconditions and structured merges.
#[allow(clippy::too_many_lines)]
pub fn prepare_migration(
    target: ProductTuple,
    roots: &TargetRoots,
    assets: &[ExtractedAsset],
) -> Result<PreparedMigration, CoreError> {
    prepare_migration_with_managed(target, roots, assets, &BTreeMap::new())
}

/// Render and plan assets using durable ownership hashes from the target
/// ledger. Only an unchanged MnemoPort-managed target is eligible for an
/// automatic managed update.
#[allow(clippy::too_many_lines)]
pub fn prepare_migration_with_managed(
    target: ProductTuple,
    roots: &TargetRoots,
    assets: &[ExtractedAsset],
    managed_hashes: &BTreeMap<String, String>,
) -> Result<PreparedMigration, CoreError> {
    let mut prepared = BTreeMap::<PathBuf, PreparedFile>::new();
    let mut skipped = Vec::new();
    for asset in assets {
        if asset.asset.sensitivity == Sensitivity::Quarantined {
            skipped.push(SkippedAsset {
                asset_id: asset.asset.asset_id.clone(),
                locator: asset.asset.provenance.locator.clone(),
                reason: "quarantined active or non-text content requires explicit review"
                    .to_owned(),
            });
            continue;
        }
        let rendered = if asset.asset.kind == mnemo_schema::AssetKind::Mcp {
            render_mcp_asset(target.platform, asset, roots, &prepared)
        } else {
            render_core_asset(target.platform, asset)
        };
        let rendered = match rendered {
            Ok(files) => files,
            Err(error) => {
                skipped.push(SkippedAsset {
                    asset_id: asset.asset.asset_id.clone(),
                    locator: asset.asset.provenance.locator.clone(),
                    reason: error.to_string(),
                });
                continue;
            }
        };
        for file in rendered {
            let target_path = resolve_rendered_path(roots, &file);
            let desired_hash = sha256_id(&file.bytes);
            if let Some(existing) = prepared.get(&target_path) {
                if asset.asset.kind == mnemo_schema::AssetKind::Mcp {
                    let combined_id =
                        sha256_id(format!("{}\0{}", existing.asset_id, file.asset_id).as_bytes());
                    prepared.insert(
                        target_path.clone(),
                        PreparedFile {
                            asset_id: combined_id,
                            asset_kind: asset.asset.kind,
                            root: target_root_name(file.root).to_owned(),
                            relative_path: file.relative_path,
                            target_path,
                            desired_hash,
                            bytes: file.bytes,
                        },
                    );
                    continue;
                }
                if existing.bytes != file.bytes {
                    skipped.push(SkippedAsset {
                        asset_id: file.asset_id,
                        locator: file.relative_path,
                        reason: "multiple assets map to the same target; explicit merge required"
                            .to_owned(),
                    });
                }
                continue;
            }
            prepared.insert(
                target_path.clone(),
                PreparedFile {
                    asset_id: file.asset_id,
                    asset_kind: asset.asset.kind,
                    root: target_root_name(file.root).to_owned(),
                    relative_path: file.relative_path,
                    target_path,
                    desired_hash,
                    bytes: file.bytes,
                },
            );
        }
    }
    let files = prepared.into_values().collect::<Vec<_>>();
    let candidates = files
        .iter()
        .map(|file| {
            let current_hash = fs::read(&file.target_path)
                .ok()
                .map(|bytes| sha256_id(&bytes));
            FilePlanCandidate {
                asset_id: file.asset_id.clone(),
                desired_hash: file.desired_hash.clone(),
                effect: serde_json::json!({
                    "root": file.root,
                    "relative_path": file.relative_path,
                    "target_path": file.target_path,
                    "desired_hash": file.desired_hash,
                }),
                verification: serde_json::json!({
                    "level": "l0",
                    "sha256": file.desired_hash,
                }),
                target: TargetObservation {
                    locator: file.target_path.to_string_lossy().into_owned(),
                    current_hash,
                    managed_hash: managed_hashes
                        .get(&file.target_path.to_string_lossy().into_owned())
                        .cloned(),
                },
                conflict_policy: ConflictPolicy::Preserve,
            }
        })
        .collect();
    let source_material = assets
        .iter()
        .map(|asset| asset.asset.asset_id.as_str())
        .collect::<Vec<_>>()
        .join("\0");
    let capability_hash = sha256_id(&serde_json::to_vec(&target)?);
    let plan = build_file_plan(
        sha256_id(source_material.as_bytes()),
        target,
        env!("CARGO_PKG_VERSION"),
        capability_hash,
        candidates,
    )?;
    Ok(PreparedMigration {
        plan,
        files,
        skipped,
    })
}

fn render_core_asset(
    target: Platform,
    asset: &ExtractedAsset,
) -> Result<Vec<RenderedFile>, AdapterError> {
    match target {
        Platform::ClaudeCode => mnemo_adapter_claude_code::render_target(asset),
        Platform::Codex => mnemo_adapter_codex::render_target(asset),
        Platform::Qoder => mnemo_adapter_qoder::render_target(asset),
        Platform::Cursor => mnemo_adapter_cursor::render_target(asset),
    }
}

fn render_mcp_asset(
    target: Platform,
    asset: &ExtractedAsset,
    roots: &TargetRoots,
    prepared: &BTreeMap<PathBuf, PreparedFile>,
) -> Result<Vec<RenderedFile>, AdapterError> {
    let initial = match target {
        Platform::ClaudeCode => mnemo_adapter_claude_code::render_mcp_target(asset, None),
        Platform::Codex => mnemo_adapter_codex::render_mcp_target(asset, None),
        Platform::Qoder => mnemo_adapter_qoder::render_mcp_target(asset, None),
        Platform::Cursor => mnemo_adapter_cursor::render_mcp_target(asset, None),
    }?;
    let target_path = resolve_rendered_path(roots, &initial);
    let existing = prepared
        .get(&target_path)
        .map(|file| file.bytes.clone())
        .or_else(|| fs::read(&target_path).ok());
    let rendered = match target {
        Platform::ClaudeCode => {
            mnemo_adapter_claude_code::render_mcp_target(asset, existing.as_deref())
        }
        Platform::Codex => mnemo_adapter_codex::render_mcp_target(asset, existing.as_deref()),
        Platform::Qoder => mnemo_adapter_qoder::render_mcp_target(asset, existing.as_deref()),
        Platform::Cursor => mnemo_adapter_cursor::render_mcp_target(asset, existing.as_deref()),
    }?;
    Ok(vec![rendered])
}

fn resolve_rendered_path(roots: &TargetRoots, file: &RenderedFile) -> PathBuf {
    let root = match file.root {
        TargetRoot::ProductConfig => &roots.product_config,
        TargetRoot::UserHome => &roots.user_home,
        TargetRoot::Workspace => &roots.workspace,
    };
    root.join(&file.relative_path)
}

const fn target_root_name(root: TargetRoot) -> &'static str {
    match root {
        TargetRoot::ProductConfig => "product-config",
        TargetRoot::UserHome => "user-home",
        TargetRoot::Workspace => "workspace",
    }
}

fn side_by_side_locator(locator: &str, desired_hash: &str) -> String {
    let suffix = desired_hash
        .strip_prefix("sha256:")
        .unwrap_or(desired_hash)
        .chars()
        .take(8)
        .collect::<String>();
    if let Some((stem, extension)) = locator.rsplit_once('.') {
        format!("{stem}.mnemo-{suffix}.{extension}")
    } else {
        format!("{locator}.mnemo-{suffix}")
    }
}

/// Return all platform adapter instances.
#[must_use]
pub fn adapters() -> Vec<Box<dyn PlatformAdapter>> {
    vec![
        Box::new(ClaudeCodeAdapter),
        Box::new(CodexAdapter),
        Box::new(QoderAdapter),
        Box::new(CursorAdapter),
    ]
}

/// Detect all platforms, optionally filtering by platform id.
pub fn detect(platform: Option<Platform>) -> Result<Vec<ProductTuple>, CoreError> {
    let mut detections = Vec::new();
    for adapter in adapters() {
        if platform.is_none_or(|requested| requested == adapter.platform()) {
            detections.extend(adapter.detect()?);
        }
    }
    Ok(detections)
}

/// Run explicit version-level L1 probes for all matching entrypoints. Each
/// adapter owns its fixed command; asset bytes can never influence execution.
pub fn probe(platform: Option<Platform>) -> Result<Vec<ProductProbe>, CoreError> {
    let mut reports = Vec::new();
    for adapter in adapters() {
        if platform.is_none_or(|requested| requested == adapter.platform()) {
            reports.extend(adapter.probe()?);
        }
    }
    Ok(reports)
}

/// Run admitted asset-level L1 discovery recipes. Unsupported tuples are
/// returned as explicit manual/version-gated results and never fall back to
/// launching a model, MCP server, plugin, hook, or migrated script.
pub fn verify_asset_discovery(
    target: &ProductTuple,
    roots: &TargetRoots,
    assets: &[ExtractedAsset],
    prepared: &PreparedMigration,
) -> Result<Vec<AssetProbe>, CoreError> {
    let mut by_kind = BTreeMap::<AssetKind, BTreeSet<String>>::new();
    for file in &prepared.files {
        by_kind
            .entry(file.asset_kind)
            .or_default()
            .insert(file.asset_id.clone());
    }
    let version_probe = probe(Some(target.platform))?.into_iter().find(|report| {
        report.tuple.entrypoint == target.entrypoint
            && report.tuple.config_root == target.config_root
    });
    let tuple = version_probe
        .as_ref()
        .map_or_else(|| target.clone(), |report| report.tuple.clone());

    let mut reports = Vec::with_capacity(by_kind.len());
    for (asset_kind, asset_ids) in by_kind {
        let expected_assets = asset_ids.len();
        let unavailable = version_probe
            .as_ref()
            .is_none_or(|report| report.status == ProbeStatus::Unavailable);
        let version_failed = version_probe
            .as_ref()
            .is_some_and(|report| report.status != ProbeStatus::Verified);
        let report = match (tuple.platform, &tuple.entrypoint, asset_kind) {
            (Platform::Codex, Entrypoint::Cli, AssetKind::Mcp)
                if tuple.version.as_deref() == Some("0.144.1") && tuple.os == "linux" =>
            {
                verify_codex_mcp(&tuple, roots, assets, prepared)?
            }
            (Platform::Qoder, Entrypoint::Cli, AssetKind::Skill)
                if tuple.version.as_deref() == Some("1.1.42") && tuple.os == "linux" =>
            {
                verify_qoder_skills(&tuple, prepared)?
            }
            (Platform::Codex, _, AssetKind::Mcp) | (Platform::Qoder, _, AssetKind::Skill)
                if unavailable || version_failed || tuple.version.is_none() =>
            {
                asset_probe_result(
                    tuple.clone(),
                    asset_kind,
                    if unavailable {
                        AssetProbeStatus::Unavailable
                    } else {
                        AssetProbeStatus::UnsupportedVersion
                    },
                    AssetProbeMethod::None,
                    Vec::new(),
                    "asset_recipe_requires_an_exact_verified_tuple",
                    expected_assets,
                    0,
                    false,
                )
            }
            (Platform::Codex, _, AssetKind::Mcp) | (Platform::Qoder, _, AssetKind::Skill) => {
                asset_probe_result(
                    tuple.clone(),
                    asset_kind,
                    AssetProbeStatus::UnsupportedVersion,
                    AssetProbeMethod::None,
                    Vec::new(),
                    "asset_recipe_not_admitted_for_this_version_os_or_entrypoint",
                    expected_assets,
                    0,
                    false,
                )
            }
            _ => asset_probe_result(
                tuple.clone(),
                asset_kind,
                AssetProbeStatus::Manual,
                AssetProbeMethod::None,
                Vec::new(),
                "no_safe_authoritative_discovery_surface",
                expected_assets,
                0,
                false,
            ),
        };
        reports.push(report);
    }
    Ok(reports)
}

fn verify_codex_mcp(
    tuple: &ProductTuple,
    roots: &TargetRoots,
    assets: &[ExtractedAsset],
    prepared: &PreparedMigration,
) -> Result<AssetProbe, CoreError> {
    let expected = expected_codex_mcp_names(assets, prepared);
    let Some(executable) = tuple.executable.as_deref() else {
        return Ok(asset_probe_result(
            tuple.clone(),
            AssetKind::Mcp,
            AssetProbeStatus::Unavailable,
            AssetProbeMethod::None,
            Vec::new(),
            "executable_unavailable",
            expected.len(),
            0,
            false,
        ));
    };
    let scratch = tempfile::tempdir()?;
    let clone_config = scratch.path().join("codex-home");
    let clone_workspace = scratch.path().join("workspace");
    let clone_home = scratch.path().join("home");
    fs::create_dir_all(&clone_config)?;
    fs::create_dir_all(&clone_workspace)?;
    fs::create_dir_all(&clone_home)?;
    copy_if_present(
        &roots.product_config.join("config.toml"),
        &clone_config.join("config.toml"),
    )?;
    copy_if_present(
        &roots.workspace.join(".codex/config.toml"),
        &clone_workspace.join(".codex/config.toml"),
    )?;
    let arguments = ["mcp", "list", "--json"];
    let execution = run_fixed_vendor_command(
        executable,
        &arguments,
        &[
            ("HOME", clone_home.as_path()),
            ("USERPROFILE", clone_home.as_path()),
            ("CODEX_HOME", clone_config.as_path()),
        ],
        &clone_workspace,
        scratch.path(),
        Duration::from_secs(10),
    )?;
    let (status, discovered, diagnostic) = match execution {
        FixedCommandResult::Completed {
            success: true,
            output,
        } => match parse_codex_mcp_names(&output) {
            Some(names) => {
                let discovered = expected.intersection(&names).count();
                if discovered == expected.len() {
                    (
                        AssetProbeStatus::Verified,
                        discovered,
                        "all_assets_discovered",
                    )
                } else {
                    (
                        AssetProbeStatus::Failed,
                        discovered,
                        "expected_asset_not_discovered",
                    )
                }
            }
            None => (AssetProbeStatus::Failed, 0, "vendor_output_unrecognized"),
        },
        FixedCommandResult::Completed { success: false, .. } => {
            (AssetProbeStatus::Failed, 0, "vendor_list_command_failed")
        }
        FixedCommandResult::TimedOut => {
            (AssetProbeStatus::Failed, 0, "vendor_list_command_timed_out")
        }
        FixedCommandResult::OutputLimitExceeded => {
            (AssetProbeStatus::Failed, 0, "vendor_output_limit_exceeded")
        }
    };
    Ok(asset_probe_result(
        tuple.clone(),
        AssetKind::Mcp,
        status,
        AssetProbeMethod::VendorListCommand,
        arguments.iter().map(ToString::to_string).collect(),
        diagnostic,
        expected.len(),
        discovered,
        true,
    ))
}

fn expected_codex_mcp_names(
    assets: &[ExtractedAsset],
    prepared: &PreparedMigration,
) -> BTreeSet<String> {
    let migrated_ids = prepared
        .files
        .iter()
        .filter(|file| file.asset_kind == AssetKind::Mcp)
        .map(|file| file.asset_id.as_str())
        .collect::<BTreeSet<_>>();
    assets
        .iter()
        .filter_map(|asset| match &asset.asset.payload {
            AssetPayload::McpServer(server)
                if asset.asset.sensitivity != Sensitivity::Quarantined
                    && migrated_ids.contains(asset.asset.asset_id.as_str()) =>
            {
                Some(server.name.clone())
            }
            _ => None,
        })
        .collect()
}

fn copy_if_present(source: &Path, destination: &Path) -> Result<(), CoreError> {
    match fs::read(source) {
        Ok(bytes) => {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(destination, bytes)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn verify_qoder_skills(
    tuple: &ProductTuple,
    prepared: &PreparedMigration,
) -> Result<AssetProbe, CoreError> {
    let Some(executable) = tuple.executable.as_deref() else {
        return Ok(asset_probe_result(
            tuple.clone(),
            AssetKind::Skill,
            AssetProbeStatus::Unavailable,
            AssetProbeMethod::None,
            Vec::new(),
            "executable_unavailable",
            0,
            0,
            true,
        ));
    };
    let scratch = tempfile::tempdir()?;
    let clone_config = scratch.path().join("qoder-config");
    let clone_workspace = scratch.path().join("workspace");
    let clone_home = scratch.path().join("home");
    fs::create_dir_all(&clone_config)?;
    fs::create_dir_all(&clone_workspace)?;
    fs::create_dir_all(&clone_home)?;
    let mut expected = BTreeSet::new();
    for file in prepared.files.iter().filter(|file| {
        file.asset_kind == AssetKind::Skill && file.relative_path.ends_with("SKILL.md")
    }) {
        let destination = match file.root.as_str() {
            "product-config" => clone_config.join(&file.relative_path),
            "workspace" => clone_workspace.join(&file.relative_path),
            _ => continue,
        };
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
            if let Some(name) = parent.file_name().and_then(|name| name.to_str()) {
                expected.insert(name.to_owned());
            }
        }
        fs::write(destination, fs::read(&file.target_path)?)?;
    }
    let arguments = ["skills", "list", "--all"];
    let execution = run_fixed_vendor_command(
        executable,
        &arguments,
        &[
            ("HOME", clone_home.as_path()),
            ("USERPROFILE", clone_home.as_path()),
            ("QODER_CONFIG_DIR", clone_config.as_path()),
        ],
        &clone_workspace,
        scratch.path(),
        Duration::from_secs(20),
    )?;
    let (status, discovered, diagnostic) = match execution {
        FixedCommandResult::Completed {
            success: true,
            output,
        } => {
            let discovered = parse_qoder_skill_names(&output, scratch.path(), &expected);
            if discovered == expected.len() {
                (
                    AssetProbeStatus::Verified,
                    discovered,
                    "all_assets_discovered",
                )
            } else {
                (
                    AssetProbeStatus::Failed,
                    discovered,
                    "expected_asset_not_discovered",
                )
            }
        }
        FixedCommandResult::Completed { success: false, .. } => {
            (AssetProbeStatus::Failed, 0, "vendor_list_command_failed")
        }
        FixedCommandResult::TimedOut => {
            (AssetProbeStatus::Failed, 0, "vendor_list_command_timed_out")
        }
        FixedCommandResult::OutputLimitExceeded => {
            (AssetProbeStatus::Failed, 0, "vendor_output_limit_exceeded")
        }
    };
    Ok(asset_probe_result(
        tuple.clone(),
        AssetKind::Skill,
        status,
        AssetProbeMethod::VendorListCommand,
        arguments.iter().map(ToString::to_string).collect(),
        diagnostic,
        expected.len(),
        discovered,
        true,
    ))
}

#[allow(clippy::too_many_arguments)]
fn asset_probe_result(
    tuple: ProductTuple,
    asset_kind: AssetKind,
    status: AssetProbeStatus,
    method: AssetProbeMethod,
    arguments: Vec<String>,
    diagnostic: &str,
    expected_assets: usize,
    discovered_assets: usize,
    isolated_copy: bool,
) -> AssetProbe {
    AssetProbe {
        tuple,
        asset_kind,
        status,
        method,
        arguments,
        diagnostic: diagnostic.to_owned(),
        expected_assets,
        discovered_assets,
        isolated_copy,
        migrated_components_started: false,
    }
}

#[derive(Debug)]
enum FixedCommandResult {
    Completed { success: bool, output: Vec<u8> },
    TimedOut,
    OutputLimitExceeded,
}

const VENDOR_OUTPUT_LIMIT: u64 = 64 * 1024;

fn run_fixed_vendor_command(
    executable: &Path,
    arguments: &[&str],
    product_environment: &[(&str, &Path)],
    working_directory: &Path,
    scratch: &Path,
    timeout: Duration,
) -> Result<FixedCommandResult, CoreError> {
    let stdout_path = scratch.join("vendor-stdout");
    let stderr_path = scratch.join("vendor-stderr");
    let stdout = File::create(&stdout_path)?;
    let stderr = File::create(&stderr_path)?;
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .current_dir(working_directory)
        .env_clear()
        .env("XDG_CONFIG_HOME", scratch.join("xdg-config"))
        .env("XDG_CACHE_HOME", scratch.join("xdg-cache"))
        .env("XDG_DATA_HOME", scratch.join("xdg-data"))
        .env("APPDATA", scratch.join("appdata"))
        .env("LOCALAPPDATA", scratch.join("local-appdata"))
        .env("TMP", scratch)
        .env("TEMP", scratch)
        .env("TMPDIR", scratch)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for (name, path) in product_environment {
        command.env(name, path);
    }
    for name in ["PATH", "SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if vendor_output_size(&stdout_path, &stderr_path)? > VENDOR_OUTPUT_LIMIT {
            child.kill()?;
            let _ = child.wait();
            return Ok(FixedCommandResult::OutputLimitExceeded);
        }
        match child.try_wait()? {
            Some(status) => {
                if vendor_output_size(&stdout_path, &stderr_path)? > VENDOR_OUTPUT_LIMIT {
                    return Ok(FixedCommandResult::OutputLimitExceeded);
                }
                let output = read_bounded_output(&stdout_path, VENDOR_OUTPUT_LIMIT)?;
                return Ok(FixedCommandResult::Completed {
                    success: status.success(),
                    output,
                });
            }
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            None => {
                child.kill()?;
                let _ = child.wait();
                return Ok(FixedCommandResult::TimedOut);
            }
        }
    }
}

fn vendor_output_size(stdout: &Path, stderr: &Path) -> std::io::Result<u64> {
    Ok(fs::metadata(stdout)?
        .len()
        .saturating_add(fs::metadata(stderr)?.len()))
}

fn read_bounded_output(stdout: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    File::open(stdout)?.take(limit).read_to_end(&mut output)?;
    Ok(output)
}

fn parse_codex_mcp_names(output: &[u8]) -> Option<BTreeSet<String>> {
    serde_json::from_slice::<Value>(output)
        .ok()?
        .as_array()?
        .iter()
        .map(|item| item.get("name")?.as_str().map(ToOwned::to_owned))
        .collect()
}

fn parse_qoder_skill_names(output: &[u8], scratch: &Path, expected: &BTreeSet<String>) -> usize {
    let text = String::from_utf8_lossy(output);
    let lines = text.lines().collect::<Vec<_>>();
    expected
        .iter()
        .filter(|name| {
            lines.iter().enumerate().any(|(index, line)| {
                line.trim_start()
                    .strip_prefix(name.as_str())
                    .is_some_and(|suffix| suffix.starts_with(" ["))
                    && lines.iter().skip(index + 1).take(5).any(|detail| {
                        detail
                            .trim_start()
                            .strip_prefix("Location:")
                            .is_some_and(|path| Path::new(path.trim()).starts_with(scratch))
                    })
            })
        })
        .count()
}

/// Inventory one platform without extracting asset bodies.
pub fn inventory(
    platform: Platform,
    mode: CollectionMode,
) -> Result<Vec<InventoryItem>, CoreError> {
    let adapter = adapters()
        .into_iter()
        .find(|candidate| candidate.platform() == platform)
        .ok_or_else(|| {
            CoreError::InvalidBundle(format!("adapter missing for {}", platform.as_str()))
        })?;
    Ok(adapter.inventory(mode)?)
}

/// Extract canonical assets from one platform.
pub fn extract(platform: Platform, mode: CollectionMode) -> Result<Vec<ExtractedAsset>, CoreError> {
    let adapter = adapters()
        .into_iter()
        .find(|candidate| candidate.platform() == platform)
        .ok_or_else(|| {
            CoreError::InvalidBundle(format!("adapter missing for {}", platform.as_str()))
        })?;
    Ok(adapter.extract(mode)?)
}

/// Encode extracted canonical assets and their referenced blobs into a signed
/// deterministic package.
pub fn package_assets(
    assets: &[ExtractedAsset],
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<SignedPackage, CoreError> {
    let mut builder = PackageBuilder::new();
    let mut blobs = BTreeMap::<String, Vec<u8>>::new();
    for extracted in assets {
        validate_extracted_asset(extracted)?;
        builder.insert(
            format!("assets/{}.json", extracted.asset.asset_id),
            serde_json::to_vec(&extracted.asset)?,
        )?;
        for (hash, bytes) in &extracted.objects {
            if sha256_id(bytes) != *hash {
                return Err(CoreError::InvalidBundle(format!(
                    "object {hash} does not match its bytes"
                )));
            }
            if let Some(existing) = blobs.insert(hash.clone(), bytes.clone()) {
                if existing != *bytes {
                    return Err(CoreError::InvalidBundle(format!(
                        "hash collision for {hash}"
                    )));
                }
            }
        }
    }
    for (hash, bytes) in blobs {
        let digest = hash
            .strip_prefix("sha256:")
            .ok_or_else(|| CoreError::InvalidBundle(format!("unsupported object hash {hash}")))?;
        builder.insert(format!("blobs/sha256/{digest}"), bytes)?;
    }
    Ok(builder.build(signing_key)?)
}

/// Reconstruct canonical assets after package signature and object verification.
pub fn unpack_assets(package: &VerifiedPackage) -> Result<Vec<ExtractedAsset>, CoreError> {
    let mut blobs = BTreeMap::new();
    for (path, bytes) in &package.objects {
        if let Some(digest) = path.strip_prefix("blobs/sha256/") {
            let hash = format!("sha256:{digest}");
            if sha256_id(bytes) != hash {
                return Err(CoreError::InvalidBundle(format!(
                    "blob path digest mismatch: {path}"
                )));
            }
            blobs.insert(hash, bytes.clone());
        }
    }
    let mut assets = Vec::new();
    for (path, bytes) in &package.objects {
        let Some(_encoded_asset_id) = path
            .strip_prefix("assets/")
            .and_then(|value| value.strip_suffix(".json"))
        else {
            continue;
        };
        let asset: mnemo_schema::CanonicalAsset = serde_json::from_slice(bytes)?;
        let expected_path = format!("assets/{}.json", asset.asset_id);
        if *path != expected_path {
            return Err(CoreError::InvalidBundle(format!(
                "asset id/path mismatch: {path}"
            )));
        }
        let required = referenced_hashes(&asset.payload);
        let mut objects = BTreeMap::new();
        for hash in required {
            let bytes = blobs.get(&hash).ok_or_else(|| {
                CoreError::InvalidBundle(format!("asset {} misses blob {hash}", asset.asset_id))
            })?;
            objects.insert(hash, bytes.clone());
        }
        let extracted = ExtractedAsset { asset, objects };
        validate_extracted_asset(&extracted)?;
        assets.push(extracted);
    }
    assets.sort_by(|left, right| left.asset.asset_id.cmp(&right.asset.asset_id));
    Ok(assets)
}

fn referenced_hashes(payload: &mnemo_schema::AssetPayload) -> Vec<String> {
    match payload {
        mnemo_schema::AssetPayload::Text(text) => vec![sha256_id(text.as_bytes())],
        mnemo_schema::AssetPayload::FileTree(files) => files.values().cloned().collect(),
        _ => Vec::new(),
    }
}

fn validate_extracted_asset(extracted: &ExtractedAsset) -> Result<(), CoreError> {
    let asset = &extracted.asset;
    if asset.schema_version != "1.0" {
        return Err(CoreError::InvalidBundle(format!(
            "unsupported asset schema {}",
            asset.schema_version
        )));
    }
    validate_portable_path(&asset.provenance.locator)
        .map_err(|error| CoreError::InvalidBundle(error.to_string()))?;
    validate_kind_payload(asset.kind, &asset.payload)?;

    let content_hash = canonical_content_hash(&asset.payload)?;
    if content_hash != asset.content_hash {
        return Err(CoreError::InvalidBundle(format!(
            "asset {} content hash mismatch",
            asset.asset_id
        )));
    }
    let reconstructed = make_asset(CanonicalAssetInput {
        platform: asset.provenance.platform,
        kind: asset.kind,
        scope: asset.scope,
        title: asset.title.clone(),
        locator: asset.provenance.locator.clone(),
        payload: asset.payload.clone(),
        source_hash: asset.provenance.source_hash.clone(),
        content_hash,
        sensitivity: asset.sensitivity,
    })?;
    if reconstructed.asset_id != asset.asset_id {
        return Err(CoreError::InvalidBundle(format!(
            "asset {} identity mismatch",
            asset.asset_id
        )));
    }

    validate_object_closure(extracted)?;
    let payload_bytes = serde_json::to_vec(&asset.payload)?;
    let scanned = scan_and_redact(&asset.provenance.locator, &payload_bytes)
        .map_err(|error| CoreError::InvalidBundle(error.to_string()))?;
    if scanned
        .report
        .findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Secret)
    {
        return Err(CoreError::InvalidBundle(format!(
            "asset {} canonical payload contains credential-like content",
            asset.asset_id
        )));
    }
    Ok(())
}

fn validate_object_closure(extracted: &ExtractedAsset) -> Result<(), CoreError> {
    let asset = &extracted.asset;
    let required = referenced_hashes(&asset.payload)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let actual = extracted
        .objects
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if required != actual {
        return Err(CoreError::InvalidBundle(format!(
            "asset {} object closure mismatch",
            asset.asset_id
        )));
    }
    for (path, hash) in file_tree_entries(&asset.payload) {
        validate_portable_path(path)
            .map_err(|error| CoreError::InvalidBundle(error.to_string()))?;
        if !is_sha256_id(hash) {
            return Err(CoreError::InvalidBundle(format!(
                "asset {} has an invalid object digest",
                asset.asset_id
            )));
        }
    }
    for (hash, bytes) in &extracted.objects {
        validate_object_bytes(asset, hash, bytes)?;
    }
    Ok(())
}

fn validate_object_bytes(
    asset: &mnemo_schema::CanonicalAsset,
    hash: &str,
    bytes: &[u8],
) -> Result<(), CoreError> {
    if sha256_id(bytes) != hash {
        return Err(CoreError::InvalidBundle(format!(
            "asset {} object digest mismatch",
            asset.asset_id
        )));
    }
    match scan_and_redact(&asset.provenance.locator, bytes) {
        Ok(scanned) => {
            if scanned
                .report
                .findings
                .iter()
                .any(|finding| finding.severity == FindingSeverity::Secret)
            {
                return Err(CoreError::InvalidBundle(format!(
                    "asset {} contains credential-like content",
                    asset.asset_id
                )));
            }
            if scanned.report.quarantined && asset.sensitivity != Sensitivity::Quarantined {
                return Err(CoreError::InvalidBundle(format!(
                    "asset {} contains unclassified active content",
                    asset.asset_id
                )));
            }
        }
        Err(mnemo_security::SecurityError::NonUtf8(_)) => {
            if asset.sensitivity != Sensitivity::Quarantined {
                return Err(CoreError::InvalidBundle(format!(
                    "asset {} contains unclassified non-text content",
                    asset.asset_id
                )));
            }
        }
        Err(error) => return Err(CoreError::InvalidBundle(error.to_string())),
    }
    Ok(())
}

fn canonical_content_hash(payload: &AssetPayload) -> Result<String, CoreError> {
    Ok(match payload {
        AssetPayload::Text(text) => sha256_id(text.as_bytes()),
        _ => sha256_id(&serde_json::to_vec(payload)?),
    })
}

fn validate_kind_payload(kind: AssetKind, payload: &AssetPayload) -> Result<(), CoreError> {
    let valid = matches!(
        (kind, payload),
        (
            AssetKind::Instruction | AssetKind::Prompt | AssetKind::Preference | AssetKind::Memory,
            AssetPayload::Text(_)
        ) | (AssetKind::Skill, AssetPayload::FileTree(_))
            | (AssetKind::Mcp, AssetPayload::McpServer(_))
            | (AssetKind::Plugin, AssetPayload::PluginIntent { .. })
            | (AssetKind::Handoff, AssetPayload::Handoff(_))
            | (AssetKind::InventoryOnly, AssetPayload::Inventory(_))
    );
    if valid {
        Ok(())
    } else {
        Err(CoreError::InvalidBundle(format!(
            "asset kind {kind:?} does not match its payload"
        )))
    }
}

fn file_tree_entries(payload: &AssetPayload) -> impl Iterator<Item = (&str, &str)> {
    match payload {
        AssetPayload::FileTree(files) => Some(files.iter()),
        _ => None,
    }
    .into_iter()
    .flatten()
    .map(|(path, hash)| (path.as_str(), hash.as_str()))
}

fn is_sha256_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Run read-only diagnostics.
pub fn doctor() -> Result<DoctorReport, CoreError> {
    let state_paths = resolve_state_paths();
    let recovery_candidates = if let Some(paths) = state_paths.as_ref() {
        let ledger_path = paths.data.join("ledger.sqlite");
        let ledger = ledger_path
            .exists()
            .then(|| Ledger::open_read_only(&ledger_path))
            .transpose()?;
        scan_recovery_candidates_with_ledger(&paths.transactions, ledger.as_ref())?
    } else {
        Vec::new()
    };
    Ok(DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        state_paths,
        detections: detect(None)?,
        recovery_candidates,
    })
}

/// Return a log-safe device signer fingerprint.
#[must_use]
pub fn signer_fingerprint(public_key_hex: &str) -> String {
    sha256_id(public_key_hex.as_bytes())
}

/// Convert a user-selected continuation capsule into a portable Handoff asset.
pub fn create_handoff(capsule: &mnemo_schema::HandoffCapsule) -> Result<ExtractedAsset, CoreError> {
    if capsule.goal.trim().is_empty() {
        return Err(CoreError::InvalidBundle(
            "handoff goal must not be empty".to_owned(),
        ));
    }
    if capsule.schema_version != "1.0" {
        return Err(CoreError::InvalidBundle(format!(
            "unsupported handoff schema {}",
            capsule.schema_version
        )));
    }
    let value = serde_json::to_value(capsule)?;
    let payload = mnemo_schema::AssetPayload::Handoff(value);
    let content_hash = canonical_content_hash(&payload)?;
    let asset = make_asset(CanonicalAssetInput {
        platform: capsule.source,
        kind: mnemo_schema::AssetKind::Handoff,
        scope: mnemo_schema::ScopeLevel::Workspace,
        title: "handoff".to_owned(),
        locator: "handoff/capsule.json".to_owned(),
        payload,
        source_hash: content_hash.clone(),
        content_hash,
        sensitivity: mnemo_schema::Sensitivity::Private,
    })?;
    let extracted = ExtractedAsset {
        asset,
        objects: BTreeMap::new(),
    };
    validate_extracted_asset(&extracted)?;
    Ok(extracted)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use mnemo_adapter_common::{CollectionMode, TargetRoot};
    use mnemo_schema::{Entrypoint, EvidenceLevel, PlanOperationKind, Platform, ProductTuple};
    use std::collections::BTreeSet;

    #[test]
    fn registry_has_all_four_platforms() {
        let platforms: Vec<_> = super::adapters()
            .into_iter()
            .map(|adapter| adapter.platform())
            .collect();
        assert_eq!(platforms, mnemo_schema::Platform::all());
    }

    fn target() -> ProductTuple {
        ProductTuple {
            platform: Platform::Codex,
            version: Some("test".to_owned()),
            os: "linux".to_owned(),
            entrypoint: Entrypoint::Cli,
            executable: None,
            config_root: None,
            evidence: EvidenceLevel::Observed,
        }
    }

    #[test]
    fn plan_is_deterministic_and_noops_converged_target() -> Result<(), Box<dyn std::error::Error>>
    {
        let candidate = super::FilePlanCandidate {
            asset_id: "sha256:asset".to_owned(),
            desired_hash: "sha256:same".to_owned(),
            effect: serde_json::json!({"locator": "AGENTS.md"}),
            verification: serde_json::json!({"parse": "markdown"}),
            target: super::TargetObservation {
                locator: "AGENTS.md".to_owned(),
                current_hash: Some("sha256:same".to_owned()),
                managed_hash: None,
            },
            conflict_policy: super::ConflictPolicy::Preserve,
        };
        let first = super::build_file_plan(
            "sha256:root",
            target(),
            "0.1.0",
            "sha256:caps",
            vec![candidate.clone()],
        )?;
        let second = super::build_file_plan(
            "sha256:root",
            target(),
            "0.1.0",
            "sha256:caps",
            vec![candidate],
        )?;
        assert_eq!(first, second);
        assert_eq!(first.operations[0].kind, PlanOperationKind::Noop);
        Ok(())
    }

    #[test]
    fn preserves_user_file_or_uses_deterministic_sibling() {
        let observation = super::TargetObservation {
            locator: "rules.md".to_owned(),
            current_hash: Some("sha256:user".to_owned()),
            managed_hash: None,
        };
        let preserved = super::resolve_file_conflict(
            "sha256:1234567890",
            &observation,
            super::ConflictPolicy::Preserve,
        );
        assert_eq!(preserved.kind, PlanOperationKind::ManualStep);
        let sibling = super::resolve_file_conflict(
            "sha256:1234567890",
            &observation,
            super::ConflictPolicy::SideBySide,
        );
        assert_eq!(sibling.locator, "rules.mnemo-12345678.md");
    }

    #[test]
    fn managed_target_is_eligible_for_an_update() {
        let observation = super::TargetObservation {
            locator: "rules.md".to_owned(),
            current_hash: Some("sha256:managed".to_owned()),
            managed_hash: Some("sha256:managed".to_owned()),
        };
        let decision = super::resolve_file_conflict(
            "sha256:new",
            &observation,
            super::ConflictPolicy::Preserve,
        );
        assert_eq!(decision.kind, PlanOperationKind::WriteFile);
        assert_eq!(decision.reason, "managed_update");
    }

    #[test]
    fn codex_mcp_parser_is_structured_and_rejects_text_fallback() {
        let parsed = super::parse_codex_mcp_names(
            br#"[{"name":"first","enabled":false},{"name":"second"}]"#,
        )
        .unwrap_or_default();
        assert_eq!(
            parsed,
            BTreeSet::from(["first".to_owned(), "second".to_owned()])
        );
        assert!(super::parse_codex_mcp_names(b"first enabled").is_none());
        assert!(super::parse_codex_mcp_names(br#"[{"enabled":true}]"#).is_none());
    }

    #[test]
    fn qoder_skill_parser_requires_a_vendor_location_inside_the_clone() {
        let scratch = std::path::Path::new("/tmp/mnemoport-fixture");
        let expected = BTreeSet::from(["review".to_owned()]);
        let accepted = b"review [Enabled]\n  Description: review\n  Location: /tmp/mnemoport-fixture/qoder-config/skills/review/SKILL.md\n";
        assert_eq!(
            super::parse_qoder_skill_names(accepted, scratch, &expected),
            1
        );
        let directory_only = b"review [Enabled]\n  Description: review\n  Location: /home/user/.qoder/skills/review/SKILL.md\n";
        assert_eq!(
            super::parse_qoder_skill_names(directory_only, scratch, &expected),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn fixed_vendor_command_stops_when_output_exceeds_the_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = tempfile::tempdir()?;
        let result = super::run_fixed_vendor_command(
            std::path::Path::new("/bin/sh"),
            &["-c", "printf '%070000d' 0"],
            &[],
            scratch.path(),
            scratch.path(),
            std::time::Duration::from_secs(2),
        )?;
        assert!(matches!(
            result,
            super::FixedCommandResult::OutputLimitExceeded
        ));
        Ok(())
    }

    #[test]
    fn claude_assets_survive_package_and_render_for_codex() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        // macOS exposes its temporary directory through `/var`, which is a
        // system symlink to `/private/var`. Resolve that trusted test root once
        // so the transaction layer can keep rejecting symlink ancestors.
        let temp_root = temp.path().canonicalize()?;
        let source_config = temp_root.join("claude-home");
        let source_repo = temp_root.join("source-repo");
        std::fs::create_dir_all(source_config.as_path())?;
        std::fs::create_dir_all(source_repo.join(".claude/skills/review"))?;
        std::fs::write(source_repo.join("CLAUDE.md"), "Keep public APIs stable.\n")?;
        std::fs::write(
            source_repo.join(".claude/skills/review/SKILL.md"),
            "# Review\nCheck compatibility.\n",
        )?;

        let source = mnemo_adapter_claude_code::collect_from_roots(
            &source_config,
            &source_repo,
            CollectionMode::OfflineStatic,
        )?;
        let signed = super::package_assets(&source.extracted, &SigningKey::from_bytes(&[3; 32]))?;
        let verified = mnemo_package::verify(&signed.bytes)?;
        let transported = super::unpack_assets(&verified)?;
        assert_eq!(transported.len(), 2);

        let target_home = temp_root.join("target-home");
        let target_config = temp_root.join("target-codex");
        let target_repo = temp_root.join("target-repo");
        std::fs::create_dir_all(&target_repo)?;
        for asset in &transported {
            for rendered in mnemo_adapter_codex::render_target(asset)? {
                let root = match rendered.root {
                    TargetRoot::ProductConfig => &target_config,
                    TargetRoot::UserHome => &target_home,
                    TargetRoot::Workspace => &target_repo,
                };
                let target = root.join(rendered.relative_path);
                let mut journal = mnemo_store::apply_file(
                    &target,
                    &rendered.bytes,
                    &temp_root.join("transactions"),
                    None,
                )?;
                assert_eq!(std::fs::read(&target)?, rendered.bytes);
                mnemo_store::undo_file(&mut journal, false)?;
                assert!(!target.exists());
            }
        }
        Ok(())
    }

    #[test]
    fn rejects_handoff_with_credential_like_content() {
        let credential = ["sk", "abcdefghijklmnopqrstuvwxyz123456"].join("-");
        let capsule = mnemo_schema::HandoffCapsule {
            schema_version: "1.0".to_owned(),
            source: Platform::Codex,
            goal: "Continue safely".to_owned(),
            latest_request: Some(format!("Use {credential}")),
            constraints: Vec::new(),
            decisions: Vec::new(),
            completed: Vec::new(),
            pending: Vec::new(),
            workspace: None,
            git_head: None,
            git_dirty: None,
            validation: Vec::new(),
            risks: Vec::new(),
        };
        assert!(super::create_handoff(&capsule).is_err());
    }

    #[test]
    fn rejects_inconsistent_canonical_asset_before_packaging()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        std::fs::write(temp.path().join("AGENTS.md"), "Keep it deterministic.\n")?;
        let mut extracted = mnemo_adapter_qoder::collect_from_roots(
            &temp.path().join("qoder-home"),
            temp.path(),
            CollectionMode::OfflineStatic,
        )?
        .extracted;
        extracted[0].asset.content_hash = "sha256:tampered".to_owned();
        assert!(super::package_assets(&extracted, &SigningKey::from_bytes(&[9; 32])).is_err());
        Ok(())
    }

    #[test]
    fn quarantined_skill_is_packaged_but_never_auto_planned()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        let skill = source.join(".qoder/skills/active");
        std::fs::create_dir_all(&skill)?;
        std::fs::write(skill.join("SKILL.md"), "# Active\n")?;
        std::fs::write(skill.join("run.sh"), "#!/bin/sh\necho marker\n")?;
        let extracted = mnemo_adapter_qoder::collect_from_roots(
            &temp.path().join("qoder-home"),
            &source,
            CollectionMode::OfflineStatic,
        )?
        .extracted;
        assert_eq!(
            extracted[0].asset.sensitivity,
            mnemo_schema::Sensitivity::Quarantined
        );
        let signed = super::package_assets(&extracted, &SigningKey::from_bytes(&[10; 32]))?;
        let transported = super::unpack_assets(&mnemo_package::verify(&signed.bytes)?)?;
        let target_repo = temp.path().join("target");
        std::fs::create_dir_all(&target_repo)?;
        let prepared = super::prepare_migration(
            target(),
            &super::TargetRoots {
                product_config: temp.path().join("codex-home"),
                user_home: temp.path().join("user-home"),
                workspace: target_repo,
            },
            &transported,
        )?;
        assert!(prepared.files.is_empty());
        assert_eq!(prepared.skipped.len(), 1);
        assert!(prepared.skipped[0].reason.contains("quarantined"));
        Ok(())
    }
}
