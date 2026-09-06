//! Versioned data contracts shared by the CLI, adapters, package, and reports.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

/// Current machine-readable command response schema.
pub const COMMAND_SCHEMA_VERSION: &str = "1.0";

/// Supported AI products in MnemoPort v0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Anthropic Claude Code.
    ClaudeCode,
    /// OpenAI Codex.
    Codex,
    /// Alibaba Qoder.
    Qoder,
    /// Cursor IDE and Agent.
    Cursor,
}

impl Platform {
    /// Stable CLI identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Qoder => "qoder",
            Self::Cursor => "cursor",
        }
    }

    /// All platforms supported by the v0.1 schema.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::ClaudeCode, Self::Codex, Self::Qoder, Self::Cursor]
    }
}

impl std::str::FromStr for Platform {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "claude" | "claude-code" => Ok(Self::ClaudeCode),
            "codex" => Ok(Self::Codex),
            "qoder" => Ok(Self::Qoder),
            "cursor" | "cursor-agent" => Ok(Self::Cursor),
            other => Err(format!("unsupported platform: {other}")),
        }
    }
}

/// Product entrypoint; capabilities are never inferred across entrypoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Entrypoint {
    /// Terminal CLI.
    Cli,
    /// Standalone desktop application.
    DesktopApp,
    /// IDE/editor extension.
    IdeEditor,
    /// JetBrains plugin.
    Jetbrains,
    /// Cursor Agent CLI.
    Agent,
    /// Unknown or not yet classified entrypoint.
    Unknown,
}

/// Evidence grade behind a capability claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// Current official documentation.
    Documented,
    /// Reproduced with an isolated local fixture.
    Observed,
    /// Detected at runtime but not part of a stable contract.
    Probe,
    /// Must be handled through an official product interface.
    OfficialInterface,
    /// Explicitly excluded from migration.
    Excluded,
}

/// A precise product tuple detected on a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductTuple {
    /// Product identifier.
    pub platform: Platform,
    /// Version reported by an approved probe, if available.
    pub version: Option<String>,
    /// OS identifier.
    pub os: String,
    /// Product entrypoint.
    pub entrypoint: Entrypoint,
    /// Executable used by this entrypoint, if found.
    pub executable: Option<PathBuf>,
    /// Resolved configuration root, if known.
    pub config_root: Option<PathBuf>,
    /// Evidence supporting the tuple.
    pub evidence: EvidenceLevel,
}

/// Terminal state of an explicit local product probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// The approved probe returned a recognized product version.
    Verified,
    /// No executable is installed for this tuple.
    Unavailable,
    /// MnemoPort will not execute this entrypoint automatically.
    UnsupportedEntrypoint,
    /// The executable could not be started or returned unusable output.
    Failed,
    /// The executable exceeded the fixed local timeout and was terminated.
    TimedOut,
}

/// Mechanism used by a local product probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    /// No command was run.
    None,
    /// The adapter-approved product `--version` command was run.
    VersionCommand,
}

/// Version-level L1 evidence for one exact product entrypoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductProbe {
    /// Exact product tuple, with version populated only after a verified probe.
    pub tuple: ProductTuple,
    /// Probe outcome.
    pub status: ProbeStatus,
    /// Probe mechanism.
    pub method: ProbeMethod,
    /// Fixed adapter-owned arguments; asset content never contributes here.
    pub arguments: Vec<String>,
    /// Stable diagnostic code without captured product output.
    pub diagnostic: String,
    /// Whether a disposable home directory was used.
    pub isolated_home: bool,
    /// Always false for L1; migrated components are never initialized.
    pub migrated_components_started: bool,
}

/// Canonical asset kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    /// Persistent instructions and rules.
    Instruction,
    /// Reusable Skill directory.
    Skill,
    /// MCP server definition.
    Mcp,
    /// Prompt or slash command.
    Prompt,
    /// Portable user preference.
    Preference,
    /// Long-term or project memory.
    Memory,
    /// Plugin, extension, connector, or marketplace intent.
    Plugin,
    /// Current-work continuation capsule.
    Handoff,
    /// Agent, hook, workflow, or other inventory-only asset.
    InventoryOnly,
}

/// Logical scope of an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLevel {
    /// Organization-managed scope.
    Organization,
    /// User-wide scope.
    User,
    /// Device-local scope.
    Device,
    /// Workspace/repository scope.
    Workspace,
    /// Project scope.
    Project,
    /// Session-only scope.
    Session,
}

/// How an asset maps to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Same stable format and semantics.
    Exact,
    /// Converted to a target representation.
    Transformed,
    /// Reinstalled from a trusted source.
    Reinstall,
    /// Requires a human step.
    Manual,
    /// Intentionally skipped.
    Skipped,
    /// Target cannot express it.
    Unsupported,
    /// Forbidden by policy.
    Excluded,
}

/// Execution stage of an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Found at source.
    Discovered,
    /// Included in an immutable plan.
    Planned,
    /// Target mutation completed.
    Applied,
    /// Target discovery/behavior verified.
    Verified,
    /// Operation failed.
    Failed,
    /// Prior mutation was rolled back.
    RolledBack,
}

/// Whether the migrated item is usable now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    /// Ready for use.
    Ready,
    /// Runtime or file dependency is absent.
    DependencyMissing,
    /// Target-side authentication is required.
    ReauthRequired,
    /// An explicit user action remains.
    UserActionRequired,
    /// Organization policy prevents activation.
    ManagedPolicyBlocked,
}

/// Confidence in a platform compatibility statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityConfidence {
    /// Backed by documentation and an observed fixture.
    Confirmed,
    /// Safe only for an explicit version tuple.
    VersionGated,
    /// Inferred and not eligible for stable support.
    Inferred,
}

/// Strength of rollback available for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackGuarantee {
    /// Byte-for-byte restoration for managed local files.
    Strong,
    /// Best-effort inverse action for external systems.
    Compensating,
    /// No reliable inverse exists.
    None,
}

/// Sensitivity classification carried through extraction and planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Safe to disclose in normal reports.
    Public,
    /// User-authored content that should remain private by default.
    Private,
    /// A reference to a secret that must be rehydrated, never secret bytes.
    SecretReference,
    /// Executable or active content held for explicit review.
    Quarantined,
}

/// Source evidence for a canonical asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetProvenance {
    /// Source product.
    pub platform: Platform,
    /// Stable source locator, normally relative to an approved root.
    pub locator: String,
    /// Evidence grade for the parser or discovery rule.
    pub evidence: EvidenceLevel,
    /// Hash of the exact source representation.
    pub source_hash: String,
    /// Whether a model inferred any of the canonical semantics.
    pub model_inferred: bool,
}

/// Canonical transport for an MCP server without embedded credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerAsset {
    /// Logical server name.
    pub name: String,
    /// `stdio`, `http`, or another adapter-declared transport.
    pub transport: String,
    /// Executable for stdio servers.
    pub command: Option<String>,
    /// Literal argument vector; never interpreted as a shell expression.
    #[serde(default)]
    pub args: Vec<String>,
    /// URL for remote transports.
    pub url: Option<String>,
    /// Environment variable names required on the target.
    #[serde(default)]
    pub env_refs: Vec<String>,
    /// Header names whose values must be supplied on the target.
    #[serde(default)]
    pub header_refs: Vec<String>,
}

/// Typed canonical asset body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AssetPayload {
    /// Markdown or plain-text instruction, prompt, preference or memory.
    Text(String),
    /// A portable directory represented by logical path to object hash.
    FileTree(BTreeMap<String, String>),
    /// Credential-free MCP definition.
    McpServer(McpServerAsset),
    /// Reinstall intent, not opaque installed plugin state.
    PluginIntent {
        /// Stable publisher/name or marketplace id.
        identifier: String,
        /// Requested version when known.
        version: Option<String>,
        /// Trusted source registry or URL when known.
        source: Option<String>,
    },
    /// Structured inventory that is preserved but not automatically applied.
    Inventory(Value),
    /// Current-work continuation capsule.
    Handoff(Value),
}

/// Deterministic new-session continuation capsule. It contains user-selected
/// state, not a product session id or internal transcript database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffCapsule {
    /// Handoff schema version.
    pub schema_version: String,
    /// Source host.
    pub source: Platform,
    /// Current objective.
    pub goal: String,
    /// Most recent user request, when selected for export.
    pub latest_request: Option<String>,
    /// Active constraints.
    #[serde(default)]
    pub constraints: Vec<String>,
    /// Decisions already made.
    #[serde(default)]
    pub decisions: Vec<String>,
    /// Completed work.
    #[serde(default)]
    pub completed: Vec<String>,
    /// Remaining work.
    #[serde(default)]
    pub pending: Vec<String>,
    /// Portable workspace label; never requires an absolute source path.
    pub workspace: Option<String>,
    /// Optional Git revision.
    pub git_head: Option<String>,
    /// Whether uncommitted work existed.
    pub git_dirty: Option<bool>,
    /// Validation evidence.
    #[serde(default)]
    pub validation: Vec<String>,
    /// Known risks or uncertainty.
    #[serde(default)]
    pub risks: Vec<String>,
}

/// Versioned, provenance-preserving canonical asset envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAsset {
    /// Canonical schema version.
    pub schema_version: String,
    /// Content-derived identity.
    pub asset_id: String,
    /// Semantic kind.
    pub kind: AssetKind,
    /// Source scope.
    pub scope: ScopeLevel,
    /// Short display name.
    pub title: String,
    /// Content hash independent of source path.
    pub content_hash: String,
    /// Privacy/execution classification.
    pub sensitivity: Sensitivity,
    /// Source evidence.
    pub provenance: AssetProvenance,
    /// Typed portable body.
    pub payload: AssetPayload,
}

/// A hash precondition rechecked immediately before apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPrecondition {
    /// Target locator.
    pub locator: String,
    /// Expected current hash, absent if the target must not exist.
    pub expected_hash: Option<String>,
}

/// Mutation category in an immutable plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOperationKind {
    /// Replace or create a complete file.
    WriteFile,
    /// Modify adapter-owned keys in structured configuration.
    MergeConfig,
    /// Invoke an allowlisted official plugin installer.
    InstallPlugin,
    /// Register an MCP server through a supported file or interface.
    RegisterMcp,
    /// Report a required human action.
    ManualStep,
    /// No target mutation is needed.
    Noop,
}

/// Apply phase controls atomicity promises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplyPhase {
    /// Local file mutations with strong rollback.
    TransactionalCore,
    /// Official installers, authentication, or other external actions.
    ExternalAction,
}

/// Authorization class required by a planned item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalClass {
    /// Read-only or no-op.
    None,
    /// Local target write.
    Write,
    /// External process or service mutation.
    External,
    /// Target-side secret rehydration.
    Secret,
    /// A conflict needs an explicit resolution.
    UserResolution,
}

/// One target effect in an immutable migration plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanOperation {
    /// Stable content-derived operation id.
    pub operation_id: String,
    /// Typed mutation.
    pub kind: PlanOperationKind,
    /// Atomicity phase.
    pub phase: ApplyPhase,
    /// Source canonical asset id.
    pub asset_id: String,
    /// Preconditions checked under the target lock.
    pub preconditions: Vec<PlanPrecondition>,
    /// Adapter-owned structured effect.
    pub effect: Value,
    /// Verification recipe.
    pub verification: Value,
    /// Rollback strength.
    pub rollback: RollbackGuarantee,
    /// Authorization needed before execution.
    pub approval: ApprovalClass,
}

/// Immutable plan document connecting a source snapshot to an exact target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Plan schema version.
    pub schema_version: String,
    /// Content-derived plan id.
    pub plan_id: String,
    /// Source inventory root hash.
    pub source_root_hash: String,
    /// Exact target product tuple.
    pub target: ProductTuple,
    /// Adapter implementation version.
    pub adapter_version: String,
    /// Hash of the capability snapshot used for decisions.
    pub capability_snapshot_hash: String,
    /// Ordered operations.
    pub operations: Vec<PlanOperation>,
}

/// Stable machine-readable diagnostic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Stable code, suitable for automation.
    pub code: String,
    /// Human-readable message without secrets.
    pub message: String,
    /// Optional structured metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

impl Diagnostic {
    /// Create a diagnostic without detail fields.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: BTreeMap::new(),
        }
    }
}

/// Stable envelope emitted by every JSON command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandResponse<T> {
    /// Output schema version.
    pub schema_version: String,
    /// Unique invocation identifier.
    pub operation_id: Uuid,
    /// Current workflow phase.
    pub phase: String,
    /// Command-specific payload.
    pub data: T,
    /// Stable diagnostics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
    /// Safe next actions for a caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<String>,
}

impl<T> CommandResponse<T> {
    /// Wrap command data in a successful response.
    #[must_use]
    pub fn success(phase: impl Into<String>, data: T) -> Self {
        Self {
            schema_version: COMMAND_SCHEMA_VERSION.to_owned(),
            operation_id: Uuid::new_v4(),
            phase: phase.into(),
            data,
            diagnostics: Vec::new(),
            next_actions: Vec::new(),
        }
    }
}

impl CommandResponse<Value> {
    /// Build a log-safe failed response without embedding raw error context.
    #[must_use]
    pub fn failure(phase: impl Into<String>, diagnostic: Diagnostic) -> Self {
        Self {
            schema_version: COMMAND_SCHEMA_VERSION.to_owned(),
            operation_id: Uuid::new_v4(),
            phase: phase.into(),
            data: Value::Null,
            diagnostics: vec![diagnostic],
            next_actions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CommandResponse, Platform};

    #[test]
    fn platform_aliases_are_stable() {
        assert_eq!("claude".parse(), Ok(Platform::ClaudeCode));
        assert_eq!("cursor-agent".parse(), Ok(Platform::Cursor));
    }

    #[test]
    fn command_response_contains_version_and_operation_id() {
        let response = CommandResponse::success("doctor", serde_json::json!({"ok": true}));
        let encoded = serde_json::to_value(response).unwrap_or_default();
        assert_eq!(encoded["schema_version"], "1.0");
        assert!(encoded["operation_id"].as_str().is_some());
    }

    #[test]
    fn checked_in_schemas_are_valid_json() {
        let command_schema = include_str!("../../../schemas/command-response.schema.json");
        let tuple_schema = include_str!("../../../schemas/product-tuple.schema.json");
        let asset_schema = include_str!("../../../schemas/canonical-asset.schema.json");
        let plan_schema = include_str!("../../../schemas/migration-plan.schema.json");
        let handoff_schema = include_str!("../../../schemas/handoff.schema.json");
        for schema in [
            command_schema,
            tuple_schema,
            asset_schema,
            plan_schema,
            handoff_schema,
        ] {
            assert!(serde_json::from_str::<serde_json::Value>(schema).is_ok());
        }
    }
}
