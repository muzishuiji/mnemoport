//! Shared read-only adapter contracts and host discovery helpers.

use mnemo_schema::{
    AssetKind, AssetPayload, AssetProvenance, CanonicalAsset, Entrypoint, EvidenceLevel,
    McpServerAsset, Platform, ProbeMethod, ProbeStatus, ProductProbe, ProductTuple, ScopeLevel,
    Sensitivity,
};
use mnemo_security::{SecurityError, scan_and_redact, sha256_id, validate_portable_path};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

/// Collection modes with increasing side-effect permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CollectionMode {
    /// Filesystem-only discovery; must not launch the source product.
    OfflineStatic,
    /// Approved local CLI/UI discovery without model usage.
    LocalAssisted,
    /// Approved account or cloud export.
    AccountAssisted,
}

/// A candidate product-owned root and why it was selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCandidate {
    /// Root path.
    pub path: PathBuf,
    /// Source such as environment override or official default.
    pub basis: String,
    /// Whether the path currently exists.
    pub exists: bool,
}

/// Metadata returned without collecting asset bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryItem {
    /// Stable logical identifier local to this inventory.
    pub id: String,
    /// Canonical kind.
    pub kind: AssetKind,
    /// Source scope.
    pub scope: ScopeLevel,
    /// Logical locator; never includes a secret value.
    pub locator: String,
    /// Size when it can be read without following unsafe links.
    pub size: Option<u64>,
    /// Whether content collection requires assisted mode.
    pub requires_assisted: bool,
}

/// Canonical metadata plus content-addressed object bytes collected from a
/// source. Object keys are hashes referenced by `asset.payload`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedAsset {
    /// Canonical portable asset.
    pub asset: CanonicalAsset,
    /// Exact or redacted object bodies keyed by SHA-256 id.
    pub objects: BTreeMap<String, Vec<u8>>,
}

/// One deterministic local file proposed by a target adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedFile {
    /// Which adapter-approved root receives the file.
    pub root: TargetRoot,
    /// Portable path relative to the adapter-approved target root.
    pub relative_path: String,
    /// Desired bytes.
    pub bytes: Vec<u8>,
    /// Canonical source asset id.
    pub asset_id: String,
}

/// Logical target root resolved by the destination adapter at apply time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetRoot {
    /// Product configuration root such as `CLAUDE_CONFIG_DIR` or `CODEX_HOME`.
    ProductConfig,
    /// User home for documented shared roots such as `~/.agents`.
    UserHome,
    /// Selected repository or workspace root.
    Workspace,
}

/// Render a canonical text payload to one target-relative file.
pub fn render_text_file(
    extracted: &ExtractedAsset,
    root: TargetRoot,
    relative_path: impl Into<String>,
) -> Result<RenderedFile, AdapterError> {
    let relative_path = relative_path.into();
    validate_portable_path(&relative_path)?;
    let AssetPayload::Text(text) = &extracted.asset.payload else {
        return Err(AdapterError::InvalidData {
            path: PathBuf::from(&relative_path),
            message: "expected canonical text payload".to_owned(),
        });
    };
    Ok(RenderedFile {
        root,
        relative_path,
        bytes: text.as_bytes().to_vec(),
        asset_id: extracted.asset.asset_id.clone(),
    })
}

/// Render a canonical file-tree payload beneath a target directory.
pub fn render_file_tree(
    extracted: &ExtractedAsset,
    root: TargetRoot,
    target_directory: &str,
) -> Result<Vec<RenderedFile>, AdapterError> {
    validate_portable_path(target_directory)?;
    let AssetPayload::FileTree(files) = &extracted.asset.payload else {
        return Err(AdapterError::InvalidData {
            path: PathBuf::from(target_directory),
            message: "expected canonical file-tree payload".to_owned(),
        });
    };
    files
        .iter()
        .map(|(relative, hash)| {
            validate_portable_path(relative)?;
            let bytes = extracted
                .objects
                .get(hash)
                .ok_or_else(|| AdapterError::InvalidData {
                    path: PathBuf::from(relative),
                    message: format!("missing object {hash}"),
                })?;
            Ok(RenderedFile {
                root,
                relative_path: format!("{target_directory}/{relative}"),
                bytes: bytes.clone(),
                asset_id: extracted.asset.asset_id.clone(),
            })
        })
        .collect()
}

/// Render a structured Handoff capsule as a portable Markdown sidecar for a
/// new target conversation.
pub fn render_handoff(extracted: &ExtractedAsset) -> Result<RenderedFile, AdapterError> {
    let AssetPayload::Handoff(value) = &extracted.asset.payload else {
        return Err(AdapterError::InvalidData {
            path: PathBuf::from(&extracted.asset.provenance.locator),
            message: "expected Handoff payload".to_owned(),
        });
    };
    let capsule: mnemo_schema::HandoffCapsule =
        serde_json::from_value(value.clone()).map_err(|error| AdapterError::InvalidData {
            path: PathBuf::from(&extracted.asset.provenance.locator),
            message: error.to_string(),
        })?;
    let body = format!(
        "# MnemoPort Handoff\n\n## Goal\n\n{}\n\n## Latest request\n\n{}\n\n{}{}{}{}{}",
        capsule.goal,
        capsule.latest_request.as_deref().unwrap_or("Not provided"),
        markdown_list("Constraints", &capsule.constraints),
        markdown_list("Decisions", &capsule.decisions),
        markdown_list("Completed", &capsule.completed),
        markdown_list("Pending", &capsule.pending),
        markdown_list("Risks", &capsule.risks),
    );
    let short_id = extracted
        .asset
        .asset_id
        .strip_prefix("sha256:")
        .unwrap_or(&extracted.asset.asset_id)
        .chars()
        .take(12)
        .collect::<String>();
    Ok(RenderedFile {
        root: TargetRoot::Workspace,
        relative_path: format!(".mnemoport/handoffs/{short_id}.md"),
        bytes: body.into_bytes(),
        asset_id: extracted.asset.asset_id.clone(),
    })
}

fn markdown_list(title: &str, values: &[String]) -> String {
    if values.is_empty() {
        return String::new();
    }
    format!(
        "## {title}\n\n{}\n\n",
        values
            .iter()
            .map(|value| format!("- {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Convert a display name to a conservative portable directory/file segment.
#[must_use]
pub fn portable_name(name: &str, fallback_hash: &str) -> String {
    let sanitized = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if sanitized.is_empty() {
        fallback_hash
            .strip_prefix("sha256:")
            .unwrap_or(fallback_hash)
            .chars()
            .take(12)
            .collect()
    } else {
        sanitized
    }
}

/// Merge one credential-free canonical MCP server into a JSON MCP document.
/// Existing unrelated keys are preserved. A same-name target is never silently
/// overwritten.
pub fn merge_mcp_json(
    existing: Option<&[u8]>,
    extracted: &ExtractedAsset,
) -> Result<Vec<u8>, AdapterError> {
    let AssetPayload::McpServer(server) = &extracted.asset.payload else {
        return Err(AdapterError::InvalidData {
            path: PathBuf::from(&extracted.asset.provenance.locator),
            message: "expected canonical MCP payload".to_owned(),
        });
    };
    let mut document = if let Some(bytes) = existing {
        serde_json::from_slice::<serde_json::Value>(bytes).map_err(|error| {
            AdapterError::InvalidData {
                path: PathBuf::from("mcp.json"),
                message: error.to_string(),
            }
        })?
    } else {
        serde_json::json!({})
    };
    let root = document
        .as_object_mut()
        .ok_or_else(|| AdapterError::InvalidData {
            path: PathBuf::from("mcp.json"),
            message: "MCP document root must be an object".to_owned(),
        })?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| AdapterError::InvalidData {
            path: PathBuf::from("mcp.json"),
            message: "mcpServers must be an object".to_owned(),
        })?;
    let rendered = mcp_json_value(server);
    if let Some(current) = servers.get(&server.name) {
        if *current != rendered {
            return Err(AdapterError::InvalidData {
                path: PathBuf::from("mcp.json"),
                message: format!("target MCP name collision: {}", server.name),
            });
        }
    } else {
        servers.insert(server.name.clone(), rendered);
    }
    serde_json::to_vec_pretty(&document).map_err(|error| AdapterError::InvalidData {
        path: PathBuf::from("mcp.json"),
        message: error.to_string(),
    })
}

/// Append one credential-free MCP server to Codex TOML while preserving all
/// existing bytes as a prefix. Existing names are rejected for plan resolution.
pub fn merge_mcp_toml(
    existing: Option<&[u8]>,
    extracted: &ExtractedAsset,
) -> Result<Vec<u8>, AdapterError> {
    let AssetPayload::McpServer(server) = &extracted.asset.payload else {
        return Err(AdapterError::InvalidData {
            path: PathBuf::from(&extracted.asset.provenance.locator),
            message: "expected canonical MCP payload".to_owned(),
        });
    };
    let existing = existing.unwrap_or_default();
    let text = std::str::from_utf8(existing).map_err(|_| AdapterError::InvalidData {
        path: PathBuf::from("config.toml"),
        message: "target TOML is not UTF-8".to_owned(),
    })?;
    let document =
        toml::from_str::<toml::Value>(text).map_err(|error| AdapterError::InvalidData {
            path: PathBuf::from("config.toml"),
            message: error.to_string(),
        })?;
    if let Some(current) = document
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .and_then(|servers| servers.get(&server.name))
    {
        let marker = extracted
            .asset
            .asset_id
            .strip_prefix("sha256:")
            .unwrap_or(&extracted.asset.asset_id);
        let start_marker = format!("# >>> mnemoport:{marker}");
        let end_marker = format!("# <<< mnemoport:{marker}");
        if text.contains(&start_marker)
            && text.contains(&end_marker)
            && mcp_toml_value_matches(current, server)
        {
            return Ok(existing.to_vec());
        }
        return Err(AdapterError::InvalidData {
            path: PathBuf::from("config.toml"),
            message: format!("target MCP name collision: {}", server.name),
        });
    }
    let mut output = existing.to_vec();
    if !output.is_empty() && !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    let marker = extracted
        .asset
        .asset_id
        .strip_prefix("sha256:")
        .unwrap_or(&extracted.asset.asset_id);
    let mut block = format!(
        "\n# >>> mnemoport:{marker}\n[mcp_servers.{}]\n",
        toml_string(&server.name)
    );
    if let Some(command) = &server.command {
        block.push_str(&format!("command = {}\n", toml_string(command)));
    }
    if !server.args.is_empty() {
        let args = server
            .args
            .iter()
            .map(|argument| toml_string(argument))
            .collect::<Vec<_>>()
            .join(", ");
        block.push_str(&format!("args = [{args}]\n"));
    }
    if let Some(url) = &server.url {
        block.push_str(&format!("url = {}\n", toml_string(url)));
    }
    if !server.env_refs.is_empty() || !server.header_refs.is_empty() {
        block.push_str("# reauth-required = ");
        block.push_str(&toml_string(
            &server
                .env_refs
                .iter()
                .chain(server.header_refs.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        ));
        block.push('\n');
    }
    block.push_str(&format!("# <<< mnemoport:{marker}\n"));
    output.extend_from_slice(block.as_bytes());
    let rendered = std::str::from_utf8(&output).map_err(|_| AdapterError::InvalidData {
        path: PathBuf::from("config.toml"),
        message: "rendered TOML is not UTF-8".to_owned(),
    })?;
    toml::from_str::<toml::Value>(rendered).map_err(|error| AdapterError::InvalidData {
        path: PathBuf::from("config.toml"),
        message: format!("rendered MCP TOML is invalid: {error}"),
    })?;
    Ok(output)
}

fn mcp_toml_value_matches(current: &toml::Value, server: &McpServerAsset) -> bool {
    let Some(table) = current.as_table() else {
        return false;
    };
    let expected_keys = [
        server.command.as_ref().map(|_| "command"),
        (!server.args.is_empty()).then_some("args"),
        server.url.as_ref().map(|_| "url"),
    ]
    .into_iter()
    .flatten()
    .collect::<std::collections::BTreeSet<_>>();
    if table
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected_keys
    {
        return false;
    }
    if table.get("command").and_then(toml::Value::as_str) != server.command.as_deref() {
        return false;
    }
    let current_args = table
        .get("args")
        .and_then(toml::Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(toml::Value::as_str)
                .collect::<Option<Vec<_>>>()
        });
    let expected_args = (!server.args.is_empty())
        .then(|| server.args.iter().map(String::as_str).collect::<Vec<_>>());
    if current_args != expected_args {
        return false;
    }
    table.get("url").and_then(toml::Value::as_str) == server.url.as_deref()
}

fn mcp_json_value(server: &McpServerAsset) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    if server.transport != "stdio" && server.transport != "http" {
        object.insert("type".to_owned(), server.transport.clone().into());
    }
    if let Some(command) = &server.command {
        object.insert("command".to_owned(), command.clone().into());
    }
    if !server.args.is_empty() {
        object.insert("args".to_owned(), serde_json::json!(server.args));
    }
    if let Some(url) = &server.url {
        object.insert("url".to_owned(), url.clone().into());
    }
    serde_json::Value::Object(object)
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

/// Read-only product adapter error.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// Host has no usable user directory.
    #[error("home directory is unavailable")]
    HomeUnavailable,
    /// Requested operation requires a stronger collection mode.
    #[error("operation requires collection mode {required:?}")]
    ModeRequired {
        /// Required mode.
        required: CollectionMode,
    },
    /// Filesystem inspection failed.
    #[error("filesystem error at {path}: {source}")]
    Io {
        /// Path being inspected.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Structured source representation is malformed.
    #[error("invalid source data at {path}: {message}")]
    InvalidData {
        /// Source path.
        path: PathBuf,
        /// Sanitized parser diagnostic.
        message: String,
    },
    /// A source object violated portable security policy.
    #[error(transparent)]
    Security(#[from] SecurityError),
}

/// Minimal interface implemented before an adapter may extract or write assets.
pub trait PlatformAdapter: Send + Sync {
    /// Platform identifier.
    fn platform(&self) -> Platform;
    /// Detect product tuples without starting the product.
    fn detect(&self) -> Result<Vec<ProductTuple>, AdapterError>;
    /// Run explicit, adapter-approved version-level L1 probes. The default
    /// implementation never initializes migrated assets or invokes a shell.
    fn probe(&self) -> Result<Vec<ProductProbe>, AdapterError> {
        Ok(self.detect()?.into_iter().map(probe_version).collect())
    }
    /// Return metadata only. M0 adapters may return an empty inventory.
    fn inventory(&self, mode: CollectionMode) -> Result<Vec<InventoryItem>, AdapterError>;
    /// Extract supported canonical assets. Unsupported categories must remain
    /// visible in inventory rather than being guessed here.
    fn extract(&self, _mode: CollectionMode) -> Result<Vec<ExtractedAsset>, AdapterError> {
        Ok(Vec::new())
    }
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_LIMIT: u64 = 8 * 1024;
const PROBE_OUTPUT_LIMIT_USIZE: usize = 8 * 1024;

/// Run the single fixed `--version` probe permitted for supported entrypoints.
/// The child receives a disposable home and a small environment allowlist.
#[must_use]
pub fn probe_version(tuple: ProductTuple) -> ProductProbe {
    let Some(executable) = tuple.executable.clone() else {
        return probe_result(
            tuple,
            ProbeStatus::Unavailable,
            ProbeMethod::None,
            Vec::new(),
            "executable_unavailable",
            false,
        );
    };
    if !approved_version_entrypoint(tuple.platform, &tuple.entrypoint) {
        return probe_result(
            tuple,
            ProbeStatus::UnsupportedEntrypoint,
            ProbeMethod::None,
            Vec::new(),
            "entrypoint_not_safe_for_automatic_probe",
            false,
        );
    }

    probe_version_with_timeout(tuple, &executable, PROBE_TIMEOUT)
}

fn probe_version_with_timeout(
    tuple: ProductTuple,
    executable: &Path,
    timeout: Duration,
) -> ProductProbe {
    let scratch = probe_scratch_path();
    if fs::create_dir(&scratch).is_err() {
        return probe_result(
            tuple,
            ProbeStatus::Failed,
            ProbeMethod::VersionCommand,
            vec!["--version".to_owned()],
            "isolated_home_create_failed",
            false,
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700));
    }

    let stdout_path = scratch.join("stdout");
    let stderr_path = scratch.join("stderr");
    let Ok(command) = prepare_probe_command(executable, &scratch, &stdout_path, &stderr_path)
    else {
        let _ = fs::remove_dir_all(&scratch);
        return probe_result(
            tuple,
            ProbeStatus::Failed,
            ProbeMethod::VersionCommand,
            vec!["--version".to_owned()],
            "probe_output_create_failed",
            true,
        );
    };
    let result = run_bounded(command, timeout);
    let output = read_probe_output(&stdout_path, &stderr_path);
    let _ = fs::remove_dir_all(&scratch);
    finish_probe(tuple, result, output)
}

fn prepare_probe_command(
    executable: &Path,
    scratch: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
) -> std::io::Result<Command> {
    let stdout = File::create(stdout_path)?;
    let stderr = File::create(stderr_path)?;
    let mut command = Command::new(executable);
    command
        .arg("--version")
        .env_clear()
        .env("HOME", scratch)
        .env("USERPROFILE", scratch)
        .env("XDG_CONFIG_HOME", scratch.join("config"))
        .env("XDG_CACHE_HOME", scratch.join("cache"))
        .env("XDG_DATA_HOME", scratch.join("data"))
        .env("APPDATA", scratch.join("appdata"))
        .env("LOCALAPPDATA", scratch.join("local-appdata"))
        .env("TMP", scratch)
        .env("TEMP", scratch)
        .env("TMPDIR", scratch)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    copy_environment_if_present(&mut command, "PATH");
    copy_environment_if_present(&mut command, "SYSTEMROOT");
    copy_environment_if_present(&mut command, "WINDIR");
    Ok(command)
}

fn finish_probe(
    mut tuple: ProductTuple,
    execution: ProbeExecution,
    output: std::io::Result<Vec<u8>>,
) -> ProductProbe {
    match (execution, output) {
        (ProbeExecution::Completed { success: true }, Ok(output)) => {
            if let Some(version) = extract_version(&output) {
                tuple.version = Some(version);
                tuple.evidence = EvidenceLevel::Probe;
                probe_result(
                    tuple,
                    ProbeStatus::Verified,
                    ProbeMethod::VersionCommand,
                    vec!["--version".to_owned()],
                    "version_recognized",
                    true,
                )
            } else {
                probe_result(
                    tuple,
                    ProbeStatus::Failed,
                    ProbeMethod::VersionCommand,
                    vec!["--version".to_owned()],
                    "version_unrecognized",
                    true,
                )
            }
        }
        (ProbeExecution::Completed { success: true }, Err(_)) => probe_result(
            tuple,
            ProbeStatus::Failed,
            ProbeMethod::VersionCommand,
            vec!["--version".to_owned()],
            "probe_output_read_failed",
            true,
        ),
        (ProbeExecution::Completed { success: false }, _) => probe_result(
            tuple,
            ProbeStatus::Failed,
            ProbeMethod::VersionCommand,
            vec!["--version".to_owned()],
            "version_command_failed",
            true,
        ),
        (ProbeExecution::TimedOut, _) => probe_result(
            tuple,
            ProbeStatus::TimedOut,
            ProbeMethod::VersionCommand,
            vec!["--version".to_owned()],
            "version_command_timed_out",
            true,
        ),
        (ProbeExecution::SpawnFailed, _) => probe_result(
            tuple,
            ProbeStatus::Failed,
            ProbeMethod::VersionCommand,
            vec!["--version".to_owned()],
            "version_command_spawn_failed",
            true,
        ),
    }
}

fn approved_version_entrypoint(platform: Platform, entrypoint: &Entrypoint) -> bool {
    matches!(
        (platform, entrypoint),
        (
            Platform::ClaudeCode | Platform::Codex | Platform::Qoder,
            Entrypoint::Cli
        ) | (Platform::Cursor, Entrypoint::Agent | Entrypoint::IdeEditor)
    )
}

fn probe_result(
    tuple: ProductTuple,
    status: ProbeStatus,
    method: ProbeMethod,
    arguments: Vec<String>,
    diagnostic: &str,
    isolated_home: bool,
) -> ProductProbe {
    ProductProbe {
        tuple,
        status,
        method,
        arguments,
        diagnostic: diagnostic.to_owned(),
        isolated_home,
        migrated_components_started: false,
    }
}

enum ProbeExecution {
    Completed { success: bool },
    TimedOut,
    SpawnFailed,
}

fn run_bounded(mut command: Command, timeout: Duration) -> ProbeExecution {
    let Ok(mut child) = command.spawn() else {
        return ProbeExecution::SpawnFailed;
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return ProbeExecution::Completed {
                    success: status.success(),
                };
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return ProbeExecution::TimedOut;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return ProbeExecution::SpawnFailed;
            }
        }
    }
}

fn read_probe_output(stdout_path: &Path, stderr_path: &Path) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    File::open(stdout_path)?
        .take(PROBE_OUTPUT_LIMIT)
        .read_to_end(&mut output)?;
    if output.len() < PROBE_OUTPUT_LIMIT_USIZE {
        let remaining = PROBE_OUTPUT_LIMIT
            .saturating_sub(u64::try_from(output.len()).unwrap_or(PROBE_OUTPUT_LIMIT));
        File::open(stderr_path)?
            .take(remaining)
            .read_to_end(&mut output)?;
    }
    Ok(output)
}

fn extract_version(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    text.lines()
        .flat_map(str::split_whitespace)
        .map(|token| {
            token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && !matches!(character, '.' | '-' | '_' | '+')
            })
        })
        .find(|token| {
            token.len() <= 128
                && token.chars().any(|character| character.is_ascii_digit())
                && token.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+')
                })
        })
        .map(str::to_owned)
}

fn probe_scratch_path() -> PathBuf {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("mnemoport-probe-{}-{epoch}", std::process::id()))
}

fn copy_environment_if_present(command: &mut Command, name: &str) {
    if let Some(value) = std::env::var_os(name) {
        command.env(name, value);
    }
}

/// Convert an extracted file into inventory metadata without reading through a
/// symlink.
pub fn inventory_file(
    root: &Path,
    path: &Path,
    kind: AssetKind,
    scope: ScopeLevel,
) -> Result<InventoryItem, AdapterError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AdapterError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(AdapterError::InvalidData {
            path: path.to_path_buf(),
            message: "expected a regular file".to_owned(),
        });
    }
    let locator = portable_relative(root, path)?;
    Ok(InventoryItem {
        id: sha256_id(format!("{}:{locator}", kind_id(kind)).as_bytes()),
        kind,
        scope,
        locator,
        size: Some(metadata.len()),
        requires_assisted: false,
    })
}

/// Extract a text asset, applying deterministic secret redaction.
pub fn extract_text(
    platform: Platform,
    root: &Path,
    path: &Path,
    kind: AssetKind,
    scope: ScopeLevel,
    title: String,
) -> Result<ExtractedAsset, AdapterError> {
    let locator = portable_relative(root, path)?;
    let source = read_regular_file(path)?;
    let scanned = scan_and_redact(&locator, &source)?;
    let content = scanned.redacted.into_bytes();
    let content_hash = sha256_id(&content);
    let payload = AssetPayload::Text(String::from_utf8(content.clone()).map_err(|error| {
        AdapterError::InvalidData {
            path: path.to_path_buf(),
            message: error.to_string(),
        }
    })?);
    let sensitivity = if scanned.report.quarantined {
        Sensitivity::Quarantined
    } else {
        Sensitivity::Private
    };
    let asset = make_asset(CanonicalAssetInput {
        platform,
        kind,
        scope,
        title,
        locator,
        payload,
        source_hash: sha256_id(&source),
        content_hash: content_hash.clone(),
        sensitivity,
    })?;
    Ok(ExtractedAsset {
        asset,
        objects: BTreeMap::from([(content_hash, content)]),
    })
}

/// Extract a directory closure without following symlinks. UTF-8 text is
/// scanned and redacted; non-text objects are retained but quarantine the asset.
pub fn extract_file_tree(
    platform: Platform,
    source_root: &Path,
    tree_root: &Path,
    kind: AssetKind,
    scope: ScopeLevel,
    title: String,
) -> Result<ExtractedAsset, AdapterError> {
    let locator = portable_relative(source_root, tree_root)?;
    let mut file_tree = BTreeMap::new();
    let mut objects = BTreeMap::new();
    let mut source_digest_material = Vec::new();
    let mut quarantined = false;
    for entry in WalkDir::new(tree_root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|error| AdapterError::InvalidData {
            path: error
                .path()
                .map_or_else(|| tree_root.to_path_buf(), Path::to_path_buf),
            message: error.to_string(),
        })?;
        if entry.file_type().is_symlink() {
            return Err(AdapterError::InvalidData {
                path: entry.path().to_path_buf(),
                message: "symlink in portable file tree".to_owned(),
            });
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = portable_relative(tree_root, entry.path())?;
        let source = read_regular_file(entry.path())?;
        source_digest_material.extend_from_slice(relative.as_bytes());
        source_digest_material.push(0);
        source_digest_material.extend_from_slice(sha256_id(&source).as_bytes());
        let content = if is_text_path(entry.path()) {
            let scanned = scan_and_redact(&format!("{locator}/{relative}"), &source)?;
            quarantined |= scanned.report.quarantined;
            scanned.redacted.into_bytes()
        } else {
            quarantined = true;
            source
        };
        let hash = sha256_id(&content);
        file_tree.insert(relative, hash.clone());
        objects.insert(hash, content);
    }
    let payload = AssetPayload::FileTree(file_tree);
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|error| AdapterError::InvalidData {
            path: tree_root.to_path_buf(),
            message: error.to_string(),
        })?;
    let content_hash = sha256_id(&payload_bytes);
    let asset = make_asset(CanonicalAssetInput {
        platform,
        kind,
        scope,
        title,
        locator,
        payload,
        source_hash: sha256_id(&source_digest_material),
        content_hash,
        sensitivity: if quarantined {
            Sensitivity::Quarantined
        } else {
            Sensitivity::Private
        },
    })?;
    Ok(ExtractedAsset { asset, objects })
}

/// Append an existing regular file to inventory and extraction vectors.
pub fn collect_text_if_present(
    platform: Platform,
    root: &Path,
    relative: &str,
    kind: AssetKind,
    scope: ScopeLevel,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
) -> Result<(), AdapterError> {
    let path = root.join(relative);
    if !path.exists() {
        return Ok(());
    }
    inventory.push(inventory_file(root, &path, kind, scope)?);
    let title = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(relative)
        .to_owned();
    extracted.push(extract_text(platform, root, &path, kind, scope, title)?);
    Ok(())
}

/// Add a supported-but-not-yet-portable file to inventory without collecting
/// its body. This keeps unsupported state visible without leaking opaque config.
pub fn inventory_only_if_present(
    root: &Path,
    relative: &str,
    kind: AssetKind,
    scope: ScopeLevel,
    inventory: &mut Vec<InventoryItem>,
) -> Result<(), AdapterError> {
    let path = root.join(relative);
    if path.exists() {
        let mut item = inventory_file(root, &path, kind, scope)?;
        item.requires_assisted = true;
        inventory.push(item);
    }
    Ok(())
}

/// Collect all Markdown files below an approved relative directory.
pub fn collect_markdown_tree(
    platform: Platform,
    root: &Path,
    directory_relative: &str,
    kind: AssetKind,
    scope: ScopeLevel,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
) -> Result<(), AdapterError> {
    let directory = root.join(directory_relative);
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in WalkDir::new(&directory)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|error| AdapterError::InvalidData {
            path: error
                .path()
                .map_or_else(|| directory.clone(), Path::to_path_buf),
            message: error.to_string(),
        })?;
        if entry.file_type().is_symlink() {
            return Err(AdapterError::InvalidData {
                path: entry.path().to_path_buf(),
                message: "symlink in Markdown tree".to_owned(),
            });
        }
        if entry.file_type().is_file()
            && matches!(
                entry.path().extension().and_then(|value| value.to_str()),
                Some("md" | "mdc")
            )
        {
            inventory.push(inventory_file(root, entry.path(), kind, scope)?);
            let title = entry
                .path()
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("untitled")
                .to_owned();
            extracted.push(extract_text(
                platform,
                root,
                entry.path(),
                kind,
                scope,
                title,
            )?);
        }
    }
    Ok(())
}

/// Append immediate child directories containing `SKILL.md` as Skill assets.
pub fn collect_skills(
    platform: Platform,
    root: &Path,
    skills_relative: &str,
    scope: ScopeLevel,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
) -> Result<(), AdapterError> {
    let skills_root = root.join(skills_relative);
    if !skills_root.is_dir() {
        return Ok(());
    }
    let mut directories = fs::read_dir(&skills_root)
        .map_err(|source| AdapterError::Io {
            path: skills_root.clone(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| AdapterError::Io {
            path: skills_root.clone(),
            source,
        })?;
    directories.sort_by_key(std::fs::DirEntry::file_name);
    for entry in directories {
        let path = entry.path();
        if !entry
            .file_type()
            .map_err(|source| AdapterError::Io {
                path: path.clone(),
                source,
            })?
            .is_dir()
            || !path.join("SKILL.md").is_file()
        {
            continue;
        }
        let locator = portable_relative(root, &path)?;
        let size = tree_size(&path)?;
        inventory.push(InventoryItem {
            id: sha256_id(format!("skill:{locator}").as_bytes()),
            kind: AssetKind::Skill,
            scope,
            locator,
            size: Some(size),
            requires_assisted: false,
        });
        let title = entry.file_name().to_string_lossy().into_owned();
        extracted.push(extract_file_tree(
            platform,
            root,
            &path,
            AssetKind::Skill,
            scope,
            title,
        )?);
    }
    Ok(())
}

/// Extract each server from a documented JSON `mcpServers` object while
/// discarding credential values. Environment and header names become refs.
pub fn collect_json_mcp_if_present(
    platform: Platform,
    root: &Path,
    relative: &str,
    scope: ScopeLevel,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
) -> Result<(), AdapterError> {
    let path = root.join(relative);
    if !path.exists() {
        return Ok(());
    }
    let source = read_regular_file(&path)?;
    let document: serde_json::Value =
        serde_json::from_slice(&source).map_err(|error| AdapterError::InvalidData {
            path: path.clone(),
            message: error.to_string(),
        })?;
    let servers = document
        .get("mcpServers")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdapterError::InvalidData {
            path: path.clone(),
            message: "missing object key mcpServers".to_owned(),
        })?;
    let locator = portable_relative(root, &path)?;
    for (name, value) in servers {
        let server = mcp_from_json(name, value, &path)?;
        let server_locator = format!("{locator}#mcpServers/{name}");
        append_mcp_asset(
            platform,
            scope,
            &server_locator,
            &source,
            server,
            inventory,
            extracted,
        )?;
    }
    Ok(())
}

/// Extract Codex-compatible TOML `mcp_servers` entries without credential
/// values. Literal env/header tables are represented only by their key names.
pub fn collect_toml_mcp_if_present(
    platform: Platform,
    root: &Path,
    relative: &str,
    scope: ScopeLevel,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
) -> Result<(), AdapterError> {
    let path = root.join(relative);
    if !path.exists() {
        return Ok(());
    }
    let source = read_regular_file(&path)?;
    let text = std::str::from_utf8(&source).map_err(|_| AdapterError::InvalidData {
        path: path.clone(),
        message: "TOML is not UTF-8".to_owned(),
    })?;
    let document =
        toml::from_str::<toml::Value>(text).map_err(|error| AdapterError::InvalidData {
            path: path.clone(),
            message: error.to_string(),
        })?;
    let Some(servers) = document.get("mcp_servers").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    let locator = portable_relative(root, &path)?;
    for (name, item) in servers {
        let table = item.as_table().ok_or_else(|| AdapterError::InvalidData {
            path: path.clone(),
            message: format!("mcp_servers.{name} must be a table"),
        })?;
        let command = table
            .get("command")
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned);
        let url = table
            .get("url")
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned);
        validate_public_url(url.as_deref(), &path)?;
        let args = table
            .get("args")
            .and_then(toml::Value::as_array)
            .map(|array| {
                array
                    .iter()
                    .map(|value| {
                        value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                            AdapterError::InvalidData {
                                path: path.clone(),
                                message: format!("mcp_servers.{name}.args must contain strings"),
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        validate_mcp_args(&args, &path)?;
        let mut env_refs = table_keys(table.get("env"));
        if let Some(array) = table.get("env_vars").and_then(toml::Value::as_array) {
            env_refs.extend(
                array
                    .iter()
                    .filter_map(|value| value.as_str().map(ToOwned::to_owned)),
            );
        }
        if let Some(variable) = table
            .get("bearer_token_env_var")
            .and_then(toml::Value::as_str)
        {
            env_refs.push(variable.to_owned());
        }
        let mut header_refs = table_keys(table.get("http_headers"));
        header_refs.extend(table_keys(table.get("env_http_headers")));
        env_refs.sort();
        env_refs.dedup();
        header_refs.sort();
        header_refs.dedup();
        let server = McpServerAsset {
            name: name.to_owned(),
            transport: if command.is_some() { "stdio" } else { "http" }.to_owned(),
            command,
            args,
            url,
            env_refs,
            header_refs,
        };
        append_mcp_asset(
            platform,
            scope,
            &format!("{locator}#mcp_servers/{name}"),
            &source,
            server,
            inventory,
            extracted,
        )?;
    }
    Ok(())
}

fn mcp_from_json(
    name: &str,
    value: &serde_json::Value,
    path: &Path,
) -> Result<McpServerAsset, AdapterError> {
    let object = value.as_object().ok_or_else(|| AdapterError::InvalidData {
        path: path.to_path_buf(),
        message: format!("mcpServers.{name} must be an object"),
    })?;
    let command = object
        .get("command")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let url = object
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    validate_public_url(url.as_deref(), path)?;
    let args = object
        .get("args")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| AdapterError::InvalidData {
                            path: path.to_path_buf(),
                            message: format!("mcpServers.{name}.args must contain strings"),
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mut env_refs = json_object_keys(object.get("env"));
    let mut header_refs = json_object_keys(object.get("headers"));
    header_refs.extend(json_object_keys(object.get("httpHeaders")));
    env_refs.sort();
    env_refs.dedup();
    header_refs.sort();
    header_refs.dedup();
    validate_mcp_args(&args, path)?;
    Ok(McpServerAsset {
        name: name.to_owned(),
        transport: object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || if command.is_some() { "stdio" } else { "http" }.to_owned(),
                ToOwned::to_owned,
            ),
        command,
        args,
        url,
        env_refs,
        header_refs,
    })
}

fn validate_mcp_args(args: &[String], path: &Path) -> Result<(), AdapterError> {
    for pair in args.windows(2) {
        let flag = pair[0].to_ascii_lowercase();
        if flag.starts_with('-')
            && ["token", "secret", "password", "api-key", "apikey", "auth"]
                .iter()
                .any(|needle| flag.contains(needle))
        {
            return Err(AdapterError::InvalidData {
                path: path.to_path_buf(),
                message:
                    "MCP arguments contain a credential-bearing flag; use an environment reference"
                        .to_owned(),
            });
        }
    }
    Ok(())
}

fn append_mcp_asset(
    platform: Platform,
    scope: ScopeLevel,
    locator: &str,
    source: &[u8],
    server: McpServerAsset,
    inventory: &mut Vec<InventoryItem>,
    extracted: &mut Vec<ExtractedAsset>,
) -> Result<(), AdapterError> {
    let payload = AssetPayload::McpServer(server.clone());
    let content = serde_json::to_vec(&payload).map_err(|error| AdapterError::InvalidData {
        path: PathBuf::from(locator),
        message: error.to_string(),
    })?;
    let content_hash = sha256_id(&content);
    let asset = make_asset(CanonicalAssetInput {
        platform,
        kind: AssetKind::Mcp,
        scope,
        title: server.name,
        locator: locator.to_owned(),
        payload,
        source_hash: sha256_id(source),
        content_hash,
        sensitivity: if server.env_refs.is_empty() && server.header_refs.is_empty() {
            Sensitivity::Private
        } else {
            Sensitivity::SecretReference
        },
    })?;
    inventory.push(InventoryItem {
        id: asset.asset_id.clone(),
        kind: AssetKind::Mcp,
        scope,
        locator: locator.to_owned(),
        size: None,
        requires_assisted: false,
    });
    extracted.push(ExtractedAsset {
        asset,
        objects: BTreeMap::new(),
    });
    Ok(())
}

fn validate_public_url(url: Option<&str>, path: &Path) -> Result<(), AdapterError> {
    if let Some(url) = url {
        let scanned = scan_and_redact(path.to_string_lossy().as_ref(), url.as_bytes())?;
        if scanned.redacted != url
            || url.split("//").nth(1).is_some_and(|rest| {
                rest.split('/')
                    .next()
                    .is_some_and(|authority| authority.contains('@'))
            })
        {
            return Err(AdapterError::InvalidData {
                path: path.to_path_buf(),
                message: "MCP URL contains embedded credentials".to_owned(),
            });
        }
    }
    Ok(())
}

fn json_object_keys(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_object)
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn table_keys(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_table)
        .map(|table| table.keys().cloned().collect())
        .unwrap_or_default()
}

/// Validated parts used to construct a content-addressed canonical asset.
#[derive(Debug)]
pub struct CanonicalAssetInput {
    /// Source platform.
    pub platform: Platform,
    /// Semantic kind.
    pub kind: AssetKind,
    /// Source scope.
    pub scope: ScopeLevel,
    /// Display name.
    pub title: String,
    /// Stable source locator relative to an approved root.
    pub locator: String,
    /// Typed canonical body.
    pub payload: AssetPayload,
    /// Hash of the exact source representation.
    pub source_hash: String,
    /// Hash of the canonical payload.
    pub content_hash: String,
    /// Privacy/execution classification.
    pub sensitivity: Sensitivity,
}

/// Construct a canonical asset id from validated parts.
pub fn make_asset(input: CanonicalAssetInput) -> Result<CanonicalAsset, AdapterError> {
    let identity = serde_json::to_vec(&(
        input.platform,
        input.kind,
        input.scope,
        &input.title,
        &input.locator,
        &input.content_hash,
    ))
    .map_err(|error| AdapterError::InvalidData {
        path: PathBuf::from(&input.locator),
        message: error.to_string(),
    })?;
    Ok(CanonicalAsset {
        schema_version: "1.0".to_owned(),
        asset_id: sha256_id(&identity),
        kind: input.kind,
        scope: input.scope,
        title: input.title,
        content_hash: input.content_hash,
        sensitivity: input.sensitivity,
        provenance: AssetProvenance {
            platform: input.platform,
            locator: input.locator,
            evidence: EvidenceLevel::Documented,
            source_hash: input.source_hash,
            model_inferred: false,
        },
        payload: input.payload,
    })
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, AdapterError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AdapterError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(AdapterError::InvalidData {
            path: path.to_path_buf(),
            message: "refusing non-regular file".to_owned(),
        });
    }
    fs::read(path).map_err(|source| AdapterError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn portable_relative(root: &Path, path: &Path) -> Result<String, AdapterError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| AdapterError::InvalidData {
            path: path.to_path_buf(),
            message: "path escaped approved root".to_owned(),
        })?;
    let portable = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    validate_portable_path(&portable)?;
    Ok(portable)
}

fn tree_size(path: &Path) -> Result<u64, AdapterError> {
    let mut size = 0_u64;
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry.map_err(|error| AdapterError::InvalidData {
            path: error
                .path()
                .map_or_else(|| path.to_path_buf(), Path::to_path_buf),
            message: error.to_string(),
        })?;
        if entry.file_type().is_file() {
            size = size.saturating_add(
                entry
                    .metadata()
                    .map_err(|error| AdapterError::InvalidData {
                        path: entry.path().to_path_buf(),
                        message: error.to_string(),
                    })?
                    .len(),
            );
        }
    }
    Ok(size)
}

fn is_text_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("md" | "txt" | "json" | "jsonc" | "toml" | "yaml" | "yml" | "sh" | "py" | "js" | "ts")
    )
}

const fn kind_id(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Instruction => "instruction",
        AssetKind::Skill => "skill",
        AssetKind::Mcp => "mcp",
        AssetKind::Prompt => "prompt",
        AssetKind::Preference => "preference",
        AssetKind::Memory => "memory",
        AssetKind::Plugin => "plugin",
        AssetKind::Handoff => "handoff",
        AssetKind::InventoryOnly => "inventory-only",
    }
}

/// Resolve the current user's home directory.
pub fn user_home() -> Result<PathBuf, AdapterError> {
    directories::UserDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or(AdapterError::HomeUnavailable)
}

/// Return an environment override or an official default beneath the home directory.
pub fn resolve_root(env_name: &str, default_relative: &str) -> Result<RootCandidate, AdapterError> {
    if let Some(value) = std::env::var_os(env_name).filter(|value| !value.is_empty()) {
        let path = PathBuf::from(value);
        return Ok(RootCandidate {
            exists: path.exists(),
            path,
            basis: format!("environment:{env_name}"),
        });
    }
    let path = user_home()?.join(default_relative);
    Ok(RootCandidate {
        exists: path.exists(),
        path,
        basis: "official-default".to_owned(),
    })
}

/// Find an executable on PATH without launching it.
#[must_use]
pub fn find_executable(name: &str) -> Option<PathBuf> {
    let path_value: OsString = std::env::var_os("PATH")?;
    std::env::split_paths(&path_value)
        .map(|directory| directory.join(executable_name(name)))
        .find(|candidate| is_executable_file(candidate))
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) && !name.to_ascii_lowercase().ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

fn is_executable_file(path: &Path) -> bool {
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

/// Construct a read-only detected tuple.
#[must_use]
pub fn detected_tuple(
    platform: Platform,
    entrypoint: Entrypoint,
    executable: Option<PathBuf>,
    root: RootCandidate,
) -> ProductTuple {
    ProductTuple {
        platform,
        version: None,
        os: std::env::consts::OS.to_owned(),
        entrypoint,
        executable,
        config_root: Some(root.path),
        evidence: mnemo_schema::EvidenceLevel::Documented,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::probe_version_with_timeout;
    use super::{
        ExtractedAsset, collect_json_mcp_if_present, collect_toml_mcp_if_present, extract_version,
        merge_mcp_json, merge_mcp_toml, probe_version,
    };
    use mnemo_schema::{
        AssetPayload, Entrypoint, EvidenceLevel, Platform, ProbeStatus, ProductTuple, ScopeLevel,
        Sensitivity,
    };

    #[test]
    fn json_mcp_extraction_keeps_refs_not_values() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let secret = ["very", "secret", "value"].join("-");
        std::fs::write(
            temp.path().join(".mcp.json"),
            serde_json::to_vec(&serde_json::json!({
                "mcpServers": {
                    "docs": {
                        "command": "npx",
                        "args": ["-y", "@example/mcp"],
                        "env": {"DOCS_TOKEN": secret},
                        "headers": {"Authorization": secret}
                    }
                }
            }))?,
        )?;
        let mut inventory = Vec::new();
        let mut extracted = Vec::<ExtractedAsset>::new();
        collect_json_mcp_if_present(
            Platform::ClaudeCode,
            temp.path(),
            ".mcp.json",
            ScopeLevel::Workspace,
            &mut inventory,
            &mut extracted,
        )?;
        assert_eq!(inventory.len(), 1);
        assert_eq!(extracted[0].asset.sensitivity, Sensitivity::SecretReference);
        let AssetPayload::McpServer(server) = &extracted[0].asset.payload else {
            return Err("expected MCP payload".into());
        };
        assert_eq!(server.env_refs, ["DOCS_TOKEN"]);
        assert_eq!(server.header_refs, ["Authorization"]);
        let encoded = serde_json::to_string(&extracted[0].asset)?;
        assert!(!encoded.contains(&secret));
        let rendered = merge_mcp_json(None, &extracted[0])?;
        assert!(!String::from_utf8(rendered)?.contains(&secret));
        Ok(())
    }

    #[test]
    fn toml_mcp_merge_preserves_prefix_and_rejects_name_collision()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let source = r#"
[mcp_servers.docs]
url = "https://mcp.example.test/api"
bearer_token_env_var = "DOCS_TOKEN"
http_headers = { X-Tenant = "private-value" }
"#;
        std::fs::write(temp.path().join("config.toml"), source)?;
        let mut inventory = Vec::new();
        let mut extracted = Vec::new();
        collect_toml_mcp_if_present(
            Platform::Codex,
            temp.path(),
            "config.toml",
            ScopeLevel::User,
            &mut inventory,
            &mut extracted,
        )?;
        let prefix = b"# keep this comment\npersonality = \"pragmatic\"\n";
        let merged = merge_mcp_toml(Some(prefix), &extracted[0])?;
        assert!(merged.starts_with(prefix));
        let reapplied = merge_mcp_toml(Some(&merged), &extracted[0])?;
        assert_eq!(reapplied, merged);
        let text = String::from_utf8(merged)?;
        assert!(text.contains("reauth-required"));
        assert!(!text.contains("private-value"));
        assert!(merge_mcp_toml(Some(source.as_bytes()), &extracted[0]).is_err());
        Ok(())
    }

    #[test]
    fn rejects_mcp_secret_positional_arguments() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        std::fs::write(
            temp.path().join(".mcp.json"),
            r#"{"mcpServers":{"unsafe":{"command":"server","args":["--api-key","credential-value"]}}}"#,
        )?;
        let mut inventory = Vec::new();
        let mut extracted = Vec::new();
        assert!(
            collect_json_mcp_if_present(
                Platform::ClaudeCode,
                temp.path(),
                ".mcp.json",
                ScopeLevel::Workspace,
                &mut inventory,
                &mut extracted,
            )
            .is_err()
        );
        assert!(extracted.is_empty());
        Ok(())
    }

    #[test]
    fn recognizes_supported_version_output_without_returning_raw_text() {
        for (output, expected) in [
            ("2.1.259 (Claude Code)\n", "2.1.259"),
            ("codex-cli 0.144.1\n", "0.144.1"),
            ("2026.09.02-c22c1a3\n", "2026.09.02-c22c1a3"),
        ] {
            assert_eq!(
                extract_version(output.as_bytes()).as_deref(),
                Some(expected)
            );
        }
        assert_eq!(extract_version(b"product version unknown"), None);
    }

    #[test]
    fn probe_reports_absent_and_unsupported_entrypoints_without_execution() {
        let absent = probe_version(ProductTuple {
            platform: Platform::ClaudeCode,
            version: None,
            os: "fixture".to_owned(),
            entrypoint: Entrypoint::Cli,
            executable: None,
            config_root: None,
            evidence: EvidenceLevel::Documented,
        });
        assert_eq!(absent.status, ProbeStatus::Unavailable);
        assert!(!absent.isolated_home);

        let desktop = probe_version(ProductTuple {
            platform: Platform::Qoder,
            version: None,
            os: "fixture".to_owned(),
            entrypoint: Entrypoint::DesktopApp,
            executable: Some("must-not-run".into()),
            config_root: None,
            evidence: EvidenceLevel::Documented,
        });
        assert_eq!(desktop.status, ProbeStatus::UnsupportedEntrypoint);
        assert!(desktop.arguments.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn probe_executes_only_the_fixed_version_argument_in_an_isolated_home()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let executable = temp.path().join("fixture-product");
        std::fs::write(
            &executable,
            "#!/bin/sh\ntest \"$1\" = \"--version\" || exit 40\ntest -n \"$HOME\" || exit 41\ntest -z \"$MNEMOPORT_FAKE_SECRET\" || exit 42\nprintf 'fixture-cli 7.8.9\\n'\n",
        )?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        let report = probe_version(ProductTuple {
            platform: Platform::Codex,
            version: None,
            os: "fixture".to_owned(),
            entrypoint: Entrypoint::Cli,
            executable: Some(executable),
            config_root: None,
            evidence: EvidenceLevel::Documented,
        });
        assert_eq!(report.status, ProbeStatus::Verified);
        assert_eq!(report.tuple.version.as_deref(), Some("7.8.9"));
        assert_eq!(report.arguments, ["--version"]);
        assert!(report.isolated_home);
        assert!(!report.migrated_components_started);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn probe_terminates_a_slow_version_command() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        let temp = tempfile::tempdir()?;
        let executable = temp.path().join("slow-product");
        std::fs::write(&executable, "#!/bin/sh\nwhile :; do :; done\n")?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        let report = probe_version_with_timeout(
            ProductTuple {
                platform: Platform::ClaudeCode,
                version: None,
                os: "fixture".to_owned(),
                entrypoint: Entrypoint::Cli,
                executable: Some(executable.clone()),
                config_root: None,
                evidence: EvidenceLevel::Documented,
            },
            &executable,
            Duration::from_millis(40),
        );
        assert_eq!(report.status, ProbeStatus::TimedOut);
        assert_eq!(report.tuple.version, None);
        Ok(())
    }
}
