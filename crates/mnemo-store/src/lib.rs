//! MnemoPort-owned state, audit ledger and recoverable file transactions.

use directories::ProjectDirs;
use ed25519_dalek::SigningKey;
use mnemo_security::sha256_id;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use uuid::Uuid;

/// Platform-native paths. Resolving them does not create directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatePaths {
    /// User-editable policy and defaults.
    pub config: PathBuf,
    /// Ledger, trusted keys, and managed-object ownership.
    pub data: PathBuf,
    /// Disposable capability/download cache.
    pub cache: PathBuf,
    /// Journals and local rollback backups.
    pub transactions: PathBuf,
}

/// Resolve MnemoPort state paths without touching the filesystem.
#[must_use]
pub fn resolve_state_paths() -> Option<StatePaths> {
    ProjectDirs::from("io", "mnemoport", "MnemoPort").map(|dirs| StatePaths {
        config: dirs.config_dir().to_path_buf(),
        data: dirs.data_dir().to_path_buf(),
        cache: dirs.cache_dir().to_path_buf(),
        transactions: dirs.data_dir().join("transactions"),
    })
}

/// Persistent operation status used by the audit ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationStatus {
    /// Planning or mutation is still underway.
    Running,
    /// The operation completed successfully.
    Succeeded,
    /// The operation failed and retained evidence for diagnosis.
    Failed,
    /// A committed mutation was rolled back.
    RolledBack,
}

impl OperationStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled-back",
        }
    }
}

/// One operation returned from the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    /// Stable operation id.
    pub id: String,
    /// Workflow name such as `inventory`, `apply` or `undo`.
    pub kind: String,
    /// Current operation status.
    pub status: String,
    /// Creation time as Unix milliseconds.
    pub created_at_ms: i64,
    /// Completion time, when terminal.
    pub finished_at_ms: Option<i64>,
    /// Sanitized JSON metadata; never raw migrated content.
    pub metadata_json: String,
}

/// Ownership proof for one file created by MnemoPort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedObjectRecord {
    /// Target file locator.
    pub target_locator: String,
    /// Operation that first claimed ownership.
    pub owner_id: String,
    /// Exact hash MnemoPort installed.
    pub installed_hash: String,
    /// Template or canonical source id.
    pub source_asset_id: String,
}

/// Explicitly trusted package signing identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKeyRecord {
    /// Log-safe SHA-256 fingerprint.
    pub fingerprint: String,
    /// Hex-encoded Ed25519 public key.
    pub public_key: String,
    /// Optional user label.
    pub label: Option<String>,
    /// Trust creation time as Unix milliseconds.
    pub trusted_at_ms: i64,
}

/// SQLite audit index. It stores metadata, hashes and backup references, not
/// migrated asset bodies.
#[derive(Debug)]
pub struct Ledger {
    connection: Connection,
}

impl Ledger {
    /// Open or create a ledger and apply the embedded schema transactionally.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection })
    }

    /// Create an in-memory ledger, primarily for deterministic tests.
    pub fn in_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection })
    }

    /// Begin an auditable operation and return its generated id.
    pub fn begin_operation(
        &self,
        kind: &str,
        metadata: &impl Serialize,
    ) -> Result<String, StoreError> {
        let id = Uuid::new_v4().to_string();
        let metadata_json = serde_json::to_string(metadata)?;
        self.connection.execute(
            "INSERT INTO operations(id, kind, status, created_at_ms, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                kind,
                OperationStatus::Running.as_str(),
                unix_millis()?,
                metadata_json
            ],
        )?;
        Ok(id)
    }

    /// Mark an operation terminal.
    pub fn finish_operation(&self, id: &str, status: OperationStatus) -> Result<(), StoreError> {
        if status == OperationStatus::Running {
            return Err(StoreError::InvalidState(
                "finish status cannot be running".to_owned(),
            ));
        }
        let changed = self.connection.execute(
            "UPDATE operations SET status = ?1, finished_at_ms = ?2 WHERE id = ?3",
            params![status.as_str(), unix_millis()?, id],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound(format!("operation {id}")));
        }
        Ok(())
    }

    /// Load one operation by id.
    pub fn operation(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, kind, status, created_at_ms, finished_at_ms, metadata_json
                 FROM operations WHERE id = ?1",
                [id],
                |row| {
                    Ok(OperationRecord {
                        id: row.get(0)?,
                        kind: row.get(1)?,
                        status: row.get(2)?,
                        created_at_ms: row.get(3)?,
                        finished_at_ms: row.get(4)?,
                        metadata_json: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Record a transaction journal reference and its integrity hashes.
    pub fn record_transaction(
        &self,
        operation_id: &str,
        journal: &FileTransactionJournal,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO transactions(
                id, operation_id, status, target_locator, before_hash, after_hash,
                backup_locator, journal_locator, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                journal.id,
                operation_id,
                journal.status.as_str(),
                journal.target.to_string_lossy(),
                journal.before_hash,
                journal.after_hash,
                journal
                    .backup
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                journal.journal_path.to_string_lossy(),
                journal.created_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Return durable journal paths for an operation in creation order.
    pub fn transaction_journals(&self, operation_id: &str) -> Result<Vec<PathBuf>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT journal_locator FROM transactions
             WHERE operation_id = ?1 ORDER BY created_at_ms, id",
        )?;
        let rows = statement.query_map([operation_id], |row| row.get::<_, String>(0))?;
        rows.map(|row| row.map(PathBuf::from).map_err(StoreError::from))
            .collect()
    }

    /// Update the ledger status after a transaction rollback.
    pub fn set_transaction_status(
        &self,
        transaction_id: &str,
        status: TransactionStatus,
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE transactions SET status = ?1 WHERE id = ?2",
            params![status.as_str(), transaction_id],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound(format!(
                "transaction {transaction_id}"
            )));
        }
        Ok(())
    }

    /// Record ownership only after MnemoPort created a target file.
    pub fn record_managed_object(&self, record: &ManagedObjectRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO managed_objects(
                target_locator, owner_id, installed_hash, source_asset_id, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(target_locator) DO UPDATE SET
                owner_id = excluded.owner_id,
                installed_hash = excluded.installed_hash,
                source_asset_id = excluded.source_asset_id,
                updated_at_ms = excluded.updated_at_ms",
            params![
                record.target_locator,
                record.owner_id,
                record.installed_hash,
                record.source_asset_id,
                unix_millis()?,
            ],
        )?;
        Ok(())
    }

    /// Load ownership proof for one target locator.
    pub fn managed_object(
        &self,
        target_locator: &str,
    ) -> Result<Option<ManagedObjectRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT target_locator, owner_id, installed_hash, source_asset_id
                 FROM managed_objects WHERE target_locator = ?1",
                [target_locator],
                |row| {
                    Ok(ManagedObjectRecord {
                        target_locator: row.get(0)?,
                        owner_id: row.get(1)?,
                        installed_hash: row.get(2)?,
                        source_asset_id: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Forget ownership after a verified managed file was removed.
    pub fn remove_managed_object(&self, target_locator: &str) -> Result<(), StoreError> {
        self.connection.execute(
            "DELETE FROM managed_objects WHERE target_locator = ?1",
            [target_locator],
        )?;
        Ok(())
    }

    /// Add or relabel an explicitly trusted signer.
    pub fn trust_key(
        &self,
        public_key: &str,
        label: Option<&str>,
    ) -> Result<TrustedKeyRecord, StoreError> {
        let fingerprint = sha256_id(public_key.as_bytes());
        let trusted_at_ms = unix_millis()?;
        self.connection.execute(
            "INSERT INTO trusted_keys(fingerprint, public_key, label, trusted_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(fingerprint) DO UPDATE SET label = excluded.label",
            params![fingerprint, public_key, label, trusted_at_ms],
        )?;
        Ok(TrustedKeyRecord {
            fingerprint,
            public_key: public_key.to_owned(),
            label: label.map(ToOwned::to_owned),
            trusted_at_ms,
        })
    }

    /// Return whether a signer was explicitly trusted.
    pub fn is_key_trusted(&self, public_key: &str) -> Result<bool, StoreError> {
        let fingerprint = sha256_id(public_key.as_bytes());
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM trusted_keys WHERE fingerprint = ?1 AND public_key = ?2",
                params![fingerprint, public_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// List explicitly trusted signing identities.
    pub fn trusted_keys(&self) -> Result<Vec<TrustedKeyRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT fingerprint, public_key, label, trusted_at_ms
             FROM trusted_keys ORDER BY trusted_at_ms, fingerprint",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(TrustedKeyRecord {
                fingerprint: row.get(0)?,
                public_key: row.get(1)?,
                label: row.get(2)?,
                trusted_at_ms: row.get(3)?,
            })
        })?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
    }
}

/// Durable state of a file transaction journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionStatus {
    /// Backup and journal exist; target mutation has not been acknowledged.
    Prepared,
    /// Target was replaced and the journal was synced.
    Committed,
    /// Target was restored or removed by undo.
    RolledBack,
}

impl TransactionStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::RolledBack => "rolled-back",
        }
    }
}

/// Evidence needed to inspect or undo one atomic file replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTransactionJournal {
    /// Transaction id.
    pub id: String,
    /// Absolute or caller-resolved target path.
    pub target: PathBuf,
    /// Hash before mutation, or `None` if the target did not exist.
    pub before_hash: Option<String>,
    /// Hash written by the transaction.
    pub after_hash: String,
    /// Local backup path, absent for a newly created target.
    pub backup: Option<PathBuf>,
    /// Durable JSON journal location.
    pub journal_path: PathBuf,
    /// Current transaction state.
    pub status: TransactionStatus,
    /// Creation time as Unix milliseconds.
    pub created_at_ms: i64,
}

/// Apply one recoverable file replacement.
///
/// A stale `expected_before_hash` rejects the mutation before any target write.
/// Symlinks are rejected so callers cannot escape an adapter-approved boundary.
pub fn apply_file(
    target: &Path,
    new_bytes: &[u8],
    transaction_root: &Path,
    expected_before_hash: Option<&str>,
) -> Result<FileTransactionJournal, StoreError> {
    let parent = target
        .parent()
        .ok_or_else(|| StoreError::UnsafePath(target.to_path_buf()))?;
    reject_symlink_ancestors(parent)?;
    fs::create_dir_all(parent)?;
    reject_symlink_ancestors(parent)?;
    if fs::symlink_metadata(target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(StoreError::UnsafePath(target.to_path_buf()));
    }

    let before = match fs::read(target) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let before_hash = before.as_deref().map(sha256_id);
    if expected_before_hash != before_hash.as_deref() {
        return Err(StoreError::Precondition {
            expected: expected_before_hash.map(ToOwned::to_owned),
            actual: before_hash,
        });
    }

    let id = Uuid::new_v4().to_string();
    let transaction_dir = transaction_root.join(&id);
    fs::create_dir_all(&transaction_dir)?;
    let backup = if let Some(bytes) = &before {
        let path = transaction_dir.join("before.bin");
        write_new_synced(&path, bytes)?;
        Some(path)
    } else {
        None
    };
    let journal_path = transaction_dir.join("journal.json");
    let mut journal = FileTransactionJournal {
        id,
        target: target.to_path_buf(),
        before_hash: before.as_deref().map(sha256_id),
        after_hash: sha256_id(new_bytes),
        backup,
        journal_path,
        status: TransactionStatus::Prepared,
        created_at_ms: unix_millis()?,
    };
    save_journal(&journal)?;

    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(new_bytes)?;
    if let Ok(metadata) = fs::metadata(target) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(target)
        .map_err(|error| StoreError::Io(error.error))?;
    sync_directory(parent)?;

    journal.status = TransactionStatus::Committed;
    save_journal(&journal)?;
    Ok(journal)
}

/// Undo a committed file replacement if the target still matches the recorded
/// post-apply hash. `force` is intentionally explicit for externally modified
/// targets.
pub fn undo_file(journal: &mut FileTransactionJournal, force: bool) -> Result<(), StoreError> {
    if journal.status != TransactionStatus::Committed {
        return Err(StoreError::InvalidState(format!(
            "transaction {} is not committed",
            journal.id
        )));
    }
    let current = fs::read(&journal.target)
        .ok()
        .map(|bytes| sha256_id(&bytes));
    if !force && current.as_deref() != Some(journal.after_hash.as_str()) {
        return Err(StoreError::Precondition {
            expected: Some(journal.after_hash.clone()),
            actual: current,
        });
    }
    if let Some(backup) = &journal.backup {
        let bytes = fs::read(backup)?;
        replace_file(&journal.target, &bytes)?;
    } else if journal.target.exists() {
        fs::remove_file(&journal.target)?;
        if let Some(parent) = journal.target.parent() {
            sync_directory(parent)?;
        }
    }
    journal.status = TransactionStatus::RolledBack;
    save_journal(journal)?;
    Ok(())
}

/// Load a durable file transaction journal.
pub fn load_journal(path: &Path) -> Result<FileTransactionJournal, StoreError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Load or create the local Ed25519 device identity. The raw secret never
/// appears in reports or the SQLite ledger.
pub fn load_or_create_signing_key(data_root: &Path) -> Result<SigningKey, StoreError> {
    fs::create_dir_all(data_root)?;
    set_private_directory_permissions(data_root)?;
    let path = data_root.join("device-signing-key.bin");
    match fs::read(&path) {
        Ok(bytes) => signing_key_from_bytes(&bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0_u8; 32];
            getrandom::fill(&mut seed).map_err(|error| StoreError::Random(error.to_string()))?;
            match File::options().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    set_private_file_permissions(&file)?;
                    file.write_all(&seed)?;
                    file.sync_all()?;
                    sync_directory(data_root)?;
                    Ok(SigningKey::from_bytes(&seed))
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    signing_key_from_bytes(&fs::read(path)?)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, StoreError> {
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::InvalidState("device signing key must contain exactly 32 bytes".to_owned())
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_private_directory_permissions(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_private_file_permissions(_file: &File) -> Result<(), StoreError> {
    Ok(())
}

fn replace_file(target: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = target
        .parent()
        .ok_or_else(|| StoreError::UnsafePath(target.to_path_buf()))?;
    reject_symlink_ancestors(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(target)
        .map_err(|error| StoreError::Io(error.error))?;
    sync_directory(parent)
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), StoreError> {
    for ancestor in path.ancestors().filter(|item| !item.as_os_str().is_empty()) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::UnsafePath(ancestor.to_path_buf()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn save_journal(journal: &FileTransactionJournal) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec_pretty(journal)?;
    let parent = journal
        .journal_path
        .parent()
        .ok_or_else(|| StoreError::UnsafePath(journal.journal_path.clone()))?;
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&journal.journal_path)
        .map_err(|error| StoreError::Io(error.error))?;
    sync_directory(parent)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut file = File::options().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

fn unix_millis() -> Result<i64, StoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StoreError::Clock(error.to_string()))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| StoreError::Clock("timestamp exceeds i64".to_owned()))
}

/// State and transaction error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Filesystem I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// SQLite operation failed.
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    /// Journal or metadata JSON failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A path is unsuitable for a controlled mutation.
    #[error("unsafe transaction path: {0}")]
    UnsafePath(PathBuf),
    /// Target content changed after the plan snapshot.
    #[error("target precondition failed; expected {expected:?}, found {actual:?}")]
    Precondition {
        /// Expected hash.
        expected: Option<String>,
        /// Observed hash.
        actual: Option<String>,
    },
    /// Requested record was absent.
    #[error("not found: {0}")]
    NotFound(String),
    /// Transaction or operation state transition is invalid.
    #[error("invalid state: {0}")]
    InvalidState(String),
    /// The system clock cannot be represented safely.
    #[error("clock error: {0}")]
    Clock(String),
    /// Secure random generation failed.
    #[error("secure random generation failed: {0}")]
    Random(String),
}

const SCHEMA: &str = r"
PRAGMA user_version = 1;
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER,
  metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json))
);
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL REFERENCES operations(id),
  source_root_hash TEXT NOT NULL,
  target_tuple_json TEXT NOT NULL CHECK(json_valid(target_tuple_json)),
  plan_hash TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS plan_items (
  plan_id TEXT NOT NULL REFERENCES plans(id),
  ordinal INTEGER NOT NULL,
  action TEXT NOT NULL,
  locator TEXT NOT NULL,
  before_hash TEXT,
  after_hash TEXT,
  resolution TEXT,
  PRIMARY KEY(plan_id, ordinal)
);
CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL REFERENCES operations(id),
  status TEXT NOT NULL,
  target_locator TEXT NOT NULL,
  before_hash TEXT,
  after_hash TEXT NOT NULL,
  backup_locator TEXT,
  journal_locator TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS backups (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL REFERENCES transactions(id),
  content_hash TEXT NOT NULL,
  local_locator TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS managed_objects (
  target_locator TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  installed_hash TEXT NOT NULL,
  source_asset_id TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS trusted_keys (
  fingerprint TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  label TEXT,
  trusted_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS capability_snapshots (
  hash TEXT PRIMARY KEY,
  product_tuple_json TEXT NOT NULL CHECK(json_valid(product_tuple_json)),
  capabilities_json TEXT NOT NULL CHECK(json_valid(capabilities_json)),
  observed_at_ms INTEGER NOT NULL
);
";

#[cfg(test)]
mod tests {
    use super::{Ledger, OperationStatus, StoreError, apply_file, load_journal, undo_file};

    #[test]
    fn ledger_tracks_terminal_operation() -> Result<(), Box<dyn std::error::Error>> {
        let ledger = Ledger::in_memory()?;
        let id = ledger.begin_operation("inventory", &serde_json::json!({"source": "codex"}))?;
        ledger.finish_operation(&id, OperationStatus::Succeeded)?;
        let record = ledger.operation(&id)?.ok_or("operation missing")?;
        assert_eq!(record.kind, "inventory");
        assert_eq!(record.status, "succeeded");
        assert!(record.finished_at_ms.is_some());
        Ok(())
    }

    #[test]
    fn apply_and_undo_restore_original_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("config/settings.json");
        std::fs::create_dir_all(target.parent().ok_or("target parent absent")?)?;
        std::fs::write(&target, b"before")?;
        let expected = mnemo_security::sha256_id(b"before");
        let mut journal = apply_file(
            &target,
            b"after",
            &temp.path().join("transactions"),
            Some(&expected),
        )?;
        assert_eq!(std::fs::read(&target)?, b"after");
        let persisted = load_journal(&journal.journal_path)?;
        assert_eq!(persisted.status, super::TransactionStatus::Committed);

        undo_file(&mut journal, false)?;
        assert_eq!(std::fs::read(&target)?, b"before");
        assert_eq!(
            load_journal(&journal.journal_path)?.status,
            super::TransactionStatus::RolledBack
        );
        Ok(())
    }

    #[test]
    fn rejects_stale_plan_and_modified_target_on_undo() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("settings.json");
        std::fs::write(&target, b"current")?;
        let result = apply_file(
            &target,
            b"new",
            &temp.path().join("transactions"),
            Some(&mnemo_security::sha256_id(b"stale")),
        );
        assert!(matches!(result, Err(StoreError::Precondition { .. })));

        let mut journal = apply_file(
            &target,
            b"new",
            &temp.path().join("transactions"),
            Some(&mnemo_security::sha256_id(b"current")),
        )?;
        std::fs::write(&target, b"external edit")?;
        assert!(matches!(
            undo_file(&mut journal, false),
            Err(StoreError::Precondition { .. })
        ));
        assert_eq!(std::fs::read(&target)?, b"external edit");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_target() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let real = temp.path().join("real");
        let link = temp.path().join("link");
        std::fs::write(&real, b"protected")?;
        symlink(&real, &link)?;
        assert!(matches!(
            apply_file(&link, b"changed", &temp.path().join("tx"), None),
            Err(StoreError::UnsafePath(_))
        ));
        assert_eq!(std::fs::read(&real)?, b"protected");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_directory() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let outside = temp.path().join("outside");
        let link = temp.path().join("approved/link");
        std::fs::create_dir_all(&outside)?;
        std::fs::create_dir_all(link.parent().ok_or("link parent missing")?)?;
        symlink(&outside, &link)?;
        let target = link.join("settings.json");
        assert!(matches!(
            apply_file(&target, b"changed", &temp.path().join("tx"), None),
            Err(StoreError::UnsafePath(_))
        ));
        assert!(!outside.join("settings.json").exists());
        Ok(())
    }

    #[test]
    fn device_signing_key_is_persistent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let first = super::load_or_create_signing_key(temp.path())?;
        let second = super::load_or_create_signing_key(temp.path())?;
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(
            std::fs::read(temp.path().join("device-signing-key.bin"))?.len(),
            32
        );
        Ok(())
    }
}
