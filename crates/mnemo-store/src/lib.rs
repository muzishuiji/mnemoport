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
    if let Some(root) = std::env::var_os("MNEMOPORT_STATE_ROOT").filter(|value| !value.is_empty()) {
        let root = PathBuf::from(root);
        return Some(StatePaths {
            config: root.join("config"),
            data: root.join("data"),
            cache: root.join("cache"),
            transactions: root.join("data/transactions"),
        });
    }

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

/// Read-only classification of an interrupted prepared transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryDisposition {
    /// The target still has its pre-transaction state; only the journal needs closing.
    MarkRolledBack,
    /// The target has the intended post-transaction bytes and can be restored safely.
    RestoreBackup,
    /// The target matches neither recorded state and requires user investigation.
    ManualReview,
}

/// Evidence for one prepared transaction found after an interrupted process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCandidate {
    /// Transaction identifier and transaction-directory name.
    pub transaction_id: String,
    /// Target whose state was being changed.
    pub target: PathBuf,
    /// Hash before the attempted mutation, absent if the target was new.
    pub before_hash: Option<String>,
    /// Hash the transaction intended to install.
    pub after_hash: String,
    /// Hash currently found at the target, absent if it does not exist.
    pub current_hash: Option<String>,
    /// Safe action inferred only from exact hashes.
    pub disposition: RecoveryDisposition,
    /// Durable journal used for explicit recovery.
    pub journal_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyCheckpoint {
    BackupSynced,
    PreparedJournalSynced,
    TargetTemporarySynced,
    TargetPersisted,
    TargetDirectorySynced,
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
    apply_file_inner(
        target,
        new_bytes,
        transaction_root,
        expected_before_hash,
        |_| Ok(()),
    )
}

fn apply_file_inner(
    target: &Path,
    new_bytes: &[u8],
    transaction_root: &Path,
    expected_before_hash: Option<&str>,
    mut checkpoint: impl FnMut(ApplyCheckpoint) -> Result<(), StoreError>,
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
    checkpoint(ApplyCheckpoint::BackupSynced)?;
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
    checkpoint(ApplyCheckpoint::PreparedJournalSynced)?;

    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(new_bytes)?;
    if let Ok(metadata) = fs::metadata(target) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())?;
    }
    temporary.as_file().sync_all()?;
    checkpoint(ApplyCheckpoint::TargetTemporarySynced)?;
    temporary
        .persist(target)
        .map_err(|error| StoreError::Io(error.error))?;
    checkpoint(ApplyCheckpoint::TargetPersisted)?;
    sync_directory(parent)?;
    checkpoint(ApplyCheckpoint::TargetDirectorySynced)?;

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
    restore_before(journal)?;
    journal.status = TransactionStatus::RolledBack;
    save_journal(journal)?;
    Ok(())
}

/// Load a durable file transaction journal.
pub fn load_journal(path: &Path) -> Result<FileTransactionJournal, StoreError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Find prepared journals left by an interrupted process without changing targets.
pub fn scan_recovery_candidates(
    transaction_root: &Path,
) -> Result<Vec<RecoveryCandidate>, StoreError> {
    let entries = match fs::read_dir(transaction_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let journal_path = entry.path().join("journal.json");
        reject_symlink_ancestors(&journal_path)?;
        let journal = match load_journal(&journal_path) {
            Ok(journal) => journal,
            Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        validate_recovery_journal(transaction_root, &journal_path, &journal)?;
        if journal.status == TransactionStatus::Prepared {
            candidates.push(classify_recovery(&journal));
        }
    }
    candidates.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
    Ok(candidates)
}

/// Roll back one prepared transaction only when exact hashes make recovery unambiguous.
pub fn rollback_prepared_transaction(
    transaction_root: &Path,
    transaction_id: &str,
) -> Result<FileTransactionJournal, StoreError> {
    let parsed = Uuid::parse_str(transaction_id)
        .map_err(|_| StoreError::InvalidState("invalid recovery transaction id".to_owned()))?;
    if parsed.to_string() != transaction_id {
        return Err(StoreError::InvalidState(
            "recovery transaction id must use canonical UUID form".to_owned(),
        ));
    }
    let journal_path = transaction_root.join(transaction_id).join("journal.json");
    reject_symlink_ancestors(&journal_path)?;
    let mut journal = load_journal(&journal_path)?;
    validate_recovery_journal(transaction_root, &journal_path, &journal)?;
    if journal.status != TransactionStatus::Prepared {
        return Err(StoreError::InvalidState(format!(
            "transaction {} is not awaiting recovery",
            journal.id
        )));
    }
    let candidate = classify_recovery(&journal);
    match candidate.disposition {
        RecoveryDisposition::MarkRolledBack => {}
        RecoveryDisposition::RestoreBackup => restore_before(&journal)?,
        RecoveryDisposition::ManualReview => {
            return Err(StoreError::Precondition {
                expected: Some(journal.after_hash.clone()),
                actual: candidate.current_hash,
            });
        }
    }
    journal.status = TransactionStatus::RolledBack;
    save_journal(&journal)?;
    Ok(journal)
}

fn classify_recovery(journal: &FileTransactionJournal) -> RecoveryCandidate {
    let current_hash = fs::read(&journal.target)
        .ok()
        .map(|bytes| sha256_id(&bytes));
    let disposition = if current_hash == journal.before_hash {
        RecoveryDisposition::MarkRolledBack
    } else if current_hash.as_deref() == Some(journal.after_hash.as_str()) {
        RecoveryDisposition::RestoreBackup
    } else {
        RecoveryDisposition::ManualReview
    };
    RecoveryCandidate {
        transaction_id: journal.id.clone(),
        target: journal.target.clone(),
        before_hash: journal.before_hash.clone(),
        after_hash: journal.after_hash.clone(),
        current_hash,
        disposition,
        journal_path: journal.journal_path.clone(),
    }
}

fn validate_recovery_journal(
    transaction_root: &Path,
    journal_path: &Path,
    journal: &FileTransactionJournal,
) -> Result<(), StoreError> {
    let parsed = Uuid::parse_str(&journal.id)
        .map_err(|_| StoreError::InvalidState("journal transaction id is invalid".to_owned()))?;
    if parsed.to_string() != journal.id {
        return Err(StoreError::InvalidState(
            "journal transaction id is not canonical".to_owned(),
        ));
    }
    let expected_dir = transaction_root.join(&journal.id);
    let expected_journal = expected_dir.join("journal.json");
    if journal_path != expected_journal || journal.journal_path != expected_journal {
        return Err(StoreError::InvalidState(
            "journal locator escapes its transaction directory".to_owned(),
        ));
    }
    if !journal.target.is_absolute() {
        return Err(StoreError::InvalidState(
            "recovery target must be absolute".to_owned(),
        ));
    }
    if fs::symlink_metadata(&journal.target).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(StoreError::UnsafePath(journal.target.clone()));
    }
    match (&journal.before_hash, &journal.backup) {
        (Some(_), Some(path)) if path == &expected_dir.join("before.bin") => {}
        (None, None) => {}
        _ => {
            return Err(StoreError::InvalidState(
                "journal backup locator is inconsistent".to_owned(),
            ));
        }
    }
    reject_symlink_ancestors(&expected_dir)?;
    Ok(())
}

fn restore_before(journal: &FileTransactionJournal) -> Result<(), StoreError> {
    if let Some(expected_before) = journal.before_hash.as_deref() {
        let backup = journal.backup.as_ref().ok_or_else(|| {
            StoreError::InvalidState("existing target has no rollback backup".to_owned())
        })?;
        if fs::symlink_metadata(backup).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(StoreError::UnsafePath(backup.clone()));
        }
        let bytes = fs::read(backup)?;
        let actual = sha256_id(&bytes);
        if actual != expected_before {
            return Err(StoreError::InvalidState(
                "rollback backup hash does not match the journal".to_owned(),
            ));
        }
        replace_file(&journal.target, &bytes)?;
    } else {
        if journal.backup.is_some() {
            return Err(StoreError::InvalidState(
                "new target journal unexpectedly contains a backup".to_owned(),
            ));
        }
        if journal.target.exists() {
            reject_symlink_ancestors(
                journal
                    .target
                    .parent()
                    .ok_or_else(|| StoreError::UnsafePath(journal.target.clone()))?,
            )?;
            fs::remove_file(&journal.target)?;
            if let Some(parent) = journal.target.parent() {
                sync_directory(parent)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn apply_file_with_fault(
    target: &Path,
    new_bytes: &[u8],
    transaction_root: &Path,
    expected_before_hash: Option<&str>,
    failure_point: ApplyCheckpoint,
) -> Result<FileTransactionJournal, StoreError> {
    apply_file_inner(
        target,
        new_bytes,
        transaction_root,
        expected_before_hash,
        |checkpoint| {
            if checkpoint == failure_point {
                Err(StoreError::InvalidState(format!(
                    "injected failure at {checkpoint:?}"
                )))
            } else {
                Ok(())
            }
        },
    )
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
    use super::{
        ApplyCheckpoint, Ledger, OperationStatus, RecoveryDisposition, StoreError, apply_file,
        apply_file_with_fault, load_journal, rollback_prepared_transaction,
        scan_recovery_candidates, undo_file,
    };

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
        let root = temp.path().canonicalize()?;
        let target = root.join("config/settings.json");
        std::fs::create_dir_all(target.parent().ok_or("target parent absent")?)?;
        std::fs::write(&target, b"before")?;
        let expected = mnemo_security::sha256_id(b"before");
        let mut journal = apply_file(
            &target,
            b"after",
            &root.join("transactions"),
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
    fn recovery_closes_prepared_journals_before_target_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        for failure_point in [
            ApplyCheckpoint::PreparedJournalSynced,
            ApplyCheckpoint::TargetTemporarySynced,
        ] {
            let temp = tempfile::tempdir()?;
            let root = temp.path().canonicalize()?;
            let target = root.join("config/settings.json");
            let transactions = root.join("transactions");
            std::fs::create_dir_all(target.parent().ok_or("target parent absent")?)?;
            std::fs::write(&target, b"before")?;
            let result = apply_file_with_fault(
                &target,
                b"after",
                &transactions,
                Some(&mnemo_security::sha256_id(b"before")),
                failure_point,
            );
            assert!(matches!(result, Err(StoreError::InvalidState(_))));
            assert_eq!(std::fs::read(&target)?, b"before");

            let candidates = scan_recovery_candidates(&transactions)?;
            assert_eq!(candidates.len(), 1);
            assert_eq!(
                candidates[0].disposition,
                RecoveryDisposition::MarkRolledBack
            );
            let recovered =
                rollback_prepared_transaction(&transactions, &candidates[0].transaction_id)?;
            assert_eq!(recovered.status, super::TransactionStatus::RolledBack);
            assert_eq!(std::fs::read(&target)?, b"before");
            assert!(scan_recovery_candidates(&transactions)?.is_empty());
        }
        Ok(())
    }

    #[test]
    fn recovery_restores_backup_after_target_persist() -> Result<(), Box<dyn std::error::Error>> {
        for failure_point in [
            ApplyCheckpoint::TargetPersisted,
            ApplyCheckpoint::TargetDirectorySynced,
        ] {
            let temp = tempfile::tempdir()?;
            let root = temp.path().canonicalize()?;
            let target = root.join("settings.json");
            let transactions = root.join("transactions");
            std::fs::write(&target, b"before")?;
            let result = apply_file_with_fault(
                &target,
                b"after",
                &transactions,
                Some(&mnemo_security::sha256_id(b"before")),
                failure_point,
            );
            assert!(matches!(result, Err(StoreError::InvalidState(_))));
            assert_eq!(std::fs::read(&target)?, b"after");

            let candidates = scan_recovery_candidates(&transactions)?;
            assert_eq!(candidates.len(), 1);
            assert_eq!(
                candidates[0].disposition,
                RecoveryDisposition::RestoreBackup
            );
            rollback_prepared_transaction(&transactions, &candidates[0].transaction_id)?;
            assert_eq!(std::fs::read(&target)?, b"before");
        }
        Ok(())
    }

    #[test]
    fn recovery_removes_a_new_target_but_refuses_external_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let transactions = root.join("transactions");
        let new_target = root.join("new.txt");
        let result = apply_file_with_fault(
            &new_target,
            b"created",
            &transactions,
            None,
            ApplyCheckpoint::TargetPersisted,
        );
        assert!(matches!(result, Err(StoreError::InvalidState(_))));
        let candidate = scan_recovery_candidates(&transactions)?
            .pop()
            .ok_or("new target recovery candidate missing")?;
        rollback_prepared_transaction(&transactions, &candidate.transaction_id)?;
        assert!(!new_target.exists());

        let drift_target = root.join("drift.txt");
        std::fs::write(&drift_target, b"before")?;
        let result = apply_file_with_fault(
            &drift_target,
            b"after",
            &transactions,
            Some(&mnemo_security::sha256_id(b"before")),
            ApplyCheckpoint::TargetPersisted,
        );
        assert!(matches!(result, Err(StoreError::InvalidState(_))));
        std::fs::write(&drift_target, b"external edit")?;
        let candidate = scan_recovery_candidates(&transactions)?
            .pop()
            .ok_or("drift recovery candidate missing")?;
        assert_eq!(candidate.disposition, RecoveryDisposition::ManualReview);
        assert!(matches!(
            rollback_prepared_transaction(&transactions, &candidate.transaction_id),
            Err(StoreError::Precondition { .. })
        ));
        assert_eq!(std::fs::read(&drift_target)?, b"external edit");
        Ok(())
    }

    #[test]
    fn undo_rejects_a_tampered_backup() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let target = root.join("settings.json");
        std::fs::write(&target, b"before")?;
        let mut journal = apply_file(
            &target,
            b"after",
            &root.join("transactions"),
            Some(&mnemo_security::sha256_id(b"before")),
        )?;
        std::fs::write(
            journal.backup.as_ref().ok_or("backup missing")?,
            b"tampered",
        )?;
        assert!(matches!(
            undo_file(&mut journal, false),
            Err(StoreError::InvalidState(_))
        ));
        assert_eq!(std::fs::read(&target)?, b"after");
        Ok(())
    }

    #[test]
    fn rejects_stale_plan_and_modified_target_on_undo() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let target = root.join("settings.json");
        std::fs::write(&target, b"current")?;
        let result = apply_file(
            &target,
            b"new",
            &root.join("transactions"),
            Some(&mnemo_security::sha256_id(b"stale")),
        );
        assert!(matches!(result, Err(StoreError::Precondition { .. })));

        let mut journal = apply_file(
            &target,
            b"new",
            &root.join("transactions"),
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
        let root = temp.path().canonicalize()?;
        let real = root.join("real");
        let link = root.join("link");
        std::fs::write(&real, b"protected")?;
        symlink(&real, &link)?;
        assert!(matches!(
            apply_file(&link, b"changed", &root.join("tx"), None),
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
        let root = temp.path().canonicalize()?;
        let outside = root.join("outside");
        let link = root.join("approved/link");
        std::fs::create_dir_all(&outside)?;
        std::fs::create_dir_all(link.parent().ok_or("link parent missing")?)?;
        symlink(&outside, &link)?;
        let target = link.join("settings.json");
        assert!(matches!(
            apply_file(&target, b"changed", &root.join("tx"), None),
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
