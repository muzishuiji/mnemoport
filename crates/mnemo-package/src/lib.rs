//! Deterministic, signed and optionally encrypted `.mnemo` packages.
//!
//! The signed payload is a zstd-compressed POSIX tar stream. `manifest.json`
//! describes every logical object and `signature.ed25519` authenticates the
//! exact canonical manifest bytes. Encryption wraps the complete signed
//! payload with the interoperable age passphrase format.

use age::secrecy::SecretString;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path};

/// Current package format identifier.
pub const PACKAGE_FORMAT_VERSION: &str = "mnemo/1";
/// Canonical manifest path inside the archive.
pub const MANIFEST_PATH: &str = "manifest.json";
/// Detached signature path inside the archive.
pub const SIGNATURE_PATH: &str = "signature.ed25519";
const OBJECT_PREFIX: &str = "objects/";
const MAX_ENTRIES: usize = 100_000;
const MAX_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Minimal manifest header used for version negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHeader {
    /// Package format.
    pub format_version: String,
    /// Oldest reader that may open this package.
    pub min_reader_version: String,
    /// Features a reader must understand.
    pub required_features: Vec<String>,
    /// Features a reader may preserve without interpreting.
    pub optional_features: Vec<String>,
}

impl Default for ManifestHeader {
    fn default() -> Self {
        Self {
            format_version: PACKAGE_FORMAT_VERSION.to_owned(),
            min_reader_version: "0.1.0".to_owned(),
            required_features: vec!["signed-manifest".to_owned(), "sha256-objects".to_owned()],
            optional_features: Vec::new(),
        }
    }
}

/// One immutable object covered by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectDescriptor {
    /// Portable logical path, always relative and slash-separated.
    pub path: String,
    /// SHA-256 digest with an explicit algorithm prefix.
    pub sha256: String,
    /// Object length in bytes.
    pub size: u64,
}

/// Canonical signed package manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Version-negotiation metadata.
    pub header: ManifestHeader,
    /// Content-derived package identifier.
    pub package_id: String,
    /// Hash over the ordered object descriptors.
    pub root_hash: String,
    /// Hex-encoded Ed25519 verifying key.
    pub signer_public_key: String,
    /// Objects in canonical lexical path order.
    pub objects: Vec<ObjectDescriptor>,
}

/// A package after signature and content verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPackage {
    /// Authenticated manifest.
    pub manifest: PackageManifest,
    /// Authenticated logical object bytes.
    pub objects: BTreeMap<String, Vec<u8>>,
}

/// A newly constructed signed archive and its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPackage {
    /// Zstd-compressed canonical tar payload.
    pub bytes: Vec<u8>,
    /// Manifest stored in `bytes`.
    pub manifest: PackageManifest,
}

/// Package construction or verification failure.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// Logical paths must be safe, normalized and portable.
    #[error("invalid logical object path: {0}")]
    InvalidPath(String),
    /// Two archive records claimed the same path.
    #[error("duplicate archive path: {0}")]
    DuplicatePath(String),
    /// A required archive record is absent.
    #[error("missing archive entry: {0}")]
    MissingEntry(&'static str),
    /// An archive record is not declared by the signed manifest.
    #[error("undeclared archive entry: {0}")]
    UndeclaredEntry(String),
    /// The package uses an unsupported format or feature.
    #[error("unsupported package contract: {0}")]
    Unsupported(String),
    /// A signature, digest or root hash did not validate.
    #[error("package integrity check failed: {0}")]
    Integrity(String),
    /// A configured resource limit was exceeded.
    #[error("package resource limit exceeded: {0}")]
    Limit(String),
    /// Serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Archive or compression I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Passphrase encryption failed without exposing secret material.
    #[error("age encryption failed: {0}")]
    Encryption(String),
    /// Passphrase decryption failed without exposing secret material.
    #[error("age decryption failed: {0}")]
    Decryption(String),
}

/// Incrementally constructs a package in deterministic path order.
#[derive(Debug, Default)]
pub struct PackageBuilder {
    objects: BTreeMap<String, Vec<u8>>,
    required_features: BTreeSet<String>,
}

impl PackageBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one logical object. Duplicate paths are rejected even when bytes
    /// happen to match so a manifest never has ambiguous ownership.
    pub fn insert(&mut self, path: impl Into<String>, bytes: Vec<u8>) -> Result<(), PackageError> {
        let path = path.into();
        validate_logical_path(&path)?;
        if self.objects.contains_key(&path) {
            return Err(PackageError::DuplicatePath(path));
        }
        self.objects.insert(path, bytes);
        Ok(())
    }

    /// Declare a format feature that readers must understand before opening
    /// the package. Added feature names are serialized deterministically.
    pub fn require_feature(&mut self, feature: impl Into<String>) {
        self.required_features.insert(feature.into());
    }

    /// Build a deterministic archive signed by `signing_key`.
    pub fn build(&self, signing_key: &SigningKey) -> Result<SignedPackage, PackageError> {
        let descriptors = self
            .objects
            .iter()
            .map(|(path, bytes)| ObjectDescriptor {
                path: path.clone(),
                sha256: sha256_id(bytes),
                size: bytes.len() as u64,
            })
            .collect::<Vec<_>>();
        let root_hash = descriptor_root_hash(&descriptors);
        let mut header = ManifestHeader::default();
        for feature in &self.required_features {
            if !header.required_features.contains(feature) {
                header.required_features.push(feature.clone());
            }
        }
        let manifest = PackageManifest {
            header,
            package_id: format!("mnemo:{root_hash}"),
            root_hash,
            signer_public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            objects: descriptors,
        };
        let manifest_bytes = canonical_manifest_bytes(&manifest)?;
        let signature: Signature = signing_key.sign(&manifest_bytes);
        let tar = build_tar(&manifest_bytes, &signature.to_bytes(), &self.objects)?;
        let bytes = zstd::stream::encode_all(Cursor::new(tar), 9)?;
        Ok(SignedPackage { bytes, manifest })
    }
}

/// Verify a signed zstd/tar package without writing it to disk.
pub fn verify(bytes: &[u8]) -> Result<VerifiedPackage, PackageError> {
    let tar = read_limited(
        zstd::stream::read::Decoder::new(Cursor::new(bytes))?,
        MAX_UNCOMPRESSED_BYTES,
    )?;
    let records = read_tar(&tar)?;
    let manifest_bytes = records
        .get(MANIFEST_PATH)
        .ok_or(PackageError::MissingEntry(MANIFEST_PATH))?;
    let signature_bytes = records
        .get(SIGNATURE_PATH)
        .ok_or(PackageError::MissingEntry(SIGNATURE_PATH))?;
    let manifest: PackageManifest = serde_json::from_slice(manifest_bytes)?;
    validate_manifest_contract(&manifest)?;
    if canonical_manifest_bytes(&manifest)? != *manifest_bytes {
        return Err(PackageError::Integrity(
            "manifest is not in canonical representation".to_owned(),
        ));
    }

    let public_key_bytes = decode_fixed::<32>(&manifest.signer_public_key, "public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| PackageError::Integrity(format!("invalid public key: {error}")))?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PackageError::Integrity("invalid signature length".to_owned()))?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(manifest_bytes, &signature)
        .map_err(|error| PackageError::Integrity(format!("signature rejected: {error}")))?;

    let expected_paths = manifest
        .objects
        .iter()
        .map(|object| format!("{OBJECT_PREFIX}{}", object.path))
        .collect::<BTreeSet<_>>();
    let actual_paths = records
        .keys()
        .filter(|path| *path != MANIFEST_PATH && *path != SIGNATURE_PATH)
        .cloned()
        .collect::<BTreeSet<_>>();
    if let Some(extra) = actual_paths.difference(&expected_paths).next() {
        return Err(PackageError::UndeclaredEntry(extra.clone()));
    }
    if let Some(missing) = expected_paths.difference(&actual_paths).next() {
        return Err(PackageError::Integrity(format!(
            "declared object is absent: {missing}"
        )));
    }

    let mut objects = BTreeMap::new();
    for descriptor in &manifest.objects {
        validate_logical_path(&descriptor.path)?;
        let archive_path = format!("{OBJECT_PREFIX}{}", descriptor.path);
        let object = records
            .get(&archive_path)
            .ok_or_else(|| PackageError::Integrity(format!("missing object: {archive_path}")))?;
        if object.len() as u64 != descriptor.size || sha256_id(object) != descriptor.sha256 {
            return Err(PackageError::Integrity(format!(
                "object digest or size mismatch: {}",
                descriptor.path
            )));
        }
        objects.insert(descriptor.path.clone(), object.clone());
    }
    if descriptor_root_hash(&manifest.objects) != manifest.root_hash
        || manifest.package_id != format!("mnemo:{}", manifest.root_hash)
    {
        return Err(PackageError::Integrity(
            "manifest root hash or package id mismatch".to_owned(),
        ));
    }

    Ok(VerifiedPackage { manifest, objects })
}

/// Encrypt a complete signed package with an age scrypt recipient.
pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &SecretString,
) -> Result<Vec<u8>, PackageError> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|error| PackageError::Encryption(error.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|error| PackageError::Encryption(error.to_string()))?;
    writer
        .finish()
        .map_err(|error| PackageError::Encryption(error.to_string()))?;
    Ok(encrypted)
}

/// Encrypt a complete signed package to one native age X25519 recipient.
pub fn encrypt_with_recipient(
    plaintext: &[u8],
    recipient: &age::x25519::Recipient,
) -> Result<Vec<u8>, PackageError> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(|error| PackageError::Encryption(error.to_string()))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|error| PackageError::Encryption(error.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|error| PackageError::Encryption(error.to_string()))?;
    writer
        .finish()
        .map_err(|error| PackageError::Encryption(error.to_string()))?;
    Ok(encrypted)
}

/// Decrypt an age passphrase-wrapped package with an output-size limit.
pub fn decrypt_with_passphrase(
    encrypted: &[u8],
    passphrase: SecretString,
) -> Result<Vec<u8>, PackageError> {
    let decryptor = age::Decryptor::new(Cursor::new(encrypted))
        .map_err(|error| PackageError::Decryption(error.to_string()))?;
    let identity = age::scrypt::Identity::new(passphrase);
    let reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|error| PackageError::Decryption(error.to_string()))?;
    read_limited(reader, MAX_UNCOMPRESSED_BYTES)
}

/// Decrypt an age package with one native X25519 identity and an output-size limit.
pub fn decrypt_with_identity(
    encrypted: &[u8],
    identity: &age::x25519::Identity,
) -> Result<Vec<u8>, PackageError> {
    let decryptor = age::Decryptor::new(Cursor::new(encrypted))
        .map_err(|error| PackageError::Decryption(error.to_string()))?;
    let reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|error| PackageError::Decryption(error.to_string()))?;
    read_limited(reader, MAX_UNCOMPRESSED_BYTES)
}

fn validate_manifest_contract(manifest: &PackageManifest) -> Result<(), PackageError> {
    if manifest.header.format_version != PACKAGE_FORMAT_VERSION {
        return Err(PackageError::Unsupported(format!(
            "format {}",
            manifest.header.format_version
        )));
    }
    let supported = ["portable-workspaces", "sha256-objects", "signed-manifest"];
    if let Some(feature) = manifest
        .header
        .required_features
        .iter()
        .find(|feature| !supported.contains(&feature.as_str()))
    {
        return Err(PackageError::Unsupported(format!(
            "required feature {feature}"
        )));
    }
    if manifest.objects.len() > MAX_ENTRIES.saturating_sub(2) {
        return Err(PackageError::Limit(format!(
            "more than {} manifest objects",
            MAX_ENTRIES.saturating_sub(2)
        )));
    }
    let mut previous: Option<&str> = None;
    let mut total_size = 0_u64;
    for object in &manifest.objects {
        validate_logical_path(&object.path)?;
        if previous.is_some_and(|path| path >= object.path.as_str()) {
            return Err(PackageError::Integrity(
                "manifest objects are not strictly ordered and unique".to_owned(),
            ));
        }
        total_size = total_size
            .checked_add(object.size)
            .ok_or_else(|| PackageError::Limit("manifest size overflow".to_owned()))?;
        if total_size > MAX_UNCOMPRESSED_BYTES {
            return Err(PackageError::Limit(format!(
                "manifest declares more than {MAX_UNCOMPRESSED_BYTES} object bytes"
            )));
        }
        previous = Some(&object.path);
    }
    Ok(())
}

fn canonical_manifest_bytes(manifest: &PackageManifest) -> Result<Vec<u8>, PackageError> {
    Ok(serde_json::to_vec(manifest)?)
}

fn descriptor_root_hash(objects: &[ObjectDescriptor]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"mnemoport-object-tree-v1\0");
    for object in objects {
        digest.update(object.path.as_bytes());
        digest.update([0]);
        digest.update(object.sha256.as_bytes());
        digest.update([0]);
        digest.update(object.size.to_be_bytes());
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn sha256_id(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn validate_logical_path(path: &str) -> Result<(), PackageError> {
    if path.is_empty() || path.contains('\\') || path.contains('\0') {
        return Err(PackageError::InvalidPath(path.to_owned()));
    }
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(PackageError::InvalidPath(path.to_owned()));
    }
    Ok(())
}

fn build_tar(
    manifest: &[u8],
    signature: &[u8],
    objects: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, PackageError> {
    let mut output = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut output);
        builder.mode(tar::HeaderMode::Deterministic);
        append_tar_file(&mut builder, MANIFEST_PATH, manifest)?;
        append_tar_file(&mut builder, SIGNATURE_PATH, signature)?;
        for (path, bytes) in objects {
            append_tar_file(&mut builder, &format!("{OBJECT_PREFIX}{path}"), bytes)?;
        }
        builder.finish()?;
    }
    Ok(output)
}

fn append_tar_file<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, Cursor::new(bytes))
}

fn read_tar(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, PackageError> {
    let mut records = BTreeMap::new();
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    for (index, entry) in archive.entries()?.enumerate() {
        if index >= MAX_ENTRIES {
            return Err(PackageError::Limit(format!(
                "more than {MAX_ENTRIES} archive entries"
            )));
        }
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            return Err(PackageError::Integrity(
                "non-regular archive entry".to_owned(),
            ));
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        validate_logical_path(&path)?;
        let content = read_limited(&mut entry, MAX_UNCOMPRESSED_BYTES)?;
        if records.insert(path.clone(), content).is_some() {
            return Err(PackageError::DuplicatePath(path));
        }
    }
    Ok(records)
}

fn read_limited<R: Read>(reader: R, limit: u64) -> Result<Vec<u8>, PackageError> {
    let mut output = Vec::new();
    let mut limited = reader.take(limit + 1);
    limited.read_to_end(&mut output)?;
    if output.len() as u64 > limit {
        return Err(PackageError::Limit(format!("more than {limit} bytes")));
    }
    Ok(output)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], PackageError> {
    let decoded = hex::decode(value)
        .map_err(|error| PackageError::Integrity(format!("invalid {label}: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| PackageError::Integrity(format!("invalid {label} length")))
}

#[cfg(test)]
mod tests {
    use super::{
        PackageBuilder, PackageError, decrypt_with_identity, decrypt_with_passphrase,
        encrypt_with_passphrase, encrypt_with_recipient,
    };
    use age::secrecy::SecretString;
    use ed25519_dalek::SigningKey;

    fn fixture() -> Result<(SigningKey, super::SignedPackage), PackageError> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut builder = PackageBuilder::new();
        builder.insert("memory/global.md", b"likes concise output\n".to_vec())?;
        builder.insert("skills/example/SKILL.md", b"# Example\n".to_vec())?;
        let package = builder.build(&key)?;
        Ok((key, package))
    }

    #[test]
    fn build_is_deterministic_and_verifiable() -> Result<(), Box<dyn std::error::Error>> {
        let (key, package) = fixture()?;
        let mut other = PackageBuilder::new();
        other.insert("skills/example/SKILL.md", b"# Example\n".to_vec())?;
        other.insert("memory/global.md", b"likes concise output\n".to_vec())?;
        let rebuilt = other.build(&key)?;
        assert_eq!(package.bytes, rebuilt.bytes);

        let verified = super::verify(&package.bytes)?;
        assert_eq!(verified.manifest, package.manifest);
        assert_eq!(verified.objects.len(), 2);
        Ok(())
    }

    #[test]
    fn rejects_modified_object() -> Result<(), Box<dyn std::error::Error>> {
        let (_, package) = fixture()?;
        let tar = zstd::stream::decode_all(std::io::Cursor::new(package.bytes))?;
        let needle = b"likes concise output";
        let position = tar
            .windows(needle.len())
            .position(|window| window == needle)
            .ok_or("fixture content absent from tar")?;
        let mut modified = tar;
        modified[position] = b'L';
        let compressed = zstd::stream::encode_all(std::io::Cursor::new(modified), 9)?;
        assert!(matches!(
            super::verify(&compressed),
            Err(PackageError::Integrity(_))
        ));
        Ok(())
    }

    #[test]
    fn age_passphrase_round_trip_and_wrong_key_rejection() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_, package) = fixture()?;
        let passphrase = SecretString::from("correct horse battery staple".to_owned());
        let encrypted = encrypt_with_passphrase(&package.bytes, &passphrase)?;
        assert_ne!(encrypted, package.bytes);
        let decrypted = decrypt_with_passphrase(encrypted.as_slice(), passphrase)?;
        assert_eq!(decrypted, package.bytes);
        assert!(
            decrypt_with_passphrase(
                encrypted.as_slice(),
                SecretString::from("incorrect".to_owned())
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn age_recipient_round_trip_and_wrong_identity_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, package) = fixture()?;
        let identity = age::x25519::Identity::generate();
        let encrypted = encrypt_with_recipient(&package.bytes, &identity.to_public())?;
        let decrypted = decrypt_with_identity(&encrypted, &identity)?;
        assert_eq!(decrypted, package.bytes);

        let wrong_identity = age::x25519::Identity::generate();
        assert!(decrypt_with_identity(&encrypted, &wrong_identity).is_err());
        assert!(
            decrypt_with_passphrase(
                &encrypted,
                SecretString::from("this-is-not-the-right-secret".to_owned())
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_traversal_paths_before_packaging() {
        let mut builder = PackageBuilder::new();
        assert!(matches!(
            builder.insert("../credentials", Vec::new()),
            Err(PackageError::InvalidPath(_))
        ));
        assert!(matches!(
            builder.insert("C:\\credentials", Vec::new()),
            Err(PackageError::InvalidPath(_))
        ));
    }

    #[test]
    fn rejects_duplicate_logical_paths() -> Result<(), PackageError> {
        let mut builder = PackageBuilder::new();
        builder.insert("assets/a.json", b"first".to_vec())?;
        assert!(matches!(
            builder.insert("assets/a.json", b"second".to_vec()),
            Err(PackageError::DuplicatePath(_))
        ));
        Ok(())
    }
}
