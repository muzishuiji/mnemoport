//! Deterministic fingerprints, path policy and content scanning.

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path};

/// Return a stable SHA-256 identifier without exposing input content.
#[must_use]
pub fn sha256_id(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Potentially identifying but not normally an authentication secret.
    Private,
    /// Likely credential or private key; export must redact or refuse.
    Secret,
    /// Active content requiring quarantine and review.
    ActiveContent,
}

/// Sanitized scanner finding. Matched plaintext is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanFinding {
    /// Stable rule id.
    pub rule_id: String,
    /// Finding severity.
    pub severity: FindingSeverity,
    /// Logical source locator.
    pub locator: String,
    /// Hash of only the matching bytes.
    pub match_hash: String,
    /// UTF-8 byte offset in the inspected object.
    pub byte_start: usize,
    /// Exclusive UTF-8 byte offset.
    pub byte_end: usize,
    /// Deterministic handling decision.
    pub disposition: String,
}

/// Scanner output safe for logs and package reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Hash of the full inspected object.
    pub object_hash: String,
    /// Sanitized findings.
    pub findings: Vec<ScanFinding>,
    /// Whether content must be quarantined instead of directly applied.
    pub quarantined: bool,
}

/// Scanner output paired with a deterministic redacted representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedContent {
    /// Safe report without matched plaintext.
    pub report: ScanReport,
    /// UTF-8 content with secret-like spans replaced.
    pub redacted: String,
}

/// Security policy error.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// Input was not valid UTF-8 text.
    #[error("content at {0} is not valid UTF-8")]
    NonUtf8(String),
    /// A built-in scanner expression failed to compile.
    #[error("scanner rule failed: {0}")]
    Rule(String),
    /// A portable logical path violated policy.
    #[error("unsafe portable path: {0}")]
    UnsafePath(String),
}

#[derive(Debug)]
struct Rule {
    id: &'static str,
    severity: FindingSeverity,
    expression: &'static str,
    disposition: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        id: "private-key-block",
        severity: FindingSeverity::Secret,
        expression: r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        disposition: "exclude",
    },
    Rule {
        id: "authorization-bearer",
        severity: FindingSeverity::Secret,
        expression: r"(?i)authorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+\-/=]{12,}",
        disposition: "redact",
    },
    Rule {
        id: "secret-assignment",
        severity: FindingSeverity::Secret,
        expression: r#"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']?[A-Za-z0-9._~+\-/=]{12,}"#,
        disposition: "redact",
    },
    Rule {
        id: "provider-token",
        severity: FindingSeverity::Secret,
        expression: r"(?:sk|gh[opusr]|xox[baprs]|glpat|npm)[-_][A-Za-z0-9_-]{16,}",
        disposition: "redact",
    },
    Rule {
        id: "aws-access-key",
        severity: FindingSeverity::Secret,
        expression: r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        disposition: "redact",
    },
    Rule {
        id: "google-api-key",
        severity: FindingSeverity::Secret,
        expression: r"AIza[A-Za-z0-9_-]{30,}",
        disposition: "redact",
    },
    Rule {
        id: "jwt-token",
        severity: FindingSeverity::Secret,
        expression: r"eyJ[A-Za-z0-9_-]{9,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        disposition: "redact",
    },
    Rule {
        id: "credential-url",
        severity: FindingSeverity::Secret,
        expression: r"https?://[^\s/@:]+:[^\s/@]+@[^\s/]+",
        disposition: "redact",
    },
    Rule {
        id: "email-address",
        severity: FindingSeverity::Private,
        expression: r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
        disposition: "review",
    },
    Rule {
        id: "active-shell",
        severity: FindingSeverity::ActiveContent,
        expression: r"(?m)^#!\s*(?:/usr/bin/env\s+|/(?:usr/)?bin/)(?:ba|z|fi)?sh\b",
        disposition: "quarantine",
    },
];

/// Scan UTF-8 content and redact credential-like spans without logging them.
pub fn scan_and_redact(locator: &str, bytes: &[u8]) -> Result<ScannedContent, SecurityError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| SecurityError::NonUtf8(locator.to_owned()))?;
    let mut matches = Vec::new();
    for rule in RULES {
        let expression = Regex::new(rule.expression)
            .map_err(|error| SecurityError::Rule(format!("{}: {error}", rule.id)))?;
        for matched in expression.find_iter(text) {
            matches.push((matched.start(), matched.end(), rule));
        }
    }
    matches.sort_by_key(|(start, end, rule)| (*start, *end, rule.id));

    let findings = matches
        .iter()
        .map(|(start, end, rule)| ScanFinding {
            rule_id: rule.id.to_owned(),
            severity: rule.severity,
            locator: locator.to_owned(),
            match_hash: sha256_id(&bytes[*start..*end]),
            byte_start: *start,
            byte_end: *end,
            disposition: rule.disposition.to_owned(),
        })
        .collect::<Vec<_>>();
    let quarantined = findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::ActiveContent);

    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, rule) in matches
        .iter()
        .filter(|(_, _, rule)| rule.severity == FindingSeverity::Secret)
    {
        if *start < cursor {
            continue;
        }
        redacted.push_str(&text[cursor..*start]);
        redacted.push_str("<redacted:");
        redacted.push_str(rule.id);
        redacted.push('>');
        cursor = *end;
    }
    redacted.push_str(&text[cursor..]);
    Ok(ScannedContent {
        report: ScanReport {
            object_hash: sha256_id(bytes),
            findings,
            quarantined,
        },
        redacted,
    })
}

/// Validate a relative, normalized, cross-platform logical path.
pub fn validate_portable_path(path: &str) -> Result<(), SecurityError> {
    if path.is_empty()
        || path.contains('\0')
        || path.contains('\\')
        || path.starts_with("//")
        || path
            .chars()
            .any(|character| character.is_control() || r#":<>"|?*"#.contains(character))
        || has_windows_drive_prefix(path)
        || path.split('/').any(invalid_portable_segment)
    {
        return Err(SecurityError::UnsafePath(path.to_owned()));
    }
    if Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SecurityError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn invalid_portable_segment(segment: &str) -> bool {
    if segment.is_empty() || matches!(segment, "." | "..") || segment.ends_with(['.', ' ']) {
        return true;
    }
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

/// Return duplicate logical paths after Unicode-preserving, case-folded target
/// comparison. Adapters can use this before writing to case-insensitive hosts.
#[must_use]
pub fn case_fold_collisions<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut collisions = BTreeSet::new();
    for path in paths {
        let folded = path.to_lowercase();
        if !seen.insert(folded) {
            collisions.insert(path.to_owned());
        }
    }
    collisions.into_iter().collect()
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::{FindingSeverity, scan_and_redact, sha256_id, validate_portable_path};

    #[test]
    fn sha256_identifier_is_stable() {
        assert_eq!(
            sha256_id(b"mnemoport"),
            "sha256:3d1977f1ec9653773fb1cc5dd21310130b458deaea5b96e1fc3582d28f405471"
        );
    }

    #[test]
    fn secret_report_never_contains_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        let secret = ["sk", "abcdefghijklmnopqrstuvwx"].join("-");
        let source = format!("token={secret}\ncontact=owner@example.com\n");
        let scanned = scan_and_redact("config.json", source.as_bytes())?;
        let report = serde_json::to_string(&scanned.report)?;
        assert!(!report.contains(&secret));
        assert!(!scanned.redacted.contains(&secret));
        assert!(scanned.redacted.contains("<redacted:provider-token>"));
        assert!(
            scanned
                .report
                .findings
                .iter()
                .any(|finding| finding.severity == FindingSeverity::Private)
        );
        Ok(())
    }

    #[test]
    fn executable_text_is_quarantined() -> Result<(), Box<dyn std::error::Error>> {
        let scanned = scan_and_redact("skill/run.sh", b"#!/usr/bin/env bash\necho safe\n")?;
        assert!(scanned.report.quarantined);
        Ok(())
    }

    #[test]
    fn portable_path_policy_rejects_escape_forms() {
        assert!(validate_portable_path("skills/demo/SKILL.md").is_ok());
        for unsafe_path in [
            "../secret",
            "/etc/passwd",
            "C:/Users/name",
            "a\\b",
            "a//../b",
        ] {
            assert!(validate_portable_path(unsafe_path).is_err());
        }
    }
}
