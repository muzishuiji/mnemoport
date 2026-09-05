//! Cross-platform negative corpus for portable paths and credential redaction.

use mnemo_security::{FindingSeverity, scan_and_redact, validate_portable_path};

#[test]
fn rejects_cross_platform_escape_and_device_path_corpus() {
    let unsafe_paths = [
        "",
        "../x",
        "a/../x",
        "./x",
        "a/./x",
        "/etc/passwd",
        "//server/share",
        "C:/Users/name",
        "z:/tmp",
        "a\\b",
        "a//b",
        "a/",
        "CON",
        "con.txt",
        "PRN",
        "AUX.md",
        "NUL",
        "COM1",
        "COM9.txt",
        "LPT1",
        "lpt9.log",
        "file.",
        "file ",
        "a/file.",
        "a/file ",
        "a:b",
        "a<b",
        "a>b",
        "a\"b",
        "a|b",
        "a?b",
        "a*b",
        "line\nfeed",
        "tab\tname",
        "dir/../secret",
        "dir/./file",
        "dir//file",
        "skills/C:/file",
        "skills/COM2/readme",
        "skills/NUL.json",
        "\\\\host\\share",
        "D:\\private",
        "trailing/",
        "double///slash",
        "./",
        "..",
        "a/..",
        "a/.",
        "LPT3.yaml",
        "COM4.md",
        "aux",
        "prn.json",
        "nul.txt",
        "folder/name*",
        "x:y/z",
    ];
    assert!(unsafe_paths.len() >= 50);
    for path in unsafe_paths {
        assert!(
            validate_portable_path(path).is_err(),
            "unsafe corpus path was accepted: {path:?}"
        );
    }
}

#[test]
fn accepts_representative_portable_path_corpus() {
    let safe_paths = [
        "AGENTS.md",
        ".agents/skills/review/SKILL.md",
        ".cursor/rules/api.mdc",
        "skills/name_with-dash/file.json",
        "unicode/记忆.md",
        "handoff/capsule.json",
        "mcp/config.toml",
        "a/b/c.txt",
        ".hidden/file",
        "plugin.json",
    ];
    for path in safe_paths {
        assert!(
            validate_portable_path(path).is_ok(),
            "safe path rejected: {path}"
        );
    }
}

#[test]
fn redacts_provider_and_assignment_canary_corpus_without_echoing_values()
-> Result<(), Box<dyn std::error::Error>> {
    let long = "abcdefghijklmnopqrstuvwxyz123456";
    let canaries = vec![
        format!("sk-{long}"),
        format!("ghp_{long}"),
        format!("gho_{long}"),
        format!("ghu_{long}"),
        format!("ghs_{long}"),
        format!("ghr_{long}"),
        format!("xoxb-{long}"),
        format!("xoxp-{long}"),
        format!("xoxa-{long}"),
        format!("xoxr-{long}"),
        format!("glpat-{long}"),
        format!("npm_{long}"),
        format!("AKIA{}", "ABCDEFGHIJKLMNOP"),
        format!("ASIA{}", "ABCDEFGHIJKLMNOP"),
        format!("AIza{long}7890"),
        format!(
            "eyJ{}.{}.{}",
            "abcdefghijk", "abcdefghijklmnop", "abcdefghijklmnop"
        ),
        format!("Authorization: Bearer {long}"),
        format!("api_key={long}"),
        format!("access-token: {long}"),
        format!("auth_token='{long}'"),
        format!("client-secret={long}"),
        format!("password={long}"),
        format!("https://identity:{long}@example.test/path"),
        ["-----BEGIN OPENSSH", "PRIVATE KEY-----"].join(" "),
    ];
    for (index, canary) in canaries.iter().enumerate() {
        let scanned = scan_and_redact(&format!("fixture/{index}.txt"), canary.as_bytes())?;
        assert!(
            scanned
                .report
                .findings
                .iter()
                .any(|finding| finding.severity == FindingSeverity::Secret),
            "secret canary was missed at index {index}"
        );
        assert!(!scanned.redacted.contains(canary));
        assert!(!serde_json::to_string(&scanned.report)?.contains(canary));
    }
    Ok(())
}
