//! `cargo deny` subprocess invocation + NDJSON parsing.
//!
//! `cargo deny --format json check` emits one JSON object per line.
//! Diagnostic records look like:
//!
//! ```text
//! { "type": "diagnostic",
//!   "fields": { "severity": "error", "code": "L001",
//!               "message": "license `GPL-3.0` not allowed",
//!               "graphs": [...], "labels": [...] } }
//! ```
//!
//! Non-diagnostic records (`summary`, `note`) are filtered out.

use std::path::Path;
use std::process::Command;

use dev_report::Severity;
use serde::Deserialize;

use crate::{AuditError, Finding, FindingSource};

pub(crate) fn run(
    workdir: Option<&Path>,
    config: Option<&Path>,
) -> Result<Vec<Finding>, AuditError> {
    detect()?;
    let mut cmd = Command::new("cargo");
    cmd.args(["deny", "--format", "json"]);
    if let Some(c) = config {
        cmd.args(["--config", &c.to_string_lossy()]);
    }
    cmd.arg("check");
    if let Some(d) = workdir {
        cmd.current_dir(d);
    }
    let output = cmd
        .output()
        .map_err(|e| AuditError::SubprocessFailed(e.to_string()))?;
    // cargo-deny exits non-zero when it finds policy violations; that
    // is the success path. We still parse stdout regardless of exit code.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if stdout.trim().is_empty() && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(AuditError::SubprocessFailed(stderr));
    }
    parse(&stdout)
}

fn detect() -> Result<(), AuditError> {
    let out = Command::new("cargo").args(["deny", "--version"]).output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err(AuditError::DenyToolNotInstalled),
    }
}

// ---------------------------------------------------------------------------
// NDJSON shape
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DenyRecord {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    fields: DenyFields,
}

#[derive(Deserialize, Default)]
struct DenyFields {
    #[serde(default)]
    severity: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: String,
    #[serde(default)]
    graphs: Vec<DenyGraph>,
}

/// Each graph node carries `name` and `version` for the affected crate.
#[derive(Deserialize, Default, Clone)]
struct DenyGraph {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

pub(crate) fn parse(ndjson: &str) -> Result<Vec<Finding>, AuditError> {
    let mut findings = Vec::new();
    for (line_num, raw) in ndjson.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let record: DenyRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            // Skip non-JSON or non-record lines — cargo-deny occasionally
            // emits human-readable noise even under --format json.
            Err(_) => continue,
        };
        if record.kind != "diagnostic" {
            continue;
        }
        let Some(severity) = severity_from_label(&record.fields.severity) else {
            continue;
        };

        // Prefer the diagnostic's code (e.g. "license-not-allowed") as
        // the stable identifier; fall back to a synthetic line-number id.
        let id = record
            .fields
            .code
            .clone()
            .unwrap_or_else(|| format!("DENY-{:04}", line_num + 1));

        // Empty `graphs` is legitimate (e.g. a workspace-level policy
        // violation); represent it explicitly rather than emitting an
        // invalid empty-string crate name.
        let (affected_crate, affected_version) = record
            .fields
            .graphs
            .first()
            .map(|g| (non_empty_string(&g.name), non_empty(&g.version)))
            .unwrap_or((None, None));

        findings.push(Finding {
            id,
            title: short_title(&record.fields.message),
            severity,
            affected_crate: affected_crate.unwrap_or_else(|| "<workspace>".to_string()),
            affected_version,
            url: None,
            description: if record.fields.message.is_empty() {
                None
            } else {
                Some(record.fields.message)
            },
            source: FindingSource::Deny,
        });
    }
    Ok(findings)
}

fn severity_from_label(label: &str) -> Option<Severity> {
    match label.to_ascii_lowercase().as_str() {
        "error" => Some(Severity::Error),
        "warning" => Some(Severity::Warning),
        "help" | "note" => Some(Severity::Info),
        _ => None,
    }
}

fn short_title(msg: &str) -> String {
    let first_line = msg.lines().next().unwrap_or("").trim();
    if first_line.is_empty() {
        "cargo-deny finding".to_string()
    } else if first_line.len() <= 120 {
        first_line.to_string()
    } else {
        // Find the largest char-boundary index <= 117 so the slice
        // never falls inside a multi-byte UTF-8 codepoint.
        let mut end = 117;
        while end > 0 && !first_line.is_char_boundary(end) {
            end -= 1;
        }
        let mut s = first_line[..end].to_string();
        s.push_str("...");
        s
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn non_empty_string(s: &str) -> Option<String> {
    non_empty(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_no_findings() {
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn ignores_non_diagnostic_records() {
        let ndjson = r#"{"type":"summary","fields":{}}
{"type":"note","fields":{}}"#;
        assert!(parse(ndjson).unwrap().is_empty());
    }

    #[test]
    fn parses_error_diagnostic() {
        let ndjson = r#"{"type":"diagnostic","fields":{"severity":"error","code":"L001","message":"license `GPL-3.0` not allowed","graphs":[{"name":"foo","version":"1.0.0"}]}}"#;
        let findings = parse(ndjson).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "L001");
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.affected_crate, "foo");
        assert_eq!(f.affected_version.as_deref(), Some("1.0.0"));
        assert_eq!(f.source, FindingSource::Deny);
    }

    #[test]
    fn parses_warning_diagnostic() {
        let ndjson = r#"{"type":"diagnostic","fields":{"severity":"warning","code":"D001","message":"duplicate version of `serde`","graphs":[{"name":"serde","version":"1.0.0"}]}}"#;
        let findings = parse(ndjson).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn parses_help_as_info() {
        let ndjson = r#"{"type":"diagnostic","fields":{"severity":"help","code":"H001","message":"consider..."}}"#;
        let findings = parse(ndjson).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn missing_code_falls_back_to_synthetic_id() {
        let ndjson =
            r#"{"type":"diagnostic","fields":{"severity":"error","message":"something bad"}}"#;
        let findings = parse(ndjson).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].id.starts_with("DENY-"));
    }

    #[test]
    fn skips_unknown_severity_levels() {
        let ndjson = r#"{"type":"diagnostic","fields":{"severity":"???","message":"x"}}"#;
        assert!(parse(ndjson).unwrap().is_empty());
    }

    #[test]
    fn skips_blank_lines_and_invalid_json() {
        let ndjson = r#"
not-json
{"type":"diagnostic","fields":{"severity":"error","code":"E1","message":"x"}}

{"type":"diagnostic","fields":{"severity":"warning","code":"W1","message":"y"}}
"#;
        let findings = parse(ndjson).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn short_title_truncates_long_messages() {
        let msg = "a".repeat(200);
        let t = short_title(&msg);
        assert!(t.ends_with("..."));
        assert_eq!(t.len(), 120);
    }

    #[test]
    fn short_title_handles_multibyte_at_truncation_boundary() {
        // Pad the first 110 bytes with ASCII so the 117-byte truncation
        // index lands inside the multi-byte "é" (which is 2 bytes in UTF-8).
        // Naive `&s[..117]` would panic here.
        let mut msg = "x".repeat(110);
        msg.push_str("éééééééééééééééé"); // each 'é' is 2 bytes
        let t = short_title(&msg);
        assert!(t.ends_with("..."));
        // Output must be valid UTF-8 (no panic) and stay under the cap.
        assert!(t.len() <= 120);
    }

    #[test]
    fn empty_graphs_become_workspace_sentinel() {
        let ndjson = r#"{"type":"diagnostic","fields":{"severity":"error","code":"W001","message":"workspace policy violation"}}"#;
        let findings = parse(ndjson).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_crate, "<workspace>");
        assert!(findings[0].affected_version.is_none());
    }
}
