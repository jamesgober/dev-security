//! `cargo audit` subprocess invocation + JSON parsing.

use std::path::Path;
use std::process::Command;

use dev_report::Severity;
use serde::Deserialize;

use crate::{AuditError, Finding, FindingSource};

pub(crate) fn run(workdir: Option<&Path>) -> Result<Vec<Finding>, AuditError> {
    detect()?;
    let mut cmd = Command::new("cargo");
    cmd.args(["audit", "--json", "--no-fetch"]);
    if let Some(d) = workdir {
        cmd.current_dir(d);
    }
    let output = cmd
        .output()
        .map_err(|e| AuditError::SubprocessFailed(e.to_string()))?;
    // cargo-audit exits non-zero when it finds vulnerabilities — that
    // is the success path for us. Treat unparseable stdout as the real
    // failure signal instead of the exit code.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if stdout.trim().is_empty() && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(AuditError::SubprocessFailed(stderr));
    }
    parse(&stdout)
}

fn detect() -> Result<(), AuditError> {
    let out = Command::new("cargo").args(["audit", "--version"]).output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err(AuditError::AuditToolNotInstalled),
    }
}

// ---------------------------------------------------------------------------
// JSON shape
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct AuditReport {
    #[serde(default)]
    vulnerabilities: Vulnerabilities,
    #[serde(default)]
    warnings: serde_json::Value,
}

#[derive(Deserialize, Default)]
struct Vulnerabilities {
    #[serde(default)]
    list: Vec<Vulnerability>,
}

#[derive(Deserialize)]
struct Vulnerability {
    advisory: Advisory,
    #[serde(default)]
    package: Package,
}

#[derive(Deserialize, Default)]
struct Advisory {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    url: Option<String>,
    /// `cargo-audit`'s severity field uses a lowercase string derived
    /// from the advisory's CVSS score: `none` | `low` | `medium` |
    /// `high` | `critical`. Older advisories may omit it; in that case
    /// we fall back to `Warning`.
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
struct Package {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize)]
struct WarningEntry {
    advisory: Advisory,
    #[serde(default)]
    package: Package,
}

pub(crate) fn parse(json: &str) -> Result<Vec<Finding>, AuditError> {
    let report: AuditReport = serde_json::from_str(json).map_err(|e| {
        AuditError::ParseError(format!("{e}; first 200 chars: {:?}", first_200(json)))
    })?;

    let mut findings = Vec::new();
    for v in &report.vulnerabilities.list {
        findings.push(Finding {
            id: v.advisory.id.clone(),
            title: v.advisory.title.clone(),
            severity: severity_from_label(v.advisory.severity.as_deref())
                .unwrap_or(Severity::Warning),
            affected_crate: v.package.name.clone(),
            affected_version: non_empty(&v.package.version),
            url: v.advisory.url.clone(),
            description: v.advisory.description.clone(),
            source: FindingSource::Audit,
        });
    }

    // `warnings` is an object keyed by warning kind. Each value is
    // either a single entry or an array of entries with the same
    // `{advisory, package}` shape. We accept either via serde_json::Value
    // and walk it ourselves.
    if let serde_json::Value::Object(map) = &report.warnings {
        for (_, value) in map.iter() {
            let entries: Vec<WarningEntry> = match value {
                serde_json::Value::Array(_) => {
                    serde_json::from_value(value.clone()).unwrap_or_default()
                }
                serde_json::Value::Object(_) => {
                    serde_json::from_value::<WarningEntry>(value.clone())
                        .map(|e| vec![e])
                        .unwrap_or_default()
                }
                _ => Vec::new(),
            };
            for e in entries {
                findings.push(Finding {
                    id: e.advisory.id.clone(),
                    title: e.advisory.title.clone(),
                    // Warnings (unmaintained, yanked, notice) don't carry
                    // CVSS data; classify them as Warning by default.
                    severity: Severity::Warning,
                    affected_crate: e.package.name.clone(),
                    affected_version: non_empty(&e.package.version),
                    url: e.advisory.url.clone(),
                    description: e.advisory.description.clone(),
                    source: FindingSource::Audit,
                });
            }
        }
    }

    Ok(findings)
}

fn severity_from_label(label: Option<&str>) -> Option<Severity> {
    match label.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => Some(Severity::Critical),
        Some("high") => Some(Severity::Error),
        Some("medium") => Some(Severity::Warning),
        Some("low") => Some(Severity::Info),
        Some("none") => Some(Severity::Info),
        _ => None,
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn first_200(s: &str) -> &str {
    if s.len() <= 200 {
        s
    } else {
        &s[..200]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_yields_no_findings() {
        let json = r#"{ "vulnerabilities": { "list": [] }, "warnings": {} }"#;
        let findings = parse(json).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn parses_a_critical_vulnerability() {
        let json = r#"{
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2024-0001",
                            "title": "Use after free in foo",
                            "description": "...",
                            "url": "https://rustsec.org/advisories/RUSTSEC-2024-0001",
                            "severity": "critical"
                        },
                        "package": { "name": "foo", "version": "1.2.3" }
                    }
                ]
            },
            "warnings": {}
        }"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "RUSTSEC-2024-0001");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.affected_crate, "foo");
        assert_eq!(f.affected_version.as_deref(), Some("1.2.3"));
        assert_eq!(f.source, FindingSource::Audit);
    }

    #[test]
    fn severity_label_maps_each_level() {
        assert_eq!(
            severity_from_label(Some("critical")),
            Some(Severity::Critical)
        );
        assert_eq!(severity_from_label(Some("high")), Some(Severity::Error));
        assert_eq!(severity_from_label(Some("medium")), Some(Severity::Warning));
        assert_eq!(severity_from_label(Some("low")), Some(Severity::Info));
        assert_eq!(severity_from_label(Some("none")), Some(Severity::Info));
        assert_eq!(severity_from_label(Some("HIGH")), Some(Severity::Error));
        assert_eq!(severity_from_label(Some("???")), None);
        assert_eq!(severity_from_label(None), None);
    }

    #[test]
    fn missing_severity_defaults_to_warning() {
        let json = r#"{
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": { "id": "X", "title": "t" },
                        "package": { "name": "p", "version": "" }
                    }
                ]
            },
            "warnings": {}
        }"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].affected_version.is_none());
    }

    #[test]
    fn parses_warnings_array_entries() {
        let json = r#"{
            "vulnerabilities": { "list": [] },
            "warnings": {
                "unmaintained": [
                    {
                        "advisory": { "id": "RUSTSEC-2024-9000", "title": "unmaintained" },
                        "package": { "name": "p", "version": "0.1.0" }
                    }
                ]
            }
        }"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "RUSTSEC-2024-9000");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn parses_warnings_single_entry() {
        let json = r#"{
            "vulnerabilities": { "list": [] },
            "warnings": {
                "notice": {
                    "advisory": { "id": "RUSTSEC-2024-NOTICE", "title": "notice" },
                    "package": { "name": "p", "version": "0.1.0" }
                }
            }
        }"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "RUSTSEC-2024-NOTICE");
    }

    #[test]
    fn rejects_garbage_input() {
        let err = parse("not json").err().unwrap();
        assert!(matches!(err, AuditError::ParseError(_)));
    }
}
