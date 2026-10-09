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
        .map_err(|e| AuditError::SubprocessFailed(format!("could not spawn cargo audit: {e}")))?;
    // cargo-audit exits non-zero when it finds vulnerabilities — that
    // is the success path for us. Treat unparseable stdout as the real
    // failure signal instead of the exit code.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if stdout.trim().is_empty() && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(AuditError::SubprocessFailed(format!(
            "cargo audit exited with {}: {}",
            output.status,
            stderr.trim()
        )));
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
    list: Vec<serde_json::Value>,
}

#[derive(Deserialize, Default)]
pub(crate) struct Advisory {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) url: Option<String>,
    /// CVSS v3.x or v4.0 vector string, e.g.
    /// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. This is what
    /// `cargo-audit` and `cargo-deny` actually emit; neither carries a
    /// numeric score or a severity label.
    #[serde(default)]
    pub(crate) cvss: Option<String>,
    /// Severity label (`none` | `low` | `medium` | `high` | `critical`).
    /// Not emitted by current `cargo-audit`; still honoured when present
    /// and no usable CVSS vector is available.
    #[serde(default)]
    pub(crate) severity: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
struct Package {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

/// One entry of `vulnerabilities.list` or of a `warnings.<kind>` array.
/// `advisory` is `null` for `yanked` warnings.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    advisory: Option<Advisory>,
    #[serde(default)]
    package: Package,
}

pub(crate) fn parse(json: &str) -> Result<Vec<Finding>, AuditError> {
    let report: AuditReport = serde_json::from_str(json).map_err(|e| {
        AuditError::ParseError(format!("{e}; first 200 chars: {:?}", first_200(json)))
    })?;

    let mut findings = Vec::new();
    // Entries are decoded one at a time so a single entry with an
    // unexpected shape cannot drop its neighbours.
    for value in report.vulnerabilities.list {
        let Ok(v) = serde_json::from_value::<Entry>(value) else {
            continue;
        };
        let Some(advisory) = v.advisory else {
            continue;
        };
        findings.push(Finding {
            severity: advisory_severity(&advisory).unwrap_or(Severity::Warning),
            url: advisory_url(&advisory),
            id: advisory.id,
            title: advisory.title,
            affected_crate: v.package.name,
            affected_version: non_empty(&v.package.version),
            description: advisory.description,
            source: FindingSource::Audit,
        });
    }

    // `warnings` is an object keyed by warning kind (`unmaintained`,
    // `unsound`, `yanked`, `notice`, ...). Each value is an array of
    // entries; a bare object is accepted too.
    if let serde_json::Value::Object(map) = report.warnings {
        for (kind, value) in map {
            let values = match value {
                serde_json::Value::Array(items) => items,
                obj @ serde_json::Value::Object(_) => vec![obj],
                _ => Vec::new(),
            };
            for value in values {
                let Ok(e) = serde_json::from_value::<Entry>(value) else {
                    continue;
                };
                let kind = e.kind.clone().unwrap_or_else(|| kind.clone());
                findings.push(warning_finding(&kind, e));
            }
        }
    }

    Ok(findings)
}

/// Warnings (unmaintained, unsound, yanked, notice) describe risk rather
/// than an exploitable vulnerability, so they are classified as
/// `Warning` regardless of any CVSS data.
fn warning_finding(kind: &str, e: Entry) -> Finding {
    match e.advisory {
        Some(advisory) => Finding {
            url: advisory_url(&advisory),
            id: advisory.id,
            title: advisory.title,
            severity: Severity::Warning,
            affected_crate: e.package.name,
            affected_version: non_empty(&e.package.version),
            description: advisory.description,
            source: FindingSource::Audit,
        },
        // `yanked` warnings carry no advisory; the kind is the id.
        None => Finding {
            id: kind.to_string(),
            title: format!(
                "{} {} is {kind}",
                e.package.name,
                if e.package.version.is_empty() {
                    "(unknown version)"
                } else {
                    &e.package.version
                }
            ),
            severity: Severity::Warning,
            affected_version: non_empty(&e.package.version),
            affected_crate: e.package.name,
            url: None,
            description: None,
            source: FindingSource::Audit,
        },
    }
}

/// Severity for an advisory: from its CVSS vector when it has a valid
/// one, otherwise from a `severity` label, otherwise `None`.
pub(crate) fn advisory_severity(a: &Advisory) -> Option<Severity> {
    a.cvss
        .as_deref()
        .and_then(crate::cvss::score)
        .map(severity_from_score)
        .or_else(|| severity_from_label(a.severity.as_deref()))
}

/// Advisory URL, falling back to the RustSec advisory page for
/// `RUSTSEC-*` ids that do not carry their own URL.
pub(crate) fn advisory_url(a: &Advisory) -> Option<String> {
    match &a.url {
        Some(u) if !u.is_empty() => Some(u.clone()),
        _ if a.id.starts_with("RUSTSEC-") => {
            Some(format!("https://rustsec.org/advisories/{}.html", a.id))
        }
        _ => None,
    }
}

/// CVSS qualitative rating scale mapped onto `Severity`:
/// critical (9.0+) -> Critical, high (7.0+) -> Error,
/// medium (4.0+) -> Warning, low / none -> Info.
fn severity_from_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::Error
    } else if score >= 4.0 {
        Severity::Warning
    } else {
        Severity::Info
    }
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

/// At most the first 200 bytes of `s`, cut on a char boundary.
pub(crate) fn first_200(s: &str) -> &str {
    if s.len() <= 200 {
        return s;
    }
    let mut end = 200;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `cargo audit --json` output (cargo-audit 0.22.1), with long
    /// descriptions shortened.
    const REAL: &str = include_str!("../tests/fixtures/cargo-audit.json");

    #[test]
    fn parses_real_cargo_audit_output() {
        let findings = parse(REAL).unwrap();
        let get = |id: &str| findings.iter().find(|f| f.id == id).unwrap();

        // regex: CVSS:3.1 .../A:H, network, score 7.5 -> high.
        let regex = get("RUSTSEC-2022-0013");
        assert_eq!(regex.severity, Severity::Error);
        assert_eq!(regex.affected_crate, "regex");
        assert_eq!(regex.affected_version.as_deref(), Some("1.5.4"));
        assert!(regex.url.as_deref().unwrap().starts_with("https://"));

        // time: local attack vector, score 6.2 -> medium.
        assert_eq!(get("RUSTSEC-2020-0071").severity, Severity::Warning);
        // smallvec: CVSS:3.0 .../C:H/I:H/A:H, score 9.8 -> critical.
        assert_eq!(get("RUSTSEC-2019-0009").severity, Severity::Critical);

        // Warnings: unmaintained + unsound carry advisories.
        assert_eq!(get("RUSTSEC-2021-0139").severity, Severity::Warning);
        assert_eq!(get("RUSTSEC-2021-0139").affected_crate, "ansi_term");
        assert_eq!(get("RUSTSEC-2018-0018").affected_crate, "smallvec");

        // Yanked warning has `"advisory": null`; it must still surface.
        let yanked = get("yanked");
        assert_eq!(yanked.affected_crate, "smallvec");
        assert_eq!(yanked.affected_version.as_deref(), Some("0.6.9"));
        assert_eq!(yanked.severity, Severity::Warning);

        assert_eq!(findings.len(), 6);
        assert!(findings.iter().all(|f| f.source == FindingSource::Audit));
    }

    #[test]
    fn empty_report_yields_no_findings() {
        let json = r#"{ "vulnerabilities": { "list": [] }, "warnings": {} }"#;
        let findings = parse(json).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn severity_comes_from_cvss_vector() {
        let json = r#"{
            "vulnerabilities": {
                "found": true,
                "count": 2,
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2024-0001",
                            "title": "Use after free in foo",
                            "description": "...",
                            "url": null,
                            "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                        },
                        "package": { "name": "foo", "version": "1.2.3" }
                    },
                    {
                        "advisory": {
                            "id": "RUSTSEC-2024-0002",
                            "title": "Info leak",
                            "cvss": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
                        },
                        "package": { "name": "bar", "version": "0.1.0" }
                    }
                ]
            },
            "warnings": {}
        }"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 2);
        let f = &findings[0];
        assert_eq!(f.id, "RUSTSEC-2024-0001");
        // CVSS 4.0 base score 9.3 -> critical.
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.affected_crate, "foo");
        assert_eq!(f.affected_version.as_deref(), Some("1.2.3"));
        assert_eq!(f.source, FindingSource::Audit);
        // No URL in the advisory: fall back to the RustSec page.
        assert_eq!(
            f.url.as_deref(),
            Some("https://rustsec.org/advisories/RUSTSEC-2024-0001.html")
        );
        // Low score -> Info.
        assert_eq!(findings[1].severity, Severity::Info);
    }

    #[test]
    fn legacy_severity_label_still_honoured() {
        let json = r#"{
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": { "id": "X-1", "title": "t", "severity": "critical" },
                        "package": { "name": "p", "version": "1.0.0" }
                    }
                ]
            }
        }"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
        // Not a RUSTSEC id and no url: no link is invented.
        assert!(findings[0].url.is_none());
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
    fn score_bands_follow_cvss_rating_scale() {
        assert_eq!(severity_from_score(0.0), Severity::Info);
        assert_eq!(severity_from_score(3.9), Severity::Info);
        assert_eq!(severity_from_score(4.0), Severity::Warning);
        assert_eq!(severity_from_score(6.9), Severity::Warning);
        assert_eq!(severity_from_score(7.0), Severity::Error);
        assert_eq!(severity_from_score(8.9), Severity::Error);
        assert_eq!(severity_from_score(9.0), Severity::Critical);
        assert_eq!(severity_from_score(10.0), Severity::Critical);
    }

    #[test]
    fn missing_or_invalid_cvss_defaults_to_warning() {
        let json = r#"{
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": { "id": "X", "title": "t" },
                        "package": { "name": "p", "version": "" }
                    },
                    {
                        "advisory": { "id": "Y", "title": "t", "cvss": "CVSS:9.9/garbage" },
                        "package": { "name": "p", "version": "1.0.0" }
                    }
                ]
            },
            "warnings": {}
        }"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].affected_version.is_none());
        assert_eq!(findings[1].severity, Severity::Warning);
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
    fn one_malformed_entry_does_not_drop_its_neighbours() {
        let json = r#"{
            "vulnerabilities": {
                "list": [
                    { "advisory": 42, "package": { "name": "bad" } },
                    {
                        "advisory": { "id": "RUSTSEC-2024-0003", "title": "t" },
                        "package": { "name": "good", "version": "1.0.0" }
                    }
                ]
            },
            "warnings": {
                "yanked": [
                    { "kind": "yanked", "package": { "name": "a", "version": "1.0.0" }, "advisory": null },
                    { "kind": "yanked", "package": "not an object" },
                    { "kind": "yanked", "package": { "name": "b", "version": "2.0.0" }, "advisory": null }
                ]
            }
        }"#;
        let findings = parse(json).unwrap();
        let crates: Vec<&str> = findings.iter().map(|f| f.affected_crate.as_str()).collect();
        assert_eq!(crates, ["good", "a", "b"]);
    }

    #[test]
    fn rejects_garbage_input() {
        let err = parse("not json").err().unwrap();
        assert!(matches!(err, AuditError::ParseError(_)));
    }

    #[test]
    fn parse_error_preview_does_not_split_multibyte_chars() {
        // 199 ASCII bytes followed by a 2-byte char straddling byte 200.
        let mut s = "x".repeat(199);
        s.push_str("ééé");
        assert_eq!(first_200(&s).len(), 199);
        let err = parse(&s).err().unwrap();
        assert!(matches!(err, AuditError::ParseError(_)));
    }
}
