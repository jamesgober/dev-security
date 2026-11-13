//! `cargo audit` subprocess invocation + JSON parsing.

use std::path::Path;

use dev_report::Severity;
use serde::Deserialize;
use serde_json::Value;

use crate::{AuditError, Finding, FindingSource};

pub(crate) fn run(workdir: Option<&Path>) -> Result<Vec<Finding>, AuditError> {
    let bin = detect()?;
    let mut cmd = crate::tool::command(&bin, "audit");
    cmd.args(["--json", "--no-fetch"]);
    if let Some(d) = workdir {
        cmd.current_dir(d);
    }
    let output = cmd
        .output()
        .map_err(|e| AuditError::SubprocessFailed(format!("could not spawn cargo audit: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    outcome(
        &stdout,
        &stderr,
        output.status.success(),
        &output.status.to_string(),
    )
}

/// Turn one `cargo audit` run into findings or an error.
///
/// cargo-audit exits non-zero when it finds vulnerabilities, so a
/// non-zero exit on its own is not a failure. It is one when the output
/// does not account for it: a non-zero exit with no vulnerability parsed
/// means the tool failed, or wrote something this parser does not
/// understand. Either way the run must not read as clean.
fn outcome(
    stdout: &str,
    stderr: &str,
    success: bool,
    status: &str,
) -> Result<Vec<Finding>, AuditError> {
    if stdout.trim().is_empty() && !success {
        return Err(AuditError::SubprocessFailed(format!(
            "cargo audit exited with {status}: {}",
            stderr.trim()
        )));
    }
    let parsed = parse_output(stdout)?;
    if !success && parsed.vulnerabilities == 0 {
        let detail = if stderr.trim().is_empty() {
            format!("output: {:?}", first_200(stdout.trim()))
        } else {
            stderr.trim().to_string()
        };
        return Err(AuditError::SubprocessFailed(format!(
            "cargo audit exited with {status} but reported no vulnerabilities: {detail}"
        )));
    }
    Ok(parsed.findings)
}

fn detect() -> Result<std::path::PathBuf, AuditError> {
    let bin = crate::tool::resolve("cargo-audit").ok_or(AuditError::AuditToolNotInstalled)?;
    let out = crate::tool::command(&bin, "audit")
        .arg("--version")
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(bin),
        _ => Err(AuditError::AuditToolNotInstalled),
    }
}

// ---------------------------------------------------------------------------
// JSON shape
// ---------------------------------------------------------------------------

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

#[derive(Default, Clone)]
struct Package {
    name: String,
    version: String,
}

/// One entry of `vulnerabilities.list` or of a `warnings.<kind>` array.
/// `advisory` is `null` for `yanked` warnings.
///
/// Entries are read field by field rather than through a strict schema,
/// so one field with an unexpected type (a CVSS object where a vector
/// string was expected, say) loses only that field, never the entry.
struct Entry {
    kind: Option<String>,
    advisory: Option<Advisory>,
    package: Package,
    /// The entry was not a JSON object, or had no usable advisory where
    /// one was required. Kept so it still becomes a finding.
    raw: Option<String>,
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Read an advisory object leniently. Returns `None` when `v` is not an
/// object.
pub(crate) fn advisory_from_value(v: &Value) -> Option<Advisory> {
    if !v.is_object() {
        return None;
    }
    Some(Advisory {
        id: str_field(v, "id").unwrap_or_default(),
        title: str_field(v, "title").unwrap_or_default(),
        description: str_field(v, "description"),
        url: str_field(v, "url"),
        cvss: str_field(v, "cvss"),
        severity: str_field(v, "severity"),
    })
}

fn entry_from_value(v: &Value) -> Entry {
    let package = v.get("package");
    Entry {
        kind: str_field(v, "kind"),
        advisory: v.get("advisory").and_then(advisory_from_value),
        package: Package {
            name: package
                .and_then(|p| str_field(p, "name"))
                .unwrap_or_default(),
            version: package
                .and_then(|p| str_field(p, "version"))
                .unwrap_or_default(),
        },
        raw: if v.is_object() {
            None
        } else {
            Some(first_200(&v.to_string()).to_string())
        },
    }
}

/// What one `cargo audit --json` document contained.
struct Parsed {
    findings: Vec<Finding>,
    /// How many of `findings` came from `vulnerabilities.list`.
    vulnerabilities: usize,
}

#[cfg(test)]
pub(crate) fn parse(json: &str) -> Result<Vec<Finding>, AuditError> {
    parse_output(json).map(|p| p.findings)
}

fn parse_output(json: &str) -> Result<Parsed, AuditError> {
    let report: Value = serde_json::from_str(json).map_err(|e| {
        AuditError::ParseError(format!("{e}; first 200 chars: {:?}", first_200(json)))
    })?;
    let parse_error = |what: &str| {
        AuditError::ParseError(format!("{what}; first 200 chars: {:?}", first_200(json)))
    };
    let vulns = match report.get("vulnerabilities") {
        Some(v @ Value::Object(_)) => v,
        Some(_) => return Err(parse_error("`vulnerabilities` is not an object")),
        None => {
            return Err(parse_error(
                "no `vulnerabilities` key in cargo audit output",
            ))
        }
    };
    let list: &[Value] = match vulns.get("list") {
        Some(Value::Array(items)) => items,
        None | Some(Value::Null) => &[],
        Some(_) => return Err(parse_error("`vulnerabilities.list` is not an array")),
    };

    let mut findings = Vec::new();
    for value in list {
        let v = entry_from_value(value);
        let package = v.package;
        let finding = match v.advisory {
            Some(advisory) => Finding {
                severity: advisory_severity(&advisory).unwrap_or(Severity::Warning),
                url: advisory_url(&advisory),
                id: if advisory.id.is_empty() {
                    "unknown-advisory".to_string()
                } else {
                    advisory.id
                },
                title: advisory.title,
                affected_crate: package.name,
                affected_version: non_empty(&package.version),
                description: advisory.description,
                source: FindingSource::Audit,
            },
            // A vulnerability entry without a readable advisory is still
            // a vulnerability. Keep it, at a severity that fails the gate.
            None => Finding {
                id: "unknown-advisory".to_string(),
                title: "cargo audit reported a vulnerability that could not be read".to_string(),
                severity: Severity::Error,
                affected_crate: package.name,
                affected_version: non_empty(&package.version),
                url: None,
                description: Some(
                    v.raw
                        .unwrap_or_else(|| first_200(&value.to_string()).to_string()),
                ),
                source: FindingSource::Audit,
            },
        };
        findings.push(finding);
    }
    let vulnerabilities = findings.len();

    // cargo-audit states how many vulnerabilities it found. If that is
    // more than were read here, the output changed shape and the gate
    // must not pass on what is left.
    let found = vulns.get("found").and_then(Value::as_bool).unwrap_or(false);
    let count = vulns.get("count").and_then(Value::as_u64).unwrap_or(0);
    if (found && vulnerabilities == 0) || count > vulnerabilities as u64 {
        return Err(parse_error(&format!(
            "cargo audit reported {count} vulnerabilities (found: {found}) but {vulnerabilities} could be read"
        )));
    }

    // `warnings` is an object keyed by warning kind (`unmaintained`,
    // `unsound`, `yanked`, `notice`, ...). Each value is an array of
    // entries; a bare object is accepted too.
    if let Some(Value::Object(map)) = report.get("warnings") {
        for (kind, value) in map {
            let values: Vec<&Value> = match value {
                Value::Array(items) => items.iter().collect(),
                obj @ Value::Object(_) => vec![obj],
                _ => Vec::new(),
            };
            for value in values {
                let e = entry_from_value(value);
                let kind = e.kind.clone().unwrap_or_else(|| kind.clone());
                findings.push(warning_finding(&kind, e));
            }
        }
    }

    Ok(Parsed {
        findings,
        vulnerabilities,
    })
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
                if e.package.name.is_empty() {
                    "(unknown crate)"
                } else {
                    &e.package.name
                },
                if e.package.version.is_empty() {
                    "(unknown version)"
                } else {
                    &e.package.version
                }
            ),
            severity: Severity::Warning,
            affected_version: non_empty(&e.package.version),
            affected_crate: if e.package.name.is_empty() {
                "<unknown>".to_string()
            } else {
                e.package.name
            },
            url: None,
            description: e.raw,
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
        // The vulnerability whose advisory could not be read is kept, and
        // fails the gate, instead of being dropped.
        assert_eq!(crates, ["bad", "good", "a", "<unknown>", "b"]);
        assert_eq!(findings[0].id, "unknown-advisory");
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn unreadable_cvss_keeps_the_vulnerability() {
        // cargo-audit exits 1 and says one vulnerability was found, but
        // the CVSS field is an object instead of a vector string.
        let stdout = r#"{"database":{},"lockfile":{},"vulnerabilities":{"found":true,"count":1,"list":[{"advisory":{"id":"RUSTSEC-2099-0001","title":"RCE in foo","cvss":{"score":9.8}},"package":{"name":"foo","version":"1.0.0"}}]},"warnings":{}}"#;
        let findings = outcome(stdout, "", false, "exit code: 1").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "RUSTSEC-2099-0001");
        assert_eq!(findings[0].affected_crate, "foo");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn json_without_vulnerabilities_is_an_error() {
        // cargo-audit exits 2 and prints an error object.
        let stdout = r#"{"error":"lockfile could not be parsed"}"#;
        let err = outcome(stdout, "", false, "exit code: 2").unwrap_err();
        assert!(matches!(err, AuditError::ParseError(_)), "{err}");
        // Missing the key is an error even with a zero exit.
        assert!(matches!(
            parse(stdout).unwrap_err(),
            AuditError::ParseError(_)
        ));
    }

    #[test]
    fn count_larger_than_entries_read_is_an_error() {
        let found_none_read = r#"{"vulnerabilities":{"found":true,"count":1,"list":[]}}"#;
        assert!(matches!(
            parse(found_none_read).unwrap_err(),
            AuditError::ParseError(_)
        ));
        let count_short = r#"{"vulnerabilities":{"found":true,"count":2,"list":[
            {"advisory":{"id":"A","title":"t"},"package":{"name":"p","version":"1.0.0"}}
        ]}}"#;
        assert!(parse(count_short).is_err());
        let list_wrong_type = r#"{"vulnerabilities":{"found":false,"count":0,"list":{}}}"#;
        assert!(parse(list_wrong_type).is_err());
    }

    #[test]
    fn non_zero_exit_with_no_vulnerability_is_an_error() {
        let clean = r#"{"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;
        assert!(outcome(clean, "", true, "exit code: 0").unwrap().is_empty());
        let err = outcome(clean, "boom", false, "exit code: 1").unwrap_err();
        assert!(matches!(err, AuditError::SubprocessFailed(_)), "{err}");
        assert!(err.to_string().contains("boom"));
        // Empty stdout with a failure exit passes stderr on.
        let err = outcome("", "no Cargo.lock", false, "exit code: 1").unwrap_err();
        assert!(err.to_string().contains("no Cargo.lock"));
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
