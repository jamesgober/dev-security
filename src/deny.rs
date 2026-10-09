//! `cargo deny` subprocess invocation + NDJSON parsing.
//!
//! `cargo deny --format json check` emits one JSON object per line on
//! **stderr** (stdout stays empty). Diagnostic records look like:
//!
//! ```text
//! { "type": "diagnostic",
//!   "fields": { "severity": "error", "code": "rejected",
//!               "message": "failed to satisfy license requirements",
//!               "graphs": [ { "Krate": { "name": "foo", "version": "1.0.0" },
//!                             "parents": [...] } ],
//!               "labels": [...], "notes": [...],
//!               "advisory": { "id": "RUSTSEC-...", ... } } }
//! ```
//!
//! `advisory` is present only for advisory diagnostics (`vulnerability`,
//! `unmaintained`, `unsound`, `notice`, `yanked`). Every completed run
//! ends with a `summary` record; `log` records carry tool messages, and
//! `ERROR` logs without a summary mean the run itself failed (bad
//! config, missing `Cargo.toml`, advisory DB fetch failure, ...).

use std::path::Path;
use std::process::Command;

use dev_report::Severity;
use serde::Deserialize;

use crate::audit::{advisory_url, Advisory};
use crate::{AuditError, Finding, FindingSource};

pub(crate) fn run(
    workdir: Option<&Path>,
    config: Option<&Path>,
) -> Result<Vec<Finding>, AuditError> {
    detect()?;
    let mut cmd = Command::new("cargo");
    cmd.args(["deny", "--format", "json", "check"]);
    // `--config` is an option of the `check` subcommand, not of
    // `cargo deny` itself (where `-c` means `--color`).
    if let Some(c) = config {
        cmd.arg("--config").arg(c);
    }
    if let Some(d) = workdir {
        cmd.current_dir(d);
    }
    let output = cmd
        .output()
        .map_err(|e| AuditError::SubprocessFailed(format!("could not spawn cargo deny: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    outcome(
        &stdout,
        &stderr,
        output.status.success(),
        &output.status.to_string(),
    )
}

/// Turn one `cargo deny` run into findings or an error.
fn outcome(
    stdout: &str,
    stderr: &str,
    success: bool,
    status: &str,
) -> Result<Vec<Finding>, AuditError> {
    // Records go to stderr in current cargo-deny; read stdout too so a
    // build that writes them there still works.
    let mut parsed = parse_records(stderr);
    let from_stdout = parse_records(stdout);
    parsed.findings.extend(from_stdout.findings);
    parsed.summary_seen |= from_stdout.summary_seen;
    parsed.errors.extend(from_stdout.errors);

    // A non-zero exit is expected when violations are found; that run
    // still ends with a summary record. Without one, the check never ran.
    if !success && !parsed.summary_seen {
        // Config errors arrive as an ERROR log plus diagnostics that
        // point at the offending span; report both.
        let mut parts = parsed.errors;
        parts.extend(parsed.findings.iter().map(|f| {
            let text = f.description.as_deref().unwrap_or(&f.title);
            format!("{}: {}", f.id, text.replace('\n', " "))
        }));
        let detail = if parts.is_empty() {
            stderr.trim().to_string()
        } else {
            parts.join("; ")
        };
        return Err(AuditError::SubprocessFailed(format!(
            "cargo deny exited with {status}: {detail}"
        )));
    }
    Ok(parsed.findings)
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
    fields: serde_json::Value,
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
    #[serde(default)]
    labels: Vec<DenyLabel>,
    #[serde(default)]
    advisory: Option<Advisory>,
}

/// Inclusion graph for the affected crate. Current cargo-deny nests the
/// crate under `Krate`; a flat `name` / `version` pair is accepted too.
#[derive(Deserialize, Default)]
struct DenyGraph {
    #[serde(default, rename = "Krate")]
    krate: Option<DenyKrate>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, Default)]
struct DenyKrate {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, Default)]
struct DenyLabel {
    #[serde(default)]
    message: String,
    #[serde(default)]
    span: String,
}

#[derive(Deserialize, Default)]
struct DenyLog {
    #[serde(default)]
    level: String,
    #[serde(default)]
    message: String,
}

#[derive(Default)]
struct Parsed {
    findings: Vec<Finding>,
    /// A `summary` record was seen, i.e. the checks ran to completion.
    summary_seen: bool,
    /// Messages of `ERROR`-level log records.
    errors: Vec<String>,
}

#[cfg(test)]
pub(crate) fn parse(ndjson: &str) -> Result<Vec<Finding>, AuditError> {
    Ok(parse_records(ndjson).findings)
}

fn parse_records(ndjson: &str) -> Parsed {
    let mut out = Parsed::default();
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
        match record.kind.as_str() {
            "diagnostic" => {}
            "summary" => {
                out.summary_seen = true;
                continue;
            }
            "log" => {
                let log: DenyLog = serde_json::from_value(record.fields).unwrap_or_default();
                if log.level.eq_ignore_ascii_case("error") && !log.message.is_empty() {
                    out.errors.push(log.message);
                }
                continue;
            }
            _ => continue,
        }
        let Ok(fields) = serde_json::from_value::<DenyFields>(record.fields) else {
            continue;
        };
        let Some(severity) = severity_from_label(&fields.severity) else {
            continue;
        };

        // Advisory diagnostics use the advisory id (e.g. RUSTSEC-2022-0013)
        // so the allow-list and cross-tool dedup work the same as for
        // cargo-audit findings. Other diagnostics use their code
        // (e.g. `rejected`, `banned`, `duplicate`); fall back to a
        // synthetic line-number id.
        let advisory_id = fields
            .advisory
            .as_ref()
            .map(|a| a.id.as_str())
            .filter(|id| !id.is_empty());
        let id = match (advisory_id, &fields.code) {
            (Some(a), _) => a.to_string(),
            (None, Some(code)) if !code.is_empty() => code.clone(),
            _ => format!("DENY-{:04}", line_num + 1),
        };

        // Empty `graphs` is legitimate (e.g. a config-level warning such
        // as `license-not-encountered`); represent it explicitly rather
        // than emitting an empty crate name.
        let (affected_crate, affected_version) = fields
            .graphs
            .first()
            .map(|g| match &g.krate {
                Some(k) => (non_empty(&k.name), non_empty(&k.version)),
                None => (non_empty(&g.name), non_empty(&g.version)),
            })
            .unwrap_or((None, None));

        out.findings.push(Finding {
            id,
            title: short_title(&fields.message),
            severity,
            affected_crate: affected_crate.unwrap_or_else(|| "<workspace>".to_string()),
            affected_version,
            url: fields.advisory.as_ref().and_then(advisory_url),
            description: description(&fields.message, &fields.labels),
            source: FindingSource::Deny,
        });
    }
    out
}

/// The diagnostic message plus any labelled spans, e.g.
/// `MIT: rejected: license is not explicitly allowed`.
fn description(message: &str, labels: &[DenyLabel]) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();
    if !message.is_empty() {
        lines.push(message.to_string());
    }
    for l in labels {
        if l.message.is_empty() {
            continue;
        }
        if l.span.is_empty() {
            lines.push(l.message.clone());
        } else {
            lines.push(format!("{}: {}", l.span, l.message));
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `cargo deny --format json check` stderr (cargo-deny 0.19.6),
    /// with long descriptions and notes shortened.
    const REAL: &str = include_str!("../tests/fixtures/cargo-deny.ndjson");

    #[test]
    fn parses_real_cargo_deny_output() {
        let parsed = parse_records(REAL);
        assert!(parsed.summary_seen);
        assert!(parsed.errors.is_empty());
        let f = &parsed.findings;

        // License rejection: crate comes from graphs[0].Krate.
        let lic = f
            .iter()
            .find(|x| x.id == "rejected" && x.affected_crate == "aho-corasick")
            .unwrap();
        assert_eq!(lic.severity, Severity::Error);
        assert_eq!(lic.affected_version.as_deref(), Some("0.7.20"));
        let desc = lic.description.as_deref().unwrap();
        assert!(desc.starts_with("failed to satisfy license requirements"));
        assert!(desc.contains("MIT: rejected: license is not explicitly allowed"));

        // Ban.
        let ban = f.iter().find(|x| x.id == "banned").unwrap();
        assert_eq!(ban.affected_crate, "ansi_term");

        // Advisory diagnostics are keyed by advisory id, with a URL.
        let vuln = f.iter().find(|x| x.id == "RUSTSEC-2022-0013").unwrap();
        assert_eq!(vuln.affected_crate, "regex");
        assert_eq!(vuln.affected_version.as_deref(), Some("1.5.4"));
        assert_eq!(vuln.severity, Severity::Error);
        assert!(vuln.url.is_some());
        assert!(f.iter().any(|x| x.id == "RUSTSEC-2020-0071"));
        assert!(f.iter().any(|x| x.id == "RUSTSEC-2021-0139"));
        assert!(!f.iter().any(|x| x.id == "vulnerability"));

        // Config-level warnings have no graph.
        let unused = f
            .iter()
            .find(|x| x.id == "license-not-encountered")
            .unwrap();
        assert_eq!(unused.affected_crate, "<workspace>");
        assert_eq!(unused.severity, Severity::Warning);

        assert!(f.iter().all(|x| x.source == FindingSource::Deny));
        assert!(!f.iter().any(|x| x.affected_crate.is_empty()));
    }

    #[test]
    fn run_failure_without_summary_is_detected() {
        // Shape of cargo-deny's output when there is no Cargo.toml.
        let out = r#"{"fields":{"level":"ERROR","message":"the directory C:\\x doesn't contain a Cargo.toml file","timestamp":"2026-10-09T09:05:15.6347025Z"},"type":"log"}"#;
        let parsed = parse_records(out);
        assert!(!parsed.summary_seen);
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.errors.len(), 1);
        assert!(parsed.errors[0].contains("Cargo.toml"));
    }

    #[test]
    fn outcome_maps_exit_status_and_summary() {
        // Violations found: non-zero exit, but a summary was written.
        let found = outcome("", REAL, false, "exit code: 3").unwrap();
        assert!(!found.is_empty());

        // Clean run.
        let clean = r#"{"type":"summary","fields":{"licenses":{"errors":0}}}"#;
        assert!(outcome("", clean, true, "exit code: 0").unwrap().is_empty());

        // Invalid deny.toml: real cargo-deny 0.19.6 output.
        let bad_config = r#"{"fields":{"code":"wanted","labels":[{"column":9,"line":2,"message":"expected an array","span":"5"}],"message":"","severity":"error"},"type":"diagnostic"}
{"fields":{"level":"ERROR","message":"failed to deserialize config from 'bad.toml'","timestamp":"2026-10-09T09:05:14.1988591Z"},"type":"log"}"#;
        let err = outcome("", bad_config, false, "exit code: 1").unwrap_err();
        let AuditError::SubprocessFailed(msg) = err else {
            panic!("expected SubprocessFailed");
        };
        assert!(msg.contains("failed to deserialize config"), "{msg}");
        assert!(msg.contains("wanted: 5: expected an array"), "{msg}");

        // Clap usage error (plain text, no records): stderr is passed on.
        let usage = "error: unexpected argument '--config' found\n";
        let err = outcome("", usage, false, "exit code: 2").unwrap_err();
        assert!(err.to_string().contains("unexpected argument"));

        // Records on stdout are read as well.
        assert!(!outcome(REAL, "", false, "exit code: 3").unwrap().is_empty());
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let out = "{\"type\":\"diagnostic\",\"fields\":{\"severity\":\"error\",\"code\":\"banned\",\"message\":\"x\",\"graphs\":[{\"Krate\":{\"name\":\"a\",\"version\":\"1.0.0\"}}]}}\r\n{\"type\":\"summary\",\"fields\":{}}\r\n";
        let parsed = parse_records(out);
        assert!(parsed.summary_seen);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].affected_crate, "a");
    }

    #[test]
    fn empty_input_yields_no_findings() {
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn ignores_non_diagnostic_records() {
        let ndjson = r#"{"type":"summary","fields":{}}
{"type":"note","fields":{}}
{"type":"log","fields":{"level":"WARN","message":"unable to find a config path"}}"#;
        assert!(parse(ndjson).unwrap().is_empty());
        let parsed = parse_records(ndjson);
        assert!(parsed.summary_seen);
        assert!(parsed.errors.is_empty());
    }

    #[test]
    fn parses_flat_graph_shape() {
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
        let ndjson = r#"{"type":"diagnostic","fields":{"severity":"warning","code":"duplicate","message":"found 2 duplicate entries for crate 'serde'","graphs":[{"Krate":{"name":"serde","version":"1.0.0"}},{"Krate":{"name":"serde","version":"0.9.0"}}]}}"#;
        let findings = parse(ndjson).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].affected_crate, "serde");
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
    fn skips_blank_lines_invalid_json_and_odd_fields() {
        let ndjson = r#"
not-json
{"type":"diagnostic","fields":{"severity":"error","code":"E1","message":"x"}}
{"type":"diagnostic","fields":"not an object"}
{"type":"diagnostic","fields":{"severity":"error","code":"E2","graphs":"nope"}}

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
