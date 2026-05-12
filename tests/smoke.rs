//! Public-API smoke tests.
//!
//! The execute-against-real-tools path is exercised only when both
//! `cargo-audit` and `cargo-deny` are installed and `CARGO_TARGET_DIR`
//! points outside the workspace; see the `#[ignore]`d test at the
//! bottom of this file.

use dev_report::Severity;
use dev_security::{AuditResult, AuditRun, AuditScope, Finding, FindingSource};

fn finding(id: &str, sev: Severity, src: FindingSource) -> Finding {
    Finding {
        id: id.into(),
        title: format!("issue {id}"),
        severity: sev,
        affected_crate: "foo".into(),
        affected_version: Some("1.2.3".into()),
        url: None,
        description: None,
        source: src,
    }
}

#[test]
fn default_scope_is_all() {
    let r = AuditRun::new("x", "0.1.0");
    assert_eq!(r.audit_scope(), AuditScope::All);
}

#[test]
fn scope_selection_round_trips() {
    let r = AuditRun::new("x", "0.1.0").scope(AuditScope::Vulnerabilities);
    assert_eq!(r.audit_scope(), AuditScope::Vulnerabilities);
}

#[test]
fn run_accessors_round_trip_subject() {
    let r = AuditRun::new("alpha", "1.2.3");
    assert_eq!(r.subject(), "alpha");
    assert_eq!(r.subject_version(), "1.2.3");
}

#[test]
fn run_builder_chains_allow_and_threshold() {
    let r = AuditRun::new("x", "0.1.0")
        .allow("RUSTSEC-0000-0000")
        .allow_all(["A", "B"])
        .severity_threshold(Severity::Warning);
    assert_eq!(r.audit_scope(), AuditScope::All);
}

#[test]
fn empty_findings_produces_passing_report() {
    let res = AuditResult {
        name: "x".into(),
        version: "0.1.0".into(),
        scope: AuditScope::All,
        findings: Vec::new(),
    };
    let report = res.into_report();
    assert!(report.passed());
}

#[test]
fn critical_finding_produces_failing_report() {
    let res = AuditResult {
        name: "x".into(),
        version: "0.1.0".into(),
        scope: AuditScope::All,
        findings: vec![finding(
            "RUSTSEC-2024-9999",
            Severity::Critical,
            FindingSource::Audit,
        )],
    };
    let report = res.into_report();
    assert!(report.failed());
}

#[test]
fn severity_filter_at_or_above() {
    let res = AuditResult {
        name: "x".into(),
        version: "0.1.0".into(),
        scope: AuditScope::All,
        findings: vec![
            finding("I", Severity::Info, FindingSource::Audit),
            finding("W", Severity::Warning, FindingSource::Audit),
            finding("C", Severity::Critical, FindingSource::Audit),
        ],
    };
    assert_eq!(res.count_at_or_above(Severity::Info), 3);
    assert_eq!(res.count_at_or_above(Severity::Warning), 2);
    assert_eq!(res.count_at_or_above(Severity::Critical), 1);
}

#[test]
fn count_from_separates_audit_and_deny_findings() {
    let res = AuditResult {
        name: "x".into(),
        version: "0.1.0".into(),
        scope: AuditScope::All,
        findings: vec![
            finding("A", Severity::Error, FindingSource::Audit),
            finding("B", Severity::Warning, FindingSource::Deny),
            finding("C", Severity::Warning, FindingSource::Deny),
        ],
    };
    assert_eq!(res.count_from(FindingSource::Audit), 1);
    assert_eq!(res.count_from(FindingSource::Deny), 2);
}

#[test]
fn report_has_one_check_per_finding() {
    let res = AuditResult {
        name: "x".into(),
        version: "0.1.0".into(),
        scope: AuditScope::All,
        findings: vec![
            finding("A", Severity::Error, FindingSource::Audit),
            finding("B", Severity::Warning, FindingSource::Deny),
        ],
    };
    let report = res.into_report();
    assert_eq!(report.checks.len(), 2);
}

/// Real subprocess test. Skipped by default.
///
/// Run with `cargo-audit` + `cargo-deny` installed and a target dir
/// outside the workspace so the inner cargo invocations don't fight
/// the outer `cargo test` for the workspace target-dir lock:
///
/// ```text
/// CARGO_TARGET_DIR=/tmp/audit-target cargo test -- --ignored
/// ```
#[test]
#[ignore = "requires cargo-audit + cargo-deny + CARGO_TARGET_DIR outside the workspace"]
fn execute_against_real_tools() {
    let run = AuditRun::new("dev-security", "0.9.0").scope(AuditScope::All);
    let res = run.execute().expect("cargo-audit + cargo-deny installed");
    let _report = res.into_report();
}
