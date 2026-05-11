use dev_report::Severity;
use dev_security::{AuditResult, AuditRun, AuditScope, Finding};

#[test]
fn smoke_default_scope_is_all() {
    let r = AuditRun::new("x", "0.1.0");
    assert_eq!(r.audit_scope(), AuditScope::All);
}

#[test]
fn smoke_scope_selection() {
    let r = AuditRun::new("x", "0.1.0").scope(AuditScope::Vulnerabilities);
    assert_eq!(r.audit_scope(), AuditScope::Vulnerabilities);
}

#[test]
fn smoke_empty_findings_produces_passing_report() {
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
fn smoke_critical_finding_produces_failing_report() {
    let res = AuditResult {
        name: "x".into(),
        version: "0.1.0".into(),
        scope: AuditScope::All,
        findings: vec![Finding {
            id: "RUSTSEC-2024-9999".into(),
            title: "test finding".into(),
            severity: Severity::Critical,
            affected_crate: "foo".into(),
        }],
    };
    let report = res.into_report();
    assert!(report.failed());
}

#[test]
fn smoke_severity_filter_at_or_above() {
    let res = AuditResult {
        name: "x".into(),
        version: "0.1.0".into(),
        scope: AuditScope::All,
        findings: vec![
            Finding {
                id: "I".into(),
                title: "info".into(),
                severity: Severity::Info,
                affected_crate: "a".into(),
            },
            Finding {
                id: "W".into(),
                title: "warn".into(),
                severity: Severity::Warning,
                affected_crate: "b".into(),
            },
            Finding {
                id: "C".into(),
                title: "crit".into(),
                severity: Severity::Critical,
                affected_crate: "c".into(),
            },
        ],
    };
    assert_eq!(res.count_at_or_above(Severity::Info), 3);
    assert_eq!(res.count_at_or_above(Severity::Warning), 2);
    assert_eq!(res.count_at_or_above(Severity::Critical), 1);
}
