//! # dev-security
//!
//! Security auditing for Rust. Wraps `cargo-audit` (RustSec advisory
//! database) and `cargo-deny` (license + policy enforcement). Part of
//! the `dev-*` verification suite.
//!
//! Output is a `dev-report::Report` so AI agents and CI gates can act
//! on findings programmatically.
//!
//! ## What it checks
//!
//! - **Vulnerabilities**: known CVEs in your dependency tree (via `cargo-audit`).
//! - **Licenses**: license policy compliance (via `cargo-deny`).
//! - **Banned crates**: explicit allow/deny lists (via `cargo-deny`).
//! - **Source policies**: registry/git source restrictions (via `cargo-deny`).
//!
//! ## Quick example
//!
//! ```no_run
//! use dev_security::{AuditRun, AuditScope};
//!
//! let run = AuditRun::new("my-crate", "0.1.0").scope(AuditScope::All);
//! let result = run.execute().unwrap();
//! let report = result.into_report();
//! ```
//!
//! ## Status
//!
//! Pre-1.0. API shape defined; subprocess integration lands in `0.9.1`.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use dev_report::{CheckResult, Report, Severity};

/// Scope of an audit run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditScope {
    /// Run only the vulnerability scanner (cargo-audit).
    Vulnerabilities,
    /// Run only the policy enforcer (cargo-deny).
    Policy,
    /// Run both vulnerability and policy checks.
    All,
}

/// Configuration for an audit run.
#[derive(Debug, Clone)]
pub struct AuditRun {
    name: String,
    version: String,
    scope: AuditScope,
}

impl AuditRun {
    /// Begin a new audit run for the given crate name and version.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            scope: AuditScope::All,
        }
    }

    /// Set the audit scope.
    pub fn scope(mut self, scope: AuditScope) -> Self {
        self.scope = scope;
        self
    }

    /// Selected scope.
    pub fn audit_scope(&self) -> AuditScope {
        self.scope
    }

    /// Execute the audit run.
    ///
    /// In `0.9.0` this is a stub; full `cargo-audit` and `cargo-deny`
    /// integration lands in `0.9.1`.
    pub fn execute(&self) -> Result<AuditResult, AuditError> {
        Ok(AuditResult {
            name: self.name.clone(),
            version: self.version.clone(),
            scope: self.scope,
            findings: Vec::new(),
        })
    }
}

/// A single security finding.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Advisory ID (e.g. `RUSTSEC-2024-0001`) or policy rule name.
    pub id: String,
    /// Short human-readable title.
    pub title: String,
    /// Severity classification.
    pub severity: Severity,
    /// Affected crate.
    pub affected_crate: String,
}

/// Result of an audit run.
#[derive(Debug, Clone)]
pub struct AuditResult {
    /// Crate name.
    pub name: String,
    /// Crate version.
    pub version: String,
    /// Scope that produced this result.
    pub scope: AuditScope,
    /// All findings discovered.
    pub findings: Vec<Finding>,
}

impl AuditResult {
    /// Number of findings at the given severity or higher.
    pub fn count_at_or_above(&self, threshold: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| severity_ord(f.severity) >= severity_ord(threshold))
            .count()
    }

    /// Convert this result into a `dev-report::Report`.
    pub fn into_report(self) -> Report {
        let mut report = Report::new(&self.name, &self.version).with_producer("dev-security");
        if self.findings.is_empty() {
            report.push(CheckResult::pass("security::audit"));
        } else {
            for f in &self.findings {
                report.push(
                    CheckResult::fail(format!("security::{}", f.id), f.severity)
                        .with_detail(format!("{} (in {})", f.title, f.affected_crate)),
                );
            }
        }
        report.finish();
        report
    }
}

fn severity_ord(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

/// Errors that can arise during an audit.
#[derive(Debug)]
pub enum AuditError {
    /// `cargo-audit` is not installed.
    AuditToolNotInstalled,
    /// `cargo-deny` is not installed.
    DenyToolNotInstalled,
    /// Subprocess failure.
    SubprocessFailed(String),
    /// Output parsing failure.
    ParseError(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuditToolNotInstalled => write!(f, "cargo-audit is not installed"),
            Self::DenyToolNotInstalled => write!(f, "cargo-deny is not installed"),
            Self::SubprocessFailed(s) => write!(f, "subprocess failed: {s}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for AuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_builds() {
        let r = AuditRun::new("x", "0.1.0").scope(AuditScope::All);
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
    fn findings_produce_failing_report() {
        let res = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::All,
            findings: vec![Finding {
                id: "RUSTSEC-2024-0001".into(),
                title: "Use after free in foo".into(),
                severity: Severity::Critical,
                affected_crate: "foo".into(),
            }],
        };
        let report = res.into_report();
        assert!(report.failed());
    }

    #[test]
    fn severity_filter_works() {
        let res = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::All,
            findings: vec![
                Finding {
                    id: "A".into(),
                    title: "low".into(),
                    severity: Severity::Info,
                    affected_crate: "a".into(),
                },
                Finding {
                    id: "B".into(),
                    title: "high".into(),
                    severity: Severity::Critical,
                    affected_crate: "b".into(),
                },
            ],
        };
        assert_eq!(res.count_at_or_above(Severity::Critical), 1);
        assert_eq!(res.count_at_or_above(Severity::Info), 2);
    }
}
