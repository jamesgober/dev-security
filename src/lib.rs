//! # dev-security
//!
//! Security auditing for Rust. Wraps [`cargo-audit`][cargo-audit]
//! (RustSec advisory database) and [`cargo-deny`][cargo-deny] (license
//! + policy enforcement). Part of the `dev-*` verification suite.
//!
//! Output is a [`dev_report::Report`] so AI agents and CI gates can act
//! on findings programmatically.
//!
//! ## What it checks
//!
//! - **Vulnerabilities** — known CVEs in your dependency tree (via `cargo-audit`).
//! - **Licenses** — license-policy compliance (via `cargo-deny`).
//! - **Banned crates** — explicit allow/deny lists (via `cargo-deny`).
//! - **Source policies** — registry/git source restrictions (via `cargo-deny`).
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
//! ## Requirements
//!
//! ```text
//! cargo install cargo-audit cargo-deny
//! ```
//!
//! The crate detects absence of each tool and emits
//! [`AuditError::AuditToolNotInstalled`] or
//! [`AuditError::DenyToolNotInstalled`] without panicking.
//!
//! [cargo-audit]: https://crates.io/crates/cargo-audit
//! [cargo-deny]: https://crates.io/crates/cargo-deny

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::path::PathBuf;

use dev_report::{CheckResult, Evidence, Report, Severity};
use serde::{Deserialize, Serialize};

mod audit;
mod deny;
mod producer;

pub use producer::AuditProducer;

// ---------------------------------------------------------------------------
// AuditScope
// ---------------------------------------------------------------------------

/// Scope of an audit run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditScope {
    /// Run only the vulnerability scanner (`cargo audit`).
    Vulnerabilities,
    /// Run only the policy enforcer (`cargo deny`).
    Policy,
    /// Run both vulnerability and policy checks.
    All,
}

impl AuditScope {
    fn runs_audit(self) -> bool {
        matches!(self, Self::Vulnerabilities | Self::All)
    }

    fn runs_deny(self) -> bool {
        matches!(self, Self::Policy | Self::All)
    }
}

// ---------------------------------------------------------------------------
// AuditRun
// ---------------------------------------------------------------------------

/// Configuration for an audit run.
///
/// # Example
///
/// ```no_run
/// use dev_security::{AuditRun, AuditScope};
/// use dev_report::Severity;
///
/// let run = AuditRun::new("my-crate", "0.1.0")
///     .scope(AuditScope::All)
///     .allow("RUSTSEC-2024-9999")
///     .severity_threshold(Severity::Warning);
///
/// let _result = run.execute().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct AuditRun {
    name: String,
    version: String,
    scope: AuditScope,
    workdir: Option<PathBuf>,
    deny_config: Option<PathBuf>,
    allow_list: Vec<String>,
    severity_threshold: Option<Severity>,
}

impl AuditRun {
    /// Begin a new audit run for the given subject name and version.
    ///
    /// `name` and `version` are descriptive — they identify the subject
    /// in the produced `Report`.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            scope: AuditScope::All,
            workdir: None,
            deny_config: None,
            allow_list: Vec::new(),
            severity_threshold: None,
        }
    }

    /// Pick which checks to run. Defaults to [`AuditScope::All`].
    pub fn scope(mut self, scope: AuditScope) -> Self {
        self.scope = scope;
        self
    }

    /// Selected scope.
    pub fn audit_scope(&self) -> AuditScope {
        self.scope
    }

    /// Run the subprocesses from `dir` instead of the current directory.
    pub fn in_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.workdir = Some(dir.into());
        self
    }

    /// Pass `--config <path>` to `cargo deny` so callers can point at a
    /// non-default `deny.toml` location.
    pub fn deny_config(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_config = Some(path.into());
        self
    }

    /// Suppress a single advisory ID. Matches advisories from
    /// `cargo-audit` and rule names / advisory IDs from `cargo-deny`.
    ///
    /// May be called repeatedly to add more entries.
    pub fn allow(mut self, id: impl Into<String>) -> Self {
        self.allow_list.push(id.into());
        self
    }

    /// Add multiple allow-list entries at once.
    pub fn allow_all<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow_list.extend(ids.into_iter().map(Into::into));
        self
    }

    /// Discard findings whose severity is *below* `threshold`. Findings
    /// at or above the threshold are kept.
    ///
    /// Order: `Info` < `Warning` < `Error` < `Critical`.
    pub fn severity_threshold(mut self, threshold: Severity) -> Self {
        self.severity_threshold = Some(threshold);
        self
    }

    /// Subject name passed in via [`new`](Self::new).
    pub fn subject(&self) -> &str {
        &self.name
    }

    /// Subject version passed in via [`new`](Self::new).
    pub fn subject_version(&self) -> &str {
        &self.version
    }

    /// Execute the audit.
    ///
    /// Each enabled tool is invoked as a subprocess. Findings are
    /// merged, deduplicated by `(id, affected_crate)`, filtered through
    /// the allow-list and severity threshold, then sorted by `id` for
    /// determinism.
    pub fn execute(&self) -> Result<AuditResult, AuditError> {
        let mut findings: Vec<Finding> = Vec::new();
        if self.scope.runs_audit() {
            findings.extend(audit::run(self.workdir.as_deref())?);
        }
        if self.scope.runs_deny() {
            findings.extend(deny::run(
                self.workdir.as_deref(),
                self.deny_config.as_deref(),
            )?);
        }

        if !self.allow_list.is_empty() {
            findings.retain(|f| !self.allow_list.iter().any(|id| id == &f.id));
        }
        if let Some(threshold) = self.severity_threshold {
            findings.retain(|f| severity_ord(f.severity) >= severity_ord(threshold));
        }
        findings.sort_by(|a, b| {
            a.id.cmp(&b.id)
                .then_with(|| a.affected_crate.cmp(&b.affected_crate))
        });
        findings.dedup_by(|a, b| a.id == b.id && a.affected_crate == b.affected_crate);

        Ok(AuditResult {
            name: self.name.clone(),
            version: self.version.clone(),
            scope: self.scope,
            findings,
        })
    }
}

// ---------------------------------------------------------------------------
// Finding + FindingSource
// ---------------------------------------------------------------------------

/// Which tool emitted a [`Finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    /// `cargo-audit` (RustSec advisory database).
    Audit,
    /// `cargo-deny` (license / banned crates / sources policy).
    Deny,
}

/// A single security finding.
///
/// # Example
///
/// ```
/// use dev_security::{Finding, FindingSource};
/// use dev_report::Severity;
///
/// let f = Finding {
///     id: "RUSTSEC-2024-0001".into(),
///     title: "Use after free in foo".into(),
///     severity: Severity::Critical,
///     affected_crate: "foo".into(),
///     affected_version: Some("1.2.3".into()),
///     url: Some("https://rustsec.org/advisories/RUSTSEC-2024-0001".into()),
///     description: None,
///     source: FindingSource::Audit,
/// };
/// assert_eq!(f.severity, Severity::Critical);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Advisory ID (e.g. `RUSTSEC-2024-0001`) or `cargo-deny` rule code.
    pub id: String,
    /// Short human-readable title.
    pub title: String,
    /// Severity classification mapped from the underlying tool.
    pub severity: Severity,
    /// Affected crate name.
    pub affected_crate: String,
    /// Affected crate version, when the underlying tool exposed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_version: Option<String>,
    /// URL with more detail (advisory page, license SPDX page, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Long-form description, when the underlying tool exposed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Which tool emitted this finding.
    pub source: FindingSource,
}

// ---------------------------------------------------------------------------
// AuditResult
// ---------------------------------------------------------------------------

/// Result of an audit run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    /// Subject name.
    pub name: String,
    /// Subject version.
    pub version: String,
    /// Scope that produced this result.
    pub scope: AuditScope,
    /// Findings discovered (deduped, allow-list filtered, sorted by id).
    pub findings: Vec<Finding>,
}

impl AuditResult {
    /// Number of findings at the given severity *or higher*.
    ///
    /// `Info` < `Warning` < `Error` < `Critical`.
    pub fn count_at_or_above(&self, threshold: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| severity_ord(f.severity) >= severity_ord(threshold))
            .count()
    }

    /// Number of findings from the given source.
    pub fn count_from(&self, source: FindingSource) -> usize {
        self.findings.iter().filter(|f| f.source == source).count()
    }

    /// Highest severity present in the findings, if any.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| severity_ord(*s))
    }

    /// Convert this result into a [`dev_report::Report`].
    ///
    /// Pass when there are no findings; otherwise push one
    /// [`CheckResult::fail`] per finding, named
    /// `security::<source>::<id>` and tagged `security` plus a
    /// source-specific tag (`cve` for audit, `policy` for deny).
    /// Each check carries `Evidence::KeyValue` with `crate`,
    /// `affected_version`, and `url` when known.
    pub fn into_report(self) -> Report {
        let mut report = Report::new(&self.name, &self.version).with_producer("dev-security");
        if self.findings.is_empty() {
            report.push(
                CheckResult::pass("security::audit")
                    .with_tag("security")
                    .with_detail(format!("{} scope: no findings", scope_label(self.scope))),
            );
        } else {
            for f in &self.findings {
                let source_label = match f.source {
                    FindingSource::Audit => "audit",
                    FindingSource::Deny => "deny",
                };
                let mut check =
                    CheckResult::fail(format!("security::{source_label}::{}", f.id), f.severity)
                        .with_detail(format!("{} (in {})", f.title, f.affected_crate))
                        .with_tag("security")
                        .with_tag(match f.source {
                            FindingSource::Audit => "cve",
                            FindingSource::Deny => "policy",
                        });

                let mut kv: Vec<(String, String)> = vec![
                    ("crate".into(), f.affected_crate.clone()),
                    ("id".into(), f.id.clone()),
                ];
                if let Some(v) = &f.affected_version {
                    kv.push(("version".into(), v.clone()));
                }
                if let Some(u) = &f.url {
                    kv.push(("url".into(), u.clone()));
                }
                check = check.with_evidence(Evidence::kv("finding", kv));
                if let Some(desc) = &f.description {
                    check = check.with_evidence(Evidence::snippet("description", desc.clone()));
                }
                report.push(check);
            }
        }
        report.finish();
        report
    }
}

fn scope_label(s: AuditScope) -> &'static str {
    match s {
        AuditScope::Vulnerabilities => "vulnerabilities",
        AuditScope::Policy => "policy",
        AuditScope::All => "all",
    }
}

pub(crate) fn severity_ord(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

// ---------------------------------------------------------------------------
// AuditError
// ---------------------------------------------------------------------------

/// Errors that can arise during an audit run.
#[derive(Debug)]
pub enum AuditError {
    /// `cargo-audit` is not installed.
    AuditToolNotInstalled,
    /// `cargo-deny` is not installed.
    DenyToolNotInstalled,
    /// Subprocess failure with the captured stderr.
    SubprocessFailed(String),
    /// Output parsing failure.
    ParseError(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuditToolNotInstalled => write!(
                f,
                "cargo-audit is not installed; run `cargo install cargo-audit`"
            ),
            Self::DenyToolNotInstalled => write!(
                f,
                "cargo-deny is not installed; run `cargo install cargo-deny`"
            ),
            Self::SubprocessFailed(s) => write!(f, "audit subprocess failed: {s}"),
            Self::ParseError(s) => write!(f, "could not parse audit output: {s}"),
        }
    }
}

impl std::error::Error for AuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_finding(id: &str, sev: Severity) -> Finding {
        Finding {
            id: id.into(),
            title: format!("issue {id}"),
            severity: sev,
            affected_crate: "foo".into(),
            affected_version: Some("1.2.3".into()),
            url: Some(format!("https://rustsec.org/advisories/{id}")),
            description: None,
            source: FindingSource::Audit,
        }
    }

    #[test]
    fn run_builds_with_full_chain() {
        let r = AuditRun::new("x", "0.1.0")
            .scope(AuditScope::Vulnerabilities)
            .allow("RUSTSEC-0000-0000")
            .severity_threshold(Severity::Warning);
        assert_eq!(r.audit_scope(), AuditScope::Vulnerabilities);
        assert_eq!(r.subject(), "x");
        assert_eq!(r.subject_version(), "0.1.0");
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
            findings: vec![audit_finding("RUSTSEC-2024-0001", Severity::Critical)],
        };
        let report = res.into_report();
        assert!(report.failed());
        // One CheckResult per finding.
        assert_eq!(report.checks.len(), 1);
        let c = &report.checks[0];
        assert!(c.has_tag("security"));
        assert!(c.has_tag("cve"));
        assert_eq!(c.name, "security::audit::RUSTSEC-2024-0001");
    }

    #[test]
    fn report_includes_evidence_keyvalue_for_finding_metadata() {
        let res = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::Vulnerabilities,
            findings: vec![audit_finding("RUSTSEC-2024-1111", Severity::Error)],
        };
        let report = res.into_report();
        let c = &report.checks[0];
        let ev_labels: Vec<&str> = c.evidence.iter().map(|e| e.label.as_str()).collect();
        assert!(ev_labels.contains(&"finding"));
    }

    #[test]
    fn count_at_or_above_filters_severity() {
        let res = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::All,
            findings: vec![
                audit_finding("A", Severity::Info),
                audit_finding("B", Severity::Error),
                audit_finding("C", Severity::Critical),
            ],
        };
        assert_eq!(res.count_at_or_above(Severity::Critical), 1);
        assert_eq!(res.count_at_or_above(Severity::Error), 2);
        assert_eq!(res.count_at_or_above(Severity::Info), 3);
    }

    #[test]
    fn count_from_filters_source() {
        let f1 = audit_finding("A", Severity::Error);
        let mut f2 = audit_finding("B", Severity::Warning);
        f2.source = FindingSource::Deny;
        let res = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::All,
            findings: vec![f1, f2],
        };
        assert_eq!(res.count_from(FindingSource::Audit), 1);
        assert_eq!(res.count_from(FindingSource::Deny), 1);
    }

    #[test]
    fn worst_severity_picks_max() {
        let res = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::All,
            findings: vec![
                audit_finding("A", Severity::Warning),
                audit_finding("B", Severity::Critical),
                audit_finding("C", Severity::Info),
            ],
        };
        assert_eq!(res.worst_severity(), Some(Severity::Critical));
        let empty = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::All,
            findings: Vec::new(),
        };
        assert_eq!(empty.worst_severity(), None);
    }

    #[test]
    fn result_round_trips_through_json() {
        let res = AuditResult {
            name: "x".into(),
            version: "0.1.0".into(),
            scope: AuditScope::Vulnerabilities,
            findings: vec![audit_finding("RUSTSEC-2024-0001", Severity::Error)],
        };
        let s = serde_json::to_string(&res).unwrap();
        let back: AuditResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].id, "RUSTSEC-2024-0001");
    }

    #[test]
    fn auditscope_runs_helpers() {
        assert!(AuditScope::All.runs_audit());
        assert!(AuditScope::All.runs_deny());
        assert!(AuditScope::Vulnerabilities.runs_audit());
        assert!(!AuditScope::Vulnerabilities.runs_deny());
        assert!(!AuditScope::Policy.runs_audit());
        assert!(AuditScope::Policy.runs_deny());
    }
}
