//! [`Producer`] adapter for [`AuditRun`].

use dev_report::{CheckResult, Producer, Report, Severity};

use crate::AuditRun;

/// `Producer` adapter that runs an [`AuditRun`] and emits a [`Report`].
///
/// Subprocess failures map to a single failing
/// [`CheckResult`] named `security::audit` with `Severity::Critical`.
/// No panics.
///
/// # Example
///
/// ```no_run
/// use dev_security::{AuditProducer, AuditRun, AuditScope};
/// use dev_report::Producer;
///
/// let producer = AuditProducer::new(
///     AuditRun::new("my-crate", "0.1.0").scope(AuditScope::All),
/// );
/// let report = producer.produce();
/// println!("{}", report.to_json().unwrap());
/// ```
pub struct AuditProducer {
    run: AuditRun,
}

impl AuditProducer {
    /// Wrap an `AuditRun` so it can be composed with other producers.
    pub fn new(run: AuditRun) -> Self {
        Self { run }
    }

    /// Access the wrapped run.
    pub fn run(&self) -> &AuditRun {
        &self.run
    }
}

impl Producer for AuditProducer {
    fn produce(&self) -> Report {
        let subject = self.run.subject().to_string();
        let version = self.run.subject_version().to_string();
        match self.run.execute() {
            Ok(result) => result.into_report(),
            Err(e) => {
                let mut report = Report::new(&subject, &version).with_producer("dev-security");
                let check = CheckResult::fail("security::audit", Severity::Critical)
                    .with_detail(e.to_string())
                    .with_tag("security")
                    .with_tag("subprocess");
                report.push(check);
                report.finish();
                report
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditScope;

    #[test]
    fn produce_returns_report_when_tool_missing() {
        // The default runner image won't have cargo-audit / cargo-deny
        // installed; the producer should surface that as a failing
        // CheckResult rather than panicking.
        let producer =
            AuditProducer::new(AuditRun::new("self", "0.0.0").scope(AuditScope::Vulnerabilities));
        let report = producer.produce();
        assert_eq!(report.subject, "self");
        assert!(!report.checks.is_empty());
    }
}
