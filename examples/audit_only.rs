//! Run only the vulnerability scanner (`cargo audit`) and print the result.
//!
//! ```text
//! cargo install cargo-audit
//! cargo run --example audit_only
//! ```

use dev_security::{AuditError, AuditRun, AuditScope};

fn main() {
    let result = match AuditRun::new("example", "0.1.0")
        .scope(AuditScope::Vulnerabilities)
        .execute()
    {
        Ok(r) => r,
        Err(AuditError::AuditToolNotInstalled) => {
            eprintln!("cargo-audit is not installed; install with `cargo install cargo-audit`.");
            return;
        }
        Err(e) => {
            eprintln!("audit failed: {e}");
            return;
        }
    };
    println!(
        "{} findings (worst severity: {:?})",
        result.findings.len(),
        result.worst_severity()
    );
    for f in &result.findings {
        println!(
            "  {} [{:?}] {} — {}",
            f.id, f.severity, f.affected_crate, f.title
        );
    }
}
