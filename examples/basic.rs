//! Run a full audit (vulnerabilities + policy) against the current crate
//! and print the resulting `Report`.
//!
//! ```text
//! cargo install cargo-audit cargo-deny
//! cargo run --example basic
//! ```
//!
//! Both `cargo-audit` and `cargo-deny` must be installed. If either is
//! missing, the example prints a clear error and exits 0 (so
//! `cargo build --examples` in CI still succeeds without the tools).

use dev_security::{AuditError, AuditRun, AuditScope};

fn main() {
    let run = AuditRun::new("example", "0.1.0").scope(AuditScope::All);
    let result = match run.execute() {
        Ok(r) => r,
        Err(AuditError::AuditToolNotInstalled) => {
            eprintln!("cargo-audit is not installed; skipping the example.");
            eprintln!("Install with: cargo install cargo-audit");
            return;
        }
        Err(AuditError::DenyToolNotInstalled) => {
            eprintln!("cargo-deny is not installed; skipping the example.");
            eprintln!("Install with: cargo install cargo-deny");
            return;
        }
        Err(e) => {
            eprintln!("audit failed: {e}");
            return;
        }
    };
    let report = result.into_report();
    println!("{}", report.to_json().expect("serialize report"));
}
