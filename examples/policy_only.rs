//! Run only the policy enforcer (`cargo deny`) and print the result.
//!
//! ```text
//! cargo install cargo-deny
//! cargo run --example policy_only
//! ```
//!
//! Reads `deny.toml` from the current directory by default; pass a path
//! via `AuditRun::deny_config(...)` to use a different file.

use dev_security::{AuditError, AuditRun, AuditScope};

fn main() {
    let result = match AuditRun::new("example", "0.1.0")
        .scope(AuditScope::Policy)
        .execute()
    {
        Ok(r) => r,
        Err(AuditError::DenyToolNotInstalled) => {
            eprintln!("cargo-deny is not installed; install with `cargo install cargo-deny`.");
            return;
        }
        Err(e) => {
            eprintln!("policy check failed: {e}");
            return;
        }
    };
    println!("{} policy findings", result.findings.len());
    for f in &result.findings {
        println!(
            "  {} [{:?}] {} — {}",
            f.id, f.severity, f.affected_crate, f.title
        );
    }
}
