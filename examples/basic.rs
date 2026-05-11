//! Minimal example: run a security audit and emit a report.
//!
//! Run with: `cargo run --example basic`

use dev_security::{AuditRun, AuditScope};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let run = AuditRun::new("example", "0.1.0").scope(AuditScope::All);
    let result = run.execute()?;
    let report = result.into_report();
    println!("{}", report.to_json()?);
    Ok(())
}
