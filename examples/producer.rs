//! Use `AuditProducer` to integrate the audit into a multi-producer
//! pipeline driven by `dev-tools`.
//!
//! ```text
//! cargo run --example producer
//! DEV_SECURITY_EXAMPLE_RUN=1 cargo run --example producer
//! ```
//!
//! The actual subprocess invocation is gated behind the
//! `DEV_SECURITY_EXAMPLE_RUN` env var so CI doesn't pay for a full
//! audit on every example build.

use dev_report::Producer;
use dev_security::{AuditProducer, AuditRun, AuditScope};

fn main() {
    let producer = AuditProducer::new(AuditRun::new("my-crate", "0.1.0").scope(AuditScope::All));
    println!("Constructed AuditProducer for 'my-crate' v0.1.0.");

    if std::env::var("DEV_SECURITY_EXAMPLE_RUN").is_ok() {
        let report = producer.produce();
        println!("{}", report.to_json().expect("serialize report"));
    } else {
        println!("Set DEV_SECURITY_EXAMPLE_RUN=1 to spawn `cargo audit` + `cargo deny`");
        println!("in the current directory and print the resulting JSON report.");
    }
}
