<h1 align="center">
    <strong>dev-security</strong>
    <br>
    <sup><sub>SECURITY AUDITING FOR RUST</sub></sup>
</h1>

<p align="center">
    <a href="https://crates.io/crates/dev-security"><img alt="crates.io" src="https://img.shields.io/crates/v/dev-security.svg"></a>
    <a href="https://crates.io/crates/dev-security"><img alt="downloads" src="https://img.shields.io/crates/d/dev-security.svg"></a>
    <a href="https://docs.rs/dev-security"><img alt="docs.rs" src="https://docs.rs/dev-security/badge.svg"></a>
    <a href="https://github.com/jamesgober/dev-security/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/dev-security/actions/workflows/ci.yml/badge.svg"></a>
    <img alt="MSRV" src="https://img.shields.io/badge/msrv-1.85%2B-blue.svg?style=flat-square" title="Rust Version">
</p>

<p align="center">
    Vulnerability scanning, license compliance, banned-crate policies.<br>
    Part of the <code>dev-*</code> verification suite.
</p>

---

## What it does

`dev-security` wraps two best-in-class Rust security tools and emits
results as a [`dev-report::Report`](https://docs.rs/dev-report):

- **[`cargo-audit`](https://crates.io/crates/cargo-audit)** scans the
  dependency tree against the RustSec advisory database for known CVEs.
- **[`cargo-deny`](https://crates.io/crates/cargo-deny)** enforces
  policy: allowed/banned licenses, allowed/banned crates,
  allowed/banned sources, multiple-version detection.

Findings from both tools come back through one typed `AuditResult`,
ready to drive an AI agent or a CI gate without parsing free-form
output.

## Quick start

```toml
[dependencies]
dev-security = "0.9"
```

One-time tool install:

```bash
cargo install cargo-audit cargo-deny
```

Drive it from code:

```rust,no_run
use dev_security::{AuditRun, AuditScope};

let run = AuditRun::new("my-crate", "0.1.0").scope(AuditScope::All);
let result = run.execute()?;
let report = result.into_report();

if report.failed() {
    eprintln!("audit failed: {}", report.to_json()?);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Scopes

| Scope                      | What it runs                                              |
|----------------------------|------------------------------------------------------------|
| `AuditScope::Vulnerabilities` | `cargo audit` only (RustSec advisory DB).             |
| `AuditScope::Policy`          | `cargo deny check` only (licenses, banned crates).    |
| `AuditScope::All`             | Both.                                                  |

## Severity mapping

| Source                                       | `dev-report::Severity` |
|----------------------------------------------|------------------------|
| `cargo-audit` `critical`                     | `Critical`             |
| `cargo-audit` `high`                         | `Error`                |
| `cargo-audit` `medium`                       | `Warning`              |
| `cargo-audit` `low` / `none` / missing       | `Info` / `Warning`     |
| `cargo-audit` warnings (unmaintained etc.)   | `Warning`              |
| `cargo-deny` `error`                         | `Error`                |
| `cargo-deny` `warning`                       | `Warning`              |
| `cargo-deny` `help` / `note`                 | `Info`                 |

## Allow-list + severity threshold

Suppress known false positives by advisory ID, and / or set a
severity floor so noisy `Info` findings stop showing up in CI:

```rust,no_run
use dev_security::{AuditRun, AuditScope};
use dev_report::Severity;

let run = AuditRun::new("my-crate", "0.1.0")
    .scope(AuditScope::All)
    .allow("RUSTSEC-2024-9999")
    .allow_all(["RUSTSEC-2023-0042", "RUSTSEC-2022-0066"])
    .severity_threshold(Severity::Warning);   // drop Info findings

let _result = run.execute()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Allow-list entries match against the `id` field of each `Finding` —
advisory IDs for `cargo-audit` findings (`RUSTSEC-2024-NNNN`) and
diagnostic codes for `cargo-deny` findings (e.g. `L001`).

## `Producer` integration

`AuditProducer` plugs the audit into a multi-producer pipeline driven
by [`dev-tools`](https://github.com/jamesgober/dev-tools):

```rust,no_run
use dev_security::{AuditProducer, AuditRun, AuditScope};
use dev_report::Producer;

let producer = AuditProducer::new(
    AuditRun::new("my-crate", "0.1.0").scope(AuditScope::All),
);

let report = producer.produce();
println!("{}", report.to_json().unwrap());
```

Subprocess failures map to a single failing `CheckResult` named
`security::audit` with `Severity::Critical` — the pipeline keeps
running.

## Wire format

`Finding`, `FindingSource`, and `AuditResult` are all
`serde`-derived. JSON output uses `snake_case` field names and omits
optional fields when they are `None`:

```json
{
  "id": "RUSTSEC-2024-0001",
  "title": "Use after free in foo",
  "severity": "critical",
  "affected_crate": "foo",
  "affected_version": "1.2.3",
  "url": "https://rustsec.org/advisories/RUSTSEC-2024-0001",
  "source": "audit"
}
```

## Examples

| File                              | What it shows                                                       |
|-----------------------------------|---------------------------------------------------------------------|
| `examples/basic.rs`               | Full audit (`All` scope); prints the JSON report.                   |
| `examples/audit_only.rs`          | `Vulnerabilities` scope only.                                       |
| `examples/policy_only.rs`         | `Policy` scope only.                                                |
| `examples/producer.rs`            | `AuditProducer` wired into a pipeline (gated by `DEV_SECURITY_EXAMPLE_RUN`). |

## Requirements

Both [`cargo-audit`](https://crates.io/crates/cargo-audit) and
[`cargo-deny`](https://crates.io/crates/cargo-deny) must be installed:

```bash
cargo install cargo-audit cargo-deny
```

The crate detects absence of either tool and surfaces
`AuditError::AuditToolNotInstalled` /
`AuditError::DenyToolNotInstalled` rather than panicking.

Runtime dependency footprint: `dev-report`, `serde`, `serde_json`.

## Migration from `0.1.0`

`Finding` gained four new fields: `affected_version`, `url`,
`description`, and `source`. If you constructed `Finding` literals in
`0.1.0`, add the new fields:

```rust
# use dev_security::{Finding, FindingSource};
# use dev_report::Severity;
let _f = Finding {
    id: "RUSTSEC-2024-0001".into(),
    title: "Use after free in foo".into(),
    severity: Severity::Critical,
    affected_crate: "foo".into(),
    // new in 0.9.0:
    affected_version: Some("1.2.3".into()),
    url: None,
    description: None,
    source: FindingSource::Audit,
};
```

The constructor surface (`AuditRun::new`, `AuditScope` variants,
`AuditResult::into_report`) is unchanged.

## The `dev-*` suite

See [`dev-tools`](https://github.com/jamesgober/dev-tools) for the
umbrella crate covering the full suite.

## Status

`v0.9.x` is the pre-1.0 stabilization line. The API is feature-complete
for vulnerability scanning, policy enforcement, allow-listing, and
severity gating. Production use is fine; `1.0` will pin the public API
and the wire format.

## Minimum supported Rust version

`1.85` — pinned in `Cargo.toml` via `rust-version` and verified by
the MSRV job in CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
