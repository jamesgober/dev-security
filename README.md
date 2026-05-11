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
</p>

<p align="center">
    Vulnerability scanning, license compliance, banned-crate policies.<br>
    Part of the <code>dev-*</code> verification suite.
</p>

---

## What it does

`dev-security` wraps two best-in-class Rust security tools and emits
results as `dev-report::Report`:

- **`cargo-audit`** scans your dependency tree against the RustSec
  advisory database for known CVEs.
- **`cargo-deny`** enforces policy: allowed/banned licenses, allowed/
  banned crates, allowed/banned sources, multiple-version detection.

Together they cover the audit surface most production Rust projects
care about.

## Quick start

```toml
[dependencies]
dev-security = "0.9"
```

```rust
use dev_security::{AuditRun, AuditScope};

let run = AuditRun::new("my-crate", "0.1.0").scope(AuditScope::All);
let result = run.execute()?;
let report = result.into_report();

if report.failed() {
    eprintln!("Security audit failed: {}", report.to_json()?);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Requirements

```bash
cargo install cargo-audit cargo-deny
```

## Scopes

| Scope                | What it runs                                          |
|----------------------|--------------------------------------------------------|
| `Vulnerabilities`    | `cargo-audit` only (RustSec advisory DB).             |
| `Policy`             | `cargo-deny` only (licenses, banned crates, sources). |
| `All`                | Both.                                                  |

## The `dev-*` suite

See [`dev-tools`](https://github.com/jamesgober/dev-tools) for the
full suite.

## Status

`v0.9.0` is the foundation release: API shape defined, subprocess
integration lands in `0.9.1`. Production use is discouraged until
`1.0`.

## Minimum supported Rust version

`1.85` — pinned in `Cargo.toml` and verified by CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
