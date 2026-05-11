# dev-security — Project Specification (REPS)

> Rust Engineering Project Specification.
> Normative language follows RFC 2119.

## 1. Purpose

`dev-security` MUST run security audits (vulnerability scans + policy
checks) and emit results as `dev-report::Report`. Output MUST be
machine-readable so AI agents and CI gates can act on findings
without parsing free-form logs.

## 2. Scope

This crate MUST provide:

- An `AuditScope` enum (`Vulnerabilities`, `Policy`, `All`).
- An `AuditRun` builder.
- A `Finding` struct.
- An `AuditResult` with `findings`, `count_at_or_above`, `into_report`.

This crate SHOULD provide (later versions):

- `cargo-audit` invocation + JSON parsing (`0.9.1`).
- `cargo-deny` invocation + JSON parsing (`0.9.2`).
- Severity-threshold gating: fail only when finding ≥ threshold.
- Allow-list management for known false positives.
- `cargo-supply-chain` integration for ownership tracking.

This crate MUST NOT:

- Define new advisory data. We consume RustSec, not redistribute.
- Implement new license parsers. We rely on `cargo-deny`.
- Make HTTP requests directly. The wrapped tools handle their own
  network I/O.

## 3. Determinism

The same project + same advisory snapshot MUST produce the same
findings list. Order MUST be deterministic (sort by advisory ID).

## 4. Tool dependencies

`cargo-audit` and `cargo-deny` MUST be installed externally. Detection
of missing tools produces `AuditError::AuditToolNotInstalled` or
`AuditError::DenyToolNotInstalled` with remediation guidance.

## 5. Stability

Through `0.9.x` the public API MAY shift. The `1.0` release pins the
API. The `Severity` mapping from CVSS scores to `dev-report::Severity`
levels is documented and stable from `1.0`.

## 6. Severity mapping

The mapping from underlying tool severity to `dev-report::Severity`:

| Source           | dev-report::Severity |
|------------------|----------------------|
| CVSS 9.0-10.0    | Critical             |
| CVSS 7.0-8.9     | Error                |
| CVSS 4.0-6.9     | Warning              |
| CVSS 0.1-3.9     | Info                 |
| `cargo-deny` deny rule violation     | Error  |
| `cargo-deny` warn rule violation     | Warning |
