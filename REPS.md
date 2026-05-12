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
- An `AuditRun` builder with `scope`, `in_dir`, `deny_config`,
  `allow`, `allow_all`, `severity_threshold`, `subject`,
  `subject_version`, and `execute` methods.
- A `Finding` struct with `id`, `title`, `severity`,
  `affected_crate`, `affected_version`, `url`, `description`, and
  `source`.
- A `FindingSource` enum (`Audit`, `Deny`).
- An `AuditResult` with `findings`, `count_at_or_above`,
  `count_from`, `worst_severity`, and `into_report`.
- `cargo-audit` invocation + JSON parsing.
- `cargo-deny` invocation + NDJSON parsing.
- Severity-threshold gating — `AuditRun::severity_threshold` filters
  findings below the threshold before they reach `AuditResult`.
- Allow-list management — `AuditRun::allow` / `allow_all` filters
  findings by advisory ID before they reach `AuditResult`.
- A `Producer` adapter (`AuditProducer`) that maps subprocess
  failures to a single failing `CheckResult` rather than panicking.

This crate MAY provide later:

- `cargo-supply-chain` integration for crate-ownership tracking.
- Aggregation of findings across multiple workspace members in a
  single `Report`.

This crate MUST NOT:

- Define new advisory data. We consume RustSec, not redistribute.
- Implement new license parsers. We rely on `cargo-deny`.
- Make HTTP requests directly. The wrapped tools handle their own
  network I/O.

## 3. Determinism

The same project + same advisory snapshot MUST produce the same
findings list, in the same order. Findings MUST be sorted ascending
by `id`, breaking ties by `affected_crate`. Findings with identical
`(id, affected_crate)` MUST be deduplicated. Two diffs of the same
input MUST be byte-equal.

## 4. Tool dependencies

`cargo-audit` and `cargo-deny` MUST be installed externally. Detection
of missing tools produces `AuditError::AuditToolNotInstalled` or
`AuditError::DenyToolNotInstalled` with remediation guidance.

Subprocess failures (non-zero exit *and* empty stdout) MUST surface
as `AuditError::SubprocessFailed(stderr)`. Parse failures MUST
surface as `AuditError::ParseError(detail)`. Neither MUST cause a
panic.

`cargo-audit` and `cargo-deny` may return a non-zero exit code when
they find issues — this is the success path. The crate MUST parse
their stdout regardless of exit code as long as stdout is non-empty.

## 5. JSON wire format

The `AuditResult` and `Finding` types MUST be serializable via
`serde_json`. Field names MUST use `snake_case`. Optional fields with
default values (e.g. `affected_version = None`, `url = None`) MUST be
omitted on serialization.

## 6. Severity mapping

| Source                                     | dev-report::Severity |
|--------------------------------------------|----------------------|
| `cargo-audit` `severity: "critical"`       | `Critical`           |
| `cargo-audit` `severity: "high"`           | `Error`              |
| `cargo-audit` `severity: "medium"`         | `Warning`            |
| `cargo-audit` `severity: "low"` / `"none"` | `Info`               |
| `cargo-audit` missing severity             | `Warning` (default)  |
| `cargo-audit` warnings (unmaintained etc.) | `Warning`            |
| `cargo-deny` severity `"error"`            | `Error`              |
| `cargo-deny` severity `"warning"`          | `Warning`            |
| `cargo-deny` severity `"help"` / `"note"`  | `Info`               |
| `cargo-deny` unknown severity              | dropped              |

## 7. Producer contract

`AuditProducer::produce()` MUST always return a `Report`. It MUST NOT
panic. On `Err(_)` from `AuditRun::execute()`, it MUST emit a single
`CheckResult::fail("security::audit", Severity::Critical)` carrying
the error message in `detail` and the tags `security` + `subprocess`.

On success, the produced `Report` MUST contain one `CheckResult` per
finding, named `security::<source>::<id>`, tagged `security` plus a
source-specific tag (`cve` for `Audit`, `policy` for `Deny`).

## 8. Stability

Through `0.9.x` the public API MAY shift. The `1.0` release pins the
API. The wire format of `Finding`, `FindingSource`, and `AuditResult`,
and the JSON shape emitted through `dev-report`, MUST stay stable
from `1.0` onward.
