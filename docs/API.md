# dev-security — API Reference

> Hand-written reference.

## Table of contents

- [`AuditScope`](#auditscope)
- [`AuditRun`](#auditrun)
  - [`AuditRun::new`](#auditrunnew)
  - [`AuditRun::scope`](#auditrunscope)
  - [Other builder methods](#other-builder-methods)
  - [`AuditRun::execute`](#auditrunexecute)
- [`Finding`](#finding)
- [`AuditResult`](#auditresult)
  - [Fields](#auditresult-fields)
  - [`AuditResult::count_at_or_above`](#auditresultcount_at_or_above)
  - [`AuditResult::into_report`](#auditresultinto_report)
- [`AuditError`](#auditerror)
- [`AuditProducer`](#auditproducer)

---

## `AuditScope`

```rust
pub enum AuditScope {
    Vulnerabilities,    // cargo-audit only
    Policy,             // cargo-deny only
    All,                // both
}
```

---

## `AuditRun`

```rust
pub struct AuditRun { /* private */ }
```

### `AuditRun::new`

```rust
pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self
```

| Parameter | Type                | Description    |
|-----------|---------------------|----------------|
| `name`    | `impl Into<String>` | Crate name.    |
| `version` | `impl Into<String>` | Crate version. |

### `AuditRun::scope`

```rust
pub fn scope(self, scope: AuditScope) -> Self
```

### Other builder methods

| Method                                    | Effect                                                         |
|-------------------------------------------|----------------------------------------------------------------|
| `in_dir(dir)`                             | Run both tools from `dir` instead of the current directory.    |
| `deny_config(path)`                       | Pass `--config <path>` to `cargo deny check`.                  |
| `allow(id)` / `allow_all(ids)`            | Drop findings whose `id` matches.                              |
| `severity_threshold(sev)`                 | Drop findings below `sev`.                                     |
| `audit_scope()` / `subject()` / `subject_version()` | Read back the configuration.                         |

### `AuditRun::execute`

```rust
pub fn execute(&self) -> Result<AuditResult, AuditError>
```

Run the configured audit. Findings are filtered through the allow-list
and severity threshold, sorted by `id`, and deduplicated by
`(id, affected_crate, affected_version)`, keeping the most severe copy.
`cargo audit` runs with `--no-fetch` and needs a local advisory
database (`cargo audit fetch`).

---

## `Finding`

```rust
pub struct Finding {
    pub id: String,                       // RUSTSEC-*, cargo-deny code, or "yanked"
    pub title: String,
    pub severity: Severity,               // from dev-report
    pub affected_crate: String,           // "<workspace>" for config-level findings
    pub affected_version: Option<String>,
    pub url: Option<String>,
    pub description: Option<String>,
    pub source: FindingSource,            // Audit | Deny
}
```

For `cargo-audit` vulnerabilities, `severity` is derived from the CVSS
base score of the advisory's vector (critical -> `Critical`, high ->
`Error`, medium -> `Warning`, low / none -> `Info`; no vector ->
`Warning`).

---

## `AuditResult`

```rust
pub struct AuditResult {
    pub name: String,
    pub version: String,
    pub scope: AuditScope,
    pub findings: Vec<Finding>,
}
```

### AuditResult fields

| Field      | Type             | Description                         |
|------------|------------------|-------------------------------------|
| `name`     | `String`         | Crate name.                         |
| `version`  | `String`         | Crate version.                      |
| `scope`    | `AuditScope`     | Scope that produced this result.    |
| `findings` | `Vec<Finding>`   | Discovered findings.                |

### `AuditResult::count_at_or_above`

```rust
pub fn count_at_or_above(&self, threshold: Severity) -> usize
```

Count findings at or above the given severity. Useful for gating
CI on "Critical or Error count > 0" without inspecting individual
findings.

### `AuditResult::count_from` / `AuditResult::worst_severity`

```rust
pub fn count_from(&self, source: FindingSource) -> usize
pub fn worst_severity(&self) -> Option<Severity>
```

Count findings from one tool; highest severity present (`None` when
there are no findings).

### `AuditResult::into_report`

```rust
pub fn into_report(self) -> Report
```

Convert findings into a `dev-report::Report`. Empty findings produces
a passing `security::audit` check.

---

## `AuditError`

```rust
pub enum AuditError {
    AuditToolNotInstalled,
    DenyToolNotInstalled,
    SubprocessFailed(String),
    ParseError(String),
}
```

Tool remediation: `cargo install cargo-audit cargo-deny`.

`SubprocessFailed` covers runs that could not complete: no `Cargo.toml`
or `Cargo.lock`, an invalid `deny.toml`, a missing advisory database.
Finding violations is not an error.

---

## `AuditProducer`

```rust
pub struct AuditProducer { /* private */ }
impl AuditProducer {
    pub fn new(run: AuditRun) -> Self;
    pub fn run(&self) -> &AuditRun;
}
impl dev_report::Producer for AuditProducer { /* ... */ }
```

Errors become a single failing `security::audit` check with
`Severity::Critical`, tagged `security` and `subprocess`.
