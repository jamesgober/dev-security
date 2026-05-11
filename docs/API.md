# dev-security — API Reference

> Hand-written reference.

## Table of contents

- [`AuditScope`](#auditscope)
- [`AuditRun`](#auditrun)
  - [`AuditRun::new`](#auditrunnew)
  - [`AuditRun::scope`](#auditrunscope)
  - [`AuditRun::execute`](#auditrunexecute)
- [`Finding`](#finding)
- [`AuditResult`](#auditresult)
  - [Fields](#auditresult-fields)
  - [`AuditResult::count_at_or_above`](#auditresultcount_at_or_above)
  - [`AuditResult::into_report`](#auditresultinto_report)
- [`AuditError`](#auditerror)

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

### `AuditRun::execute`

```rust
pub fn execute(&self) -> Result<AuditResult, AuditError>
```

Run the configured audit.

---

## `Finding`

```rust
pub struct Finding {
    pub id: String,             // RUSTSEC-* or policy rule name
    pub title: String,
    pub severity: Severity,     // from dev-report
    pub affected_crate: String,
}
```

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
