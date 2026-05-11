# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-05-11

### Added

- Initial crate skeleton.
- `AuditScope` enum: `Vulnerabilities`, `Policy`, `All`.
- `AuditRun` builder with `new`, `scope`, `audit_scope`, `execute`.
- `Finding` struct with id, title, severity, affected_crate.
- `AuditResult` with findings list and `count_at_or_above` filter.
- `AuditResult::into_report` produces a `dev-report::Report`.
- `AuditError` for tool-missing / subprocess / parse failures.
- Smoke tests covering scope selection, empty findings, severity filtering.

### Note

This is the name-claim release. The actual `cargo-audit` and
`cargo-deny` subprocess integrations land in `0.9.1`.

[Unreleased]: https://github.com/jamesgober/dev-security/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/jamesgober/dev-security/releases/tag/v0.9.0
