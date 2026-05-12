# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.2] - 2026-05-12

Bug-fix release surfaced by the post-polish audit pass.

### Fixed

- `deny::short_title()` no longer panics when the first 117 bytes of a `cargo-deny` diagnostic message end inside a multi-byte UTF-8 codepoint. The naive `&first_line[..117]` slice has been replaced with a char-boundary walkback. A regression test pins the behavior using a string with `é` (2-byte) characters straddling the truncation index.
- `deny::parse()` no longer emits findings with `affected_crate: ""` when a diagnostic record has no `graphs` entries (workspace-level policy violations). Empty names now become the explicit `<workspace>` sentinel so consumers can detect the case rather than silently swallowing an empty string.
- Dead `counter` variable removed from `deny::parse()` — it had no effect, masked the real iteration flow, and was flagged by the audit as suspicious.

### Internal

- Two new tests: `short_title_handles_multibyte_at_truncation_boundary` (UTF-8 regression) and `empty_graphs_become_workspace_sentinel` (sentinel behavior).

[0.9.2]: https://github.com/jamesgober/dev-security/releases/tag/v0.9.2

## [0.9.1] - 2026-05-12

Documentation and SEO pass. No code changes.

### Changed

- README header standardized: Rust logo image, MSRV badge between CI and docs.rs (was at the end of the badge list, lowercase label), copyright block at bottom.
- Subtitle now reads `DEPENDENCY AUDIT & LICENSE POLICY FOR RUST` (was `SECURITY AUDITING FOR RUST`). More specific; surfaces the license-policy half of the crate's value.
- Tagline rewritten to lead with the underlying tools (`cargo-audit` + `cargo-deny`) and the outcomes (CVEs, license policy, banned crates).
- `## The dev-* suite` retitled to `The dev-* collection` and expanded with the full 14-crate map.
- `Cargo.toml` description rewritten: leads with the wrapped tools and the actual policy surface.
- `Cargo.toml` keywords retuned: dropped `verification` and `ai-tools`, added `license` and `rustsec` for crates.io search.

### Added

- "Part of the `dev-*` verification collection" block on the README, under the intro, linking the umbrella `dev-tools` crate.

[0.9.1]: https://github.com/jamesgober/dev-security/releases/tag/v0.9.1

## [0.9.0] - 2026-05-12

Foundation release. Replaces the `0.1.0` name-claim with full
`cargo-audit` + `cargo-deny` integration.

### Added

- Real `cargo audit --json --no-fetch` subprocess integration. Parses
  the `vulnerabilities.list` array plus every entry in the `warnings`
  map (unmaintained, yanked, notice, etc.). Tool absence and parse
  failures surface as typed `AuditError` variants — no panics.
- Real `cargo deny --format json check` subprocess integration with
  NDJSON parsing. Skips non-diagnostic records gracefully.
- Severity mapping per REPS § 6:
  - `cargo-audit` `severity` field: `critical` → `Critical`, `high` → `Error`, `medium` → `Warning`, `low` / `none` → `Info`. Missing severity defaults to `Warning`.
  - `cargo-audit` warnings (unmaintained / yanked / notice) → `Warning`.
  - `cargo-deny` severity: `error` → `Error`, `warning` → `Warning`, `help` / `note` → `Info`.
- `AuditRun` builder methods: `in_dir(path)`, `deny_config(path)`, `allow(id)`, `allow_all(iter)`, `severity_threshold(sev)`, `subject()`, `subject_version()`.
- `FindingSource` enum (`Audit`, `Deny`) so consumers can tell which tool produced each finding.
- `Finding` expanded: added `affected_version`, `url`, `description`, `source`. All optional except `source` and the original four. Fields with `Option` defaults are omitted from JSON when absent.
- `AuditResult` methods: `count_from(source)`, `worst_severity()`.
- Deterministic output: findings are filtered through the allow-list and severity threshold, deduplicated by `(id, affected_crate)`, and sorted by `id` then `affected_crate`.
- `AuditResult::into_report` now emits one `CheckResult` per finding named `security::<source>::<id>` with the `security` tag plus a source-specific tag (`cve` for audit findings, `policy` for deny findings). Each carries `Evidence::KeyValue` with crate / version / url metadata, plus an optional `description` snippet.
- New `producer` module exposing `AuditProducer`: a `dev_report::Producer` adapter. Subprocess failures map to a `CheckResult::fail("security::audit", Severity::Critical)` rather than panicking.
- Examples: `basic.rs` (graceful tool-missing handling for both tools), `audit_only.rs` (Vulnerabilities scope), `policy_only.rs` (Policy scope), `producer.rs` (Producer integration, gated by `DEV_SECURITY_EXAMPLE_RUN`).
- 26 unit tests across `lib.rs`, `audit.rs`, `deny.rs`, `producer.rs`. Coverage includes: severity-label mapping for every level, JSON parsing for `cargo audit` vulnerabilities and warnings (both array and single-entry shapes), NDJSON parsing for `cargo deny` (error / warning / help / unknown severities), garbage-input rejection, source filtering, severity threshold filtering, worst-severity picking, and JSON round-trip on `AuditResult`.
- 9 integration tests in `tests/smoke.rs`. One real-subprocess test gated by `#[ignore]` — it requires both `cargo-audit` *and* `cargo-deny`, plus `CARGO_TARGET_DIR` pointing outside the workspace, because the inner cargo invocations otherwise block on the workspace target-dir lock.

### Changed

- `cargo install cargo-audit` and `cargo install cargo-deny` are now real runtime requirements (previously declared but the code did not actually invoke them).
- README rewritten: removes the "subprocess integration lands in 0.9.1" disclaimer, documents the allow-list and severity-threshold workflow, describes the JSON shape of `Finding`, and pins MSRV at 1.85.
- REPS.md tightened: the "SHOULD provide" items (`cargo-audit` integration, `cargo-deny` integration, severity-threshold gating, allow-list management) are now MUST-have for 0.9.x.
- CI workflow: new `integration` job installs both `cargo-audit` and `cargo-deny` via `taiki-e/install-action` and verifies they run. Path-dep `../dev-report` is cloned in every job. `actions/checkout@v5` everywhere.

### Dependencies

- Added: `serde` 1.0 (derive feature), `serde_json` 1.0. Both required for parsing `cargo audit --json` and `cargo deny --format json` and for serializing `AuditResult` / `Finding`.
- Added: `tempfile` 3 as a `dev-dependency` for filesystem-backed tests.

### Note

`0.1.0` was a name-claim publish with a stub `execute()` returning empty findings. The public API additions in 0.9.0 are mostly additive but `Finding` gained four new fields, so direct struct construction must be updated — see the migration block in the README.

[Unreleased]: https://github.com/jamesgober/dev-security/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/jamesgober/dev-security/releases/tag/v0.9.0
[0.1.0]: https://github.com/jamesgober/dev-security/releases/tag/v0.1.0
