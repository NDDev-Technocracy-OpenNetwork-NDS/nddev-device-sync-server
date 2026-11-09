# nddev-device-sync-server working contract

This public AGPL-3.0-only repository owns the generic Rust control-plane server. It must
remain independently self-hostable and must never contain private estate topology,
production endpoints, secrets, real telemetry or organization policy.

Read `contracts.lock` and the pinned protocol/core versions before editing. Keep
domain/application logic in the core module, wire contracts in the protocol module and
server I/O in adapters. Every endpoint needs structured telemetry, correlation, timeout
behavior and a focused test.

Prepare locked dependencies with `just setup`. `just check` is source-only:
browser type/lint checks, Rust format/license/source policy and cargo-shear.
Run `just test` and `just verify` only on execution hosts or runners: these include
Clippy, Rust/Bun tests, emitted JavaScript equivalence, release compilation,
advisories and protocol regeneration. Keep the existing PostgreSQL/SMTP,
protocol-projection, advisory and actual-container gates when changing CI.
