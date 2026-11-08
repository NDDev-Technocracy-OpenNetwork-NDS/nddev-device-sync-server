# nddev-device-sync-server working contract

This public AGPL-3.0-only repository owns the generic Rust control-plane server. It must
remain independently self-hostable and must never contain private estate topology,
production endpoints, secrets, real telemetry or organization policy.

Read `contracts.lock` and the pinned protocol/core versions before editing. Keep
domain/application logic in the core module, wire contracts in the protocol module and
server I/O in adapters. Every endpoint needs structured telemetry, correlation, timeout
behavior and a focused test.
