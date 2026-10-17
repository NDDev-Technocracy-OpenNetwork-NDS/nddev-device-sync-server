# nddev-device-sync-server

Public AGPL-3.0-only Rust control-plane server for `nddev-device-sync`.

Part of [NDDev OpenNetwork](https://nddev.ai).

The current server provides:

- one shared SDK JSON envelope for process, migration and request events;
- real local OpenTelemetry request/SMTP spans and native W3C `traceparent` correlation;
- `/v1/health`, `/v1/ready` and `/source` endpoints;
- PostgreSQL readiness and an explicit migration command with a separate identity;
- direct Rust/rustls HTTPS, bounded connection drain and safe certificate reload;
- finite connection/handler admission and scoped, expiring debug diagnostics;
- email OTP, explicitly bound GitHub identities and browser WebAuthn passkeys;
- signed company invitations, revision-checked membership and last-administrator protection;
- bounded passkey metadata and fresh-session credential/session revocation;
- browser pairing approval, expiring/revocable sessions and bounded abuse controls;
- session-bound Ed25519 device enrollment, paged owner inventory and revocation;
- signed owned screen endpoint binding and finite view metadata/artifact control;
  native capture and shared Flutter pixels are separate consumer acceptance;
- signed encrypted sync operations, immutable idempotency receipts and explicit conflicts;
- automatic owner-key delivery to authenticated active devices, with encrypted PostgreSQL key envelopes;
- signed client event/native OTLP ingress, operator delivery status and incident actions;
- generated wire types and immutable core/protocol source pins;
- compatible health metadata without a speculative core module registry.

The legacy `module_count` health field is zero: the server composes no local-tool
adapters. The native agent discovers those adapters; core owns their observation
rules and the shared replica policy.

Company identity storage preserves existing user/device/Vault bindings. Personal
data remains owner-only, including for administrators. The administrative API and
SMTP invitation/OTP path are implemented. RDS control metadata permits current
same-company administrators to request another member's device while retaining
participant-only grants and current-session/membership revalidation. Device
discovery and end-to-end screen capture remain separate client acceptance. Global monitoring
controls remain bound to the configured deployment operator, independently of
company roles; ordinary clients use the narrow export-policy endpoint.

Sync reads honor the requested limit up to 100 operations and stop before the
encoded JSON page exceeds the core's 60 KiB budget. A truncated page advances
only through its included operations and retains `has_more`; the existing
two-item default remains compatible with callers that omit a limit.

Vault keys are wrapped under a distinct operator key outside PostgreSQL; the
server has decryption authority. Native key caching and ciphertext replicas
belong to clients. Without private identity configuration, `/v2/auth/methods`
reports unavailable methods. Provider readiness does not prove a completed
sign-in or delivery to an external mailbox.

## Local development

```sh
just fmt-check
just test
just clippy
just protocol-check
just integration-postgres
```

The PostgreSQL/SMTP acceptance also validates actual process NDJSON against the
closed telemetry schema at the manifest's exact protocol commit, including
formats and the 16 KiB event limit. Its canonical Python validator runs in a
temporary virtual environment with hash-locked dependencies; Python 3 with
`venv` and pip support is required. OpenSSL provides an independent Ed25519
signer for real enrollment acceptance. Event values are neither saved nor printed.

Set `DATABASE_URL_FILE` (or `DATABASE_URL`) to enable PostgreSQL readiness.
Run the explicit `migrate` command with `NDS_MIGRATION_DATABASE_URL_FILE` first;
runtime startup does not execute DDL. Without a runtime database URL the process
still starts for route tests, while `/v1/ready` reports degraded.

See [self-hosting](docs/self-hosting.md) for HTTPS, mounted secrets, role separation,
Compose, certificate reload and resource bounds, and [dependency decisions](docs/dependencies.md).

Requests have a 15-second handler deadline; pool acquisition and database
readiness queries have a 3-second deadline. Completion logs retain the request
trace/span context and use matched route patterns, never raw URL paths or query
strings. Database readiness errors expose a stable error class rather than
driver messages. The maintained W3C propagator validates incoming `traceparent`
and `tracestate`, including future-version handling; malformed or repeated
traceparent headers start a fresh SDK trace. Each propagation header is capped
at 512 bytes before native parsing. Remote sampling does not suppress
local error/security events. SMTP jobs retain immutable parent IDs, not the live
HTTP span, and create their own delivery span.
All HTTP responses, including readiness failures and timeouts, use
`Cache-Control: no-store`. An instance that requires direct origin access must
also use DNS-only records and omit CDN/proxy response caching in its deployment.

The local JSON log remains available for diagnosis. The telemetry-enabled health
field describes operator intent. Configure `NDS_OTLP_ENDPOINT` with the origin of
an operator-owned Vector collector to export actual native request and operation
spans through the shared SDK. Setting `NDS_TELEMETRY_ENABLED=off` prevents exporter
construction; local error/security records remain available. Native OTLP uses the internal Vector endpoint; the optional signed client
gateway separately holds operator-configured ingest/admin tokens, never client
credentials for the indexing backend. Tracing admission, retries and shutdown are
bounded; the SDK records successful batches, failures and dropped spans. Confirm
actual OpenObserve receipt independently of the configuration flag.

The signed trace gateway returns the receiver's accepted span count in the
existing receipt, including valid partial success and zero accepted spans.
A warning with `rejected_spans=0` still acknowledges the full batch. Negative or
excess rejected counts and malformed protobuf fail closed; receiver text is
neither returned nor logged. A valid partial receipt settles the entire batch
without resending it. Before deploying this server, qualify the exact native
and browser client cohort against Protocol alpha.16: older clients require a
full-count receipt and may retry partially accepted spans.

Browser release acceptance can use `--fixture-tls` together with an explicit
`--fixture-receipt`. The harness generates a short-lived loopback certificate,
validates it with a private Python trust context and writes only its certificate
path/public-key digest to the private receipt. A test browser must trust that
exact fixture certificate independently; no system trust or live certificate
is changed. This option is confined to the acceptance harness.

Client catalog acceptance uses `--fixture-sync3` with `--fixture-receipt`.
The fixture operator explicitly admits current writes only after the client
creates its empty owner counter. Migration defaults and existing histories are
unchanged; the real client must negotiate the admitted format.
