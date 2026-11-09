# Development workflow

Use the pinned toolchain and the repository's `just` recipes. Keep runtime
credentials, private estate data and live telemetry outside this repository.

Run `just setup` to fetch locked Cargo and Bun inputs, then `just check` for
source-only browser analysis, Rust formatting, cargo-deny license/source policy
and cargo-shear. Source checks compile no Rust or JavaScript and run no tests.
The workflow installs the source-check tools before this gate.

On an execution host, `just test` runs Clippy, Rust nextest/doctests, Bun tests
and the emitted browser JavaScript equivalence check. `just verify` adds the
advisory audit, pinned protocol projection and real PostgreSQL/SMTP acceptance.
Existing CI retains its complete native contract and separate real-container
qualification. Dependency and protocol pins stay authoritative for those checks.

The `NDS checks / quality` job runs on GitHub-hosted Ubuntu with read-only
repository permissions and immutable action pins. It checks this repository's
current foundation. A green result is not deployment, release, integration or
cross-platform acceptance. The repository owns its release and runtime acceptance checks.

## Source compatibility

`contracts.lock` records the immutable product identity contract.
ADR 0006 defines the three sign-in methods and server-managed vault keys;
ADR 0007 defines browser sessions and offline replicas. `module.yaml` records
the paired core and protocol commits. Source updates do not rename published
releases or imply deployment or client-platform acceptance.

`just protocol-check` regenerates the owned authentication DTO from the exact
protocol commit, its locked quicktype tool and rustfmt. It reads existing local
Git objects when available or downloads only the pinned source files into a
temporary directory. It never clones another checkout or edits the generated
consumer as a substitute for changing its canonical schema.

Run `just integration-postgres` for the explicit migration boundary. It creates
only a new loopback-only PostgreSQL container with tmpfs storage and generated
test secrets, validates migrations from zero and repeated runs, proves the
runtime cannot create tables or modify the SQLx ledger, rejects an administrative
runtime identity, and stops that test container. The same isolated database and
a pinned Mailpit SMTP mailbox exercise real OTP delivery, concurrent replay,
resend/attempt/expiry rules, owner binding, session persistence/revocation and
socket-source rate limits. Private operator databases and mailboxes are not used.
Local SMTP capture does not prove delivery to an external provider's mailbox;
live GitHub identity/consent acceptance remains a separate observation.

For a real client, `scripts/check-postgres.py --fixture-receipt <new-absolute-path>
--fixture-seconds 1800` starts the same isolated runtime and writes a private
receipt containing its loopback API, Mailpit API and generated owner address.
Create the receipt's `stop_marker` to finish early; the bounded lease also stops
the owned processes/containers automatically. The receipt must be outside Git.
`--fixture-passkeys` uses the `localhost` origin required by WebAuthn.
`--fixture-web-root <absolute-directory>` hosts a task-owned manifest-verified
artifact through the ordinary server adapter. The receipt's `control_file`
accepts `{"mode":"offline"}` or `{"mode":"online"}` to stop or restart only
the owned listener while retaining its disposable database and mailbox.
