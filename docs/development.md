# Development workflow

Use the pinned toolchain and the repository's `just` recipes. Keep runtime
credentials, private estate data and live telemetry outside this repository.

Run `just setup` to fetch locked Cargo and Bun inputs, then `just check` for
source-only browser analysis, Rust formatting, cargo-deny license/source policy
and cargo-shear. Source checks compile no Rust or JavaScript and run no tests.
The workflow installs the source-check tools before this gate.

On an execution host, `just test` runs Clippy, Rust nextest/doctests, Bun tests,
the emitted browser JavaScript equivalence check, the advisory audit, pinned
protocol projection and the release build. Nextest uses the `ci` profile and
writes `.nddev-reports/nextest/ci/junit.xml`; Bun writes
`.nddev-reports/bun-test.xml`. `just verify` adds real PostgreSQL/SMTP acceptance.
Dependency and protocol pins stay authoritative for those checks.

The workflows call the public `NDDev-Technocracy-OpenNetwork/nddev-ci` library at
an immutable commit, with read-only repository access and explicit Node, Python,
Bun and Rust inputs. `.github/native-tools.json` pins the Linux x64 tool release
assets and their executable members by repository, immutable asset ID, size and
SHA-256. Hosted preparation verifies both the archive and each selected member
before adding a tool to the job's path; it never compiles quality tools as an
installation fallback. The project's `just` recipes own every validation step.

Pull requests run source checks and `just test`, together with the shared commit,
secret and workflow-security merge stops. Full runs execute `just verify` once,
then a separate job builds and exercises the actual server container. That job
retains the existing image name, health/source checks, receipt shape and
three-day image retention. It does not repeat the PostgreSQL/SMTP fixture.
A green result is not deployment, release or cross-platform acceptance. The
repository owns its release and runtime acceptance checks; the former CI result
bundle is no longer the producer contract. Diagnostic command output remains in
the workflow log, and the JUnit files are generated in the executing workspace.
The retained `main` producer is tracked by #134: its consumers must move to the
qualified `dev` image before promotion can reuse that result without rebuilding.

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
