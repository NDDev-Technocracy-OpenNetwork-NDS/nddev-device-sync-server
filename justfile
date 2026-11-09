set shell := ["bash", "-euo", "pipefail", "-c"]

export CARGO_PROFILE_DEV_DEBUG := "0"
export CARGO_PROFILE_TEST_DEBUG := "0"

default:
    @just --list

setup:
    cargo fetch --locked
    bun install --frozen-lockfile --ignore-scripts

fmt-check:
    cargo fmt --all -- --check

test: clippy browser-generated advisories-check protocol-check release-build
    cargo nextest run --locked --workspace --jobs 4 --profile ci
    cargo test --locked --workspace --doc --jobs 4
    bun test --reporter=junit --reporter-outfile=.nddev-reports/bun-test.xml

clippy:
    cargo clippy --locked --workspace --all-targets --jobs 4 -- -D warnings

dependencies-check: advisories-check
    cargo deny --locked check licenses sources

advisories-check:
    cargo audit --deny warnings

release-build:
    cargo build --locked --workspace --release --jobs 4

check: browser-check fmt-check
    cargo deny --locked check licenses sources
    cargo shear --locked --deny-warnings

browser-check:
    bun run check

browser-generated:
    bun run check:generated

verify: check test integration-postgres

protocol-check:
    python3 scripts/check-protocol.py

protocol-generate:
    python3 scripts/check-protocol.py --write

# Real PostgreSQL + SMTP mailbox, tmpfs data and generated synthetic identities.
integration-postgres:
    cargo build --locked --jobs 4
    python3 scripts/check-postgres.py --fixture-passkeys
