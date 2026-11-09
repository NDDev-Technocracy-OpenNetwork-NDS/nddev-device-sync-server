set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

setup:
    cargo fetch --locked
    bun install --frozen-lockfile --ignore-scripts

fmt-check:
    cargo fmt --all -- --check

test: clippy browser-generated
    cargo nextest run --locked --workspace --jobs 4
    cargo test --locked --workspace --doc --jobs 4
    bun test

clippy:
    cargo clippy --locked --workspace --all-targets --jobs 4 -- -D warnings

dependencies-check:
    cargo audit --deny warnings
    cargo deny --locked check licenses sources

check: browser-check fmt-check
    cargo deny --locked check licenses sources
    cargo shear --locked --deny-warnings

browser-check:
    bun run check

browser-generated:
    bun run check:generated

verify: check test dependencies-check protocol-check integration-postgres

protocol-check:
    python3 scripts/check-protocol.py

protocol-generate:
    python3 scripts/check-protocol.py --write

# Real PostgreSQL + SMTP mailbox, tmpfs data and generated synthetic identities.
integration-postgres:
    cargo build --locked --jobs 4
    python3 scripts/check-postgres.py --fixture-passkeys
