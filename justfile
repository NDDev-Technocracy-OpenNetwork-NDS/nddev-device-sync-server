set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt-check:
    cargo fmt --all -- --check

test:
    cargo nextest run --locked --workspace --jobs 4
    cargo test --locked --workspace --doc --jobs 4

clippy:
    cargo clippy --locked --workspace --all-targets --jobs 4 -- -D warnings

dependencies-check:
    cargo audit --deny warnings
    cargo deny --locked check licenses sources

check: browser-check fmt-check test clippy dependencies-check

browser-check:
    bun install --frozen-lockfile --ignore-scripts
    bun run check
    bun run check:generated

protocol-check:
    python3 scripts/check-protocol.py

protocol-generate:
    python3 scripts/check-protocol.py --write


# Real PostgreSQL + SMTP mailbox, tmpfs data and generated synthetic identities.
integration-postgres:
    cargo build --locked --jobs 4
    python3 scripts/check-postgres.py --fixture-passkeys
