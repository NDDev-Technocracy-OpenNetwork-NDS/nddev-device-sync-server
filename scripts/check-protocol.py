#!/usr/bin/env python3
"""Regenerate the consumed DTO from its immutable canonical source; no Git clone."""
import argparse
from pathlib import Path
import subprocess
import tempfile
from protocol_source import ROOT, source
FILES = ["package.json", "bun.lock", "scripts/generate-dtos.mjs", "contracts/v2/control-plane.schema.json", "contracts/v2/observability.schema.json", "contracts/v2/screen.schema.json", "contracts/v2/company.schema.json", "contracts/v3/sync.schema.json", "contracts/v3/personal.schema.json"]
arguments = argparse.ArgumentParser(description=__doc__)
arguments.add_argument("--write", action="store_true", help="Write the consumer DTOs from the exact manifest pin instead of checking drift")
options = arguments.parse_args()


with tempfile.TemporaryDirectory(prefix="nds-protocol-check-") as directory:
    directory = Path(directory)
    for name in FILES:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source(name))
    subprocess.run(["bun", "install", "--frozen-lockfile", "--ignore-scripts"], cwd=directory, check=True, timeout=120, stdout=subprocess.DEVNULL)
    for profile, target in [("auth", "protocol_v2.rs"), ("devices", "protocol_devices.rs"), ("personal", "protocol_personal.rs"), ("sync", "protocol_sync.rs"), ("sync3", "protocol_sync3.rs"), ("vault", "protocol_vault.rs"), ("observability", "protocol_observability.rs"), ("screen", "protocol_screen.rs"), ("company", "protocol_company.rs")]:
        output = directory / target
        subprocess.run(["node", "scripts/generate-dtos.mjs", "rust", profile, str(output)], cwd=directory, check=True, timeout=30)
        subprocess.run(["rustfmt", "--edition", "2024", str(output)], cwd=ROOT, check=True, timeout=20)
        destination = ROOT / "src" / target
        if options.write:
            destination.write_bytes(output.read_bytes())
        else:
            assert output.read_bytes() == destination.read_bytes(), "protocol DTO drift: run just protocol-generate from the manifest's exact protocol commit"
print("Canonical Rust consumer DTOs generated." if options.write else "Canonical Rust consumer DTO regeneration passed.")
