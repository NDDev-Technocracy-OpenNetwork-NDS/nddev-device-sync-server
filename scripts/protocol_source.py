"""Read only the immutable protocol source declared by this consumer."""
import os
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol"
matches = re.findall(r"^protocol_commit: ([a-f0-9]{40})$", (ROOT / "module.yaml").read_text(), re.MULTILINE)
assert len(matches) == 1, "module manifest must pin one full protocol commit"
COMMIT = matches[0]


def source(name):
    local = Path(os.environ.get("NDS_PROTOCOL_SOURCE", str(ROOT.parent / "nddev-device-sync-protocol")))
    if local.is_dir():
        result = subprocess.run(["git", "-C", str(local), "show", f"{COMMIT}:{name}"], capture_output=True, env=os.environ | {"GIT_OPTIONAL_LOCKS": "0"}, timeout=10)
        if result.returncode == 0:
            assert len(result.stdout) <= 1024 * 1024, "protocol source exceeded its bound"
            return result.stdout
    url = f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/{name}"
    with urllib.request.urlopen(url, timeout=20) as response:
        data = response.read(1024 * 1024 + 1)
    assert len(data) <= 1024 * 1024, "protocol source exceeded its bound"
    return data
