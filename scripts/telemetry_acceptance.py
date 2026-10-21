"""Use the canonical pinned validator on real process output without retaining it."""
from pathlib import Path
import subprocess
import sys
from protocol_source import source


class TelemetryValidator:
    def __init__(self, directory):
        self.root = Path(directory) / "telemetry-contract"
        for name in ["requirements.lock", "scripts/validate.py", "scripts/validate-events.py", "contracts/v2/telemetry-event.schema.json"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source(name))
        subprocess.run([sys.executable, "-m", "venv", str(self.root / ".venv")], check=True, timeout=30)
        self.python = self.root / ".venv/bin/python"
        subprocess.run([str(self.python), "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes", "-r", str(self.root / "requirements.lock")], check=True, timeout=120, stdout=subprocess.DEVNULL)

    def __call__(self, logs):
        # The canonical validator reports counts/constraint names only. Process
        # output travels through stdin and is never written to a fixture file.
        result = subprocess.run([str(self.python), str(self.root / "scripts/validate-events.py")], input=logs, text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())

    def stream(self):
        # The canonical validator reads bounded NDJSON records. A fixture may
        # outlive an in-memory transcript; the OS pipe supplies backpressure.
        return subprocess.Popen([str(self.python), str(self.root / "scripts/validate-events.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def finish_stream(self, process):
        try:
            output, _ = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
            raise AssertionError("streamed telemetry validation timed out") from None
        assert process.returncode == 0, output
        print(output.strip())
