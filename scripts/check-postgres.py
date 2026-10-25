#!/usr/bin/env python3
"""Disposable loopback-only PostgreSQL acceptance; never uses operator credentials."""
import json
import argparse
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from identity_acceptance import check_identity
from telemetry_acceptance import TelemetryValidator

arguments = argparse.ArgumentParser(description="Real isolated PostgreSQL/SMTP acceptance or a bounded client fixture")
arguments.add_argument("--fixture-receipt", type=Path)
arguments.add_argument("--observability-config", type=Path, help="Explicit owned loopback collector fixture configuration")
arguments.add_argument("--fixture-seconds", type=int, default=1200)
arguments.add_argument("--fixture-tls", action="store_true", help="Owned ephemeral localhost TLS certificate for browser release acceptance")
arguments.add_argument("--fixture-passkeys", action="store_true", help="Use the localhost secure browser origin for owned passkey acceptance")
arguments.add_argument("--fixture-sync3", action="store_true", help="Explicitly admit current writes for the fresh, empty fixture owner")
arguments.add_argument("--upgrade-from", type=Path, help="Existing immutable schema9 server binary outside this repository, for real upgrade acceptance")
arguments.add_argument("--upgrade-company", action="store_true", help="Also qualify production company migration SQL with encrypted witnesses in a separate owned database (cryptography50.0.2 required)")
arguments.add_argument("--fixture-web-root", type=Path, help="Owned manifest-verified browser test bundle, served by the real server")
options = arguments.parse_args()
if options.upgrade_from is not None:
    if not options.upgrade_from.is_absolute() or not options.upgrade_from.is_file() or options.upgrade_from.resolve().is_relative_to(Path(__file__).resolve().parent.parent):
        arguments.error("upgrade source must be an explicit existing binary outside the repository")
if options.fixture_tls and options.fixture_receipt is None:
    arguments.error("TLS browser acceptance requires an owned fixture")
if options.fixture_sync3 and options.fixture_receipt is None:
    arguments.error("sync admission requires an owned client fixture")
if not 60 <= options.fixture_seconds <= 14400:
    arguments.error("fixture lifetime must be 60..14400 seconds")
if options.fixture_receipt is not None:
    repository = Path(__file__).resolve().parent.parent
    receipt = options.fixture_receipt.resolve()
    if not options.fixture_receipt.is_absolute() or receipt.is_relative_to(repository) or receipt.exists():
        arguments.error("fixture receipt must be a new absolute path outside the repository")

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"
BINARY = Path(json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
    cwd=ROOT, text=True, timeout=30))["target_directory"]) / "debug/nddev-device-sync-server"
name = "nds-db-check-" + uuid.uuid4().hex[:12]
created = False
server = None
lock_holder = None


def command(*args, **kwargs):
    kwargs.setdefault("timeout", 90)
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def sql(statement, role="postgres", check=True, database="nds"):
    return subprocess.run(["docker", "exec", "-i", name, "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", role, "-d", database, "-f", "-"], input=statement, check=check, capture_output=True, text=True, timeout=10)


LOCAL_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def wait_ready(port, wanted):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with LOCAL_HTTP.open(f"http://127.0.0.1:{port}/v1/ready", timeout=1) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        except urllib.error.URLError:
            time.sleep(0.1)
            continue
        if status == wanted:
            return
        time.sleep(0.1)
    raise AssertionError("readiness did not reach expected status")


try:
    with tempfile.TemporaryDirectory(prefix="nds-db-check-") as directory:
        directory = Path(directory)
        validate_events = TelemetryValidator(directory)
        passwords = {kind: secrets.token_hex(24) for kind in ["admin", "migrator", "runtime"]}
        mounts = []
        for kind, password in passwords.items():
            path = directory / f"postgres_{kind}_password"
            path.write_text(password)
            path.chmod(0o444)  # Ephemeral parent is private; postgres UID reads bind-mounted file.
            mounts.extend(["--mount", f"type=bind,src={path},dst=/run/secrets/{path.name},readonly"])
        # A private checkout umask can make the source unreadable to the container UID.
        init_script = directory / "postgres-init.sh"
        init_script.write_bytes((ROOT / "deploy/postgres-init.sh").read_bytes())
        init_script.chmod(0o555)
        # Actual retained-byte saturation needs log bodies plus PostgreSQL WAL;
        # this disposable fixture stays bounded independently of product limits.
        command("docker", "run", "--rm", "--detach", "--name", name, "--user", "postgres", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--memory", "768m", "--cpus", "1", "--pids-limit", "128", "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql:uid=999,gid=999,mode=0700,size=512m", "--tmpfs", "/var/run/postgresql:uid=999,gid=999,mode=3775,size=16m", "--tmpfs", "/tmp:uid=999,gid=999,mode=1777,size=16m", "--env", "POSTGRES_DB=nds", "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_admin_password", *mounts, "--mount", f"type=bind,src={init_script},dst=/docker-entrypoint-initdb.d/10-nds-roles.sh,readonly", IMAGE)
        created = True
        host_port = json.loads(command("docker", "inspect", name))[0]["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
        for _ in range(100):
            # Initdb restarts PostgreSQL after provisioning roles. Every probe
            # must tolerate that transition rather than chaining a checked query.
            result = sql("SELECT count(*) FROM pg_roles WHERE rolname='nds_runtime'", check=False)
            if result.returncode == 0 and result.stdout.strip() == "1":
                # Wait for final TCP server, not the initialization socket server.
                probe = subprocess.run(["docker", "exec", name, "pg_isready", "--quiet",
                    "--host", "127.0.0.1", "--port", "5432", "--username", "nds_runtime",
                    "--dbname", "nds"], capture_output=True, timeout=5)
                if probe.returncode == 0:
                    break
            time.sleep(0.1)
        else:
            raise AssertionError("disposable PostgreSQL did not initialize")
        from authority_migration_acceptance import check_authority_upgrade
        sql("CREATE DATABASE nds_authority_upgrade OWNER nds_migrator")
        try:
            check_authority_upgrade(lambda statement, role="postgres", check=True:
                                    sql(statement, role, check, "nds_authority_upgrade"))
        finally:
            sql("DROP DATABASE nds_authority_upgrade")
        if options.upgrade_company:
            from company_migration_acceptance import check_company_upgrade
            sql("CREATE DATABASE nds_company_upgrade OWNER nds_migrator")
            try:
                check_company_upgrade(lambda statement, role="postgres", check=True:
                                      sql(statement, role, check, "nds_company_upgrade"))
            finally:
                sql("DROP DATABASE nds_company_upgrade")
        urls = {}
        for kind, password in passwords.items():
            role = "postgres" if kind == "admin" else "nds_" + kind
            path = directory / f"{kind}_url"
            path.write_text(f"postgres://{role}:{password}@127.0.0.1:{host_port}/nds\n")
            urls[kind] = str(path)
        env = {key: value for key, value in os.environ.items() if not key.startswith(("NDS_", "DATABASE_URL")) and key != "RUST_LOG"}
        if options.fixture_web_root is not None:
            web_root = options.fixture_web_root.resolve()
            if not options.fixture_receipt or not options.fixture_web_root.is_absolute() or web_root.is_relative_to(ROOT):
                arguments.error("browser assets require an owned fixture and absolute private bundle path")
            if not (web_root / "nds-assets.json").is_file():
                arguments.error("browser fixture bundle requires the ordinary production asset manifest")
            env["NDS_WEB_ROOT"] = str(web_root)
        if options.observability_config is not None:
            config = options.observability_config.resolve()
            if not options.fixture_receipt or not options.observability_config.is_absolute() or config.is_relative_to(ROOT):
                arguments.error("observability configuration requires an owned fixture and absolute private path")
            from urllib.parse import urlparse
            settings = json.loads(config.read_text())
            if any(urlparse(settings[key]).scheme != "http" or urlparse(settings[key]).hostname != "127.0.0.1" for key in ["origin", "trace_origin"]):
                arguments.error("acceptance collector must use explicit loopback origins")
            env["NDS_OBSERVABILITY_CONFIG_FILE"] = str(config)
        env["DATABASE_URL_FILE"] = urls["runtime"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env["NDS_SERVER_ADDR"] = f"127.0.0.1:{port}"
        env["NDS_MAX_REQUESTS"] = "1"
        env["NDS_LOG_MODE"] = "normal"
        for key in ["NDS_DEBUG_SCOPE", "NDS_DEBUG_SECONDS", "NDS_DEBUG_EVENT_LIMIT"]:
            env.pop(key, None)
        server = subprocess.Popen([BINARY, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_ready(port, 503)
        assert sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").stdout.strip() == "0", "runtime created schema before migrations"
        server.terminate()
        logs = server.communicate(timeout=25)[0]
        assert server.returncode == 0
        server = None
        migration_env = env | {"NDS_MIGRATION_DATABASE_URL_FILE": urls["migrator"]}
        upgrade_witness = None
        if options.upgrade_from is not None:
            logs += command(str(options.upgrade_from), "migrate", env=migration_env) + "\n"
            assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "9"
            assert sql("SELECT count(*) FROM _sqlx_migrations WHERE success").stdout.strip() == "9"
            sql("INSERT INTO nddev_schema_meta(key,value) VALUES('upgrade_acceptance','retained9')")
            from upgrade_acceptance import prepare, verify, clean, check_rejected_history
            upgrade_witness = prepare(sql)
            check_rejected_history(sql, upgrade_witness)
            server = subprocess.Popen([BINARY, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            wait_ready(port, 503)
            server.terminate()
            logs += server.communicate(timeout=25)[0]
            assert server.returncode == 0
            server = None
        for _ in range(2):
            logs += command(str(BINARY), "migrate", env=migration_env) + "\n"
            if upgrade_witness is not None:
                verify(sql, upgrade_witness)
                assert sql("SELECT authenticated_at_ms=GREATEST(expires_at_ms-28800000,0) FROM nds_sessions").stdout.strip() == "t"
        assert sql("SELECT count(*) FROM _sqlx_migrations WHERE success").stdout.strip() == "14"
        assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "14"
        assert sql("SELECT to_regclass('public.nds_sync_operations') IS NULL").stdout.strip() == "t"
        assert sql("UPDATE public.nds_replica_counters SET admission_version=3 WHERE false", "nds_runtime", check=False).returncode != 0
        if options.upgrade_from is not None:
            assert sql("SELECT value FROM nddev_schema_meta WHERE key='upgrade_acceptance'").stdout.strip() == "retained9"
            server = subprocess.Popen([options.upgrade_from, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            wait_ready(port, 503)
            server.terminate()
            logs += server.communicate(timeout=25)[0]
            assert server.returncode == 0
            server = None
            clean(sql, upgrade_witness)
            print("Schema9-to14 upgrade passed: seven canonical identity/device/vault/sync rows preserve original columns and decrypt after migration and repeat; new runtime rejects schema9 and old runtime rejects schema14 readiness; old migration history retained.")
        assert sql("CREATE TABLE prohibited(id INT)", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE _sqlx_migrations SET success=false WHERE false", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE nds_sessions SET expires_at_ms=expires_at_ms WHERE false", "nds_runtime", check=False).returncode == 0
        assert sql("UPDATE nds_sessions SET authenticated_at_ms=authenticated_at_ms WHERE false", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE nds_sessions SET auth_method=auth_method WHERE false", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE nds_sessions SET user_id=user_id WHERE false", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE nds_devices SET public_key=public_key WHERE false", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE nds_enrollment_challenges SET challenge=challenge WHERE false", "nds_runtime", check=False).returncode != 0
        server = subprocess.Popen([BINARY, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_ready(port, 200)
        # Actual PostgreSQL lock contention holds the only request permit. The
        # second HTTP request must reject immediately, and recover after release.
        lock_holder = subprocess.Popen(["docker", "exec", name, "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "nds", "-c", "BEGIN; LOCK TABLE nddev_schema_meta IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(2); COMMIT;"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            if sql("SELECT count(*) FROM pg_locks WHERE relation='nddev_schema_meta'::regclass AND mode='AccessExclusiveLock' AND granted").stdout.strip() == "1":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("lock holder did not acquire table lock")
        with ThreadPoolExecutor(max_workers=1) as executor:
            waiting = executor.submit(urllib.request.urlopen, f"http://127.0.0.1:{port}/v1/ready", timeout=5)
            for _ in range(100):
                if sql("SELECT count(*) FROM pg_stat_activity WHERE usename='nds_runtime' AND wait_event_type='Lock'").stdout.strip() == "1":
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("readiness did not wait on real database contention")
            try:
                LOCAL_HTTP.open(f"http://127.0.0.1:{port}/v1/health", timeout=1)
                raise AssertionError("request admission did not reject saturation")
            except urllib.error.HTTPError as error:
                assert error.code == 503
                assert error.headers["Cache-Control"] == "no-store"
                assert error.headers["Retry-After"] == "1"
                assert len(error.headers["X-Request-Id"]) == 32
                assert json.load(error)["error"] == "server_busy"
            with waiting.result(timeout=5) as response:
                assert response.status == 200
        lock_holder.communicate(timeout=5)
        assert lock_holder.returncode == 0
        lock_holder = None
        with LOCAL_HTTP.open(f"http://127.0.0.1:{port}/v1/health", timeout=1) as response:
            assert response.status == 200
        server.terminate()
        logs += server.communicate(timeout=25)[0]
        assert server.returncode == 0
        server = None
        rejected = subprocess.run([BINARY, "serve"], env=env | {"DATABASE_URL_FILE": urls["admin"]}, capture_output=True, text=True, timeout=8)
        assert rejected.returncode != 0
        logs += rejected.stdout + rejected.stderr
        assert any(event.get("event.name") == "process.failed" and event.get("error.type") == "database_runtime_role" for event in map(json.loads, rejected.stdout.splitlines()))
        for password in passwords.values():
            assert password not in logs
        assert str(directory) not in logs
        events = [json.loads(line) for line in logs.splitlines() if line.strip()]
        validate_events(logs)
        for event_name in ["database.migration.started", "database.migration.completed", "process.failed", "admission.saturated", "admission.recovered"]:
            assert any(event["event.name"] == event_name for event in events)
        print("PostgreSQL acceptance passed: migrations replay safely; restricted runtime performs no DDL; real database contention proves bounded request admission and recovery; process/migration envelopes and secrets are verified.")
        check_identity(BINARY, directory, env, sql, command, validate_events, options.fixture_receipt, options.fixture_seconds, options.fixture_passkeys, options.fixture_tls, options.fixture_sync3)
finally:
    if lock_holder is not None:
        lock_holder.terminate()
        lock_holder.communicate(timeout=5)
    if server is not None:
        server.terminate()
        server.communicate(timeout=25)
    if created:
        command("docker", "stop", "--time", "10", name)
