"""Real HTTP + PostgreSQL + isolated SMTP mailbox acceptance. No external mail."""
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from enrollment_acceptance import check_enrollment
from sync_acceptance import check_sync
from screen_acceptance import check_screen
from browser_acceptance import check_browser
from company_identity_acceptance import check_company_identity

MAILPIT = "axllent/mailpit:v1.31.4@sha256:b68349e3a014b90c5610bfb26b2ae36f3892d7b8cf25ee140c6c71c98d2fcf48"


def publish_fixture_receipt(path, state, *, initial=False):
    pending = path.with_suffix(".pending")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(state, handle)
        if initial:
            os.link(pending, path)  # Publish without overwriting an existing receipt.
        else:
            pending.replace(path)
    finally:
        pending.unlink(missing_ok=True)


def check_identity(binary, directory, env, sql, command, validate_events, fixture_receipt=None, fixture_seconds=1200, fixture_passkeys=False, fixture_tls=False, fixture_sync3=False):
    mailbox = "nds-mail-check-" + uuid.uuid4().hex[:12]
    server = None
    created = False
    logs = ""
    sensitive = []
    captures = {}
    # Short acceptance retains its audit transcript. Long-lived fixtures stream
    # every record through the same validator without accumulating output.
    log_budget = 4 * 1024 * 1024
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        command("docker", "run", "--rm", "--detach", "--name", mailbox, "--user", "10001:10001", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--publish", "127.0.0.1::1025", "--publish", "127.0.0.1::8025", "--tmpfs", "/data:uid=10001,gid=10001,mode=0700,size=32m", "--env", "MP_DATABASE=/data/mailpit.db", "--env", "MP_MAX_MESSAGES=25", "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2", MAILPIT)
        created = True
        ports = json.loads(command("docker", "inspect", mailbox))[0]["NetworkSettings"]["Ports"]
        smtp_port = int(ports["1025/tcp"][0]["HostPort"])
        mail_url = "http://127.0.0.1:" + ports["8025/tcp"][0]["HostPort"]
        owner = "owner-" + uuid.uuid4().hex + "@example.invalid"
        unknown = "other-" + uuid.uuid4().hex + "@example.invalid"
        sensitive += [owner, unknown]
        pepper = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        sensitive.append(pepper)
        pepper_file = Path(directory) / "identity_pepper"
        pepper_file.write_text(pepper)
        pepper_file.chmod(0o600)
        config = {"owner_email": owner, "pepper_file": str(pepper_file), "smtp": {"host": "127.0.0.1", "port": smtp_port, "tls": "loopback", "from": "nds-" + uuid.uuid4().hex + "@example.invalid"}}
        config_file = Path(directory) / "identity.json"
        config_file.write_text(json.dumps(config))
        config_file.chmod(0o600)
        vault_kek = Path(directory) / "vault_kek"
        vault_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        sensitive.append(vault_key)
        vault_kek.write_text(vault_key)
        vault_kek.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        host = "localhost" if fixture_passkeys else "127.0.0.1"
        origin = f"{'https' if fixture_tls else 'http'}://{host}:{port}"
        env = env | {"NDS_AUTH_CONFIG_FILE": str(config_file), "NDS_VAULT_KEK_FILE": str(vault_kek), "NDS_SERVER_ADDR": f"127.0.0.1:{port}", "NDS_PUBLIC_ORIGIN": origin, "NDS_MAX_REQUESTS": "64"}
        tls_evidence = {}
        if fixture_tls:
            # All material is newly generated inside the private fixture. No
            # operator certificate, credential or global trust store is used.
            certificate = Path(directory) / "browser-certificate.pem"
            key = Path(directory) / "browser-key.pem"
            # A directly trusted self-signed leaf must not inherit OpenSSL's
            # default CA:TRUE: native verifiers reject a CA used as a server.
            command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "extendedKeyUsage=serverAuth", "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", str(key), "-out", str(certificate))
            key.chmod(0o600)
            context = ssl.create_default_context(cafile=str(certificate))
            http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
            env.update(NDS_TLS_CERT_FILE=str(certificate), NDS_TLS_KEY_FILE=str(key))
            public = subprocess.run(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"], capture_output=True, check=True, timeout=10).stdout
            der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, capture_output=True, check=True, timeout=10).stdout
            tls_evidence = {"certificate_file": str(certificate), "certificate_spki_sha256": base64.b64encode(hashlib.sha256(der).digest()).decode()}

        def request(path, body=None, token=None, method=None, headers=None):
            headers = (headers or {}) | ({"Content-Type": "application/json"} if body is not None else {})
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            req = urllib.request.Request(origin + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
            try:
                response = http.open(req, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                raw = response.read(65537)
                assert len(raw) <= 65536, "response exceeded the protocol byte budget"
                assert response.headers["Cache-Control"] == "no-store"
                assert len(response.headers["X-Request-Id"]) == 32
                return response.status, json.loads(raw) if raw else None

        def start():
            validator = validate_events.stream() if fixture_receipt is not None else None
            try:
                child = subprocess.Popen([binary, "serve"], env=env, stdout=validator.stdin if validator else subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            except BaseException:
                if validator is not None:
                    validator.kill()
                    validator.communicate(timeout=5)
                raise
            if validator is not None:
                # Only the server owns the writer; its exit must deliver EOF.
                validator.stdin.close()
                validator.stdin = None
                captures[child.pid] = (validator, None)
            else:
                capture_output(child)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                try:
                    if request("/v1/ready")[0] == 200:
                        return child
                except (urllib.error.URLError, OSError):
                    pass
                if child.poll() is not None:
                    break
                time.sleep(0.05)
            stop(child)
            raise AssertionError("identity process did not become ready")

        def capture_output(child):
            capture = {"lines": [], "bytes": 0, "overflow": False}
            def drain():
                for line in child.stdout:
                    capture["bytes"] += len(line)
                    if capture["bytes"] > log_budget:
                        capture["overflow"] = True
                        child.terminate()
                        break
                    capture["lines"].append(line)
            reader = threading.Thread(target=drain, daemon=True)
            captures[child.pid] = (capture, reader)
            reader.start()

        def stop(child):
            child.terminate()
            child.wait(timeout=25)
            saved = captures.pop(child.pid, None)
            if saved is None:
                return ""
            capture, reader = saved
            if reader is None:
                validate_events.finish_stream(capture)
                return ""
            reader.join(timeout=2)
            assert not reader.is_alive() and not capture["overflow"], "bounded process log capture failed"
            return "".join(capture["lines"])

        def messages():
            with http.open(mail_url + "/api/v1/messages", timeout=2) as response:
                return json.load(response)["messages"]

        def code(expected_count):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                items = messages()
                if len(items) == expected_count:
                    with http.open(mail_url + "/api/v1/message/" + items[0]["ID"], timeout=2) as response:
                        message = json.load(response)
                    assert any(recipient["Address"] == owner for recipient in message["To"])
                    match = re.search(r"(?:code|код входа): (\d{8})", message["Text"])
                    assert match, "actual SMTP message did not contain an OTP"
                    sensitive.append(match[1])
                    return match[1]
                time.sleep(0.05)
            raise AssertionError("SMTP mailbox did not receive expected message count")

        deadline = time.monotonic() + 10
        while True:
            try:
                assert messages() == []
                break
            except (urllib.error.URLError, OSError):
                assert time.monotonic() < deadline, "isolated SMTP mailbox did not start"
                time.sleep(0.05)
        assert sql("SELECT count(*) FROM nds_owner").stdout.strip() == "0"
        server = start()
        assert request("/v2/auth/methods") == (200, {"email_otp": "available", "github": "unavailable", "passkey": "unavailable"})
        if fixture_receipt is not None:
            receipt = Path(fixture_receipt)
            stop_marker = receipt.with_suffix(".stop")
            control = receipt.with_suffix(".control.json")
            state = {"base_url": origin, "mailpit_url": mail_url, "owner_email": owner, "expires_at_unix": int(time.time()) + fixture_seconds, "stop_marker": str(stop_marker), "control_file": str(control), "status": "running"}
            state.update(tls_evidence)
            publish_fixture_receipt(receipt, state, initial=True)
            print("Isolated identity fixture ready; receipt saved outside the repository.", flush=True)
            deadline = time.monotonic() + fixture_seconds
            try:
                while time.monotonic() < deadline and not stop_marker.exists():
                    if fixture_sync3 and state.get("new_operation_version") != 3:
                        # Explicit fixture-operator action after the real client
                        # creates its counter. Never change the migration default
                        # or admit an owner with existing operations implicitly.
                        changed = sql("WITH changed AS (UPDATE nds_replica_counters SET admission_version=3 "
                                      "WHERE admission_version=2 AND server_seq=0 "
                                      "AND floor_seq=0 AND base_seq=0 RETURNING 1) SELECT count(*) FROM changed").stdout.strip()
                        assert changed in {"0", "1"}
                        if changed == "1":
                            state["new_operation_version"] = 3
                            publish_fixture_receipt(receipt, state)
                    # The test harness owns this exact child and its temporary
                    # dependencies. Broken connections and restarts are real I/O
                    # failures; no test bypass enters the product server.
                    if control.exists():
                        desired = json.loads(control.read_text())
                        assert set(desired) == {"mode"} and desired["mode"] in {"online", "offline"}
                        control.unlink()
                        if desired["mode"] == "offline" and server is not None:
                            logs += stop(server)
                            assert server.returncode == 0
                            server = None
                        elif desired["mode"] == "online" and server is None:
                            server = start()
                        state["status"] = "running" if server is not None else "offline"
                        publish_fixture_receipt(receipt, state)
                    if server is not None and server.poll() is not None:
                        raise AssertionError("isolated identity server exited")
                    if server is not None and captures[server.pid][0].poll() is not None:
                        raise AssertionError("streamed telemetry validator exited before the server")
                    time.sleep(0.1)
            finally:
                state["status"] = "stopped"
                publish_fixture_receipt(receipt, state)
                if server is not None:
                    logs += stop(server)
                    server = None
            return
        denied_status, denied_receipt = request("/v2/auth/email/challenges", {"email": unknown})
        otp_trace = secrets.token_hex(16)
        status, receipt = request("/v2/auth/email/challenges", {"email": owner.upper()}, headers={"Accept-Language": "ru", "traceparent": f"00-{otp_trace}-{secrets.token_hex(8)}-01"})
        assert status == denied_status == 202
        assert denied_receipt.keys() == receipt.keys()
        assert len(denied_receipt["challenge_id"]) == len(receipt["challenge_id"]) == 43
        assert denied_receipt["expires_in_seconds"] == receipt["expires_in_seconds"] == 300
        assert denied_receipt["resend_after_seconds"] == receipt["resend_after_seconds"] == 60
        first_code = code(1)
        assert request("/v2/auth/email/verify", {"challenge_id": denied_receipt["challenge_id"], "code": first_code})[0] == 401
        assert request("/v2/auth/email/challenges", {"email": owner, "user_id": uuid.uuid4().hex})[0] == 400
        assert request("/v2/auth/email/challenges", {"email": " " * 255 + owner})[0] == 400
        assert request("/v2/auth/email/verify", {"challenge_id": receipt["challenge_id"], "code": first_code, "extra": "rejected"})[0] == 400
        assert sql("SELECT count(*) FROM nds_owner").stdout.strip() == "1"
        assert sql("SELECT bool_and(octet_length(verifier)=32) FROM nds_email_challenges").stdout.strip() == "t"
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(request, "/v2/auth/email/verify", {"challenge_id": receipt["challenge_id"], "code": first_code}) for _ in range(2)]
            results = [future.result(timeout=8) for future in futures]
        assert sorted(status for status, _ in results) == [200, 401], "concurrent OTP replay created multiple sessions"
        issued = next(body for status, body in results if status == 200)
        token = issued["session_token"]
        sensitive.append(token)
        assert len(token) == 43
        assert issued["session"]["auth_method"] == "email_otp"
        assert request("/v2/session", token=token) == (200, issued["session"])
        assert request("/v2/session")[0] == 401
        assert request("/v2/session", token=token, headers={"X-Forwarded-For": "192.0.2.90"})[0] == 200
        assert sql("SELECT bool_and(octet_length(token_digest)=32) FROM nds_sessions").stdout.strip() == "t"
        logs += stop(server)
        assert server.returncode == 0
        server = start()
        assert request("/v2/session", token=token) == (200, issued["session"]), "session or bootstrap owner changed on restart"
        wrong_config = Path(directory) / "different-owner.json"
        wrong_config.write_text(json.dumps(config | {"owner_email": unknown}))
        wrong_config.chmod(0o600)
        rejected = subprocess.run([binary, "serve"], env=env | {"NDS_AUTH_CONFIG_FILE": str(wrong_config), "NDS_SERVER_ADDR": "127.0.0.1:0"}, capture_output=True, text=True, timeout=8)
        assert rejected.returncode != 0
        assert any(event.get("event.name") == "process.failed" and event.get("error.type") == "database_identity" for event in map(json.loads, rejected.stdout.splitlines()))
        logs += rejected.stdout + rejected.stderr
        assert request("/v2/session", token=token) == (200, issued["session"])
        plaintext = subprocess.run([binary, "serve"], env=env | {"NDS_SERVER_ADDR": "0.0.0.0:0"}, capture_output=True, text=True, timeout=8)
        assert plaintext.returncode != 0
        assert any(event.get("event.name") == "process.failed" and event.get("error.type") == "configuration_identity_https_required" for event in map(json.loads, plaintext.stdout.splitlines()))
        logs += plaintext.stdout + plaintext.stderr
        assert request("/v2/session", token=token, method="DELETE")[0] == 204
        assert request("/v2/session", token=token)[0] == 401

        # Reset only synthetic fixture budgets between independent cases. No
        # operator clock, credentials or database is touched by this test.
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        _, old = request("/v2/auth/email/challenges", {"email": owner})
        old_code = code(2)
        _, suppressed = request("/v2/auth/email/challenges", {"email": owner})
        assert len(messages()) == 2
        assert request("/v2/auth/email/verify", {"challenge_id": suppressed["challenge_id"], "code": old_code})[0] == 401
        sql("UPDATE nds_email_challenges SET created_at_ms=created_at_ms-61000")
        _, new = request("/v2/auth/email/challenges", {"email": owner})
        new_code = code(3)
        assert request("/v2/auth/email/verify", {"challenge_id": old["challenge_id"], "code": old_code})[0] == 401
        wrong = ("0" if new_code[0] != "0" else "1") + new_code[1:]
        for _ in range(5):
            assert request("/v2/auth/email/verify", {"challenge_id": new["challenge_id"], "code": wrong})[0] == 401
        assert request("/v2/auth/email/verify", {"challenge_id": new["challenge_id"], "code": new_code})[0] == 401
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        _, expired = request("/v2/auth/email/challenges", {"email": owner})
        expired_code = code(4)
        sql("UPDATE nds_email_challenges SET created_at_ms=created_at_ms-600000, expires_at_ms=expires_at_ms-600000")
        assert request("/v2/auth/email/verify", {"challenge_id": expired["challenge_id"], "code": expired_code})[0] == 401
        assert sql("SELECT count(*) FROM nds_email_challenges").stdout.strip() == "0"
        sql("DELETE FROM nds_auth_limits;")
        _, session_receipt = request("/v2/auth/email/challenges", {"email": owner})
        session_code = code(5)
        status, session_issued = request("/v2/auth/email/verify", {"challenge_id": session_receipt["challenge_id"], "code": session_code})
        assert status == 200
        sensitive.append(session_issued["session_token"])

        def second_session():
            expected_count = len(messages()) + 1
            sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
            status, receipt = request("/v2/auth/email/challenges", {"email": owner})
            assert status == 202
            status, issued = request("/v2/auth/email/verify", {"challenge_id": receipt["challenge_id"], "code": code(expected_count)})
            assert status == 200
            return issued["session_token"]

        def restart_enrollment():
            nonlocal server, logs
            logs += stop(server)
            assert server.returncode == 0
            server = start()

        sensitive += check_sync(request, session_issued["session_token"], restart_enrollment, directory, sql, f"http://{host}:{port}", observability_configured="NDS_OBSERVABILITY_CONFIG_FILE" in env)
        sensitive += check_screen(request, session_issued["session_token"], second_session, restart_enrollment, directory, sql, f"http://{host}:{port}")
        sensitive += check_enrollment(request, session_issued["session_token"], second_session, restart_enrollment, directory, sql)
        expired_logout = second_session()
        sensitive.append(expired_logout)
        mail_count = len(messages())
        sql("UPDATE nds_sessions SET expires_at_ms=authenticated_at_ms")
        assert request("/v2/session", token=expired_logout, method="DELETE")[0] == 401
        assert sql("SELECT count(*) FROM nds_sessions").stdout.strip() == "1", "expired logout deletion rolled back"
        assert request("/v2/session", token=session_issued["session_token"])[0] == 401
        assert sql("SELECT count(*) FROM nds_sessions").stdout.strip() == "0"
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        for attempt in range(11):
            status, _ = request("/v2/auth/email/challenges", {"email": uuid.uuid4().hex + "@example.invalid"}, headers={"X-Forwarded-For": f"192.0.2.{attempt + 1}"})
            assert status == (202 if attempt < 10 else 429), "socket-source budget was bypassed through headers or new ports"
        assert len(messages()) == mail_count
        assert request("/v2/auth/github/start", {})[0] == 503
        sensitive += check_browser(f"http://{host}:{port}", owner, code, messages, sql)
        if fixture_passkeys:
            recent = second_session()
            sensitive.append(recent)
            # Only owned synthetic fixture proofs are aged. The real Rust service
            # must deny the sensitive action while retaining ordinary identity.
            sql("UPDATE nds_sessions SET authenticated_at_ms=authenticated_at_ms-360000")
            assert request("/v2/session", token=recent)[0] == 200
            assert request("/v2/auth/passkeys/start", {"registration": True}, token=recent) == (403, {"error": "recent_authentication_required"})
            assert request("/v2/auth/passkeys/" + "0"*64, method="DELETE", token=recent) == (403, {"error": "recent_authentication_required"})
            assert request("/v2/session", token=recent)[0] == 200
            assert request("/v2/session", method="DELETE", token=recent)[0] == 204
            print("Recent-authentication scope passed: aged valid session retains ordinary access after credential-management rejection.")
        company_secrets, unavailable_invitation = check_company_identity(request, sql, mail_url, http, pepper, restart_enrollment, directory, origin, observability_configured="NDS_OBSERVABILITY_CONFIG_FILE" in env)
        sensitive += company_secrets
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        command("docker", "stop", "--time", "5", mailbox)
        created = False
        _, unavailable_receipt = request("/v2/auth/email/challenges", {"email": owner})
        deadline = time.monotonic() + 8
        while request("/v2/auth/methods")[1]["email_otp"] != "unavailable":
            assert time.monotonic() < deadline, "SMTP failure did not degrade readiness"
            time.sleep(0.05)
        while sql("SELECT bool_and(consumed) FROM nds_email_challenges").stdout.strip() != "t":
            assert time.monotonic() < deadline, "failed delivery challenge was not invalidated"
            time.sleep(0.05)
        assert request("/v2/auth/email/challenges", {"email": unknown})[0] == 503
        sensitive += unavailable_invitation()
        logs += stop(server)
        assert server.returncode == 0
        server = None
        for secret in sensitive:
            assert secret not in logs, "identity logs exposed sensitive fixture material"
        assert str(directory) not in logs
        validate_events(logs)
        events = [json.loads(line) for line in logs.splitlines() if line]
        completion = next(event for event in events if event.get("event.name") == "http.request.completed" and event.get("trace_id") == otp_trace)
        delivery = next(event for event in events if event.get("event.name") == "email.delivery.accepted" and event.get("trace_id") == otp_trace)
        assert completion["status"] == 202 and completion["module"] == "http"
        assert delivery["module"] == "identity" and delivery["scope"] == "transport" and delivery["mailbox_delivery"] == "unverified"
        assert delivery["span_id"] != completion["span_id"], "SMTP must have its own child span"
        device_events = [event for event in events if event.get("event.name", "").startswith("device.")]
        assert device_events and all(event["module"] == "devices" for event in device_events)
        assert not any(event.get("event.name") in ("logging.fields.rejected", "logging.event.rejected") for event in events)
        assert any(event.get("event.name") == "identity.session.issued" for event in events)
        accepted = [event for event in events if event.get("event.name") == "company.invitation.accepted"]
        assert accepted and len({event["invitation.id"] for event in accepted}) == len(accepted)
        created_events = {event["invitation.id"]: event for event in events
                   if event.get("event.name") in {"company.invitation.admin.created", "company.invitation.user.created"}}
        assert created_events and any(event["invitation.id"] in created_events for event in accepted)
        for event in created_events.values():
            assert all(event.get(field) for field in ["operation.id", "user.id", "tenant.id", "device.id", "trace_id", "span_id"])
            delivered = [item for item in events if item.get("event.name") == "company.invitation.delivery.accepted"
                         and item.get("invitation.id") == event["invitation.id"]]
            assert len(delivered) <= 1, "an idempotent command resent its invitation"
            assert all(item["trace_id"] == event["trace_id"] for item in delivered)
        for event in accepted:
            if event["invitation.id"] in created_events:
                issuer = created_events[event["invitation.id"]]
                assert event["tenant.id"] == issuer["tenant.id"] and event["user.id"] != issuer["user.id"]
        for action in ["role_admin", "role_user", "remove"]:
            action_events = [event for event in events if event.get("event.name") == f"company.member.{action}.completed"]
            assert action_events and all(event.get("target.user.id") and event.get("operation.id") for event in action_events)
        assert any(event.get("event.name") == "company.invitation.delivery.recorded_failed" for event in events)
        print("Company audit acceptance passed: committed creation, one-use acceptance, distinct role/remove actions, verified actor/target scope and SMTP dispatch without replay resends are correlated; no invitation tokens or recipient emails appear in logs.")
        print("Identity acceptance passed: real isolated SMTP mailbox delivery; generic owner/other receipts; atomic replay denial; resend, attempts and expiry; persistent/revoked sessions; immutable bootstrap ownership; socket-only source limits; redacted logs. Live GitHub and external mailbox acceptance remain separate.")
    finally:
        try:
            if server is not None:
                stop(server)
        finally:
            if created:
                command("docker", "stop", "--time", "5", mailbox)
