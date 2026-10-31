"""Real HTTP/SQL enrollment with independent OpenSSL Ed25519 signatures."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import time
import uuid


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def check_enrollment(request, token, second_session, restart, directory, sql):
    directory = Path(directory) / "enrollment"
    directory.mkdir(mode=0o700)
    sensitive = []
    keys = 0

    def run(*args):
        return subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=5).stdout

    def key():
        nonlocal keys
        keys += 1
        assert keys <= 160, "fixture key budget exceeded"
        path = directory / f"device-{keys}.pem"
        run("genpkey", "-algorithm", "ED25519", "-out", path)
        path.chmod(0o600)
        sensitive.extend(path.read_text().splitlines()[1:-1])
        public = run("pkey", "-in", path, "-pubout", "-outform", "DER")
        # RFC 8410 Ed25519 SubjectPublicKeyInfo, produced by OpenSSL itself.
        assert len(public) == 44 and public[:12] == bytes.fromhex("302a300506032b6570032100")
        return path, encoded(public[12:])

    def proof(path, challenge, prefixed=True):
        value = base64.urlsafe_b64decode(challenge["challenge"] + "=")
        assert len(value) == 32
        content = (b"NDS-ENROLLMENT-V2\0" if prefixed else b"") + value
        payload = directory / "challenge.bin"
        payload.write_bytes(content)
        signature = run("pkeyutl", "-sign", "-inkey", path, "-rawin", "-in", payload)
        assert len(signature) == 64
        return {"challenge_id": challenge["challenge_id"], "signature": encoded(signature)}

    def challenge(public, session=token, platform="linux", name="🚀"*128):
        return request("/v2/devices/challenges", {"platform": platform, "display_name": name, "public_key": public}, token=session)

    def enroll(path, public, platform="linux"):
        status, receipt = challenge(public, platform=platform)
        assert status == 201, "enrollment challenge failed"
        expiry = datetime.fromisoformat(receipt["expires_at"].replace("Z", "+00:00"))
        assert 0 < (expiry - datetime.now(timezone.utc)).total_seconds() <= 300
        status, device = request("/v2/devices/enrollments", proof(path, receipt), token=token)
        assert status == 201 and device["device_id"] == receipt["device_id"]
        assert device["public_key"] == public and device["platform"] == platform and device["status"] == "active"
        return device

    def wait_sql(statement, expected):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if sql(statement).stdout.strip() == str(expected): return
            time.sleep(0.01)
        raise AssertionError("bounded enrollment race did not reach its PostgreSQL lock boundary")

    path, public = key()
    assert request("/v2/devices")[0] == 401
    assert request("/v3/personal/devices")[0] == 401
    assert challenge(public, session=None)[0] == 401
    for invalid in [encoded(bytes(32)), encoded(b"\x01" + bytes(31)), encoded(bytes([0xee]) + bytes([0xff])*30 + b"\x7f"), public + "=", encoded(bytes(31))]:
        assert challenge(invalid)[0] == 400
    assert sql("SELECT count(*) FROM nds_enrollment_challenges").stdout.strip() == "0", "invalid keys allocated pending state"
    assert request("/v2/devices/challenges", {"platform":"linux", "display_name":"Synthetic", "public_key":public, "user_id":uuid.uuid4().hex}, token=token)[0] == 400
    status, receipt = challenge(public, name="Тест " + "я"*123)
    assert status == 201, (status, receipt.get("error"))
    assert request("/v2/devices/enrollments", proof(path, receipt, prefixed=False), token=token) == (400, {"error":"invalid_signature"})
    other = second_session()
    sensitive.append(other)
    valid = proof(path, receipt)
    assert request("/v2/devices/enrollments", valid, token=other)[0] == 400, "a different owner session completed enrollment"
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(request, "/v2/devices/enrollments", valid, token=token) for _ in range(2)]
        results = [future.result(timeout=8) for future in futures]
    assert sorted(status for status, _ in results) == [201, 400]
    first = next(value for status,value in results if status == 201)
    assert sql("SELECT count(*) FROM nds_devices").stdout.strip() == "1"
    assert request("/v2/devices/enrollments", valid, token=token)[0] == 400
    restart()
    assert request("/v2/devices", token=token) == (200, {"devices":[first], "next_cursor":None})
    status, session = request("/v2/session", token=token)
    assert status == 200
    context = {"principal_id": session["user_id"], "space": {"kind": "personal", "id": session["user_id"]}}
    retained_device = sql("SELECT to_jsonb(d)::text FROM nds_devices d ORDER BY device_id").stdout
    assert request("/v3/personal/devices", token=token) == (200, {"context": context, "devices": [first], "next_cursor": None})
    for query in ("limit=0", "cursor=devices.01", "user_id=" + str(uuid.uuid4()), "space_id=" + session["tenant_id"]):
        assert request("/v3/personal/devices?" + query, token=token)[0] == 400
    assert sql("SELECT to_jsonb(d)::text FROM nds_devices d ORDER BY device_id").stdout == retained_device, "personal projection changed retained device ownership or proof"
    assert request("/v2/devices?limit=0", token=token)[0] == 400
    assert request("/v2/devices?cursor=devices.01", token=token)[0] == 400
    # Device control policy (ADR 0018): a new enrollment starts as fullauto.
    policy_path = "/v3/personal/devices/" + first["device_id"] + "/policy"
    def policy(mode, purposes, revision):
        return {"context": context, "device_id": first["device_id"],
                "policy": {"mode": mode, "purposes": purposes, "revision": revision}}
    assert request(policy_path)[0] == 401
    assert request(policy_path, token=token) == (200, policy("fullauto", ["desktop"], 1))
    # Foreign and unknown devices share one request refusal, never a session failure.
    assert request(policy_path, token=other) == (400, {"error": "invalid_request"}), "another owner observed a foreign device policy"
    assert request("/v3/personal/devices/" + uuid.uuid4().hex + "/policy", token=token) == (400, {"error": "invalid_request"})
    narrowed = {"expected_revision": 1, "mode": "manual", "purposes": ["desktop", "dev-desktop"]}
    assert request(policy_path, narrowed, token=other, method="PUT") == (400, {"error": "invalid_request"})
    assert request(policy_path, narrowed, token=token, method="PUT") == (200, policy("manual", ["dev-desktop", "desktop"], 2))
    assert request(policy_path, narrowed, token=token, method="PUT") == (409, {"error": "operation_conflict"})
    for invalid in (narrowed | {"expected_revision": 2, "purposes": []}, narrowed | {"expected_revision": 2, "purposes": ["admin"]},
                    narrowed | {"expected_revision": 2, "purposes": ["desktop", "desktop"]}, narrowed | {"expected_revision": 2, "mode": "auto"},
                    narrowed | {"expected_revision": 0}, narrowed | {"expected_revision": 2, "device_id": "injected"}):
        assert request(policy_path, invalid, token=token, method="PUT")[0] == 400
    widened = {"expected_revision": 2, "mode": "fullauto", "purposes": ["dev-desktop"]}
    # The session stays valid, but widening needs a recent sign-in proof.
    sql("UPDATE nds_sessions SET authenticated_at_ms=authenticated_at_ms-600000")
    assert request(policy_path, widened, token=token, method="PUT") == (403, {"error": "recent_authentication_required"})
    assert request(policy_path, token=token) == (200, policy("manual", ["dev-desktop", "desktop"], 2))
    reclassified = {"expected_revision": 2, "mode": "manual", "purposes": ["server-dev-desktop"]}
    assert request(policy_path, reclassified, token=token, method="PUT") == (200, policy("manual", ["server-dev-desktop"], 3))
    sql("UPDATE nds_sessions SET authenticated_at_ms=authenticated_at_ms+600000")
    widened["expected_revision"] = 3
    assert request(policy_path, widened, token=token, method="PUT") == (200, policy("fullauto", ["dev-desktop"], 4))
    restart()
    assert request(policy_path, token=token) == (200, policy("fullauto", ["dev-desktop"], 4))
    assert sql("SELECT to_jsonb(d)::text FROM nds_devices d ORDER BY device_id").stdout == retained_device, "policy replacement changed device identity, key or proof"
    for statement in ("UPDATE nds_device_policies SET device_id=device_id WHERE false", "DELETE FROM nds_device_policies WHERE false"):
        assert sql(statement, "nds_runtime", check=False).returncode != 0
    assert sql("UPDATE nds_device_policies SET control_mode=control_mode,purposes=purposes,policy_revision=policy_revision WHERE false", "nds_runtime").returncode == 0
    assert challenge(public)[0] == 400, "active key was registered twice"
    assert request("/v2/devices/" + first["device_id"], token=token, method="DELETE")[0] == 204
    assert request(policy_path, {"expected_revision": 4, "mode": "manual", "purposes": ["desktop"]}, token=token, method="PUT") == (400, {"error": "invalid_request"}), "revoked device policy changed"
    assert request(policy_path, token=token)[1]["policy"]["revision"] == 4
    assert request("/v2/devices/" + first["device_id"], token=token, method="DELETE")[0] == 204
    assert challenge(public)[0] == 400, "revoked key was silently reassigned"
    assert request("/v2/devices", token=token)[1]["devices"][0]["status"] == "revoked"
    assert sql("DELETE FROM nds_devices WHERE false", "nds_runtime", check=False).returncode != 0

    sql("DELETE FROM nds_auth_limits;")
    second_path, second_public = key()
    _, pending = challenge(second_public, session=other)
    with ThreadPoolExecutor(max_workers=3) as executor:
        blocker = executor.submit(sql, f"BEGIN; SELECT pg_advisory_xact_lock({0x4e44533241555448}); SELECT pg_sleep(2); COMMIT;")
        wait_sql("SELECT count(*) FROM pg_stat_activity WHERE usename='postgres' AND wait_event='PgSleep'", 1)
        revoking = executor.submit(request,"/v2/session",token=other,method="DELETE")
        wait_sql("SELECT count(*) FROM pg_stat_activity WHERE usename='nds_runtime' AND wait_event_type='Lock' AND query LIKE 'SELECT pg_advisory_xact_lock%'", 1)
        completing = executor.submit(request,"/v2/devices/enrollments",proof(second_path,pending),token=other)
        wait_sql("SELECT count(*) FROM pg_stat_activity WHERE usename='nds_runtime' AND wait_event_type='Lock' AND query LIKE 'SELECT pg_advisory_xact_lock%'", 2)
        blocker.result(timeout=5)
        assert revoking.result(timeout=5)[0] == 204
        assert completing.result(timeout=5)[0] == 401, "enrollment escaped the earlier session revocation"
    assert sql("SELECT count(*) FROM nds_enrollment_challenges WHERE challenge_id=" + literal(pending["challenge_id"])).stdout.strip() == "0"
    assert request("/v2/devices/enrollments", proof(second_path,pending), token=other)[0] == 401
    assert request("/v2/devices/enrollments", proof(second_path,pending), token=token)[0] == 400

    # Reverse order: an enrollment holding the authority must commit before the
    # queued revocation can complete; then no reuse of that session is possible.
    other = second_session()
    sensitive.append(other)
    _, pending = challenge(second_public, session=other)
    with ThreadPoolExecutor(max_workers=3) as executor:
        blocker = executor.submit(sql,"BEGIN; LOCK TABLE nds_enrollment_challenges IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(2); COMMIT;")
        wait_sql("SELECT count(*) FROM pg_locks WHERE relation='nds_enrollment_challenges'::regclass AND mode='AccessExclusiveLock' AND granted",1)
        completing = executor.submit(request,"/v2/devices/enrollments",proof(second_path,pending),token=other)
        wait_sql("SELECT count(*) FROM pg_stat_activity WHERE usename='nds_runtime' AND wait_event_type='Lock' AND query LIKE 'SELECT %FROM nds_enrollment_challenges%'",1)
        revoking = executor.submit(request,"/v2/session",token=other,method="DELETE")
        wait_sql("SELECT count(*) FROM pg_stat_activity WHERE usename='nds_runtime' AND wait_event_type='Lock' AND query LIKE 'SELECT pg_advisory_xact_lock%'",1)
        assert not revoking.done()
        blocker.result(timeout=5)
        status, enrolled = completing.result(timeout=5)
        assert status == 201 and revoking.result(timeout=5)[0] == 204
    assert request("/v2/devices/enrollments",proof(second_path,pending),token=other)[0] == 401
    assert request("/v2/devices/"+enrolled["device_id"],token=token,method="DELETE")[0] == 204

    # A new key is needed: completed/revoked identities cannot be reassigned.
    second_path, second_public = key()

    _, expired = challenge(second_public)
    sql("UPDATE nds_enrollment_challenges SET created_at_ms=created_at_ms-600000,expires_at_ms=expires_at_ms-600000 WHERE challenge_id=" + literal(expired["challenge_id"]))
    assert request("/v2/devices/enrollments", proof(second_path,expired), token=token) == (400, {"error":"challenge_expired"})
    sql("UPDATE nds_enrollment_challenges SET expires_at_ms=expires_at_ms+600000 WHERE challenge_id=" + literal(expired["challenge_id"]))
    assert request("/v2/devices/enrollments", proof(second_path,expired), token=token)[0] == 400, "observed expiry revived"
    _, exhausted = challenge(second_public)
    for _ in range(5):
        assert request("/v2/devices/enrollments", {"challenge_id":exhausted["challenge_id"], "signature":encoded(bytes(64))}, token=token)[0] == 400
    assert request("/v2/devices/enrollments", proof(second_path,exhausted), token=token)[0] == 400

    # Only generated fixture abuse windows are reset between independent bounds.
    sql("DELETE FROM nds_auth_limits;")
    pending = []
    for _ in range(8):
        new_path,new_public = key()
        status,receipt = challenge(new_public)
        assert status == 201
        pending.append((new_path,receipt))
    spare_path,spare_public = key()
    assert challenge(spare_public) == (503,{"error":"server_busy"})
    for new_path,receipt in pending:
        status,value = request("/v2/devices/enrollments",proof(new_path,receipt),token=token)
        assert status == 201
        assert request("/v2/devices/" + value["device_id"],token=token,method="DELETE")[0] == 204

    platforms = ["linux","macos","windows","ios","android","web"]
    active = []
    # A fresh owner window admits the full fleet without intermediate resets.
    sql("DELETE FROM nds_auth_limits;")
    for index in range(32):
        new_path,new_public = key()
        active.append(enroll(new_path,new_public,platforms[index % len(platforms)]))
    assert challenge(spare_public) == (429,{"error":"rate_limited"})
    # Exercise the independent active-device bound with an available rate window.
    sql("DELETE FROM nds_auth_limits;")
    assert challenge(spare_public) == (503,{"error":"server_busy"})
    for value in active:
        assert request("/v2/devices/" + value["device_id"],token=token,method="DELETE")[0] == 204
    retained = int(sql("SELECT count(*) FROM nds_devices").stdout)
    for index in range(128-retained):
        if index % 8 == 0: sql("DELETE FROM nds_auth_limits;")
        new_path,new_public = key()
        value = enroll(new_path,new_public)
        assert request("/v2/devices/" + value["device_id"],token=token,method="DELETE")[0] == 204
    assert sql("SELECT count(*) FROM nds_devices").stdout.strip() == "128"
    sql("DELETE FROM nds_auth_limits;")
    for index in range(33):
        status,_ = request("/v2/devices/challenges",{"platform":"linux","display_name":"Synthetic","public_key":spare_public},token=token,headers={"X-Forwarded-For":f"192.0.2.{index+1}"})
        assert status == (503 if index < 32 else 429), "owner enrollment budget trusted unowned forwarding headers"

    seen = set()
    cursor = None
    for page_number in range(4):
        query = "?limit=100" + ("&cursor="+cursor if cursor else "")
        status,page = request("/v2/devices" + query,token=token)
        assert status == 200 and len(page["devices"]) == 32
        assert request("/v3/personal/devices" + query, token=token) == (200, {"context": context, **page})
        for device in page["devices"]:
            assert device["device_id"] not in seen and device["status"] == "revoked"
            seen.add(device["device_id"])
        cursor=page["next_cursor"]
        assert (cursor is None) == (page_number == 3)
    assert len(seen) == 128
    assert sql("SELECT count(*) FROM information_schema.columns WHERE table_name IN ('nds_devices','nds_enrollment_challenges') AND column_name LIKE '%private%'").stdout.strip() == "0"
    print("Enrollment acceptance passed on the Linux server: real OpenSSL proofs with all six platform values; strict key rejection before allocation; same-session and concurrent consume; both PostgreSQL-locked revoke/enroll orderings; restart, expiry, attempts and key uniqueness; actual 8/32/128 capacities;32 enrollments in one untouched owner window; finite owner cursor pages and bounded enrollment despite untrusted forwarding headers.")
    return sensitive
