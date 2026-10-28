"""Actual OTP/SMTP/SQL acceptance of company identity adapters.

Only pending invitation metadata and a foreign-company principal are seeded in
the disposable database. No session, OTP or device proof is fabricated for
authentication. Administrative invitation issuance/UI are a separate acceptance.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from company_management_acceptance import check_company_management


def check_company_identity(request, sql, mailbox, http, pepper, restart, directory, origin, observability_configured=False):
    sensitive = [pepper]
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    literal = lambda value: "'" + value.replace("'", "''") + "'"
    binary = lambda value: "decode('" + value.hex() + "','hex')"
    secret = base64.urlsafe_b64decode(pepper + "=")
    bootstrap = json.loads(sql("SELECT row_to_json(o) FROM nds_owner o WHERE is_bootstrap").stdout)

    def protect(purpose, *parts):
        transcript = b"NDS-IDENTITY-V2\0"
        for part in (purpose, *parts):
            raw = part.encode()
            transcript += len(raw).to_bytes(8, "big") + raw
        return hmac.digest(secret, transcript, "sha256")

    def reset_cases():
        # Independent negative boundary cases, not throughput qualification.
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")

    def messages():
        with http.open(mailbox + "/api/v1/messages", timeout=2) as response:
            return json.load(response)["messages"]

    def challenge(email, invitation=None):
        old = {message["ID"] for message in messages()}
        body = {"email": email} | (invitation or {})
        path = "/v2/auth/invitations/challenges" if invitation else "/v2/auth/email/challenges"
        status, receipt = request(path, body)
        assert status == 202, "company OTP challenge was not accepted"
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            for item in messages():
                if item["ID"] in old:
                    continue
                with http.open(mailbox + "/api/v1/message/" + item["ID"], timeout=2) as response:
                    message = json.load(response)
                if not any(recipient["Address"] == email for recipient in message["To"]):
                    continue
                match = re.search(r"(?:code|код входа): (\d{8})", message["Text"])
                assert match, "company OTP message was malformed"
                sensitive.extend([email, match[1]])
                return {"challenge_id": receipt["challenge_id"], "code": match[1]}
            time.sleep(0.05)
        raise AssertionError("company recipient did not receive an isolated SMTP OTP")

    def verify(proof, user, tenant):
        status, issued = request("/v2/auth/email/verify", proof)
        assert status == 200, "company OTP verification failed"
        assert issued["session"]["user_id"] == user and issued["session"]["tenant_id"] == tenant
        sensitive.append(issued["session_token"])
        return issued["session_token"]

    def pending(role="user", email=None, user=None, tenant=None):
        email = email or uuid.uuid4().hex + "@example.invalid"
        user = user or str(uuid.uuid4())
        tenant = tenant or bootstrap["tenant_id"]
        identifier, token = encode(secrets.token_bytes(32)), encode(secrets.token_bytes(32))
        sensitive.extend([email, token])
        now = int(time.time() * 1000)
        sql("INSERT INTO nds_company_invitations(invitation_id,tenant_id,issuer_user_id,recipient_user_id,recipient_email,recipient_binding,recipient_subject,company_role,verifier,issued_at_ms,expires_at_ms,status) VALUES("
            + ",".join([literal(identifier), literal(tenant), literal(bootstrap["user_id"]), literal(user),
                        literal(email), binary(protect("owner_binding", email)), binary(protect("email_subject", email)),
                        literal(role), binary(protect("company_invitation", identifier, token)), str(now), str(now + 604800000), "'pending'"]) + ")")
        return email, user, tenant, {"invitation_id": identifier, "invitation_token": token}

    def unavailable(email, invite):
        reset_cases()
        before = {message["ID"] for message in messages()}
        status, receipt = request("/v2/auth/invitations/challenges", {"email": email} | invite)
        assert status == 202 and set(receipt) == {"challenge_id", "expires_in_seconds", "resend_after_seconds"}
        assert sql("SELECT count(*) FROM nds_email_challenges WHERE eligible").stdout.strip() == "0"
        assert {message["ID"] for message in messages()} == before

    reset_cases()
    member = pending()
    email, user, tenant, invite = member
    unavailable(email, invite | {"invitation_token": encode(secrets.token_bytes(32))})
    unavailable(uuid.uuid4().hex + "@example.invalid", invite)
    reset_cases()
    proof = challenge(email, invite)
    assert sql(f"SELECT count(*) FROM nds_owner WHERE user_id={literal(user)}").stdout.strip() == "0"
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: request("/v2/auth/email/verify", proof), range(2)))
    assert sorted(status for status, _ in outcomes) == [200, 401]
    issued = next(value for status, value in outcomes if status == 200)
    assert issued["session"]["user_id"] == user and issued["session"]["tenant_id"] == tenant
    member_token = issued["session_token"]
    sensitive.append(member_token)
    assert sql(f"SELECT status FROM nds_company_invitations WHERE invitation_id={literal(invite['invitation_id'])}").stdout.strip() == "accepted"
    assert sql(f"SELECT company_role||':'||membership_active::text FROM nds_owner WHERE user_id={literal(user)}").stdout.strip() == "user:true"
    unavailable(email, invite)

    # All three decisions are rechecked after actual recipient authentication
    # starts; the challenge does not cache an irrevocable permission.
    for failure in ("revoked", "expired", "issuer_demoted"):
        reset_cases()
        recipient, planned_user, _, claim = pending()
        proof = challenge(recipient, claim)
        identifier = literal(claim["invitation_id"])
        if failure == "issuer_demoted":
            sql("UPDATE nds_owner SET company_role='user' WHERE is_bootstrap")
        elif failure == "revoked":
            sql(f"UPDATE nds_company_invitations SET status='revoked' WHERE invitation_id={identifier}")
        else:
            sql(f"UPDATE nds_company_invitations SET issued_at_ms=issued_at_ms-604801000,expires_at_ms=expires_at_ms-604801000 WHERE invitation_id={identifier}")
        try:
            assert request("/v2/auth/email/verify", proof)[0] == 401
            assert sql(f"SELECT count(*) FROM nds_owner WHERE user_id={literal(planned_user)}").stdout.strip() == "0"
            if failure != "issuer_demoted":
                assert sql(f"SELECT status FROM nds_company_invitations WHERE invitation_id={identifier}").stdout.strip() == failure
        finally:
            sql("UPDATE nds_owner SET company_role='admin' WHERE is_bootstrap")

    reset_cases()
    admin_email, admin_user, _, admin_invite = pending("admin")
    admin_token = verify(challenge(admin_email, admin_invite), admin_user, tenant)
    foreign_user, foreign_tenant = str(uuid.uuid4()), str(uuid.uuid4())
    foreign_email = uuid.uuid4().hex + "@example.invalid"
    sensitive.append(foreign_email)
    sql(f"INSERT INTO nds_companies(tenant_id,display_name) VALUES({literal(foreign_tenant)},'Foreign fixture');"
        f"INSERT INTO nds_owner(user_id,tenant_id,email_binding,email,company_role) VALUES({literal(foreign_user)},{literal(foreign_tenant)},{binary(protect('owner_binding', foreign_email))},{literal(foreign_email)},'admin')")
    foreign_token = verify(challenge(foreign_email), foreign_user, foreign_tenant)
    cross_invite = pending(email=foreign_email, user=foreign_user)[3]
    unavailable(foreign_email, cross_invite)
    assert sql(f"SELECT tenant_id FROM nds_owner WHERE user_id={literal(foreign_user)}").stdout.strip() == foreign_tenant

    # Synthetic unused rows fill only the tested account's capacity. Every
    # exercised session still comes from actual SMTP/OTP verification above.
    reset_cases()
    count = int(sql(f"SELECT count(*) FROM nds_sessions WHERE user_id={literal(user)}").stdout)
    fillers = [secrets.token_bytes(32) for _ in range(32 - count)]
    issued_at = int(time.time()*1000)
    for digest in fillers:
        sql(f"INSERT INTO nds_sessions(token_digest,user_id,tenant_id,auth_method,authenticated_at_ms,expires_at_ms) VALUES({binary(digest)},{literal(user)},{literal(tenant)},'email_otp',{issued_at},{issued_at+604800000})")
    proof = challenge(email)
    assert request("/v2/auth/email/verify", proof) == (503, {"error": "server_busy"})
    assert sql(f"SELECT consumed FROM nds_email_challenges WHERE challenge_id={literal(proof['challenge_id'])}").stdout.strip() == "f"
    assert verify(challenge(admin_email), admin_user, tenant)
    sql(f"DELETE FROM nds_sessions WHERE token_digest={binary(fillers[0])}")
    unobserved_member_token = verify(proof, user, tenant)
    for digest in fillers:
        sql(f"DELETE FROM nds_sessions WHERE token_digest={binary(digest)}")

    keys = Path(directory) / "company-devices"
    keys.mkdir(mode=0o700)
    def openssl(*args):
        return subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=5).stdout
    def sign(key, body):
        path = keys / (uuid.uuid4().hex + ".bin")
        path.write_bytes(body)
        try:
            return openssl("pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", path)
        finally:
            path.unlink()
    def enroll(token):
        key = keys / (uuid.uuid4().hex + ".pem")
        openssl("genpkey", "-algorithm", "ED25519", "-out", key)
        key.chmod(0o600)
        sensitive.extend(key.read_text().splitlines()[1:-1])
        public = openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
        assert len(public) == 44 and public[:12] == bytes.fromhex("302a300506032b6570032100")
        public = encode(public[12:])
        status, receipt = request("/v2/devices/challenges", {"platform": "linux", "display_name": "Company acceptance", "public_key": public}, token=token)
        assert status == 201
        status, device = request("/v2/devices/enrollments", {"challenge_id": receipt["challenge_id"], "signature": encode(sign(key, b"NDS-ENROLLMENT-V2\0" + base64.urlsafe_b64decode(receipt["challenge"] + "=")))}, token=token)
        assert status == 201
        return key, device["device_id"], public
    def signed(device, token, path, body=None, *, nonce=None, expiry=None, method=None):
        key, identifier, _ = device
        method = method or ("GET" if body is None else "POST")
        raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode())
        digest = "sha-256=:" + base64.b64encode(hashlib.sha256(raw).digest()).decode() + ":"
        now = int(time.time())
        nonce = nonce or encode(secrets.token_bytes(24))
        expiry = expiry or (now + 60) * 1000
        params = f'("@method" "@target-uri" "content-digest");created={now};expires={expiry//1000};nonce="{nonce}";alg="ed25519";keyid="{identifier}"'
        signature = sign(key, f'"@method": {method}\n"@target-uri": {origin+path}\n"content-digest": {digest}\n"@signature-params": {params}'.encode())
        headers = {"Authorization": "Bearer " + token, "Signature-Input": "nds=" + params, "Signature": "nds=:" + base64.b64encode(signature).decode() + ":", "Content-Digest": digest, "Content-Type": "application/json"}
        req = urllib.request.Request(origin + path, data=raw if body is not None else None, headers=headers, method=method)
        try:
            response = http.open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            value = response.read(65537)
            assert len(value) <= 65536 and response.headers["Cache-Control"] == "no-store"
            return response.status, json.loads(value) if value else None

    peers = [enroll(token) for token in (member_token, admin_token, foreign_token)]
    materials = []
    for peer, token, principal in zip(peers, (member_token, admin_token, foreign_token), (user, admin_user, foreign_user), strict=True):
        status, own = request("/v2/devices", token=token)
        assert status == 200 and [item["device_id"] for item in own["devices"]] == [peer[1]]
        retained_devices = sql("SELECT to_jsonb(d)::text FROM nds_devices d ORDER BY device_id").stdout
        assert request("/v3/personal/devices", token=token) == (200, {
            "context": {"principal_id": principal, "space": {"kind": "personal", "id": principal}}, **own,
        })
        assert request("/v3/personal/devices?user_id=" + (admin_user if principal == user else user), token=token)[0] == 400
        assert sql("SELECT to_jsonb(d)::text FROM nds_devices d ORDER BY device_id").stdout == retained_devices
        status, key = signed(peer, token, "/v2/vault/key", {"existing_key": None})
        assert status == 200
        materials.append(key["key_material"])
        sensitive.append(key["key_material"])
    assert len(set(materials)) == 3
    for other in (admin_token, foreign_token):
        assert signed(peers[0], other, "/v2/vault/key", {"existing_key": None})[0] == 401
        assert signed(peers[0], other, "/v2/sync/operations?after_seq=0")[0] == 401
        assert request("/v2/devices/challenges", {"platform": "linux", "display_name": "Rebind rejected", "public_key": peers[0][2]}, token=other)[0] == 400
    restart()
    for token in (member_token, admin_token, foreign_token):
        assert request("/v2/session", token=token)[0] == 200
    reset_cases()
    proof = challenge(email)
    sql(f"UPDATE nds_owner SET membership_active=FALSE WHERE user_id={literal(user)}")
    assert request("/v2/auth/email/verify", proof)[0] == 401
    assert request("/v2/session", token=member_token)[0] == 401
    assert request("/v3/personal/devices", token=member_token)[0] == 401
    assert signed(peers[0], member_token, "/v2/vault/key", {"existing_key": None})[0] == 401
    reset_cases()
    returning_invite = pending(email=email, user=user)[3]
    returning_token = verify(challenge(email, returning_invite), user, tenant)
    assert request("/v2/session", token=member_token)[0] == 401, "observed membership denial revived a session"
    assert request("/v2/session", token=unobserved_member_token)[0] == 401, "reinvitation revived an unobserved old session"
    assert signed(peers[0], returning_token, "/v2/vault/key", {"existing_key": None})[1]["key_material"] == materials[0]
    assert sql(f"SELECT member_revision FROM nds_owner WHERE user_id={literal(user)}").stdout.strip() == "2"
    assert request("/v2/session", token=admin_token)[0] == 200
    print("Company identity acceptance passed: real recipient OTP, atomic invitation consume/replay, current issuer/revocation/expiry, one-company ownership, per-user session capacity, independent device proofs and Vault keys, same-company admin/cross-company personal-data denial, restart and reinvitation preserving keys while retiring all old sessions. Invitation issuance/UI and RDS cross-user access remain separate.")
    unavailable_delivery = check_company_management(
        signed=signed, request=request, sql=sql, challenge=challenge, verify=verify,
        enroll=enroll, messages=messages, http=http, mailbox=mailbox, restart=restart,
        sensitive=sensitive, admin=(peers[1], admin_token, admin_user),
        member=(peers[0], returning_token, user), foreign=(peers[2], foreign_token, foreign_user),
        bootstrap=bootstrap, directory=keys, origin=origin, observability_configured=observability_configured,
    )
    return sensitive, unavailable_delivery
