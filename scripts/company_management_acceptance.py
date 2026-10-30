"""Real signed administrative commands, SMTP invitations and recipient OTP.

All peers/mailboxes/data belong to the existing disposable acceptance fixture.
The RDS check proves HTTP control metadata retirement, not native screen capture.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import re
import secrets
import subprocess
import time
from urllib.parse import urlsplit
import uuid


def check_company_management(*, signed, request, sql, challenge, verify, enroll,
                             messages, http, mailbox, restart, sensitive, admin,
                             member, foreign, bootstrap, directory, origin, observability_configured):
    literal = lambda value: "'" + value.replace("'", "''") + "'"
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    company = bootstrap["tenant_id"]
    company_path = "/v3/organizations/" + company
    captured_commands = {}

    def operation(now=None):
        # RFC9562 UUIDv7 layout; maintained stdlib UUID formats the generated bits.
        stamp = int(time.time() * 1000) if now is None else now
        return str(uuid.UUID(int=(stamp << 80) | (7 << 76) | (secrets.randbits(12) << 64) | (2 << 62) | secrets.randbits(62)))

    def call(actor, path, body=None, **options):
        if not path.startswith(company_path):
            return signed(actor[0], actor[1], path, body, **options)
        # SQL supplies only an observed counter in this HTTP/store fixture, not
        # a role or authentication grant. Production clients select via signed
        # network discovery and have their own original-lifetime tests.
        current = sql(f"SELECT member_revision FROM nds_company_memberships WHERE tenant_id={literal(company)} AND user_id={literal(actor[2])}").stdout.strip()
        revision = int(current or "1")
        method = options.get("method") or ("GET" if body is None else "POST")
        if method == "POST":
            raw = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode()
            payload = json.loads(raw)
            key = (actor[2], actor[0][1], payload.get("operation_id"), company)
            revision = captured_commands.setdefault(key, revision)
            body = b'{"membership_revision":' + str(revision).encode() + b',"payload":' + raw + b'}'
        else:
            path += ("&" if "?" in path else "?") + "membership_revision=" + str(revision)
        status, value = signed(actor[0], actor[1], path, body, **options)
        if 200 <= status < 300:
            assert value["context"] == {"principal_id": actor[2], "space": {"kind": "organization", "id": company}, "membership_revision": revision}
            for name in ("overview", "page", "invitation", "member"):
                if name in value:
                    return status, value[name]
            raise AssertionError("scoped response lacked its canonical payload")
        return status, value

    def page(actor, name):
        values, after = [], None
        for _ in range(30):
            path = company_path+"/" + name + ("?after=" + after if after else "")
            status, result = call(actor, path)
            assert status == 200
            assert len(result[name]) <= 50
            values += result[name]
            following = result["next_cursor"]
            if following is None:
                return values
            assert following != after
            after = following
        raise AssertionError("company page did not terminate within its fixture bound")

    def member_row(actor, user):
        return next(item for item in page(actor, "members") if item["user_id"] == user)

    def change(actor, target, revision, role=None, identifier=None):
        body = {"operation_id": identifier or operation(), "expected_revision": revision,
                "action": "remove" if role is None else "set_role", "role": role}
        return body, call(actor, company_path+"/members/" + target, body)

    def revoke(actor, identifier, command=None):
        body = {"operation_id": command or operation()}
        return call(actor, company_path+"/invitations/" + identifier + "/revoke", body)

    def invitation_mail(address, identifier, old):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            for item in messages():
                if item["ID"] in old:
                    continue
                with http.open(mailbox + "/api/v1/message/" + item["ID"], timeout=2) as response:
                    message = json.load(response)
                if not any(recipient["Address"] == address for recipient in message["To"]):
                    continue
                match = re.search(r"https?://\S+#invite/([A-Za-z0-9_-]{43})/([A-Za-z0-9_-]{43})", message["Text"])
                if match and match[1] == identifier:
                    link = urlsplit(match[0]); base = urlsplit(origin)
                    assert (link.scheme, link.netloc, link.path, link.query) == (base.scheme, base.netloc, "/", "")
                    sensitive.extend([address, match[2], match[0]])
                    return {"invitation_id": identifier, "invitation_token": match[2]}
            time.sleep(0.05)
        raise AssertionError("administrative invitation did not reach its real isolated mailbox")

    def invite(actor, role="user", *, duplicate=False):
        address = uuid.uuid4().hex + "@example.invalid"
        sensitive.append(address)
        body = {"operation_id": operation(), "email": address, "role": role}
        old = {message["ID"] for message in messages()}
        if duplicate:
            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda _: call(actor, company_path+"/invitations", body), range(2)))
            assert outcomes[0] == outcomes[1] and outcomes[0][0] == 201
            result = outcomes[0][1]
        else:
            status, result = call(actor, company_path+"/invitations", body)
            assert status == 201
        assert result["status"] == result["delivery"] == "pending"
        assert set(result) == {"invitation_id", "issuer_user_id", "recipient_email", "role", "expires_at_ms", "status", "delivery"}
        claim = invitation_mail(address, result["invitation_id"], old)
        assert sql(f"SELECT count(*) FROM nds_company_invitations WHERE invitation_id={literal(result['invitation_id'])}").stdout.strip() == "1"
        return body, result, claim

    from organization_spaces_acceptance import check_organization_spaces
    check_organization_spaces(signed=signed, request=request, sql=sql, challenge=challenge,
        verify=verify, invitation_mail=invitation_mail, messages=messages, operation=operation,
        admin=admin, member=member, foreign=foreign)

    for actor in (admin, member, foreign):
        for path in ("/v2/observability/status", "/v2/observability/incidents"):
            assert call(actor, path) == (403, {"error":"authorization_denied"})
        assert call(actor, "/v2/observability/incidents/unknown/acknowledge", {"operation_id":operation(),"expected_revision":1}) == (403, {"error":"authorization_denied"})
        status, policy = call(actor, "/v2/observability/client-policy")
        if observability_configured:
            assert status == 200 and policy == {"export_mode":"enabled"}
        else:
            assert status == 503
        assert request("/v2/session", token=actor[1])[0] == 200
    print("Company operator boundary passed: admin/user/foreign accounts cannot read or manage the global pipeline; client policy is independent and valid sessions remain usable.", flush=True)
    before = sql("SELECT count(*) FROM nds_company_commands").stdout
    assert signed(admin[0],admin[1],"/v2/company/invitations",{"operation_id":operation(),"email":"legacy@example.invalid","role":"user"}) == (403,{"error":"authorization_denied"})
    assert sql("SELECT count(*) FROM nds_company_commands").stdout == before
    assert call(admin, company_path)[1]["member"]["role"] == "admin"
    assert call(member, company_path)[1]["member"]["user_id"] == member[2]
    assert call(member, company_path+"/members")[0] == 403
    assert call(member, company_path+"/invitations", {"operation_id": operation(), "email": "denied@example.invalid", "role": "admin"})[0] == 403
    assert call(admin, company_path+"?company_id=injected")[0] == 400
    assert call(admin, company_path+"/members?company_id=injected")[0] == 400
    assert call(admin, company_path+"/invitations", {"operation_id": operation(), "email": "denied@example.invalid", "role": "user", "tenant_id": company})[0] == 400
    assert change(admin, foreign[2], 1, "user")[1][0] == 403
    stale = {"operation_id": operation(int(time.time()*1000)-360000), "email": "expired@example.invalid", "role": "user"}
    assert call(admin, company_path+"/invitations", stale) == (409, {"error": "command_expired"})
    nonce = encode(secrets.token_bytes(24))
    assert call(member, company_path+"/members", nonce=nonce)[0] == 403
    assert call(member, company_path+"/members", nonce=nonce) == (409, {"error": "replayed_nonce"})

    def targets(actor, selected):
        status, page = call(actor, "/v2/rds/targets/" + selected[2])
        assert status == 200 and set(page) == {"user_id", "targets"}
        assert page["user_id"] == selected[2] and len(page["targets"]) <= 32
        personal, cursor = [], None
        for _ in range(5):
            status, inventory = request("/v2/devices" + ("?cursor=" + cursor if cursor else ""), token=selected[1])
            assert status == 200
            personal += inventory["devices"]
            cursor = inventory["next_cursor"]
            if cursor is None: break
        else: raise AssertionError("owned inventory did not terminate within its retained-device bound")
        active = {row["device_id"]: row for row in personal if row["status"] == "active"}
        # Both views retain the canonical enrollment order, independent of DB locale.
        assert [row["device_id"] for row in page["targets"]] == list(active)
        for row in page["targets"]:
            assert set(row) == {"device_id", "display_name", "platform", "registered"}
            assert row["display_name"] == active[row["device_id"]]["display_name"]
            assert row["platform"] == active[row["device_id"]]["platform"]
        return page["targets"]

    assert all(not row["registered"] for row in targets(admin, member))
    assert targets(member, member) == targets(admin, member)
    for actor, selected in [(member, admin), (member, foreign), (admin, foreign), (foreign, member)]:
        assert call(actor, "/v2/rds/targets/" + selected[2])[0] == 403
    assert call(admin, "/v2/rds/targets/" + str(uuid.uuid4()))[0] == 403
    assert call(admin, "/v2/rds/targets/" + member[2] + "?limit=1024")[0] == 400
    assert call(admin, "/v2/rds/targets/" + member[2], b"{}", method="GET")[0] == 400

    # Retire an actual successful command only after its real five-minute window.
    expiry_start = time.monotonic()
    expiry_body, expiry_invite, _ = invite(admin, duplicate=True)
    assert call(admin, company_path+"/invitations", json.dumps(expiry_body, indent=1).encode()) == (409, {"error": "operation_conflict"})
    assert revoke(admin, expiry_invite["invitation_id"], expiry_body["operation_id"]) == (409, {"error": "operation_conflict"})
    restart()
    assert call(admin, company_path+"/invitations", expiry_body) == (201, expiry_invite)

    body, invited, claim = invite(admin, "admin")
    planned = sql(f"SELECT recipient_user_id FROM nds_company_invitations WHERE invitation_id={literal(invited['invitation_id'])}").stdout.strip()
    assert sql(f"SELECT verified FROM nds_owner WHERE user_id={literal(planned)}").stdout.strip() == "f"
    token = verify(challenge(body["email"], claim), planned, company)
    extra_admin = (enroll(token), token, planned)
    assert call(extra_admin, company_path)[1]["member"]["role"] == "admin"

    _, doomed, doomed_claim = invite(admin)
    status, revoked = revoke(admin, doomed["invitation_id"])
    assert status == 200 and revoked["status"] == "revoked"
    assert request("/v2/auth/invitations/challenges", {"email": doomed["recipient_email"]} | doomed_claim)[0] == 202
    assert sql(f"SELECT count(*) FROM nds_email_challenges WHERE invitation_id={literal(doomed['invitation_id'])} AND eligible").stdout.strip() == "0"

    # Page real retained metadata with an authenticated administrator. Additional
    # synthetic rows test pagination only and issue no sessions or user proofs.
    for _ in range(51):
        user = str(uuid.uuid4())
        sql(f"INSERT INTO nds_owner(user_id,tenant_id,email_binding,verified) VALUES({literal(user)},{literal(company)},decode('{secrets.token_hex(32)}','hex'),TRUE);"
            f"INSERT INTO nds_company_memberships(tenant_id,user_id,company_role,membership_active,member_revision) VALUES({literal(company)},{literal(user)},'user',TRUE,1)")
    all_members = page(admin, "members")
    expected = sql(f"SELECT m.user_id FROM nds_company_memberships m JOIN nds_owner o USING(user_id) WHERE m.tenant_id={literal(company)} AND o.verified ORDER BY m.user_id").stdout.splitlines()
    assert [item["user_id"] for item in all_members] == expected
    assert foreign[2] not in expected

    bootstrap_row = member_row(admin, bootstrap["user_id"])
    _, result = change(admin, bootstrap["user_id"], bootstrap_row["revision"], "user")
    assert result[0] == 200
    actors = [admin, extra_admin]
    revisions = [member_row(admin, actor[2])["revision"] for actor in actors]
    command_ids = [operation(), operation()]
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda index: change(actors[index], actors[index][2], revisions[index], "user", command_ids[index])[1], range(2)))
    assert sorted(status for status, _ in outcomes) == [200, 409]
    survivor_index = next(index for index, outcome in enumerate(outcomes) if outcome == (409, {"error": "last_administrator"}))
    authority = actors[survivor_index]
    demoted = actors[1-survivor_index]
    assert call(demoted, company_path+"/members")[0] == 403
    assert request("/v2/session", token=demoted[1])[0] == 200
    assert change(authority, authority[2], revisions[survivor_index])[1] == (409, {"error": "last_administrator"})
    # A privileged receipt never bypasses the actor's current role on replay.
    repeated = {"operation_id": command_ids[1-survivor_index], "expected_revision": revisions[1-survivor_index], "action": "set_role", "role": "user"}
    assert call(demoted, company_path+"/members/" + demoted[2], repeated)[0] == 403
    _, restored = change(authority, bootstrap["user_id"], bootstrap_row["revision"]+1, "admin")
    assert restored[0] == 200

    # Actual independent device/endpoint proofs across company users. Ready
    # remains an opaque server artifact; these checks do not establish native pixels.
    def openssl(*args):
        return subprocess.run(["openssl", *map(str,args)], check=True, capture_output=True, timeout=5).stdout
    def endpoint(actor):
        peer = actor[0]
        key = directory / (uuid.uuid4().hex + ".pem")
        openssl("genpkey", "-algorithm", "ED25519", "-out", key); key.chmod(0o600)
        sensitive.extend(key.read_text().splitlines()[1:-1])
        public = openssl("pkey", "-in", key, "-pubout", "-outform", "DER")[12:]
        assert len(public) == 32
        instance, nonce = uuid.uuid4(), encode(secrets.token_bytes(24))
        expires = (int(time.time())+60)*1000
        transcript = b"NDS-RDS-ENDPOINT-BINDING-V2\0"
        for field in [origin.encode(),peer[1].encode()]: transcript += len(field).to_bytes(2,"big")+field
        transcript += public + instance.bytes + (0).to_bytes(8,"big") + len(nonce).to_bytes(2,"big") + nonce.encode() + expires.to_bytes(8,"big")
        path = directory / (uuid.uuid4().hex + ".bin"); path.write_bytes(transcript)
        signature = openssl("pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", path); path.unlink()
        status, binding = call(actor, "/v2/rds/bindings", {"endpoint_public_key":encode(public),"instance_id":str(instance),"base_revision":0,"nonce":nonce,"expires_at_ms":expires,"signature":encode(signature)}, nonce=nonce, expiry=expires)
        assert status == 200
        return binding
    host = (enroll(member[1]), member[1], member[2])
    bindings = {actor[0][1]: endpoint(actor) for actor in (member, host, authority, demoted, foreign)}
    def view_request(viewer, target, seconds=120):
        return {"target_device_id":target[0][1],"viewer_revision":bindings[viewer[0][1]]["revision"],
                "host_revision":bindings[target[0][1]]["revision"],"display":0,"max_fps":30,
                "output_height":1080,"expires_at_ms":(int(time.time())+seconds)*1000,"idempotency_key":uuid.uuid4().hex}
    def create_view(viewer, target):
        payload = view_request(viewer, target)
        status, view = call(viewer, "/v2/rds/views", payload)
        assert status == 201
        return payload, view
    def end(viewer, view):
        assert call(viewer, "/v2/rds/views/"+view["view_id"]+"/end", b"") == (204,None)
    def ready(view):
        assert call(host, "/v2/rds/views/"+view["view_id"]+"/ready", {"native_grant":"AA"})[0] == 200

    # No broadening of personal inventory or device proof from administrator status.
    assert request("/v2/devices", token=authority[1])[1]["devices"][0]["device_id"] == authority[0][1]
    assert host[0][1] not in [d["device_id"] for d in request("/v2/devices",token=authority[1])[1]["devices"]]
    assert signed(member[0],authority[1],"/v2/vault/key",{"existing_key":None})[0] == 401
    for viewer,target in ((member,authority),(member,demoted),(authority,foreign),(foreign,member)):
        assert call(viewer,"/v2/rds/bindings/"+target[0][1])[0] == 403
        assert call(viewer,"/v2/rds/views",view_request(viewer,target))[0] == 403
    assert call(authority,"/v2/rds/bindings/"+host[0][1])[1]["binding"] == bindings[host[0][1]]
    _, own = create_view(member,host)
    ready(own)
    end(host,own)

    # Full per-user target bound uses actual enrollment proofs, not synthetic
    # device rows or a reset of the enrollment budget.
    for _ in range(30):
        enroll(member[1])
    discovered = targets(authority, member)
    assert len(discovered) == 32
    assert {row["device_id"] for row in discovered if row["registered"]} == {member[0][1], host[0][1]}

    # Two genuinely different administrators compete for the same immutable host.
    promoted = member_row(authority,demoted[2])
    assert change(authority,demoted[2],promoted["revision"],"admin")[1][0] == 200
    viewers = [authority,demoted]
    requests = [view_request(viewer,host) for viewer in viewers]
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda i: call(viewers[i],"/v2/rds/views",requests[i]),range(2)))
    assert sorted(status for status,_ in outcomes) == [201,503]
    winner_index = next(i for i,result in enumerate(outcomes) if result[0] == 201)
    winner, outsider = viewers[winner_index],viewers[1-winner_index]
    view = outcomes[winner_index][1]
    assert call(host,"/v2/rds/views/incoming")[1]["view"] == view
    ready(view)
    path = "/v2/rds/views/"+view["view_id"]
    assert call(winner,path)[1]["native_grant"] == "AA"
    assert call(winner,"/v2/rds/views",requests[winner_index])[1]["state"] == "ready"
    assert call(outsider,path)[0] == 403
    assert call(outsider,path+"/end",b"")[0] == 403
    assert call(winner,path+"/ready",{"native_grant":"AA"})[0] == 403
    assert call(host,path)[0] == 403
    restart()
    assert call(host,"/v2/rds/views/incoming")[1]["view"]["state"] == "ready"
    assert call(winner,path)[1]["native_grant"] == "AA"

    current = member_row(outsider,winner[2])
    assert change(outsider,winner[2],current["revision"],"user")[1][0] == 200
    assert call(host,"/v2/rds/views/incoming") == (200,{"view":None})
    assert call(winner,path)[0] == 403
    assert call(host,path+"/ready",{"native_grant":"AA"})[0] == 403
    assert call(winner,"/v2/rds/views",requests[winner_index])[0] == 403
    assert call(winner,"/v2/rds/bindings/"+host[0][1])[0] == 403
    assert call(winner,"/v2/rds/targets/"+member[2])[0] == 403
    assert targets(winner, winner)
    assert request("/v2/session",token=winner[1])[0] == 200
    end(host,view) # Cleanup remains allowed for the actual host after viewer demotion.
    current = member_row(outsider,winner[2])
    assert change(outsider,winner[2],current["revision"],"admin")[1][0] == 200
    assert call(winner,"/v2/rds/views",requests[winner_index])[1]["state"] == "ended"
    assert sql(f"SELECT user_id FROM nds_devices WHERE device_id={literal(host[0][1])}").stdout.strip() == member[2]

    # Original viewer session revocation is still enforced when the host belongs
    # to another user. Both sessions come through real recipient SMTP/OTP.
    viewer_email = member_row(authority,authority[2])["email"]
    # Respect the real recipient resend window; never clear rate state or age OTPs.
    resend_ready = time.monotonic() + 61
    while time.monotonic() < resend_ready:
        time.sleep(min(1,resend_ready-time.monotonic()))
    session = verify(challenge(viewer_email),authority[2],company)
    renewed = (authority[0],session,authority[2])
    _, old_session_view = create_view(renewed,host)
    assert request("/v2/session",token=session,method="DELETE")[0] == 204
    assert call(host,"/v2/rds/views/"+old_session_view["view_id"]+"/ready",{"native_grant":"AA"})[0] == 403
    end(host,old_session_view)

    # Membership removal retires a cross-user view and keeps personal Vault rows.
    _, view = create_view(authority,host)
    ready(view)
    print("Company RDS authority passed: minimal signed32-device discovery, separate users, signed binding policy, own-device access, cross-user admin access, cross-company/user denial, participant-only artifacts, shared host admission, restart, demotion/repromotion and original-viewer-session revocation.", flush=True)
    revision = member_row(authority, member[2])["revision"]
    payload, removed = change(authority, member[2], revision)
    assert removed[0] == 200 and removed[1]["active"] is False
    assert request("/v2/session", token=member[1])[0] == 200
    assert call(authority,"/v2/rds/targets/"+member[2])[0] == 403
    assert sql(f"SELECT state||':'||(native_grant IS NULL)::text FROM nds_screen_views WHERE view_id={literal(view['view_id'])}").stdout.strip() == "ended:true"
    assert call(authority, company_path+"/members/" + member[2], payload) == removed
    assert change(authority, member[2], revision)[1] == (409, {"error": "operation_conflict"})
    assert sql(f"SELECT count(*) FROM nds_vault_keys WHERE user_id={literal(member[2])}").stdout.strip() == "1"

    # No clock rewriting or expiration-column edits qualify this boundary.
    while time.monotonic()-expiry_start < 301:
        time.sleep(max(0.001,min(1,301-(time.monotonic()-expiry_start))))
    assert call(authority, company_path+"/invitations", {"operation_id":operation(),"email":uuid.uuid4().hex+"@example.invalid","role":"user"})[0] == 201
    # Cleanup is scoped to the original actor. It may have been demoted; use a
    # new current-authority command from that same actor after a real promotion.
    if authority[2] != admin[2]:
        current = member_row(authority, admin[2])
        assert change(authority, admin[2], current["revision"], "admin")[1][0] == 200
    assert revoke(admin, expiry_invite["invitation_id"])[0] == 200
    assert sql(f"SELECT count(*) FROM nds_company_commands WHERE operation_id={literal(expiry_body['operation_id'])}::uuid").stdout.strip() == "0"
    assert call(admin, company_path+"/invitations", expiry_body) == (409, {"error":"command_expired"})
    print("Company management acceptance passed: signed admin creation, actual SMTP link and recipient OTP, exact concurrent replay/restart, role and cross-company denial, bounded pages, concurrent last-admin protection, removal retires cross-user HTTP screen access while retaining personal sessions and Vault, and real five-minute receipt retirement rejects reuse.", flush=True)

    def unavailable_delivery():
        address = uuid.uuid4().hex + "@example.invalid"
        body = {"operation_id":operation(),"email":address,"role":"user"}
        status, created = call(admin, company_path+"/invitations", body)
        assert status == 201 and created["delivery"] == "pending"
        current = next(item for item in page(admin,"invitations") if item["invitation_id"] == created["invitation_id"])
        assert current["delivery"] == "failed" and current["status"] == "pending"
        assert call(admin,company_path+"/invitations",body) == (201,created)
        assert sql(f"SELECT count(*) FROM nds_company_invitations WHERE invitation_id={literal(created['invitation_id'])}").stdout.strip() == "1"
        print("Company delivery failure passed: creation remains distinct from delivery; unavailable shared SMTP produces explicit failed state and replay never creates or sends another invitation.")
        return [address]
    return unavailable_delivery
