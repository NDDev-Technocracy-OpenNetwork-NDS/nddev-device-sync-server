"""Actual signed v3 spaces, immutable membership epochs and retained owners.

All participants already authenticated through the owning PG/SMTP fixture.
Reads capture their revision from signed server output, never from SQL grants.
"""
import json
import time


def check_organization_spaces(*, signed, request, sql, challenge, verify,
                              invitation_mail, messages, operation, admin, member, foreign):
    literal = lambda value: "'" + value.replace("'", "''") + "'"

    def listing(actor):
        status, value = signed(actor[0], actor[1], "/v3/organizations")
        assert status == 200
        assert value["context"] == {"principal_id": actor[2], "space": {"kind": "personal", "id": actor[2]}}
        rows = value["organizations"]
        assert len(rows) <= 32 and len({row["company"]["company_id"] for row in rows}) == len(rows)
        assert all(row["member"]["user_id"] == actor[2] and row["member"]["active"] for row in rows)
        return rows

    def scoped(actor, company, revision, resource="", body=None):
        path = "/v3/organizations/" + company + resource
        if body is None:
            path += "?membership_revision=" + str(revision)
        else:
            body = {"membership_revision": revision, "payload": body}
        status, value = signed(actor[0], actor[1], path, body)
        if 200 <= status < 300:
            assert value["context"] == {"principal_id": actor[2], "space": {"kind": "organization", "id": company}, "membership_revision": revision}
        return status, value

    def original_rows(actor):
        user = literal(actor[2])
        return {table: sql(f"SELECT COALESCE(json_agg(t ORDER BY row_to_json(t)::text),'[]'::json)::text FROM {table} t WHERE user_id={user}").stdout
                for table in ("nds_owner", "nds_devices", "nds_vault_keys")}

    before = {actor[2]: original_rows(actor) for actor in (admin, member, foreign)}
    initial = listing(admin)
    create = {"operation_id": operation(), "display_name": "Same displayed name"}
    status, created = signed(admin[0], admin[1], "/v3/organizations", create)
    assert status == 201
    first = created["overview"]
    first_id = first["company"]["company_id"]
    assert created["context"] == {"principal_id": admin[2], "space": {"kind": "organization", "id": first_id}, "membership_revision": 1}
    assert first["member"]["role"] == "admin" and first["member"]["revision"] == 1
    assert signed(admin[0], admin[1], "/v3/organizations", create) == (201, created)
    assert signed(admin[0], admin[1], "/v3/organizations", create | {"display_name": "Changed"}) == (409, {"error": "operation_conflict"})
    status, second = signed(admin[0], admin[1], "/v3/organizations", create | {"operation_id": operation()})
    assert status == 201 and second["overview"]["company"]["company_id"] != first_id
    assert second["overview"]["company"]["display_name"] == first["company"]["display_name"]
    assert len(listing(admin)) == len(initial) + 2
    assert scoped(admin, first_id, 1)[1]["overview"] == first
    assert scoped(member, first_id, 1)[0] == 403
    assert scoped(foreign, first_id, 1)[0] == 403
    assert signed(admin[0], member[1], "/v3/organizations")[0] == 401
    assert signed(admin[0], admin[1], "/v3/organizations?tenant_id=" + first_id)[0] == 400
    assert signed(admin[0], admin[1], "/v3/organizations/" + first_id)[0] == 400
    assert scoped(admin, first_id, 0)[0] == 400
    assert signed(admin[0], admin[1], "/v3/organizations", create | {"operation_id": operation(), "principal_id": foreign[2]})[0] == 400
    assert request("/v2/session", token=admin[1])[1]["user_id"] == admin[2]

    foreign_choices = listing(foreign)
    own = next(row for row in foreign_choices if row["member"]["role"] == "admin")
    company = own["company"]["company_id"]
    actor_revision = own["member"]["revision"]
    selected = next(row for row in listing(member) if row["company"]["company_id"] == company)
    old_revision = selected["member"]["revision"]
    assert selected["member"]["role"] == "user"
    old_command = {"operation_id": operation(), "email": "uncommitted@example.invalid", "role": "user"}
    change = {"operation_id": operation(), "expected_revision": old_revision, "action": "set_role", "role": "admin"}
    status, promoted = scoped(foreign, company, actor_revision, "/members/" + member[2], change)
    assert status == 200 and promoted["member"]["revision"] == old_revision + 1
    retained = original_rows(member)
    command_count = sql("SELECT count(*) FROM nds_company_commands").stdout
    assert scoped(member, company, old_revision)[0] == 403
    assert scoped(member, company, old_revision, "/invitations", old_command)[0] == 403
    assert sql("SELECT count(*) FROM nds_company_commands").stdout == command_count
    assert scoped(member, company, old_revision + 1, "/members")[0] == 200
    remove = {"operation_id": operation(), "expected_revision": old_revision + 1, "action": "remove", "role": None}
    status, removed = scoped(foreign, company, actor_revision, "/members/" + member[2], remove)
    assert status == 200 and not removed["member"]["active"]
    assert not any(row["company"]["company_id"] == company for row in listing(member))
    assert scoped(member, company, old_revision + 1)[0] == 403
    assert request("/v2/session", token=member[1])[0] == 200
    assert request("/v3/personal/devices", token=member[1])[0] == 200
    assert original_rows(member) == retained

    # Respect the actual recipient resend budget without changing rate state,
    # challenge dates or the server clock. This is an independent new join.
    deadline = time.monotonic() + 61
    while time.monotonic() < deadline:
        time.sleep(min(1, max(0.001, deadline - time.monotonic())))
    email = json.loads(before[member[2]]["nds_owner"])[0]["email"]
    old_mail = {message["ID"] for message in messages()}
    invitation_body = {"operation_id": operation(), "email": email, "role": "admin"}
    status, invited = scoped(foreign, company, actor_revision, "/invitations", invitation_body)
    assert status == 201
    claim = invitation_mail(email, invited["invitation"]["invitation_id"], old_mail)
    personal = json.loads(before[member[2]]["nds_owner"])[0]
    token = verify(challenge(email, claim), member[2], personal["tenant_id"])
    rejoined = (member[0], token, member[2])
    current = next(row for row in listing(rejoined) if row["company"]["company_id"] == company)
    assert current["member"]["revision"] == old_revision + 3 and current["member"]["role"] == "admin"
    assert scoped(member, company, old_revision, "/invitations", old_command)[0] == 403
    assert scoped(member, company, old_revision + 1, "/members")[0] == 403
    assert scoped(rejoined, company, old_revision + 3, "/members")[0] == 200
    assert request("/v2/session", token=member[1])[0] == 200
    assert original_rows(member) == retained
    assert all(original_rows(actor) == before[actor[2]] for actor in (admin, member, foreign))

    # Real admitted creates reach the retained bound. The next command must not
    # create a company, membership or receipt, and cannot invalidate the person.
    while len(listing(admin)) < 32:
        status, _ = signed(admin[0], admin[1], "/v3/organizations", {"operation_id": operation(), "display_name": "Capacity fixture"})
        assert status == 201
    counts = sql("SELECT (SELECT count(*) FROM nds_companies)||':'||(SELECT count(*) FROM nds_company_memberships)||':'||(SELECT count(*) FROM nds_company_commands)").stdout
    assert signed(admin[0], admin[1], "/v3/organizations", {"operation_id": operation(), "display_name": "Refused fixture"}) == (503, {"error": "server_busy"})
    assert sql("SELECT (SELECT count(*) FROM nds_companies)||':'||(SELECT count(*) FROM nds_company_memberships)||':'||(SELECT count(*) FROM nds_company_commands)").stdout == counts
    assert len(listing(admin)) == 32 and request("/v2/session", token=admin[1])[0] == 200
    print("Organization spaces passed: signed personal list/create/replay, same names with distinct IDs, wrong-scope and missing-revision denial, role/rejoin epochs refuse stale reads and commands without effects, real invitation+OTP rejoin preserves original owner/device/Vault bytes and personal sessions, and actual32-membership capacity refuses without partial writes.", flush=True)
