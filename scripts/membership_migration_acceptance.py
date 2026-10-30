"""Production 14→15 SQL over generated encrypted originals and revoked authority.

This helper runs only in the existing disposable company-upgrade database. It
creates no copy of operator data and does not simulate authenticated HTTP grants.
"""
import json
from pathlib import Path
import secrets
import time
import uuid

from upgrade_acceptance import verify


def check_membership_upgrade(sql, witness):
    root = Path(__file__).resolve().parent.parent / "migrations"
    sql("BEGIN;\n" + (root / "0014_session_authority.sql").read_text() + "\nCOMMIT;", "nds_migrator")
    assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "14"
    user, company = witness["user"], witness["tenant"]
    removed = str(uuid.uuid4())
    recipient = str(uuid.uuid4())
    invitation = "A" * 43
    now = time.time_ns() // 1_000_000
    sql(f"INSERT INTO nds_owner(user_id,tenant_id,email_binding,company_role,membership_active,member_revision) VALUES('{removed}','{company}',decode('{secrets.token_hex(32)}','hex'),'user',FALSE,7)")
    sql(f"INSERT INTO nds_sessions(token_digest,user_id,tenant_id,auth_method,authenticated_at_ms,expires_at_ms) VALUES(decode('{secrets.token_hex(32)}','hex'),'{removed}','{company}','email_otp',{now},{now+28_800_000})")
    sql(f"INSERT INTO nds_company_invitations(invitation_id,tenant_id,issuer_user_id,recipient_user_id,recipient_email,recipient_binding,recipient_subject,company_role,verifier,issued_at_ms,expires_at_ms,status) VALUES('{invitation}','{company}','{user}','{recipient}','synthetic@example.invalid',decode('{secrets.token_hex(32)}','hex'),decode('{secrets.token_hex(32)}','hex'),'user',decode('{secrets.token_hex(32)}','hex'),{now},{now+300000},'pending')")
    sql(f"INSERT INTO nds_email_challenges(challenge_id,subject,verifier,created_at_ms,expires_at_ms,attempts_remaining,eligible,consumed,invitation_id) VALUES('{'B'*43}',decode('{secrets.token_hex(32)}','hex'),decode('{secrets.token_hex(32)}','hex'),{now},{now+300000},3,TRUE,FALSE,'{invitation}')")
    # Original immutable command bytes are retained even though old commands
    # without a membership revision cannot acquire a new v3 grant.
    operation = "01900000-0000-7000-8000-000000000001"
    device = sql(f"SELECT device_id FROM nds_devices WHERE user_id='{user}' AND tenant_id='{company}'").stdout.strip()
    sql(f"INSERT INTO nds_company_commands(user_id,tenant_id,device_id,operation_id,fingerprint,status,response,expires_at_ms) VALUES('{user}','{company}','{device}','{operation}',decode('{secrets.token_hex(32)}','hex'),200,convert_to('{{}}','UTF8'),{now+300000})")

    def rows(table):
        return json.loads(sql(f"SELECT COALESCE(json_agg(t ORDER BY row_to_json(t)::text),'[]'::json) FROM {table} t").stdout)

    tables = ("nds_owner", "nds_sessions", "nds_company_invitations", "nds_email_challenges", "nds_company_commands")
    before = {table: rows(table) for table in tables}
    forward = (root / "0015_independent_memberships.sql").read_text()
    # PostgreSQL must roll the complete production transition back, including
    # its DDL, if a later statement fails. No partial owner/authority activation.
    failed = sql("BEGIN;\n" + forward + "\nSELECT 1/0;\nCOMMIT;", "nds_migrator", check=False)
    assert failed.returncode != 0
    assert {table: rows(table) for table in tables} == before
    assert sql("SELECT to_regclass('public.nds_company_memberships') IS NULL").stdout.strip() == "t"
    assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "14"

    sql("BEGIN;\n" + forward + "\nCOMMIT;", "nds_migrator")
    verify(sql, witness)
    after = {table: rows(table) for table in tables}
    old_owners = {row["user_id"]: row for row in before["nds_owner"]}
    moved = {"company_role", "membership_active", "member_revision"}
    for current in after["nds_owner"]:
        original = old_owners[current["user_id"]]
        assert {key: value for key, value in current.items() if key != "verified"} == {key: value for key, value in original.items() if key not in moved}
        assert current["verified"] is True
    memberships = {row["user_id"]: row for row in rows("nds_company_memberships")}
    for key, original in old_owners.items():
        assert memberships[key] == {name: original[name] for name in ("user_id", "tenant_id", *sorted(moved))}
    for current in after["nds_sessions"]:
        original = next(row for row in before["nds_sessions"] if row["token_digest"] == current["token_digest"])
        assert {key: value for key, value in current.items() if key != "revoked"} == original
        assert current["revoked"] == (current["user_id"] == removed)
    for table in ("nds_email_challenges", "nds_company_commands"):
        assert after[table] == before[table]
    original = before["nds_company_invitations"][0]
    current = after["nds_company_invitations"][0]
    assert {key: value for key, value in current.items() if key not in {"issuer_tenant_id", "recipient_tenant_id"}} == original
    assert current["issuer_tenant_id"] == current["recipient_tenant_id"] == company

    assert sql("UPDATE nds_company_memberships SET company_role=company_role,member_revision=member_revision WHERE false", "nds_runtime").returncode == 0
    for column in ("tenant_id", "user_id"):
        assert sql(f"UPDATE nds_company_memberships SET {column}={column} WHERE false", "nds_runtime", check=False).returncode != 0
    assert sql("DELETE FROM nds_company_memberships WHERE false", "nds_runtime", check=False).returncode != 0
    assert sql("UPDATE nds_sessions SET revoked=FALSE WHERE false", "nds_runtime", check=False).returncode != 0
    assert sql("UPDATE nds_owner SET company_role='admin' WHERE false", "nds_runtime", check=False).returncode != 0
    rejected = sql("BEGIN;\n" + forward + "\nCOMMIT;", "nds_migrator", check=False)
    assert rejected.returncode != 0 and "require schema version 14" in rejected.stderr
    verify(sql, witness)
    assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "15"
    print("Membership migration passed: original encrypted owner/key/record/receipt bytes decrypt, revoked old sessions remain terminal, pending challenges/invitations survive, one membership authority replaces old roles, immutable scope fields and unrevocation refuse, failure and reapplication leave originals intact.")
