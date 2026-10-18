"""Production 13→14 SQL over generated storage rows in an owned database.

Random protected digests are storage witnesses, never usable login credentials.
The ordinary acceptance separately exercises real SQLx migration and replay.
"""
import json
from pathlib import Path
import secrets
import time
import uuid


def check_authority_upgrade(sql):
    root = Path(__file__).resolve().parent.parent / "migrations"
    for path in sorted(root.glob("*.sql")):
        if int(path.name.split("_")[0]) >= 14:
            break
        sql("BEGIN;\n" + path.read_text() + "\nCOMMIT;", "nds_migrator")
    assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "13"
    user, tenant = str(uuid.uuid4()), str(uuid.uuid4())
    sql(f"INSERT INTO nds_companies(tenant_id,display_name) VALUES('{tenant}','Owned migration input')")
    sql(f"INSERT INTO nds_owner(user_id,tenant_id,email_binding) VALUES('{user}','{tenant}',decode('{secrets.token_hex(32)}','hex'))")
    now = time.time_ns() // 1_000_000
    for expiry in [0, now - 1, now + 60_000, now + 28_800_000]:
        sql("INSERT INTO nds_sessions(token_digest,user_id,tenant_id,auth_method,expires_at_ms) "
            f"VALUES(decode('{secrets.token_hex(32)}','hex'),'{user}','{tenant}','email_otp',{expiry})")
    snapshot = "SELECT json_agg(s ORDER BY token_digest) FROM nds_sessions s"
    original = json.loads(sql(snapshot).stdout)
    forward = (root / "0014_session_authority.sql").read_text()
    sql("BEGIN;\n" + forward + "\nCOMMIT;", "nds_migrator")
    current = json.loads(sql(snapshot).stdout)
    for before, after in zip(original, current, strict=True):
        assert {key: after[key] for key in before} == before
        assert after["authenticated_at_ms"] == max(before["expires_at_ms"] - 28_800_000, 0)
    assert sql("UPDATE nds_sessions SET expires_at_ms=expires_at_ms WHERE false", "nds_runtime").returncode == 0
    for column in ["authenticated_at_ms", "user_id", "tenant_id", "auth_method", "token_digest"]:
        assert sql(f"UPDATE nds_sessions SET {column}={column} WHERE false", "nds_runtime", check=False).returncode != 0
    rejected = sql("BEGIN;\n" + forward + "\nCOMMIT;", "nds_migrator", check=False)
    assert rejected.returncode != 0 and "requires schema version 13" in rejected.stderr
    assert json.loads(sql(snapshot).stdout) == current
    print("Session migration passed: original expiries retained, authentication time recovered, proof/owner updates refused to runtime and direct reapplication rejected.")
