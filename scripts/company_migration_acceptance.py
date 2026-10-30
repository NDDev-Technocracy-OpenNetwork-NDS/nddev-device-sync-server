"""Production 11→12 SQL over owned encrypted upgrade witnesses; no live data."""
import json
from pathlib import Path
import secrets
import time

from upgrade_acceptance import prepare, verify


def check_company_upgrade(sql):
    root = Path(__file__).resolve().parent.parent / "migrations"
    for path in sorted(root.glob("*.sql")):
        version = int(path.name.split("_")[0])
        if version > 11:
            break
        sql("BEGIN;\n" + path.read_text() + "\nCOMMIT;", "nds_migrator")
        if version == 9:
            witness = prepare(sql)
    assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "11"
    now = int(time.time() * 1000)
    # Existing eligible and deliberately ineligible challenges retain their
    # original protected bytes, attempts and expiry through the membership join.
    for index, eligible in enumerate((True, False)):
        sql("INSERT INTO nds_email_challenges(challenge_id,subject,verifier,created_at_ms,expires_at_ms,attempts_remaining,eligible) "
            f"VALUES('{str(index)*43}',decode('{secrets.token_hex(32)}','hex'),decode('{secrets.token_hex(32)}','hex'),"
            f"{now},{now+300000},3,{str(eligible).lower()})")
    before = json.loads(sql("SELECT json_agg(c ORDER BY challenge_id) FROM nds_email_challenges c").stdout)
    forward = (root / "0012_company_membership.sql").read_text()
    sql("BEGIN;\n" + forward + "\nCOMMIT;", "nds_migrator")
    verify(sql, witness)
    after = json.loads(sql("SELECT json_agg(c ORDER BY challenge_id) FROM nds_email_challenges c").stdout)
    for original, current in zip(before, after, strict=True):
        assert {name: current[name] for name in original} == original
        assert current["invitation_id"] is None
        assert current["user_id"] == (witness["user"] if original["eligible"] else None)
        assert current["tenant_id"] == (witness["tenant"] if original["eligible"] else None)
    rejected = sql("BEGIN;\n" + forward + "\nCOMMIT;", "nds_migrator", check=False)
    assert rejected.returncode != 0 and "requires schema version 11" in rejected.stderr
    verify(sql, witness)
    assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "12"
    sql("BEGIN;\n" + (root / "0013_company_commands.sql").read_text() + "\nCOMMIT;", "nds_migrator")
    verify(sql, witness)
    assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == "13"
    assert sql("UPDATE nds_company_commands SET response=response WHERE false", "nds_runtime", check=False).returncode != 0
    print("Company migration passed: production 11-to12-to13 SQL preserves owner/device/key/record/receipt bytes and decryption, binds existing OTP challenges, rejects accidental direct reapplication, and keeps command receipts immutable to runtime.")
    from membership_migration_acceptance import check_membership_upgrade
    check_membership_upgrade(sql, witness)
