"""Seven bounded schema9 storage witnesses; not fabricated NDS authentication.

Only the owned PostgreSQL upgrade fixture calls this helper. Real AES-GCM from
the independent cryptography provider produces valid opaque envelope/record data;
all keys/plaintext stay in process memory, and only row digests are reported.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from pathlib import Path

TABLES = ("nds_owner", "nds_devices", "nds_sessions", "nds_vault_keys",
          "nds_sync_counters", "nds_sync_entities", "nds_sync_operations")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def snapshot(sql, original=None):
    # This fixture starts with exactly one generated row in each table.
    # row_to_json retains every column (including nullable fields and bytea hex).
    result = {}
    for table in TABLES:
        source = table if original is None else table.replace("nds_sync_", "nds_replica_")
        columns = "*" if original is None else ",".join(
            name for name in json.loads(original[table])[0] if name != "singleton")
        selected = ""
        if original is not None:
            binding = json.loads(original[table])[0]
            literal = lambda value: "'" + value.replace("'", "''") + "'"
            selected = f" WHERE user_id={literal(binding['user_id'])} AND tenant_id={literal(binding['tenant_id'])}"
        text = sql(f"SELECT row_to_json(t)::text FROM (SELECT {columns} FROM {source}{selected}) t").stdout.strip()
        rows = [json.loads(line) for line in text.splitlines()]
        assert len(rows) == 1, f"upgrade witness row count changed: {table}"
        # Schema12 deliberately removes only the obsolete singleton constraint;
        # every identity, device, ciphertext and receipt column remains exact.
        rows[0].pop("singleton", None)
        result[table] = canonical(rows)
    return result


def prepare(sql):
    # Optional --upgrade-from tool prerequisite; never a runtime dependency.
    import cryptography
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    assert cryptography.__version__ == "50.0.2", "upgrade witness requires cryptography50.0.2"
    assert all(sql(f"SELECT count(*) FROM {table}").stdout.strip() == "0" for table in TABLES)
    text = lambda value: "'" + value.replace("'", "''") + "'"
    binary = lambda value: f"decode('{value.hex()}','hex')"
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    user, tenant, key_id, operation_id = [str(uuid.uuid4()) for _ in range(4)]
    device = encode(secrets.token_bytes(32))
    public = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    now = int(time.time() * 1000)
    pepper = secrets.token_bytes(32)

    def protect(purpose, value):
        transcript = b"NDS-IDENTITY-V2\0"
        for field in (purpose.encode(), value):
            transcript += len(field).to_bytes(8, "big") + field
        return hmac.digest(pepper, transcript, "sha256")

    email_digest = protect("email_subject", ("upgrade-" + user + "@example.invalid").encode())
    session_digest = protect("session", encode(secrets.token_bytes(32)).encode())
    material = uuid.UUID(key_id).bytes + secrets.token_bytes(32)
    wrapping, envelope_nonce, record_nonce = secrets.token_bytes(32), secrets.token_bytes(12), secrets.token_bytes(12)
    # Same canonical JSON-array AAD as existing Server WrappingKey and VaultKey;
    # encryption uses an independent maintained provider, not a homemade cipher.
    envelope_aad = canonical(["NDS-SERVER-OWNER-KEY-V1", tenant, user, key_id])
    envelope = AESGCM(wrapping).encrypt(envelope_nonce, material, envelope_aad)
    plaintext = canonical({"version": 1, "deleted": False, "title": "Owned upgrade witness",
                           "username": "fixture", "secret": secrets.token_hex(16)})
    entity = "upgrade-record"
    record_aad = canonical(["NDS-RECORD-V2", "https://upgrade.example.invalid/", tenant,
                            user, device, "vault_record", entity, operation_id, 0, key_id])
    ciphertext = AESGCM(material[16:]).encrypt(record_nonce, plaintext, record_aad)
    request = canonical({"schema_version": 2, "operation_id": operation_id, "device_id": device,
                         "entity_type": "vault_record", "entity_id": entity, "base_revision": 0,
                         "idempotency_key": operation_id, "payload": {"algorithm": "aes-256-gcm",
                         "key_id": key_id, "nonce": encode(record_nonce), "ciphertext": encode(ciphertext)}})
    response = canonical({"outcome": "applied", "operation_id": operation_id, "server_seq": 1, "revision": 1})
    assert len(envelope) == 64 and len(request) <= 24576 and len(response) <= 2048
    cost = len(request) * 2 + len(response)
    sql(f"""BEGIN;
INSERT INTO nds_owner(singleton,user_id,tenant_id,email_binding) VALUES(1,{text(user)},{text(tenant)},{binary(email_digest)});
INSERT INTO nds_devices(device_id,user_id,tenant_id,ordinal,platform,display_name,public_key,status,created_at_ms)
 VALUES({text(device)},{text(user)},{text(tenant)},1,'linux','Owned upgrade witness',{binary(public)},'active',{now});
INSERT INTO nds_sessions(token_digest,user_id,tenant_id,auth_method,expires_at_ms)
 VALUES({binary(session_digest)},{text(user)},{text(tenant)},'email_otp',{now + 28800000});
INSERT INTO nds_vault_keys(user_id,tenant_id,key_id,nonce,ciphertext)
 VALUES({text(user)},{text(tenant)},{text(key_id)},{binary(envelope_nonce)},{binary(envelope)});
INSERT INTO nds_sync_counters(user_id,tenant_id,server_seq,operation_count,stored_bytes,clock_floor_ms,root_key_id)
 VALUES({text(user)},{text(tenant)},1,1,{cost},{now},{text(key_id)});
INSERT INTO nds_sync_entities(user_id,tenant_id,entity_type,entity_id,revision,request_body)
 VALUES({text(user)},{text(tenant)},'vault_record',{text(entity)},1,{binary(request)});
INSERT INTO nds_sync_operations(user_id,tenant_id,device_id,operation_id,idempotency_key,fingerprint,server_seq,request_body,result_body,status)
 VALUES({text(user)},{text(tenant)},{text(device)},{text(operation_id)},{text(operation_id)},
 {binary(hashlib.sha256(request).digest())},1,{binary(request)},{binary(response)},201);
COMMIT;""")
    return {"rows": snapshot(sql), "wrapping": wrapping, "material": material,
            "envelope_aad": envelope_aad, "record_aad": record_aad, "plaintext": plaintext,
            "user": user, "tenant": tenant, "checks": 0}


def verify(sql, witness):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    current = snapshot(sql, witness["rows"])
    user,tenant=witness["user"],witness["tenant"]
    if int(sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip()) >= 15:
        assert sql(f"SELECT o.is_bootstrap AND o.verified AND m.company_role='admin' AND m.membership_active AND m.member_revision=1 FROM nds_owner o JOIN nds_company_memberships m USING(user_id,tenant_id) WHERE o.user_id='{user}' AND o.tenant_id='{tenant}'").stdout.strip() == "t"
    else:
        assert sql(f"SELECT is_bootstrap AND company_role='admin' AND membership_active AND member_revision=1 FROM nds_owner WHERE user_id='{user}' AND tenant_id='{tenant}'").stdout.strip() == "t"
    assert sql(f"SELECT count(*) FROM nds_companies WHERE tenant_id='{tenant}'").stdout.strip() == "1"
    assert sql("SELECT admission_version=2 AND floor_seq=0 AND base_seq=0 FROM public.nds_replica_counters").stdout.strip() == "t"
    assert sql("SELECT applied_seq=1 FROM public.nds_replica_entities").stdout.strip() == "t"
    assert sql("SELECT wire_version=2 AND base_revision=0 AND applied_revision=1 AND request_bytes=octet_length(request_body) AND result_bytes=octet_length(result_body) FROM public.nds_replica_operations").stdout.strip() == "t"
    for table in TABLES:
        assert current[table] == witness["rows"][table], f"migration changed canonical row bytes: {table}"
    rows = {table: json.loads(data)[0] for table, data in current.items()}
    raw = lambda value: bytes.fromhex(value.removeprefix("\\x"))
    envelope = rows["nds_vault_keys"]
    material = AESGCM(witness["wrapping"]).decrypt(raw(envelope["nonce"]), raw(envelope["ciphertext"]), witness["envelope_aad"])
    assert material == witness["material"] and str(uuid.UUID(bytes=material[:16])) == envelope["key_id"]
    operation = rows["nds_sync_operations"]
    request = raw(operation["request_body"])
    assert request == raw(rows["nds_sync_entities"]["request_body"])
    assert hashlib.sha256(request).digest() == raw(operation["fingerprint"])
    payload = json.loads(request)["payload"]
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    plain = AESGCM(material[16:]).decrypt(decode(payload["nonce"]), decode(payload["ciphertext"]), witness["record_aad"])
    assert plain == witness["plaintext"]
    assert rows["nds_sync_counters"]["server_seq"] == 1 and rows["nds_sync_entities"]["revision"] == 1
    witness["checks"] += 1
    print("Upgrade row witness check passed: " + json.dumps({table: hashlib.sha256(data).hexdigest() for table, data in current.items()}, sort_keys=True))


def check_rejected_history(sql, witness):
    # Execute the owning forward SQL in a transaction on generated schema9
    # rows. Every failed transition must leave the original namespace/data and
    # migration ledger intact; nothing is repaired or discarded automatically.
    root = Path(__file__).resolve().parent.parent / 'migrations'
    screen = (root / '0010_owned_screen.sql').read_text()
    history = (root / '0011_sync_lifecycle.sql').read_text()
    cases = {
        'retained byte counter': 'UPDATE nds_sync_counters SET stored_bytes=stored_bytes+1;',
        'committed sequence gap': 'UPDATE nds_sync_operations SET server_seq=2;',
        'missing owner counter': 'DELETE FROM nds_sync_counters;',
    }
    for name, mutation in cases.items():
        result = sql('BEGIN;\n' + screen + '\n' + mutation + '\n' + history + '\nROLLBACK;',
                     'nds_migrator', check=False)
        assert result.returncode != 0, f'migration accepted inconsistent {name}'
        assert 'retained counter mismatch' in result.stderr, f'unexpected migration rejection: {name}'
        assert snapshot(sql) == witness['rows'], f'failed migration changed original rows: {name}'
        assert sql("SELECT value FROM nddev_schema_meta WHERE key='schema_version'").stdout.strip() == '9'
        assert sql("SELECT count(*) FROM _sqlx_migrations WHERE success").stdout.strip() == '9'
        assert sql("SELECT to_regclass('public.nds_replica_operations') IS NULL").stdout.strip() == 't'
    print('Migration rejection passed: inconsistent byte count, sequence gap and missing counter abort without changing originals or schema.')


def clean(sql, witness):
    assert witness["checks"] == 2, "upgrade witnesses must survive both migration and repeat"
    user, tenant = witness["user"], witness["tenant"]  # Generated canonical UUIDs only.
    if sql("SELECT to_regclass('public.nds_company_memberships') IS NOT NULL").stdout.strip()=="t":
        sql(f"DELETE FROM nds_company_memberships WHERE user_id='{user}'")
    order = ("nds_sync_entities", "nds_sync_operations", "nds_sync_counters",
             "nds_vault_keys", "nds_sessions", "nds_devices", "nds_owner")
    for old in order:
        table = old.replace("nds_sync_", "nds_replica_")
        sql(f"DELETE FROM {table} WHERE user_id='{user}' AND tenant_id='{tenant}'")
    sql(f"DELETE FROM nds_companies WHERE tenant_id='{tenant}'")
    assert all(sql(f"SELECT count(*) FROM {table.replace('nds_sync_', 'nds_replica_')}").stdout.strip() == "0" for table in TABLES)
