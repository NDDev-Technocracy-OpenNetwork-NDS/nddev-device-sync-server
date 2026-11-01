DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='16') THEN
        RAISE EXCEPTION 'global diagnostic grants require schema version 16';
    END IF;
END $$;

-- One-time challenges for the global diagnostic administrator key (P2). A challenge
-- is bound to the signed session binding and device that asked for it, lives two
-- minutes and is deleted when a proof spends it, valid or not.
CREATE TABLE nds_global_diagnostic_challenges (
    challenge TEXT PRIMARY KEY CHECK(challenge ~ '^[A-Za-z0-9_-]{43}$'),
    session_binding BYTEA NOT NULL CHECK(length(session_binding)=32),
    device_id TEXT NOT NULL CHECK(length(device_id) BETWEEN 1 AND 128),
    user_id TEXT NOT NULL CHECK(length(user_id) BETWEEN 1 AND 128),
    expires_at_ms BIGINT NOT NULL CHECK(expires_at_ms > 0)
);
CREATE INDEX nds_global_diagnostic_challenges_holder
    ON nds_global_diagnostic_challenges(session_binding,device_id);

-- Global diagnostic access of one session and device until expiry. Not a bearer
-- token: every search re-proves the session and device signature, and the grant
-- ends early when its key fingerprint leaves the server's allowed key file.
CREATE TABLE nds_global_diagnostic_grants (
    session_binding BYTEA NOT NULL CHECK(length(session_binding)=32),
    device_id TEXT NOT NULL CHECK(length(device_id) BETWEEN 1 AND 128),
    user_id TEXT NOT NULL CHECK(length(user_id) BETWEEN 1 AND 128),
    key_fingerprint TEXT NOT NULL CHECK(key_fingerprint ~ '^SHA256:[A-Za-z0-9+/]{43}$'),
    granted_at_ms BIGINT NOT NULL CHECK(granted_at_ms > 0),
    expires_at_ms BIGINT NOT NULL CHECK(expires_at_ms > granted_at_ms),
    PRIMARY KEY(session_binding,device_id)
);

GRANT SELECT,INSERT,DELETE ON nds_global_diagnostic_challenges TO nds_runtime;
GRANT SELECT,INSERT,DELETE ON nds_global_diagnostic_grants TO nds_runtime;
GRANT UPDATE(user_id,key_fingerprint,granted_at_ms,expires_at_ms) ON nds_global_diagnostic_grants TO nds_runtime;

UPDATE nddev_schema_meta SET value='17',updated_at=NOW() WHERE key='schema_version';
