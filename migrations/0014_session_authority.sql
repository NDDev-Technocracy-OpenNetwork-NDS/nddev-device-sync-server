DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='13') THEN
        RAISE EXCEPTION 'session authority requires schema version 13';
    END IF;
END $$;

-- Existing sessions were issued for exactly eight hours. Keep their original
-- expiry and recover their original proof time; migration grants no extra time.
ALTER TABLE nds_sessions ADD COLUMN authenticated_at_ms BIGINT;
UPDATE nds_sessions SET authenticated_at_ms=GREATEST(expires_at_ms-28800000,0);
ALTER TABLE nds_sessions ALTER COLUMN authenticated_at_ms SET NOT NULL;
ALTER TABLE nds_sessions ADD CONSTRAINT nds_session_authentication_time
    CHECK(authenticated_at_ms>=0 AND authenticated_at_ms<=expires_at_ms);

-- Runtime can renew an authorized lease, but cannot rewrite the proof time,
-- owner, method or retained credential binding.
GRANT UPDATE(expires_at_ms) ON nds_sessions TO nds_runtime;
UPDATE nddev_schema_meta SET value='14',updated_at=NOW() WHERE key='schema_version';
