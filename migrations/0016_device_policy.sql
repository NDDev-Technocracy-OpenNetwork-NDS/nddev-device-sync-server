DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='15') THEN
        RAISE EXCEPTION 'device policy requires schema version 15';
    END IF;
END $$;

-- One authenticated control policy per device (ADR 0018). It is separate from
-- the immutable device identity: ID, owner, key and proof never change here.
CREATE TABLE nds_device_policies (
    device_id TEXT PRIMARY KEY REFERENCES nds_devices(device_id) ON DELETE CASCADE,
    control_mode TEXT NOT NULL CHECK(control_mode IN ('fullauto','manual')),
    purposes TEXT[] NOT NULL CHECK(
        cardinality(purposes) BETWEEN 1 AND 6
        AND array_position(purposes, NULL) IS NULL
        AND purposes <@ ARRAY['server-hosting','server-dev-desktop','server-desktop',
            'build-dev-desktop','dev-desktop','desktop']::TEXT[]
    ),
    policy_revision BIGINT NOT NULL CHECK(policy_revision BETWEEN 1 AND 9007199254740991)
);

-- Devices enrolled before control profiles keep their explicit module
-- checklist: manual never widens existing authority. Revoked rows keep a
-- policy for inspection only. New enrollments insert fullauto/desktop.
INSERT INTO nds_device_policies(device_id,control_mode,purposes,policy_revision)
    SELECT device_id,'manual',ARRAY['desktop']::TEXT[],1 FROM nds_devices;

GRANT SELECT,INSERT ON nds_device_policies TO nds_runtime;
GRANT UPDATE(control_mode,purposes,policy_revision) ON nds_device_policies TO nds_runtime;

UPDATE nddev_schema_meta SET value='16',updated_at=NOW() WHERE key='schema_version';
