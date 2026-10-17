DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='12') THEN
        RAISE EXCEPTION 'company commands require schema version 12';
    END IF;
END $$;

ALTER TABLE nds_company_invitations DROP CONSTRAINT nds_company_invitations_delivery_state_check;
ALTER TABLE nds_company_invitations ADD CHECK(delivery_state IN ('pending','accepted','failed','unknown'));

-- Current authority is checked before every replay. UUIDv7 timestamps bind the
-- request's five-minute deadline independently of receipt retention or retries.
CREATE TABLE nds_company_commands (
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    operation_id UUID NOT NULL CHECK(COALESCE(uuid_extract_version(operation_id),0)=7),
    fingerprint BYTEA NOT NULL CHECK(octet_length(fingerprint)=32),
    status SMALLINT NOT NULL CHECK(status IN (200,201)),
    response BYTEA NOT NULL CHECK(octet_length(response)<=4096),
    expires_at_ms BIGINT NOT NULL CHECK(expires_at_ms>0),
    PRIMARY KEY(user_id,tenant_id,device_id,operation_id),
    FOREIGN KEY(user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id),
    FOREIGN KEY(device_id,user_id,tenant_id) REFERENCES nds_devices(device_id,user_id,tenant_id)
);
CREATE INDEX nds_company_command_expiry ON nds_company_commands(user_id,tenant_id,expires_at_ms);
GRANT SELECT,INSERT,DELETE ON nds_company_commands TO nds_runtime;
UPDATE nddev_schema_meta SET value='13',updated_at=NOW() WHERE key='schema_version';
