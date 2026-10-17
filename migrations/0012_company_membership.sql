-- Preserve established owner/user/device/ciphertext identities. A tenant is now
-- a company; each retained user belongs to exactly one company in this alpha.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='11') THEN
        RAISE EXCEPTION 'company membership requires schema version 11';
    END IF;
END $$;

CREATE TABLE nds_companies (
    tenant_id TEXT PRIMARY KEY CHECK (length(tenant_id) BETWEEN 1 AND 128),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 9007199254740991)
);
INSERT INTO nds_companies(tenant_id, display_name)
    SELECT tenant_id, 'NDS' FROM nds_owner;

ALTER TABLE nds_owner
    ADD COLUMN is_bootstrap BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN company_role TEXT NOT NULL DEFAULT 'user' CHECK (company_role IN ('admin','user')),
    ADD COLUMN membership_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN member_revision BIGINT NOT NULL DEFAULT 1 CHECK (member_revision BETWEEN 1 AND 9007199254740991),
    ADD COLUMN email TEXT CHECK (octet_length(email) BETWEEN 3 AND 254);
UPDATE nds_owner SET is_bootstrap=TRUE, company_role='admin';
ALTER TABLE nds_owner DROP CONSTRAINT nds_owner_pkey;
ALTER TABLE nds_owner DROP COLUMN singleton;
ALTER TABLE nds_owner DROP CONSTRAINT nds_owner_user_id_key;
ALTER TABLE nds_owner ADD PRIMARY KEY(user_id);
ALTER TABLE nds_owner ADD FOREIGN KEY(tenant_id) REFERENCES nds_companies(tenant_id);
CREATE UNIQUE INDEX nds_bootstrap_owner ON nds_owner(is_bootstrap) WHERE is_bootstrap;
CREATE UNIQUE INDEX nds_owner_email_binding ON nds_owner(email_binding);
CREATE UNIQUE INDEX nds_owner_github_binding ON nds_owner(github_id) WHERE github_id IS NOT NULL;
CREATE INDEX nds_owner_company_members ON nds_owner(tenant_id,user_id);
CREATE INDEX nds_sessions_owner_expiry ON nds_sessions(user_id,tenant_id,expires_at_ms);

-- A public device key is never silently reassigned to another user, including
-- after revocation. Existing singleton data already has unique public keys.
CREATE UNIQUE INDEX nds_device_key_owner ON nds_devices(public_key);
ALTER TABLE nds_devices ADD UNIQUE(device_id,user_id,tenant_id);

CREATE TABLE nds_company_invitations (
    invitation_id TEXT PRIMARY KEY CHECK (length(invitation_id)=43),
    tenant_id TEXT NOT NULL REFERENCES nds_companies(tenant_id),
    issuer_user_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL CHECK (length(recipient_user_id) BETWEEN 1 AND 128),
    recipient_email TEXT NOT NULL CHECK (octet_length(recipient_email) BETWEEN 3 AND 254),
    recipient_binding BYTEA NOT NULL CHECK (octet_length(recipient_binding)=32),
    recipient_subject BYTEA NOT NULL CHECK (octet_length(recipient_subject)=32),
    company_role TEXT NOT NULL CHECK (company_role IN ('admin','user')),
    verifier BYTEA NOT NULL CHECK (octet_length(verifier)=32),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms>=0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms>issued_at_ms AND expires_at_ms-issued_at_ms<=604800000),
    status TEXT NOT NULL CHECK (status IN ('pending','accepted','revoked','expired')),
    delivery_state TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','accepted','failed')),
    FOREIGN KEY(issuer_user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id),
    CHECK (recipient_user_id<>issuer_user_id)
);
CREATE UNIQUE INDEX nds_pending_company_recipient ON nds_company_invitations(tenant_id,recipient_binding)
    WHERE status='pending';
CREATE INDEX nds_company_invitation_expiry ON nds_company_invitations(tenant_id,expires_at_ms);

-- The old singleton policy issued every eligible challenge for that one owner.
-- Preserve its verifier, attempts and original expiry while making the proven
-- principal explicit. Unknown eligibility without that owner is not repaired.
ALTER TABLE nds_email_challenges
    ADD COLUMN user_id TEXT,
    ADD COLUMN tenant_id TEXT,
    ADD COLUMN invitation_id TEXT REFERENCES nds_company_invitations(invitation_id),
    ADD FOREIGN KEY(user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id) MATCH FULL;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM nds_email_challenges WHERE eligible)
       AND NOT EXISTS(SELECT 1 FROM nds_owner WHERE is_bootstrap) THEN
        RAISE EXCEPTION 'eligible challenge has no established bootstrap owner';
    END IF;
END $$;
UPDATE nds_email_challenges c SET user_id=o.user_id,tenant_id=o.tenant_id
    FROM nds_owner o WHERE c.eligible AND o.is_bootstrap;
ALTER TABLE nds_email_challenges ADD CHECK (
        (NOT eligible AND user_id IS NULL AND tenant_id IS NULL AND invitation_id IS NULL)
        OR (eligible AND user_id IS NOT NULL AND tenant_id IS NOT NULL AND invitation_id IS NULL)
        OR (eligible AND user_id IS NULL AND tenant_id IS NULL AND invitation_id IS NOT NULL)
    );

GRANT SELECT, INSERT ON nds_companies TO nds_runtime;
GRANT UPDATE(display_name,revision) ON nds_companies TO nds_runtime;
GRANT UPDATE(company_role,membership_active,member_revision,email) ON nds_owner TO nds_runtime;
GRANT SELECT, INSERT, DELETE ON nds_company_invitations TO nds_runtime;
GRANT UPDATE(status,delivery_state) ON nds_company_invitations TO nds_runtime;

UPDATE nddev_schema_meta SET value='12', updated_at=NOW() WHERE key='schema_version';
