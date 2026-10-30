DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='14') THEN
        RAISE EXCEPTION 'independent memberships require schema version 14';
    END IF;
END $$;

-- Every retained owner was established by verified invitation authentication or
-- explicit bootstrap. Leaving its company never relabels or disables that
-- personal identity. New invitation reservations are not eligible accounts.
-- Preserve unobserved old session revocation as an explicit terminal fact.
-- Do not renew a credential that the earlier membership rule already denied.
-- Token digests, owners, original proof times and expiries remain unchanged.
ALTER TABLE nds_sessions ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE nds_sessions s SET revoked=TRUE FROM nds_owner o
    WHERE o.user_id=s.user_id AND o.tenant_id=s.tenant_id AND NOT o.membership_active;

ALTER TABLE nds_owner ADD COLUMN verified BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE nds_owner ALTER COLUMN verified SET DEFAULT FALSE;

CREATE TABLE nds_company_memberships (
    tenant_id TEXT NOT NULL REFERENCES nds_companies(tenant_id),
    user_id TEXT NOT NULL REFERENCES nds_owner(user_id),
    company_role TEXT NOT NULL CHECK(company_role IN ('admin','user')),
    membership_active BOOLEAN NOT NULL,
    member_revision BIGINT NOT NULL CHECK(member_revision BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY(tenant_id,user_id)
);
INSERT INTO nds_company_memberships(tenant_id,user_id,company_role,membership_active,member_revision)
    SELECT tenant_id,user_id,company_role,membership_active,member_revision FROM nds_owner;
CREATE INDEX nds_memberships_principal ON nds_company_memberships(user_id,tenant_id);

-- Personal owner tuples, device proofs, keys, ciphertext/AAD, outboxes, command
-- receipts, challenges and their deadlines remain byte-for-byte unchanged.
-- Only memberships own organization roles; no second writable role authority.
ALTER TABLE nds_owner DROP COLUMN company_role,
    DROP COLUMN membership_active,
    DROP COLUMN member_revision;

-- The old tenant column still identifies the organization. Issuer and recipient
-- retain their original personal storage tuples independently. An unresolved
-- historical reservation is not guessed or rebound to another existing user.
ALTER TABLE nds_company_invitations
    ADD COLUMN issuer_tenant_id TEXT,
    ADD COLUMN recipient_tenant_id TEXT;
UPDATE nds_company_invitations i SET
    issuer_tenant_id=i.tenant_id,
    recipient_tenant_id=COALESCE((SELECT o.tenant_id FROM nds_owner o WHERE o.user_id=i.recipient_user_id),i.tenant_id);
ALTER TABLE nds_company_invitations
    ALTER COLUMN issuer_tenant_id SET NOT NULL,
    ALTER COLUMN recipient_tenant_id SET NOT NULL,
    DROP CONSTRAINT nds_company_invitations_issuer_user_id_tenant_id_fkey,
    ADD FOREIGN KEY(issuer_user_id,issuer_tenant_id) REFERENCES nds_owner(user_id,tenant_id);
ALTER TABLE nds_company_invitations ADD CHECK(length(recipient_tenant_id) BETWEEN 1 AND 128);

GRANT SELECT,INSERT ON nds_company_memberships TO nds_runtime;
GRANT UPDATE(company_role,membership_active,member_revision) ON nds_company_memberships TO nds_runtime;
GRANT UPDATE(verified) ON nds_owner TO nds_runtime;

UPDATE nddev_schema_meta SET value='15',updated_at=NOW() WHERE key='schema_version';
