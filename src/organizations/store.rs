use crate::identity::{
    crypto::equal,
    store::{self as identity, Tx},
};
use nddev_device_sync_application::identity::{
    EmailAddress, EmailIssue, IdentityError, InvitationId, Owner, ProtectedDigest, TenantId, UserId,
};
use nddev_device_sync_domain::{
    organizations::{
        CompanyRole, MAX_ORGANIZATIONS_PER_PRINCIPAL,
        invitations::{Invitation, InvitationMetadata, InvitationStatus},
    },
    sync::MAX_REVISION,
};
use sqlx::{Acquire, Row, postgres::PgRow};
mod control;
pub use control::Store;

fn unavailable<E>(_: E) -> IdentityError {
    IdentityError::Unavailable
}
fn unsigned(value: i64) -> Result<u64, IdentityError> {
    value.try_into().map_err(unavailable)
}
fn digest(value: Vec<u8>) -> Result<ProtectedDigest, IdentityError> {
    Ok(ProtectedDigest(value.try_into().map_err(unavailable)?))
}
fn role(value: &str) -> Result<CompanyRole, IdentityError> {
    match value {
        "admin" => Ok(CompanyRole::Admin),
        "user" => Ok(CompanyRole::User),
        _ => Err(IdentityError::Unavailable),
    }
}
fn role_text(value: CompanyRole) -> &'static str {
    match value {
        CompanyRole::Admin => "admin",
        CompanyRole::User => "user",
    }
}
fn status_text(value: InvitationStatus) -> &'static str {
    match value {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
        InvitationStatus::Expired => "expired",
    }
}
fn invitation(row: &PgRow) -> Result<Invitation, IdentityError> {
    let tenant = TenantId::new(row.try_get::<String, _>("tenant_id").map_err(unavailable)?)
        .map_err(unavailable)?;
    Invitation::restore(InvitationMetadata {
        id: InvitationId::new(
            row.try_get::<String, _>("invitation_id")
                .map_err(unavailable)?,
        )
        .map_err(unavailable)?,
        company_id: tenant,
        issuer: Owner {
            user_id: UserId::new(
                row.try_get::<String, _>("issuer_user_id")
                    .map_err(unavailable)?,
            )
            .map_err(unavailable)?,
            tenant_id: TenantId::new(
                row.try_get::<String, _>("issuer_tenant_id")
                    .map_err(unavailable)?,
            )
            .map_err(unavailable)?,
        },
        recipient: Owner {
            user_id: UserId::new(
                row.try_get::<String, _>("recipient_user_id")
                    .map_err(unavailable)?,
            )
            .map_err(unavailable)?,
            tenant_id: TenantId::new(
                row.try_get::<String, _>("recipient_tenant_id")
                    .map_err(unavailable)?,
            )
            .map_err(unavailable)?,
        },
        role: role(row.try_get("company_role").map_err(unavailable)?)?,
        issued_at_ms: unsigned(row.try_get("issued_at_ms").map_err(unavailable)?)?,
        expires_at_ms: unsigned(row.try_get("expires_at_ms").map_err(unavailable)?)?,
        status: match row.try_get::<&str, _>("status").map_err(unavailable)? {
            "pending" => InvitationStatus::Pending,
            "accepted" => InvitationStatus::Accepted,
            "revoked" => InvitationStatus::Revoked,
            "expired" => InvitationStatus::Expired,
            _ => return Err(IdentityError::Unavailable),
        },
    })
    .map_err(unavailable)
}
async fn persist_status(tx: &mut Tx<'_>, value: &Invitation) -> Result<(), IdentityError> {
    sqlx::query("UPDATE nds_company_invitations SET status=$2 WHERE invitation_id=$1")
        .bind(value.metadata().id.as_str())
        .bind(status_text(value.metadata().status))
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn recipient_available(
    tx: &mut Tx<'_>,
    binding: &[u8],
    owner: &Owner,
    company: &TenantId,
) -> Result<bool, IdentityError> {
    let current = sqlx::query(
        "SELECT o.user_id,o.tenant_id,COALESCE(m.membership_active,FALSE) AS membership_active FROM nds_owner o LEFT JOIN nds_company_memberships m ON m.user_id=o.user_id AND m.tenant_id=$2 WHERE o.email_binding=$1",
    )
    .bind(binding)
    .bind(company.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    match current {
        None => {
            let collision: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_owner WHERE user_id=$1)")
                    .bind(owner.user_id.as_str())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(unavailable)?;
            Ok(!collision)
        }
        Some(row) => Ok(row.try_get::<String, _>("user_id").map_err(unavailable)?
            == owner.user_id.as_str()
            && row.try_get::<String, _>("tenant_id").map_err(unavailable)?
                == owner.tenant_id.as_str()
            && !row
                .try_get::<bool, _>("membership_active")
                .map_err(unavailable)?),
    }
}

/// Admission uses the same identity transaction as OTP issuance. No membership
/// is created here; a link proves invitation possession, not email possession.
pub(crate) async fn invitation_for_email(
    tx: &mut Tx<'_>,
    issue: &EmailIssue,
    now: u64,
) -> Result<Option<InvitationId>, IdentityError> {
    let Some(proof) = &issue.invitation else {
        return Ok(None);
    };
    let row =
        sqlx::query("SELECT * FROM nds_company_invitations WHERE invitation_id=$1 FOR UPDATE")
            .bind(proof.id.as_str())
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let verified = equal(
        &digest(row.try_get("verifier").map_err(unavailable)?)?,
        &proof.verifier,
    ) & equal(
        &digest(row.try_get("recipient_binding").map_err(unavailable)?)?,
        &issue.owner_binding,
    ) & equal(
        &digest(row.try_get("recipient_subject").map_err(unavailable)?)?,
        &issue.subject,
    );
    if !verified {
        return Ok(None);
    }
    let mut value = invitation(&row)?;
    let issuer =
        identity::membership_in(tx, &value.metadata().issuer, &value.metadata().company_id).await?;
    let recipient = value.metadata().recipient.clone();
    let admitted = value
        .prepare_authentication(&recipient, &issuer, now)
        .is_ok();
    persist_status(tx, &value).await?;
    if !admitted
        || !recipient_available(
            tx,
            &issue.owner_binding.0,
            &recipient,
            &value.metadata().company_id,
        )
        .await?
    {
        return Ok(None);
    }
    Ok(Some(proof.id.clone()))
}

/// Called only after the bound OTP challenge has consumed a correct code.
/// Activation, invitation consumption and session insertion share one transaction.
pub(crate) async fn accept_invitation(
    tx: &mut Tx<'_>,
    id: &str,
    now: u64,
) -> Result<(Owner, TenantId), IdentityError> {
    let row =
        sqlx::query("SELECT * FROM nds_company_invitations WHERE invitation_id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?
            .ok_or(IdentityError::Denied)?;
    let mut value = invitation(&row)?;
    let issuer =
        identity::membership_in(tx, &value.metadata().issuer, &value.metadata().company_id).await?;
    let recipient = value.metadata().recipient.clone();
    if value
        .prepare_authentication(&recipient, &issuer, now)
        .is_err()
    {
        persist_status(tx, &value).await?;
        return Err(IdentityError::Denied);
    }
    let binding: Vec<u8> = row.try_get("recipient_binding").map_err(unavailable)?;
    let company = value.metadata().company_id.clone();
    if !recipient_available(tx, &binding, &recipient, &company).await? {
        return Err(IdentityError::Denied);
    }
    let next = value
        .accept(&recipient, &issuer, now)
        .map_err(|_| IdentityError::Denied)?;
    let email = EmailAddress::parse(
        &row.try_get::<String, _>("recipient_email")
            .map_err(unavailable)?,
    )?;
    // Preserve OTP-attempt consumption on denial, while activation itself is
    // atomic even for a known business failure after an intermediate write.
    let mut savepoint = tx.begin().await.map_err(unavailable)?;
    let result = async {
        let tx = &mut savepoint;
    // Older pending invitations may predate identity reservation. Establish only
    // their exact retained tuple; a conflicting historical reservation refuses.
    sqlx::query("INSERT INTO nds_owner(user_id,tenant_id,email_binding,email,verified) VALUES($1,$2,$3,$4,FALSE) ON CONFLICT DO NOTHING")
        .bind(recipient.user_id.as_str()).bind(recipient.tenant_id.as_str()).bind(&binding).bind(email.as_str())
        .execute(&mut **tx).await.map_err(unavailable)?;
    if !recipient_available(tx, &binding, &recipient, &company).await? { return Err(IdentityError::Denied); }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_company_memberships WHERE tenant_id=$1 AND user_id=$2)")
        .bind(company.as_str()).bind(recipient.user_id.as_str()).fetch_one(&mut **tx).await.map_err(unavailable)?;
    if !exists {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_company_memberships WHERE user_id=$1")
            .bind(recipient.user_id.as_str()).fetch_one(&mut **tx).await.map_err(unavailable)?;
        if count >= MAX_ORGANIZATIONS_PER_PRINCIPAL as i64 { return Err(IdentityError::Capacity); }
    }
    let changed=sqlx::query("INSERT INTO nds_company_memberships(tenant_id,user_id,company_role,membership_active,member_revision) VALUES($1,$2,$3,TRUE,1) ON CONFLICT(tenant_id,user_id) DO UPDATE SET company_role=EXCLUDED.company_role,membership_active=TRUE,member_revision=nds_company_memberships.member_revision+1 WHERE NOT nds_company_memberships.membership_active AND nds_company_memberships.member_revision<$4")
        .bind(company.as_str()).bind(recipient.user_id.as_str()).bind(role_text(next.role)).bind(MAX_REVISION as i64)
        .execute(&mut **tx).await.map_err(unavailable)?;
    if changed.rows_affected() != 1 {
        return Err(IdentityError::Denied);
    }
    // Only the proven invitation plus recipient OTP establishes a reservation.
    // Existing personal sessions/keys are unaffected. The incremented membership
    // revision, not a replacement session, fences earlier organization commands.
    let established = sqlx::query("UPDATE nds_owner SET verified=TRUE WHERE user_id=$1 AND tenant_id=$2 AND email_binding=$3")
        .bind(recipient.user_id.as_str()).bind(recipient.tenant_id.as_str()).bind(&binding).execute(&mut **tx).await.map_err(unavailable)?;
    if established.rows_affected()!=1 { return Err(IdentityError::Denied); }
    persist_status(tx, &value).await?;
    Ok((recipient, company))
    }.await;
    match result {
        Ok(accepted) => {
            savepoint.commit().await.map_err(unavailable)?;
            Ok(accepted)
        }
        Err(error) => {
            savepoint.rollback().await.map_err(unavailable)?;
            Err(error)
        }
    }
}
