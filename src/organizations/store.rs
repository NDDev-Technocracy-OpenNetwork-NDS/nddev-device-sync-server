use crate::identity::{
    crypto::equal,
    store::{self as identity, Tx},
};
use nddev_device_sync_application::identity::{
    EmailAddress, EmailIssue, IdentityError, InvitationId, Owner, ProtectedDigest, TenantId, UserId,
};
use nddev_device_sync_domain::{
    organizations::{
        CompanyRole,
        invitations::{Invitation, InvitationMetadata, InvitationStatus},
    },
    sync::MAX_REVISION,
};
use sqlx::{Row, postgres::PgRow};
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
        issuer: Owner {
            user_id: UserId::new(
                row.try_get::<String, _>("issuer_user_id")
                    .map_err(unavailable)?,
            )
            .map_err(unavailable)?,
            tenant_id: tenant.clone(),
        },
        recipient: Owner {
            user_id: UserId::new(
                row.try_get::<String, _>("recipient_user_id")
                    .map_err(unavailable)?,
            )
            .map_err(unavailable)?,
            tenant_id: tenant,
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
) -> Result<bool, IdentityError> {
    let current = sqlx::query(
        "SELECT user_id,tenant_id,membership_active FROM nds_owner WHERE email_binding=$1",
    )
    .bind(binding)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    match current {
        None => Ok(true),
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
    let issuer = identity::membership(tx, &value.metadata().issuer).await?;
    let recipient = value.metadata().recipient.clone();
    let admitted = value
        .prepare_authentication(&recipient, &issuer, now)
        .is_ok();
    persist_status(tx, &value).await?;
    if !admitted || !recipient_available(tx, &issue.owner_binding.0, &recipient).await? {
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
) -> Result<Owner, IdentityError> {
    let row =
        sqlx::query("SELECT * FROM nds_company_invitations WHERE invitation_id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?
            .ok_or(IdentityError::Denied)?;
    let mut value = invitation(&row)?;
    let issuer = identity::membership(tx, &value.metadata().issuer).await?;
    let recipient = value.metadata().recipient.clone();
    if value
        .prepare_authentication(&recipient, &issuer, now)
        .is_err()
    {
        persist_status(tx, &value).await?;
        return Err(IdentityError::Denied);
    }
    let binding: Vec<u8> = row.try_get("recipient_binding").map_err(unavailable)?;
    if !recipient_available(tx, &binding, &recipient).await? {
        return Err(IdentityError::Denied);
    }
    let next = value
        .accept(&recipient, &issuer, now)
        .map_err(|_| IdentityError::Denied)?;
    let email = EmailAddress::parse(
        &row.try_get::<String, _>("recipient_email")
            .map_err(unavailable)?,
    )?;
    let changed=sqlx::query("INSERT INTO nds_owner(user_id,tenant_id,email_binding,email,company_role,membership_active) VALUES($1,$2,$3,$4,$5,TRUE) ON CONFLICT(user_id) DO UPDATE SET company_role=EXCLUDED.company_role,membership_active=TRUE,member_revision=nds_owner.member_revision+1 WHERE nds_owner.tenant_id=EXCLUDED.tenant_id AND nds_owner.email_binding=EXCLUDED.email_binding AND NOT nds_owner.membership_active AND nds_owner.member_revision<$6")
        .bind(recipient.user_id.as_str()).bind(recipient.tenant_id.as_str()).bind(&binding).bind(email.as_str()).bind(role_text(next.role)).bind(MAX_REVISION as i64)
        .execute(&mut **tx).await.map_err(unavailable)?;
    if changed.rows_affected() != 1 {
        return Err(IdentityError::Denied);
    }
    // Reactivation preserves the user's data/key identity, never old authority.
    // A session that was not presented while membership was inactive must not
    // become valid again after accepting a new invitation.
    let sessions: Vec<Vec<u8>> = sqlx::query_scalar(
        "DELETE FROM nds_sessions WHERE user_id=$1 AND tenant_id=$2 RETURNING token_digest",
    )
    .bind(recipient.user_id.as_str())
    .bind(recipient.tenant_id.as_str())
    .fetch_all(&mut **tx)
    .await
    .map_err(unavailable)?;
    for session in sessions {
        crate::screen::store::retire_session(tx, &session)
            .await
            .map_err(unavailable)?;
    }
    persist_status(tx, &value).await?;
    Ok(recipient)
}
