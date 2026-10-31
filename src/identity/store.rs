use super::crypto::equal;
use nddev_device_sync_application::identity::*;
use nddev_device_sync_domain::organizations::{CompanyRole, Membership};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::future::Future;

mod renewal;

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}
pub(crate) type Tx<'a> = Transaction<'a, Postgres>;
fn unavailable<E>(_: E) -> IdentityError {
    IdentityError::Unavailable
}
fn millis(value: u64) -> Result<i64, IdentityError> {
    value.try_into().map_err(|_| IdentityError::InvalidInput)
}
fn unsigned(value: i64) -> Result<u64, IdentityError> {
    value.try_into().map_err(unavailable)
}
fn digest(value: Vec<u8>) -> Result<ProtectedDigest, IdentityError> {
    Ok(ProtectedDigest(value.try_into().map_err(unavailable)?))
}

fn retained_session(row: &sqlx::postgres::PgRow) -> Result<Session, IdentityError> {
    Ok(Session {
        owner: Owner {
            user_id: UserId::new(row.try_get::<String, _>("user_id").map_err(unavailable)?)
                .map_err(unavailable)?,
            tenant_id: TenantId::new(row.try_get::<String, _>("tenant_id").map_err(unavailable)?)
                .map_err(unavailable)?,
        },
        method: match row.try_get::<&str, _>("auth_method").map_err(unavailable)? {
            "email_otp" => AuthMethod::EmailOtp,
            "github" => AuthMethod::Github,
            "passkey" => AuthMethod::Passkey,
            _ => return Err(IdentityError::Unavailable),
        },
        authenticated_at_ms: unsigned(row.try_get("authenticated_at_ms").map_err(unavailable)?)?,
        expires_at_ms: unsigned(row.try_get("expires_at_ms").map_err(unavailable)?)?,
    })
}

/// Reuse the owner's existing authorization clock. A server clock rollback
/// cannot restore an already observed expiry or make an old sign-in recent.
pub(crate) async fn authorization_clock(
    tx: &mut Tx<'_>,
    owner: &Owner,
    now: u64,
) -> Result<u64, IdentityError> {
    let floor: Option<i64> = sqlx::query_scalar(
        "SELECT clock_floor_ms FROM nds_replica_counters WHERE user_id=$1 AND tenant_id=$2",
    )
    .bind(owner.user_id.as_str())
    .bind(owner.tenant_id.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(now.max(floor.map(unsigned).transpose()?.unwrap_or(0)))
}

pub(crate) async fn bounded<T>(
    work: impl Future<Output = Result<T, IdentityError>>,
) -> Result<T, IdentityError> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(unavailable)?
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub(crate) async fn transaction(&self) -> Result<Tx<'_>, IdentityError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Identity mutations are serialized across processes. Preserve this
        // capacity/rate/consume boundary while qualifying company membership.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(0x4e44533241555448_i64)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        Ok(tx)
    }
    pub async fn bootstrap(
        &self,
        address: &EmailAddress,
        email: ProtectedDigest,
        github_id: Option<u64>,
    ) -> Result<Owner, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_owner WHERE is_bootstrap)").fetch_one(&mut *tx).await.map_err(unavailable)?;
            if !exists {
                let tenant = uuid::Uuid::new_v4().to_string();
                sqlx::query("INSERT INTO nds_companies(tenant_id,display_name) VALUES($1,'NDS')").bind(&tenant).execute(&mut *tx).await.map_err(unavailable)?;
                sqlx::query("INSERT INTO nds_owner(user_id,tenant_id,email_binding,github_id,is_bootstrap,verified,email) VALUES($1,$2,$3,$4,TRUE,TRUE,$5)")
                    .bind(uuid::Uuid::new_v4().to_string()).bind(&tenant).bind(email.0.as_slice()).bind(github_id.map(millis).transpose()?).bind(address.as_str()).execute(&mut *tx).await.map_err(unavailable)?;
                sqlx::query("INSERT INTO nds_company_memberships(tenant_id,user_id,company_role,membership_active,member_revision) SELECT tenant_id,user_id,'admin',TRUE,1 FROM nds_owner WHERE is_bootstrap").execute(&mut *tx).await.map_err(unavailable)?;
            }
            let row = sqlx::query("SELECT user_id,tenant_id,email_binding,github_id,email FROM nds_owner WHERE is_bootstrap").fetch_one(&mut *tx).await.map_err(unavailable)?;
            let stored_github: Option<i64> = row.try_get("github_id").map_err(unavailable)?;
            if !equal(&digest(row.try_get("email_binding").map_err(unavailable)?)?, &email) || stored_github.map(unsigned).transpose()? != github_id { return Err(IdentityError::Denied); }
            let stored_email: Option<String> = row.try_get("email").map_err(unavailable)?;
            if stored_email.as_deref().is_some_and(|value| value!=address.as_str()) { return Err(IdentityError::Denied); }
            sqlx::query("UPDATE nds_owner SET email=$1 WHERE is_bootstrap AND email IS NULL").bind(address.as_str()).execute(&mut *tx).await.map_err(unavailable)?;
            let owner = Owner { user_id: UserId::new(row.try_get::<String,_>("user_id").map_err(unavailable)?).map_err(unavailable)?, tenant_id: TenantId::new(row.try_get::<String,_>("tenant_id").map_err(unavailable)?).map_err(unavailable)? };
            tx.commit().await.map_err(unavailable)?;
            Ok(owner)
        }).await
    }
}

pub(crate) async fn membership(
    tx: &mut Tx<'_>,
    owner: &Owner,
) -> Result<Membership, IdentityError> {
    membership_in(tx, owner, &owner.tenant_id).await
}

pub(crate) async fn membership_in(
    tx: &mut Tx<'_>,
    owner: &Owner,
    company: &TenantId,
) -> Result<Membership, IdentityError> {
    let row = sqlx::query(
        "SELECT m.company_role,m.membership_active FROM nds_company_memberships m JOIN nds_owner o USING(user_id) WHERE m.user_id=$1 AND o.tenant_id=$2 AND m.tenant_id=$3 AND o.verified",
    )
    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(company.as_str())
    .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(IdentityError::Denied)?;
    Ok(Membership {
        owner: owner.clone(),
        company_id: company.clone(),
        role: match row
            .try_get::<&str, _>("company_role")
            .map_err(unavailable)?
        {
            "admin" => CompanyRole::Admin,
            "user" => CompanyRole::User,
            _ => return Err(IdentityError::Unavailable),
        },
        active: row.try_get("membership_active").map_err(unavailable)?,
    })
}

/// An established personal session survives an organization membership change.
/// Organization/remote-screen administration checks current membership separately.
pub(crate) async fn session_expiry(
    tx: &mut Tx<'_>,
    owner: &Owner,
    token: ProtectedDigest,
) -> Result<Option<i64>, IdentityError> {
    sqlx::query_scalar("SELECT s.expires_at_ms FROM nds_sessions s JOIN nds_owner o USING(user_id,tenant_id) WHERE s.token_digest=$1 AND s.user_id=$2 AND s.tenant_id=$3 AND o.verified AND NOT s.revoked")
        .bind(token.0.as_slice()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut **tx).await.map_err(unavailable)
}

pub(crate) async fn clean(tx: &mut Tx<'_>, now: u64) -> Result<(), IdentityError> {
    let now = millis(now)?;
    sqlx::query("DELETE FROM nds_auth_limits WHERE ends_at_ms <= $1")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("DELETE FROM nds_email_challenges WHERE expires_at_ms <= $1")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("DELETE FROM nds_sessions WHERE expires_at_ms <= $1 OR revoked")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn rate(
    tx: &mut Tx<'_>,
    key: ProtectedDigest,
    policy: RatePolicy,
    now: u64,
) -> Result<(), IdentityError> {
    let row = sqlx::query("SELECT count,ends_at_ms FROM nds_auth_limits WHERE key=$1 FOR UPDATE")
        .bind(key.0.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
    let mut window = match row {
        Some(row) => RateWindow {
            count: row
                .try_get::<i32, _>("count")
                .map_err(unavailable)?
                .try_into()
                .map_err(unavailable)?,
            ends_at_ms: unsigned(row.try_get("ends_at_ms").map_err(unavailable)?)?,
        },
        None => {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_auth_limits")
                .fetch_one(&mut **tx)
                .await
                .map_err(unavailable)?;
            if count as usize >= MAX_RATE_KEYS {
                return Err(IdentityError::Capacity);
            }
            RateWindow::default()
        }
    };
    window.admit(now, policy)?;
    sqlx::query("INSERT INTO nds_auth_limits(key,count,ends_at_ms) VALUES ($1,$2,$3) ON CONFLICT(key) DO UPDATE SET count=EXCLUDED.count,ends_at_ms=EXCLUDED.ends_at_ms")
        .bind(key.0.as_slice()).bind(window.count as i32).bind(millis(window.ends_at_ms)?).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn insert_session(
    tx: &mut Tx<'_>,
    issue: SessionIssue,
    passkey: Option<&[u8]>,
) -> Result<Session, IdentityError> {
    let owner = &issue.session.owner;
    let established: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM nds_owner WHERE user_id=$1 AND tenant_id=$2 AND verified)",
    )
    .bind(owner.user_id.as_str())
    .bind(owner.tenant_id.as_str())
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    if !established {
        return Err(IdentityError::Denied);
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM nds_sessions WHERE user_id=$1 AND tenant_id=$2")
            .bind(owner.user_id.as_str())
            .bind(owner.tenant_id.as_str())
            .fetch_one(&mut **tx)
            .await
            .map_err(unavailable)?;
    if count as usize >= MAX_SESSIONS {
        return Err(IdentityError::Capacity);
    }
    sqlx::query("INSERT INTO nds_sessions(token_digest,user_id,tenant_id,auth_method,expires_at_ms,passkey_credential_id,authenticated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(issue.digest.0.as_slice()).bind(issue.session.owner.user_id.as_str()).bind(issue.session.owner.tenant_id.as_str())
        .bind(match issue.session.method { AuthMethod::EmailOtp => "email_otp", AuthMethod::Github => "github", AuthMethod::Passkey => "passkey" }).bind(millis(issue.session.expires_at_ms)?).bind(passkey).bind(millis(issue.session.authenticated_at_ms)?).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(issue.session)
}

impl IdentityStore for Store {
    async fn issue_email(&self, issue: EmailIssue) -> Result<bool, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            let now = issue.created_at_ms;
            clean(&mut tx, now).await?;
            rate(&mut tx, issue.source, START_RATE, now).await?;
            // A suppressed resend returns the same generic receipt. Its source
            // budget still commits so repeated suppressed requests remain bounded.
            let newest: Option<i64> = sqlx::query_scalar("SELECT max(created_at_ms) FROM nds_email_challenges WHERE subject=$1")
                .bind(issue.subject.0.as_slice()).fetch_one(&mut *tx).await.map_err(unavailable)?;
            if newest.is_some_and(|created| now.saturating_sub(created as u64) < OTP_RESEND_MS) {
                tx.commit().await.map_err(unavailable)?;
                return Ok(false);
            }
            let admitted = rate(&mut tx, issue.subject, SUBJECT_RATE, now).await;
            if let Err(IdentityError::RateLimited) = admitted {
                tx.commit().await.map_err(unavailable)?;
                return Ok(false);
            }
            admitted?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_email_challenges").fetch_one(&mut *tx).await.map_err(unavailable)?;
            if count as usize >= MAX_PENDING_EMAIL { return Err(IdentityError::Capacity); }
            let principal = if issue.invitation.is_none() {
                sqlx::query("SELECT user_id,tenant_id FROM nds_owner WHERE email_binding=$1 AND verified")
                    .bind(issue.owner_binding.0.as_slice()).fetch_optional(&mut *tx).await.map_err(unavailable)?
            } else { None };
            let invitation = crate::organizations::store::invitation_for_email(&mut tx,&issue,now).await?;
            let eligible = principal.is_some() || invitation.is_some();
            let user: Option<String> = principal.as_ref().map(|row|row.try_get("user_id")).transpose().map_err(unavailable)?;
            let tenant: Option<String> = principal.as_ref().map(|row|row.try_get("tenant_id")).transpose().map_err(unavailable)?;
            sqlx::query("DELETE FROM nds_email_challenges WHERE subject=$1").bind(issue.subject.0.as_slice()).execute(&mut *tx).await.map_err(unavailable)?;
            sqlx::query("INSERT INTO nds_email_challenges(challenge_id,subject,verifier,created_at_ms,expires_at_ms,attempts_remaining,eligible,consumed,user_id,tenant_id,invitation_id) VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE,$8,$9,$10)")
                .bind(&issue.id).bind(issue.subject.0.as_slice()).bind(issue.verifier.0.as_slice()).bind(millis(now)?).bind(millis(issue.challenge.expires_at_ms)?)
                .bind(issue.challenge.attempts_remaining as i16).bind(eligible).bind(user).bind(tenant).bind(invitation.as_ref().map(InvitationId::as_str)).execute(&mut *tx).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)?;
            Ok(eligible)
        }).await
    }
    async fn invalidate_email(&self, id: &str) -> Result<(), IdentityError> {
        bounded(async {
            sqlx::query("UPDATE nds_email_challenges SET consumed=TRUE WHERE challenge_id=$1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(unavailable)?;
            Ok(())
        })
        .await
    }
    async fn consume_email(
        &self,
        id: &str,
        verifier: ProtectedDigest,
        source: ProtectedDigest,
        issue: SessionSeed,
        now: u64,
    ) -> Result<Session, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            clean(&mut tx, now).await?;
            rate(&mut tx, source, VERIFY_RATE, now).await?;
            let row = sqlx::query("SELECT verifier,expires_at_ms,attempts_remaining,eligible,consumed,user_id,tenant_id,invitation_id FROM nds_email_challenges WHERE challenge_id=$1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await.map_err(unavailable)?;
            let Some(row) = row else { tx.commit().await.map_err(unavailable)?; return Err(IdentityError::Denied); };
            let mut challenge = OtpChallenge { expires_at_ms: unsigned(row.try_get("expires_at_ms").map_err(unavailable)?)?, attempts_remaining: row.try_get::<i16,_>("attempts_remaining").map_err(unavailable)?.try_into().map_err(unavailable)?, eligible: row.try_get("eligible").map_err(unavailable)?, consumed: row.try_get("consumed").map_err(unavailable)? };
            let matches = equal(&digest(row.try_get("verifier").map_err(unavailable)?)?, &verifier);
            let accepted = challenge.consume(now, matches);
            sqlx::query("UPDATE nds_email_challenges SET attempts_remaining=$2,consumed=$3 WHERE challenge_id=$1").bind(id).bind(challenge.attempts_remaining as i16).bind(challenge.consumed).execute(&mut *tx).await.map_err(unavailable)?;
            let invitation: Option<String> = row.try_get("invitation_id").map_err(unavailable)?;
            let mut invitation_company = None;
            let outcome = match accepted {
                Ok(()) => {
                    let owner = if let Some(invitation) = &invitation {
                        match crate::organizations::store::accept_invitation(&mut tx,invitation,now).await {
                            Ok((owner,company)) => { invitation_company=Some(company); Ok(owner) },
                            Err(error) => Err(error),
                        }
                    } else {
                        Ok(Owner {
                            user_id: UserId::new(row.try_get::<String,_>("user_id").map_err(unavailable)?).map_err(unavailable)?,
                            tenant_id: TenantId::new(row.try_get::<String,_>("tenant_id").map_err(unavailable)?).map_err(unavailable)?,
                        })
                    };
                    match owner {
                        Ok(owner)=>insert_session(&mut tx, issue.issue(owner,AuthMethod::EmailOtp)?, None).await,
                        Err(error)=>Err(error),
                    }
                },
                Err(error)=>Err(error),
            };
            // Denied verification commits attempts. Capacity failure rolls back
            // the entire consumption, allowing correct reauthentication later.
            if matches!(outcome, Err(IdentityError::Capacity | IdentityError::Unavailable)) { return outcome; }
            tx.commit().await.map_err(unavailable)?;
            if let (Some(invitation),Some(company),Ok(session))=(&invitation,&invitation_company,&outcome) {
                tracing::info!(module="organizations",scope="database",event.name="company.invitation.accepted",outcome="ok",invitation.id=invitation.as_str(),user.id=session.owner.user_id.as_str(),tenant.id=company.as_str());
            }
            outcome
        }).await
    }
    async fn github_owner(
        &self,
        provider_id: u64,
        _now: u64,
    ) -> Result<Option<Owner>, IdentityError> {
        bounded(async {
            let row = sqlx::query(
                "SELECT user_id,tenant_id FROM nds_owner WHERE github_id=$1 AND verified",
            )
            .bind(millis(provider_id)?)
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?;
            row.map(|row| {
                Ok(Owner {
                    user_id: UserId::new(row.try_get::<String, _>("user_id").map_err(unavailable)?)
                        .map_err(unavailable)?,
                    tenant_id: TenantId::new(
                        row.try_get::<String, _>("tenant_id").map_err(unavailable)?,
                    )
                    .map_err(unavailable)?,
                })
            })
            .transpose()
        })
        .await
    }
    async fn create_github_session(
        &self,
        identity: VerifiedGithubIdentity,
        issue: SessionSeed,
        now: u64,
    ) -> Result<Session, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            clean(&mut tx, now).await?;
            let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_owner WHERE user_id=$1 AND tenant_id=$2 AND github_id=$3 AND verified)")
                .bind(identity.owner.user_id.as_str()).bind(identity.owner.tenant_id.as_str()).bind(millis(identity.provider_id)?).fetch_one(&mut *tx).await.map_err(unavailable)?;
            if !current { return Err(IdentityError::Denied); }
            let session = insert_session(&mut tx, issue.issue(identity.owner,AuthMethod::Github)?, None).await?;
            tx.commit().await.map_err(unavailable)?;
            Ok(session)
        })
        .await
    }
    async fn session(&self, token: ProtectedDigest, now: u64) -> Result<Session, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            // Observed expiry or loss of the established personal account is
            // terminal. Organization changes do not replace personal sessions.
            sqlx::query("DELETE FROM nds_sessions s WHERE token_digest=$1 AND (revoked OR expires_at_ms <= GREATEST($2,COALESCE((SELECT clock_floor_ms FROM nds_replica_counters c WHERE c.user_id=s.user_id AND c.tenant_id=s.tenant_id),0)) OR NOT EXISTS(SELECT 1 FROM nds_owner o WHERE o.user_id=s.user_id AND o.tenant_id=s.tenant_id AND o.verified))").bind(token.0.as_slice()).bind(millis(now)?).execute(&mut *tx).await.map_err(unavailable)?;
            let row = sqlx::query("SELECT s.user_id,s.tenant_id,s.auth_method,s.authenticated_at_ms,s.expires_at_ms FROM nds_sessions s JOIN nds_owner o USING(user_id,tenant_id) LEFT JOIN nds_replica_counters c USING(user_id,tenant_id) WHERE s.token_digest=$1 AND s.expires_at_ms > GREATEST($2,COALESCE(c.clock_floor_ms,0)) AND o.verified AND NOT s.revoked").bind(token.0.as_slice()).bind(millis(now)?).fetch_optional(&mut *tx).await.map_err(unavailable)?;
            // Denial must not roll back the observed-expiry deletion.
            tx.commit().await.map_err(unavailable)?;
            let row = row.ok_or(IdentityError::Denied)?;
            retained_session(&row)
        }).await
    }
    async fn revoke(&self, token: ProtectedDigest, now: u64) -> Result<(), IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            let expiry: Option<i64> = sqlx::query_scalar(
                "DELETE FROM nds_sessions WHERE token_digest=$1 RETURNING expires_at_ms",
            )
            .bind(token.0.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
            crate::screen::store::retire_session(&mut tx, token.0.as_slice())
                .await
                .map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)?;
            if expiry
                .map(unsigned)
                .transpose()?
                .is_some_and(|expiry| now < expiry)
            {
                Ok(())
            } else {
                Err(IdentityError::Denied)
            }
        })
        .await
    }
    async fn admit_source(
        &self,
        source: ProtectedDigest,
        policy: RatePolicy,
        now: u64,
    ) -> Result<(), IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            clean(&mut tx, now).await?;
            rate(&mut tx, source, policy, now).await?;
            tx.commit().await.map_err(unavailable)?;
            Ok(())
        })
        .await
    }
}
