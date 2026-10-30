use super::{Store, millis, retained_session};
use nddev_device_sync_application::{
    identity::{AuthenticatedSession, IdentityError, Session, SessionRenewalStore},
    sync::{SignedRequest, SyncError},
};

fn unavailable<E>(_: E) -> SyncError {
    SyncError::Unavailable
}

impl SessionRenewalStore for Store {
    async fn renew_session(
        &self,
        authorization: &AuthenticatedSession,
        signed: &SignedRequest,
        now: u64,
    ) -> Result<(Session, u64), SyncError> {
        tokio::time::timeout(crate::database::DATABASE_TIMEOUT, async {
            let mut tx = self.transaction().await.map_err(unavailable)?;
            let result = async {
                let now = now.max(crate::identity::now_ms().map_err(unavailable)?);
                let now = crate::sync::store::authorize(&mut tx, authorization, signed, now).await?;
                let row = sqlx::query(
                    "SELECT user_id,tenant_id,auth_method,authenticated_at_ms,expires_at_ms \
                     FROM nds_sessions WHERE token_digest=$1 AND user_id=$2 AND tenant_id=$3 AND NOT revoked FOR UPDATE",
                )
                .bind(authorization.binding.0.as_slice())
                .bind(authorization.session.owner.user_id.as_str())
                .bind(authorization.session.owner.tenant_id.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?
                .ok_or(SyncError::Denied)?;
                let session = retained_session(&row).map_err(unavailable)?;
                if session.authenticated_at_ms != authorization.session.authenticated_at_ms
                    || session.method != authorization.session.method
                {
                    return Err(SyncError::Denied);
                }
                let renewed = session.renewed(now).map_err(|error| match error {
                    IdentityError::Denied => SyncError::Denied,
                    _ => SyncError::Unavailable,
                })?;
                let updated = sqlx::query(
                    "UPDATE nds_sessions SET expires_at_ms=$2 WHERE token_digest=$1 AND user_id=$3 AND tenant_id=$4 AND NOT revoked",
                )
                .bind(authorization.binding.0.as_slice())
                .bind(millis(renewed.expires_at_ms).map_err(unavailable)?)
                .bind(renewed.owner.user_id.as_str())
                .bind(renewed.owner.tenant_id.as_str())
                .execute(&mut *tx)
                .await
                .map_err(unavailable)?;
                if updated.rows_affected() != 1 {
                    return Err(SyncError::Denied);
                }
                Ok((renewed, now))
            }
            .await;
            crate::sync::store::finish(tx, result).await
        })
        .await
        .map_err(unavailable)?
    }
}
