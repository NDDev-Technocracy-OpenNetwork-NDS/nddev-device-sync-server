use crate::identity::store::bounded;
use nddev_device_sync_application::identity::*;
use sqlx::Row;
use webauthn_rs::prelude::Passkey;

#[derive(Clone)]
pub struct Store(pub sqlx::PgPool);
fn unavailable<E>(_: E) -> IdentityError {
    IdentityError::Unavailable
}
impl Store {
    pub async fn owner(&self, email: Option<ProtectedDigest>) -> Result<Owner, IdentityError> {
        bounded(async {
            // Existing single-account clients may omit a selector. Ambiguity
            // must never select the bootstrap/first user in a company instance.
            let rows = sqlx::query("SELECT user_id,tenant_id FROM nds_owner WHERE membership_active AND ($1::bytea IS NULL OR email_binding=$1) ORDER BY user_id LIMIT 2")
                .bind(email.as_ref().map(|value| value.0.as_slice()))
                .fetch_all(&self.0)
                .await
                .map_err(unavailable)?;
            if rows.len() != 1 { return Err(IdentityError::Denied); }
            let row = &rows[0];
            Ok(Owner {
                user_id: UserId::new(row.try_get::<String, _>("user_id").map_err(unavailable)?)
                    .map_err(unavailable)?,
                tenant_id: TenantId::new(
                    row.try_get::<String, _>("tenant_id").map_err(unavailable)?,
                )
                .map_err(unavailable)?,
            })
        })
        .await
    }
    pub async fn available(&self) -> Result<bool, IdentityError> {
        bounded(async {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_passkeys p JOIN nds_owner o USING(user_id,tenant_id) WHERE o.membership_active)")
                .fetch_one(&self.0).await.map_err(unavailable)
        }).await
    }
    pub async fn credentials(&self, owner: &Owner) -> Result<Vec<Passkey>, IdentityError> {
        bounded(async {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT credential FROM nds_passkeys WHERE user_id=$1 AND tenant_id=$2 ORDER BY credential_id LIMIT 17")
            .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_all(&self.0).await.map_err(unavailable)?;
        if rows.len() > 16 {
            return Err(IdentityError::Capacity);
        }
        rows.into_iter()
            .map(|value| serde_json::from_value(value).map_err(unavailable))
            .collect()

        }).await
    }
    pub async fn list(
        &self,
        auth: &AuthenticatedSession,
    ) -> Result<Vec<(String, u64)>, IdentityError> {
        bounded(async {
            let identity = crate::identity::store::Store::new(self.0.clone());
            let mut tx = identity.transaction().await?;
            active_session(&mut tx, auth, crate::identity::now_ms()?).await?;
            let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as("SELECT credential_id,created_at_ms FROM nds_passkeys WHERE user_id=$1 AND tenant_id=$2 ORDER BY created_at_ms,credential_id LIMIT 17")
                .bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str()).fetch_all(&mut *tx).await.map_err(unavailable)?;
            if rows.len() > 16 { return Err(IdentityError::Capacity); }
            tx.commit().await.map_err(unavailable)?;
            rows.into_iter().map(|(id, created)| Ok((fingerprint(&id), u64::try_from(created).map_err(unavailable)?))).collect()
        }).await
    }
    pub async fn revoke(
        &self,
        auth: &AuthenticatedSession,
        id: &str,
        now: u64,
    ) -> Result<(bool, bool), IdentityError> {
        bounded(async {
            let identity = crate::identity::store::Store::new(self.0.clone());
            let mut tx = identity.transaction().await?;
            let now = now.max(crate::identity::now_ms()?);
            let now = active_session(&mut tx, auth, now).await?;
            let current: Option<(Option<Vec<u8>>, String)> = sqlx::query_as("SELECT passkey_credential_id,auth_method FROM nds_sessions WHERE token_digest=$1 AND user_id=$2 AND tenant_id=$3 AND expires_at_ms>$4")
                .bind(auth.binding.0.as_slice()).bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str()).bind(i64::try_from(now).map_err(unavailable)?)
                .fetch_optional(&mut *tx).await.map_err(unavailable)?;
            let (credential, method) = current.ok_or(IdentityError::Denied)?;
            if !auth.session.recently_authenticated(now) { return Err(IdentityError::RecentAuthenticationRequired); }
            let keys: Vec<Vec<u8>> = sqlx::query_scalar("SELECT credential_id FROM nds_passkeys WHERE user_id=$1 AND tenant_id=$2 LIMIT 17")
                .bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str()).fetch_all(&mut *tx).await.map_err(unavailable)?;
            if keys.len() > 16 { return Err(IdentityError::Capacity); }
            let available_before = !keys.is_empty();
            let available_after = keys.len() > 1;
            let Some(key) = keys.into_iter().find(|key| fingerprint(key) == id) else { tx.commit().await.map_err(unavailable)?; return Ok((false, available_before)); };
            let revoked = credential.as_ref() == Some(&key) || method == "passkey" && credential.is_none();
            // Pre-schema8 sessions have no proven credential link. Do not leave
            // them usable after the owner explicitly removes a passkey.
            sqlx::query("DELETE FROM nds_sessions WHERE user_id=$1 AND tenant_id=$2 AND auth_method='passkey' AND passkey_credential_id IS NULL")
                .bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str()).execute(&mut *tx).await.map_err(unavailable)?;
            sqlx::query("DELETE FROM nds_passkeys WHERE credential_id=$1 AND user_id=$2 AND tenant_id=$3")
                .bind(key).bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str()).execute(&mut *tx).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)?;
            Ok((revoked, available_after))
        }).await
    }
    pub async fn register(
        &self,
        auth: &AuthenticatedSession,
        key: Passkey,
        now: u64,
    ) -> Result<(), IdentityError> {
        bounded(async {
        let identity = crate::identity::store::Store::new(self.0.clone());
        let mut tx = identity.transaction().await?;
        let now = now.max(crate::identity::now_ms()?);
        let now = active_session(&mut tx, auth, now).await?;
        if !auth.session.recently_authenticated(now) { return Err(IdentityError::RecentAuthenticationRequired); }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM nds_passkeys WHERE user_id=$1 AND tenant_id=$2",
        )
        .bind(auth.session.owner.user_id.as_str())
        .bind(auth.session.owner.tenant_id.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if count >= 16 {
            return Err(IdentityError::Capacity);
        }
        sqlx::query("INSERT INTO nds_passkeys(credential_id,user_id,tenant_id,credential,created_at_ms) VALUES ($1,$2,$3,$4,$5)")
            .bind(key.cred_id().as_ref()).bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str())
            .bind(serde_json::to_value(key).map_err(unavailable)?).bind(i64::try_from(now).map_err(|_| IdentityError::InvalidInput)?).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)

        }).await
    }
    pub async fn authenticate(
        &self,
        owner: &Owner,
        key: Passkey,
        original: serde_json::Value,
        issue: SessionIssue,
    ) -> Result<Session, IdentityError> {
        bounded(async {
        let identity = crate::identity::store::Store::new(self.0.clone());
        let mut tx = identity.transaction().await?;
        if &issue.session.owner != owner { return Err(IdentityError::Denied); }
        let stored: Option<serde_json::Value> = sqlx::query_scalar("SELECT credential FROM nds_passkeys WHERE credential_id=$1 AND user_id=$2 AND tenant_id=$3 FOR UPDATE")
            .bind(key.cred_id().as_ref()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        if stored.as_ref() != Some(&original) {
            return Err(IdentityError::Denied);
        }
        sqlx::query("UPDATE nds_passkeys SET credential=$2 WHERE credential_id=$1")
            .bind(key.cred_id().as_ref())
            .bind(serde_json::to_value(&key).map_err(unavailable)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let session = crate::identity::store::insert_session(&mut tx, issue, Some(key.cred_id().as_ref())).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(session)

        }).await
    }
}

async fn active_session(
    tx: &mut crate::identity::store::Tx<'_>,
    auth: &AuthenticatedSession,
    now: u64,
) -> Result<u64, IdentityError> {
    let now = crate::identity::store::authorization_clock(tx, &auth.session.owner, now).await?;
    let expiry =
        crate::identity::store::session_expiry(tx, &auth.session.owner, auth.binding).await?;
    if expiry.is_some_and(|value| value > 0 && (value as u64) > now) {
        Ok(now)
    } else {
        Err(IdentityError::Denied)
    }
}

fn fingerprint(id: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, id)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
