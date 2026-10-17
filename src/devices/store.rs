use crate::identity::{crypto::Crypto, now_ms, store as identity_store};
use nddev_device_sync_application::{
    devices::*,
    identity::{Owner, ProtectedDigest, TenantId, UserId},
};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use std::future::Future;

type Tx<'a> = Transaction<'a, Postgres>;
pub struct Store {
    identity: identity_store::Store,
    crypto: Crypto,
}
impl Store {
    pub fn new(pool: sqlx::PgPool, crypto: Crypto) -> Self {
        Self {
            identity: identity_store::Store::new(pool),
            crypto,
        }
    }
}
fn unavailable<E>(_: E) -> DeviceError {
    DeviceError::Unavailable
}
fn millis(now: u64) -> Result<i64, DeviceError> {
    now.try_into().map_err(unavailable)
}
fn unsigned(value: i64) -> Result<u64, DeviceError> {
    value.try_into().map_err(unavailable)
}
fn bytes<const N: usize>(row: &PgRow, key: &str) -> Result<[u8; N], DeviceError> {
    row.try_get::<Vec<u8>, _>(key)
        .map_err(unavailable)?
        .try_into()
        .map_err(unavailable)
}
fn clock(now: u64) -> Result<u64, DeviceError> {
    Ok(now.max(now_ms().map_err(identity_error)?))
}
async fn bounded<T>(work: impl Future<Output = Result<T, DeviceError>>) -> Result<T, DeviceError> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(unavailable)?
}
async fn finish<T>(tx: Tx<'_>, outcome: Result<T, DeviceError>) -> Result<T, DeviceError> {
    // Failed proof/expiry/rate transitions are authoritative mutations too.
    // Database failures leave the transaction to roll back, never partially save.
    if matches!(outcome, Err(DeviceError::Unavailable)) {
        return outcome;
    }
    tx.commit().await.map_err(unavailable)?;
    outcome
}
async fn authorize(
    tx: &mut Tx<'_>,
    authorization: &AuthenticatedSession,
    now: u64,
) -> Result<(), DeviceError> {
    let owner = &authorization.session.owner;
    // Every session writer, revocation and observed-expiry deletion holds the
    // existing identity transaction lock. No session UPDATE grant is needed.
    let expiry = identity_store::session_expiry(tx, owner, authorization.binding)
        .await
        .map_err(identity_error)?;
    match expiry {
        Some(expiry) if unsigned(expiry)? > now => Ok(()),
        Some(_) => {
            sqlx::query("DELETE FROM nds_sessions WHERE token_digest=$1")
                .bind(authorization.binding.0.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(unavailable)?;
            Err(DeviceError::Denied)
        }
        None => Err(DeviceError::Denied),
    }
}
async fn capacity(tx: &mut Tx<'_>, owner: &Owner) -> Result<u16, DeviceError> {
    let row = sqlx::query("SELECT count(*) AS total,count(*) FILTER (WHERE status='active') AS active FROM nds_devices WHERE user_id=$1 AND tenant_id=$2")
        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut **tx).await.map_err(unavailable)?;
    let total = unsigned(row.try_get("total").map_err(unavailable)?)?;
    let active = unsigned(row.try_get("active").map_err(unavailable)?)?;
    if total >= MAX_DEVICE_IDENTITIES as u64 || active >= MAX_ACTIVE_DEVICES as u64 {
        return Err(DeviceError::Capacity);
    }
    (total + 1).try_into().map_err(unavailable)
}
pub fn platform(value: DevicePlatform) -> &'static str {
    match value {
        DevicePlatform::Macos => "macos",
        DevicePlatform::Linux => "linux",
        DevicePlatform::Windows => "windows",
        DevicePlatform::Ios => "ios",
        DevicePlatform::Android => "android",
        DevicePlatform::Web => "web",
    }
}
pub(crate) fn device(row: &PgRow) -> Result<Device, DeviceError> {
    Ok(Device {
        id: DeviceId::new(row.try_get::<String, _>("device_id").map_err(unavailable)?)
            .map_err(unavailable)?,
        owner: Owner {
            user_id: UserId::new(row.try_get::<String, _>("user_id").map_err(unavailable)?)
                .map_err(unavailable)?,
            tenant_id: TenantId::new(row.try_get::<String, _>("tenant_id").map_err(unavailable)?)
                .map_err(unavailable)?,
        },
        platform: match row.try_get::<&str, _>("platform").map_err(unavailable)? {
            "macos" => DevicePlatform::Macos,
            "linux" => DevicePlatform::Linux,
            "windows" => DevicePlatform::Windows,
            "ios" => DevicePlatform::Ios,
            "android" => DevicePlatform::Android,
            "web" => DevicePlatform::Web,
            _ => return Err(DeviceError::Unavailable),
        },
        name: DeviceName::new(row.try_get("display_name").map_err(unavailable)?)
            .map_err(unavailable)?,
        public_key: PublicDeviceKey(bytes(row, "public_key")?),
        status: match row.try_get::<&str, _>("status").map_err(unavailable)? {
            "active" => DeviceStatus::Active,
            "revoked" => DeviceStatus::Revoked,
            _ => return Err(DeviceError::Unavailable),
        },
        created_at_ms: unsigned(row.try_get("created_at_ms").map_err(unavailable)?)?,
    })
}

impl DeviceStore for Store {
    async fn issue(
        &self,
        issue: EnrollmentIssue,
        now: u64,
    ) -> Result<EnrollmentChallenge, DeviceError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(identity_error)?;
            let now = clock(now)?;
            let outcome = async {
                authorize(&mut tx,&issue.authorization,now).await?;
                identity_store::clean(&mut tx,now).await.map_err(identity_error)?;
                identity_store::rate(&mut tx,issue.owner_rate_key,ENROLLMENT_RATE,now).await.map_err(identity_error)?;
                sqlx::query("DELETE FROM nds_enrollment_challenges WHERE expires_at_ms <= $1 OR consumed OR attempts_remaining=0").bind(millis(now)?).execute(&mut *tx).await.map_err(unavailable)?;
                let challenge = issue.challenge;
                let owner = &challenge.device.owner;
                capacity(&mut tx,owner).await?;
                let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_enrollment_challenges WHERE user_id=$1 AND tenant_id=$2")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                if count >= MAX_PENDING_ENROLLMENTS as i64 { return Err(DeviceError::Capacity); }
                let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_devices WHERE public_key=$1)")
                    .bind(challenge.device.public_key.0.as_slice()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                if duplicate { return Err(DeviceError::InvalidInput); }
                sqlx::query("INSERT INTO nds_enrollment_challenges(challenge_id,device_id,user_id,tenant_id,session_digest,platform,display_name,public_key,challenge,created_at_ms,expires_at_ms,attempts_remaining) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
                    .bind(&challenge.id).bind(challenge.device.id.as_str()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(challenge.session.0.as_slice())
                    .bind(platform(challenge.device.platform)).bind(challenge.device.name.as_str()).bind(challenge.device.public_key.0.as_slice()).bind(challenge.challenge.as_slice())
                    .bind(millis(challenge.device.created_at_ms)?).bind(millis(challenge.expires_at_ms)?).bind(i16::from(challenge.attempts_remaining)).execute(&mut *tx).await.map_err(unavailable)?;
                Ok(challenge)
            }.await;
            finish(tx,outcome).await
        }).await
    }
    async fn complete(
        &self,
        authorization: &AuthenticatedSession,
        id: &str,
        signature: [u8; 64],
        now: u64,
    ) -> Result<Device, DeviceError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(identity_error)?;
            let now = clock(now)?;
            let outcome = async {
                authorize(&mut tx,authorization,now).await?;
                let owner = &authorization.session.owner;
                let row = sqlx::query("SELECT *, 'active'::text AS status FROM nds_enrollment_challenges WHERE challenge_id=$1 AND session_digest=$2 AND user_id=$3 AND tenant_id=$4 FOR UPDATE")
                    .bind(id).bind(authorization.binding.0.as_slice()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(DeviceError::InvalidProof)?;
                let mut challenge = EnrollmentChallenge {
                    id: id.into(), device: device(&row)?, session: ProtectedDigest(bytes(&row,"session_digest")?), challenge: bytes(&row,"challenge")?,
                    expires_at_ms: unsigned(row.try_get("expires_at_ms").map_err(unavailable)?)?,
                    attempts_remaining: row.try_get::<i16,_>("attempts_remaining").map_err(unavailable)?.try_into().map_err(unavailable)?, consumed: row.try_get("consumed").map_err(unavailable)?,
                };
                let valid = self.crypto.verify_proof(&challenge,&signature);
                let proof = challenge.consume(valid,now);
                sqlx::query("UPDATE nds_enrollment_challenges SET attempts_remaining=$2,consumed=$3 WHERE challenge_id=$1")
                    .bind(id).bind(i16::from(challenge.attempts_remaining)).bind(challenge.consumed).execute(&mut *tx).await.map_err(unavailable)?;
                proof?;
                let ordinal = capacity(&mut tx,owner).await?;
                let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_devices WHERE public_key=$1)")
                    .bind(challenge.device.public_key.0.as_slice()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                if duplicate { return Err(DeviceError::InvalidInput); }
                let mut device = challenge.device;
                device.created_at_ms = now;
                sqlx::query("INSERT INTO nds_devices(device_id,user_id,tenant_id,ordinal,platform,display_name,public_key,status,created_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)")
                    .bind(device.id.as_str()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(i16::try_from(ordinal).map_err(unavailable)?)
                    .bind(platform(device.platform)).bind(device.name.as_str()).bind(device.public_key.0.as_slice()).bind(millis(now)?).execute(&mut *tx).await.map_err(unavailable)?;
                Ok(device)
            }.await;
            finish(tx,outcome).await
        }).await
    }
    async fn list(
        &self,
        authorization: &AuthenticatedSession,
        after: u16,
        limit: usize,
        now: u64,
    ) -> Result<DevicePage, DeviceError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(identity_error)?;
            let now = clock(now)?;
            let outcome = async {
                authorize(&mut tx,authorization,now).await?;
                let owner = &authorization.session.owner;
                let mut rows = sqlx::query("SELECT * FROM nds_devices WHERE user_id=$1 AND tenant_id=$2 AND ordinal>$3 ORDER BY ordinal LIMIT $4")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(i16::try_from(after).map_err(unavailable)?).bind(i64::try_from(limit+1).map_err(unavailable)?)
                    .fetch_all(&mut *tx).await.map_err(unavailable)?;
                let more = rows.len()>limit;
                rows.truncate(limit);
                let next_after = if more { Some(rows.last().ok_or(DeviceError::Unavailable)?.try_get::<i16,_>("ordinal").map_err(unavailable)?.try_into().map_err(unavailable)?) } else {None};
                Ok(DevicePage { devices: rows.iter().map(device).collect::<Result<_,_>>()?, next_after })
            }.await;
            finish(tx,outcome).await
        }).await
    }
    async fn revoke(
        &self,
        authorization: &AuthenticatedSession,
        id: &DeviceId,
        now: u64,
    ) -> Result<(), DeviceError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(identity_error)?;
            let now = clock(now)?;
            let outcome = async {
                authorize(&mut tx,authorization,now).await?;
                let owner = &authorization.session.owner;
                let owned: Option<String> = sqlx::query_scalar("SELECT device_id FROM nds_devices WHERE device_id=$1 AND user_id=$2 AND tenant_id=$3 FOR UPDATE")
                    .bind(id.as_str()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
                if owned.is_none() { return Err(DeviceError::Denied); }
                sqlx::query("UPDATE nds_devices SET status='revoked' WHERE device_id=$1").bind(id.as_str()).execute(&mut *tx).await.map_err(unavailable)?;
                crate::screen::store::retire_device(&mut tx,id.as_str()).await.map_err(unavailable)?;
                Ok(())
            }.await;
            finish(tx,outcome).await
        }).await
    }
}
