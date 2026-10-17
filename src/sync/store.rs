use crate::identity::{now_ms, store::Store as IdentityStore};
use nddev_device_sync_application::sync::*;
use sqlx::{Postgres, Row, Transaction};
type Tx<'a> = Transaction<'a, Postgres>;
#[derive(Clone)]
pub struct Store {
    identity: IdentityStore,
}
impl Store {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            identity: IdentityStore::new(pool),
        }
    }
}
fn unavailable<E>(_: E) -> SyncError {
    SyncError::Unavailable
}
fn integer(value: u64) -> Result<i64, SyncError> {
    value.try_into().map_err(unavailable)
}
fn counter(value: i64) -> Result<u64, SyncError> {
    value.try_into().map_err(unavailable)
}
pub(crate) async fn finish<T>(tx: Tx<'_>, result: Result<T, SyncError>) -> Result<T, SyncError> {
    if matches!(result, Err(SyncError::Unavailable)) {
        return result;
    }
    tx.commit().await.map_err(unavailable)?;
    result
}
pub(crate) async fn authorize(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    now: u64,
) -> Result<u64, SyncError> {
    let owner = &auth.session.owner;
    let session = crate::identity::store::session_expiry(tx, owner, auth.binding)
        .await
        .map_err(|error| match error {
            nddev_device_sync_application::identity::IdentityError::Denied => SyncError::Denied,
            _ => SyncError::Unavailable,
        })?;
    if !session.is_some_and(|expires| expires > now as i64) {
        return Err(SyncError::Denied);
    }
    let status:Option<String>=sqlx::query_scalar("SELECT status FROM nds_devices WHERE device_id=$1 AND user_id=$2 AND tenant_id=$3 FOR UPDATE")
        .bind(signed.device.as_str()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut **tx).await.map_err(unavailable)?;
    match status.as_deref() {
        Some("active") => {}
        Some("revoked") => return Err(SyncError::Revoked),
        _ => return Err(SyncError::Denied),
    }
    sqlx::query(
        "INSERT INTO public.nds_replica_counters(user_id,tenant_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(owner.user_id.as_str())
    .bind(owner.tenant_id.as_str())
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    let floor:i64=sqlx::query_scalar("UPDATE public.nds_replica_counters SET clock_floor_ms=GREATEST(clock_floor_ms,$3) WHERE user_id=$1 AND tenant_id=$2 RETURNING clock_floor_ms")
        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(integer(now)?).fetch_one(&mut **tx).await.map_err(unavailable)?;
    let now = counter(floor)?;
    if session.is_none_or(|expires| expires <= floor) {
        return Err(SyncError::Denied);
    }
    if signed.expires_at_ms <= now {
        return Err(SyncError::Signature);
    }
    sqlx::query("DELETE FROM public.nds_replica_nonces WHERE expires_at_ms <= $1")
        .bind(floor)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.nds_replica_nonces WHERE device_id=$1")
            .bind(signed.device.as_str())
            .fetch_one(&mut **tx)
            .await
            .map_err(unavailable)?;
    if count >= 512 {
        return Err(SyncError::Capacity);
    }
    let inserted=sqlx::query("INSERT INTO public.nds_replica_nonces(device_id,nonce,expires_at_ms) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(signed.device.as_str()).bind(&signed.nonce).bind(integer(signed.expires_at_ms)?).execute(&mut **tx).await.map_err(unavailable)?;
    if inserted.rows_affected() != 1 {
        return Err(SyncError::Nonce);
    }
    Ok(now)
}

mod history;
