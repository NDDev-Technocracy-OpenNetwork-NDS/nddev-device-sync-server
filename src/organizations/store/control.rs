use super::*;
use crate::organizations::codec;
use nddev_device_sync_application::{
    organizations::{self as application, *},
    sync::{StoredResult, SyncError},
};
use nddev_device_sync_domain::organizations::{
    Company, CompanyName, Membership, MembershipChange, OrganizationError as Error,
    commands::*,
    invitations::{Invitation, MAX_PENDING_INVITATIONS},
};
use sqlx::Acquire;

#[derive(Clone)]
pub struct Store {
    pool: sqlx::PgPool,
    identity: identity::Store,
}
impl Store {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            identity: identity::Store::new(pool.clone()),
            pool,
        }
    }
}
fn io<E>(_: E) -> Error {
    Error::Unavailable
}
fn identity_error(error: IdentityError) -> Error {
    match error {
        IdentityError::Denied => Error::Denied,
        IdentityError::Capacity | IdentityError::RateLimited => Error::Busy,
        _ => Error::Unavailable,
    }
}
fn int(value: u64) -> Result<i64, Error> {
    value.try_into().map_err(io)
}
async fn bounded<T>(work: impl std::future::Future<Output = Result<T, Error>>) -> Result<T, Error> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(io)?
}
async fn finish<T>(tx: Tx<'_>, result: Result<T, Error>) -> Result<T, Error> {
    if result.as_ref().is_err_and(|error| {
        matches!(
            error,
            Error::Unavailable | Error::Authorization(SyncError::Unavailable)
        )
    }) {
        return result;
    }
    tx.commit().await.map_err(io)?;
    result
}
async fn authorize(
    tx: &mut Tx<'_>,
    context: &Context,
    command: Option<&CommandId>,
    admin: bool,
) -> Result<(Membership, u64), Error> {
    let now = context.now_ms.max(crate::identity::now_ms().map_err(io)?);
    let now = crate::sync::store::authorize(tx, &context.auth, &context.signed, now)
        .await
        .map_err(Error::Authorization)?;
    let member = identity::membership(tx, &context.auth.session.owner)
        .await
        .map_err(identity_error)?;
    application::authorize(context, &member, command, now, admin)?;
    identity::clean(tx, now).await.map_err(identity_error)?;
    Ok((member, now))
}
fn member_row(row: PgRow) -> Result<Member, Error> {
    Ok(Member {
        membership: Membership {
            owner: Owner {
                user_id: UserId::new(row.try_get::<String, _>("user_id").map_err(io)?)
                    .map_err(io)?,
                tenant_id: TenantId::new(row.try_get::<String, _>("tenant_id").map_err(io)?)
                    .map_err(io)?,
            },
            role: role(row.try_get("company_role").map_err(io)?).map_err(io)?,
            active: row.try_get("membership_active").map_err(io)?,
        },
        revision: unsigned(row.try_get("member_revision").map_err(io)?).map_err(io)?,
        email: row
            .try_get::<Option<String>, _>("email")
            .map_err(io)?
            .map(|email| EmailAddress::parse(&email))
            .transpose()
            .map_err(io)?,
    })
}
async fn member(tx: &mut Tx<'_>, owner: &Owner) -> Result<Member, Error> {
    let row=sqlx::query("SELECT user_id,tenant_id,company_role,membership_active,member_revision,email FROM nds_owner WHERE user_id=$1 AND tenant_id=$2")
        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut **tx).await.map_err(io)?.ok_or(Error::Denied)?;
    member_row(row)
}
fn delivery_state(text: &str) -> Result<DeliveryState, Error> {
    match text {
        "pending" => Ok(DeliveryState::Pending),
        "accepted" => Ok(DeliveryState::Accepted),
        "failed" => Ok(DeliveryState::Failed),
        "unknown" => Ok(DeliveryState::Unknown),
        _ => Err(Error::Unavailable),
    }
}
fn delivery_text(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Pending => "pending",
        DeliveryState::Accepted => "accepted",
        DeliveryState::Failed => "failed",
        DeliveryState::Unknown => "unknown",
    }
}
async fn record(tx: &mut Tx<'_>, row: &PgRow, now: u64) -> Result<InvitationRecord, Error> {
    let mut value = invitation(row).map_err(io)?;
    let previous = value.metadata().status;
    // A metadata read is not authentication; a clock before issue retains the
    // original state. Claim/accept independently reject that clock condition.
    let _ = value.observe_expiry(now);
    if value.metadata().status != previous {
        persist_status(tx, &value).await.map_err(io)?;
    }
    let previous = delivery_state(row.try_get("delivery_state").map_err(io)?)?;
    let delivery = previous.observe(value.metadata().issued_at_ms, now);
    if delivery != previous {
        sqlx::query("UPDATE nds_company_invitations SET delivery_state=$2 WHERE invitation_id=$1")
            .bind(value.metadata().id.as_str())
            .bind(delivery_text(delivery))
            .execute(&mut **tx)
            .await
            .map_err(io)?;
    }
    Ok(InvitationRecord {
        metadata: value.metadata().clone(),
        email: EmailAddress::parse(row.try_get("recipient_email").map_err(io)?).map_err(io)?,
        delivery,
    })
}
async fn clean_invitations(tx: &mut Tx<'_>, owner: &Owner, now: u64) -> Result<(), Error> {
    let rows=sqlx::query("SELECT * FROM nds_company_invitations WHERE tenant_id=$1 AND status='pending' AND expires_at_ms<=$2 ORDER BY invitation_id LIMIT $3 FOR UPDATE")
        .bind(owner.tenant_id.as_str()).bind(int(now)?).bind((MAX_PENDING_INVITATIONS+1) as i64).fetch_all(&mut **tx).await.map_err(io)?;
    if rows.len() > MAX_PENDING_INVITATIONS {
        return Err(Error::Busy);
    }
    for row in rows {
        record(tx, &row, now).await?;
    }
    sqlx::query("DELETE FROM nds_company_invitations i WHERE tenant_id=$1 AND expires_at_ms<=$2 AND NOT EXISTS(SELECT 1 FROM nds_email_challenges c WHERE c.invitation_id=i.invitation_id)")
        .bind(owner.tenant_id.as_str()).bind(int(now.saturating_sub(COMMAND_LIFETIME_MS))?).execute(&mut **tx).await.map_err(io)?;
    Ok(())
}
fn fingerprint(context: &Context, kind: &str, target: &str) -> [u8; 32] {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    for bytes in [
        b"NDS-COMPANY-COMMAND".as_slice(),
        kind.as_bytes(),
        target.as_bytes(),
        context.signed.fingerprint.as_slice(),
    ] {
        hash.update(&(bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finish().as_ref().try_into().expect("SHA256 length")
}
async fn receipt(
    tx: &mut Tx<'_>,
    context: &Context,
    command: &CommandId,
    fingerprint: &[u8; 32],
    now: u64,
) -> Result<Option<StoredResult>, Error> {
    let owner = &context.auth.session.owner;
    sqlx::query(
        "DELETE FROM nds_company_commands WHERE user_id=$1 AND tenant_id=$2 AND expires_at_ms<=$3",
    )
    .bind(owner.user_id.as_str())
    .bind(owner.tenant_id.as_str())
    .bind(int(now)?)
    .execute(&mut **tx)
    .await
    .map_err(io)?;
    let id = uuid::Uuid::parse_str(command.as_str()).map_err(io)?;
    let row=sqlx::query("SELECT fingerprint,status,response FROM nds_company_commands WHERE user_id=$1 AND tenant_id=$2 AND device_id=$3 AND operation_id=$4")
        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(context.signed.device.as_str()).bind(id).fetch_optional(&mut **tx).await.map_err(io)?;
    if let Some(row) = row {
        if row.try_get::<Vec<u8>, _>("fingerprint").map_err(io)? != fingerprint {
            return Err(Error::Conflict);
        }
        return Ok(Some(StoredResult {
            status: row
                .try_get::<i16, _>("status")
                .map_err(io)?
                .try_into()
                .map_err(io)?,
            body: row.try_get("response").map_err(io)?,
        }));
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM nds_company_commands WHERE user_id=$1 AND tenant_id=$2 AND device_id=$3")
        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(context.signed.device.as_str()).fetch_one(&mut **tx).await.map_err(io)?;
    if count >= MAX_COMMANDS_PER_DEVICE as i64 {
        return Err(Error::Busy);
    }
    Ok(None)
}
async fn save(
    tx: &mut Tx<'_>,
    context: &Context,
    command: &CommandId,
    fingerprint: &[u8; 32],
    status: u16,
    body: Vec<u8>,
) -> Result<StoredResult, Error> {
    if body.len() > MAX_COMMAND_RESULT_BYTES {
        return Err(Error::Unavailable);
    }
    let owner = &context.auth.session.owner;
    sqlx::query("INSERT INTO nds_company_commands(user_id,tenant_id,device_id,operation_id,fingerprint,status,response,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(context.signed.device.as_str()).bind(uuid::Uuid::parse_str(command.as_str()).map_err(io)?)
        .bind(fingerprint.as_slice()).bind(status as i16).bind(&body).bind(int(command.expires_at_ms())?).execute(&mut **tx).await.map_err(io)?;
    Ok(StoredResult { status, body })
}
async fn complete_mutation<T>(tx: Tx<'_>, result: Result<T, Error>) -> Result<T, Error> {
    if result.is_ok() {
        tx.commit().await.map_err(io)?;
    } else {
        tx.rollback().await.map_err(io)?;
    }
    result
}

impl OrganizationStore for Store {
    async fn overview(&self, context: &Context) -> Result<Overview, Error> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(identity_error)?;
            let result = async {
                authorize(&mut tx, context, None, false).await?;
                let owner = &context.auth.session.owner;
                let row = sqlx::query(
                    "SELECT display_name,revision FROM nds_companies WHERE tenant_id=$1",
                )
                .bind(owner.tenant_id.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(io)?;
                Ok(Overview {
                    company: Company::new(
                        owner.tenant_id.clone(),
                        CompanyName::new(row.try_get("display_name").map_err(io)?)?,
                        unsigned(row.try_get("revision").map_err(io)?).map_err(io)?,
                    )?,
                    member: member(&mut tx, owner).await?,
                })
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
    async fn members(
        &self,
        context: &Context,
        after: Option<UserId>,
    ) -> Result<Page<Member>, Error> {
        bounded(async {
        let mut tx=self.identity.transaction().await.map_err(identity_error)?;
        let result=async {
            authorize(&mut tx,context,None,true).await?;
            let owner=&context.auth.session.owner;
            let rows=sqlx::query("SELECT user_id,tenant_id,company_role,membership_active,member_revision,email FROM nds_owner WHERE tenant_id=$1 AND user_id>$2 ORDER BY user_id LIMIT $3")
                .bind(owner.tenant_id.as_str()).bind(after.as_ref().map_or("",UserId::as_str)).bind((PAGE_SIZE+1) as i64).fetch_all(&mut *tx).await.map_err(io)?;
            let next_cursor=if rows.len()>PAGE_SIZE {Some(rows[PAGE_SIZE-1].try_get("user_id").map_err(io)?)} else {None};
            let entries=rows.into_iter().take(PAGE_SIZE).map(member_row).collect::<Result<Vec<_>,_>>()?;
            Ok(Page{entries,next_cursor})
        }.await;finish(tx,result).await
    }).await
    }
    async fn invitations(
        &self,
        context: &Context,
        after: Option<InvitationId>,
    ) -> Result<Page<InvitationRecord>, Error> {
        bounded(async {
        let mut tx=self.identity.transaction().await.map_err(identity_error)?;
        let result=async {
            let (_,now)=authorize(&mut tx,context,None,true).await?;
            clean_invitations(&mut tx,&context.auth.session.owner,now).await?;
            let rows=sqlx::query("SELECT * FROM nds_company_invitations WHERE tenant_id=$1 AND invitation_id>$2 ORDER BY invitation_id LIMIT $3 FOR UPDATE")
                .bind(context.auth.session.owner.tenant_id.as_str()).bind(after.as_ref().map_or("",InvitationId::as_str)).bind((PAGE_SIZE+1) as i64).fetch_all(&mut *tx).await.map_err(io)?;
            let next_cursor=if rows.len()>PAGE_SIZE {Some(rows[PAGE_SIZE-1].try_get("invitation_id").map_err(io)?)} else {None};
            let mut entries=Vec::with_capacity(PAGE_SIZE);
            for row in rows.into_iter().take(PAGE_SIZE) {entries.push(record(&mut tx,&row,now).await?);}
            Ok(Page{entries,next_cursor})
        }.await;finish(tx,result).await
    }).await
    }
    async fn create(
        &self,
        context: &Context,
        command: &CommandId,
        prepared: PreparedInvitation,
    ) -> Result<CreatedInvitation, Error> {
        bounded(async {
        let selected_role=prepared.request.role;
        let mut tx=self.identity.transaction().await.map_err(identity_error)?;
        let result=async {
            let (actor,now)=authorize(&mut tx,context,Some(command),true).await?;
            let hash=fingerprint(context,"invite","");
            if let Some(result)=receipt(&mut tx,context,command,&hash,now).await? {return Ok(CreatedInvitation{result,delivery:None});}
            clean_invitations(&mut tx,&actor.owner,now).await?;
            let (pending,retained):(i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE status='pending'),count(*) FROM nds_company_invitations WHERE tenant_id=$1")
                .bind(actor.owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(io)?;
            if pending>=MAX_PENDING_INVITATIONS as i64 || retained>=MAX_RETAINED_INVITATIONS as i64 {return Err(Error::Busy);}
            let duplicate:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_company_invitations WHERE tenant_id=$1 AND recipient_binding=$2 AND status='pending')")
                .bind(actor.owner.tenant_id.as_str()).bind(prepared.recipient_binding.0.as_slice()).fetch_one(&mut *tx).await.map_err(io)?;
            if duplicate { return Err(Error::Conflict); }
            let existing=sqlx::query("SELECT user_id,tenant_id,membership_active FROM nds_owner WHERE email_binding=$1")
                .bind(prepared.recipient_binding.0.as_slice()).fetch_optional(&mut *tx).await.map_err(io)?;
            let recipient=match existing {
                Some(row)=>{
                    if row.try_get::<bool,_>("membership_active").map_err(io)? || row.try_get::<String,_>("tenant_id").map_err(io)?!=actor.owner.tenant_id.as_str() {return Err(Error::InvitationUnavailable);}
                    Owner{user_id:UserId::new(row.try_get::<String,_>("user_id").map_err(io)?).map_err(io)?,tenant_id:actor.owner.tenant_id.clone()}
                },
                None=>Owner{user_id:UserId::new(uuid::Uuid::new_v4().to_string()).map_err(io)?,tenant_id:actor.owner.tenant_id.clone()}
            };
            let value=Invitation::issue(prepared.id.clone(),&actor,&actor.owner,recipient,prepared.request.role,now)?;
            let mut savepoint=tx.begin().await.map_err(io)?;
            let result=async {
                let tx=&mut savepoint;
                let metadata=value.metadata();
                sqlx::query("INSERT INTO nds_company_invitations(invitation_id,tenant_id,issuer_user_id,recipient_user_id,recipient_email,recipient_binding,recipient_subject,company_role,verifier,issued_at_ms,expires_at_ms,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending')")
                    .bind(metadata.id.as_str()).bind(actor.owner.tenant_id.as_str()).bind(actor.owner.user_id.as_str()).bind(metadata.recipient.user_id.as_str()).bind(prepared.request.email.as_str())
                    .bind(prepared.recipient_binding.0.as_slice()).bind(prepared.recipient_subject.0.as_slice()).bind(role_text(prepared.request.role)).bind(prepared.verifier.0.as_slice()).bind(int(now)?).bind(int(metadata.expires_at_ms)?).execute(&mut **tx).await.map_err(io)?;
                let body=codec::invitation(&InvitationRecord{metadata:metadata.clone(),email:prepared.request.email.clone(),delivery:DeliveryState::Pending})?;
                save(tx,context,command,&hash,201,serde_json::to_vec(&body).map_err(io)?).await
            }.await;
            let result=complete_mutation(savepoint,result).await?;
            Ok(CreatedInvitation{result,delivery:Some(InvitationMessage{id:prepared.id,recipient:prepared.request.email,token:prepared.token,expires_at_ms:value.metadata().expires_at_ms,delivery_deadline_ms:now.saturating_add(DELIVERY_LIFETIME_MS),locale:prepared.request.locale})})
        }.await;
        let result=finish(tx,result).await?;
        if let Some(message)=&result.delivery {
            tracing::info!(module="organizations",scope="database",event.name=match selected_role {CompanyRole::Admin=>"company.invitation.admin.created",CompanyRole::User=>"company.invitation.user.created"},outcome="ok",operation.id=command.as_str(),invitation.id=message.id.as_str(),user.id=context.auth.session.owner.user_id.as_str(),tenant.id=context.auth.session.owner.tenant_id.as_str(),device.id=context.signed.device.as_str());
        } else {
            tracing::info!(module="organizations",scope="database",event.name="company.invitation.creation_replayed",outcome="ok",operation.id=command.as_str(),user.id=context.auth.session.owner.user_id.as_str(),tenant.id=context.auth.session.owner.tenant_id.as_str(),device.id=context.signed.device.as_str());
        }
        Ok(result)
    }).await
    }
    async fn revoke(
        &self,
        context: &Context,
        command: &CommandId,
        id: &InvitationId,
    ) -> Result<StoredResult, Error> {
        bounded(async {
        let mut tx=self.identity.transaction().await.map_err(identity_error)?;
        let result=async {
            let (actor,now)=authorize(&mut tx,context,Some(command),true).await?;
            let hash=fingerprint(context,"revoke",id.as_str());
            if let Some(result)=receipt(&mut tx,context,command,&hash,now).await? { return Ok(result); }
            let row=sqlx::query("SELECT * FROM nds_company_invitations WHERE invitation_id=$1 AND tenant_id=$2 FOR UPDATE")
                .bind(id.as_str()).bind(actor.owner.tenant_id.as_str()).fetch_optional(&mut *tx).await.map_err(io)?.ok_or(Error::InvitationUnavailable)?;
            let mut value=invitation(&row).map_err(io)?;
            value.revoke(&actor,&actor.owner,now)?;
            let mut savepoint=tx.begin().await.map_err(io)?;
            let result=async {
                let tx=&mut savepoint;
                persist_status(tx,&value).await.map_err(io)?;
                let result=InvitationRecord{metadata:value.metadata().clone(),email:EmailAddress::parse(row.try_get("recipient_email").map_err(io)?).map_err(io)?,delivery:delivery_state(row.try_get("delivery_state").map_err(io)?)?.observe(value.metadata().issued_at_ms,now)};
                save(tx,context,command,&hash,200,serde_json::to_vec(&codec::invitation(&result)?).map_err(io)?).await
            }.await;
            complete_mutation(savepoint,result).await
        }.await;
        let result=finish(tx,result).await?;
        tracing::info!(module="organizations",scope="database",event.name="company.invitation.revoke.completed",outcome="ok",operation.id=command.as_str(),invitation.id=id.as_str(),user.id=context.auth.session.owner.user_id.as_str(),tenant.id=context.auth.session.owner.tenant_id.as_str(),device.id=context.signed.device.as_str());
        Ok(result)
    }).await
    }
    async fn change(
        &self,
        context: &Context,
        command: &CommandId,
        target: &UserId,
        expected: u64,
        change: MembershipChange,
    ) -> Result<StoredResult, Error> {
        bounded(async {
        let mut tx=self.identity.transaction().await.map_err(identity_error)?;
        let result=async {
            let (actor,now)=authorize(&mut tx,context,Some(command),true).await?;
            let hash=fingerprint(context,"member",target.as_str());
            if let Some(result)=receipt(&mut tx,context,command,&hash,now).await? { return Ok(result); }
            let owner=Owner{user_id:target.clone(),tenant_id:actor.owner.tenant_id.clone()};
            let current=member(&mut tx,&owner).await?;
            let admins:i64=sqlx::query_scalar("SELECT count(*) FROM nds_owner WHERE tenant_id=$1 AND membership_active AND company_role='admin'").bind(owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(io)?;
            let (next,revision)=current.change(&actor,&actor.owner,expected,change,admins.try_into().map_err(io)?)?;
            clean_invitations(&mut tx,&actor.owner,now).await?;
            let mut savepoint=tx.begin().await.map_err(io)?;
            let result=async {
                let tx=&mut savepoint;
                if revision!=current.revision {
                    let changed=sqlx::query("UPDATE nds_owner SET company_role=$3,membership_active=$4,member_revision=$5 WHERE user_id=$1 AND tenant_id=$2 AND member_revision=$6")
                        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(role_text(next.role)).bind(next.active).bind(int(revision)?).bind(int(expected)?).execute(&mut **tx).await.map_err(io)?;
                    if changed.rows_affected()!=1 {return Err(Error::Conflict);}
                    if !next.active || current.membership.role==CompanyRole::Admin && next.role!=CompanyRole::Admin {
                        let rows=sqlx::query("SELECT * FROM nds_company_invitations WHERE tenant_id=$1 AND issuer_user_id=$2 AND status='pending' FOR UPDATE")
                            .bind(owner.tenant_id.as_str()).bind(owner.user_id.as_str()).fetch_all(&mut **tx).await.map_err(io)?;
                        if rows.len()>MAX_PENDING_INVITATIONS {return Err(Error::Busy);}
                        for row in rows {let mut invitation=invitation(&row).map_err(io)?;invitation.revoke(&actor,&actor.owner,now)?;persist_status(tx,&invitation).await.map_err(io)?;}
                    }
                    if !next.active {
                        sqlx::query("DELETE FROM nds_sessions WHERE user_id=$1 AND tenant_id=$2").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).execute(&mut **tx).await.map_err(io)?;
                        sqlx::query("DELETE FROM nds_enrollment_challenges WHERE user_id=$1 AND tenant_id=$2").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).execute(&mut **tx).await.map_err(io)?;
                        crate::screen::store::retire_owner(tx,&owner,false).await.map_err(io)?;
                    } else if current.membership.role==CompanyRole::Admin && next.role==CompanyRole::User {
                        crate::screen::store::retire_owner(tx,&owner,true).await.map_err(io)?;
                    }
                }
                let result=Member{membership:next,revision,email:current.email};
                save(tx,context,command,&hash,200,serde_json::to_vec(&codec::member(&result)?).map_err(io)?).await
            }.await;
            complete_mutation(savepoint,result).await
        }.await;
        let result=finish(tx,result).await?;
        tracing::info!(module="organizations",scope="database",event.name=match change {MembershipChange::SetRole(CompanyRole::Admin)=>"company.member.role_admin.completed",MembershipChange::SetRole(CompanyRole::User)=>"company.member.role_user.completed",MembershipChange::Remove=>"company.member.remove.completed"},outcome="ok",operation.id=command.as_str(),target.user.id=target.as_str(),user.id=context.auth.session.owner.user_id.as_str(),tenant.id=context.auth.session.owner.tenant_id.as_str(),device.id=context.signed.device.as_str());
        Ok(result)
    }).await
    }
    async fn delivery(&self, id: &InvitationId, state: DeliveryState) -> Result<(), Error> {
        bounded(async {
        if state==DeliveryState::Pending {return Err(Error::InvalidInput);}
        let changed=sqlx::query("UPDATE nds_company_invitations SET delivery_state=$2 WHERE invitation_id=$1 AND delivery_state IN ('pending','unknown')")
            .bind(id.as_str()).bind(delivery_text(state)).execute(&self.pool).await.map_err(io)?;
        if changed.rows_affected()==1 {
            tracing::info!(module="organizations",scope="database",event.name=match state {DeliveryState::Accepted=>"company.invitation.delivery.recorded_accepted",DeliveryState::Failed=>"company.invitation.delivery.recorded_failed",DeliveryState::Unknown=>"company.invitation.delivery.recorded_unknown",DeliveryState::Pending=>unreachable!()},invitation.id=id.as_str(),outcome="ok");
        }
        Ok(())
    }).await
    }
}
