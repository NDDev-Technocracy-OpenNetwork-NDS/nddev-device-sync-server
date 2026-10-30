use super::{Service, codec};
use crate::{AppState, protocol_company as dto, protocol_organizations as scoped};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nddev_device_sync_application::{
    organizations::{self as application, Context, InvitationRequest, OrganizationStore},
    sync::{StoredResult, SyncError},
};
use nddev_device_sync_domain::{
    InvitationId, TenantId, UserId,
    identity::{EmailAddress, Locale},
    organizations::{
        CompanyName, MembershipChange, OrganizationError as Error, commands::CommandId,
    },
    scope::PersonalContext,
    sync::MAX_REVISION,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v3/organizations", get(organizations).post(create_company))
        .route("/v3/organizations/{company_id}", get(overview))
        .route("/v3/organizations/{company_id}/members", get(members))
        .route(
            "/v3/organizations/{company_id}/invitations",
            get(invitations).post(create),
        )
        .route(
            "/v3/organizations/{company_id}/invitations/{invitation_id}/revoke",
            post(revoke),
        )
        .route(
            "/v3/organizations/{company_id}/members/{user_id}",
            post(change),
        )
        .route("/v2/company", get(overview))
        .route("/v2/company/members", get(members))
        .route("/v2/company/invitations", get(invitations).post(create))
        .route(
            "/v2/company/invitations/{invitation_id}/revoke",
            post(revoke),
        )
        .route("/v2/company/members/{user_id}", post(change))
        .layer(DefaultBodyLimit::max(4096))
}
pub enum ApiError {
    Company(Error),
    Auth(SyncError),
}
impl From<Error> for ApiError {
    fn from(value: Error) -> Self {
        Self::Company(value)
    }
}
impl From<SyncError> for ApiError {
    fn from(value: SyncError) -> Self {
        Self::Auth(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Auth(error) | Self::Company(Error::Authorization(error)) => {
                return crate::sync::http::ApiError::from(error).into_response();
            }
            Self::Company(Error::Denied) => {
                (StatusCode::FORBIDDEN, dto::Error::AuthorizationDenied)
            }
            Self::Company(Error::LastAdministrator) => {
                (StatusCode::CONFLICT, dto::Error::LastAdministrator)
            }
            Self::Company(Error::InvitationUnavailable) => {
                (StatusCode::CONFLICT, dto::Error::InvitationUnavailable)
            }
            Self::Company(Error::CommandExpired) => {
                (StatusCode::CONFLICT, dto::Error::CommandExpired)
            }
            Self::Company(Error::Conflict | Error::RevisionExhausted) => {
                (StatusCode::CONFLICT, dto::Error::OperationConflict)
            }
            Self::Company(Error::Busy) => (StatusCode::SERVICE_UNAVAILABLE, dto::Error::ServerBusy),
            Self::Company(Error::Unavailable | Error::InvalidState) => (
                StatusCode::SERVICE_UNAVAILABLE,
                dto::Error::DependencyUnavailable,
            ),
            Self::Company(Error::InvalidInput) => {
                (StatusCode::BAD_REQUEST, dto::Error::InvalidRequest)
            }
        };
        let error_class = serde_json::to_value(&error).unwrap_or_default();
        tracing::warn!(
            module = "organizations",
            scope = "http",
            event.name = "company.request.rejected",
            status = status.as_u16(),
            error.type = error_class.as_str().unwrap_or("company_dependency_unavailable"),
            outcome = "rejected"
        );
        let mut response = (status, Json(dto::CompanyError { error })).into_response();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("2"));
        }
        response
    }
}
fn service(state: &AppState) -> Result<&Service, Error> {
    state.organizations.as_deref().ok_or(Error::Unavailable)
}
async fn context(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    uri: &axum::http::Uri,
    body: &[u8],
) -> Result<Context, ApiError> {
    if uri.query().is_some()
        && (method == "POST" || matches!(uri.path(), "/v2/company" | "/v3/organizations"))
    {
        return Err(Error::InvalidInput.into());
    }
    let now_ms = crate::identity::now_ms().map_err(|_| Error::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(state, headers, method, uri, body, now_ms).await?;
    let company_id = if let Some(path) = uri.path().strip_prefix("/v3/organizations/") {
        let id = path.split('/').next().ok_or(Error::InvalidInput)?;
        if matches!(id, "." | "..") {
            return Err(Error::InvalidInput.into());
        }
        Some(TenantId::new(id).map_err(|_| Error::InvalidInput)?)
    } else if uri.path() == "/v3/organizations" {
        None
    } else {
        Some(auth.session.owner.tenant_id.clone())
    };
    tracing::info!(
        module = "organizations",
        scope = "http",
        event.name = "company.request.identity_verified",
        outcome = "checked",
        user.id = auth.session.owner.user_id.as_str(),
        tenant.id = auth.session.owner.tenant_id.as_str(),
        device.id = signed.device.as_str()
    );
    Ok(Context {
        personal: PersonalContext::new(&auth, now_ms).map_err(|_| Error::Denied)?,
        company_id,
        expected_membership_revision: None,
        signed,
        now_ms,
    })
}
fn input<T: DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|_| Error::InvalidInput)
}
fn command(value: String) -> Result<CommandId, Error> {
    let command = CommandId::new(value)?;
    tracing::info!(
        module = "organizations",
        scope = "http",
        event.name = "company.command.requested",
        operation.id = command.as_str(),
        outcome = "started"
    );
    Ok(command)
}
fn response(value: StoredResult) -> Result<Response, Error> {
    let mut result = (
        StatusCode::from_u16(value.status).map_err(|_| Error::Unavailable)?,
        value.body,
    )
        .into_response();
    result
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    Ok(result)
}
fn read_body(body: &Bytes) -> Result<(), Error> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<String>,
    membership_revision: Option<i64>,
}
fn is_scoped(uri: &axum::http::Uri) -> bool {
    uri.path().starts_with("/v3/organizations/")
}
fn capture_revision(context: &mut Context, revision: i64) -> Result<(), Error> {
    let revision = u64::try_from(revision).map_err(|_| Error::InvalidInput)?;
    if !(1..=MAX_REVISION).contains(&revision) {
        return Err(Error::InvalidInput);
    }
    context.expected_membership_revision = Some(revision);
    Ok(())
}
fn read_revision(context: &mut Context, uri: &axum::http::Uri, page: &Page) -> Result<(), Error> {
    match (is_scoped(uri), page.membership_revision) {
        (true, Some(revision)) => capture_revision(context, revision),
        (false, None) => Ok(()),
        _ => Err(Error::InvalidInput),
    }
}
/// Project referenced canonical payloads between the two generated profiles.
/// No handwritten wire shape, owner conversion or authority is introduced.
fn project<T: DeserializeOwned>(value: impl Serialize) -> Result<T, Error> {
    serde_json::from_value(serde_json::to_value(value).map_err(|_| Error::Unavailable)?)
        .map_err(|_| Error::Unavailable)
}
fn scope(
    context: &Context,
    company: &str,
    revision: u64,
) -> Result<scoped::OrganizationContext, Error> {
    Ok(scoped::OrganizationContext {
        principal_id: context.personal.principal_id().as_str().into(),
        membership_revision: revision.try_into().map_err(|_| Error::Unavailable)?,
        space: scoped::OrganizationSpace {
            kind: scoped::OrganizationSpaceKind::Organization,
            id: company.into(),
        },
    })
}
fn captured_scope(context: &Context) -> Result<scoped::OrganizationContext, Error> {
    scope(
        context,
        context.company()?.as_str(),
        context
            .expected_membership_revision
            .ok_or(Error::InvalidInput)?,
    )
}
fn overview_response(
    context: &Context,
    value: dto::CompanyOverview,
    status: StatusCode,
) -> Result<Response, Error> {
    let revision = u64::try_from(value.member.revision).map_err(|_| Error::Unavailable)?;
    Ok((
        status,
        Json(scoped::OrganizationOverview {
            context: scope(context, &value.company.company_id, revision)?,
            overview: project(value)?,
        }),
    )
        .into_response())
}
enum ResultKind {
    Invitation,
    Member,
}
fn mutation_response(
    value: StoredResult,
    context: &Context,
    kind: ResultKind,
    scoped: bool,
) -> Result<Response, Error> {
    if !scoped {
        return response(value);
    }
    let status = StatusCode::from_u16(value.status).map_err(|_| Error::Unavailable)?;
    let context = captured_scope(context)?;
    match kind {
        ResultKind::Invitation => {
            let invitation: scoped::CompanyInvitation =
                serde_json::from_slice(&value.body).map_err(|_| Error::Unavailable)?;
            Ok((
                status,
                Json(scoped::OrganizationInvitationResult {
                    context,
                    invitation,
                }),
            )
                .into_response())
        }
        ResultKind::Member => {
            let member: scoped::CompanyMember =
                serde_json::from_slice(&value.body).map_err(|_| Error::Unavailable)?;
            Ok((
                status,
                Json(scoped::OrganizationMemberResult { context, member }),
            )
                .into_response())
        }
    }
}
fn invitation_id(value: String) -> Result<InvitationId, Error> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(Error::InvalidInput);
    }
    InvitationId::new(value).map_err(|_| Error::InvalidInput)
}
async fn overview(
    State(state): State<AppState>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    read_body(&body)?;
    let mut context = context(&state, &headers, "GET", &uri, &body).await?;
    let Query(page) = query.map_err(|_| Error::InvalidInput)?;
    if page.after.is_some() {
        return Err(Error::InvalidInput.into());
    }
    read_revision(&mut context, &uri, &page)?;
    let value = codec::overview(&service(&state)?.store.overview(&context).await?)?;
    if is_scoped(&uri) {
        Ok(overview_response(&context, value, StatusCode::OK)?)
    } else {
        Ok(Json(value).into_response())
    }
}
async fn organizations(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Json<scoped::OrganizationList>, ApiError> {
    read_body(&body)?;
    let context = context(&state, &headers, "GET", &uri, &body).await?;
    let entries = service(&state)?.store.organizations(&context).await?;
    let values = entries
        .iter()
        .map(codec::overview)
        .collect::<Result<Vec<_>, _>>()?;
    let principal = context.personal.principal_id().as_str();
    Ok(Json(scoped::OrganizationList {
        context: scoped::PersonalContext {
            principal_id: principal.into(),
            space: scoped::PersonalSpace {
                kind: scoped::PersonalSpaceKind::Personal,
                id: principal.into(),
            },
        },
        organizations: project(values)?,
    }))
}
async fn create_company(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let context = context(&state, &headers, "POST", &uri, &body).await?;
    let input: scoped::OrganizationCreateRequest = input(&body)?;
    let name = CompanyName::new(input.display_name)?;
    let result = service(&state)?
        .store
        .create_company(&context, &command(input.operation_id)?, name)
        .await?;
    let value: dto::CompanyOverview =
        serde_json::from_slice(&result.body).map_err(|_| Error::Unavailable)?;
    Ok(overview_response(
        &context,
        value,
        StatusCode::from_u16(result.status).map_err(|_| Error::Unavailable)?,
    )?)
}
async fn members(
    State(state): State<AppState>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    read_body(&body)?;
    let mut context = context(&state, &headers, "GET", &uri, &body).await?;
    let Query(query) = query.map_err(|_| Error::InvalidInput)?;
    read_revision(&mut context, &uri, &query)?;
    let after = query
        .after
        .map(UserId::new)
        .transpose()
        .map_err(|_| Error::InvalidInput)?;
    let page = service(&state)?.store.members(&context, after).await?;
    let page = dto::CompanyMemberPage {
        members: page
            .entries
            .iter()
            .map(codec::member)
            .collect::<Result<_, _>>()?,
        next_cursor: page.next_cursor,
    };
    if is_scoped(&uri) {
        Ok(Json(scoped::OrganizationMemberPage {
            context: captured_scope(&context)?,
            page: project(page)?,
        })
        .into_response())
    } else {
        Ok(Json(page).into_response())
    }
}
async fn invitations(
    State(state): State<AppState>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    read_body(&body)?;
    let mut context = context(&state, &headers, "GET", &uri, &body).await?;
    let Query(query) = query.map_err(|_| Error::InvalidInput)?;
    read_revision(&mut context, &uri, &query)?;
    let after = query
        .after
        .map(invitation_id)
        .transpose()
        .map_err(|_| Error::InvalidInput)?;
    let page = service(&state)?.store.invitations(&context, after).await?;
    let page = dto::CompanyInvitationPage {
        invitations: page
            .entries
            .iter()
            .map(codec::invitation)
            .collect::<Result<_, _>>()?,
        next_cursor: page.next_cursor,
    };
    if is_scoped(&uri) {
        Ok(Json(scoped::OrganizationInvitationPage {
            context: captured_scope(&context)?,
            page: project(page)?,
        })
        .into_response())
    } else {
        Ok(Json(page).into_response())
    }
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut context = context(&state, &headers, "POST", &uri, &body).await?;
    let input: dto::CompanyInvitationRequest = if is_scoped(&uri) {
        let input: scoped::OrganizationInvitationRequest = input(&body)?;
        capture_revision(&mut context, input.membership_revision)?;
        project(input.payload)?
    } else {
        input(&body)?
    };
    if input.email.len() > 254 || input.email.trim() != input.email {
        return Err(Error::InvalidInput.into());
    }
    let request = InvitationRequest {
        email: EmailAddress::parse(&input.email).map_err(|_| Error::InvalidInput)?,
        role: codec::selected_role(input.role),
        locale: locale(&headers),
    };
    let command = command(input.operation_id)?;
    let service = service(&state)?;
    Ok(mutation_response(
        application::create_invitation(
            &service.store,
            &service.crypto,
            &service.mailer,
            &context,
            &command,
            request,
        )
        .await?,
        &context,
        ResultKind::Invitation,
        is_scoped(&uri),
    )?)
}
async fn revoke(
    State(state): State<AppState>,
    Path(ids): Path<HashMap<String, String>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut context = context(&state, &headers, "POST", &uri, &body).await?;
    let input: dto::CompanyRevokeRequest = if is_scoped(&uri) {
        let input: scoped::OrganizationRevokeRequest = input(&body)?;
        capture_revision(&mut context, input.membership_revision)?;
        project(input.payload)?
    } else {
        input(&body)?
    };
    let id = invitation_id(ids.get("invitation_id").ok_or(Error::InvalidInput)?.clone())?;
    Ok(mutation_response(
        service(&state)?
            .store
            .revoke(&context, &command(input.operation_id)?, &id)
            .await?,
        &context,
        ResultKind::Invitation,
        is_scoped(&uri),
    )?)
}
async fn change(
    State(state): State<AppState>,
    Path(ids): Path<HashMap<String, String>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut context = context(&state, &headers, "POST", &uri, &body).await?;
    let input: dto::CompanyMemberChangeRequest = if is_scoped(&uri) {
        let input: scoped::OrganizationMemberChangeRequest = input(&body)?;
        capture_revision(&mut context, input.membership_revision)?;
        project(input.payload)?
    } else {
        input(&body)?
    };
    let expected: u64 = input
        .expected_revision
        .try_into()
        .map_err(|_| Error::InvalidInput)?;
    if !(1..=MAX_REVISION).contains(&expected) {
        return Err(Error::InvalidInput.into());
    }
    let change = match (input.action, input.role) {
        (dto::Action::SetRole, Some(role)) => MembershipChange::SetRole(codec::selected_role(role)),
        (dto::Action::Remove, None) => MembershipChange::Remove,
        _ => return Err(Error::InvalidInput.into()),
    };
    let target = UserId::new(ids.get("user_id").ok_or(Error::InvalidInput)?)
        .map_err(|_| Error::InvalidInput)?;
    Ok(mutation_response(
        service(&state)?
            .store
            .change(
                &context,
                &command(input.operation_id)?,
                &target,
                expected,
                change,
            )
            .await?,
        &context,
        ResultKind::Member,
        is_scoped(&uri),
    )?)
}
fn locale(headers: &HeaderMap) -> Locale {
    crate::identity::http::locale(headers)
}
