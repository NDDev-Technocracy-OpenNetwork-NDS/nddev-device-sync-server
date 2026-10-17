use super::{Service, codec};
use crate::{AppState, protocol_company as dto};
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
    InvitationId, UserId,
    identity::{EmailAddress, Locale},
    organizations::{MembershipChange, OrganizationError as Error, commands::CommandId},
    sync::MAX_REVISION,
};
use serde::{Deserialize, de::DeserializeOwned};

pub fn routes() -> Router<AppState> {
    Router::new()
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
    if uri.query().is_some() && (method == "POST" || uri.path() == "/v2/company") {
        return Err(Error::InvalidInput.into());
    }
    let now_ms = crate::identity::now_ms().map_err(|_| Error::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(state, headers, method, uri, body, now_ms).await?;
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
        auth,
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
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Json<dto::CompanyOverview>, ApiError> {
    read_body(&body)?;
    let context = context(&state, &headers, "GET", &uri, &body).await?;
    Ok(Json(codec::overview(
        &service(&state)?.store.overview(&context).await?,
    )?))
}
async fn members(
    State(state): State<AppState>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Json<dto::CompanyMemberPage>, ApiError> {
    read_body(&body)?;
    let context = context(&state, &headers, "GET", &uri, &body).await?;
    let Query(query) = query.map_err(|_| Error::InvalidInput)?;
    let after = query
        .after
        .map(UserId::new)
        .transpose()
        .map_err(|_| Error::InvalidInput)?;
    let page = service(&state)?.store.members(&context, after).await?;
    Ok(Json(dto::CompanyMemberPage {
        members: page
            .entries
            .iter()
            .map(codec::member)
            .collect::<Result<_, _>>()?,
        next_cursor: page.next_cursor,
    }))
}
async fn invitations(
    State(state): State<AppState>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Json<dto::CompanyInvitationPage>, ApiError> {
    read_body(&body)?;
    let context = context(&state, &headers, "GET", &uri, &body).await?;
    let Query(query) = query.map_err(|_| Error::InvalidInput)?;
    let after = query
        .after
        .map(invitation_id)
        .transpose()
        .map_err(|_| Error::InvalidInput)?;
    let page = service(&state)?.store.invitations(&context, after).await?;
    Ok(Json(dto::CompanyInvitationPage {
        invitations: page
            .entries
            .iter()
            .map(codec::invitation)
            .collect::<Result<_, _>>()?,
        next_cursor: page.next_cursor,
    }))
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let context = context(&state, &headers, "POST", &uri, &body).await?;
    let input: dto::CompanyInvitationRequest = input(&body)?;
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
    Ok(response(
        application::create_invitation(
            &service.store,
            &service.crypto,
            &service.mailer,
            &context,
            &command,
            request,
        )
        .await?,
    )?)
}
async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let context = context(&state, &headers, "POST", &uri, &body).await?;
    let input: dto::CompanyRevokeRequest = input(&body)?;
    let id = invitation_id(id)?;
    Ok(response(
        service(&state)?
            .store
            .revoke(&context, &command(input.operation_id)?, &id)
            .await?,
    )?)
}
async fn change(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let context = context(&state, &headers, "POST", &uri, &body).await?;
    let input: dto::CompanyMemberChangeRequest = input(&body)?;
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
    let target = UserId::new(id).map_err(|_| Error::InvalidInput)?;
    Ok(response(
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
    )?)
}
fn locale(headers: &HeaderMap) -> Locale {
    crate::identity::http::locale(headers)
}
