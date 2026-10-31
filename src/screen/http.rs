use crate::{AppState, protocol_screen as dto};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_application::{screen::*, sync::SyncError};
use nddev_device_sync_domain::{
    DeviceId, UserId,
    devices::DevicePlatform,
    modules::ModuleError,
    screen::{
        EndpointBinding, MAX_NATIVE_GRANT_BYTES, ScreenError, ViewLease, ViewPermit,
        ViewProjection, ViewState,
    },
    sync::MAX_REVISION,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v2/rds/targets/{user_id}", get(targets))
        .route("/v2/rds/bindings", post(bind))
        .route("/v2/rds/bindings/{device_id}", get(binding))
        .route("/v2/rds/views", post(create))
        .route("/v2/rds/views/incoming", get(incoming))
        .route("/v2/rds/views/{view_id}", get(view))
        .route("/v2/rds/views/{view_id}/ready", post(ready))
        .route("/v2/rds/views/{view_id}/end", post(end))
}
pub enum ApiError {
    Screen(ScreenError),
    Auth(SyncError),
}
impl From<ScreenError> for ApiError {
    fn from(e: ScreenError) -> Self {
        Self::Screen(e)
    }
}
impl From<SyncError> for ApiError {
    fn from(e: SyncError) -> Self {
        Self::Auth(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Auth(e) => return crate::sync::http::ApiError::from(e).into_response(),
            Self::Screen(ScreenError::Denied) => (StatusCode::FORBIDDEN, "authorization_denied"),
            Self::Screen(ScreenError::Closed | ScreenError::Expired) => {
                (StatusCode::CONFLICT, "operation_conflict")
            }
            Self::Screen(ScreenError::Module(ModuleError::Busy)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "server_busy")
            }
            Self::Screen(ScreenError::Module(ModuleError::Unavailable | ModuleError::Timeout)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable")
            }
            Self::Screen(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        };
        tracing::warn!(module="remote",scope="http",event.name="remote.request.rejected",error.type=code,outcome="rejected");
        let mut response = (status, Json(serde_json::json!({"error":code}))).into_response();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("2"));
        }
        response
    }
}
fn invalid<E>(_: E) -> ScreenError {
    ScreenError::Module(ModuleError::InvalidInput)
}
fn service(state: &AppState) -> Result<&super::store::Store, ScreenError> {
    state
        .screen
        .as_deref()
        .ok_or(ScreenError::Module(ModuleError::Unavailable))
}
fn value(v: i64) -> Result<u64, ScreenError> {
    let v: u64 = v.try_into().map_err(invalid)?;
    if v > MAX_REVISION {
        return Err(invalid(()));
    }
    Ok(v)
}
fn int(v: u64) -> Result<i64, ScreenError> {
    v.try_into().map_err(invalid)
}
fn decoded<const N: usize>(s: &str) -> Result<[u8; N], ScreenError> {
    let value = URL_SAFE_NO_PAD.decode(s).map_err(invalid)?;
    if URL_SAFE_NO_PAD.encode(&value) != s {
        return Err(invalid(()));
    }
    value.try_into().map_err(invalid)
}
fn grant(s: &str) -> Result<Vec<u8>, ScreenError> {
    if s.len() > 10923 {
        return Err(invalid(()));
    }
    let bytes = URL_SAFE_NO_PAD.decode(s).map_err(invalid)?;
    native_grant_payload(&bytes)?;
    if bytes.len() > MAX_NATIVE_GRANT_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != s {
        return Err(invalid(()));
    }
    Ok(bytes)
}
fn id(s: String) -> Result<DeviceId, ScreenError> {
    DeviceId::new(s).map_err(invalid)
}
fn empty(body: &[u8]) -> Result<(), ScreenError> {
    if !body.is_empty() {
        return Err(invalid(()));
    }
    Ok(())
}
fn done(operation: &'static str) {
    tracing::info!(
        module = "remote",
        scope = "http",
        event.name = operation,
        outcome = "ok"
    );
}
pub(crate) fn public(view: &ViewProjection) -> Result<dto::ScreenView, ScreenError> {
    let permit = view.permit();
    let lease = permit.lease;
    let mut current = view.clone();
    Ok(dto::ScreenView {
        view_id: view.id().into(),
        viewer_device_id: permit.viewer.as_str().into(),
        host_device_id: permit.host.as_str().into(),
        viewer_endpoint: URL_SAFE_NO_PAD.encode(permit.viewer_endpoint),
        host_endpoint: URL_SAFE_NO_PAD.encode(permit.host_endpoint),
        viewer_revision: int(permit.viewer_revision)?,
        host_revision: int(permit.host_revision)?,
        display: i64::from(lease.display()),
        max_fps: lease.max_fps().try_into().map_err(invalid)?,
        output_height: lease.output_height().try_into().map_err(invalid)?,
        admitted_at_ms: int(lease.admitted_at_ms())?,
        expires_at_ms: int(lease.expires_at_ms())?,
        state: match current.state(lease.admitted_at_ms()) {
            ViewState::Requested => dto::State::Requested,
            ViewState::Ready => dto::State::Ready,
            ViewState::Ended => dto::State::Ended,
        },
    })
}
pub(crate) fn projection(view: dto::ScreenView) -> Result<ViewProjection, ScreenError> {
    let lease = ViewLease::restore(
        view.display.try_into().map_err(invalid)?,
        view.max_fps.try_into().map_err(invalid)?,
        view.output_height.try_into().map_err(invalid)?,
        value(view.admitted_at_ms)?,
        value(view.expires_at_ms)?,
    )?;
    ViewProjection::restore(
        view.view_id,
        ViewPermit {
            viewer: id(view.viewer_device_id)?,
            host: id(view.host_device_id)?,
            viewer_endpoint: decoded(&view.viewer_endpoint)?,
            host_endpoint: decoded(&view.host_endpoint)?,
            viewer_revision: value(view.viewer_revision)?,
            host_revision: value(view.host_revision)?,
            lease,
        },
        match view.state {
            dto::State::Requested => ViewState::Requested,
            dto::State::Ready => ViewState::Ready,
            dto::State::Ended => ViewState::Ended,
        },
    )
    .map_err(invalid)
}
fn bound(v: EndpointBinding) -> Result<dto::ScreenBinding, ScreenError> {
    Ok(dto::ScreenBinding {
        device_id: v.device.as_str().into(),
        endpoint_public_key: URL_SAFE_NO_PAD.encode(v.endpoint),
        instance_id: uuid::Uuid::from_bytes(v.instance_id).to_string(),
        revision: int(v.revision)?,
    })
}

async fn targets(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(user): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::ScreenTargetList>, ApiError> {
    empty(&body)?;
    if uri.query().is_some() {
        return Err(invalid(()).into());
    }
    let user = UserId::new(user).map_err(invalid)?;
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let device = signed.device.clone();
    let rows = service(&state)?.targets(&auth, signed, &user, now).await?;
    let targets = rows
        .into_iter()
        .map(|row| dto::ScreenTarget {
            device_id: row.device.into(),
            display_name: row.name.as_str().into(),
            registered: row.registered,
            platform: match row.platform {
                DevicePlatform::Android => dto::Platform::Android,
                DevicePlatform::Ios => dto::Platform::Ios,
                DevicePlatform::Linux => dto::Platform::Linux,
                DevicePlatform::Macos => dto::Platform::Macos,
                DevicePlatform::Web => dto::Platform::Web,
                DevicePlatform::Windows => dto::Platform::Windows,
            },
        })
        .collect();
    tracing::info!(
        event.name = "remote.targets.completed",
        module = "remote",
        scope = "http",
        outcome = "ok",
        user.id = auth.session.owner.user_id.as_str(),
        tenant.id = auth.session.owner.tenant_id.as_str(),
        device.id = device.as_str(),
        target.user.id = user.as_str()
    );
    Ok(Json(dto::ScreenTargetList {
        user_id: user.as_str().into(),
        targets,
    }))
}

async fn bind(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::ScreenBinding>, ApiError> {
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let input: dto::ScreenBindRequest = serde_json::from_slice(&body).map_err(invalid)?;
    let instance = uuid::Uuid::parse_str(&input.instance_id).map_err(invalid)?;
    if instance.is_nil()
        || instance.to_string() != input.instance_id
        || input.expires_at_ms % 1000 != 0
    {
        return Err(invalid(()).into());
    }
    let claim = EndpointClaim {
        endpoint: decoded(&input.endpoint_public_key)?,
        instance_id: *instance.as_bytes(),
        base_revision: value(input.base_revision)?,
        nonce: input.nonce,
        expires_at_ms: value(input.expires_at_ms)?,
    };
    let result = service(&state)?
        .bind(&auth, signed, claim, decoded(&input.signature)?, now)
        .await?;
    done("remote.bind.completed");
    Ok(Json(bound(result)?))
}
async fn binding(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(target): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::ScreenBindingResponse>, ApiError> {
    empty(&body)?;
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let result = service(&state)?
        .binding(&auth, signed, &id(target)?, now)
        .await?;
    done("remote.binding.completed");
    Ok(Json(dto::ScreenBindingResponse {
        binding: result.map(bound).transpose()?,
    }))
}
async fn create(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<dto::ScreenView>), ApiError> {
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let input: dto::ScreenViewRequest = serde_json::from_slice(&body).map_err(invalid)?;
    if input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 256
        || !input
            .idempotency_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(invalid(()).into());
    }
    let request = ViewRequest {
        target: id(input.target_device_id)?,
        viewer_revision: value(input.viewer_revision)?,
        host_revision: value(input.host_revision)?,
        display: input.display.try_into().map_err(invalid)?,
        max_fps: input.max_fps.try_into().map_err(invalid)?,
        output_height: input.output_height.try_into().map_err(invalid)?,
        expires_at_ms: value(input.expires_at_ms)?,
        idempotency_key: input.idempotency_key,
    };
    let result = service(&state)?
        .create(&auth, signed, request, body.to_vec(), now)
        .await?;
    done("remote.create.completed");
    Ok((StatusCode::CREATED, Json(public(result.public())?)))
}
async fn incoming(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::ScreenIncoming>, ApiError> {
    empty(&body)?;
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let result = service(&state)?.incoming(&auth, signed, now).await?;
    done("remote.incoming.completed");
    Ok(Json(dto::ScreenIncoming {
        view: result.as_ref().map(|v| public(v.public())).transpose()?,
    }))
}
async fn view(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::ScreenViewResponse>, ApiError> {
    empty(&body)?;
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let (view, grant) = service(&state)?.view(&auth, signed, &id, now).await?;
    done("remote.view.completed");
    Ok(Json(dto::ScreenViewResponse {
        view: public(view.public())?,
        native_grant: grant.map(|v| URL_SAFE_NO_PAD.encode(v)),
    }))
}
async fn ready(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::ScreenView>, ApiError> {
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let input: dto::ScreenReadyRequest = serde_json::from_slice(&body).map_err(invalid)?;
    let result = service(&state)?
        .ready(&auth, signed, &id, grant(&input.native_grant)?, now)
        .await?;
    done("remote.ready.completed");
    Ok(Json(public(result.public())?))
}
async fn end(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    empty(&body)?;
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "POST", &uri, &body, now).await?;
    service(&state)?.end(&auth, signed, &id, now).await?;
    done("remote.end.completed");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_grant_budget_canonical_encoding_and_closed_dto_are_independent() {
        let artifact = URL_SAFE_NO_PAD.encode([7u8; 8192]);
        assert_eq!(grant(&artifact).unwrap().len(), 8192);
        for encoded in [
            URL_SAFE_NO_PAD.encode([7u8; 8193]),
            "AA=".into(),
            "AB".into(),
            "".into(),
        ] {
            assert!(grant(&encoded).is_err());
        }
        assert!(
            serde_json::from_str::<dto::ScreenReadyRequest>(
                r#"{"native_grant":"AA","viewer_session":"secret"}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<dto::ScreenBindingResponse>("{}").is_err());
    }
    #[test]
    fn stored_projection_reconstruction_keeps_original_time_and_ended_state() {
        let projection = ViewProjection::restore(
            "view-1".into(),
            ViewPermit {
                viewer: DeviceId::new("viewer").unwrap(),
                host: DeviceId::new("host").unwrap(),
                viewer_endpoint: [3; 32],
                host_endpoint: [4; 32],
                viewer_revision: 1,
                host_revision: 2,
                lease: ViewLease::restore(0, 30, 1080, 1000, 3000).unwrap(),
            },
            ViewState::Ended,
        )
        .unwrap();
        let wire = public(&projection).unwrap();
        assert_eq!((wire.admitted_at_ms, wire.expires_at_ms), (1000, 3000));
        let mut retained = super::projection(wire).unwrap();
        assert_eq!(retained.state(2000), ViewState::Ended);
        assert!(retained.ready(2000).is_err());
        assert_eq!(retained.state(4000), ViewState::Ended);
        assert_eq!(retained.permit().lease.admitted_at_ms(), 1000);
    }
}
