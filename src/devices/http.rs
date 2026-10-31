use crate::protocol_personal as personal_dto;
use crate::{AppState, admission::PeerAddress, identity, protocol_devices as dto};
use axum::{
    Json, Router,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_application::devices::*;
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v2/devices/challenges", post(request))
        .route("/v2/devices/enrollments", post(complete))
        .route("/v2/devices", get(list))
        .route("/v3/personal/devices", get(list_personal))
        .route(
            "/v3/personal/devices/{device_id}/policy",
            get(get_policy).put(put_policy),
        )
        .route("/v2/devices/{device_id}", delete(revoke))
}
pub struct ApiError(DeviceError);
impl From<DeviceError> for ApiError {
    fn from(value: DeviceError) -> Self {
        Self(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self.0 {
            DeviceError::InvalidInput => (StatusCode::BAD_REQUEST, dto::ErrorEnum::InvalidRequest),
            DeviceError::InvalidProof => {
                (StatusCode::BAD_REQUEST, dto::ErrorEnum::InvalidSignature)
            }
            DeviceError::Expired => (StatusCode::BAD_REQUEST, dto::ErrorEnum::ChallengeExpired),
            DeviceError::Denied => (
                StatusCode::UNAUTHORIZED,
                dto::ErrorEnum::AuthenticationFailed,
            ),
            DeviceError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, dto::ErrorEnum::RateLimited)
            }
            DeviceError::Capacity => (StatusCode::SERVICE_UNAVAILABLE, dto::ErrorEnum::ServerBusy),
            DeviceError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                dto::ErrorEnum::DependencyUnavailable,
            ),
            DeviceError::Conflict => (StatusCode::CONFLICT, dto::ErrorEnum::OperationConflict),
            DeviceError::RecentAuthenticationRequired => (
                StatusCode::FORBIDDEN,
                dto::ErrorEnum::RecentAuthenticationRequired,
            ),
        };
        tracing::warn!(module = "devices", scope = "http", event.name="device.request.rejected",error.type=%self.0,outcome="rejected");
        let mut response = (status, Json(dto::Error { error })).into_response();
        if matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        ) {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("2"));
        }
        response
    }
}
fn service(state: &AppState) -> Result<&super::Service, DeviceError> {
    state.devices.as_deref().ok_or(DeviceError::Unavailable)
}
fn now() -> Result<u64, DeviceError> {
    identity::now_ms().map_err(identity_error)
}
async fn authorization(
    state: &AppState,
    headers: &HeaderMap,
    now: u64,
) -> Result<AuthenticatedSession, DeviceError> {
    let token = identity::http::bearer(headers).map_err(identity_error)?;
    state
        .identity
        .as_ref()
        .ok_or(DeviceError::Unavailable)?
        .authenticate(token, now)
        .await
        .map_err(identity_error)
}
fn decode<const N: usize>(text: &str) -> Result<[u8; N], DeviceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| DeviceError::InvalidInput)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(DeviceError::InvalidInput);
    }
    bytes.try_into().map_err(|_| DeviceError::InvalidInput)
}
fn timestamp(value: u64) -> Result<String, DeviceError> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .map_err(|_| DeviceError::Unavailable)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| DeviceError::Unavailable)
}
fn platform(value: dto::Platform) -> DevicePlatform {
    match value {
        dto::Platform::Android => DevicePlatform::Android,
        dto::Platform::Web => DevicePlatform::Web,
        dto::Platform::Ios => DevicePlatform::Ios,
        dto::Platform::Linux => DevicePlatform::Linux,
        dto::Platform::Macos => DevicePlatform::Macos,
        dto::Platform::Windows => DevicePlatform::Windows,
    }
}
fn device(value: Device) -> Result<dto::Device, DeviceError> {
    Ok(dto::Device {
        device_id: value.id.into(),
        display_name: value.name.as_str().into(),
        public_key: URL_SAFE_NO_PAD.encode(value.public_key.0),
        created_at: timestamp(value.created_at_ms)?,
        platform: match value.platform {
            DevicePlatform::Android => dto::Platform::Android,
            DevicePlatform::Web => dto::Platform::Web,
            DevicePlatform::Ios => dto::Platform::Ios,
            DevicePlatform::Linux => dto::Platform::Linux,
            DevicePlatform::Macos => dto::Platform::Macos,
            DevicePlatform::Windows => dto::Platform::Windows,
        },
        status: match value.status {
            DeviceStatus::Active => dto::Status::Active,
            DeviceStatus::Revoked => dto::Status::Revoked,
        },
    })
}
async fn request(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    headers: HeaderMap,
    body: Result<Json<dto::EnrollmentRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let now = now()?;
    let authorization = authorization(&state, &headers, now).await?;
    let Json(body) = body.map_err(|_| DeviceError::InvalidInput)?;
    let input = EnrollmentInput {
        platform: platform(body.platform),
        name: DeviceName::new(body.display_name)?,
        public_key: PublicDeviceKey(decode(&body.public_key)?),
    };
    let source = identity::http::peer(source).map_err(identity_error)?;
    let value = service(&state)?
        .request(&authorization, input, &source, now)
        .await?;
    tracing::info!(module = "devices", scope = "http", event.name="device.enrollment.requested",device.id=%value.device.id.as_str(),user.id=%authorization.session.owner.user_id.as_str(),tenant.id=%authorization.session.owner.tenant_id.as_str(),outcome="accepted");
    Ok((
        StatusCode::CREATED,
        Json(dto::EnrollmentChallenge {
            challenge_id: value.id,
            device_id: value.device.id.into(),
            challenge: URL_SAFE_NO_PAD.encode(value.challenge),
            expires_at: timestamp(value.expires_at_ms)?,
        }),
    ))
}
async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<dto::EnrollmentProof>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let now = now()?;
    let authorization = authorization(&state, &headers, now).await?;
    let Json(body) = body.map_err(|_| DeviceError::InvalidInput)?;
    let value = service(&state)?
        .complete(
            &authorization,
            &body.challenge_id,
            decode(&body.signature)?,
            now,
        )
        .await?;
    tracing::info!(module = "devices", scope = "http", event.name="device.enrollment.completed",device.id=%value.id.as_str(),user.id=%value.owner.user_id.as_str(),tenant.id=%value.owner.tenant_id.as_str(),outcome="accepted");
    Ok((StatusCode::CREATED, Json(device(value)?)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn inventory(
    state: &AppState,
    headers: &HeaderMap,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<PersonalDevicePage, ApiError> {
    let now = now()?;
    let authorization = authorization(state, headers, now).await?;
    let Query(page) = page.map_err(|_| DeviceError::InvalidInput)?;
    let after = match page.cursor {
        None => 0,
        Some(cursor) => {
            let value = cursor
                .strip_prefix("devices.")
                .ok_or(DeviceError::InvalidInput)?
                .parse::<u16>()
                .map_err(|_| DeviceError::InvalidInput)?;
            if cursor != format!("devices.{value}") {
                return Err(DeviceError::InvalidInput.into());
            }
            value
        }
    };
    Ok(service(state)?
        .list_personal(&authorization, after, page.limit.unwrap_or(50), now)
        .await?)
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Json<dto::DeviceList>, ApiError> {
    let page = inventory(&state, &headers, page).await?.page;
    Ok(Json(dto::DeviceList {
        devices: page
            .devices
            .into_iter()
            .map(device)
            .collect::<Result<_, _>>()?,
        next_cursor: page.next_after.map(|after| format!("devices.{after}")),
    }))
}

async fn list_personal(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<Page>, QueryRejection>,
) -> Result<Json<personal_dto::PersonalDeviceList>, ApiError> {
    let scoped = inventory(&state, &headers, query).await?;
    let context = personal_dto::PersonalContext {
        principal_id: scoped.context.principal_id().as_str().into(),
        space: personal_dto::PersonalSpace {
            kind: personal_dto::Kind::Personal,
            id: scoped.context.space_id().as_str().into(),
        },
    };
    Ok(Json(personal_dto::PersonalDeviceList {
        context,
        devices: scoped
            .page
            .devices
            .into_iter()
            .map(|value| {
                let value = device(value)?;
                Ok(personal_dto::Device {
                    created_at: value.created_at,
                    device_id: value.device_id,
                    display_name: value.display_name,
                    public_key: value.public_key,
                    platform: match value.platform {
                        dto::Platform::Android => personal_dto::Platform::Android,
                        dto::Platform::Web => personal_dto::Platform::Web,
                        dto::Platform::Ios => personal_dto::Platform::Ios,
                        dto::Platform::Linux => personal_dto::Platform::Linux,
                        dto::Platform::Macos => personal_dto::Platform::Macos,
                        dto::Platform::Windows => personal_dto::Platform::Windows,
                    },
                    status: match value.status {
                        dto::Status::Active => personal_dto::Status::Active,
                        dto::Status::Revoked => personal_dto::Status::Revoked,
                    },
                })
            })
            .collect::<Result<_, DeviceError>>()?,
        next_cursor: scoped
            .page
            .next_after
            .map(|after| format!("devices.{after}")),
    }))
}
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let now = now()?;
    let authorization = authorization(&state, &headers, now).await?;
    let id = DeviceId::new(id).map_err(|_| DeviceError::InvalidInput)?;
    service(&state)?.revoke(&authorization, &id, now).await?;
    tracing::info!(module = "devices", scope = "http", event.name="device.revoked",device.id=%id.as_str(),user.id=%authorization.session.owner.user_id.as_str(),tenant.id=%authorization.session.owner.tenant_id.as_str(),outcome="ok");
    Ok(StatusCode::NO_CONTENT)
}

fn policy_response(value: PersonalDevicePolicy) -> personal_dto::PersonalDevicePolicy {
    personal_dto::PersonalDevicePolicy {
        context: personal_dto::PersonalContext {
            principal_id: value.context.principal_id().as_str().into(),
            space: personal_dto::PersonalSpace {
                kind: personal_dto::Kind::Personal,
                id: value.context.space_id().as_str().into(),
            },
        },
        device_id: value.device.into(),
        policy: personal_dto::DevicePolicy {
            mode: match value.policy.mode() {
                ControlMode::Fullauto => personal_dto::ControlMode::Fullauto,
                ControlMode::Manual => personal_dto::ControlMode::Manual,
            },
            purposes: value
                .policy
                .purposes()
                .iter()
                .map(|purpose| match purpose {
                    DevicePurpose::ServerHosting => personal_dto::DevicePurpose::ServerHosting,
                    DevicePurpose::ServerDevDesktop => {
                        personal_dto::DevicePurpose::ServerDevDesktop
                    }
                    DevicePurpose::ServerDesktop => personal_dto::DevicePurpose::ServerDesktop,
                    DevicePurpose::BuildDevDesktop => personal_dto::DevicePurpose::BuildDevDesktop,
                    DevicePurpose::DevDesktop => personal_dto::DevicePurpose::DevDesktop,
                    DevicePurpose::Desktop => personal_dto::DevicePurpose::Desktop,
                })
                .collect(),
            // Bounded to MAX_POLICY_REVISION, which fits i64 exactly.
            revision: value.policy.revision() as i64,
        },
    }
}
async fn get_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<personal_dto::PersonalDevicePolicy>, ApiError> {
    let now = now()?;
    let authorization = authorization(&state, &headers, now).await?;
    let id = DeviceId::new(id).map_err(|_| DeviceError::InvalidInput)?;
    let value = service(&state)?.policy(&authorization, &id, now).await?;
    Ok(Json(policy_response(value)))
}
async fn put_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<personal_dto::DevicePolicyUpdate>, JsonRejection>,
) -> Result<Json<personal_dto::PersonalDevicePolicy>, ApiError> {
    let now = now()?;
    let authorization = authorization(&state, &headers, now).await?;
    let id = DeviceId::new(id).map_err(|_| DeviceError::InvalidInput)?;
    let Json(body) = body.map_err(|_| DeviceError::InvalidInput)?;
    let requested = body.purposes.len();
    let purposes = body
        .purposes
        .into_iter()
        .map(|purpose| match purpose {
            personal_dto::DevicePurpose::ServerHosting => DevicePurpose::ServerHosting,
            personal_dto::DevicePurpose::ServerDevDesktop => DevicePurpose::ServerDevDesktop,
            personal_dto::DevicePurpose::ServerDesktop => DevicePurpose::ServerDesktop,
            personal_dto::DevicePurpose::BuildDevDesktop => DevicePurpose::BuildDevDesktop,
            personal_dto::DevicePurpose::DevDesktop => DevicePurpose::DevDesktop,
            personal_dto::DevicePurpose::Desktop => DevicePurpose::Desktop,
        })
        .collect::<std::collections::BTreeSet<_>>();
    // Duplicates are a malformed request, never silently collapsed.
    if purposes.len() != requested {
        return Err(DeviceError::InvalidInput.into());
    }
    let change = PolicyChange {
        expected_revision: u64::try_from(body.expected_revision)
            .map_err(|_| DeviceError::InvalidInput)?,
        mode: match body.mode {
            personal_dto::ControlMode::Fullauto => ControlMode::Fullauto,
            personal_dto::ControlMode::Manual => ControlMode::Manual,
        },
        purposes,
    };
    let value = service(&state)?
        .replace_policy(&authorization, &id, change, now)
        .await?;
    tracing::info!(module = "devices", scope = "http", event.name="device.policy.replaced",device.id=%id.as_str(),user.id=%authorization.session.owner.user_id.as_str(),tenant.id=%authorization.session.owner.tenant_id.as_str(),outcome="ok");
    Ok(Json(policy_response(value)))
}
