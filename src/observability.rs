//! Signed owner/device gateway to the separately owned observability service.
//! Operator credentials stay server-side; no arbitrary authenticated HTTP proxy.
use crate::{AppState, config::SecretString, identity, protocol_observability as dto};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nddev_device_sync_application::sync::SyncError;

pub enum ApiError {
    Transport(SyncError),
    OperatorDenied,
    /// A P2 diagnostic refusal: the caller has no right to the scope, or lacks a global grant.
    Diagnostic(dto::Error),
}
impl From<SyncError> for ApiError {
    fn from(error: SyncError) -> Self {
        Self::Transport(error)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Transport(error) => crate::sync::http::ApiError::from(error).into_response(),
            Self::OperatorDenied => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error":"authorization_denied"})),
            )
                .into_response(),
            Self::Diagnostic(error) => (
                StatusCode::FORBIDDEN,
                Json(dto::ObservabilityError { error }),
            )
                .into_response(),
        }
    }
}

use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path as FilePath, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    origin: String,
    trace_origin: String,
    ingest_token_file: PathBuf,
    admin_token_file: PathBuf,
    /// Allowed global diagnostic administrator keys (`ssh-ed25519 <base64> [comment]` lines).
    #[serde(default)]
    global_admin_keys_file: Option<PathBuf>,
    /// Operator debug windows per device; absent means every enabled client is standard.
    #[serde(default)]
    collection_policy_file: Option<PathBuf>,
}
pub struct Gateway {
    origin: reqwest::Url,
    trace_origin: reqwest::Url,
    ingest: SecretString,
    admin: SecretString,
    http: reqwest::Client,
    permits: tokio::sync::Semaphore,
    pub(crate) global_admin_keys: Option<PathBuf>,
    pub(crate) collection_policy: Option<PathBuf>,
}
impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservabilityGateway([REDACTED])")
    }
}
pub(crate) fn read(path: &FilePath) -> Result<Vec<u8>, ()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(());
        }
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > 16_384 {
        return Err(());
    }
    Ok(bytes)
}
fn token(path: &FilePath) -> Result<SecretString, ()> {
    let value = String::from_utf8(read(path)?).map_err(|_| ())?;
    let value = value.trim_end_matches(['\r', '\n']);
    if !(32..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(());
    }
    Ok(SecretString::from_native(value.into()))
}
fn internal_origin(value: &str) -> Result<reqwest::Url, ()> {
    let origin = reqwest::Url::parse(value).map_err(|_| ())?;
    if value.len() > 2048
        || !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || origin.path() != "/"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(());
    }
    Ok(origin)
}
impl Gateway {
    pub(crate) fn from_file(path: &FilePath) -> Result<Arc<Self>, ()> {
        let settings: Settings = serde_json::from_slice(&read(path)?).map_err(|_| ())?;
        let origin = internal_origin(&settings.origin)?;
        let trace_origin = internal_origin(&settings.trace_origin)?;
        Ok(Arc::new(Self {
            origin,
            trace_origin,
            ingest: token(&settings.ingest_token_file)?,
            admin: token(&settings.admin_token_file)?,
            http: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(2)
                .build()
                .map_err(|_| ())?,
            permits: tokio::sync::Semaphore::new(4),
            global_admin_keys: settings.global_admin_keys_file,
            collection_policy: settings.collection_policy_file,
        }))
    }
    pub(crate) async fn forward<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: Option<Vec<u8>>,
        actor: &str,
    ) -> Result<T, SyncError> {
        let bytes = self.forward_bytes(path, body, actor).await?;
        serde_json::from_slice(&bytes).map_err(|_| SyncError::Unavailable)
    }
    /// Forwards one scoped diagnostic search. The scope was decided by the server and travels in
    /// fixed headers next to the admin token; the observability service only narrows to it.
    pub(crate) async fn search(
        &self,
        body: Vec<u8>,
        actor: &str,
        kind: &str,
        subject: Option<&str>,
    ) -> Result<dto::DiagnosticSearchPage, SyncError> {
        let bytes = self
            .send(
                "/v2/observability/search",
                Some(body),
                actor,
                Some((kind, subject)),
                1_048_576,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| SyncError::Unavailable)
    }
    async fn forward_bytes(
        &self,
        path: &str,
        body: Option<Vec<u8>>,
        actor: &str,
    ) -> Result<Vec<u8>, SyncError> {
        self.send(path, body, actor, None, 65_536).await
    }
    async fn send(
        &self,
        path: &str,
        body: Option<Vec<u8>>,
        actor: &str,
        scope: Option<(&str, Option<&str>)>,
        limit: usize,
    ) -> Result<Vec<u8>, SyncError> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| SyncError::Capacity)?;
        let events = path == "/v2/observability/events";
        let traces = path == "/v1/traces";
        let token = if events { &self.ingest } else { &self.admin };
        let mut request = self.http.request(
            if body.is_some() {
                reqwest::Method::POST
            } else {
                reqwest::Method::GET
            },
            (if traces {
                &self.trace_origin
            } else {
                &self.origin
            })
            .join(path)
            .map_err(|_| SyncError::Invalid)?,
        );
        if !traces {
            request = request
                .bearer_auth(token.expose())
                .header("x-nds-actor", actor);
        }
        if let Some((kind, subject)) = scope {
            request = request.header("x-nds-scope-kind", kind);
            if let Some(subject) = subject {
                request = request.header("x-nds-scope-subject", subject);
            }
        }
        if let Some(body) = body {
            request = request
                .header(
                    "content-type",
                    if traces {
                        "application/x-protobuf"
                    } else if events {
                        "application/x-ndjson"
                    } else {
                        "application/json"
                    },
                )
                .body(body);
        }
        let mut response = request.send().await.map_err(|_| SyncError::Unavailable)?;
        if !response.status().is_success() {
            return Err(match response.status() {
                StatusCode::BAD_REQUEST => SyncError::Invalid,
                StatusCode::CONFLICT => SyncError::KeyConflict,
                _ => SyncError::Unavailable,
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(SyncError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| SyncError::Unavailable)? {
            if bytes.len() + chunk.len() > limit {
                return Err(SyncError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
pub(crate) fn gateway(state: &AppState) -> Result<&Gateway, SyncError> {
    state
        .config
        .observability
        .as_deref()
        .ok_or(SyncError::Unavailable)
}
pub(crate) async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    uri: &axum::http::Uri,
    body: &[u8],
    operator: bool,
) -> Result<
    (
        nddev_device_sync_application::sync::AuthenticatedSession,
        nddev_device_sync_application::sync::SignedRequest,
    ),
    ApiError,
> {
    use nddev_device_sync_application::identity::{
        Owner, TenantId, UserId, is_configured_operator,
    };
    let now = identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(state, headers, method, uri, body, now).await?;
    let allowed = tokio::time::timeout(crate::database::DATABASE_TIMEOUT, async {
        let identity = crate::identity::store::Store::new(
            state.database.clone().ok_or(SyncError::Unavailable)?,
        );
        let mut tx = identity
            .transaction()
            .await
            .map_err(|_| SyncError::Unavailable)?;
        let outcome = async {
            let now = crate::sync::store::authorize(
                &mut tx,
                &auth,
                &signed,
                now.max(crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?),
            )
            .await?;
            if !operator {
                return Ok(true);
            }
            let (user, tenant): (String, String) =
                sqlx::query_as("SELECT user_id,tenant_id FROM nds_owner WHERE is_bootstrap")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| SyncError::Unavailable)?;
            let configured = Owner {
                user_id: UserId::new(user).map_err(|_| SyncError::Unavailable)?,
                tenant_id: TenantId::new(tenant).map_err(|_| SyncError::Unavailable)?,
            };
            Ok(is_configured_operator(&auth, &configured, now))
        }
        .await;
        crate::sync::store::finish(tx, outcome).await
    })
    .await
    .map_err(|_| SyncError::Unavailable)??;
    if !allowed {
        tracing::warn!(
            module = "observability",
            scope = "http",
            event.name = "observability.operator.denied",
            outcome = "denied",
            user.id = auth.session.owner.user_id.as_str(),
            tenant.id = auth.session.owner.tenant_id.as_str(),
            device.id = signed.device.as_str()
        );
        return Err(ApiError::OperatorDenied);
    }
    gateway(state)?;
    Ok((auth, signed))
}

fn identifier(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v2/observability/events", post(events))
        .route("/v2/observability/traces", post(traces))
        .route("/v2/observability/status", get(status))
        .route("/v2/observability/client-policy", get(client_policy))
        .route("/v2/observability/incidents", get(incidents))
        .route(
            "/v2/observability/incidents/{id}/acknowledge",
            post(acknowledge),
        )
        .route("/v2/observability/incidents/{id}/silence", post(silence))
}
async fn events(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::IngressReceipt>, ApiError> {
    if headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        != Some("application/x-ndjson")
        || body.is_empty()
        || body.len() > 65_536
    {
        return Err(SyncError::Invalid.into());
    }
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, false).await?;
    if !state.config.telemetry_enabled {
        return Ok(Json(disabled()));
    }
    let mut normalized = Vec::new();
    let mut count = 0;
    for line in body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if count >= 32 {
            return Err(SyncError::Invalid.into());
        }
        let mut value: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| SyncError::Invalid)?;
        nddev_device_sync_telemetry::decode_event(value.clone()).map_err(|_| SyncError::Invalid)?;
        if !matches!(
            value["service.name"].as_str(),
            Some("nddev-device-sync-client" | "nddev-device-sync-agent")
        ) {
            return Err(SyncError::Invalid.into());
        }
        for (key, expected) in [
            ("user.id", auth.session.owner.user_id.as_str()),
            ("tenant.id", auth.session.owner.tenant_id.as_str()),
            ("device.id", signed.device.as_str()),
        ] {
            if value
                .get(key)
                .is_some_and(|current| current.as_str() != Some(expected))
            {
                return Err(SyncError::Denied.into());
            }
            value[key] = expected.into();
        }
        let instance = value["producer.instance_id"]
            .as_str()
            .ok_or(SyncError::Invalid)?;
        let namespaced = serde_json::to_vec(&(
            auth.session.owner.user_id.as_str(),
            auth.session.owner.tenant_id.as_str(),
            signed.device.as_str(),
            instance,
        ))
        .map_err(|_| SyncError::Invalid)?;
        value["producer.instance_id"] = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, &namespaced)
            .to_string()
            .into();
        nddev_device_sync_telemetry::decode_event(value.clone()).map_err(|_| SyncError::Invalid)?;
        serde_json::to_writer(&mut normalized, &value).map_err(|_| SyncError::Invalid)?;
        normalized.push(b'\n');
        count += 1;
    }
    if count == 0 || normalized.len() > 75_000 {
        return Err(SyncError::Invalid.into());
    }
    let receipt: dto::IngressReceipt = gateway(&state)?
        .forward(
            "/v2/observability/events",
            Some(normalized),
            signed.device.as_str(),
        )
        .await?;
    if receipt.accepted < 0
        || receipt.duplicates < 0
        || i64::from(receipt.accepted) + i64::from(receipt.duplicates) != i64::from(count)
    {
        return Err(SyncError::Unavailable.into());
    }
    tracing::info!(
        module = "telemetry",
        scope = "http",
        event.name = "telemetry.client.accepted",
        accepted_count = receipt.accepted,
        duplicate_count = receipt.duplicates,
        outcome = "accepted"
    );
    Ok(Json(receipt))
}
fn disabled() -> dto::IngressReceipt {
    dto::IngressReceipt {
        accepted: 0,
        duplicates: 0,
        export_mode: dto::ExportMode::Disabled,
    }
}
async fn traces(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::IngressReceipt>, ApiError> {
    use nddev_device_sync_telemetry::client_traces::{AuthenticatedSource, authenticated_batch};
    if headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        != Some("application/x-protobuf")
        || body.is_empty()
        || body.len() > 65_536
    {
        return Err(SyncError::Invalid.into());
    }
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, false).await?;
    if !state.config.telemetry_enabled {
        return Ok(Json(disabled()));
    }
    let gateway = gateway(&state)?;
    // The collector owns its export opt-out. Native traces must observe it too,
    // even though their binary transport goes directly to the internal Vector.
    let status: dto::ObservabilityStatus = gateway
        .forward("/v2/observability/status", None, signed.device.as_str())
        .await?;
    if matches!(status.export_mode, dto::ExportMode::Disabled) {
        return Ok(Json(disabled()));
    }
    let now = identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (body, count) = authenticated_batch(
        &body,
        AuthenticatedSource {
            tenant: auth.session.owner.tenant_id.as_str(),
            user: auth.session.owner.user_id.as_str(),
            device: signed.device.as_str(),
        },
        now.checked_mul(1_000_000).ok_or(SyncError::Unavailable)?,
    )
    .map_err(|_| SyncError::Invalid)?;
    let response = gateway
        .forward_bytes("/v1/traces", Some(body), signed.device.as_str())
        .await?;
    Ok(Json(trace_receipt(&response, count)?))
}
fn trace_receipt(response: &[u8], count: u32) -> Result<dto::IngressReceipt, SyncError> {
    use prost::Message;
    let response =
        opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse::decode(
            response,
        )
        .map_err(|_| SyncError::Unavailable)?;
    let rejected = response
        .partial_success
        .as_ref()
        .map_or(0, |partial| partial.rejected_spans);
    if rejected < 0 || rejected > i64::from(count) {
        return Err(SyncError::Unavailable);
    }
    let accepted =
        i32::try_from(i64::from(count) - rejected).map_err(|_| SyncError::Unavailable)?;
    if response
        .partial_success
        .as_ref()
        .is_some_and(|partial| !partial.error_message.is_empty())
    {
        tracing::warn!(
            module = "telemetry",
            scope = "http",
            event.name = "telemetry.traces.receiver_warning",
            rejected_count = rejected,
            outcome = if accepted == 0 {
                "rejected"
            } else {
                "accepted"
            }
        );
    }
    tracing::info!(
        module = "telemetry",
        scope = "http",
        event.name = "telemetry.traces.receipted",
        rejected_count = rejected,
        outcome = if accepted == 0 {
            "rejected"
        } else {
            "accepted"
        }
    );
    Ok(dto::IngressReceipt {
        accepted,
        duplicates: 0,
        export_mode: dto::ExportMode::Enabled,
    })
}
async fn client_policy(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<dto::ClientTelemetryPolicy>, ApiError> {
    let (_, signed) = authorize(&state, &headers, "GET", &uri, &[], false).await?;
    let status: dto::ObservabilityStatus = gateway(&state)?
        .forward("/v2/observability/status", None, signed.device.as_str())
        .await?;
    Ok(Json(dto::ClientTelemetryPolicy {
        export_mode: if state.config.telemetry_enabled {
            status.export_mode
        } else {
            dto::ExportMode::Disabled
        },
    }))
}
async fn status(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<dto::ObservabilityStatus>, ApiError> {
    let (_, signed) = authorize(&state, &headers, "GET", &uri, &[], true).await?;
    let mut status: dto::ObservabilityStatus = gateway(&state)?
        .forward("/v2/observability/status", None, signed.device.as_str())
        .await?;
    if !state.config.telemetry_enabled {
        status.export_mode = dto::ExportMode::Disabled;
    }
    Ok(Json(status))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    after: String,
}
async fn incidents(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<dto::IncidentPage>, ApiError> {
    if !identifier(&page.after) {
        return Err(SyncError::Invalid.into());
    }
    let (_, signed) = authorize(&state, &headers, "GET", &uri, &[], true).await?;
    Ok(Json(
        gateway(&state)?
            .forward(
                &format!("/v2/observability/incidents?limit=50&after={}", page.after),
                None,
                signed.device.as_str(),
            )
            .await?,
    ))
}
async fn action(
    state: &AppState,
    uri: axum::http::Uri,
    headers: HeaderMap,
    id: String,
    body: Bytes,
    kind: &str,
) -> Result<Json<dto::Incident>, ApiError> {
    if id.is_empty() || !identifier(&id) || body.len() > 1024 {
        return Err(SyncError::Invalid.into());
    }
    if kind == "silence" {
        serde_json::from_slice::<dto::SilenceAction>(&body).map_err(|_| SyncError::Invalid)?;
    } else {
        serde_json::from_slice::<dto::IncidentAction>(&body).map_err(|_| SyncError::Invalid)?;
    }
    let (_, signed) = authorize(state, &headers, "POST", &uri, &body, true).await?;
    Ok(Json(
        gateway(state)?
            .forward(
                &format!("/v2/observability/incidents/{id}/{kind}"),
                Some(body.to_vec()),
                signed.device.as_str(),
            )
            .await?,
    ))
}
async fn acknowledge(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<dto::Incident>, ApiError> {
    action(&state, uri, headers, id, body, "acknowledge").await
}
async fn silence(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<dto::Incident>, ApiError> {
    action(&state, uri, headers, id, body, "silence").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTracePartialSuccess, ExportTraceServiceResponse,
    };
    use prost::Message;

    #[tokio::test]
    async fn upstream_revision_conflict_remains_a_conflict_receipt() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let app = Router::new().route("/incident", post(|| async { StatusCode::CONFLICT }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway = Gateway {
            origin: origin.clone(),
            trace_origin: origin,
            ingest: SecretString::from_native("generated_fixture_ingest".into()),
            admin: SecretString::from_native("generated_fixture_admin".into()),
            http: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            permits: tokio::sync::Semaphore::new(1),
            global_admin_keys: None,
            collection_policy: None,
        };
        let result = gateway
            .forward_bytes("/incident", Some(b"{}".to_vec()), "fixture")
            .await;
        server.abort();
        let response = ApiError::from(result.unwrap_err()).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "operation_conflict");
    }

    fn response(rejected: i64, message: &str) -> Vec<u8> {
        ExportTraceServiceResponse {
            partial_success: Some(ExportTracePartialSuccess {
                rejected_spans: rejected,
                error_message: message.into(),
            }),
        }
        .encode_to_vec()
    }

    #[test]
    fn trace_receipts_report_full_partial_and_zero_receiver_acceptance() {
        for (bytes, accepted) in [
            (ExportTraceServiceResponse::default().encode_to_vec(), 2),
            (response(0, ""), 2),
            (response(0, "receiver warning"), 2),
            (response(1, ""), 1),
            (response(1, "receiver warning"), 1),
            (response(2, "receiver rejection"), 0),
        ] {
            let receipt = trace_receipt(&bytes, 2).unwrap();
            assert_eq!(receipt.accepted, accepted);
            assert_eq!(receipt.duplicates, 0);
            assert!(matches!(receipt.export_mode, dto::ExportMode::Enabled));
        }
    }

    #[test]
    fn invalid_trace_receiver_responses_are_not_receipts() {
        for bytes in [
            response(-1, ""),
            response(3, ""),
            response(i64::MIN, ""),
            response(i64::MAX, ""),
            vec![0x0a, 0xff],
        ] {
            assert!(matches!(
                trace_receipt(&bytes, 2),
                Err(SyncError::Unavailable)
            ));
        }
    }
}
