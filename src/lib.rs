mod admission;
pub mod browser;
pub mod config;
pub mod database;
pub mod devices;
pub mod diagnostics;
pub mod identity;
pub mod logging;
pub mod observability;
mod organizations;
pub mod passkeys;
pub mod protocol_company;
pub mod protocol_devices;
pub mod protocol_observability;
pub mod protocol_organizations;
pub mod protocol_personal;
pub mod protocol_screen;
pub mod protocol_sync;
pub mod protocol_sync3;
pub mod protocol_v2;
pub mod protocol_vault;
pub mod screen;
pub mod sync;
#[cfg(test)]
mod telemetry_test;
pub mod transport;
pub mod vault;
pub mod web;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, MatchedPath, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use database::DATABASE_TIMEOUT;
use opentelemetry::{
    Context,
    propagation::{Extractor, TextMapPropagator},
    trace::TraceContextExt,
};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use config::ServerConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub const SOURCE_COMMIT: &str = match option_env!("NDS_BUILD_COMMIT") {
    Some(value) => value,
    None => "unknown",
};

#[derive(Clone)]
pub struct AppState {
    pub config: ServerConfig,
    pub database: Option<PgPool>,
    pub identity: Option<Arc<identity::Service>>,
    pub devices: Option<Arc<devices::Service>>,
    pub sync: Option<Arc<sync::Service>>,
    pub screen: Option<Arc<screen::store::Store>>,
    pub vault: Option<Arc<vault::Service>>,
    pub passkeys: Option<Arc<passkeys::Service>>,
    pub organizations: Option<Arc<organizations::Service>>,
    requests: Arc<Semaphore>,
    pressure: Arc<admission::Pressure>,
}

impl AppState {
    pub async fn from_config(config: ServerConfig) -> Result<Self, database::DatabaseError> {
        let database = if let Some(url) = &config.database_url {
            Some(database::connect_runtime(url).await?)
        } else {
            None
        };
        let (identity, mailer) = match &config.identity {
            Some(settings) => {
                let (identity, mailer) = identity::initialize(
                    database.clone().ok_or(database::DatabaseError::Identity)?,
                    settings,
                    config.public_origin.as_ref(),
                )
                .await
                .map_err(|_| database::DatabaseError::Identity)?;
                (Some(identity), Some(mailer))
            }
            None => (None, None),
        };
        let organizations = match (&database, &config.identity, &config.public_origin, mailer) {
            (Some(pool), Some(settings), Some(_), Some(mailer)) => Some(Arc::new(
                organizations::Service::new(pool.clone(), settings.crypto.clone(), mailer),
            )),
            _ => None,
        };
        let devices = config.identity.as_ref().and_then(|identity| {
            database
                .clone()
                .map(|database| Arc::new(devices::initialize(database, identity.crypto.clone())))
        });
        let sync = config.public_origin.as_ref().and_then(|_| {
            identity.as_ref().and_then(|_| {
                database
                    .clone()
                    .map(|database| Arc::new(sync::initialize(database)))
            })
        });
        let screen = sync
            .as_ref()
            .and(config.public_origin.as_ref())
            .and_then(|origin| {
                database.clone().map(|pool| {
                    Arc::new(screen::initialize(
                        pool,
                        origin.origin().ascii_serialization(),
                    ))
                })
            });
        let vault = config.vault_wrapping_key.as_ref().and_then(|wrapping| {
            sync.as_ref().and_then(|_| {
                database
                    .clone()
                    .map(|pool| Arc::new(vault::initialize(pool, wrapping.clone())))
            })
        });
        let passkeys = match (&database, &config.public_origin, &config.identity) {
            (Some(pool), Some(origin), Some(identity)) if origin.domain().is_some() => {
                Some(Arc::new(
                    passkeys::Service::new(pool.clone(), origin, identity.crypto.clone())
                        .map_err(|_| database::DatabaseError::Identity)?,
                ))
            }
            _ => None,
        };
        Ok(Self {
            identity,
            devices,
            sync,
            screen,
            vault,
            passkeys,
            organizations,
            requests: Arc::new(Semaphore::new(config.max_requests)),
            pressure: Arc::default(),
            config,
            database,
        })
    }

    #[cfg(test)]
    pub fn test() -> Self {
        Self {
            config: ServerConfig {
                addr: "127.0.0.1:0".parse().expect("valid test address"),
                database_url: None,
                tls: None,
                version: "test".into(),
                channel: "alpha".into(),
                standards_release: "test".into(),
                source_url: "https://nddev.ai".into(),
                telemetry_enabled: true,
                public_origin: None,
                max_connections: 256,
                max_requests: 64,
                identity: None,
                vault_wrapping_key: None,
                observability: None,
                web_assets: None,
            },
            database: None,
            identity: None,
            devices: None,
            sync: None,
            screen: None,
            vault: None,
            passkeys: None,
            organizations: None,
            requests: Arc::new(Semaphore::new(64)),
            pressure: Arc::default(),
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: String,
    channel: String,
    standards_release: String,
    source_commit: &'static str,
    module_count: usize,
    telemetry_enabled: bool,
    database_configured: bool,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    database: &'static str,
}

#[derive(Serialize)]
struct SourceResponse {
    source_url: String,
    license: &'static str,
}

pub fn router(state: AppState) -> Router {
    let routes = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .route("/source", get(source))
        .route("/v2/browser", get(browser::capabilities))
        .merge(identity::http::routes())
        .merge(devices::http::routes())
        .merge(sync::routes())
        .merge(screen::routes())
        .merge(vault::routes())
        .merge(passkeys::http::routes())
        .merge(organizations::http::routes())
        .merge(observability::routes())
        .merge(diagnostics::routes());
    let routes = if state.config.web_assets.is_some() {
        routes
            .route("/", get(web::index))
            .route("/{*asset}", get(web::asset))
    } else {
        routes
    };
    routes
        .layer(DefaultBodyLimit::max(65_536))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            browser::transport,
        ))
        .layer(middleware::from_fn_with_state(state, request_trace))
}

async fn request_trace(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched");
    // The router wildcard is a template, never an actual asset path. Keep the
    // canonical bounded HTTP span grammar shared with the telemetry SDK.
    let route = if route == "/{*asset}" {
        "/{asset}"
    } else {
        route
    };
    let method = match request.method().as_str() {
        method @ ("GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT"
        | "TRACE") => method,
        _ => "OTHER",
    };
    let span = nddev_device_sync_telemetry::http_server_span(method, route)
        .expect("compiled route and normalized method");
    // Start from an empty context so malformed/missing headers cannot inherit a
    // different request's ambient parent. Parsing is owned by the W3C propagator.
    let parent = TraceContextPropagator::new()
        .extract_with_context(&Context::new(), &Headers(request.headers()));
    if span.set_parent(parent).is_err() {
        tracing::error!(module = "http", scope = "http", event.name = "http.context.unavailable", error.type = "trace_context", outcome = "error");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({"error": "server_busy"})),
        )
            .into_response();
    }
    let context = nddev_device_sync_telemetry::trace_context(&span);
    let trace_id = context.span().span_context().trace_id().to_string();
    let started = Instant::now();
    let mut response = async {
        let permit = state.requests.try_acquire();
        let response = if let Ok(_permit) = permit {
            state.pressure.recover("requests");
            tracing::debug!(event.name = "http.request.started", outcome = "started");
            match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
                Ok(response) => response,
                Err(_) => (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({"error": "request_timeout"})),
                )
                    .into_response(),
            }
        } else {
            state.pressure.reject("requests");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [("retry-after", "1")],
                Json(serde_json::json!({"error": "server_busy"})),
            )
                .into_response()
        };
        if nddev_device_sync_telemetry::finish_http_server_span(&tracing::Span::current(), response.status().as_u16()).is_err() {
            tracing::error!(module = "http", scope = "http", event.name = "http.context.unavailable", error.type = "trace_context", outcome = "error");
        }
        if response.status().is_server_error() {
            tracing::error!(
                event.name = "http.request.completed",
                error.type = "http_server_error",
                status = response.status().as_u16(),
                duration_ms = started.elapsed().as_secs_f64() * 1000.0,
                outcome = "error"
            );
        } else {
            tracing::info!(
                event.name = "http.request.completed",
                status = response.status().as_u16(),
                duration_ms = started.elapsed().as_secs_f64() * 1000.0,
                outcome = if response.status().is_client_error() {
                    "rejected"
                } else {
                    "ok"
                }
            );
        }
        response
    }
    .instrument(span)
    .await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&trace_id).expect("generated trace id"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

struct Headers<'a>(&'a axum::http::HeaderMap);
impl Extractor for Headers<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        let mut values = self.0.get_all(key).iter();
        let value = values.next()?;
        // Keep future-version/tracestate parsing bounded independently of the
        // HTTP driver's larger header budget. No value is retained or logged.
        if values.next().is_some() || value.as_bytes().len() > 512 {
            return None;
        }
        value.to_str().ok()
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    tracing::debug!(event.name = "health.read", outcome = "ok");
    Json(HealthResponse {
        status: "ok",
        service: "nddev-device-sync-server",
        version: state.config.version,
        channel: state.config.channel,
        standards_release: state.config.standards_release,
        source_commit: SOURCE_COMMIT,
        // This control plane composes no native-tool adapter manifests.
        // Keep the v1 field for existing clients; the agent owns actual inventory.
        module_count: 0,
        telemetry_enabled: state.config.telemetry_enabled,
        database_configured: state.database.is_some(),
    })
}

async fn ready(State(state): State<AppState>) -> Response {
    let Some(database) = state.database else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "degraded",
                database: "not_configured",
            }),
        )
            .into_response();
    };
    match tokio::time::timeout(
        DATABASE_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1 FROM nddev_schema_meta WHERE key = 'product' AND value = 'nddev-device-sync-server' AND EXISTS (SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value=$1)").bind(database::REQUIRED_SCHEMA_VERSION.to_string()).fetch_one(&database),
    )
    .await
    {
        Ok(Ok(_)) => Json(ReadyResponse {
            status: "ready",
            database: "ok",
        })
        .into_response(),
        failed => {
            tracing::error!(
                event.name = "database.readiness_failed",
                error.type = if failed.is_err() { "database_timeout" } else { "database_unavailable" },
                outcome = "error"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResponse {
                    status: "degraded",
                    database: "error",
                }),
            )
                .into_response()
        }
    }
}

async fn source(State(state): State<AppState>) -> Json<SourceResponse> {
    Json(SourceResponse {
        source_url: state.config.source_url,
        license: "AGPL-3.0-only",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;

    #[tokio::test]
    async fn health_exposes_pinned_product_state() {
        let (dispatch, _provider, _captured) = crate::telemetry_test::capture();
        let response = router(AppState::test())
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header(
                        "traceparent",
                        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .with_subscriber(dispatch.clone())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-request-id"],
            "0123456789abcdef0123456789abcdef"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["channel"], "alpha");
        assert_eq!(value["telemetry_enabled"], true);
        assert_eq!(value["module_count"], 0);
        let spans = _captured.0.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].span_kind, opentelemetry::trace::SpanKind::Server);
        assert_eq!(spans[0].parent_span_id.to_string(), "0123456789abcdef");
        assert!(spans[0].parent_span_is_remote);
        assert_eq!(
            spans[0].span_context.trace_id().to_string(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[tokio::test]
    async fn readiness_is_honest_without_database() {
        let (dispatch, _provider, _captured) = crate::telemetry_test::capture();
        let response = router(AppState::test())
            .oneshot(Request::get("/v1/ready").body(Body::empty()).unwrap())
            .with_subscriber(dispatch.clone())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let spans = _captured.0.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(matches!(
            spans[0].status,
            opentelemetry::trace::Status::Error { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_handler_is_cancelled_with_a_correlated_timeout() {
        let (dispatch, _provider, _captured) = crate::telemetry_test::capture();
        let state = AppState::test();
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    StatusCode::OK
                }),
            )
            .layer(middleware::from_fn_with_state(state, request_trace));
        let response = app
            .oneshot(Request::get("/slow").body(Body::empty()).unwrap())
            .with_subscriber(dispatch.clone())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["x-request-id"].to_str().unwrap().len(),
            32
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "request_timeout"
        );
    }

    #[tokio::test]
    async fn invalid_flags_do_not_control_response_correlation() {
        let (dispatch, _provider, _captured) = crate::telemetry_test::capture();
        let response = router(AppState::test())
            .oneshot(
                Request::get("/v1/health")
                    .header(
                        "traceparent",
                        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-zz",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .with_subscriber(dispatch.clone())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(
            response.headers()["x-request-id"],
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[tokio::test]
    async fn success_and_error_responses_disable_http_storage() {
        let (dispatch, _provider, _captured) = crate::telemetry_test::capture();
        for (path, status) in [
            ("/v1/health", StatusCode::OK),
            ("/source", StatusCode::OK),
            ("/v1/ready", StatusCode::SERVICE_UNAVAILABLE),
            ("/missing", StatusCode::NOT_FOUND),
        ] {
            let response = router(AppState::test())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .with_subscriber(dispatch.clone())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["cache-control"], "no-store", "{path}");
        }
    }
    #[tokio::test]
    async fn native_propagation_preserves_valid_parents_and_replaces_invalid_headers() {
        let (dispatch, _provider, _captured) = crate::telemetry_test::capture();
        let trace = "0123456789abcdef0123456789abcdef";
        for (header, valid) in [
            (
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-00",
                true,
            ),
            (
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-02",
                true,
            ),
            (
                "01-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra",
                true,
            ),
            (
                "00-00000000000000000000000000000000-0123456789abcdef-01",
                false,
            ),
            (
                "ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                false,
            ),
            (
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-zz",
                false,
            ),
            (
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-FF",
                false,
            ),
            (
                "00-0123456789ABCDEF0123456789abcdef-0123456789abcdef-01",
                false,
            ),
            (
                "00-0123456789abcdef0123456789abcdef-0123456789ABCDEF-01",
                false,
            ),
            (
                "00-0123456789abcdef0123456789abcdef-0000000000000000-01",
                false,
            ),
            (
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra",
                false,
            ),
        ] {
            let response = router(AppState::test())
                .oneshot(
                    Request::get("/v1/health")
                        .header("traceparent", header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .with_subscriber(dispatch.clone())
                .await
                .unwrap();
            let observed = response.headers()["x-request-id"].to_str().unwrap();
            assert_eq!(
                observed == trace,
                valid,
                "propagator accepted/rejected {header}"
            );
            assert_ne!(observed, "00000000000000000000000000000000");
            assert_eq!(observed.len(), 32);
        }
        let oversized = format!("01-{trace}-0123456789abcdef-01-{}", "a".repeat(512));
        let response = router(AppState::test())
            .oneshot(
                Request::get("/v1/health")
                    .header("traceparent", oversized)
                    .body(Body::empty())
                    .unwrap(),
            )
            .with_subscriber(dispatch.clone())
            .await
            .unwrap();
        assert_ne!(
            response.headers()["x-request-id"],
            trace,
            "oversized context header"
        );
        let response = router(AppState::test())
            .oneshot(
                Request::get("/v1/health")
                    .header(
                        "traceparent",
                        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                    )
                    .header(
                        "traceparent",
                        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .with_subscriber(dispatch)
            .await
            .unwrap();
        assert_ne!(
            response.headers()["x-request-id"],
            trace,
            "ambiguous repeated header"
        );
    }
}
