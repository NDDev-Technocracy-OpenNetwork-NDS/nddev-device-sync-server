use super::{Exchange, Service};
use crate::{
    AppState,
    admission::PeerAddress,
    identity::{
        self,
        http::{ApiError, bearer},
    },
    protocol_v2 as dto,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use nddev_device_sync_application::identity::{
    IdentityCrypto, IdentityError, IdentityStore, POLL_RATE, START_RATE,
};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v2/auth/passkeys/start", post(start))
        .route("/v2/auth/passkeys", get(list))
        .route("/v2/auth/passkeys/{id}", delete(revoke))
        .route("/v2/auth/passkeys/exchange", post(exchange))
        .route("/v2/auth/passkeys/browser", get(browser))
        .route("/v2/auth/passkeys/options", get(options))
        .route(
            "/v2/auth/passkeys/verify",
            post(verify).layer(DefaultBodyLimit::max(16_384)),
        )
}
fn service(state: &AppState) -> Result<&Service, IdentityError> {
    state.passkeys.as_deref().ok_or(IdentityError::Unavailable)
}
async fn limit(
    state: &AppState,
    source: &PeerAddress,
    action: &'static str,
    policy: nddev_device_sync_application::identity::RatePolicy,
    now: u64,
) -> Result<(), IdentityError> {
    let crypto = &state
        .config
        .identity
        .as_ref()
        .ok_or(IdentityError::Unavailable)?
        .crypto;
    let key = crypto.protect(action, &[source.0.to_string().as_bytes()]);
    crate::identity::store::Store::new(state.database.clone().ok_or(IdentityError::Unavailable)?)
        .admit_source(key, policy, now)
        .await
}
async fn start(
    State(state): State<AppState>,
    Extension(source): Extension<PeerAddress>,
    headers: HeaderMap,
    Json(input): Json<dto::PasskeyRequest>,
) -> Result<Json<dto::PasskeyStart>, ApiError> {
    let now = identity::now_ms()?;
    limit(&state, &source, "passkey_start", START_RATE, now).await?;
    let auth = if input.registration {
        Some(
            state
                .identity
                .as_ref()
                .ok_or(IdentityError::Unavailable)?
                .authenticate(bearer(&headers)?, now)
                .await?,
        )
    } else {
        None
    };
    let result = service(&state)?
        .start(auth, input.email.as_deref(), now)
        .await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.passkey.started",
        outcome = "pending"
    );
    Ok(Json(result))
}
async fn exchange(
    State(state): State<AppState>,
    Extension(source): Extension<PeerAddress>,
    browser: Option<Extension<crate::browser::BrowserRequest>>,
    Json(input): Json<dto::GithubExchangeRequest>,
) -> Result<Response, ApiError> {
    let now = identity::now_ms()?;
    limit(&state, &source, "passkey_poll", POLL_RATE, now).await?;
    Ok(
        match service(&state)?
            .exchange(&input.flow_id, &input.exchange_token, now)
            .await?
        {
            Exchange::Pending => (
                axum::http::StatusCode::ACCEPTED,
                Json(dto::PasskeyStatus {
                    status: dto::PasskeyStatusStatus::Pending,
                    retry_after_seconds: 2,
                }),
            )
                .into_response(),
            Exchange::Registered => Json(dto::PasskeyStatus {
                status: dto::PasskeyStatusStatus::Registered,
                retry_after_seconds: 0,
            })
            .into_response(),
            Exchange::Session(session) => identity::http::issued(session, browser.is_some())?,
        },
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    flow_id: String,
}
fn cookie(headers: &HeaderMap) -> Result<Option<&str>, IdentityError> {
    // HTTP/2 may split cookies across fields (RFC 9113 section 8.2.3).
    // Reject duplicate credentials, not unrelated session-cookie fields.
    if headers
        .get_all("cookie")
        .iter()
        .map(HeaderValue::len)
        .sum::<usize>()
        > 8192
    {
        return Err(IdentityError::Denied);
    }
    let mut cookie = None;
    for field in headers.get_all("cookie") {
        let field = field.to_str().map_err(|_| IdentityError::Denied)?;
        for part in field.split(';') {
            if let Some(value) = part.trim().strip_prefix("nds_passkey=") {
                if cookie.is_some() || !super::opaque(value) {
                    return Err(IdentityError::Denied);
                }
                cookie = Some(value);
            }
        }
    }
    Ok(cookie)
}
fn proof(headers: &HeaderMap) -> Result<(&str, &str), IdentityError> {
    if headers.get_all("x-nds-csrf").iter().count() != 1 {
        return Err(IdentityError::Denied);
    }
    let cookie = cookie(headers)?.ok_or(IdentityError::Denied)?;
    let csrf = headers
        .get("x-nds-csrf")
        .and_then(|value| value.to_str().ok())
        .ok_or(IdentityError::Denied)?;
    if !super::opaque(csrf) {
        return Err(IdentityError::Denied);
    }
    Ok((cookie, csrf))
}
async fn options(
    State(state): State<AppState>,
    Query(id): Query<Id>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (cookie, csrf) = proof(&headers)?;
    Ok(Json(service(&state)?.options(&id.flow_id, cookie, csrf)?))
}
async fn verify(
    State(state): State<AppState>,
    Query(id): Query<Id>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if headers.get_all("origin").iter().count() != 1 {
        return Err(IdentityError::Denied.into());
    }
    let origin = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .ok_or(IdentityError::Denied)?;
    if origin != service(&state)?.origin.origin().ascii_serialization() {
        return Err(IdentityError::Denied.into());
    }
    let (cookie, csrf) = proof(&headers)?;
    service(&state)?
        .finish(&id.flow_id, cookie, csrf, value, identity::now_ms()?)
        .await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.passkey.verified",
        outcome = "ok"
    );
    Ok(Json(serde_json::json!({"status":"verified"})))
}
async fn browser(
    State(state): State<AppState>,
    Query(id): Query<Id>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let service = service(&state)?;
    let previous_cookie = cookie(&headers)?;
    let (cookie, csrf, code, registration) = service.browser(&id.flow_id, previous_cookie)?;
    let russian = headers
        .get("accept-language")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("ru"));
    let title = if russian {
        "Ключ доступа NDS"
    } else {
        "NDS passkey"
    };
    let instruction = if russian {
        "Сравните код с приложением NDS и продолжайте только при совпадении."
    } else {
        "Compare this code with the NDS application and continue only when it matches."
    };
    let action = if registration {
        if russian {
            "Создать ключ доступа"
        } else {
            "Create passkey"
        }
    } else if russian {
        "Войти с ключом доступа"
    } else {
        "Sign in with passkey"
    };
    let settings =
        serde_json::json!({"id":id.flow_id,"csrf":csrf,"registration":registration}).to_string();
    let nonce = state
        .config
        .identity
        .as_ref()
        .ok_or(IdentityError::Unavailable)?
        .crypto
        .token()?
        .into_inner();
    let body = format!(
        "<!doctype html><html lang=\"{}\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>{title}</title><body><h1>NDDev OpenNetwork · {title}</h1><p>{instruction}</p><p><strong>{code}</strong></p><button id=\"continue\">{action}</button><p id=\"result\" role=\"status\"></p><a href=\"https://nddev.ai\">nddev.ai</a><script nonce=\"{nonce}\">const settings={settings};{}</script></body></html>",
        if russian { "ru" } else { "en" },
        include_str!("browser.js")
    );
    let mut response = Html(body).into_response();
    response.headers_mut().insert("content-security-policy",HeaderValue::from_str(&format!("default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")).map_err(|_|IdentityError::Unavailable)?);
    let secure = if service.origin.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().insert("set-cookie",HeaderValue::from_str(&format!("nds_passkey={cookie}; Path=/v2/auth/passkeys; HttpOnly; SameSite=Strict; Max-Age=300{secure}")).map_err(|_|IdentityError::Unavailable)?);
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    Ok(response)
}

async fn owner(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<nddev_device_sync_application::identity::AuthenticatedSession, IdentityError> {
    state
        .identity
        .as_ref()
        .ok_or(IdentityError::Unavailable)?
        .authenticate(bearer(headers)?, identity::now_ms()?)
        .await
}
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<dto::PasskeyList>, ApiError> {
    let auth = owner(&state, &headers).await?;
    let passkeys = service(&state)?
        .list(&auth)
        .await?
        .into_iter()
        .map(|(id, created)| {
            let created_at =
                time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(created) * 1_000_000)
                    .map_err(|_| IdentityError::Unavailable)?
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|_| IdentityError::Unavailable)?;
            Ok(dto::PasskeyInfo { id, created_at })
        })
        .collect::<Result<Vec<_>, IdentityError>>()?;
    Ok(Json(dto::PasskeyList { passkeys }))
}
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    browser: Option<Extension<crate::browser::BrowserRequest>>,
) -> Result<Response, ApiError> {
    let auth = owner(&state, &headers).await?;
    let (current_session_revoked, passkey_available) = service(&state)?
        .revoke(&auth, &id, identity::now_ms()?)
        .await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.passkey.revoked",
        outcome = "ok"
    );
    let mut response = Json(dto::PasskeyRevocation {
        current_session_revoked,
        passkey_available,
    })
    .into_response();
    if browser.is_some() && current_session_revoked {
        crate::browser::clear_session(&mut response);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_proof_accepts_http2_cookie_fields_with_a_browser_session() {
        let cookie = "C".repeat(43);
        let csrf = "S".repeat(43);
        let mut headers = HeaderMap::new();
        headers.append(
            "cookie",
            HeaderValue::from_static("__Host-nds-session=unrelated"),
        );
        headers.append(
            "cookie",
            HeaderValue::from_str(&format!("nds_passkey={cookie}")).unwrap(),
        );
        headers.insert("x-nds-csrf", HeaderValue::from_str(&csrf).unwrap());
        assert_eq!(proof(&headers).unwrap(), (cookie.as_str(), csrf.as_str()));
    }

    #[test]
    fn passkey_proof_rejects_ambiguous_or_excessive_credentials() {
        let cookie = format!("nds_passkey={}", "C".repeat(43));
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_str(&cookie).unwrap());
        headers.insert(
            "x-nds-csrf",
            HeaderValue::from_str(&"S".repeat(43)).unwrap(),
        );
        assert!(proof(&headers).is_ok());
        let mut duplicate = headers.clone();
        duplicate.append("cookie", HeaderValue::from_str(&cookie).unwrap());
        assert!(proof(&duplicate).is_err());
        let mut duplicate = headers.clone();
        duplicate.insert(
            "cookie",
            HeaderValue::from_str(&format!("{cookie}; {cookie}")).unwrap(),
        );
        assert!(proof(&duplicate).is_err());
        let mut duplicate = headers.clone();
        duplicate.append("x-nds-csrf", headers["x-nds-csrf"].clone());
        assert!(proof(&duplicate).is_err());
        let mut excessive = headers.clone();
        excessive.insert(
            "cookie",
            HeaderValue::from_str(&format!("other={}; {cookie}", "x".repeat(8192))).unwrap(),
        );
        assert!(proof(&excessive).is_err());
        headers.remove("cookie");
        assert!(proof(&headers).is_err());
    }
}
