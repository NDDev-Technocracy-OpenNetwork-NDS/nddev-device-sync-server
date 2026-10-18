use super::{Service, now_ms};
use crate::{AppState, admission::PeerAddress, protocol_v2 as dto};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Extension, Form, OriginalUri, Query, State,
        rejection::{FormRejection, JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use nddev_device_sync_application::identity::{
    AuthMethod, BrowserApproval, GITHUB_LIFETIME_MS, GITHUB_POLL_MS, GithubCallback,
    GithubExchange, IdentityError, InvitationClaim, InvitationId, IssuedSession, Locale,
    SecretText, Session,
};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v2/auth/methods", get(methods))
        .route("/v2/auth/email/challenges", post(email_challenge))
        .route(
            "/v2/auth/invitations/challenges",
            post(invitation_challenge),
        )
        .route("/v2/auth/email/verify", post(email_verify))
        .route("/v2/auth/github/start", post(github_start))
        .route("/v2/auth/github/callback", get(github_callback))
        .route("/v2/auth/github/approve", post(github_approve))
        .route("/v2/auth/github/exchange", post(github_exchange))
        .route("/v2/session", get(session).delete(revoke))
        .route("/v2/session/renew", post(renew_session))
}

#[derive(Debug)]
pub struct ApiError(IdentityError);
impl From<IdentityError> for ApiError {
    fn from(error: IdentityError) -> Self {
        Self(error)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self.0 {
            IdentityError::InvalidInput => {
                (StatusCode::BAD_REQUEST, dto::ErrorEnum::InvalidRequest)
            }
            IdentityError::Denied => (
                StatusCode::UNAUTHORIZED,
                dto::ErrorEnum::AuthenticationFailed,
            ),
            IdentityError::RecentAuthenticationRequired => (
                StatusCode::FORBIDDEN,
                dto::ErrorEnum::RecentAuthenticationRequired,
            ),
            IdentityError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, dto::ErrorEnum::RateLimited)
            }
            IdentityError::Capacity => {
                (StatusCode::SERVICE_UNAVAILABLE, dto::ErrorEnum::ServerBusy)
            }
            IdentityError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                dto::ErrorEnum::DependencyUnavailable,
            ),
        };
        tracing::warn!(module = "identity", scope = "http", event.name="identity.request.rejected",error.type=%self.0,outcome="rejected");
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

fn service(state: &AppState) -> Result<&Service, ApiError> {
    state
        .identity
        .as_deref()
        .ok_or(IdentityError::Unavailable.into())
}
pub(crate) fn peer(peer: Option<Extension<PeerAddress>>) -> Result<Vec<u8>, IdentityError> {
    // Only the accepted socket peer enters abuse controls. Neither ports nor
    // Forwarded/X-Forwarded-For are trusted by this direct-origin server.
    match peer.ok_or(IdentityError::Unavailable)?.0.0 {
        std::net::IpAddr::V4(ip) => Ok(ip.octets().to_vec()),
        std::net::IpAddr::V6(ip) => Ok(ip
            .to_ipv4_mapped()
            .map(|ip| ip.octets().to_vec())
            .unwrap_or_else(|| ip.octets().to_vec())),
    }
}
pub(crate) fn locale(headers: &HeaderMap) -> Locale {
    for language in headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("en")
        .split(',')
    {
        let language = language.trim().split([';', '-']).next().unwrap_or("en");
        if language.eq_ignore_ascii_case("ru") {
            return Locale::Ru;
        }
        if language.eq_ignore_ascii_case("en") {
            return Locale::En;
        }
    }
    Locale::En
}
pub(crate) fn bearer(headers: &HeaderMap) -> Result<&str, IdentityError> {
    if headers.get_all("authorization").iter().count() != 1 {
        return Err(IdentityError::Denied);
    }
    let (scheme, token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .ok_or(IdentityError::Denied)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(IdentityError::Denied);
    }
    Ok(token)
}
fn session_dto(session: Session) -> Result<dto::Session, ApiError> {
    let expires =
        time::OffsetDateTime::from_unix_timestamp_nanos(session.expires_at_ms as i128 * 1_000_000)
            .map_err(|_| IdentityError::Unavailable)?;
    Ok(dto::Session {
        user_id: session.owner.user_id.as_str().into(),
        tenant_id: session.owner.tenant_id.as_str().into(),
        auth_method: match session.method {
            AuthMethod::EmailOtp => dto::AuthMethod::EmailOtp,
            AuthMethod::Github => dto::AuthMethod::Github,
            AuthMethod::Passkey => dto::AuthMethod::Passkey,
        },
        expires_at: expires
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| IdentityError::Unavailable)?,
    })
}
pub(crate) fn issued(value: IssuedSession, browser: bool) -> Result<Response, ApiError> {
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.session.issued",
        auth_method = match value.session.method {
            AuthMethod::EmailOtp => "email_otp",
            AuthMethod::Github => "github",
            AuthMethod::Passkey => "passkey",
        },
        outcome = "ok"
    );
    if browser {
        let token = zeroize::Zeroizing::new(value.token.into_inner());
        let cookie =
            crate::browser::session_cookie(&token, value.session.expires_at_ms, now_ms()?)?;
        let mut response = Json(dto::BrowserSessionIssued {
            session: session_dto(value.session)?,
        })
        .into_response();
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
        Ok(response)
    } else {
        Ok(Json(dto::SessionIssued {
            session: session_dto(value.session)?,
            session_token: value.token.into_inner(),
        })
        .into_response())
    }
}
async fn methods(State(state): State<AppState>) -> Json<dto::AuthMethods> {
    let (email, github) = state
        .identity
        .as_ref()
        .map(|service| service.methods())
        .unwrap_or((false, false));
    let availability = |available| {
        if available {
            dto::MethodAvailability::Available
        } else {
            dto::MethodAvailability::Unavailable
        }
    };
    Json(dto::AuthMethods {
        email_otp: availability(email),
        github: availability(github),
        passkey: availability(match &state.passkeys {
            Some(service) => service.available().await.unwrap_or(false),
            None => false,
        }),
    })
}
async fn email_challenge(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    headers: HeaderMap,
    body: Result<Json<dto::EmailChallengeRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(body) = body.map_err(|_| IdentityError::InvalidInput)?;
    request_email_challenge(&state, source, &headers, &body.email, None).await
}
async fn invitation_challenge(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    headers: HeaderMap,
    body: Result<Json<dto::InvitationEmailChallengeRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(body) = body.map_err(|_| IdentityError::InvalidInput)?;
    let claim = InvitationClaim {
        id: InvitationId::new(body.invitation_id).map_err(|_| IdentityError::InvalidInput)?,
        token: SecretText::new(body.invitation_token),
    };
    request_email_challenge(&state, source, &headers, &body.email, Some(claim)).await
}
async fn request_email_challenge(
    state: &AppState,
    source: Option<Extension<PeerAddress>>,
    headers: &HeaderMap,
    email: &str,
    invitation: Option<InvitationClaim>,
) -> Result<(StatusCode, Json<dto::EmailChallenge>), ApiError> {
    if email.len() > 254 || email.trim() != email {
        return Err(IdentityError::InvalidInput.into());
    }
    let peer = peer(source)?;
    let service = service(state)?;
    let receipt = match invitation {
        Some(claim) => {
            service
                .request_invitation_email(email, claim, &peer, locale(headers), now_ms()?)
                .await?
        }
        None => {
            service
                .request_email(email, &peer, locale(headers), now_ms()?)
                .await?
        }
    };
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.email.requested",
        outcome = "accepted"
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(dto::EmailChallenge {
            challenge_id: receipt.id,
            expires_in_seconds: receipt.expires_in_seconds as i32,
            resend_after_seconds: receipt.resend_after_seconds as i32,
        }),
    ))
}
async fn email_verify(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    browser: Option<Extension<crate::browser::BrowserRequest>>,
    body: Result<Json<dto::EmailVerifyRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|_| IdentityError::InvalidInput)?;
    issued(
        service(&state)?
            .verify_email(&body.challenge_id, &body.code, &peer(source)?, now_ms()?)
            .await?,
        browser.is_some(),
    )
}
async fn github_start(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    headers: HeaderMap,
) -> Result<Json<dto::GithubStart>, ApiError> {
    let start = service(&state)?
        .start_github(&peer(source)?, locale(&headers), now_ms()?)
        .await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.github.started",
        outcome = "pending"
    );
    Ok(Json(dto::GithubStart {
        flow_id: start.flow_id,
        authorization_url: start.authorization_url,
        exchange_token: start.exchange_token.into_inner(),
        verification_code: start.verification_code,
        expires_in_seconds: (GITHUB_LIFETIME_MS / 1000) as i32,
        poll_after_seconds: (GITHUB_POLL_MS / 1000) as i32,
    }))
}

// Provider-owned callback query, not an NDS JSON DTO. Error-description fields
// may be added by GitHub and are ignored; duplicate known fields are rejected by serde.
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
fn page(locale: Locale, body: String) -> Response {
    let language = match locale {
        Locale::En => "en",
        Locale::Ru => "ru",
    };
    let mut response = Html(format!("<!doctype html><html lang=\"{language}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>NDDev OpenNetwork</title></head><body>{body}<p><a href=\"https://nddev.ai\" rel=\"noreferrer\">NDDev OpenNetwork</a></p></body></html>")).into_response();
    for (header, value) in [
        (
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
        // Native form POST needs its Origin for CSRF validation. Unlike
        // no-referrer, strict-origin preserves it without exposing callback queries.
        ("referrer-policy", "strict-origin"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
    ] {
        response
            .headers_mut()
            .insert(header, HeaderValue::from_static(value));
    }
    response
}
fn completed_page(locale: Locale) -> Response {
    page(
        locale,
        match locale {
            Locale::En => {
                "<h1>Return to NDS</h1><p>Continue in the application that requested sign-in.</p>"
            }
            Locale::Ru => {
                "<h1>Вернитесь в NDS</h1><p>Продолжите в приложении, запросившем вход.</p>"
            }
        }
        .into(),
    )
}
fn approval_page(approval: BrowserApproval) -> Result<Response, ApiError> {
    use nddev_device_sync_application::identity::valid_opaque;
    if approval.display.verification_code.len() != 8
        || !approval
            .display
            .verification_code
            .bytes()
            .all(|b| b.is_ascii_digit())
        || !valid_opaque(&approval.flow_id)
        || !valid_opaque(approval.csrf.expose())
        || !valid_opaque(approval.cookie.expose())
    {
        return Err(IdentityError::Unavailable.into());
    }
    let (title, instruction, approve, cancel) = match approval.display.locale {
        Locale::En => (
            "Confirm NDS sign-in",
            "Approve only if you started this sign-in and this code matches your NDS application.",
            "Approve",
            "Cancel",
        ),
        Locale::Ru => (
            "Подтвердите вход в NDS",
            "Подтверждайте только начатый вами вход, если код совпадает с кодом в приложении NDS.",
            "Подтвердить",
            "Отмена",
        ),
    };
    // Interpolation is limited to generated alphabets and fixed localized text.
    let mut response = page(
        approval.display.locale,
        format!(
            "<h1>{title}</h1><p>{instruction}</p><p><strong>{}</strong></p><form method=\"post\" action=\"/v2/auth/github/approve\"><input type=\"hidden\" name=\"flow_id\" value=\"{}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button name=\"decision\" value=\"approve\">{approve}</button><button name=\"decision\" value=\"deny\">{cancel}</button></form>",
            approval.display.verification_code,
            approval.flow_id,
            approval.csrf.expose()
        ),
    );
    let seconds = approval.display.expires_at_ms.saturating_sub(now_ms()?) / 1000;
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "__Host-nds-approval={}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
            approval.cookie.expose(),
            seconds.min(300)
        ))
        .map_err(|_| IdentityError::Unavailable)?,
    );
    Ok(response)
}
async fn github_callback(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    query: Result<Query<Callback>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| IdentityError::InvalidInput)?;
    if query.code.is_some() == query.error.is_some()
        || query
            .error
            .as_ref()
            .is_some_and(|error| error.is_empty() || error.len() > 128)
    {
        return Err(IdentityError::InvalidInput.into());
    }
    match service(&state)?
        .github_callback(
            &query.state,
            query.code.as_deref(),
            &peer(source)?,
            now_ms()?,
        )
        .await?
    {
        GithubCallback::Approval(approval) => {
            tracing::info!(
                module = "identity",
                scope = "http",
                event.name = "identity.github.awaiting_approval",
                outcome = "pending"
            );
            approval_page(approval)
        }
        GithubCallback::Complete(locale) => {
            tracing::info!(
                module = "identity",
                scope = "http",
                event.name = "identity.github.denied",
                outcome = "rejected"
            );
            Ok(completed_page(locale))
        }
    }
}
fn approval_cookie(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut found = None;
    for header in headers.get_all("cookie") {
        for pair in header
            .to_str()
            .map_err(|_| IdentityError::Denied)?
            .split(';')
        {
            if let Some(value) = pair.trim().strip_prefix("__Host-nds-approval=")
                && found.replace(value).is_some()
            {
                return Err(IdentityError::Denied.into());
            }
        }
    }
    found.ok_or(IdentityError::Denied.into())
}
async fn github_approve(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    headers: HeaderMap,
    form: Result<Form<dto::GithubApprovalForm>, FormRejection>,
) -> Result<Response, ApiError> {
    let Form(form) = form.map_err(|_| IdentityError::InvalidInput)?;
    let github = state
        .config
        .identity
        .as_ref()
        .and_then(|identity| identity.github.as_ref())
        .ok_or(IdentityError::Unavailable)?;
    if headers.get_all("origin").iter().count() != 1
        || headers.get("origin").and_then(|value| value.to_str().ok())
            != Some(github.callback.origin().ascii_serialization().as_str())
    {
        return Err(IdentityError::Denied.into());
    }
    let permit = matches!(form.decision, dto::Decision::Approve);
    let locale = service(&state)?
        .approve_github(
            &form.flow_id,
            approval_cookie(&headers)?,
            &form.csrf_token,
            permit,
            &peer(source)?,
            now_ms()?,
        )
        .await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.github.browser_decision",
        outcome = if permit { "approved" } else { "denied" }
    );
    let mut response = completed_page(locale);
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_static(
            "__Host-nds-approval=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        ),
    );
    Ok(response)
}
async fn github_exchange(
    State(state): State<AppState>,
    source: Option<Extension<PeerAddress>>,
    browser: Option<Extension<crate::browser::BrowserRequest>>,
    body: Result<Json<dto::GithubExchangeRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|_| IdentityError::InvalidInput)?;
    match service(&state)?
        .exchange_github(
            &body.flow_id,
            &body.exchange_token,
            &peer(source)?,
            now_ms()?,
        )
        .await?
    {
        GithubExchange::Pending => Ok((
            StatusCode::ACCEPTED,
            Json(dto::GithubPending {
                status: dto::GithubPendingStatus::Pending,
                retry_after_seconds: (GITHUB_POLL_MS / 1000) as i32,
            }),
        )
            .into_response()),
        GithubExchange::Session(session) => issued(session, browser.is_some()),
    }
}
async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<dto::Session>, ApiError> {
    Ok(Json(session_dto(
        service(&state)?
            .session(bearer(&headers)?, now_ms()?)
            .await?,
    )?))
}

async fn renew_session(
    State(state): State<AppState>,
    browser: Option<Extension<crate::browser::BrowserRequest>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, crate::sync::http::ApiError> {
    use nddev_device_sync_application::sync::SyncError;
    if !body.is_empty() || uri.query().is_some() {
        return Err(SyncError::Invalid.into());
    }
    let now = now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let renewed = state
        .identity
        .as_ref()
        .ok_or(SyncError::Unavailable)?
        .renew_session(&auth, &signed, now)
        .await?;
    let verified = time::OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(renewed.verified_at_ms) * 1_000_000,
    )
    .map_err(|_| SyncError::Unavailable)?;
    let expires_at_ms = renewed.session.expires_at_ms;
    let mut response = Json(dto::SessionRenewal {
        session: session_dto(renewed.session).map_err(|_| SyncError::Unavailable)?,
        verified_at: verified
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| SyncError::Unavailable)?,
        authorization_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(renewed.authorization_id),
    })
    .into_response();
    if browser.is_some() {
        let cookie = crate::browser::session_cookie(
            bearer(&headers).map_err(|_| SyncError::Denied)?,
            expires_at_ms,
            now_ms()
                .map_err(|_| SyncError::Unavailable)?
                .max(renewed.verified_at_ms),
        )
        .map_err(|_| SyncError::Unavailable)?;
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
    tracing::info!(module="identity",scope="http",event.name="identity.session.renewed",user.id=%auth.session.owner.user_id.as_str(),tenant.id=%auth.session.owner.tenant_id.as_str(),device.id=%signed.device.as_str(),outcome="ok");
    Ok(response)
}

async fn revoke(State(state): State<AppState>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    service(&state)?
        .revoke(bearer(&headers)?, now_ms()?)
        .await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.session.revoked",
        outcome = "ok"
    );
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use nddev_device_sync_application::identity::{ApprovalDisplay, SecretText};
    #[tokio::test]
    async fn localized_browser_consent_has_no_script_and_strict_cookie_policy() {
        for (language, expected, label) in [
            (Locale::En, "Confirm NDS sign-in", "en"),
            (Locale::Ru, "Подтвердите вход в NDS", "ru"),
        ] {
            let response = approval_page(BrowserApproval {
                flow_id: "a".repeat(43),
                display: ApprovalDisplay {
                    verification_code: "12345678".into(),
                    expires_at_ms: now_ms().unwrap() + 300_000,
                    locale: language,
                },
                cookie: SecretText::new("b".repeat(43)),
                csrf: SecretText::new("c".repeat(43)),
            })
            .unwrap();
            let cookie = response.headers()["set-cookie"].to_str().unwrap();
            for attribute in [
                "__Host-nds-approval=",
                "Secure",
                "HttpOnly",
                "SameSite=Strict",
                "Path=/",
            ] {
                assert!(cookie.contains(attribute));
            }
            assert!(
                response.headers()["content-security-policy"]
                    .to_str()
                    .unwrap()
                    .contains("frame-ancestors 'none'")
            );
            assert_eq!(response.headers()["referrer-policy"], "strict-origin");
            let body = String::from_utf8(
                to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(body.contains(expected) && body.contains(&format!("lang=\"{label}\"")));
            assert!(body.contains("method=\"post\"") && body.contains("name=\"csrf_token\""));
            assert!(body.contains("href=\"https://nddev.ai\" rel=\"noreferrer\""));
            assert!(!body.contains("<script") && !body.contains(&"b".repeat(43)));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept-language",
            HeaderValue::from_static("ru-RU,ru;q=0.9,en;q=0.8"),
        );
        assert_eq!(locale(&headers), Locale::Ru);
        headers.insert("accept-language", HeaderValue::from_static("en"));
        assert_eq!(locale(&headers), Locale::En);
    }
}
