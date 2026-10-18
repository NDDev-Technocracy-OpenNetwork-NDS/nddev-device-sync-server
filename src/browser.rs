//! Same-origin browser transport adapter. It does not replace identity use cases,
//! device proof, the operation protocol or server-side authorization.
use crate::{AppState, identity::http::ApiError, protocol_v2 as dto};
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use nddev_device_sync_application::identity::{IdentityError, SESSION_LIFETIME_MS};
use zeroize::Zeroizing;

const SELECTOR: &str = "x-nds-client";
const COOKIE: &str = "__Host-nds-session";

#[derive(Clone, Copy)]
pub struct BrowserRequest;

fn token_valid(token: &str) -> bool {
    (43..=128).contains(&token.len())
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

fn credential(headers: &HeaderMap) -> Result<Option<Zeroizing<String>>, IdentityError> {
    if headers
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::len)
        .sum::<usize>()
        > 8192
    {
        return Err(IdentityError::InvalidInput);
    }
    let mut token = None;
    for value in headers.get_all(header::COOKIE) {
        let value = value.to_str().map_err(|_| IdentityError::InvalidInput)?;
        if value.len() > 8192 {
            return Err(IdentityError::InvalidInput);
        }
        for part in value.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == COOKIE {
                if token.is_some() || !token_valid(value) {
                    return Err(IdentityError::InvalidInput);
                }
                token = Some(Zeroizing::new(value.to_owned()));
            }
        }
    }
    Ok(token)
}

fn validate(method: &Method, headers: &HeaderMap, origin: &str) -> Result<(), IdentityError> {
    if headers.get_all(SELECTOR).iter().count() != 1
        || headers.get(SELECTOR).is_none_or(|v| v != "browser")
        || headers.contains_key(header::AUTHORIZATION)
        || headers.get_all(header::ORIGIN).iter().count() > 1
        || headers.get_all("sec-fetch-site").iter().count() > 1
        || headers
            .get("sec-fetch-site")
            .is_some_and(|v| v != "same-origin")
    {
        return Err(IdentityError::InvalidInput);
    }
    let supplied_origin = headers.get(header::ORIGIN);
    if supplied_origin.is_some_and(|v| v.as_bytes() != origin.as_bytes())
        || (!matches!(*method, Method::GET | Method::HEAD) && supplied_origin.is_none())
    {
        return Err(IdentityError::InvalidInput);
    }
    Ok(())
}

pub async fn capabilities(
    State(state): State<AppState>,
) -> Result<Json<dto::BrowserCapabilities>, ApiError> {
    if state.config.public_origin.is_none() || state.identity.is_none() {
        return Err(IdentityError::Unavailable.into());
    }
    Ok(Json(dto::BrowserCapabilities {
        session_mode: dto::SessionMode::Cookie,
        device_platform: dto::DevicePlatform::Web,
        replica_protocol: 2,
    }))
}

pub async fn transport(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if !request.headers().contains_key(SELECTOR) {
        return next.run(request).await;
    }
    let Some(origin) = state
        .config
        .public_origin
        .as_ref()
        .filter(|_| state.identity.is_some())
    else {
        return ApiError::from(IdentityError::Unavailable).into_response();
    };
    let context = (|| {
        validate(
            request.method(),
            request.headers(),
            &origin.origin().ascii_serialization(),
        )?;
        credential(request.headers())
    })();
    let credential = match context {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(module="identity", scope="http", event.name="browser.request.rejected", error.type="browser_origin_or_credentials", outcome="rejected");
            return ApiError::from(error).into_response();
        }
    };
    if let Some(token) = &credential {
        let value = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let Ok(mut value) = HeaderValue::from_str(&value) else {
            return ApiError::from(IdentityError::InvalidInput).into_response();
        };
        value.set_sensitive(true);
        request.headers_mut().insert(header::AUTHORIZATION, value);
    }
    request.extensions_mut().insert(BrowserRequest);
    let session_route = matches!(request.uri().path(), "/v2/session" | "/v2/session/renew");
    let logout = request.uri().path() == "/v2/session" && request.method() == Method::DELETE;
    let mut response = next.run(request).await;
    if (logout && response.status() == StatusCode::NO_CONTENT)
        || (session_route && response.status() == StatusCode::UNAUTHORIZED)
    {
        clear_session(&mut response);
    }
    response
}

pub fn session_cookie(
    token: &str,
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<HeaderValue, IdentityError> {
    let remaining = expires_at_ms
        .checked_sub(now_ms)
        .ok_or(IdentityError::Denied)?;
    if !token_valid(token) || !(1000..=SESSION_LIFETIME_MS).contains(&remaining) {
        return Err(IdentityError::InvalidInput);
    }
    let value = Zeroizing::new(format!(
        "{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        remaining / 1000
    ));
    let mut header = HeaderValue::from_str(&value).map_err(|_| IdentityError::InvalidInput)?;
    header.set_sensitive(true);
    Ok(header)
}

pub fn clear_session(response: &mut Response) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-nds-session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_selection_requires_an_unambiguous_same_origin_context() {
        let mut headers = HeaderMap::new();
        headers.insert(SELECTOR, HeaderValue::from_static("browser"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://instance.example"),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(validate(&Method::POST, &headers, "https://instance.example").is_ok());
        for (name, value) in [
            ("origin", "https://instance.example.evil.invalid"),
            ("origin", "null"),
            ("sec-fetch-site", "same-site"),
            ("sec-fetch-site", "cross-site"),
            (SELECTOR, "native"),
            ("authorization", "Bearer conflicting"),
        ] {
            let mut wrong = headers.clone();
            wrong.insert(name, HeaderValue::from_static(value));
            assert!(validate(&Method::POST, &wrong, "https://instance.example").is_err());
        }
        for name in [SELECTOR, "origin", "sec-fetch-site"] {
            let mut duplicate = headers.clone();
            duplicate.append(name, headers[name].clone());
            assert!(validate(&Method::POST, &duplicate, "https://instance.example").is_err());
        }
        headers.remove(header::ORIGIN);
        assert!(validate(&Method::POST, &headers, "https://instance.example").is_err());
        assert!(validate(&Method::GET, &headers, "https://instance.example").is_ok());
    }

    #[test]
    fn cookie_parsing_and_lifetime_cannot_smuggle_another_credential() {
        let token = "A".repeat(43);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("unrelated=x; {COOKIE}={token}")).unwrap(),
        );
        assert_eq!(credential(&headers).unwrap().unwrap().as_str(), token);
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE}={token}")).unwrap(),
        );
        assert!(credential(&headers).is_err());
        let mut excessive = HeaderMap::new();
        for _ in 0..3 {
            excessive.append(
                header::COOKIE,
                HeaderValue::from_str(&format!("unrelated={}", "x".repeat(3000))).unwrap(),
            );
        }
        assert!(credential(&excessive).is_err());
        for bad in ["", "short", "A\r\nInjected: yes"] {
            assert!(session_cookie(bad, 20_000, 10_000).is_err());
        }
        for expiry in [
            9_000,
            10_000,
            10_999,
            10_000 + SESSION_LIFETIME_MS + 1,
            u64::MAX,
        ] {
            assert!(session_cookie(&token, expiry, 10_000).is_err());
        }
        let value = session_cookie(&token, 20_000, 10_000).unwrap();
        assert!(value.is_sensitive());
        let value = value.to_str().unwrap();
        for attribute in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=10",
        ] {
            assert!(value.contains(attribute));
        }
        assert!(!value.contains("Domain="));
    }
}
