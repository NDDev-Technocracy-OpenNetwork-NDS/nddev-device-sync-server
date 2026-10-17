pub mod http;
mod store;
use crate::identity::crypto::{Crypto, equal};
use nddev_device_sync_application::identity::*;
use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use webauthn_rs::prelude::*;

enum Challenge {
    Register(PasskeyRegistration, AuthenticatedSession),
    Authenticate(PasskeyAuthentication, Vec<Passkey>),
}
enum Outcome {
    Registered,
    Authenticated(Box<Passkey>, serde_json::Value),
    Failed,
}
struct Flow {
    owner: Owner,
    exchange: ProtectedDigest,
    deadline: Instant,
    code: String,
    options: serde_json::Value,
    challenge: Option<Challenge>,
    cookie: Option<ProtectedDigest>,
    csrf: Option<ProtectedDigest>,
    outcome: Option<Outcome>,
}
pub struct Service {
    webauthn: Webauthn,
    pub origin: reqwest::Url,
    store: store::Store,
    crypto: Crypto,
    flows: Mutex<BTreeMap<String, Flow>>,
}
fn unavailable<E>(_: E) -> IdentityError {
    IdentityError::Unavailable
}
impl Service {
    pub fn new(
        pool: sqlx::PgPool,
        origin: &reqwest::Url,
        crypto: Crypto,
    ) -> Result<Self, IdentityError> {
        let domain = origin.domain().ok_or(IdentityError::InvalidInput)?;
        let webauthn = WebauthnBuilder::new(domain, origin)
            .map_err(unavailable)?
            .rp_name("NDDev OpenNetwork")
            .build()
            .map_err(unavailable)?;
        Ok(Self {
            webauthn,
            origin: origin.clone(),
            store: store::Store(pool),
            crypto,
            flows: Mutex::default(),
        })
    }
    fn locked(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, Flow>>, IdentityError> {
        let mut flows = self.flows.lock().map_err(unavailable)?;
        flows.retain(|_, flow| flow.deadline > Instant::now());
        Ok(flows)
    }
    pub async fn list(
        &self,
        auth: &AuthenticatedSession,
    ) -> Result<Vec<(String, u64)>, IdentityError> {
        self.store.list(auth).await
    }
    pub async fn revoke(
        &self,
        auth: &AuthenticatedSession,
        id: &str,
        now: u64,
    ) -> Result<(bool, bool), IdentityError> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IdentityError::Denied);
        }
        if !auth.session.recently_authenticated(now) {
            return Err(IdentityError::RecentAuthenticationRequired);
        }
        self.store.revoke(auth, id, now).await
    }
    pub async fn available(&self) -> Result<bool, IdentityError> {
        self.store.available().await
    }
    pub async fn start(
        &self,
        auth: Option<AuthenticatedSession>,
        email: Option<&str>,
        now: u64,
    ) -> Result<crate::protocol_v2::PasskeyStart, IdentityError> {
        let owner = match &auth {
            Some(auth) if email.is_none() => auth.session.owner.clone(),
            Some(_) => return Err(IdentityError::InvalidInput),
            None => {
                let binding = email.map(EmailAddress::parse).transpose()?.map(|email| {
                    self.crypto
                        .protect("owner_binding", &[email.as_str().as_bytes()])
                });
                self.store.owner(binding).await?
            }
        };
        if auth
            .as_ref()
            .is_some_and(|auth| !auth.session.recently_authenticated(now))
        {
            return Err(IdentityError::RecentAuthenticationRequired);
        }
        let keys = self.store.credentials(&owner).await?;
        let (options, challenge) = if let Some(auth) = auth {
            if keys.len() >= 16 {
                return Err(IdentityError::Capacity);
            }
            let id = uuid::Uuid::parse_str(owner.user_id.as_str()).map_err(unavailable)?;
            let (options, state) = self
                .webauthn
                .start_passkey_registration(
                    id,
                    "NDS owner",
                    "NDS owner",
                    Some(keys.iter().map(|key| key.cred_id().clone()).collect()),
                )
                .map_err(unavailable)?;
            (
                serde_json::to_value(options).map_err(unavailable)?,
                Challenge::Register(state, auth),
            )
        } else {
            if keys.is_empty() {
                return Err(IdentityError::Denied);
            }
            let (options, state) = self
                .webauthn
                .start_passkey_authentication(&keys)
                .map_err(unavailable)?;
            (
                serde_json::to_value(options).map_err(unavailable)?,
                Challenge::Authenticate(state, keys),
            )
        };
        let id = self.crypto.token()?.into_inner();
        let exchange = self.crypto.token()?;
        let code = self.crypto.otp()?.into_inner();
        let flow = Flow {
            owner,
            exchange: self
                .crypto
                .protect("passkey_exchange", &[exchange.expose().as_bytes()]),
            deadline: Instant::now() + Duration::from_secs(300),
            code: code.clone(),
            options,
            challenge: Some(challenge),
            cookie: None,
            csrf: None,
            outcome: None,
        };
        let mut flows = self.locked()?;
        if flows.len() >= 128 {
            return Err(IdentityError::Capacity);
        }
        flows.insert(id.clone(), flow);
        Ok(crate::protocol_v2::PasskeyStart {
            authorization_url: self
                .origin
                .join(&format!("/v2/auth/passkeys/browser?flow_id={id}"))
                .map_err(unavailable)?
                .to_string(),
            flow_id: id,
            exchange_token: exchange.into_inner(),
            verification_code: code,
            expires_in_seconds: 300,
            poll_after_seconds: 2,
        })
    }
    pub fn browser(
        &self,
        id: &str,
        previous_cookie: Option<&str>,
    ) -> Result<(String, String, String, bool), IdentityError> {
        if !opaque(id) {
            return Err(IdentityError::InvalidInput);
        }
        let cookie = previous_cookie
            .map(str::to_owned)
            .map(Ok)
            .unwrap_or_else(|| self.crypto.token().map(|token| token.into_inner()))?;
        let csrf = self.crypto.token()?.into_inner();
        let mut flows = self.locked()?;
        let flow = flows.get_mut(id).ok_or(IdentityError::Denied)?;
        if flow.challenge.is_none()
            || flow.cookie.as_ref().is_some_and(|expected| {
                previous_cookie.is_none()
                    || !equal(
                        expected,
                        &self.crypto.protect("passkey_cookie", &[cookie.as_bytes()]),
                    )
            })
        {
            return Err(IdentityError::Denied);
        }
        flow.cookie = Some(self.crypto.protect("passkey_cookie", &[cookie.as_bytes()]));
        flow.csrf = Some(self.crypto.protect("passkey_csrf", &[csrf.as_bytes()]));
        Ok((
            cookie,
            csrf,
            flow.code.clone(),
            matches!(flow.challenge, Some(Challenge::Register(..))),
        ))
    }
    fn browser_valid(&self, flow: &Flow, cookie: &str, csrf: &str) -> bool {
        flow.cookie.as_ref().is_some_and(|expected| {
            equal(
                expected,
                &self.crypto.protect("passkey_cookie", &[cookie.as_bytes()]),
            )
        }) && flow.csrf.as_ref().is_some_and(|expected| {
            equal(
                expected,
                &self.crypto.protect("passkey_csrf", &[csrf.as_bytes()]),
            )
        })
    }
    pub fn options(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
    ) -> Result<serde_json::Value, IdentityError> {
        let flows = self.locked()?;
        let flow = flows.get(id).ok_or(IdentityError::Denied)?;
        if !self.browser_valid(flow, cookie, csrf) || flow.challenge.is_none() {
            return Err(IdentityError::Denied);
        }
        Ok(flow.options.clone())
    }
    pub async fn finish(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
        value: serde_json::Value,
        now: u64,
    ) -> Result<(), IdentityError> {
        let challenge = {
            let mut flows = self.locked()?;
            let flow = flows.get_mut(id).ok_or(IdentityError::Denied)?;
            if !self.browser_valid(flow, cookie, csrf) {
                return Err(IdentityError::Denied);
            }
            flow.challenge.take().ok_or(IdentityError::Denied)?
        };
        let result = async {
            Ok(match challenge {
                Challenge::Register(state, auth) => {
                    let value =
                        serde_json::from_value(value).map_err(|_| IdentityError::InvalidInput)?;
                    let key = self
                        .webauthn
                        .finish_passkey_registration(&value, &state)
                        .map_err(|_| IdentityError::Denied)?;
                    self.store.register(&auth, key, now).await?;
                    Outcome::Registered
                }
                Challenge::Authenticate(state, mut keys) => {
                    let value =
                        serde_json::from_value(value).map_err(|_| IdentityError::InvalidInput)?;
                    let verified = self
                        .webauthn
                        .finish_passkey_authentication(&value, &state)
                        .map_err(|_| IdentityError::Denied)?;
                    let mut key = keys
                        .drain(..)
                        .find(|key| key.cred_id() == verified.cred_id())
                        .ok_or(IdentityError::Denied)?;
                    let original = serde_json::to_value(&key).map_err(unavailable)?;
                    key.update_credential(&verified)
                        .ok_or(IdentityError::Denied)?;
                    Outcome::Authenticated(Box::new(key), original)
                }
            })
        }
        .await;
        let mut flows = self.locked()?;
        let flow = flows.get_mut(id).ok_or(IdentityError::Denied)?;
        match result {
            Ok(outcome) => {
                flow.outcome = Some(outcome);
                Ok(())
            }
            Err(error) => {
                flow.outcome = Some(Outcome::Failed);
                Err(error)
            }
        }
    }
    pub async fn exchange(
        &self,
        id: &str,
        exchange: &str,
        now: u64,
    ) -> Result<Exchange, IdentityError> {
        if !opaque(id) || !opaque(exchange) {
            return Err(IdentityError::InvalidInput);
        }
        let ready = {
            let mut flows = self.locked()?;
            let flow = flows.get(id).ok_or(IdentityError::Denied)?;
            if !equal(
                &flow.exchange,
                &self
                    .crypto
                    .protect("passkey_exchange", &[exchange.as_bytes()]),
            ) {
                return Err(IdentityError::Denied);
            }
            if flow.outcome.is_none() {
                return Ok(Exchange::Pending);
            }
            flows.remove(id).ok_or(IdentityError::Denied)?
        };
        match ready.outcome.ok_or(IdentityError::Denied)? {
            Outcome::Registered => Ok(Exchange::Registered),
            Outcome::Failed => Err(IdentityError::Denied),
            Outcome::Authenticated(key, original) => {
                let token = self.crypto.token()?;
                let issue = SessionIssue {
                    digest: self.crypto.protect("session", &[token.expose().as_bytes()]),
                    session: Session::new(ready.owner.clone(), AuthMethod::Passkey, now)?,
                };
                let session = self
                    .store
                    .authenticate(&ready.owner, *key, original, issue)
                    .await?;
                Ok(Exchange::Session(IssuedSession { token, session }))
            }
        }
    }
}
fn opaque(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

pub enum Exchange {
    Pending,
    Registered,
    Session(IssuedSession),
}
