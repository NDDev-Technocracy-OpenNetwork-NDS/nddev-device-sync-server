pub mod config;
pub(crate) mod crypto;
pub(crate) mod email;
mod flows;
mod github;
pub mod http;
pub(crate) mod store;

use config::AuthConfig;
use nddev_device_sync_application::identity::{IdentityCrypto, IdentityError, IdentityService};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
pub type Service =
    IdentityService<store::Store, crypto::Crypto, email::Mailer, github::Github, flows::Flows>;

pub fn now_ms() -> Result<u64, IdentityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdentityError::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| IdentityError::Unavailable)
}

pub async fn initialize(
    pool: sqlx::PgPool,
    config: &AuthConfig,
    origin: Option<&reqwest::Url>,
) -> Result<(Arc<Service>, email::Mailer), IdentityError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let companies = crate::organizations::store::Store::new(pool.clone());
    let store = store::Store::new(pool);
    let github_id = config.github.as_ref().map(|github| github.owner_id);
    store
        .bootstrap(
            &config.owner_email,
            config
                .crypto
                .protect("owner_binding", &[config.owner_email.as_str().as_bytes()]),
            github_id,
        )
        .await?;
    let email = email::Mailer::new(
        config.smtp.as_ref(),
        store.clone(),
        companies,
        origin.cloned(),
    )
    .await?;
    let github = github::Github::new(config.github.as_ref()).await?;
    let service = IdentityService::new(
        store,
        config.crypto.clone(),
        email.clone(),
        github,
        flows::Flows::default(),
    );
    let methods = service.methods();
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.initialized",
        email_available = methods.0,
        github_available = methods.1,
        outcome = "ready"
    );
    Ok((Arc::new(service), email))
}
