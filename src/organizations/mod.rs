//! Company control adapters. Core owns membership and invitation transitions.
mod codec;
pub(crate) mod http;
pub(crate) mod store;

pub struct Service {
    store: store::Store,
    crypto: crate::identity::crypto::Crypto,
    mailer: crate::identity::email::Mailer,
}
impl Service {
    pub fn new(
        pool: sqlx::PgPool,
        crypto: crate::identity::crypto::Crypto,
        mailer: crate::identity::email::Mailer,
    ) -> Self {
        Self {
            store: store::Store::new(pool),
            crypto,
            mailer,
        }
    }
}
