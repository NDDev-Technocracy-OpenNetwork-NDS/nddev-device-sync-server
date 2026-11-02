//! Admission happens before connection tasks and handler futures are created.
use std::{
    future::{Ready, ready},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use axum::{Extension, Router};
use tokio::sync::Semaphore;
use tower::Service;

#[derive(Clone, Copy)]
pub(crate) struct PeerAddress(pub std::net::IpAddr);

/// Rejections are a pressure counter, not sampled security/audit events. Report
/// the first, powers of two, and the final count on recovery without a log queue.
#[derive(Default)]
pub struct Pressure(AtomicU64);

impl Pressure {
    pub fn reject(&self, resource: &'static str) {
        let count = self.0.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if count.is_power_of_two() {
            tracing::warn!(
                module = "admission",
                scope = if resource == "connections" {
                    "transport"
                } else {
                    "http"
                },
                event.name = "admission.saturated",
                resource,
                rejected_count = count,
                outcome = "rejected"
            );
        }
    }

    pub fn recover(&self, resource: &'static str) {
        let count = self.0.swap(0, Ordering::Relaxed);
        if count > 0 {
            tracing::info!(
                module = "admission",
                scope = if resource == "connections" {
                    "transport"
                } else {
                    "http"
                },
                event.name = "admission.recovered",
                resource,
                rejected_count = count,
                outcome = "ok"
            );
        }
    }
}

pub struct Connections {
    app: Router,
    permits: Arc<Semaphore>,
    pressure: Pressure,
    trusted_proxies: Vec<std::net::IpAddr>,
}

impl Connections {
    pub fn new(app: Router, maximum: usize) -> Self {
        Self::with_trusted_proxies(app, maximum, Vec::new())
    }

    pub fn with_trusted_proxies(
        app: Router,
        maximum: usize,
        trusted_proxies: Vec<std::net::IpAddr>,
    ) -> Self {
        Self {
            trusted_proxies,
            app,
            permits: Arc::new(Semaphore::new(maximum)),
            pressure: Pressure::default(),
        }
    }
}

impl Service<SocketAddr> for Connections {
    type Response = Router;
    type Error = std::io::Error;
    type Future = Ready<Result<Router, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, address: SocketAddr) -> Self::Future {
        // axum-server drops this accepted socket on MakeService error, before
        // spawning a connection task or attempting its TLS handshake.
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            self.pressure.reject("connections");
            return ready(Err(std::io::Error::other("connection capacity reached")));
        };
        self.pressure.recover("connections");
        // The Router and its in-flight requests retain this permit. A failed
        // TLS handshake drops the Router too, without a separate cleanup task.
        let app = self.app.clone().layer(Extension(Arc::new(permit)));
        let app = if self.trusted_proxies.contains(&address.ip()) {
            app.layer(axum::middleware::from_fn(
                crate::proxy::trusted_client_address,
            ))
        } else {
            app
        };
        // The accepted peer is installed first; the trusted middleware inside
        // it may replace this value before any handler sees the request.
        ready(Ok(app.layer(Extension(PeerAddress(address.ip())))))
    }
}
