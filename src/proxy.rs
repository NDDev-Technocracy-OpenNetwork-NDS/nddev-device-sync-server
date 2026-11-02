//! Only an explicitly trusted socket peer may assert a client address.
use crate::admission::PeerAddress;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::IpAddr;

pub(crate) const CLIENT_IP_HEADER: &str = "x-real-ip";

fn client_address(request: &Request) -> Option<IpAddr> {
    let mut values = request.headers().get_all(CLIENT_IP_HEADER).iter();
    let value = values.next()?;
    if values.next().is_some() || value.as_bytes().len() > 45 {
        return None;
    }
    let address: IpAddr = value.to_str().ok()?.parse().ok()?;
    (!address.is_unspecified() && !address.is_multicast()).then_some(address)
}

pub(crate) async fn trusted_client_address(mut request: Request, next: Next) -> Response {
    let Some(address) = client_address(&request) else {
        // Never log the supplied address or header contents.
        tracing::warn!(
            module = "admission", scope = "http",
            event.name = "proxy.client_address.rejected",
            error.type = "invalid_proxy_client_address", outcome = "rejected"
        );
        return StatusCode::BAD_REQUEST.into_response();
    };
    request.extensions_mut().insert(PeerAddress(address));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Extension, Router, body::Body, routing::get};
    use http_body_util::BodyExt;
    use std::net::SocketAddr;
    use tower::{Service, ServiceExt};

    async fn exchange(
        trusted: Vec<IpAddr>,
        socket: &str,
        addresses: &[&str],
    ) -> (StatusCode, String) {
        let app = Router::new().route(
            "/",
            get(|Extension(peer): Extension<PeerAddress>| async move { peer.0.to_string() }),
        );
        let mut connections = crate::admission::Connections::with_trusted_proxies(app, 1, trusted);
        let app = connections
            .call(socket.parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let mut request = Request::builder().uri("/");
        for address in addresses {
            request = request.header(CLIENT_IP_HEADER, *address);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn direct_origin_ignores_forged_and_invalid_headers() {
        for headers in [
            vec![],
            vec!["198.51.100.23"],
            vec!["invalid", "198.51.100.24"],
        ] {
            let (status, peer) = exchange(vec![], "192.0.2.7:12345", &headers).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(peer, "192.0.2.7");
        }
    }

    #[tokio::test]
    async fn an_allowlist_never_trusts_a_different_socket_peer() {
        let (status, peer) = exchange(
            vec!["127.0.0.1".parse().unwrap()],
            "192.0.2.7:12345",
            &["198.51.100.23"],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(peer, "192.0.2.7");
    }

    #[tokio::test]
    async fn trusted_proxy_preserves_each_clients_ipv4_and_ipv6_identity() {
        for address in ["198.51.100.23", "198.51.100.24", "2001:db8::23"] {
            let (status, peer) = exchange(
                vec!["127.0.0.1".parse().unwrap()],
                "127.0.0.1:12345",
                &[address],
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(peer, address);
        }
    }

    #[tokio::test]
    async fn a_trusted_proxy_must_supply_one_valid_unicast_address() {
        let long = "1".repeat(46);
        for headers in [
            vec![],
            vec![""],
            vec!["198.51.100.23", "198.51.100.24"],
            vec!["198.51.100.23, 198.51.100.24"],
            vec![" 198.51.100.23"],
            vec!["198.51.100.23:1234"],
            vec!["not-an-address"],
            vec!["0.0.0.0"],
            vec!["::"],
            vec!["224.0.0.1"],
            vec!["ff02::1"],
            vec![long.as_str()],
        ] {
            let (status, body) = exchange(
                vec!["127.0.0.1".parse().unwrap()],
                "127.0.0.1:12345",
                &headers,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.is_empty());
        }
    }
}
