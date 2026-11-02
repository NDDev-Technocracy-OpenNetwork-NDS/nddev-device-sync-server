use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use axum::{Router, routing::get};
use axum_server::Handle;
use nddev_device_sync_server::{
    AppState,
    config::{ServerConfig, TlsFiles},
    router,
    transport::{load_tls, reload_tls, serve_listener},
};
use rcgen::{CertifiedKey, KeyPair, generate_simple_self_signed};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

struct CertificateFiles {
    dir: PathBuf,
    files: TlsFiles,
}

impl CertificateFiles {
    fn new(cert: &CertifiedKey<KeyPair>) -> Self {
        let dir = std::env::temp_dir().join(format!("nds-tls-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let files = TlsFiles {
            certificate: dir.join("cert.pem"),
            private_key: dir.join("key.pem"),
        };
        std::fs::write(&files.certificate, cert.cert.pem()).unwrap();
        std::fs::write(&files.private_key, cert.signing_key.serialize_pem()).unwrap();
        Self { dir, files }
    }
}
impl Drop for CertificateFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn connector(certificates: &[CertificateDer<'static>]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for cert in certificates {
        roots.add(cert.clone()).unwrap();
    }
    TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

async fn exchange(addr: SocketAddr, connector: &TlsConnector) -> (Vec<u8>, String) {
    let socket = TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap();
    let cert = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    use opentelemetry::{propagation::TextMapPropagator, trace::TraceContextExt};
    let parent = nddev_device_sync_telemetry::operation_span("test_client", "http").unwrap();
    let context = nddev_device_sync_telemetry::trace_context(&parent);
    let trace_id = context.span().span_context().trace_id().to_string();
    let mut headers = std::collections::HashMap::new();
    opentelemetry_sdk::propagation::TraceContextPropagator::new()
        .inject_context(&context, &mut headers);
    tls.write_all(format!("GET /v1/health HTTP/1.1\r\nHost: localhost\r\ntraceparent: {}\r\nConnection: close\r\n\r\n", headers["traceparent"]).as_bytes())
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(bytes).unwrap();
    assert!(response.contains(&format!("x-request-id: {trace_id}\r\n")));
    (cert, response)
}

#[tokio::test]
async fn https_preserves_headers_and_only_reloads_valid_pairs() {
    let _logging = nddev_device_sync_server::logging::init_logging().unwrap();
    _logging.validate().unwrap();
    let first = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let second = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let files = CertificateFiles::new(&first);
    let tls = load_tls(&files.files).await.unwrap();
    let client = connector(&[first.cert.der().clone(), second.cert.der().clone()]);
    let state = AppState::from_config(ServerConfig {
        addr: "127.0.0.1:0".parse().unwrap(),
        database_url: None,
        tls: None,
        version: "test".into(),
        channel: "alpha".into(),
        standards_release: "test".into(),
        source_url: "https://example.invalid/source".into(),
        telemetry_enabled: true,
        public_origin: None,
        max_connections: 256,
        max_requests: 64,
        trusted_proxy_ips: Vec::new(),
        identity: None,
        vault_wrapping_key: None,
        observability: None,
        web_assets: None,
    })
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let handle = Handle::new();
    let server = tokio::spawn(serve_listener(
        listener,
        router(state),
        Some(tls.clone()),
        handle.clone(),
        256,
    ));
    let addr = tokio::time::timeout(Duration::from_secs(2), handle.listening())
        .await
        .unwrap()
        .unwrap();
    let (presented, response) = exchange(addr, &client).await;
    assert_eq!(presented, first.cert.der().to_vec());
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("cache-control: no-store\r\n"));
    assert!(response.contains("x-request-id: "));

    // A mismatched pair must not replace the current certificate.
    std::fs::write(&files.files.certificate, second.cert.pem()).unwrap();
    let error = reload_tls(&tls, &files.files).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("nds-tls-test"));
    assert_eq!(exchange(addr, &client).await.0, first.cert.der().to_vec());
    std::fs::write(&files.files.private_key, second.signing_key.serialize_pem()).unwrap();
    reload_tls(&tls, &files.files).await.unwrap();
    assert_eq!(exchange(addr, &client).await.0, second.cert.der().to_vec());

    // A client that never starts TLS cannot hold an accepted socket indefinitely.
    let mut stalled = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(7), stalled.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn graceful_shutdown_closes_a_never_ending_request_by_its_deadline() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let notify = entered.clone();
    let app = Router::new().route(
        "/pending",
        get(move || async move {
            notify.notify_one();
            std::future::pending::<()>().await;
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let handle = Handle::new();
    let server = tokio::spawn(serve_listener(listener, app, None, handle.clone(), 256));
    let mut socket = TcpStream::connect(
        tokio::time::timeout(Duration::from_secs(2), handle.listening())
            .await
            .unwrap()
            .unwrap(),
    )
    .await
    .unwrap();
    socket
        .write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    handle.graceful_shutdown(Some(Duration::from_millis(50)));
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn oversized_or_missing_tls_material_fails_closed_without_exposing_paths() {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let files = CertificateFiles::new(&cert);
    std::fs::write(&files.files.private_key, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert!(load_tls(&files.files).await.is_err());
    std::fs::remove_file(&files.files.private_key).unwrap();
    let error = load_tls(&files.files).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "TLS certificate or key is unreadable or invalid"
    );
}

#[tokio::test]
async fn saturated_connections_close_before_tls_and_capacity_returns_on_disconnect() {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let files = CertificateFiles::new(&cert);
    let tls = load_tls(&files.files).await.unwrap();
    let client = connector(&[cert.cert.der().clone()]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let handle = Handle::new();
    let app = Router::new().route("/v1/health", get(|| async { "ok" }));
    let server = tokio::spawn(serve_listener(listener, app, Some(tls), handle.clone(), 1));
    let addr = tokio::time::timeout(Duration::from_secs(2), handle.listening())
        .await
        .unwrap()
        .unwrap();
    let first = client
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    let rejected = client.connect(
        ServerName::try_from("localhost").unwrap(),
        TcpStream::connect(addr).await.unwrap(),
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), rejected)
            .await
            .unwrap()
            .is_err(),
        "extra connection reached TLS despite admission limit"
    );
    drop(first);
    // Closing TLS is asynchronous at the server; retry within a fixed deadline.
    let mut recovered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(tls) = client
                .connect(
                    ServerName::try_from("localhost").unwrap(),
                    TcpStream::connect(addr).await.unwrap(),
                )
                .await
            {
                break tls;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    recovered
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), recovered.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
