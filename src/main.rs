use std::process::ExitCode;

use nddev_device_sync_server::{
    AppState,
    config::{ServerConfig, migration_database_url},
    database,
    logging::init_logging,
    router, transport,
};

fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let logging = match init_logging() {
        Ok(guard) => guard,
        Err(error) => {
            tracing::error!(event.name = "process.failed", module = "process", error.type = %error, outcome = "error");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = logging.validate() {
        tracing::error!(event.name = "process.failed", module = "process", error.type = %error, outcome = "error");
        return ExitCode::FAILURE;
    }
    // The native blocking OTLP client is constructed and dropped outside Tokio.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(8)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            tracing::error!(event.name="process.failed", module="process", error.type="runtime_unavailable", outcome="error");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        let observer = logging.watch_delivery();
        let result = run().await;
        if let Some(observer) = observer {
            observer.abort();
            let _ = observer.await;
        }
        result
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Adapter errors expose stable classes, never driver messages, paths or URLs.
            tracing::error!(event.name = "process.failed", module = "process", error.type = process_error_class(error.as_ref()), outcome = "error");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["serve"] => {
            let config = ServerConfig::from_env()?;
            if config.web_assets.is_some() {
                tracing::info!(
                    module = "http",
                    scope = "io",
                    event.name = "web.assets.loaded",
                    available = true,
                    outcome = "ok"
                );
            }
            let state = AppState::from_config(config.clone()).await?;
            transport::serve(&config, router(state)).await?;
        }
        ["migrate"] => database::migrate(&migration_database_url()?).await?,
        ["--help"] | ["help"] => println!(
            "Usage: nddev-device-sync-server [serve|migrate]\nTLS: NDS_TLS_CERT_FILE + NDS_TLS_KEY_FILE\nRuntime: DATABASE_URL or DATABASE_URL_FILE\nMigration: NDS_MIGRATION_DATABASE_URL or NDS_MIGRATION_DATABASE_URL_FILE"
        ),
        _ => return Err("invalid command; use --help".into()),
    }
    Ok(())
}

fn process_error_class(error: &(dyn std::error::Error + 'static)) -> &'static str {
    use nddev_device_sync_server::{
        config::ConfigError, database::DatabaseError, transport::TransportError,
    };
    if let Some(error) = error.downcast_ref::<ConfigError>() {
        return match error {
            ConfigError::Address => "configuration_address",
            ConfigError::TlsPair => "configuration_tls_pair",
            ConfigError::ConflictingSecret => "configuration_secret_conflict",
            ConfigError::SecretFile => "configuration_secret_file",
            ConfigError::SecretValue => "configuration_secret_value",
            ConfigError::MigrationDatabaseMissing => "configuration_migration_database_missing",
            ConfigError::AdmissionLimit => "configuration_admission_limit",
            ConfigError::TrustedProxy => "configuration_trusted_proxy",
            ConfigError::Identity => "configuration_identity",
            ConfigError::IdentityHttpsRequired => "configuration_identity_https_required",
            ConfigError::PublicOrigin => "configuration_public_origin",
            ConfigError::VaultKey => "configuration_vault_key",
            ConfigError::Observability => "configuration_observability",
            ConfigError::WebAssets => "configuration_web_assets",
        };
    }
    if let Some(error) = error.downcast_ref::<DatabaseError>() {
        return match error {
            DatabaseError::Connection => "database_connection",
            DatabaseError::RuntimeRole => "database_runtime_role",
            DatabaseError::Migration => "database_migration",
            DatabaseError::MigrationTimeout => "database_migration_timeout",
            DatabaseError::Identity => "database_identity",
        };
    }
    if let Some(error) = error.downcast_ref::<TransportError>() {
        return match error {
            TransportError::TlsConfiguration => "transport_tls_configuration",
            TransportError::Listener => "transport_listener",
            TransportError::Signal => "transport_signal",
        };
    }
    "invalid_command"
}
