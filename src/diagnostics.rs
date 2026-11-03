//! P2 diagnostic access through the signed gateway: the one effective client collection policy,
//! scoped search of stored diagnostics, and the global grant.
//!
//! Search scope is decided here, never by the request body. A member reads their own records.
//! An active organization administrator reads records stored in that organization's tenant.
//! Global reads need a grant that only a fresh SSHSIG signature by an allowed administrator key
//! over a one-time challenge opens. The grant is bound to the signed session and device, is not a
//! bearer token, expires after fifteen minutes and ends as soon as its key leaves the allowed set.
use crate::{
    AppState,
    observability::{ApiError, authorize, gateway},
    protocol_observability as dto,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::HeaderMap,
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use nddev_device_sync_application::sync::SyncError;
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde::Deserialize;

pub const NAMESPACE: &str = "nds-global-admin@nddev.ai";
const CHALLENGE_TTL_MS: u64 = 2 * 60 * 1000;
const GRANT_TTL_MS: u64 = 15 * 60 * 1000;
const MAX_PENDING_CHALLENGES: i64 = 4;
const MAX_DEBUG_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v2/observability/collection-policy",
            get(collection_policy),
        )
        .route("/v2/observability/search", post(search))
        .route("/v2/observability/global-challenge", post(global_challenge))
        .route("/v2/observability/global-grant", post(global_grant))
}

fn timestamp(ms: u64) -> Result<String, SyncError> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|_| SyncError::Unavailable)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| SyncError::Unavailable)
}
fn millis(value: &str) -> Option<u64> {
    let time =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(time.unix_timestamp_nanos() / 1_000_000).ok()
}
fn now() -> Result<u64, SyncError> {
    crate::identity::now_ms().map_err(|_| SyncError::Unavailable)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}
fn database(state: &AppState) -> Result<sqlx::PgPool, SyncError> {
    state.database.clone().ok_or(SyncError::Unavailable)
}
async fn bounded<T>(
    work: impl std::future::Future<Output = Result<T, SyncError>>,
) -> Result<T, SyncError> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(|_| SyncError::Unavailable)?
}
fn unavailable<E>(_: E) -> SyncError {
    SyncError::Unavailable
}

// --- Allowed administrator keys and SSHSIG (OpenSSH PROTOCOL.sshsig) ---------------------------

/// One allowed global administrator public key: its SSH wire blob and OpenSSH fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdminKey {
    blob: Vec<u8>,
    pub(crate) fingerprint: String,
}

fn take<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let value = input.get(4..4 + length)?;
    *input = &input[4 + length..];
    Some(value)
}
fn put(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}
fn ed25519_key(blob: &[u8]) -> Option<&[u8]> {
    let mut rest = blob;
    (take(&mut rest)? == b"ssh-ed25519").then_some(())?;
    let key = take(&mut rest)?;
    (key.len() == 32 && rest.is_empty()).then_some(key)
}
fn fingerprint(blob: &[u8]) -> String {
    format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(digest::digest(&digest::SHA256, blob))
    )
}

/// Parses an allowed-keys file: one `ssh-ed25519 <base64> [comment]` per line; blank lines and
/// `#` comments are skipped. Any other key type or a malformed line refuses the whole file.
pub(crate) fn admin_keys(text: &str) -> Result<Vec<AdminKey>, ()> {
    let mut keys = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("ssh-ed25519") {
            return Err(());
        }
        let blob = STANDARD.decode(fields.next().ok_or(())?).map_err(|_| ())?;
        ed25519_key(&blob).ok_or(())?;
        let key = AdminKey {
            fingerprint: fingerprint(&blob),
            blob,
        };
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    if keys.is_empty() || keys.len() > 16 {
        return Err(());
    }
    Ok(keys)
}

/// Verifies an armored SSHSIG signature over `message` in the global namespace by one of `keys`
/// and returns that key's fingerprint. Only Ed25519 and SHA-512 (the `ssh-keygen -Y sign`
/// default) are accepted.
pub(crate) fn verify(armored: &str, message: &[u8], keys: &[AdminKey]) -> Option<String> {
    let body = armored
        .trim_end_matches('\n')
        .strip_prefix("-----BEGIN SSH SIGNATURE-----\n")?
        .strip_suffix("\n-----END SSH SIGNATURE-----")?
        .replace('\n', "");
    if body.len() > 2048 {
        return None;
    }
    let blob = STANDARD.decode(body).ok()?;
    let mut rest = blob.as_slice();
    (rest.get(..6)? == b"SSHSIG").then_some(())?;
    rest = &rest[6..];
    (rest.get(..4)? == 1u32.to_be_bytes()).then_some(())?;
    rest = &rest[4..];
    let public_key = take(&mut rest)?;
    let namespace = take(&mut rest)?;
    let reserved = take(&mut rest)?;
    let hash = take(&mut rest)?;
    let mut encoded = take(&mut rest)?;
    if !rest.is_empty() || namespace != NAMESPACE.as_bytes() || hash != b"sha512" {
        return None;
    }
    let key = keys.iter().find(|key| key.blob == public_key)?;
    (take(&mut encoded)? == b"ssh-ed25519").then_some(())?;
    let raw = take(&mut encoded)?;
    if raw.len() != 64 || !encoded.is_empty() {
        return None;
    }
    let mut signed = b"SSHSIG".to_vec();
    put(&mut signed, namespace);
    put(&mut signed, reserved);
    put(&mut signed, hash);
    put(
        &mut signed,
        digest::digest(&digest::SHA512, message).as_ref(),
    );
    signature::UnparsedPublicKey::new(&signature::ED25519, ed25519_key(&key.blob)?)
        .verify(&signed, raw)
        .ok()?;
    Some(key.fingerprint.clone())
}

fn current_keys(state: &AppState) -> Result<Vec<AdminKey>, SyncError> {
    let path = gateway(state)?
        .global_admin_keys
        .as_deref()
        .ok_or(SyncError::Unavailable)?;
    let text = String::from_utf8(crate::observability::read(path).map_err(unavailable)?)
        .map_err(unavailable)?;
    admin_keys(&text).map_err(unavailable)
}

// --- Collection policy --------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    revision: i64,
    #[serde(default)]
    debug: Vec<DebugWindow>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugWindow {
    device_id: String,
    expires_at: String,
}

/// The effective policy for one device. `off` whenever export is disabled; `debug` only inside an
/// operator window for this device that has not expired and is at most a week long from now;
/// otherwise `standard`.
fn effective(
    export: bool,
    file: Option<&[u8]>,
    device: &str,
    now: u64,
) -> Result<dto::CollectionPolicy, SyncError> {
    let file = file
        .map(|bytes| serde_json::from_slice::<PolicyFile>(bytes).map_err(unavailable))
        .transpose()?;
    let revision = file.as_ref().map_or(1, |file| file.revision);
    if !(1..=9_007_199_254_740_991).contains(&revision)
        || file.as_ref().is_some_and(|file| file.debug.len() > 64)
    {
        return Err(SyncError::Unavailable);
    }
    let debug = file
        .iter()
        .flat_map(|file| &file.debug)
        .filter(|window| window.device_id == device)
        .filter_map(|window| millis(&window.expires_at))
        .filter(|expires| *expires > now && *expires - now <= MAX_DEBUG_WINDOW_MS)
        .max();
    Ok(match (export, debug) {
        (false, _) => dto::CollectionPolicy {
            mode: dto::CollectionMode::Off,
            debug_expires_at: None,
            revision,
        },
        (true, Some(expires)) => dto::CollectionPolicy {
            mode: dto::CollectionMode::Debug,
            debug_expires_at: Some(timestamp(expires)?),
            revision,
        },
        (true, None) => dto::CollectionPolicy {
            mode: dto::CollectionMode::Standard,
            debug_expires_at: None,
            revision,
        },
    })
}

async fn collection_policy(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<dto::CollectionPolicy>, ApiError> {
    let (_, signed) = authorize(&state, &headers, "GET", &uri, &[], false).await?;
    let gateway = gateway(&state)?;
    let export = state.config.telemetry_enabled
        && matches!(
            gateway
                .forward::<dto::ObservabilityStatus>(
                    "/v2/observability/status",
                    None,
                    signed.device.as_str()
                )
                .await?
                .export_mode,
            dto::ExportMode::Enabled
        );
    let file = gateway
        .collection_policy
        .as_deref()
        .map(crate::observability::read)
        .transpose()
        .map_err(unavailable)?;
    Ok(Json(effective(
        export,
        file.as_deref(),
        signed.device.as_str(),
        now()?,
    )?))
}

// --- Scoped search ------------------------------------------------------------------------------

async fn organization_admin(
    state: &AppState,
    organization: &str,
    user: &str,
) -> Result<bool, SyncError> {
    let pool = database(state)?;
    bounded(async move {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM nds_company_memberships WHERE tenant_id=$1 AND user_id=$2 \
             AND company_role='admin' AND membership_active)",
        )
        .bind(organization)
        .bind(user)
        .fetch_one(&pool)
        .await
        .map_err(unavailable)
    })
    .await
}

/// The current global grant of this session and device, if its key is still allowed.
async fn global_grant_of(
    state: &AppState,
    binding: &[u8; 32],
    device: &str,
    user: &str,
) -> Result<bool, SyncError> {
    let pool = database(state)?;
    let now = i64::try_from(now()?).map_err(unavailable)?;
    let fingerprint: Option<String> = bounded(async move {
        sqlx::query_scalar(
            "SELECT key_fingerprint FROM nds_global_diagnostic_grants WHERE session_binding=$1 \
             AND device_id=$2 AND user_id=$3 AND expires_at_ms>$4",
        )
        .bind(binding.as_slice())
        .bind(device)
        .bind(user)
        .bind(now)
        .fetch_optional(&pool)
        .await
        .map_err(unavailable)
    })
    .await?;
    let Some(fingerprint) = fingerprint else {
        return Ok(false);
    };
    Ok(current_keys(state)?
        .iter()
        .any(|key| key.fingerprint == fingerprint))
}

async fn search(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::DiagnosticSearchPage>, ApiError> {
    if body.is_empty() || body.len() > 8192 {
        return Err(SyncError::Invalid.into());
    }
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, false).await?;
    let request: dto::DiagnosticSearchRequest =
        serde_json::from_slice(&body).map_err(|_| SyncError::Invalid)?;
    let user = auth.session.owner.user_id.as_str();
    let (kind, subject) = match request.scope {
        dto::DiagnosticScope::Member => ("member", Some(user)),
        dto::DiagnosticScope::Organization => {
            let organization = request
                .organization_id
                .as_deref()
                .filter(|value| identifier(value))
                .ok_or(SyncError::Invalid)?;
            if !organization_admin(&state, organization, user).await? {
                return Err(ApiError::Diagnostic(dto::Error::ForbiddenScope));
            }
            ("organization", Some(organization))
        }
        dto::DiagnosticScope::Global => {
            if !global_grant_of(&state, &auth.binding.0, signed.device.as_str(), user).await? {
                return Err(ApiError::Diagnostic(dto::Error::GlobalGrantRequired));
            }
            ("global", None)
        }
    };
    tracing::info!(
        module = "observability",
        scope = "http",
        event.name = "observability.search.forwarded",
        outcome = "ok",
        diagnostic.scope = kind,
        user.id = user,
        device.id = signed.device.as_str()
    );
    let page = gateway(&state)?
        .search(body.to_vec(), signed.device.as_str(), kind, subject)
        .await?;
    Ok(Json(page))
}

// --- Global challenge and grant -----------------------------------------------------------------

fn challenge_text(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

async fn global_challenge(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::GlobalDiagnosticChallenge>, ApiError> {
    if !body.is_empty() {
        return Err(SyncError::Invalid.into());
    }
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, false).await?;
    // No challenge is issued while no administrator key is configured.
    current_keys(&state)?;
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).map_err(unavailable)?;
    let challenge = URL_SAFE_NO_PAD.encode(bytes);
    let now = now()?;
    let expires = now + CHALLENGE_TTL_MS;
    let pool = database(&state)?;
    let (stored, device, user) = (
        challenge.clone(),
        signed.device.as_str().to_owned(),
        auth.session.owner.user_id.as_str().to_owned(),
    );
    bounded(async move {
        let mut tx = pool.begin().await.map_err(unavailable)?;
        sqlx::query("DELETE FROM nds_global_diagnostic_challenges WHERE expires_at_ms<=$1")
            .bind(i64::try_from(now).map_err(unavailable)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM nds_global_diagnostic_challenges WHERE session_binding=$1 AND device_id=$2",
        )
        .bind(auth.binding.0.as_slice())
        .bind(&device)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if pending >= MAX_PENDING_CHALLENGES {
            return Err(SyncError::Capacity);
        }
        sqlx::query(
            "INSERT INTO nds_global_diagnostic_challenges(challenge,session_binding,device_id,user_id,expires_at_ms) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&stored)
        .bind(auth.binding.0.as_slice())
        .bind(&device)
        .bind(&user)
        .bind(i64::try_from(expires).map_err(unavailable)?)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    })
    .await?;
    Ok(Json(dto::GlobalDiagnosticChallenge {
        challenge,
        namespace: dto::Namespace::NdsGlobalAdminNddevAi,
        expires_at: timestamp(expires)?,
    }))
}

async fn global_grant(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::GlobalDiagnosticGrant>, ApiError> {
    if body.is_empty() || body.len() > 4096 {
        return Err(SyncError::Invalid.into());
    }
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, false).await?;
    let proof: dto::GlobalDiagnosticProof =
        serde_json::from_slice(&body).map_err(|_| SyncError::Invalid)?;
    if !challenge_text(&proof.challenge) {
        return Err(SyncError::Invalid.into());
    }
    let now = now()?;
    let pool = database(&state)?;
    let device = signed.device.as_str().to_owned();
    let user = auth.session.owner.user_id.as_str().to_owned();
    let binding = auth.binding.0;
    // The challenge is spent before the signature is checked: a failed or replayed proof never
    // gets a second attempt with the same challenge.
    let spent: Option<i64> = bounded({
        let (pool, challenge, device) = (pool.clone(), proof.challenge.clone(), device.clone());
        async move {
            sqlx::query_scalar(
                "DELETE FROM nds_global_diagnostic_challenges WHERE challenge=$1 AND session_binding=$2 \
                 AND device_id=$3 RETURNING expires_at_ms",
            )
            .bind(challenge)
            .bind(binding.as_slice())
            .bind(device)
            .fetch_optional(&pool)
            .await
            .map_err(unavailable)
        }
    })
    .await?;
    let fingerprint = spent
        .filter(|expires| u64::try_from(*expires).is_ok_and(|expires| expires > now))
        .and_then(|_| {
            current_keys(&state)
                .ok()
                .and_then(|keys| verify(&proof.signature, proof.challenge.as_bytes(), &keys))
        });
    let Some(fingerprint) = fingerprint else {
        tracing::warn!(
            module = "observability",
            scope = "http",
            event.name = "observability.global_grant.denied",
            outcome = "denied",
            user.id = user.as_str(),
            device.id = device.as_str()
        );
        return Err(ApiError::Diagnostic(dto::Error::ForbiddenScope));
    };
    let expires = now + GRANT_TTL_MS;
    bounded({
        let (fingerprint, device, user) = (fingerprint.clone(), device.clone(), user.clone());
        async move {
            let mut tx = pool.begin().await.map_err(unavailable)?;
            sqlx::query("DELETE FROM nds_global_diagnostic_grants WHERE expires_at_ms<=$1")
                .bind(i64::try_from(now).map_err(unavailable)?)
                .execute(&mut *tx)
                .await
                .map_err(unavailable)?;
            sqlx::query(
                "INSERT INTO nds_global_diagnostic_grants(session_binding,device_id,user_id,key_fingerprint,granted_at_ms,expires_at_ms) \
                 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (session_binding,device_id) DO UPDATE SET \
                 user_id=EXCLUDED.user_id,key_fingerprint=EXCLUDED.key_fingerprint,granted_at_ms=EXCLUDED.granted_at_ms,expires_at_ms=EXCLUDED.expires_at_ms",
            )
            .bind(binding.as_slice())
            .bind(device)
            .bind(user)
            .bind(fingerprint)
            .bind(i64::try_from(now).map_err(unavailable)?)
            .bind(i64::try_from(expires).map_err(unavailable)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)
        }
    })
    .await?;
    tracing::warn!(
        module = "observability",
        scope = "http",
        event.name = "observability.global_grant.issued",
        outcome = "ok",
        key.fingerprint = fingerprint.as_str(),
        user.id = user.as_str(),
        device.id = device.as_str()
    );
    Ok(Json(dto::GlobalDiagnosticGrant {
        expires_at: timestamp(expires)?,
        key_fingerprint: fingerprint,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by OpenSSH: `printf %s "$CHALLENGE" | ssh-keygen -Y sign -f vector -n
    // nds-global-admin@nddev.ai` with a throwaway key; `ssh-keygen -Y verify` accepts it.
    const VECTOR_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG6s5fPv4QcDvRjhnVEOUmDB0j35/UWqkFwxWk6VsbWc test-vector";
    const VECTOR_FINGERPRINT: &str = "SHA256:I6/fU9AtJWVUIOR2Y/DqUqceoi2l5e2p+Mnhm+v6dUA";
    const VECTOR_MESSAGE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const VECTOR_SIGNATURE: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbqzl8+/hBwO9GOGdUQ5SYMHSPf
n9RaqQXDFaTpWxtZwAAAAZbmRzLWdsb2JhbC1hZG1pbkBuZGRldi5haQAAAAAAAAAGc2hh
NTEyAAAAUwAAAAtzc2gtZWQyNTUxOQAAAED446sEP9+IDRPRsNh3/eCxLSe8yO1/sUhA1s
mmAZ7Q+1CbDpOtLwT60nJa+UmfBxv7AUXCbf/0ZNsMb9In+ksC
-----END SSH SIGNATURE-----
";
    // The real global administrator public key (Estate deploy/nds/global-admin-key.json).
    const OWNER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHjpfleg58WnGUo7vOdeL89FiBYsnTqn+WcTXeUi684z nds-global-admin@nddev.ai 2026-11-01";

    #[test]
    fn an_openssh_signature_by_an_allowed_key_is_verified() {
        let keys = admin_keys(&format!("# allowed\n\n{VECTOR_KEY}\n")).unwrap();
        assert_eq!(keys[0].fingerprint, VECTOR_FINGERPRINT);
        assert_eq!(
            verify(VECTOR_SIGNATURE, VECTOR_MESSAGE.as_bytes(), &keys).as_deref(),
            Some(VECTOR_FINGERPRINT)
        );
        assert_eq!(
            admin_keys(OWNER_KEY).unwrap()[0].fingerprint,
            "SHA256:QRdeCjmSIGvn0H+ckgyoc8gjLTgSUoxuS7dXzX/3Ct8"
        );
    }

    #[test]
    fn anything_else_is_refused() {
        let keys = admin_keys(VECTOR_KEY).unwrap();
        // Another message (another challenge) is not covered by the signature.
        let other = VECTOR_MESSAGE.replace('A', "B");
        assert!(verify(VECTOR_SIGNATURE, other.as_bytes(), &keys).is_none());
        // A key that is not (or no longer) allowed opens nothing: revocation is removal.
        assert!(
            verify(
                VECTOR_SIGNATURE,
                VECTOR_MESSAGE.as_bytes(),
                &admin_keys(OWNER_KEY).unwrap()
            )
            .is_none()
        );
        // A flipped signature byte fails.
        let tampered = VECTOR_SIGNATURE.replacen("mmAZ7Q", "mmAZ7R", 1);
        assert!(verify(&tampered, VECTOR_MESSAGE.as_bytes(), &keys).is_none());
        // Armour and size are strict.
        assert!(verify("not a signature", VECTOR_MESSAGE.as_bytes(), &keys).is_none());
        // Allowed-key files accept only Ed25519 keys and refuse the whole file on any bad line.
        for file in [
            "",
            "# only a comment\n",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== rsa\n",
            &format!("{VECTOR_KEY}\nssh-ed25519 not-base64\n"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG6s\n",
        ] {
            assert!(admin_keys(file).is_err(), "{file:?}");
        }
    }

    #[test]
    fn a_signature_in_another_namespace_is_refused() {
        // Re-sign the same structure under a different namespace with a fresh key: valid
        // SSHSIG, wrong purpose.
        let random = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        use signature::KeyPair;
        let mut blob = Vec::new();
        put(&mut blob, b"ssh-ed25519");
        put(&mut blob, pair.public_key().as_ref());
        let keys = admin_keys(&format!("ssh-ed25519 {}", STANDARD.encode(&blob))).unwrap();
        let sign = |namespace: &str| {
            let mut signed = b"SSHSIG".to_vec();
            put(&mut signed, namespace.as_bytes());
            put(&mut signed, b"");
            put(&mut signed, b"sha512");
            put(
                &mut signed,
                digest::digest(&digest::SHA512, VECTOR_MESSAGE.as_bytes()).as_ref(),
            );
            let mut sig = Vec::new();
            put(&mut sig, b"ssh-ed25519");
            put(&mut sig, pair.sign(&signed).as_ref());
            let mut out = b"SSHSIG".to_vec();
            out.extend_from_slice(&1u32.to_be_bytes());
            put(&mut out, &blob);
            put(&mut out, namespace.as_bytes());
            put(&mut out, b"");
            put(&mut out, b"sha512");
            put(&mut out, &sig);
            let text = STANDARD.encode(out);
            let lines: Vec<_> = text
                .as_bytes()
                .chunks(70)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect();
            format!(
                "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
                lines.join("\n")
            )
        };
        assert!(verify(&sign(NAMESPACE), VECTOR_MESSAGE.as_bytes(), &keys).is_some());
        assert!(verify(&sign("file"), VECTOR_MESSAGE.as_bytes(), &keys).is_none());
    }

    #[test]
    fn the_collection_policy_is_off_standard_or_a_finite_debug_window() {
        let now = 1_793_500_000_000;
        let file = br#"{"revision": 3, "debug": [
            {"device_id": "device-a", "expires_at": "2026-11-01T06:00:00Z"},
            {"device_id": "device-b", "expires_at": "2026-11-01T00:00:00Z"},
            {"device_id": "device-c", "expires_at": "2027-01-01T00:00:00Z"}]}"#;
        let policy = effective(true, Some(file), "device-a", now).unwrap();
        assert!(matches!(policy.mode, dto::CollectionMode::Debug));
        assert_eq!(
            policy.debug_expires_at.as_deref(),
            Some("2026-11-01T06:00:00Z")
        );
        assert_eq!(policy.revision, 3);
        // Expired and over-long windows give the standard policy.
        for device in ["device-b", "device-c", "device-z"] {
            let policy = effective(true, Some(file), device, now).unwrap();
            assert!(
                matches!(policy.mode, dto::CollectionMode::Standard),
                "{device}"
            );
            assert!(policy.debug_expires_at.is_none());
        }
        // Disabled export is off for everyone, debug included.
        let policy = effective(false, Some(file), "device-a", now).unwrap();
        assert!(matches!(policy.mode, dto::CollectionMode::Off));
        assert!(policy.debug_expires_at.is_none());
        assert_eq!(effective(true, None, "device-a", now).unwrap().revision, 1);
        assert!(effective(true, Some(b"{\"revision\": 0}"), "device-a", now).is_err());
        assert!(
            effective(
                true,
                Some(b"{\"revision\": 1, \"other\": 1}"),
                "device-a",
                now
            )
            .is_err()
        );
    }
}
