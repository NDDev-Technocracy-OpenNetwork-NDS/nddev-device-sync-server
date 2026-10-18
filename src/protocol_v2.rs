// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v2/control-plane.schema.json
// Schema SHA-256: 301f0aa51fa5774216690e257c56186c598b207e465f3284bda8f746146b8cf4
// Generator script SHA-256: d87232c61e2f32b56dc9c6d92d9f58f45108c2b0d4fe07ff570bedd7570352b7
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: 643e0f2ba88602f4acb9546c401d4838e8e106a9180c0e6f3a760985081bfcf6
// DTO generation is not schema, authorization or cryptographic validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthMethods {
    pub email_otp: MethodAvailability,

    pub github: MethodAvailability,

    pub passkey: MethodAvailability,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodAvailability {
    Available,

    Unavailable,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailChallengeRequest {
    pub email: String,
}

/// Begin normal email verification for the intended recipient of a live invitation.
/// Invitation possession alone never activates membership or creates a session.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationEmailChallengeRequest {
    pub email: String,

    pub invitation_id: String,

    pub invitation_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailChallenge {
    pub challenge_id: String,

    pub expires_in_seconds: i32,

    pub resend_after_seconds: i32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailVerifyRequest {
    pub challenge_id: String,

    pub code: String,
}

/// One successful device-bound server verification. Retains the original authentication
/// proof; this metadata contains no credential and cannot itself renew authorization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRenewal {
    /// Canonical unpadded base64url identity for this retained server session, not an
    /// authentication token. Rust credential ownership only; never expose in presentation
    /// metadata or telemetry.
    pub authorization_id: String,

    pub session: Session,

    pub verified_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub auth_method: AuthMethod,

    pub expires_at: String,

    pub tenant_id: String,

    pub user_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    #[serde(rename = "email_otp")]
    EmailOtp,

    Github,

    Passkey,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionIssued {
    pub session: Session,

    pub session_token: String,
}

/// Same-origin browser session result. The credential is delivered only through the Secure
/// HttpOnly host-only session cookie.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserSessionIssued {
    pub session: Session,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCapabilities {
    pub device_platform: DevicePlatform,

    pub replica_protocol: i64,

    pub session_mode: SessionMode,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    Web,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Cookie,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubStart {
    pub authorization_url: String,

    pub exchange_token: String,

    pub expires_in_seconds: i32,

    pub flow_id: String,

    pub poll_after_seconds: i32,

    /// Comparison code displayed by the initiating app and browser approval page; not a bearer
    /// credential or email OTP.
    pub verification_code: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubExchangeRequest {
    pub exchange_token: String,

    pub flow_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPending {
    pub retry_after_seconds: i32,

    pub status: GithubPendingStatus,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubPendingStatus {
    Pending,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubApprovalForm {
    pub csrf_token: String,

    pub decision: Decision,

    pub flow_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,

    Deny,
}

/// Bounded native/browser WebAuthn handoff. Exchange token remains native; the browser
/// proves authenticator possession and user verification before delivery.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyStart {
    pub authorization_url: String,

    pub exchange_token: String,

    pub expires_in_seconds: i32,

    pub flow_id: String,

    pub poll_after_seconds: i32,

    /// Comparison code displayed by the initiating app and browser approval page; not a bearer
    /// credential or email OTP.
    pub verification_code: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRequest {
    /// Login account selector, never authentication. Omit for registration, which uses the
    /// authenticated session. Omission at login is accepted only when exactly one active account
    /// exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    pub registration: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyStatus {
    pub retry_after_seconds: i32,

    pub status: PasskeyStatusStatus,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyStatusStatus {
    Pending,

    Registered,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyList {
    pub passkeys: Vec<PasskeyInfo>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyInfo {
    pub created_at: String,

    pub id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRevocation {
    pub current_session_revoked: bool,

    pub passkey_available: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub error: ErrorEnum,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorEnum {
    #[serde(rename = "authentication_failed")]
    AuthenticationFailed,

    #[serde(rename = "authorization_denied")]
    AuthorizationDenied,

    #[serde(rename = "challenge_expired")]
    ChallengeExpired,

    #[serde(rename = "cursor_expired")]
    CursorExpired,

    #[serde(rename = "dependency_unavailable")]
    DependencyUnavailable,

    #[serde(rename = "device_revoked")]
    DeviceRevoked,

    #[serde(rename = "idempotency_conflict")]
    IdempotencyConflict,

    #[serde(rename = "invalid_request")]
    InvalidRequest,

    #[serde(rename = "invalid_signature")]
    InvalidSignature,

    #[serde(rename = "method_unavailable")]
    MethodUnavailable,

    #[serde(rename = "operation_conflict")]
    OperationConflict,

    #[serde(rename = "rate_limited")]
    RateLimited,

    #[serde(rename = "recent_authentication_required")]
    RecentAuthenticationRequired,

    #[serde(rename = "replayed_nonce")]
    ReplayedNonce,

    #[serde(rename = "request_timeout")]
    RequestTimeout,

    #[serde(rename = "revision_exhausted")]
    RevisionExhausted,

    #[serde(rename = "server_busy")]
    ServerBusy,

    #[serde(rename = "sync_capacity_exhausted")]
    SyncCapacityExhausted,

    #[serde(rename = "vault_key_registration_required")]
    VaultKeyRegistrationRequired,
}
