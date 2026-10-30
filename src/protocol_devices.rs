// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v2/control-plane.schema.json
// Schema SHA-256: 301f0aa51fa5774216690e257c56186c598b207e465f3284bda8f746146b8cf4
// Generator script SHA-256: 4d114bb4979e5a2d816875ae362b982fd3dca76513ed82cf3ad8aa2d90c015de
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: ec1d8541bcae0771e2fe0e95e572f60898fd62e6e31fbfbea80451d244aff5b9
// DTO generation is not schema, authorization or cryptographic validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub display_name: String,

    pub platform: Platform,

    pub public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,

    Ios,

    Linux,

    Macos,

    Web,

    Windows,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub challenge: String,

    pub challenge_id: String,

    pub device_id: String,

    pub expires_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProof {
    pub challenge_id: String,

    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceList {
    pub devices: Vec<Device>,

    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub created_at: String,

    pub device_id: String,

    pub display_name: String,

    pub platform: Platform,

    pub public_key: String,

    pub status: Status,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,

    Revoked,
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

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
