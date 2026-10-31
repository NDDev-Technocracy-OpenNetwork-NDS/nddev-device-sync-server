// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v3/personal.schema.json
// Schema SHA-256: 115693d85e393b251d65d52bfc8aaa250f80532b5497e1dfbf78bd4925469896
// Generator script SHA-256: 7d14f49ab7a94ec68910c3e15a158af1c23626ec52abebac537c8bc04fcee73d
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: ec1d8541bcae0771e2fe0e95e572f60898fd62e6e31fbfbea80451d244aff5b9
// DTO generation is not schema, authorization or cryptographic validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalDeviceList {
    pub context: PersonalContext,

    pub devices: Vec<Device>,

    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub next_cursor: Option<String>,
}

/// The server derives principal_id and space.id from the same authenticated user; consumers
/// must require equality to their captured initiating principal. This does not expose
/// session credentials or legacy storage ownership.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalContext {
    pub principal_id: String,

    pub space: PersonalSpace,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalSpace {
    pub id: String,

    pub kind: Kind,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Personal,
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
pub enum Platform {
    Android,

    Ios,

    Linux,

    Macos,

    Web,

    Windows,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,

    Revoked,
}

/// Current policy of one device owned by the authenticated principal. Device identity, key
/// and proof are unaffected by policy revisions.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalDevicePolicy {
    pub context: PersonalContext,

    pub device_id: String,

    pub policy: DevicePolicy,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicy {
    pub mode: ControlMode,

    pub purposes: Vec<DevicePurpose>,

    pub revision: i64,
}

/// Authenticated device action-admission mode (ADR 0018). Fullauto admits supported system
/// tools without an NDS checklist; manual keeps the owner's explicit module configuration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    Fullauto,

    Manual,
}

/// Intended workload profile from the architecture's device placement table. Describes
/// intent only; never a grant.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DevicePurpose {
    #[serde(rename = "build-dev-desktop")]
    BuildDevDesktop,

    Desktop,

    #[serde(rename = "dev-desktop")]
    DevDesktop,

    #[serde(rename = "server-desktop")]
    ServerDesktop,

    #[serde(rename = "server-dev-desktop")]
    ServerDevDesktop,

    #[serde(rename = "server-hosting")]
    ServerHosting,
}

/// Compare-and-set replacement by the device owner. Widening manual into fullauto requires a
/// recent sign-in.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicyUpdate {
    pub expected_revision: i64,

    pub mode: ControlMode,

    pub purposes: Vec<DevicePurpose>,
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
