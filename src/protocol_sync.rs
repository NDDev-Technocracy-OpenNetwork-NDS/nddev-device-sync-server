// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v2/control-plane.schema.json
// Schema SHA-256: 22f8a01aa3ff70b3198dcceb72f42e4de2dcc2087fa2db2a9c3864f513e051a9
// Generator script SHA-256: ae62f41c006f464727fbd660edaecacfc3713a3a84f4050ab600a89ec4a06a77
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: 643e0f2ba88602f4acb9546c401d4838e8e106a9180c0e6f3a760985081bfcf6
// DTO generation is not schema, authorization or cryptographic validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncApplied {
    pub operation_id: String,

    pub outcome: SyncAppliedOutcome,

    pub revision: i64,

    pub server_seq: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncAppliedOutcome {
    Applied,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConflict {
    pub base_revision: i64,

    pub current_revision: i64,

    pub operation_id: String,

    pub outcome: SyncConflictOutcome,

    pub resolution_state: ResolutionState,

    pub server_seq: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncConflictOutcome {
    Conflict,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionState {
    Unresolved,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncPage {
    pub entries: Vec<SyncEntry>,

    pub has_more: bool,

    pub next_after_seq: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEntry {
    pub operation: SyncOperation,

    pub result: Sync,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncOperation {
    pub base_revision: i64,

    pub device_id: String,

    pub entity_id: String,

    pub entity_type: EntityType,

    pub idempotency_key: String,

    pub operation_id: String,

    pub payload: EncryptedPayload,

    pub schema_version: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    #[serde(rename = "account_state")]
    AccountState,

    #[serde(rename = "clipboard_item")]
    ClipboardItem,

    #[serde(rename = "device_state")]
    DeviceState,

    #[serde(rename = "module_state")]
    ModuleState,

    #[serde(rename = "vault_record")]
    VaultRecord,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedPayload {
    pub algorithm: Algorithm,

    pub ciphertext: String,

    pub key_id: String,

    pub nonce: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Sync {
    Applied(SyncApplied),
    Conflict(SyncConflict),
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
