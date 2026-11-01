// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v2/company.schema.json
// Schema SHA-256: b0ecd6b70f408e14974f3ae144e8d32a88ba4aee1e777d6bfc6d3d754c4d7a58
// Generator script SHA-256: ba71ce353a691d59227fbe948f45edf4b0667be7e5a105741f551d3186f6a8b8
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: ec1d8541bcae0771e2fe0e95e572f60898fd62e6e31fbfbea80451d244aff5b9
// DTO generation is not schema, authorization or cryptographic validation.
// Shared schema SHA-256: 301f0aa51fa5774216690e257c56186c598b207e465f3284bda8f746146b8cf4

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyOverview {
    pub company: Company,

    pub member: CompanyMember,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Company {
    pub company_id: String,

    pub display_name: String,

    pub revision: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyMember {
    pub active: bool,

    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub email: Option<String>,

    pub revision: i64,

    pub role: Role,

    pub user_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,

    User,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyMemberPage {
    pub members: Vec<CompanyMember>,

    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyInvitationPage {
    pub invitations: Vec<CompanyInvitation>,

    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyInvitation {
    pub delivery: Delivery,

    pub expires_at_ms: i64,

    pub invitation_id: String,

    pub issuer_user_id: String,

    pub recipient_email: String,

    pub role: Role,

    pub status: Status,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    Accepted,

    Failed,

    Pending,

    Unknown,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Accepted,

    Expired,

    Pending,

    Revoked,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyInvitationRequest {
    pub email: String,

    pub operation_id: String,

    pub role: Role,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyRevokeRequest {
    pub operation_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyMemberChangeRequest {
    pub action: Action,

    pub expected_revision: i64,

    pub operation_id: String,

    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub role: Option<Role>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Remove,

    #[serde(rename = "set_role")]
    SetRole,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyError {
    pub error: Error,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[serde(rename = "authentication_failed")]
    AuthenticationFailed,

    #[serde(rename = "authorization_denied")]
    AuthorizationDenied,

    #[serde(rename = "command_expired")]
    CommandExpired,

    #[serde(rename = "dependency_unavailable")]
    DependencyUnavailable,

    #[serde(rename = "device_revoked")]
    DeviceRevoked,

    #[serde(rename = "invalid_request")]
    InvalidRequest,

    #[serde(rename = "invalid_signature")]
    InvalidSignature,

    #[serde(rename = "invitation_unavailable")]
    InvitationUnavailable,

    #[serde(rename = "last_administrator")]
    LastAdministrator,

    #[serde(rename = "operation_conflict")]
    OperationConflict,

    #[serde(rename = "replayed_nonce")]
    ReplayedNonce,

    #[serde(rename = "server_busy")]
    ServerBusy,
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
