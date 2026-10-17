// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v2/company.schema.json
// Schema SHA-256: b0ecd6b70f408e14974f3ae144e8d32a88ba4aee1e777d6bfc6d3d754c4d7a58
// Generator script SHA-256: ae62f41c006f464727fbd660edaecacfc3713a3a84f4050ab600a89ec4a06a77
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: 643e0f2ba88602f4acb9546c401d4838e8e106a9180c0e6f3a760985081bfcf6
// DTO generation is not schema, authorization or cryptographic validation.
// Shared schema SHA-256: 22f8a01aa3ff70b3198dcceb72f42e4de2dcc2087fa2db2a9c3864f513e051a9

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
