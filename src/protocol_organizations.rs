// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v3/organizations.schema.json
// Schema SHA-256: dfe08a5027552c9b009ce9786eabcd62bfa3c75c042a8df2785f39a99ef0b839
// Generator script SHA-256: 7d14f49ab7a94ec68910c3e15a158af1c23626ec52abebac537c8bc04fcee73d
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: ec1d8541bcae0771e2fe0e95e572f60898fd62e6e31fbfbea80451d244aff5b9
// DTO generation is not schema, authorization or cryptographic validation.
// Dependency https://nddev.ai/schemas/nddev-device-sync/v2/control-plane.schema.json SHA-256: 301f0aa51fa5774216690e257c56186c598b207e465f3284bda8f746146b8cf4
// Dependency https://nddev.ai/schemas/nddev-device-sync/v2/company.schema.json SHA-256: b0ecd6b70f408e14974f3ae144e8d32a88ba4aee1e777d6bfc6d3d754c4d7a58
// Dependency https://nddev.ai/schemas/nddev-device-sync/v3/personal.schema.json SHA-256: 115693d85e393b251d65d52bfc8aaa250f80532b5497e1dfbf78bd4925469896

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationList {
    pub context: PersonalContext,

    pub organizations: Vec<CompanyOverview>,
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

    pub kind: PersonalSpaceKind,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalSpaceKind {
    Personal,
}

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

/// An already verified and enrolled principal creates an organization with an administrative
/// membership. No open account registration or global administration is implied. The
/// original command ID and exact bytes own replay; capacity is a typed refusal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationCreateRequest {
    pub display_name: String,

    pub operation_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationOverview {
    pub context: OrganizationContext,

    pub overview: CompanyOverview,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationContext {
    pub membership_revision: i64,

    pub principal_id: String,

    pub space: OrganizationSpace,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationSpace {
    pub id: String,

    pub kind: OrganizationSpaceKind,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationSpaceKind {
    Organization,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMemberPage {
    pub context: OrganizationContext,

    pub page: CompanyMemberPage,
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
pub struct OrganizationInvitationPage {
    pub context: OrganizationContext,

    pub page: CompanyInvitationPage,
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
pub struct OrganizationInvitationResult {
    pub context: OrganizationContext,

    pub invitation: CompanyInvitation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMemberResult {
    pub context: OrganizationContext,

    pub member: CompanyMember,
}

/// Capture the initiating membership revision once with the immutable command. Role
/// change/removal/rejoin cannot lend a newer grant to an earlier command.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationInvitationRequest {
    pub membership_revision: i64,

    pub payload: CompanyInvitationRequest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyInvitationRequest {
    pub email: String,

    pub operation_id: String,

    pub role: Role,
}

/// Capture the initiating membership revision once with the immutable command. Role
/// change/removal/rejoin cannot lend a newer grant to an earlier command.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRevokeRequest {
    pub membership_revision: i64,

    pub payload: CompanyRevokeRequest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanyRevokeRequest {
    pub operation_id: String,
}

/// Capture the initiating membership revision once with the immutable command. Role
/// change/removal/rejoin cannot lend a newer grant to an earlier command.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMemberChangeRequest {
    pub membership_revision: i64,

    pub payload: CompanyMemberChangeRequest,
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

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
