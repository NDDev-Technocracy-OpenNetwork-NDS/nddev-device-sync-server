use crate::protocol_company as dto;
use nddev_device_sync_application::organizations::{InvitationRecord, Member, Overview};
use nddev_device_sync_domain::organizations::{
    CompanyRole, OrganizationError, commands::DeliveryState, invitations::InvitationStatus,
};
fn integer(value: u64) -> Result<i64, OrganizationError> {
    value.try_into().map_err(|_| OrganizationError::Unavailable)
}
pub fn role(value: CompanyRole) -> dto::Role {
    match value {
        CompanyRole::Admin => dto::Role::Admin,
        CompanyRole::User => dto::Role::User,
    }
}
pub fn selected_role(value: dto::Role) -> CompanyRole {
    match value {
        dto::Role::Admin => CompanyRole::Admin,
        dto::Role::User => CompanyRole::User,
    }
}
pub fn member(value: &Member) -> Result<dto::CompanyMember, OrganizationError> {
    Ok(dto::CompanyMember {
        user_id: value.membership.owner.user_id.as_str().into(),
        email: value.email.as_ref().map(|email| email.as_str().into()),
        role: role(value.membership.role),
        active: value.membership.active,
        revision: integer(value.revision)?,
    })
}
pub fn overview(value: &Overview) -> Result<dto::CompanyOverview, OrganizationError> {
    if value.company.id != value.member.membership.company_id {
        return Err(OrganizationError::Unavailable);
    }
    Ok(dto::CompanyOverview {
        company: dto::Company {
            company_id: value.company.id.as_str().into(),
            display_name: value.company.name.as_str().into(),
            revision: integer(value.company.revision)?,
        },
        member: member(&value.member)?,
    })
}
pub fn invitation(value: &InvitationRecord) -> Result<dto::CompanyInvitation, OrganizationError> {
    Ok(dto::CompanyInvitation {
        invitation_id: value.metadata.id.as_str().into(),
        issuer_user_id: value.metadata.issuer.user_id.as_str().into(),
        recipient_email: value.email.as_str().into(),
        role: role(value.metadata.role),
        expires_at_ms: integer(value.metadata.expires_at_ms)?,
        status: match value.metadata.status {
            InvitationStatus::Pending => dto::Status::Pending,
            InvitationStatus::Accepted => dto::Status::Accepted,
            InvitationStatus::Revoked => dto::Status::Revoked,
            InvitationStatus::Expired => dto::Status::Expired,
        },
        delivery: match value.delivery {
            DeliveryState::Pending => dto::Delivery::Pending,
            DeliveryState::Accepted => dto::Delivery::Accepted,
            DeliveryState::Failed => dto::Delivery::Failed,
            DeliveryState::Unknown => dto::Delivery::Unknown,
        },
    })
}
