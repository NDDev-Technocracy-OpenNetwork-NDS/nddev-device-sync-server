//! One-use delivery through the same bounded SMTP worker as ordinary OTP.
use super::*;
use nddev_device_sync_application::organizations::{InvitationMessage, OrganizationStore};
use nddev_device_sync_domain::organizations::commands::DeliveryState;

pub(super) async fn deliver(
    transport: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
    store: &crate::organizations::store::Store,
    origin: Option<&reqwest::Url>,
    message: InvitationMessage,
) -> Result<(), IdentityError> {
    let prepared = (|| {
        let now = super::super::now_ms()?;
        if now >= message.delivery_deadline_ms || now >= message.expires_at_ms {
            return Err(IdentityError::Denied);
        }
        let mut url = origin
            .ok_or(IdentityError::Unavailable)?
            .join("/")
            .map_err(|_| IdentityError::Unavailable)?;
        url.set_fragment(Some(&format!(
            "invite/{}/{}",
            message.id.as_str(),
            message.token.expose()
        )));
        let (subject, body) = match message.locale {
            Locale::En => (
                "Invitation to NDDev OpenNetwork",
                format!(
                    "You have been invited to a company in NDS.\n\n{}\n\nThis invitation expires seven days after creation. Accept with this email address and verify the separate sign-in code. The link alone does not sign you in. Do not share it. If unexpected, ignore it.\n",
                    url.as_str()
                ),
            ),
            Locale::Ru => (
                "Приглашение в NDDev OpenNetwork",
                format!(
                    "Вас пригласили в компанию в NDS.\n\n{}\n\nПриглашение действует семь дней с момента создания. Примите его с этим адресом почты и подтвердите отдельный код входа. Одна ссылка не выполняет вход. Не передавайте её другим. Если письмо неожиданное, проигнорируйте его.\n",
                    url.as_str()
                ),
            ),
        };
        Message::builder()
            .from(from.clone())
            .to(Mailbox::new(
                None,
                message
                    .recipient
                    .as_str()
                    .parse()
                    .map_err(|_| IdentityError::InvalidInput)?,
            ))
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|_| IdentityError::InvalidInput)
    })();
    let (state, result) = match prepared {
        Err(error) => (DeliveryState::Failed, Err(error)),
        Ok(email) => {
            match tokio::time::timeout(Duration::from_secs(8), transport.send(email)).await {
                Ok(Ok(_)) => (DeliveryState::Accepted, Ok(())),
                _ => (DeliveryState::Unknown, Err(IdentityError::Unavailable)),
            }
        }
    };
    match state {
        DeliveryState::Accepted => tracing::info!(
            module = "organizations",
            scope = "transport",
            event.name = "company.invitation.delivery.accepted",
            invitation.id = message.id.as_str(),
            outcome = "provider_accepted",
            mailbox_delivery = "unverified"
        ),
        _ => {
            tracing::warn!(module="organizations",scope="transport",event.name="company.invitation.delivery.failed",invitation.id=message.id.as_str(),outcome="error",error.type=if state==DeliveryState::Unknown{"delivery_unknown"}else{"delivery_not_attempted"})
        }
    }
    if store.delivery(&message.id, state).await.is_err() {
        tracing::error!(module="organizations",scope="database",event.name="company.invitation.delivery.record_failed",invitation.id=message.id.as_str(),outcome="error",error.type="company_dependency_unavailable");
    }
    result
}
