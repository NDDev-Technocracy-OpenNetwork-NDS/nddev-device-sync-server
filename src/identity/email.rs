use super::{
    config::{SmtpConfig, SmtpTls},
    store::Store,
};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use nddev_device_sync_application::identity::{
    EmailDelivery, EmailMessage, IdentityError, IdentityStore, Locale,
};
use opentelemetry::{
    Context,
    trace::{SpanContext, TraceContextExt},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

mod invitation;

const QUEUE_CAPACITY: usize = 16;
enum Content {
    Code(EmailMessage),
    Invitation(nddev_device_sync_application::organizations::InvitationMessage),
}
struct Job {
    message: Content,
    // IDs/flags only: never retain the live HTTP span while a message is queued.
    parent: SpanContext,
}
struct Inner {
    sender: mpsc::Sender<Job>,
    ready: Arc<AtomicBool>,
    last_probe: Arc<AtomicU64>,
    busy: Arc<AtomicBool>,
    worker: tokio::task::JoinHandle<()>,
    invitations_available: bool,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.worker.abort();
        let dropped = QUEUE_CAPACITY - self.sender.capacity()
            + usize::from(self.busy.load(Ordering::Relaxed));
        tracing::info!(
            module = "identity",
            scope = "transport",
            event.name = "email.delivery.stopped",
            dropped_count = dropped,
            outcome = "stopped"
        );
    }
}
#[derive(Clone, Default)]
pub struct Mailer(Option<Arc<Inner>>);

async fn probe(transport: &AsyncSmtpTransport<Tokio1Executor>) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(5), transport.test_connection()).await,
        Ok(Ok(true))
    )
}

impl Mailer {
    pub async fn new(
        config: Option<&SmtpConfig>,
        store: Store,
        companies: crate::organizations::store::Store,
        origin: Option<reqwest::Url>,
    ) -> Result<Self, IdentityError> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        let builder = match config.tls {
            SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|_| IdentityError::InvalidInput)?,
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|_| IdentityError::InvalidInput)?,
            SmtpTls::Loopback => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
            }
        }
        .port(config.port)
        .timeout(Some(Duration::from_secs(5)));
        let builder = match (&config.username, &config.password) {
            (Some(user), Some(password)) => {
                builder.credentials(Credentials::new(user.clone(), password.expose().into()))
            }
            _ => builder,
        };
        let transport = builder.build();
        let from = Mailbox::new(
            Some("NDDev OpenNetwork".into()),
            config
                .from
                .as_str()
                .parse()
                .map_err(|_| IdentityError::InvalidInput)?,
        );
        let ready = Arc::new(AtomicBool::new(probe(&transport).await));
        tracing::info!(
            module = "identity",
            scope = "transport",
            event.name = "email.transport.checked",
            available = ready.load(Ordering::Relaxed),
            outcome = "checked"
        );
        let worker_ready = ready.clone();
        let last_probe = Arc::new(AtomicU64::new(super::now_ms()?));
        let worker_time = last_probe.clone();
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = busy.clone();
        let (sender, mut receiver) = mpsc::channel::<Job>(QUEUE_CAPACITY);
        let invitations_available = origin.is_some();
        let worker = tokio::spawn(async move {
            let refresh = tokio::time::sleep(Duration::from_secs(60));
            tokio::pin!(refresh);
            let mut backoff_seconds = 60;
            let mut failed_probes = 0_u32;
            loop {
                tokio::select! {
                    _=&mut refresh=>{
                        let available=probe(&transport).await;
                        worker_time.store(super::now_ms().unwrap_or(0),Ordering::Relaxed);
                        let previous=worker_ready.swap(available,Ordering::Relaxed);
                        if previous!=available { tracing::info!(module = "identity", scope = "transport", event.name="email.transport.changed", available, outcome=if available {"ready"} else {"unavailable"}); }
                        if available {backoff_seconds=60;failed_probes=0;} else {
                            backoff_seconds=(backoff_seconds*2).min(300);failed_probes=failed_probes.saturating_add(1);
                            tracing::warn!(module = "identity", scope = "transport", event.name="email.transport.unavailable",retry_count=failed_probes,backoff_seconds,outcome="unavailable");
                        }
                        refresh.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(backoff_seconds));
                    },
                    job=receiver.recv()=>{
                        let Some(job)=job else { break; };
                        worker_busy.store(true,Ordering::Relaxed);
                        let span = delivery_span(job.parent);
                        async {
                            let message=match job.message {
                                Content::Code(message)=>message,
                                Content::Invitation(message)=>{
                                    let result=invitation::deliver(&transport,&from,&companies,origin.as_ref(),message).await;
                                    if result.is_ok() { worker_ready.store(true,Ordering::Relaxed);worker_time.store(super::now_ms().unwrap_or(0),Ordering::Relaxed); }
                                    else if result==Err(IdentityError::Unavailable) { worker_ready.store(false,Ordering::Relaxed); }
                                    return;
                                }
                            };
                            let delivery=async {
                                if super::now_ms()? >= message.expires_at_ms { return Err(IdentityError::Denied); }
                                let recipient=message.recipient.as_str().parse().map_err(|_|IdentityError::InvalidInput)?;
                                let (subject, body) = match message.locale {
                                    Locale::En => ("NDDev OpenNetwork sign-in code", format!("NDDev OpenNetwork\n\nYour sign-in code: {}\n\nThis code expires five minutes after your request. Do not share it. If you did not request sign-in, ignore this message.\n\nhttps://nddev.ai\n", message.code.expose())),
                                    Locale::Ru => ("Код входа в NDDev OpenNetwork", format!("NDDev OpenNetwork\n\nВаш код входа: {}\n\nКод действует пять минут с момента запроса. Никому его не сообщайте. Если вы не запрашивали вход, проигнорируйте это письмо.\n\nhttps://nddev.ai\n", message.code.expose())),
                                };
                                let email=Message::builder().from(from.clone()).to(Mailbox::new(None,recipient)).subject(subject).header(ContentType::TEXT_PLAIN).body(body).map_err(|_|IdentityError::InvalidInput)?;
                                transport.send(email).await.map_err(|_|IdentityError::Unavailable)?;
                                Ok::<(),IdentityError>(())
                            };
                            let result=tokio::time::timeout(Duration::from_secs(8),delivery).await.unwrap_or(Err(IdentityError::Unavailable));
                            match result {
                                Ok(()) => { worker_ready.store(true,Ordering::Relaxed); worker_time.store(super::now_ms().unwrap_or(0),Ordering::Relaxed); tracing::info!(module = "identity", scope = "transport", event.name="email.delivery.accepted", outcome="provider_accepted", mailbox_delivery="unverified"); },
                                Err(error) => {
                                    if error==IdentityError::Unavailable { worker_ready.store(false,Ordering::Relaxed); }
                                    let invalidated=store.invalidate_email(&message.challenge_id).await.is_ok();
                                    tracing::error!(module = "identity", scope = "transport", event.name="email.delivery.failed", error.type=%error, challenge_invalidated=invalidated, outcome="error");
                                }
                            }
                        }.instrument(span).await;
                        worker_busy.store(false,Ordering::Relaxed);
                    }
                }
            }
        });
        Ok(Self(Some(Arc::new(Inner {
            sender,
            ready,
            last_probe,
            busy,
            worker,
            invitations_available,
        }))))
    }
}
impl EmailDelivery for Mailer {
    fn available(&self) -> bool {
        self.0.as_ref().is_some_and(|inner| {
            inner.ready.load(Ordering::Relaxed)
                && super::now_ms().is_ok_and(|now| {
                    now.saturating_sub(inner.last_probe.load(Ordering::Relaxed)) <= 120_000
                })
        })
    }
    fn queue(&self, message: EmailMessage) -> Result<(), IdentityError> {
        self.enqueue(Content::Code(message))
    }
}
impl Mailer {
    fn enqueue(&self, message: Content) -> Result<(), IdentityError> {
        let inner = self.0.as_ref().ok_or(IdentityError::Unavailable)?;
        inner
            .sender
            .try_send(Job {
                message,
                parent: nddev_device_sync_telemetry::trace_context(&tracing::Span::current())
                    .span()
                    .span_context()
                    .clone(),
            })
            .map_err(|_| {
                tracing::warn!(
                    module = "identity",
                    scope = "http",
                    event.name = "email.delivery.queue_rejected",
                    outcome = "rejected"
                );
                IdentityError::Capacity
            })
    }
}
impl nddev_device_sync_application::organizations::InvitationDelivery for Mailer {
    fn available(&self) -> bool {
        EmailDelivery::available(self)
            && self
                .0
                .as_ref()
                .is_some_and(|inner| inner.invitations_available)
    }
    fn queue(
        &self,
        message: nddev_device_sync_application::organizations::InvitationMessage,
    ) -> Result<(), nddev_device_sync_domain::organizations::OrganizationError> {
        self.enqueue(Content::Invitation(message))
            .map_err(|error| match error {
                IdentityError::Capacity => {
                    nddev_device_sync_domain::organizations::OrganizationError::Busy
                }
                _ => nddev_device_sync_domain::organizations::OrganizationError::Unavailable,
            })
    }
}

fn delivery_span(parent: SpanContext) -> tracing::Span {
    let span = nddev_device_sync_telemetry::operation_span("identity", "transport")
        .expect("static delivery span labels");
    if span
        .set_parent(Context::new().with_remote_span_context(parent))
        .is_err()
    {
        tracing::warn!(module = "identity", scope = "transport", event.name = "email.delivery.context_unavailable", error.type = "trace_context", outcome = "error");
    }
    span
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_context_does_not_retain_the_http_parent_span() {
        let (subscriber, provider, captured) = crate::telemetry_test::capture();
        tracing::dispatcher::with_default(&subscriber, || {
            let request = nddev_device_sync_telemetry::operation_span("http", "http").unwrap();
            let parent = nddev_device_sync_telemetry::trace_context(&request)
                .span()
                .span_context()
                .clone();
            assert!(parent.is_valid());
            let parent_id = parent.span_id();
            let trace_id = parent.trace_id();
            drop(request);
            // Only the immutable queued context remains. The actual SDK parent
            // must already be complete before SMTP work creates its child.
            assert_eq!(captured.0.lock().unwrap().len(), 1);
            let delivery = delivery_span(parent);
            assert_eq!(
                nddev_device_sync_telemetry::trace_context(&delivery)
                    .span()
                    .span_context()
                    .trace_id(),
                trace_id
            );
            drop(delivery);
            let spans = captured.0.lock().unwrap();
            assert_eq!(spans.len(), 2);
            assert_eq!(spans[1].parent_span_id, parent_id);
            assert!(
                spans[1]
                    .attributes
                    .iter()
                    .any(|field| field.key.as_str() == "scope"
                        && field.value.as_str() == "transport")
            );
            assert!(spans[1].start_time >= spans[0].end_time);
        });
        provider.shutdown().unwrap();
    }
}
