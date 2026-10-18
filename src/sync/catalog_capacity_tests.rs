//! Generated catalog sizes and canonical lifecycle qualification. This is not
//! PostgreSQL, deployed-device or provider acceptance; those have separate gates.
use super::codec;
use crate::{protocol_sync as wire, protocol_sync3 as v3};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_application::sync::retention_reserve_rows;
use nddev_device_sync_domain::{
    DeviceId,
    repositories::catalog::{observations::*, *},
    state::{Snapshot, State},
    sync::{history::*, *},
};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::collections::BTreeMap;

const DEVICES: u64 = 32;
const REPOSITORIES: u64 = 1024;
const OWNERS: u64 = 32;

fn owner(index: u64) -> GithubAccountId {
    GithubAccountId::new(u64::MAX - index).unwrap()
}
fn observed(data: ObservationData, device: u64) -> RepositoryObservation {
    RepositoryObservation {
        source: ObservationSource {
            context: ObservationContext {
                principal: owner(0),
                selection: CredentialSelection::new(
                    format!("{}{:02}", "c".repeat(126), device),
                    1,
                    None,
                )
                .unwrap(),
                scan_id: format!("scan-{device:0123}"),
            },
            page: Some(1),
        },
        data,
    }
}

fn encoded(
    value: &RepositoryObservation,
    device: u64,
    basis: u64,
    revision: u64,
    resolved: u64,
    nonce_id: u64,
    key: &aead::LessSafeKey,
) -> (VersionedOperation, Vec<u8>) {
    let writer = DeviceId::new(format!("device-{device:036}")).unwrap();
    let entity = value.key().entity_id();
    let snapshot = Snapshot {
        schema_version: 2,
        observed_at_ms: 1_800_000_000_000 + device,
        data: State::Repository {
            observation: value.clone(),
        },
    };
    snapshot
        .validate(&writer, EntityKind::RepositoryState, &entity)
        .unwrap();
    let id = format!("operation-{nonce_id:026}");
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&nonce_id.to_be_bytes());
    let mut op = VersionedOperation::qualify(
        Operation {
            id: id.clone(),
            device: writer,
            entity_kind: EntityKind::RepositoryState,
            entity_id: entity,
            base_revision: revision,
            idempotency_key: id,
            payload: EncryptedPayload {
                key_id: "generated-capacity-key".into(),
                nonce,
                ciphertext: vec![],
            },
        },
        basis,
        Lifecycle {
            resolved_through_seq: resolved,
        },
    )
    .unwrap();
    let scope = AadScope {
        origin: "https://capacity.example.invalid/",
        tenant: "tenant",
        user: "owner",
    };
    let aad = serde_json::to_vec(&op.aad(scope, &op.operation.payload.key_id).unwrap()).unwrap();
    let plain = serde_json::to_vec(&snapshot).unwrap();
    let mut cipher = plain.clone();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(&aad),
        &mut cipher,
    )
    .unwrap();
    let mut opened = cipher.clone();
    assert_eq!(
        key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad),
            &mut opened
        )
        .unwrap(),
        plain
    );
    op.operation.payload.ciphertext = cipher;
    let o = &op.operation;
    let body = serde_json::to_vec(&v3::SyncOperationV3 {
        schema_version: 3,
        base_revision: revision as i64,
        basis_seq: basis as i64,
        device_id: o.device.as_str().into(),
        entity_id: o.entity_id.clone(),
        entity_type: v3::EntityType::RepositoryState,
        idempotency_key: o.idempotency_key.clone(),
        operation_id: o.id.clone(),
        lifecycle: v3::Lifecycle {
            resolved_through_seq: resolved as i64,
        },
        payload: v3::EncryptedPayload {
            algorithm: v3::Algorithm::Aes256Gcm,
            key_id: o.payload.key_id.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&o.payload.ciphertext),
        },
    })
    .unwrap();
    let decoded = codec::version3(serde_json::from_slice(&body).unwrap(), body.len()).unwrap();
    assert!(decoded == op);
    (op, body)
}

// Retained metadata drives production pure functions; this is not a fake store.
struct Budget<'a> {
    rows: Vec<RetainedMeta<'a>>,
    history: HistoryVersion,
    bytes: u64,
    caps: RetentionCaps,
    cuts: usize,
    peak_rows: usize,
    peak_bytes: u64,
}
impl<'a> Budget<'a> {
    fn append(
        &mut self,
        entity: &'a str,
        op: &VersionedOperation,
        body: &[u8],
        current: u64,
    ) -> u64 {
        assert_eq!(
            admission(Lookup::Missing, op.version, self.history, false).unwrap(),
            Admission::New
        );
        let seq = self.history.head + 1;
        let decision = op.operation.decide(current).unwrap();
        let (status, result) = match decision {
            Decision::Apply { revision } => (
                201,
                serde_json::to_vec(&wire::SyncApplied {
                    operation_id: op.operation.id.clone(),
                    outcome: wire::SyncAppliedOutcome::Applied,
                    revision: revision as i64,
                    server_seq: seq as i64,
                })
                .unwrap(),
            ),
            Decision::Conflict {
                base_revision,
                current_revision,
            } => (
                409,
                serde_json::to_vec(&wire::SyncConflict {
                    operation_id: op.operation.id.clone(),
                    outcome: wire::SyncConflictOutcome::Conflict,
                    base_revision: base_revision as i64,
                    current_revision: current_revision as i64,
                    resolution_state: wire::ResolutionState::Unresolved,
                    server_seq: seq as i64,
                })
                .unwrap(),
            ),
        };
        codec::validate_original(body, &result, status, seq).unwrap();
        let extra = RetainedMeta {
            sequence: seq,
            kind: EntityKind::RepositoryState,
            entity,
            decision,
            version: op.version,
            request_bytes: body.len() as u32,
            result_bytes: result.len() as u32,
        };
        let reserve = retention_reserve_rows(DEVICES).unwrap();
        if self
            .caps
            .requires_retention(self.rows.len() as u64, self.bytes, extra, reserve)
        {
            let plan =
                append_retention_plan(&self.rows, extra, self.history, self.caps, reserve * 2)
                    .unwrap();
            if plan.base > self.history.base {
                self.cuts += 1;
                self.rows
                    .retain(|row| plan.keep.binary_search(&row.sequence).is_ok());
                self.history.floor = plan.base;
                self.history.base = plan.base;
            }
            self.bytes = plan.bytes;
        } else {
            self.bytes += extra.cost();
        }
        self.rows.push(extra);
        self.history.head = seq;
        self.peak_rows = self.peak_rows.max(self.rows.len());
        self.peak_bytes = self.peak_bytes.max(self.bytes);
        assert!(self.rows.len() as u64 <= self.caps.rows && self.bytes <= self.caps.bytes);
        seq
    }
}

#[test]
fn catalog_1024_repositories_32_devices_converges_with_bounded_history() {
    let mut facts = (0..OWNERS)
        .map(|i| ObservationData::Owner {
            owner: GithubOwner {
                id: owner(i),
                kind: if i == 0 {
                    GithubOwnerKind::User
                } else {
                    GithubOwnerKind::Organization
                },
                login: "o".repeat(256),
            },
        })
        .collect::<Vec<_>>();
    facts.extend((0..REPOSITORIES).map(|i| ObservationData::Repository {
        repository: RepositoryFact {
            id: RepositoryId::new(u64::MAX - i).unwrap(),
            owner_id: owner(i % OWNERS),
            name: "r".repeat(400),
            visibility: RepositoryVisibility::Private,
            archived: false,
            default_branch: Some("b".repeat(1024)),
        },
    }));
    let entities = facts
        .iter()
        .map(|data| observed(data.clone(), 0).key().entity_id())
        .collect::<Vec<_>>();
    let scopes = (0..DEVICES)
        .map(|device| {
            observed(
                ObservationData::ScopeScan {
                    scan: ScopeScan {
                        outcome: TraversalOutcome::Complete,
                        pages: REPOSITORIES.div_ceil(REPOSITORIES_PER_PAGE as u64) as u8,
                        repositories: REPOSITORIES as u16,
                        last_complete: Some(CompleteTraversal {
                            pages: REPOSITORIES.div_ceil(REPOSITORIES_PER_PAGE as u64) as u8,
                            repositories: REPOSITORIES as u16,
                            observed_at_ms: 1_800_000_000_000,
                            scan_id: "complete-scan".into(),
                        }),
                    },
                },
                device,
            )
        })
        .collect::<Vec<_>>();
    let scope_entities = scopes
        .iter()
        .map(|value| value.key().entity_id())
        .collect::<Vec<_>>();
    let mut key_bytes = [0; 32];
    SystemRandom::new().fill(&mut key_bytes).unwrap();
    let key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap());
    // Independently reserve maximum wire sizes for device/account/credential and
    // six observations AND six independent consent rows per device.
    // Keep product quotas unchanged while reserving each original and receipt.
    let other_rows = DEVICES * (3 + 2 * 6);
    let mut budget = Budget {
        rows: vec![],
        history: HistoryVersion {
            head: 0,
            floor: 0,
            base: 0,
        },
        bytes: 0,
        caps: RetentionCaps {
            rows: MAX_OPERATIONS - other_rows,
            entities: MAX_ENTITY_COUNT - other_rows,
            bytes: MAX_STORED_BYTES
                - other_rows * (2 * MAX_OPERATION_BYTES + MAX_RESULT_BYTES) as u64,
        },
        cuts: 0,
        peak_rows: 0,
        peak_bytes: 0,
    };
    let mut heads = BTreeMap::new();
    let mut nonce_id = 0;
    for round in 0..2 {
        for (chunk_index, chunk) in facts.chunks(32).enumerate() {
            let basis = budget.history.head;
            let before = heads.clone();
            let mut conflicts = BTreeMap::<usize, Vec<u64>>::new();
            // All 32 devices prepare against one pre-I/O view, then their
            // original requests arrive interleaved. Never requalify an identity.
            for device in 0..DEVICES {
                for (offset, data) in chunk.iter().enumerate() {
                    let index = chunk_index * 32 + offset;
                    let entity = entities[index].as_str();
                    let (revision, resolved) = before.get(&index).copied().unwrap_or((0, 0));
                    let current = heads.get(&index).map_or(0, |h: &(u64, u64)| h.0);
                    nonce_id += 1;
                    let (op, body) = encoded(
                        &observed(data.clone(), device),
                        device,
                        basis,
                        revision,
                        resolved,
                        nonce_id,
                        &key,
                    );
                    let seq = budget.append(entity, &op, &body, current);
                    if device == 0 {
                        heads.insert(index, (revision + 1, resolved));
                    } else {
                        conflicts.entry(index).or_default().push(seq);
                    }
                }
            }
            for (offset, data) in chunk.iter().enumerate() {
                let index = chunk_index * 32 + offset;
                let (revision, previous) = heads[&index];
                let resolved = resolution_lifecycle(
                    Lifecycle {
                        resolved_through_seq: previous,
                    },
                    &conflicts[&index],
                    budget.history.head,
                )
                .unwrap()
                .resolved_through_seq;
                nonce_id += 1;
                let (op, body) = encoded(
                    &observed(data.clone(), 0),
                    0,
                    budget.history.head,
                    revision,
                    resolved,
                    nonce_id,
                    &key,
                );
                budget.append(&entities[index], &op, &body, revision);
                heads.insert(index, (revision + 1, resolved));
            }
        }
        // Unchanged provider reads from every device must not produce history.
        for device in 0..DEVICES {
            for (index, data) in facts.iter().enumerate() {
                let value = observed(data.clone(), device);
                let target = ObservedTarget {
                    key: value.key(),
                    version: TargetVersion {
                        revision: heads[&index].0,
                        next_base: heads[&index].0,
                        pending_id: None,
                        conflicted: false,
                    },
                    value: Some(observed(data.clone(), 0)),
                    history_cursor: budget.history.head,
                };
                let candidate = Capture::before_read(value.key(), target.version.clone())
                    .unwrap()
                    .confirm(value.clone())
                    .unwrap();
                assert!(matches!(
                    candidate
                        .decide(&target, Some(&value.source.context))
                        .unwrap(),
                    PublicationDecision::Noop
                ));
            }
        }
        if round == 0 {
            // The next scan observes changed provider metadata, not duplicate work.
            for data in &mut facts {
                match data {
                    ObservationData::Repository { repository } => repository.archived = true,
                    ObservationData::Owner { owner } => owner.login = "n".repeat(256),
                    _ => unreachable!(),
                }
            }
        }
    }
    // Distinct credential scopes are additional entities, never copied owner or
    // repository facts. Account for their actual encrypted/wire size as well.
    for (device, value) in scopes.iter().enumerate() {
        nonce_id += 1;
        let (op, body) = encoded(
            value,
            device as u64,
            budget.history.head,
            0,
            0,
            nonce_id,
            &key,
        );
        budget.append(&scope_entities[device], &op, &body, 0);
    }
    assert!(budget.cuts > 1 && budget.history.head > MAX_OPERATIONS * 4);
    let plan = retention_plan(
        &budget.rows,
        None,
        budget.history,
        budget.history.head,
        budget.caps,
    )
    .unwrap();
    assert_eq!(plan.entities, REPOSITORIES + OWNERS + DEVICES);
    assert_eq!(plan.keep.len() as u64, REPOSITORIES + OWNERS + DEVICES);
    assert_eq!(heads.len() as u64, REPOSITORIES + OWNERS);
    eprintln!(
        "1024 repositories / 32 devices: {} original operations, {} cuts, peak {} rows / {} bytes; final {} canonical entities; {} maximum-sized non-catalog rows reserved",
        budget.history.head,
        budget.cuts,
        budget.peak_rows,
        budget.peak_bytes,
        plan.entities,
        other_rows
    );
}
