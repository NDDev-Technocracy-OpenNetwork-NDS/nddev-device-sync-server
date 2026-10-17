use super::crypto::equal;
use nddev_device_sync_application::identity::{
    ApprovalDisplay, BrowserProof, GithubApproval, GithubFlow, GithubFlowStore, GithubPoll,
    IdentityError, Locale, MAX_PENDING_GITHUB, ProtectedDigest, SecretText,
};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
pub struct Flows(Mutex<BTreeMap<String, GithubFlow>>);
impl Flows {
    fn locked(
        &self,
        now: u64,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, GithubFlow>>, IdentityError> {
        let mut flows = self.0.lock().map_err(|_| IdentityError::Unavailable)?;
        flows.retain(|_, flow| flow.expires_at_ms > now);
        Ok(flows)
    }
}
impl GithubFlowStore for Flows {
    fn insert(&self, flow: GithubFlow, now: u64) -> Result<(), IdentityError> {
        let mut flows = self.locked(now)?;
        if flows.len() >= MAX_PENDING_GITHUB || flows.contains_key(&flow.id) {
            return Err(IdentityError::Capacity);
        }
        flows.insert(flow.id.clone(), flow);
        Ok(())
    }
    fn claim_callback(
        &self,
        state: ProtectedDigest,
        now: u64,
    ) -> Result<(String, SecretText), IdentityError> {
        let mut flows = self.locked(now)?;
        let flow = flows
            .values_mut()
            .find(|flow| equal(&flow.state, &state))
            .ok_or(IdentityError::Denied)?;
        Ok((flow.id.clone(), flow.claim_callback(now)?))
    }
    fn complete_callback(
        &self,
        id: &str,
        approval: Option<GithubApproval>,
        now: u64,
    ) -> Result<ApprovalDisplay, IdentityError> {
        let mut flows = self.locked(now)?;
        let flow = flows.get_mut(id).ok_or(IdentityError::Denied)?;
        flow.complete_callback(approval, now)?;
        Ok(ApprovalDisplay {
            verification_code: flow.verification_code().into(),
            expires_at_ms: flow.expires_at_ms,
            locale: flow.locale,
        })
    }
    fn approve(
        &self,
        id: &str,
        proof: BrowserProof,
        permit: bool,
        now: u64,
    ) -> Result<Locale, IdentityError> {
        let mut flows = self.locked(now)?;
        let flow = flows.get_mut(id).ok_or(IdentityError::Denied)?;
        let expected = flow.browser_proof().ok_or(IdentityError::Denied)?;
        let matches = equal(&expected.cookie, &proof.cookie) & equal(&expected.csrf, &proof.csrf);
        flow.approve(matches, permit, now)?;
        Ok(flow.locale)
    }
    fn poll(
        &self,
        id: &str,
        exchange: ProtectedDigest,
        now: u64,
    ) -> Result<GithubPoll, IdentityError> {
        let mut flows = self.locked(now)?;
        let flow = flows.get_mut(id).ok_or(IdentityError::Denied)?;
        let outcome = flow.poll(equal(&flow.exchange, &exchange), now);
        if matches!(&outcome, Ok(GithubPoll::Approved(_))) {
            flows.remove(id);
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_application::identity::{
        GITHUB_LIFETIME_MS, GITHUB_POLL_MS, Owner, TenantId, UserId, VerifiedGithubIdentity,
    };
    #[test]
    fn provider_callback_cannot_bypass_browser_proof_or_one_use_exchange() {
        let flows = Flows::default();
        let state = ProtectedDigest([1; 32]);
        let exchange = ProtectedDigest([2; 32]);
        let proof = BrowserProof {
            cookie: ProtectedDigest([3; 32]),
            csrf: ProtectedDigest([4; 32]),
        };
        flows
            .insert(
                GithubFlow::new(
                    "flow".into(),
                    state,
                    exchange,
                    SecretText::new("ephemeral".into()),
                    SecretText::new("12345678".into()),
                    Locale::Ru,
                    100,
                )
                .unwrap(),
                100,
            )
            .unwrap();
        flows.claim_callback(state, 101).unwrap();
        let identity = VerifiedGithubIdentity {
            provider_id: 42,
            owner: Owner {
                user_id: UserId::new("verified-user").unwrap(),
                tenant_id: TenantId::new("verified-company").unwrap(),
            },
        };
        let display = flows
            .complete_callback(
                "flow",
                Some(GithubApproval {
                    identity: identity.clone(),
                    proof,
                }),
                102,
            )
            .unwrap();
        assert_eq!(display.locale, Locale::Ru);
        assert_eq!(flows.poll("flow", exchange, 103), Ok(GithubPoll::Pending));
        for wrong in [
            BrowserProof {
                cookie: ProtectedDigest([0; 32]),
                ..proof
            },
            BrowserProof {
                csrf: ProtectedDigest([0; 32]),
                ..proof
            },
        ] {
            assert!(flows.approve("flow", wrong, true, 104).is_err());
        }
        assert_eq!(flows.approve("flow", proof, true, 105).unwrap(), Locale::Ru);
        assert!(flows.approve("flow", proof, true, 106).is_err());
        assert_eq!(
            flows.poll("flow", exchange, 103 + GITHUB_POLL_MS),
            Ok(GithubPoll::Approved(identity))
        );
        assert_eq!(
            flows.poll("flow", exchange, 103 + 2 * GITHUB_POLL_MS),
            Err(IdentityError::Denied)
        );
        assert!(flows.claim_callback(state, 107).is_err());
    }
    #[test]
    fn pending_capacity_and_observed_expiry_do_not_depend_on_a_background_task() {
        let flows = Flows::default();
        for index in 0..MAX_PENDING_GITHUB {
            flows
                .insert(
                    GithubFlow::new(
                        index.to_string(),
                        ProtectedDigest([1; 32]),
                        ProtectedDigest([2; 32]),
                        SecretText::new("ephemeral".into()),
                        SecretText::new("12345678".into()),
                        Locale::En,
                        100,
                    )
                    .unwrap(),
                    100,
                )
                .unwrap();
        }
        assert!(
            flows
                .insert(
                    GithubFlow::new(
                        "overflow".into(),
                        ProtectedDigest([1; 32]),
                        ProtectedDigest([2; 32]),
                        SecretText::new("ephemeral".into()),
                        SecretText::new("12345678".into()),
                        Locale::En,
                        100
                    )
                    .unwrap(),
                    100
                )
                .is_err()
        );
        assert_eq!(
            flows.poll("0", ProtectedDigest([2; 32]), 100 + GITHUB_LIFETIME_MS),
            Err(IdentityError::Denied)
        );
        assert_eq!(
            flows.poll("0", ProtectedDigest([2; 32]), 101),
            Err(IdentityError::Denied)
        );
        assert!(flows.locked(101).unwrap().is_empty());
    }
}
