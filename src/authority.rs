use crate::*;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Current authenticated trust from Assurance. Neither the member nor a parsed
/// network response can construct a VerifiedCharter. Time comes from Switchboard.
pub struct Verification<'a> {
    pub charter: &'a cchr::VerifiedCharter,
    /// Admission action selected by the service, never by a member request.
    pub action: &'a str,
}

/// One bounded challenge; possessing these public bytes grants no authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub token: [u8; 16],
    pub expires_at_ms: u64,
    /// Opaque service-selected context, covered by the original device signature.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<u8>,
}

/// Each operation proves the same currently authorized device's possession.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Possession {
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

/// Untrusted admission bytes, with an independently configured expected origin.
pub struct EntryProof<'a> {
    pub origin: &'a str,
    pub challenge: &'a Challenge,
    pub signature: &'a [u8],
    pub publication: &'a Publication,
}

/// Exact request being executed, selected by the generated API dispatcher.
pub struct RequestProof<'a> {
    pub origin: &'a str,
    pub session: &'a Session,
    pub action: &'a str,
    pub body: &'a [u8],
    pub possession: &'a Possession,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    binding: Binding,
    origin: String,
    publication: [u8; 32],
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    payload: Vec<u8>,
}

// One-use storage state only. It retains no member, request or authority bytes.
const CONSUMED: &[u8] = &[0];

/// Exact domain framing for a device-owned signing capability. The caller uses
/// its independently configured forum origin, never an origin from a response.
pub fn challenge_message(
    origin: &str,
    community: &str,
    challenge: &Challenge,
    publication: &[u8],
) -> Vec<u8> {
    serde_json::json!([
        "cswb.challenge.v1",
        origin,
        community,
        challenge,
        digest(publication)
    ])
    .to_string()
    .into_bytes()
}

/// Sign the exact operation, session, nonce and body bytes. An HTTP adapter must
/// pass the same canonical unsigned body to this function and to its executor.
pub fn request_message(
    origin: &str,
    action: &str,
    session: &Session,
    nonce: &[u8; 16],
    body: &[u8],
) -> Vec<u8> {
    serde_json::json!([
        "cswb.request.v1",
        origin,
        action,
        session,
        nonce,
        digest(body)
    ])
    .to_string()
    .into_bytes()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn signature(device: &[u8; 32], message: &[u8], bytes: &[u8]) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(device).map_err(|_| Error::DeviceUnavailable)?;
    let signature = Signature::from_slice(bytes).map_err(|_| Error::DeviceUnavailable)?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::DeviceUnavailable)
}

fn challenge_key(challenge: &Challenge) -> String {
    format!(
        "challenge_{}",
        data_encoding::HEXLOWER.encode(&challenge.token)
    )
}

impl<S: Store, C: Clock, R: Tokens> Switchboard<S, C, R> {
    pub(crate) fn verify_publication(
        &self,
        origin: &str,
        publication: &Publication,
        verification: &Verification<'_>,
        minimum_revision: u64,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(Admission, cpfl::VerifiedPublication), Error> {
        self.publication(publication)?;
        let now = self.clock.now()?;
        let settings = crbk::ForumSettings::from_snapshot(
            verification
                .charter
                .settings(now / 1000)
                .map_err(|_| Error::TrustUnavailable)?,
        )
        .map_err(|_| Error::TrustUnavailable)?;
        let policy = verification
            .charter
            .current_admission_policy(verification.action, now / 1000)
            .map_err(|_| Error::TrustUnavailable)?;
        let wire =
            cpfl::Publication::from_bytes(&publication.signed).map_err(|_| Error::Invalid)?;
        if wire.envelope != publication.ciphertext {
            return Err(Error::Invalid);
        }
        let checked = cpfl::verify_publication(
            &wire,
            &policy,
            verification
                .charter
                .publication(cchr::Kind::Schema)
                .signed_bytes(),
            minimum_revision,
            contact,
        )
        .map_err(|_| Error::TrustUnavailable)?;
        let transcript = checked.transcript();
        let binding = Binding {
            origin: origin.into(),
            community: transcript.community.clone(),
            member: transcript.member.clone(),
            device: transcript.device,
            epoch: verification.charter.policy_epoch(),
            schema: verification.charter.schema().version,
        };
        self.binding(&binding)?;
        let authority_until = checked
            .authority_until()
            .min(verification.charter.valid_until())
            .saturating_mul(1000)
            .min(cmmr::MAX_TIME);
        self.deadline(authority_until, settings.lease_ms)?;
        Ok((
            Admission {
                binding,
                publication: publication.clone(),
                authority_until,
                lease_ms: settings.lease_ms,
                attachment: None,
            },
            checked,
        ))
    }

    /// Guard checks the whole credential/public profile before any challenge is
    /// stored. A challenge discloses no member state and cannot create presence.
    pub async fn challenge(
        &self,
        origin: &str,
        publication: &Publication,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Challenge, Error> {
        self.issue_challenge(
            origin,
            publication,
            verification,
            contact,
            None::<fn(&Binding, u64, [u8; 32]) -> Result<Vec<u8>, Error>>,
        )
        .await
    }

    /// Bind opaque caller-owned context to a real G1 challenge. The builder gets
    /// the verified scope, exclusive challenge deadline and independent random
    /// bytes. It returns data only; Switchboard does not verify accounting proof.
    pub async fn challenge_bound(
        &self,
        origin: &str,
        publication: &Publication,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        build: impl FnOnce(&Binding, u64, [u8; 32]) -> Result<Vec<u8>, Error>,
    ) -> Result<Challenge, Error> {
        self.issue_challenge(origin, publication, verification, contact, Some(build))
            .await
    }

    async fn issue_challenge(
        &self,
        origin: &str,
        publication: &Publication,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        build: Option<impl FnOnce(&Binding, u64, [u8; 32]) -> Result<Vec<u8>, Error>>,
    ) -> Result<Challenge, Error> {
        let (admission, _) =
            self.verify_publication(origin, publication, verification, 1, contact)?;
        let deadline = self.deadline(admission.authority_until, admission.lease_ms)?;
        let payload = if let Some(build) = build {
            let mut random = [0; 32];
            random[..16].copy_from_slice(&self.token()?.0);
            random[16..].copy_from_slice(&self.token()?.0);
            let payload = build(&admission.binding, deadline.unix_ms(), random)?;
            if payload.is_empty() || payload.len() > MAX_PUBLICATION_BYTES {
                return Err(Error::Invalid);
            }
            payload
        } else {
            Vec::new()
        };
        let token = self.token()?;
        let challenge = Challenge {
            token: token.0,
            expires_at_ms: deadline.unix_ms(),
            payload: payload.clone(),
        };
        let pending = Pending {
            binding: admission.binding,
            origin: origin.into(),
            publication: digest(&publication.signed),
            payload,
        };
        let key = challenge_key(&challenge);
        self.store
            .compare_exchange(&[Write {
                expected: None,
                record: Record {
                    key: key.clone(),
                    generation: key,
                    revision: token,
                    deadline,
                    value: serde_json::to_vec(&pending).map_err(|_| Error::Invalid)?,
                    indexes: vec![],
                },
            }])
            .await?;
        Ok(challenge)
    }

    /// Consume a genuine one-use challenge after checking the current owner
    /// authority again and verifying possession of the exact certified device.
    pub async fn admit(
        &self,
        proof: EntryProof<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Admission, Error> {
        let (record, admission) = self.verified_pending(proof, verification, contact).await?;
        // Original lower-owner partial operation; Gather uses admit_enter.
        self.store
            .compare_exchange(&[self.consumed(record)?])
            .await?;
        Ok(admission)
    }

    pub(crate) async fn verified_pending(
        &self,
        proof: EntryProof<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(Record, Admission), Error> {
        let EntryProof {
            origin,
            challenge,
            signature: proof,
            publication,
        } = proof;
        let key = challenge_key(challenge);
        let record = self.store.get(&key).await?.ok_or(Error::Absent)?;
        if record.value == CONSUMED {
            return Err(Error::Stale);
        }
        let pending: Pending = serde_json::from_slice(&record.value)
            .map_err(|_| Error::Storage(cmmr::Error::Corrupt))?;
        let (admission, _) =
            self.verify_publication(origin, publication, verification, 1, contact)?;
        if pending.binding != admission.binding
            || pending.origin != origin
            || pending.publication != digest(&publication.signed)
            || pending.payload != challenge.payload
            || challenge.payload.len() > MAX_PUBLICATION_BYTES
            || record.deadline.unix_ms() != challenge.expires_at_ms
        {
            return Err(Error::Stale);
        }
        signature(
            &admission.binding.device,
            &challenge_message(origin, &self.community, challenge, &publication.signed),
            proof,
        )?;
        Ok((record, admission))
    }

    /// Atomically consume the pending challenge and publish complete attendance.
    /// This composes the original person/profile/device checks only; mandatory
    /// accounting frontier authority is still required by the Forum boundary.
    pub async fn admit_enter(
        &self,
        proof: EntryProof<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(Session, Live), Error> {
        let prepared = self.prepare_entry(proof, verification, contact).await?;
        let deadline = prepared.deadline();
        self.commit_entry(prepared, None, deadline).await
    }

    pub(crate) fn consumed(&self, pending: Record) -> Result<Write, Error> {
        Ok(Write {
            expected: Some(pending.revision),
            record: Record {
                key: pending.key,
                generation: pending.generation,
                revision: self.token()?,
                deadline: pending.deadline,
                value: CONSUMED.to_vec(),
                indexes: vec![],
            },
        })
    }

    pub(crate) fn check_completion(&self, floor: u64, deadline: Deadline) -> Result<u64, Error> {
        let now = self.clock.now()?;
        if now < floor {
            return Err(Error::Storage(cmmr::Error::ClockRegression));
        }
        if now >= deadline.unix_ms() {
            return Err(Error::Expired);
        }
        Ok(now)
    }

    /// Reverify stored original publication and current revocations, bind the
    /// request, then commit its nonce before exposing the current capability.
    /// A lost reply requires reconciliation; replay never repeats a mutation.
    pub async fn authorize(
        &self,
        request: RequestProof<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Current, Error> {
        let RequestProof {
            origin,
            session,
            action,
            body,
            possession,
        } = request;
        cmmr::validate_name(&session.member)?;
        let record = self
            .store
            .get(&format!("swb_{}", session.member))
            .await?
            .ok_or(Error::Absent)?;
        if record.generation != session.generation || possession.nonce == [0; 16] {
            return Err(Error::Stale);
        }
        let entry: Entry = serde_json::from_slice(&record.value)
            .map_err(|_| Error::Storage(cmmr::Error::Corrupt))?;
        if entry.binding.origin != origin {
            return Err(Error::Stale);
        }
        let admission =
            match self.verify_publication(origin, &entry.publication, verification, 1, contact) {
                Ok((admission, _)) => admission,
                Err(error) => {
                    self.store.delete_generation(&session.generation).await?;
                    return Err(error);
                }
            };
        let current = Current {
            binding: admission.binding,
            authority_until: admission.authority_until.min(entry.authority_until),
            lease_ms: admission.lease_ms,
            attachment: entry.attachment.clone(),
        };
        self.load(session, &current).await?;
        signature(
            &current.binding.device,
            &request_message(origin, action, session, &possession.nonce, body),
            &possession.signature,
        )?;
        self.store
            .compare_exchange(&[Write {
                expected: None,
                record: Record {
                    key: format!(
                        "nonce_{}_{}",
                        session.generation,
                        data_encoding::HEXLOWER.encode(&possession.nonce)
                    ),
                    generation: session.generation.clone(),
                    revision: self.token()?,
                    // Heartbeats can extend liveness. A used nonce must stay
                    // spent for the whole original authority interval, or an
                    // old signed read could replay after the earlier lease.
                    deadline: Deadline::new(entry.authority_until.min(current.authority_until))?,
                    value: vec![1],
                    indexes: vec![],
                },
            }])
            .await?;
        Ok(current)
    }

    /// Prepare a whole replacement for the currently authenticated request.
    /// Both old and new originals pass the owner verifier; revisions increase.
    pub async fn replacement(
        &self,
        session: &Session,
        current: &Current,
        publication: &Publication,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Admission, Error> {
        let (_, entry) = self.load(session, current).await?;
        let (_, previous) = self.verify_publication(
            &current.binding.origin,
            &entry.publication,
            verification,
            1,
            contact,
        )?;
        let minimum = previous
            .transcript()
            .revision
            .checked_add(1)
            .ok_or(Error::Invalid)?;
        let (admission, _) = self.verify_publication(
            &current.binding.origin,
            publication,
            verification,
            minimum,
            contact,
        )?;
        if admission.binding != current.binding {
            return Err(Error::Stale);
        }
        Ok(admission)
    }
}
