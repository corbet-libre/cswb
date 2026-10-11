use crate::*;

/// Bounded opaque evidence supplied by the higher verification owner. This is
/// data, not proof of an accounting decision or a complete Forum admission.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    bytes: Vec<u8>,
    record_until: u64,
}
impl Attachment {
    /// Validate syntax and the exclusive retained-record deadline only.
    pub fn new(bytes: Vec<u8>, record_until: u64) -> Result<Self, Error> {
        let attachment = Self {
            bytes,
            record_until,
        };
        attachment.validate()?;
        Ok(attachment)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_PUBLICATION_BYTES {
            return Err(Error::Invalid);
        }
        Deadline::new(self.record_until)?;
        Ok(())
    }
    /// Exact opaque bytes for the higher owner to verify afresh.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exclusive Unix-millisecond bound supplied by that owner.
    pub fn record_until(&self) -> u64 {
        self.record_until
    }
}

/// Genuine device/profile challenge verification retained across the higher
/// owner's accounting check. Only the original pending CAS can commit it.
pub struct PreparedEntry {
    pending: Record,
    admission: Admission,
    payload: Vec<u8>,
    floor: u64,
}
impl PreparedEntry {
    /// Scope verified against the current signed owner publication.
    pub fn binding(&self) -> &Binding {
        &self.admission.binding
    }
    /// Exact service-selected payload covered by the certified device signature.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Exclusive deadline of the original one-use challenge.
    pub fn deadline(&self) -> u64 {
        self.pending.deadline.unix_ms()
    }
}

impl<S: Store, C: Clock, R: Tokens> Switchboard<S, C, R> {
    /// Verify the original pending challenge without consuming it. Higher owners
    /// may inspect the sealed scope and context before the atomic entry commit.
    pub async fn prepare_entry(
        &self,
        proof: EntryProof<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<PreparedEntry, Error> {
        let started = self.clock.now()?;
        let payload = proof.challenge.payload.clone();
        let (pending, admission) = self.verified_pending(proof, verification, contact).await?;
        let floor = self.check_completion(started, pending.deadline)?;
        Ok(PreparedEntry {
            pending,
            admission,
            payload,
            floor,
        })
    }

    /// Commit exactly one pending marker and complete attendance in the existing
    /// atomic pair. Opaque evidence does not replace higher-owner verification.
    /// The short commit bound caps initial liveness; retained authority also
    /// stays below G1 and the attachment's original record interval.
    pub async fn commit_entry(
        &self,
        prepared: PreparedEntry,
        attachment: Option<Attachment>,
        commit_until_ms: u64,
    ) -> Result<(Session, Live), Error> {
        let PreparedEntry {
            pending,
            mut admission,
            floor,
            ..
        } = prepared;
        let commit_deadline = Deadline::new(pending.deadline.unix_ms().min(commit_until_ms))?;
        let checked = self.check_completion(floor, commit_deadline)?;
        if let Some(attachment) = &attachment {
            attachment.validate()?;
            admission.authority_until = admission.authority_until.min(attachment.record_until());
        }
        admission.attachment = attachment;
        let (session, entry, previous, deadline) = self.prepare_enter(admission).await?;
        let deadline = Deadline::new(deadline.unix_ms().min(commit_deadline.unix_ms()))?;
        let (attendance, live) = self.prepare_write(
            &session,
            entry,
            previous.as_ref().map(|record| record.revision),
            deadline,
        )?;
        // Preserve the original marker deadline, so shortening attendance cannot
        // revive a consumed challenge. Each new row deadline bounds the pair.
        let consumed = self.consumed(pending)?;
        let before_commit = self.check_completion(checked, deadline)?;
        self.store.compare_exchange(&[consumed, attendance]).await?;
        if let Some(previous) = previous {
            self.store.delete_generation(&previous.generation).await?;
        }
        self.check_completion(before_commit, deadline)?;
        Ok((session, live))
    }
}
