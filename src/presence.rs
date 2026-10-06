use crate::*;

/// A verified committed row, internal to the service composition. This is
/// neither serializable nor reciprocal disclosure authority; Lookup checks
/// both participants and confirms their revisions before building a response.
pub struct VerifiedPresence {
    record: Record,
    admission: Admission,
    profile: cpfl::VerifiedPublication,
}
impl VerifiedPresence {
    pub fn profile(&self) -> &cpfl::VerifiedPublication {
        &self.profile
    }
    pub fn publication(&self) -> &Publication {
        &self.admission.publication
    }
    pub fn revision(&self) -> Revision {
        self.record.revision
    }
    pub fn generation(&self) -> &str {
        &self.record.generation
    }
    pub fn deadline(&self) -> u64 {
        self.record
            .deadline
            .unix_ms()
            .min(self.admission.authority_until)
    }
    pub fn binding(&self) -> &Binding {
        &self.admission.binding
    }
}

/// Bounded candidate enumeration. A storage cursor never carries authority.
pub struct Scan<'a> {
    pub session: &'a Session,
    pub current: &'a Current,
    pub cursor: Option<&'a cmmr::Cursor>,
    pub limit: usize,
}
pub struct CandidatePage {
    pub candidates: Vec<VerifiedPresence>,
    pub next: Option<cmmr::Cursor>,
}

impl<S: Store, C: Clock, R: Tokens> Switchboard<S, C, R> {
    async fn verify_row(
        &self,
        record: Record,
        origin: &str,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<VerifiedPresence, Error> {
        let entry: Entry = serde_json::from_slice(&record.value)
            .map_err(|_| Error::Storage(cmmr::Error::Corrupt))?;
        // Different configured origins have separate attendance. Do not let
        // one origin's read erase another origin's otherwise valid presence.
        if entry.binding.origin != origin {
            return Err(Error::Stale);
        }
        let result = self.verify_publication(origin, &entry.publication, verification, 1, contact);
        match result {
            Ok((mut admission, profile)) if admission.binding == entry.binding => {
                if record.key != format!("swb_{}", admission.binding.member) {
                    return Err(Error::Storage(cmmr::Error::Corrupt));
                }
                admission.authority_until = admission.authority_until.min(entry.authority_until);
                self.deadline(
                    admission.authority_until.min(record.deadline.unix_ms()),
                    admission.lease_ms,
                )?;
                Ok(VerifiedPresence {
                    record,
                    admission,
                    profile,
                })
            }
            _ => {
                self.store.delete_generation(&record.generation).await?;
                Err(Error::TrustUnavailable)
            }
        }
    }

    pub async fn requester(
        &self,
        session: &Session,
        current: &Current,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<VerifiedPresence, Error> {
        let (record, _) = self.load(session, current).await?;
        let mut row = self
            .verify_row(record, &current.binding.origin, verification, contact)
            .await?;
        row.admission.authority_until = row.admission.authority_until.min(current.authority_until);
        Ok(row)
    }

    pub async fn candidates(
        &self,
        scan: Scan<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<CandidatePage, Error> {
        self.load(scan.session, scan.current).await?;
        let page = self
            .store
            .page("swb_present", scan.cursor, scan.limit)
            .await?;
        let mut candidates = Vec::new();
        for record in page.records {
            match self
                .verify_row(record, &scan.current.binding.origin, verification, contact)
                .await
            {
                Ok(row) => candidates.push(row),
                // Withdrawn or foreign-origin candidates are never disclosed.
                Err(Error::TrustUnavailable | Error::Expired | Error::Stale) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(CandidatePage {
            candidates,
            next: page.next,
        })
    }

    pub async fn candidate(
        &self,
        session: &Session,
        current: &Current,
        member: &str,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<VerifiedPresence, Error> {
        self.load(session, current).await?;
        cmmr::validate_name(member)?;
        let record = self
            .store
            .get(&format!("swb_{member}"))
            .await?
            .ok_or(Error::Absent)?;
        self.verify_row(record, &current.binding.origin, verification, contact)
            .await
    }

    /// Fresh owner verification followed by one atomic committed-read cut.
    /// Replacement, departure, expiry or a concurrent block in either original
    /// makes the whole response fail. No write refreshes the observation.
    pub async fn confirm(
        &self,
        rows: &[&VerifiedPresence],
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(), Error> {
        let mut checks = Vec::with_capacity(rows.len());
        for row in rows {
            let (admission, _) = self.verify_publication(
                &row.binding().origin,
                row.publication(),
                verification,
                row.profile().transcript().revision,
                contact,
            )?;
            if admission.binding != *row.binding() {
                return Err(Error::Stale);
            }
            checks.push(cmmr::Check {
                key: row.record.key.clone(),
                revision: row.revision(),
                deadline: Deadline::new(row.deadline().min(admission.authority_until))?,
            });
        }
        self.store.check_current(&checks).await?;
        Ok(())
    }
}
