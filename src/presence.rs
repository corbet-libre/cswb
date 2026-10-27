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
    /// Opaque retained evidence for the higher owner to reverify.
    pub fn attachment(&self) -> Option<&Attachment> {
        self.admission.attachment.as_ref()
    }
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
    /// The row's opaque storage key (a hash; it names neither member nor
    /// device). Candidate pages are ordered by it.
    pub fn key(&self) -> &str {
        &self.record.key
    }
}

/// The row with the freshest verified profile revision; the first such row in
/// the given order wins a tie.
pub fn freshest(rows: Vec<VerifiedPresence>) -> Option<VerifiedPresence> {
    let mut best: Option<VerifiedPresence> = None;
    for row in rows {
        let newer = match &best {
            Some(keep) => {
                row.profile().transcript().revision > keep.profile().transcript().revision
            }
            None => true,
        };
        if newer {
            best = Some(row);
        }
    }
    best
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
        if let Some(attachment) = &entry.attachment {
            attachment.validate()?;
            if entry.authority_until > attachment.record_until() {
                return Err(Error::Storage(cmmr::Error::Corrupt));
            }
        }
        // Different configured origins have separate attendance. Do not let
        // one origin's read erase another origin's otherwise valid presence.
        if entry.binding.origin != origin {
            return Err(Error::Stale);
        }
        let result = self.verify_publication(origin, &entry.publication, verification, 1, contact);
        match result {
            Ok((mut admission, profile)) if admission.binding == entry.binding => {
                if record.key
                    != attendance_key(&admission.binding.member, &admission.binding.device)
                {
                    // A row stored under the wrong key (including the retired
                    // per-member key) is withdrawn, never disclosed or trusted.
                    self.store.delete_generation(&record.generation).await?;
                    return Err(Error::Stale);
                }
                admission.authority_until = admission.authority_until.min(entry.authority_until);
                admission.attachment = entry.attachment;
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
        // One member may hold several device rows; the freshest verified
        // profile revision answers, so a requester naming a stale revision
        // reconciles by re-reading instead of decrypting old ciphertext.
        freshest(
            self.member_rows(session, current, member, verification, contact)
                .await?,
        )
        .ok_or(Error::Absent)
    }

    /// Every verified live device row of one member, in storage key order.
    /// Withdrawn or foreign-origin rows are never disclosed.
    pub async fn member_rows(
        &self,
        session: &Session,
        current: &Current,
        member: &str,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<VerifiedPresence>, Error> {
        self.load(session, current).await?;
        cmmr::validate_name(member)?;
        let mut cursor: Option<cmmr::Cursor> = None;
        let mut rows = Vec::new();
        loop {
            let page = self
                .store
                .page(&member_index(member), cursor.as_ref(), 8)
                .await?;
            for record in page.records {
                match self
                    .verify_row(record, &current.binding.origin, verification, contact)
                    .await
                {
                    Ok(row) if row.binding().member == member => rows.push(row),
                    Ok(_) => {}
                    Err(Error::TrustUnavailable | Error::Expired | Error::Stale) => {}
                    Err(error) => return Err(error),
                }
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        rows.sort_by(|a, b| a.key().cmp(b.key()));
        Ok(rows)
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
