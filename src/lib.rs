//! Bounded attendance transitions over the shared volatile storage port.
//! Admission capabilities have no public constructors until their verifiers
//! are integrated. Storage transition tests do not establish admission.
#![forbid(unsafe_code)]

use cmmr::{Clock, Deadline, Record, Revision, Store, Write};
use serde::{Deserialize, Serialize};

/// Stable failures contain neither identifiers nor dependency diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Absent,
    Stale,
    Expired,
    TrustUnavailable,
    RecordUnavailable,
    DeviceUnavailable,
    Storage(cmmr::Error),
}
impl From<cmmr::Error> for Error {
    fn from(error: cmmr::Error) -> Self {
        Self::Storage(error)
    }
}

/// Exact opaque device publication. Its verifier must bind all these bytes,
/// public guard projection, reciprocal rules, ciphertext and reachability.
/// This type is input, never evidence of successful verification.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub signed: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Expected authority context for all owner-supplied verification ports.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub community: String,
    pub member: String,
    pub device: [u8; 32],
    pub epoch: u64,
    pub schema: u32,
}

/// There is deliberately no constructor from raw keys, JSON or a boolean.
/// The concrete device attestation verifier belongs to the identity owner.
pub enum VerifiedDevice {}
/// The concrete local public-record verifier belongs to accounting.
pub enum VerifiedRecord {}

pub trait DeviceVerifier {
    fn verify(
        &self,
        binding: &Binding,
        challenge: &[u8],
        proof: &[u8],
    ) -> Result<VerifiedDevice, Error>;
}
pub trait RecordVerifier {
    fn verify(
        &self,
        binding: &Binding,
        publication: &Publication,
        proof: &[u8],
    ) -> Result<VerifiedRecord, Error>;
}

/// Explicit refusal ports until the concrete owner APIs exist. Neither can
/// mint authority; an unavailable proof never becomes optional.
pub struct Unavailable;
impl DeviceVerifier for Unavailable {
    fn verify(&self, _: &Binding, _: &[u8], _: &[u8]) -> Result<VerifiedDevice, Error> {
        Err(Error::DeviceUnavailable)
    }
}
impl RecordVerifier for Unavailable {
    fn verify(&self, _: &Binding, _: &Publication, _: &[u8]) -> Result<VerifiedRecord, Error> {
        Err(Error::RecordUnavailable)
    }
}

/// A whole, validated publication and exclusive authority deadline. No public
/// constructor exists: production admission is blocked on current Guard,
/// device attestation and local public-record verification.
pub struct Admission {
    binding: Binding,
    publication: Publication,
    authority_until: u64,
}

/// Current verified scope and authority, supplied afresh for every operation.
/// Current epoch/schema/revocations and device possession are not caller flags.
pub struct Current {
    binding: Binding,
    authority_until: u64,
}

/// All generated IDs must be independently random and unique. The service
/// supplies its CSPRNG; the library never uses a wall clock as entropy.
pub trait Tokens: Send + Sync {
    fn next(&self) -> Result<[u8; 16], Error>;
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub lease_ms: u64,
    pub publication_bytes: usize,
    pub ciphertext_bytes: usize,
}

/// Redacted possession handle. The door must verify the device on each request;
/// knowing a handle alone does not create a Current capability.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    member: String,
    generation: String,
    device: [u8; 32],
}

/// Current storage revision and exact original publication. This is not a
/// public match result; Lookup must independently authorize reciprocal reads.
pub struct Live {
    pub revision: Revision,
    pub deadline: u64,
    pub publication: Publication,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    binding: Binding,
    authority_until: u64,
    publication: Publication,
}

/// Owns no second roster: the supplied scoped volatile store is authoritative.
pub struct Switchboard<S, C, R> {
    store: S,
    clock: C,
    tokens: R,
    community: String,
    limits: Limits,
}
impl<S: Store, C: Clock, R: Tokens> Switchboard<S, C, R> {
    pub fn new(
        store: S,
        clock: C,
        tokens: R,
        community: String,
        limits: Limits,
    ) -> Result<Self, Error> {
        cmmr::validate_name(&community)?;
        if limits.lease_ms == 0
            || limits.lease_ms > cmmr::MAX_TIME
            || limits.publication_bytes == 0
            || limits.ciphertext_bytes == 0
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            clock,
            tokens,
            community,
            limits,
        })
    }

    fn binding(&self, binding: &Binding) -> Result<(), Error> {
        if binding.community != self.community
            || binding.epoch == 0
            || binding.schema == 0
            || binding.member.len() > 124
        {
            return Err(Error::Invalid);
        }
        cmmr::validate_name(&binding.member)?;
        Ok(())
    }

    fn publication(&self, publication: &Publication) -> Result<(), Error> {
        if publication.signed.is_empty()
            || publication.signed.len() > self.limits.publication_bytes
            || publication.ciphertext.len() > self.limits.ciphertext_bytes
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn deadline(&self, authority_until: u64) -> Result<Deadline, Error> {
        let now = self.clock.now()?;
        if now >= authority_until {
            return Err(Error::Expired);
        }
        let end = now
            .checked_add(self.limits.lease_ms)
            .ok_or(Error::Invalid)?;
        Ok(Deadline::new(end.min(authority_until))?)
    }

    fn token(&self) -> Result<Revision, Error> {
        let bytes = self.tokens.next()?;
        if bytes == [0; 16] {
            return Err(Error::Invalid);
        }
        Ok(Revision(bytes))
    }

    /// New verified device attendance replaces the previous generation by CAS.
    /// A racing replacement must retry a fresh verification and new generation.
    pub async fn enter(&self, admission: Admission) -> Result<(Session, Live), Error> {
        self.binding(&admission.binding)?;
        self.publication(&admission.publication)?;
        let deadline = self.deadline(admission.authority_until)?;
        let previous = self
            .store
            .get(&format!("swb_{}", admission.binding.member))
            .await?;
        let generation = data_encoding::HEXLOWER.encode(&self.token()?.0);
        let session = Session {
            member: admission.binding.member.clone(),
            generation,
            device: admission.binding.device,
        };
        let entry = Entry {
            binding: admission.binding,
            authority_until: admission.authority_until,
            publication: admission.publication,
        };
        let live = self
            .write(&session, entry, previous.map(|r| r.revision), deadline)
            .await?;
        Ok((session, live))
    }

    async fn write(
        &self,
        session: &Session,
        entry: Entry,
        expected: Option<Revision>,
        deadline: Deadline,
    ) -> Result<Live, Error> {
        let revision = self.token()?;
        let value = serde_json::to_vec(&entry).map_err(|_| Error::Invalid)?;
        self.store
            .compare_exchange(&[Write {
                expected,
                record: Record {
                    key: format!("swb_{}", session.member),
                    generation: session.generation.clone(),
                    revision,
                    deadline,
                    value,
                    indexes: vec!["swb_present".into()],
                },
            }])
            .await?;
        Ok(Live {
            revision,
            deadline: deadline.unix_ms(),
            publication: entry.publication,
        })
    }

    async fn load(&self, session: &Session, current: &Current) -> Result<(Record, Entry), Error> {
        self.binding(&current.binding)?;
        if current.binding.member != session.member || current.binding.device != session.device {
            return Err(Error::Stale);
        }
        let record = self
            .store
            .get(&format!("swb_{}", session.member))
            .await?
            .ok_or(Error::Absent)?;
        if record.generation != session.generation {
            return Err(Error::Stale);
        }
        let entry: Entry = serde_json::from_slice(&record.value)
            .map_err(|_| Error::Storage(cmmr::Error::Corrupt))?;
        let now = self.clock.now()?;
        if now >= record.deadline.unix_ms()
            || now >= entry.authority_until
            || now >= current.authority_until
        {
            self.store.delete_generation(&session.generation).await?;
            return Err(Error::Expired);
        }
        if entry.binding != current.binding {
            self.store.delete_generation(&session.generation).await?;
            return Err(Error::Stale);
        }
        Ok((record, entry))
    }

    pub async fn read(&self, session: &Session, current: &Current) -> Result<Live, Error> {
        let (record, entry) = self.load(session, current).await?;
        Ok(Live {
            revision: record.revision,
            deadline: record.deadline.unix_ms(),
            publication: entry.publication,
        })
    }

    /// Refresh liveness only. The original authority deadline cannot grow.
    pub async fn heartbeat(
        &self,
        session: &Session,
        current: &Current,
        expected: Revision,
    ) -> Result<Live, Error> {
        let (record, mut entry) = self.load(session, current).await?;
        if record.revision != expected {
            return Err(Error::Stale);
        }
        entry.authority_until = entry.authority_until.min(current.authority_until);
        let deadline = self.deadline(entry.authority_until)?;
        self.write(session, entry, Some(expected), deadline).await
    }

    /// Atomically replace all signed bytes after fresh whole-bundle verification.
    pub async fn replace(
        &self,
        session: &Session,
        current: &Current,
        expected: Revision,
        admission: Admission,
    ) -> Result<Live, Error> {
        let (record, _) = self.load(session, current).await?;
        if record.revision != expected || admission.binding != current.binding {
            return Err(Error::Stale);
        }
        self.publication(&admission.publication)?;
        let authority_until = admission.authority_until.min(current.authority_until);
        let deadline = self.deadline(authority_until)?;
        self.write(
            session,
            Entry {
                binding: admission.binding,
                authority_until,
                publication: admission.publication,
            },
            Some(expected),
            deadline,
        )
        .await
    }

    /// Delayed disconnect cannot delete a newer generation. This only withdraws
    /// state, including indexes and ciphertext, and grants no read authority.
    pub async fn depart(&self, session: &Session) -> Result<usize, Error> {
        Ok(self.store.delete_generation(&session.generation).await?)
    }

    pub async fn expire(&self) -> Result<usize, Error> {
        Ok(self.store.maintain().await?)
    }
}

#[cfg(test)]
#[path = "../tests/internal/transitions.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/internal/backends.rs"]
mod backend_tests;
