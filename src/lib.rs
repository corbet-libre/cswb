//! Bounded attendance transitions over the shared volatile storage port.
//! Profile and Charter own current person/profile/device verification; this
//! library binds their result to one-use challenges and signed current requests.
#![forbid(unsafe_code)]

mod authority;
mod presence;
pub use authority::{
    Challenge, EntryProof, Possession, RequestProof, Verification, challenge_message,
    request_message,
};
pub use presence::{CandidatePage, Scan, VerifiedPresence};

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

/// The Profile owner bounds its complete serialized publication.
pub const MAX_PUBLICATION_BYTES: usize = cpfl::MAX_PROFILE_BYTES;

/// Exact opaque device publication. Its verifier must bind all these bytes,
/// public guard projection, reciprocal rules, ciphertext and reachability.
/// This type is input, never evidence of successful verification.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub signed: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Publication {
    /// Decode the owner format without treating it as verified authority.
    pub fn from_signed(signed: Vec<u8>) -> Result<Self, Error> {
        let wire = cpfl::Publication::from_bytes(&signed).map_err(|_| Error::Invalid)?;
        Ok(Self {
            signed,
            ciphertext: wire.envelope,
        })
    }
}

/// Expected authority context for all owner-supplied verification ports.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub origin: String,
    pub community: String,
    pub member: String,
    pub device: [u8; 32],
    pub epoch: u64,
    pub schema: u32,
}

/// A whole, validated publication and exclusive authority deadline. No public
/// unchecked constructor exists. This candidate validates person/profile/device
/// authority; mandatory G2 frontier currentness integration is still pending.
pub struct Admission {
    binding: Binding,
    publication: Publication,
    authority_until: u64,
    lease_ms: u64,
}

/// Current verified scope and authority, supplied afresh for every operation.
/// Current epoch/schema/revocations and device possession are not caller flags.
pub struct Current {
    binding: Binding,
    authority_until: u64,
    lease_ms: u64,
}

impl Current {
    /// Original scope after fresh current-device request verification. Reading
    /// this value neither constructs a capability nor extends its authority.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    /// Exclusive Unix-millisecond authority bound; the live row may expire sooner.
    pub fn authority_until(&self) -> u64 {
        self.authority_until
    }
}

/// All generated IDs must be independently random and unique. The service
/// supplies its CSPRNG; the library never uses a wall clock as entropy.
pub trait Tokens: Send + Sync {
    fn next(&self) -> Result<[u8; 16], Error>;
}

#[derive(Clone, Copy)]
pub struct Limits {
    /// Deployment storage ceiling, never a replacement for signed settings.
    pub lease_ms: u64,
    pub publication_bytes: usize,
    pub ciphertext_bytes: usize,
}

/// Redacted possession handle. The door must verify the device on each request;
/// knowing a handle alone does not create a Current capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        let origin = url::Url::parse(&binding.origin).map_err(|_| Error::Invalid)?;
        if origin.scheme() != "https" || origin.origin().ascii_serialization() != binding.origin {
            return Err(Error::Invalid);
        }
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

    fn deadline(&self, authority_until: u64, lease_ms: u64) -> Result<Deadline, Error> {
        let now = self.clock.now()?;
        if now >= authority_until {
            return Err(Error::Expired);
        }
        if lease_ms == 0 || lease_ms > self.limits.lease_ms {
            return Err(Error::Invalid);
        }
        let end = now.checked_add(lease_ms).ok_or(Error::Invalid)?;
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
        let (session, entry, previous, deadline) = self.prepare_enter(admission).await?;
        let live = self
            .write(
                &session,
                entry,
                previous.as_ref().map(|r| r.revision),
                deadline,
            )
            .await?;
        if let Some(previous) = previous {
            self.store.delete_generation(&previous.generation).await?;
        }
        Ok((session, live))
    }

    async fn prepare_enter(
        &self,
        admission: Admission,
    ) -> Result<(Session, Entry, Option<Record>, Deadline), Error> {
        self.binding(&admission.binding)?;
        self.publication(&admission.publication)?;
        let deadline = self.deadline(admission.authority_until, admission.lease_ms)?;
        let previous = self
            .store
            .get(&format!("swb_{}", admission.binding.member))
            .await?;
        let generation = data_encoding::HEXLOWER.encode(&self.token()?.0);
        if previous
            .as_ref()
            .is_some_and(|record| record.generation == generation)
        {
            return Err(Error::Invalid);
        }
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
        Ok((session, entry, previous, deadline))
    }

    async fn write(
        &self,
        session: &Session,
        entry: Entry,
        expected: Option<Revision>,
        deadline: Deadline,
    ) -> Result<Live, Error> {
        let (write, live) = self.prepare_write(session, entry, expected, deadline)?;
        self.store.compare_exchange(&[write]).await?;
        Ok(live)
    }

    fn prepare_write(
        &self,
        session: &Session,
        entry: Entry,
        expected: Option<Revision>,
        deadline: Deadline,
    ) -> Result<(Write, Live), Error> {
        let revision = self.token()?;
        let value = serde_json::to_vec(&entry).map_err(|_| Error::Invalid)?;
        let write = Write {
            expected,
            record: Record {
                key: format!("swb_{}", session.member),
                generation: session.generation.clone(),
                revision,
                deadline,
                value,
                indexes: vec!["swb_present".into()],
            },
        };
        let live = Live {
            revision,
            deadline: deadline.unix_ms(),
            publication: entry.publication,
        };
        Ok((write, live))
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
        let deadline = self.deadline(entry.authority_until, current.lease_ms)?;
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
        let deadline = self.deadline(authority_until, admission.lease_ms)?;
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
