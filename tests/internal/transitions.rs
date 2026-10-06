//! Exercise real storage transitions at their verified-input precondition.
//! These fixtures are not trust, record or device-verifier implementations.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct Sequence(AtomicU64);
impl Tokens for Sequence {
    fn next(&self) -> Result<[u8; 16], Error> {
        Ok((self.0.fetch_add(1, Ordering::SeqCst) as u128).to_be_bytes())
    }
}
type Board = Switchboard<Arc<cmmr::Memory<Time>>, Time, Sequence>;
fn setup() -> (Board, Time) {
    let time = Time(Arc::new(AtomicU64::new(100)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("community", "boot").unwrap(),
            cmmr::Limits {
                records: 5,
                value_bytes: 4096,
                batch: 8,
                indexes_per_record: 4,
                page: 8,
                ttl_ms: 1000,
            },
            time.clone(),
        )
        .unwrap(),
    );
    (
        Switchboard::new(
            store,
            time.clone(),
            Sequence(AtomicU64::new(1)),
            "community".into(),
            Limits {
                lease_ms: 100,
                publication_bytes: 100,
                ciphertext_bytes: 100,
            },
        )
        .unwrap(),
        time,
    )
}
fn binding() -> Binding {
    Binding {
        origin: "https://forum.example".into(),
        community: "community".into(),
        member: "alice".into(),
        device: [7; 32],
        epoch: 1,
        schema: 1,
    }
}
fn publication() -> Publication {
    Publication {
        signed: vec![1, 2, 3],
        ciphertext: vec![9, 8, 7],
    }
}
fn admission() -> Admission {
    Admission {
        binding: binding(),
        publication: publication(),
        authority_until: 1000,
    }
}
fn current() -> Current {
    Current {
        binding: binding(),
        authority_until: 1000,
    }
}

#[tokio::test]
async fn replacement_heartbeat_and_departure_are_whole_and_fenced() {
    let (board, time) = setup();
    let (session, live) = board.enter(admission()).await.unwrap();
    assert_eq!(live.deadline, 200);
    assert!(live.publication == publication());
    assert_eq!(
        board.read(&session, &current()).await.unwrap().revision,
        live.revision
    );
    time.0.store(150, Ordering::SeqCst);
    let renewed = board
        .heartbeat(&session, &current(), live.revision)
        .await
        .unwrap();
    assert_eq!(renewed.deadline, 250);
    assert!(matches!(
        board.heartbeat(&session, &current(), live.revision).await,
        Err(Error::Stale)
    ));
    let mut next = admission();
    next.publication.ciphertext = vec![42];
    let replaced = board
        .replace(&session, &current(), renewed.revision, next)
        .await
        .unwrap();
    assert_eq!(replaced.publication.ciphertext, vec![42]);
    assert_eq!(
        board
            .store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    let mut next = admission();
    next.binding.device = [8; 32];
    let (other, _) = board.enter(next).await.unwrap();
    assert!(matches!(
        board.read(&session, &current()).await,
        Err(Error::Stale)
    ));
    assert_eq!(board.depart(&session).await.unwrap(), 0);
    let mut authority = current();
    authority.binding.device = [8; 32];
    assert!(board.read(&other, &authority).await.is_ok());
    assert_eq!(board.depart(&other).await.unwrap(), 1);
    assert_eq!(board.depart(&other).await.unwrap(), 0);
    assert!(matches!(
        board.read(&other, &authority).await,
        Err(Error::Absent)
    ));
    assert!(
        board
            .store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .is_empty()
    );
}

#[tokio::test]
async fn expiry_and_authority_deadlines_never_extend_on_heartbeat() {
    let (board, time) = setup();
    let mut input = admission();
    input.authority_until = 160;
    let (session, live) = board.enter(input).await.unwrap();
    assert_eq!(live.deadline, 160);
    time.0.store(155, Ordering::SeqCst);
    assert_eq!(
        board
            .heartbeat(&session, &current(), live.revision)
            .await
            .unwrap()
            .deadline,
        160
    );
    time.0.store(160, Ordering::SeqCst);
    assert_eq!(board.expire().await.unwrap(), 1);
    assert_eq!(board.expire().await.unwrap(), 0);
    assert!(matches!(
        board.read(&session, &current()).await,
        Err(Error::Absent)
    ));
    let mut expired = admission();
    expired.authority_until = 160;
    assert!(matches!(board.enter(expired).await, Err(Error::Expired)));
}

#[tokio::test]
async fn current_epoch_schema_and_expiry_withdraw_immediately() {
    for mode in 0..3 {
        let (board, _) = setup();
        let (session, _) = board.enter(admission()).await.unwrap();
        let mut fresh = current();
        match mode {
            0 => fresh.binding.epoch = 2,
            1 => fresh.binding.schema = 2,
            _ => fresh.authority_until = 100,
        }
        assert!(matches!(
            board.read(&session, &fresh).await,
            Err(Error::Expired | Error::Stale)
        ));
        assert!(board.store.get("swb_alice").await.unwrap().is_none());
    }
}

#[tokio::test]
async fn rejected_updates_keep_prior_entry_and_wrong_device_cannot_read() {
    let (board, _) = setup();
    let (session, live) = board.enter(admission()).await.unwrap();
    let mut bad = admission();
    bad.publication.signed.clear();
    assert!(matches!(
        board
            .replace(&session, &current(), live.revision, bad)
            .await,
        Err(Error::Invalid)
    ));
    let mut bad = admission();
    bad.binding.member = "bob".into();
    assert!(matches!(
        board
            .replace(&session, &current(), live.revision, bad)
            .await,
        Err(Error::Stale)
    ));
    assert!(matches!(
        board
            .replace(&session, &current(), Revision([8; 16]), admission())
            .await,
        Err(Error::Stale)
    ));
    for mode in 0..2 {
        let mut fresh = current();
        if mode == 0 {
            fresh.binding.member = "bob".into()
        } else {
            fresh.binding.device = [4; 32]
        }
        assert!(matches!(
            board.read(&session, &fresh).await,
            Err(Error::Stale)
        ));
    }
    assert_eq!(
        board.read(&session, &current()).await.unwrap().revision,
        live.revision
    );
}

#[tokio::test]
async fn bounds_and_scope_fail_before_a_write() {
    let (board, time) = setup();
    for mode in 0..8 {
        let mut bad = admission();
        match mode {
            0 => bad.binding.community = "foreign".into(),
            1 => bad.binding.member = "!".into(),
            2 => bad.binding.epoch = 0,
            3 => bad.binding.schema = 0,
            4 => bad.publication.signed.clear(),
            5 => bad.publication.signed = vec![0; 101],
            6 => bad.publication.ciphertext = vec![0; 101],
            _ => bad.binding.member = "a".repeat(125),
        }
        assert!(board.enter(bad).await.is_err());
    }
    assert!(
        board
            .store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    time.0.store(u64::MAX, Ordering::SeqCst);
    assert!(matches!(board.deadline(u64::MAX), Err(Error::Expired)));
    time.0.store(u64::MAX - 1, Ordering::SeqCst);
    assert!(matches!(board.deadline(u64::MAX), Err(Error::Invalid)));
}

#[tokio::test]
async fn concurrent_updates_have_one_winner_and_departure_stops_old_writes() {
    let (board, _) = setup();
    let (session, live) = board.enter(admission()).await.unwrap();
    let fresh = current();
    let (a, b) = tokio::join!(
        board.heartbeat(&session, &fresh, live.revision),
        board.heartbeat(&session, &fresh, live.revision)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let (record, entry) = board.load(&session, &fresh).await.unwrap();
    board.depart(&session).await.unwrap();
    assert!(matches!(
        board
            .write(&session, entry, Some(record.revision), record.deadline)
            .await,
        Err(Error::Storage(cmmr::Error::Conflict))
    ));
    assert!(board.store.get("swb_alice").await.unwrap().is_none());
}

#[tokio::test]
async fn storage_capacity_clock_regression_and_close_are_refusals() {
    let (board, time) = setup();
    for id in ["a", "b", "c", "d", "e"] {
        let mut input = admission();
        input.binding.member = id.into();
        board.enter(input).await.unwrap();
    }
    assert!(matches!(
        board.enter(admission()).await,
        Err(Error::Storage(cmmr::Error::Capacity))
    ));
    time.0.store(99, Ordering::SeqCst);
    assert!(matches!(
        board.expire().await,
        Err(Error::Storage(cmmr::Error::ClockRegression))
    ));
    time.0.store(100, Ordering::SeqCst);
    board.store.close();
    assert!(matches!(
        board.enter(admission()).await,
        Err(Error::Storage(cmmr::Error::Closed))
    ));
}

#[tokio::test]
async fn corrupt_storage_and_shorter_authority_refuse() {
    let (board, _) = setup();
    let (session, live) = board.enter(admission()).await.unwrap();
    let mut record = board.store.get("swb_alice").await.unwrap().unwrap();
    record.value = vec![0];
    record.revision = Revision([5; 16]);
    board
        .store
        .compare_exchange(&[Write {
            expected: Some(live.revision),
            record,
        }])
        .await
        .unwrap();
    assert!(matches!(
        board.read(&session, &current()).await,
        Err(Error::Storage(cmmr::Error::Corrupt))
    ));
    let (session, live) = board.enter(admission()).await.unwrap();
    let mut shorter = current();
    shorter.authority_until = 120;
    assert_eq!(
        board
            .heartbeat(&session, &shorter, live.revision)
            .await
            .unwrap()
            .deadline,
        120
    );
}

#[test]
fn zero_tokens_and_invalid_limits_refuse() {
    let (mut board, _) = setup();
    board.tokens = Sequence(AtomicU64::new(0));
    assert!(matches!(board.token(), Err(Error::Invalid)));
    for limits in [
        Limits {
            lease_ms: 0,
            publication_bytes: 1,
            ciphertext_bytes: 1,
        },
        Limits {
            lease_ms: u64::MAX,
            publication_bytes: 1,
            ciphertext_bytes: 1,
        },
        Limits {
            lease_ms: 1,
            publication_bytes: 0,
            ciphertext_bytes: 1,
        },
        Limits {
            lease_ms: 1,
            publication_bytes: 1,
            ciphertext_bytes: 0,
        },
    ] {
        assert!(
            Switchboard::new(
                board.store.clone(),
                board.clock.clone(),
                Sequence(AtomicU64::new(1)),
                "community".into(),
                limits
            )
            .is_err()
        );
    }
    assert!(
        Switchboard::new(
            board.store.clone(),
            board.clock.clone(),
            Sequence(AtomicU64::new(1)),
            "!".into(),
            board.limits
        )
        .is_err()
    );
}

#[tokio::test]
async fn deadline_passed_after_storage_read_and_corrupt_authority_are_rejected() {
    let (mut board, _) = setup();
    let (session, _) = board.enter(admission()).await.unwrap();
    // The backend read happened before the operation's later time observation.
    board.clock = Time(Arc::new(AtomicU64::new(200)));
    assert!(matches!(
        board.read(&session, &current()).await,
        Err(Error::Expired)
    ));
    let (board, _) = setup();
    let (session, live) = board.enter(admission()).await.unwrap();
    let mut record = board.store.get("swb_alice").await.unwrap().unwrap();
    let mut entry: Entry = serde_json::from_slice(&record.value).unwrap();
    entry.authority_until = 100;
    record.value = serde_json::to_vec(&entry).unwrap();
    record.revision = Revision([5; 16]);
    board
        .store
        .compare_exchange(&[Write {
            expected: Some(live.revision),
            record,
        }])
        .await
        .unwrap();
    assert!(matches!(
        board.read(&session, &current()).await,
        Err(Error::Expired)
    ));
}
