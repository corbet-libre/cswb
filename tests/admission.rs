mod support;
use cmmr::{Clock, Store};
use cswb::*;
use ed25519_dalek::Signer as _;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use support::*;

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct RandomTokens;
impl Tokens for RandomTokens {
    fn next(&self) -> Result<[u8; 16], Error> {
        use ckmg::Entropy;
        let mut token = [0; 16];
        ckmg::SystemEntropy
            .fill(&mut token)
            .map_err(|_| Error::Invalid)?;
        Ok(token)
    }
}
fn storage_limits() -> cmmr::Limits {
    cmmr::Limits {
        records: 64,
        value_bytes: 262_144,
        batch: 4,
        indexes_per_record: 4,
        page: 8,
        ttl_ms: 600_000,
    }
}
fn board<S: Store, C: Clock>(store: S, clock: C) -> Switchboard<S, C, RandomTokens> {
    Switchboard::new(
        store,
        clock,
        RandomTokens,
        "garden".into(),
        Limits {
            lease_ms: 10_000,
            publication_bytes: cpfl::MAX_PROFILE_BYTES,
            ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
        },
    )
    .unwrap()
}
fn proof(fixture: &Fixture, session: &Session, action: &str, nonce: u8, body: &[u8]) -> Possession {
    let nonce = [nonce; 16];
    Possession {
        nonce,
        signature: fixture
            .device
            .sign(&request_message(ORIGIN, action, session, &nonce, body))
            .to_bytes()
            .to_vec(),
    }
}
async fn enter<S: Store, C: Clock>(
    board: &Switchboard<S, C, RandomTokens>,
    fixture: &mut Fixture,
) -> (Session, Live) {
    let publication = fixture.publication.clone();
    let challenge = board
        .challenge(ORIGIN, &publication, &fixture.verification(), &clean)
        .await
        .unwrap();
    let signature = fixture
        .device
        .sign(&challenge_message(
            ORIGIN,
            "garden",
            &challenge,
            &publication.signed,
        ))
        .to_bytes();
    let entered = board
        .admit_enter(
            EntryProof {
                origin: ORIGIN,
                challenge: &challenge,
                signature: &signature,
                publication: &publication,
            },
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(matches!(
        board
            .admit(
                EntryProof {
                    origin: ORIGIN,
                    challenge: &challenge,
                    signature: &signature,
                    publication: &publication
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Stale)
    ));
    entered
}
async fn round_trip<S: Store, C: Clock>(board: Switchboard<S, C, RandomTokens>, now: u64) {
    let mut fixture = Fixture::new("alice", 1, now).await;
    let (session, live) = enter(&board, &mut fixture).await;
    let possession = proof(&fixture, &session, "heartbeat", 1, b"current-revision");
    for (action, body) in [
        ("depart", b"current-revision".as_slice()),
        ("heartbeat", b"changed".as_slice()),
    ] {
        assert!(matches!(
            board
                .authorize(
                    RequestProof {
                        origin: ORIGIN,
                        session: &session,
                        action,
                        body,
                        possession: &possession
                    },
                    &fixture.verification(),
                    &clean
                )
                .await,
            Err(Error::DeviceUnavailable)
        ));
    }
    let current = board
        .authorize(
            RequestProof {
                origin: ORIGIN,
                session: &session,
                action: "heartbeat",
                body: b"current-revision",
                possession: &possession,
            },
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    let renewed = board
        .heartbeat(&session, &current, live.revision)
        .await
        .unwrap();
    assert_eq!(current.binding().community, "garden");
    assert_eq!(current.binding().member, "alice");
    assert_eq!(
        current.binding().device,
        fixture.device.verifying_key().to_bytes()
    );
    assert!(current.authority_until() >= renewed.deadline);
    assert!(matches!(
        board
            .authorize(
                RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "heartbeat",
                    body: b"current-revision",
                    possession: &possession
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Storage(cmmr::Error::Conflict))
    ));
    assert_eq!(
        board
            .read(&session, &current)
            .await
            .unwrap()
            .publication
            .signed,
        fixture.publication.signed
    );
    let next = Fixture::new("alice", 2, now).await;
    let replacement = board
        .replacement(
            &session,
            &current,
            &next.publication,
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    board
        .replace(&session, &current, renewed.revision, replacement)
        .await
        .unwrap();
    assert!(
        board
            .replacement(
                &session,
                &current,
                &fixture.publication.clone(),
                &fixture.verification(),
                &clean
            )
            .await
            .is_err()
    );
    fixture.revoke("alice");
    let possession = proof(&fixture, &session, "search", 2, b"page");
    assert!(matches!(
        board
            .authorize(
                RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "search",
                    body: b"page",
                    possession: &possession
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::TrustUnavailable)
    ));
    assert!(matches!(
        board.read(&session, &current).await,
        Err(Error::Absent)
    ));
}
#[tokio::test]
async fn current_signed_admission_request_replacement_and_revocation_in_memory() {
    let clock = Time(Arc::new(AtomicU64::new(1_100_000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "test").unwrap(),
            storage_limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    round_trip(board(store, clock), 1100).await;
}

#[tokio::test]
async fn current_signed_settings_bound_renewals_and_missing_values_withdraw() {
    let clock = Time(Arc::new(AtomicU64::new(1_100_000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "policy").unwrap(),
            storage_limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    let board = board(store.clone(), clock);
    let mut fixture = Fixture::new("alice", 1, 1100).await;
    fixture.settings(2, serde_json::json!(1000), serde_json::json!(5000));
    let (session, live) = enter(&board, &mut fixture).await;
    assert_eq!(live.deadline, 1_105_000);
    fixture.settings(3, serde_json::json!(500), serde_json::json!(2000));
    let possession = proof(&fixture, &session, "heartbeat", 1, b"renew");
    let current = board
        .authorize(
            RequestProof {
                origin: ORIGIN,
                session: &session,
                action: "heartbeat",
                body: b"renew",
                possession: &possession,
            },
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    let live = board
        .heartbeat(&session, &current, live.revision)
        .await
        .unwrap();
    assert_eq!(live.deadline, 1_102_000);
    fixture.settings(4, serde_json::Value::Null, serde_json::json!(2000));
    let possession = proof(&fixture, &session, "heartbeat", 2, b"renew");
    assert!(matches!(
        board
            .authorize(
                RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "heartbeat",
                    body: b"renew",
                    possession: &possession
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::TrustUnavailable)
    ));
    assert!(store.get("swb_alice").await.unwrap().is_none());
}
#[derive(Clone, Copy)]
struct Wall;
impl Clock for Wall {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| cmmr::Error::Unavailable)?
            .as_millis() as u64)
    }
}
#[tokio::test]
async fn same_signed_round_trip_uses_actual_valkey() {
    let client =
        redis::Client::open(std::env::var("VALKEY_URL").expect("Disposable Valkey is required"))
            .unwrap();
    let network = cvlk::RedisNetwork::new(
        client.get_multiplexed_async_connection().await.unwrap(),
        std::time::Duration::from_secs(3),
    )
    .unwrap();
    let incarnation = data_encoding::HEXLOWER.encode(&RandomTokens.next().unwrap());
    let store = cvlk::Valkey::open(
        Arc::new(network),
        cmmr::Scope::new("garden", incarnation).unwrap(),
        storage_limits(),
        Wall,
    )
    .await
    .unwrap();
    round_trip(board(store, Wall), Wall.now().unwrap() / 1000).await;
}

#[tokio::test]
async fn challenge_binds_origin_publication_expiry_and_single_consumer() {
    let clock = Time(Arc::new(AtomicU64::new(1_100_000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "binding").unwrap(),
            storage_limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    let board = board(store.clone(), clock.clone());
    let mut fixture = Fixture::new("alice", 1, 1100).await;
    let publication = fixture.publication.clone();
    for origin in [
        "not an origin",
        "http://forum.example.test",
        "https://forum.example.test/",
    ] {
        assert!(matches!(
            board
                .challenge(origin, &publication, &fixture.verification(), &clean)
                .await,
            Err(Error::Invalid)
        ));
    }
    let challenge = board
        .challenge(ORIGIN, &publication, &fixture.verification(), &clean)
        .await
        .unwrap();
    let signature = fixture
        .device
        .sign(&challenge_message(
            ORIGIN,
            "garden",
            &challenge,
            &publication.signed,
        ))
        .to_bytes();
    let input = |origin| EntryProof {
        origin,
        challenge: &challenge,
        signature: &signature,
        publication: &publication,
    };
    assert!(matches!(
        board
            .admit(
                input("https://other.example.test"),
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Stale)
    ));
    let mut changed = challenge.clone();
    changed.expires_at_ms += 1;
    assert!(matches!(
        board
            .admit(
                EntryProof {
                    challenge: &changed,
                    ..input(ORIGIN)
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Stale)
    ));
    let next = Fixture::new("alice", 2, 1100).await;
    assert!(matches!(
        board
            .admit(
                EntryProof {
                    publication: &next.publication,
                    ..input(ORIGIN)
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Stale)
    ));
    for bad in [vec![], vec![0; 64]] {
        assert!(matches!(
            board
                .admit(
                    EntryProof {
                        signature: &bad,
                        ..input(ORIGIN)
                    },
                    &fixture.verification(),
                    &clean
                )
                .await,
            Err(Error::DeviceUnavailable)
        ));
    }
    let verification = fixture.verification();
    let (first, second) = tokio::join!(
        board.admit(input(ORIGIN), &verification, &clean),
        board.admit(input(ORIGIN), &verification, &clean)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let admitted = first.or(second).unwrap();
    let (session, _) = board.enter(admitted).await.unwrap();
    assert_eq!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    let possession = proof(&fixture, &session, "search", 9, b"page");
    assert!(matches!(
        board
            .authorize(
                RequestProof {
                    origin: "https://other.example.test",
                    session: &session,
                    action: "search",
                    body: b"page",
                    possession: &possession
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Stale)
    ));
    let mut zero = possession.clone();
    zero.nonce = [0; 16];
    assert!(matches!(
        board
            .authorize(
                RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "search",
                    body: b"page",
                    possession: &zero
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Stale)
    ));
    clock.0.store(challenge.expires_at_ms, Ordering::SeqCst);
    assert!(matches!(
        board
            .authorize(
                RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "search",
                    body: b"page",
                    possession: &possession
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Absent)
    ));
}

#[tokio::test]
async fn forged_publications_and_revoked_challenges_never_publish() {
    let clock = Time(Arc::new(AtomicU64::new(1_100_000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "refusals").unwrap(),
            storage_limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    let board = board(store.clone(), clock.clone());
    let mut fixture = Fixture::new("alice", 1, 1100).await;
    let publication = fixture.publication.clone();
    let mut bad_ciphertext = publication.clone();
    bad_ciphertext.ciphertext.push(0);
    assert!(matches!(
        board
            .challenge(ORIGIN, &bad_ciphertext, &fixture.verification(), &clean)
            .await,
        Err(Error::Invalid)
    ));
    let mut malformed = publication.clone();
    malformed.signed = b"{}".to_vec();
    assert!(matches!(
        board
            .challenge(ORIGIN, &malformed, &fixture.verification(), &clean)
            .await,
        Err(Error::Invalid)
    ));
    let mut wire = cpfl::Publication::from_bytes(&publication.signed).unwrap();
    wire.signature[0] ^= 1;
    let invalid = Publication {
        signed: wire.to_bytes().unwrap(),
        ciphertext: wire.envelope,
    };
    assert!(matches!(
        board
            .challenge(ORIGIN, &invalid, &fixture.verification(), &clean)
            .await,
        Err(Error::TrustUnavailable)
    ));
    let challenge = board
        .challenge(ORIGIN, &publication, &fixture.verification(), &clean)
        .await
        .unwrap();
    let signature = fixture
        .device
        .sign(&challenge_message(
            ORIGIN,
            "garden",
            &challenge,
            &publication.signed,
        ))
        .to_bytes();
    fixture.revoke("alice");
    assert!(matches!(
        board
            .admit(
                EntryProof {
                    origin: ORIGIN,
                    challenge: &challenge,
                    signature: &signature,
                    publication: &publication
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::TrustUnavailable)
    ));
    assert!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    let verification = fixture.verification();
    clock.0.store(1_401_000, Ordering::SeqCst);
    assert!(matches!(
        board
            .challenge(ORIGIN, &publication, &verification, &clean)
            .await,
        Err(Error::TrustUnavailable)
    ));
}

#[tokio::test]
async fn nonce_cannot_replay_after_heartbeat_extends_its_original_lease() {
    let now = 2_000_000_000;
    let clock = Time(Arc::new(AtomicU64::new(now * 1000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "nonce-retention").unwrap(),
            storage_limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    let board = board(store.clone(), clock.clone());
    let mut fixture = Fixture::new("alice", 1, now).await;
    let (session, live) = enter(&board, &mut fixture).await;
    let possession = proof(&fixture, &session, "search", 11, b"query");
    let current = board
        .authorize(
            RequestProof {
                origin: ORIGIN,
                session: &session,
                action: "search",
                body: b"query",
                possession: &possession,
            },
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    clock.0.store(now * 1000 + 9000, Ordering::SeqCst);
    board
        .heartbeat(&session, &current, live.revision)
        .await
        .unwrap();
    clock.0.store(now * 1000 + 10001, Ordering::SeqCst);
    assert!(matches!(
        board
            .authorize(
                RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "search",
                    body: b"query",
                    possession: &possession
                },
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Storage(cmmr::Error::Conflict))
    ));
    // Replacement erases the displaced generation's cursor/nonce state too.
    let (replacement, _) = enter(&board, &mut fixture).await;
    assert_eq!(board.depart(&session).await.unwrap(), 0);
    assert_eq!(board.depart(&replacement).await.unwrap(), 1);
    assert!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .is_empty()
    );
}

#[path = "admission/atomic.rs"]
mod atomic;
