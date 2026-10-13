//! Genuine G1/device/CAS tests for opaque data retention, not G2 acceptance.
use super::*;
#[path = "atomic_support.rs"]
mod atomic_support;
use atomic_support::*;

fn key(challenge: &Challenge) -> String {
    format!(
        "challenge_{}",
        data_encoding::HEXLOWER.encode(&challenge.token)
    )
}
fn signed(fixture: &Fixture, challenge: &Challenge) -> [u8; 64] {
    fixture
        .device
        .sign(&challenge_message(
            ORIGIN,
            "garden",
            challenge,
            &fixture.publication.signed,
        ))
        .to_bytes()
}
fn input<'a>(
    fixture: &'a Fixture,
    challenge: &'a Challenge,
    signature: &'a [u8; 64],
) -> EntryProof<'a> {
    EntryProof {
        origin: ORIGIN,
        challenge,
        signature,
        publication: &fixture.publication,
    }
}
async fn bound<S: Store>(
    board: &Switchboard<S, Time, RandomTokens>,
    fixture: &Fixture,
    now: u64,
) -> Challenge {
    board
        .challenge_bound(
            ORIGIN,
            &fixture.publication,
            &fixture.verification(),
            &clean,
            |binding, deadline, random| {
                assert_eq!(binding.member, "alice");
                assert_eq!(binding.device, fixture.device.verifying_key().to_bytes());
                assert_eq!(deadline, now + 10_000);
                assert_ne!(&random[..16], &[0; 16]);
                assert_ne!(&random[16..], &[0; 16]);
                Ok(serde_json::to_vec(&("opaque-test-context", deadline, random)).unwrap())
            },
        )
        .await
        .unwrap()
}
async fn retention<S: Store + Clone>(store: S, clock: Time) {
    let now = clock.now().unwrap();
    let board = board(store.clone(), clock.clone());
    let fixture = Fixture::new("alice", 1, now / 1000).await;
    let challenge = bound(&board, &fixture, now).await;
    let signature = signed(&fixture, &challenge);
    let prepared = board
        .prepare_entry(
            input(&fixture, &challenge, &signature),
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(prepared.payload(), challenge.payload);
    assert_eq!(prepared.binding().member, "alice");
    assert_eq!(prepared.deadline(), challenge.expires_at_ms);
    let pending = store.get(&key(&challenge)).await.unwrap().unwrap();
    // Deliberately opaque bytes: this test proves only lower-owner retention.
    let attachment = Attachment::new(b"opaque-retained-record".to_vec(), now + 8000).unwrap();
    let (session, live) = board
        .commit_entry(prepared, Some(attachment), now + 1000)
        .await
        .unwrap();
    assert_eq!(live.deadline, now + 1000);
    let marker = store.get(&key(&challenge)).await.unwrap().unwrap();
    assert_eq!(marker.value, [0]);
    assert_eq!(marker.deadline, pending.deadline);
    assert!(matches!(
        board
            .prepare_entry(
                input(&fixture, &challenge, &signature),
                &fixture.verification(),
                &clean
            )
            .await,
        Err(Error::Stale)
    ));
    let possession = proof(&fixture, &session, "heartbeat", 41, b"renew");
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
    assert_eq!(current.authority_until(), now + 8000);
    assert_eq!(
        current.attachment().unwrap().bytes(),
        b"opaque-retained-record"
    );
    let presence = board
        .requester(&session, &current, &fixture.verification(), &clean)
        .await
        .unwrap();
    assert_eq!(presence.attachment().unwrap().record_until(), now + 8000);
    assert_eq!(presence.deadline(), live.deadline);
    board
        .confirm(&[&presence], &fixture.verification(), &clean)
        .await
        .unwrap();
    clock.0.store(now + 500, Ordering::SeqCst);
    // A later true heartbeat can outlast the short entry-commit interval.
    let live = board
        .heartbeat(&session, &current, live.revision)
        .await
        .unwrap();
    assert_eq!(live.deadline, now + 8000);
    let next = Fixture::new("alice", 2, now / 1000).await;
    let replacement = board
        .replacement(
            &session,
            &current,
            &next.publication,
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap()
        .with_attachment(Attachment::new(b"new-opaque-record".to_vec(), now + 7000).unwrap())
        .unwrap();
    assert_eq!(
        replacement.attachment().unwrap().bytes(),
        b"new-opaque-record"
    );
    let live = board
        .replace(&session, &current, live.revision, replacement)
        .await
        .unwrap();
    assert_eq!(live.deadline, now + 7000);
    // A still-live older Current must not enlarge the retained attachment on a
    // later ordinary profile replacement lacking new accounting data.
    let third = Fixture::new("alice", 3, now / 1000).await;
    let replacement = board
        .replacement(
            &session,
            &current,
            &third.publication,
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(replacement.attachment().is_none());
    let live = board
        .replace(&session, &current, live.revision, replacement)
        .await
        .unwrap();
    assert_eq!(live.deadline, now + 7000);
    let possession = proof(&next, &session, "heartbeat", 42, b"bounded");
    let current = board
        .authorize(
            RequestProof {
                origin: ORIGIN,
                session: &session,
                action: "heartbeat",
                body: b"bounded",
                possession: &possession,
            },
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(current.attachment().unwrap().bytes(), b"new-opaque-record");
    let current = current.bounded_until(now + 6000).unwrap();
    let live = board
        .heartbeat(&session, &current, live.revision)
        .await
        .unwrap();
    assert_eq!(live.deadline, now + 6000);
    assert_eq!(current.authority_until(), now + 6000);
    assert_eq!(
        current.bounded_until(now + 9000).unwrap().authority_until(),
        now + 6000
    );
    clock.0.store(now + 6000, Ordering::SeqCst);
    assert!(store.get("swb_alice").await.unwrap().is_none());
    // The shorter attendance expiry cannot revive the one-use challenge.
    assert_eq!(
        store.get(&key(&challenge)).await.unwrap().unwrap().value,
        [0]
    );
    store.close();
}

async fn tamper_and_completion<S: Store + Clone>(store: S, clock: Time) {
    let now = clock.now().unwrap();
    let gate = Gate::new();
    let board = board(
        Gated {
            real: store.clone(),
            gate: gate.clone(),
        },
        clock.clone(),
    );
    let fixture = Fixture::new("alice", 1, now / 1000).await;
    let legacy = board
        .challenge(
            ORIGIN,
            &fixture.publication,
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(legacy.payload.is_empty());
    assert!(
        serde_json::to_value(&legacy)
            .unwrap()
            .get("payload")
            .is_none()
    );
    for bytes in [Vec::new(), vec![1; MAX_PUBLICATION_BYTES + 1]] {
        assert!(matches!(
            board
                .challenge_bound(
                    ORIGIN,
                    &fixture.publication,
                    &fixture.verification(),
                    &clean,
                    |_, _, _| Ok(bytes)
                )
                .await,
            Err(Error::Invalid)
        ));
    }
    assert!(Attachment::new(Vec::new(), now + 1000).is_err());
    assert!(Attachment::new(vec![1; MAX_PUBLICATION_BYTES + 1], now + 1000).is_err());
    assert!(Attachment::new(vec![1], 0).is_err());
    let challenge = bound(&board, &fixture, now).await;
    let signature = signed(&fixture, &challenge);
    let pending = store.get(&key(&challenge)).await.unwrap().unwrap();
    let mut changed = challenge.clone();
    changed.payload[0] ^= 1;
    // Even a new valid signature cannot change the service's stored context.
    for signature in [signature, signed(&fixture, &changed)] {
        assert!(matches!(
            board
                .prepare_entry(
                    input(&fixture, &changed, &signature),
                    &fixture.verification(),
                    &clean
                )
                .await,
            Err(Error::Stale)
        ));
    }
    assert!(store.get(&key(&challenge)).await.unwrap().unwrap() == pending);
    let prepared = board
        .prepare_entry(
            input(&fixture, &challenge, &signature),
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    clock.0.store(now - 1, Ordering::SeqCst);
    assert!(matches!(
        board.commit_entry(prepared, None, now + 1000).await,
        Err(Error::Storage(cmmr::Error::ClockRegression))
    ));
    clock.0.store(now, Ordering::SeqCst);
    assert!(store.get(&key(&challenge)).await.unwrap().unwrap() == pending);
    let prepared = board
        .prepare_entry(
            input(&fixture, &challenge, &signature),
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    gate.mode.store(2, Ordering::SeqCst);
    // Expire the new attendance row while the original marker is still live.
    let (result, ()) = tokio::join!(
        board.commit_entry(
            prepared,
            Some(Attachment::new(vec![2], now + 8000).unwrap()),
            now + 1000
        ),
        async {
            gate.paused.notified().await;
            clock.0.store(now + 1000, Ordering::SeqCst);
            gate.resume.notify_one();
        }
    );
    assert!(result.is_err());
    assert!(store.get(&key(&challenge)).await.unwrap().unwrap() == pending);
    assert!(store.get("swb_alice").await.unwrap().is_none());
    let prepared = board
        .prepare_entry(
            input(&fixture, &challenge, &signature),
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    let (_, live) = board
        .commit_entry(
            prepared,
            Some(Attachment::new(vec![2], now + 8000).unwrap()),
            now + 2000,
        )
        .await
        .unwrap();
    assert_eq!(live.deadline, now + 2000);
    assert_eq!(
        store.get(&key(&challenge)).await.unwrap().unwrap().deadline,
        pending.deadline
    );
    store.close();
}

fn memory(clock: Time) -> Arc<cmmr::Memory<Time>> {
    Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "attachments").unwrap(),
            limits(64),
            clock,
        )
        .unwrap(),
    )
}
#[tokio::test]
async fn opaque_retention_and_shortened_authority_use_genuine_memory_admission() {
    let clock = Time(Arc::new(AtomicU64::new(1_100_000)));
    retention(memory(clock.clone()), clock).await;
}
#[tokio::test]
async fn payload_and_pair_deadlines_use_genuine_memory_admission() {
    let clock = Time(Arc::new(AtomicU64::new(1_100_000)));
    tamper_and_completion(memory(clock.clone()), clock).await;
}
#[tokio::test]
async fn opaque_retention_and_shortened_authority_use_actual_valkey() {
    let clock = wall_future();
    let store = valkey(network(clock.clone()).await, clock.clone(), 64).await;
    retention(store, clock).await;
}
#[tokio::test]
async fn payload_and_pair_deadlines_use_actual_valkey() {
    let clock = wall_future();
    let store = valkey(network(clock.clone()).await, clock.clone(), 64).await;
    tamper_and_completion(store, clock).await;
}
