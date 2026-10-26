//! Real signed owner atomic admission, without a G2 acceptance claim.
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
async fn issued<S: Store>(
    board: &Switchboard<S, Time, RandomTokens>,
    publication: &Publication,
    device: &ed25519_dalek::SigningKey,
    verification: &Verification<'_>,
) -> (Challenge, [u8; 64]) {
    let challenge = board
        .challenge(ORIGIN, publication, verification, &clean)
        .await
        .unwrap();
    let signature = device
        .sign(&challenge_message(
            ORIGIN,
            "garden",
            &challenge,
            &publication.signed,
        ))
        .to_bytes();
    (challenge, signature)
}
fn input<'a>(
    publication: &'a Publication,
    challenge: &'a Challenge,
    signature: &'a [u8; 64],
) -> EntryProof<'a> {
    EntryProof {
        origin: ORIGIN,
        challenge,
        signature,
        publication,
    }
}

async fn races<S: Store + Clone>(store: S, clock: Time) {
    let gate = Gate::new();
    let board = board(
        Gated {
            real: store.clone(),
            gate: gate.clone(),
        },
        clock.clone(),
    );
    let mut fixture = Fixture::new("alice", 1, clock.now().unwrap() / 1000).await;
    let publication = fixture.publication.clone();
    let device = fixture.device.clone();
    let verification = fixture.verification();
    let (challenge, signature) = issued(&board, &publication, &device, &verification).await;
    let pending = store.get(&key(&challenge)).await.unwrap().unwrap();
    gate.mode.store(1, Ordering::SeqCst);
    let (first, second) = tokio::join!(
        board.admit_enter(
            input(&publication, &challenge, &signature),
            &verification,
            &clean
        ),
        board.admit_enter(
            input(&publication, &challenge, &signature),
            &verification,
            &clean
        )
    );
    gate.mode.store(0, Ordering::SeqCst);
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let loser = if first.is_ok() { &second } else { &first };
    assert!(matches!(loser, Err(Error::Storage(cmmr::Error::Conflict))));
    let (session, live) = first.or(second).unwrap();
    let marker = store.get(&key(&challenge)).await.unwrap().unwrap();
    assert_eq!(marker.value, [0]);
    assert_eq!(marker.deadline, pending.deadline);
    assert_eq!(marker.generation, pending.generation);
    assert_ne!(marker.revision, pending.revision);
    assert!(marker.indexes.is_empty());
    let page = store.page("swb_present", None, 8).await.unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].revision, live.revision);
    assert_eq!(
        serde_json::to_value(&session).unwrap()["generation"],
        page.records[0].generation
    );
    assert!(live.publication == publication);
    assert!(live.deadline <= challenge.expires_at_ms);
    assert!(matches!(
        board
            .admit_enter(
                input(&publication, &challenge, &signature),
                &verification,
                &clean
            )
            .await,
        Err(Error::Stale)
    ));

    // A legacy public consumer already holding the original pending revision
    // cannot delete a composed winner's marker or mint a second Admission.
    let (mixed, mixed_signature) = issued(&board, &publication, &device, &verification).await;
    gate.mode.store(1, Ordering::SeqCst);
    let (partial, composed) = tokio::join!(
        board.admit(
            input(&publication, &mixed, &mixed_signature),
            &verification,
            &clean
        ),
        board.admit_enter(
            input(&publication, &mixed, &mixed_signature),
            &verification,
            &clean
        )
    );
    gate.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        usize::from(partial.is_ok()) + usize::from(composed.is_ok()),
        1
    );
    match (partial, composed) {
        (Ok(admission), Err(Error::Storage(cmmr::Error::Conflict))) => {
            board.enter(admission).await.unwrap();
        }
        (Err(Error::Storage(cmmr::Error::Conflict)), Ok(_)) => {}
        _ => panic!("Both owner paths must contend on the original pending revision"),
    }
    assert_eq!(store.get(&key(&mixed)).await.unwrap().unwrap().value, [0]);
    assert_eq!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    assert_eq!(board.depart(&session).await.unwrap(), 0);
    assert!(store.get(&key(&mixed)).await.unwrap().is_some());
}

async fn capacity<S: Store + Clone>(store: S, clock: Time) {
    let board = board(store.clone(), clock.clone());
    let mut fixture = Fixture::new("alice", 1, clock.now().unwrap() / 1000).await;
    let publication = fixture.publication.clone();
    let device = fixture.device.clone();
    let verification = fixture.verification();
    let (first, first_signature) = issued(&board, &publication, &device, &verification).await;
    let (blocked, _) = issued(&board, &publication, &device, &verification).await;
    let original = store.get(&key(&first)).await.unwrap().unwrap();
    assert!(matches!(
        board
            .admit_enter(
                input(&publication, &first, &first_signature),
                &verification,
                &clean
            )
            .await,
        Err(Error::Storage(cmmr::Error::Capacity))
    ));
    assert_eq!(store.get(&key(&first)).await.unwrap(), Some(original));
    assert!(store.get("swb_alice").await.unwrap().is_none());
    assert!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    store.delete_generation(&key(&blocked)).await.unwrap();
    let (session, _) = board
        .admit_enter(
            input(&publication, &first, &first_signature),
            &verification,
            &clean,
        )
        .await
        .unwrap();
    // Pruning the consumed pending slot permits another challenge. A full-store
    // replacement needs no extra slot and atomically replaces complete indexes.
    clock.0.store(first.expires_at_ms, Ordering::SeqCst);
    store.maintain().await.unwrap();
    assert!(store.get(&key(&first)).await.unwrap().is_none());
    assert!(matches!(
        board
            .admit(
                input(&publication, &first, &first_signature),
                &verification,
                &clean
            )
            .await,
        Err(Error::Absent)
    ));
    // Recreate a live attendance with the original partial owner path so the
    // replacement capacity vector remains independent of expired presence.
    let (seed, seed_signature) = issued(&board, &publication, &device, &verification).await;
    let admission = board
        .admit(
            input(&publication, &seed, &seed_signature),
            &verification,
            &clean,
        )
        .await
        .unwrap();
    store.delete_generation(&key(&seed)).await.unwrap();
    board.enter(admission).await.unwrap();
    let (next, next_signature) = issued(&board, &publication, &device, &verification).await;
    let next_pending = store.get(&key(&next)).await.unwrap().unwrap();
    let (replacement, _) = board
        .admit_enter(
            input(&publication, &next, &next_signature),
            &verification,
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(
        store.get(&key(&next)).await.unwrap().unwrap().deadline,
        next_pending.deadline
    );
    assert_eq!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    assert_eq!(board.depart(&session).await.unwrap(), 0);
    assert_eq!(board.depart(&replacement).await.unwrap(), 1);
    assert!(store.get(&key(&next)).await.unwrap().is_some());
}

#[tokio::test]
async fn atomic_signed_memory_races_and_capacity() {
    let clock = Time(Arc::new(AtomicU64::new(1_100_000)));
    let store = |scope, records| {
        Arc::new(
            cmmr::Memory::new(
                cmmr::Scope::new("garden", scope).unwrap(),
                limits(records),
                clock.clone(),
            )
            .unwrap(),
        )
    };
    races(store("atomic-race", 64), clock.clone()).await;
    capacity(store("atomic-capacity", 2), clock).await;
}

#[tokio::test]
async fn atomic_signed_valkey_races_and_capacity() {
    if std::env::var_os("VALKEY_URL").is_none() {
        eprintln!("skipped: VALKEY_URL is required (disposable Valkey)");
        return;
    }
    let clock = wall_future();
    races(
        valkey(network(clock.clone()).await, clock.clone(), 64).await,
        clock.clone(),
    )
    .await;
    capacity(
        valkey(network(clock.clone()).await, clock.clone(), 2).await,
        clock,
    )
    .await;
}

async fn stale_attendance<S: Store + Clone>(store: S, clock: Time) {
    let gate = Gate::new();
    let board = board(
        Gated {
            real: store.clone(),
            gate: gate.clone(),
        },
        clock.clone(),
    );
    let mut fixture = Fixture::new("alice", 1, clock.now().unwrap() / 1000).await;
    let publication = fixture.publication.clone();
    let device = fixture.device.clone();
    let verification = fixture.verification();
    let (first, signature) = issued(&board, &publication, &device, &verification).await;
    let (session, live) = board
        .admit_enter(
            input(&publication, &first, &signature),
            &verification,
            &clean,
        )
        .await
        .unwrap();
    let (next, next_signature) = issued(&board, &publication, &device, &verification).await;
    let before = store.get(&key(&next)).await.unwrap().unwrap();
    gate.mode.store(2, Ordering::SeqCst);
    let attempted = board.admit_enter(
        input(&publication, &next, &next_signature),
        &verification,
        &clean,
    );
    let changed = async {
        gate.paused.notified().await;
        let nonce = [91; 16];
        let possession = Possession {
            nonce,
            signature: device
                .sign(&request_message(
                    ORIGIN,
                    "heartbeat",
                    &session,
                    &nonce,
                    b"renew",
                ))
                .to_bytes()
                .to_vec(),
        };
        let current = board
            .authorize(
                RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "heartbeat",
                    body: b"renew",
                    possession: &possession,
                },
                &verification,
                &clean,
            )
            .await
            .unwrap();
        let renewed = board
            .heartbeat(&session, &current, live.revision)
            .await
            .unwrap();
        gate.resume.notify_one();
        renewed
    };
    let (refused, renewed) = tokio::join!(attempted, changed);
    assert!(matches!(
        refused,
        Err(Error::Storage(cmmr::Error::Conflict))
    ));
    assert_eq!(store.get(&key(&next)).await.unwrap(), Some(before));
    assert_eq!(
        store.get("swb_alice").await.unwrap().unwrap().revision,
        renewed.revision
    );
    assert_eq!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    // A fresh owner verification against the current attendance may now consume
    // this still-live pending challenge; the rejected CAS never spent it.
    let (replacement, _) = board
        .admit_enter(
            input(&publication, &next, &next_signature),
            &verification,
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(board.depart(&session).await.unwrap(), 0);
    assert_eq!(board.depart(&replacement).await.unwrap(), 1);
    assert!(store.get(&key(&next)).await.unwrap().is_some());
}

async fn boundary<S: Store + Clone>(store: S, clock: Time, rollback: bool, phase: u8) {
    let gate = Gate::new();
    let board = board(
        Gated {
            real: store.clone(),
            gate: gate.clone(),
        },
        clock.clone(),
    );
    let started = clock.now().unwrap();
    let mut fixture = Fixture::new("alice", 1, started / 1000).await;
    let publication = fixture.publication.clone();
    let device = fixture.device.clone();
    let verification = fixture.verification();
    let (challenge, signature) = issued(&board, &publication, &device, &verification).await;
    let before = store.get(&key(&challenge)).await.unwrap().unwrap();
    gate.mode.store(phase, Ordering::SeqCst);
    let attempted = board.admit_enter(
        input(&publication, &challenge, &signature),
        &verification,
        &clean,
    );
    let changed = async {
        gate.paused.notified().await;
        clock.0.store(
            if rollback {
                started - 1
            } else {
                challenge.expires_at_ms
            },
            Ordering::SeqCst,
        );
        gate.resume.notify_one();
    };
    let (refused, ()) = tokio::join!(attempted, changed);
    if rollback {
        assert!(matches!(
            refused,
            Err(Error::Storage(cmmr::Error::ClockRegression))
        ));
        clock.0.store(started, Ordering::SeqCst);
        let retained = store.get(&key(&challenge)).await.unwrap().unwrap();
        if phase == 4 {
            assert_eq!(retained.value, [0]);
            assert_ne!(retained.revision, before.revision);
            assert_eq!(retained.deadline, before.deadline);
            assert!(store.get("swb_alice").await.unwrap().is_some());
            assert_eq!(
                store
                    .page("swb_present", None, 8)
                    .await
                    .unwrap()
                    .records
                    .len(),
                1
            );
            return;
        }
        assert_eq!(retained, before);
    } else {
        assert!(matches!(
            refused,
            Err(Error::Storage(cmmr::Error::Expired)) | Err(Error::Expired)
        ));
        assert!(store.get(&key(&challenge)).await.unwrap().is_none());
    }
    assert!(store.get("swb_alice").await.unwrap().is_none());
    assert!(
        store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .is_empty()
    );
}

#[tokio::test]
async fn atomic_signed_memory_rechecks_commit_preconditions() {
    let fresh = || {
        let clock = Time(Arc::new(AtomicU64::new(1_200_000)));
        let store = Arc::new(
            cmmr::Memory::new(
                cmmr::Scope::new("garden", "commit").unwrap(),
                limits(64),
                clock.clone(),
            )
            .unwrap(),
        );
        (store, clock)
    };
    let (store, clock) = fresh();
    stale_attendance(store, clock).await;
    for phase in [2, 3, 4] {
        for rollback in [false, true] {
            let (store, clock) = fresh();
            boundary(store, clock, rollback, phase).await;
        }
    }
}
#[tokio::test]
async fn atomic_signed_valkey_rechecks_commit_preconditions() {
    if std::env::var_os("VALKEY_URL").is_none() {
        eprintln!("skipped: VALKEY_URL is required (disposable Valkey)");
        return;
    }
    let clock = wall_future();
    stale_attendance(
        valkey(network(clock.clone()).await, clock.clone(), 64).await,
        clock,
    )
    .await;
    for phase in [2, 3, 4] {
        for rollback in [false, true] {
            let clock = wall_future();
            boundary(
                valkey(network(clock.clone()).await, clock.clone(), 64).await,
                clock,
                rollback,
                phase,
            )
            .await;
        }
    }
}

#[tokio::test]
async fn committed_valkey_pair_survives_lost_reply_and_cancellation() {
    if std::env::var_os("VALKEY_URL").is_none() {
        eprintln!("skipped: VALKEY_URL is required (disposable Valkey)");
        return;
    }
    for fault in [1, 2] {
        let clock = wall_future();
        let network = network(clock.clone()).await;
        let store = valkey(network.clone(), clock.clone(), 64).await;
        let board = board(store.clone(), clock.clone());
        let mut fixture = Fixture::new("alice", 1, clock.now().unwrap() / 1000).await;
        let publication = fixture.publication.clone();
        let device = fixture.device.clone();
        let verification = fixture.verification();
        let (challenge, signature) = issued(&board, &publication, &device, &verification).await;
        let before = store.get(&key(&challenge)).await.unwrap().unwrap();
        network.fault.store(fault, Ordering::SeqCst);
        if fault == 1 {
            assert!(matches!(
                board
                    .admit_enter(
                        input(&publication, &challenge, &signature),
                        &verification,
                        &clean
                    )
                    .await,
                Err(Error::Storage(cmmr::Error::Unavailable))
            ));
        } else {
            // The real atomic script has completed before cancellation. Drop
            // only the caller future, causing the adapter's original Flight
            // guard to fence the uncertain committed operation.
            let pending = board.admit_enter(
                input(&publication, &challenge, &signature),
                &verification,
                &clean,
            );
            tokio::pin!(pending);
            tokio::select! {
                result = &mut pending => panic!("The post-commit reply is withheld: {}", result.is_ok()),
                () = network.committed.notified() => {}
            }
        }
        assert_eq!(store.state(), cmmr::State::Unavailable);
        store.reopen().await.unwrap();
        let marker = store.get(&key(&challenge)).await.unwrap().unwrap();
        let attendance = store.get("swb_alice").await.unwrap().unwrap();
        assert_ne!(marker.revision, before.revision);
        assert_eq!(marker.value, [0]);
        assert_eq!(marker.deadline, before.deadline);
        assert_eq!(marker.generation, before.generation);
        assert!(marker.indexes.is_empty());
        let page = store.page("swb_present", None, 8).await.unwrap();
        assert_eq!(page.records, vec![attendance]);
        // Reconciliation observes the actual committed pair. It does not mint
        // a new session, declare a lost request uncommitted or retry mutation.
        assert!(matches!(
            board
                .admit_enter(
                    input(&publication, &challenge, &signature),
                    &verification,
                    &clean
                )
                .await,
            Err(Error::Stale)
        ));
    }
}
