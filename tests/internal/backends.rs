//! Same presence transitions on both actual backends. Internal capabilities
//! represent the verified-input precondition, never a synthetic G1/G2/G3 API.
use super::*;
use cvlk::{Network, RedisNetwork};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy)]
struct WallClock;
impl Clock for WallClock {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
    }
}
struct Sequence(AtomicU64);
impl Tokens for Sequence {
    fn next(&self) -> Result<[u8; 16], Error> {
        Ok((self.0.fetch_add(1, Ordering::SeqCst) as u128).to_be_bytes())
    }
}
fn limits() -> cmmr::Limits {
    cmmr::Limits {
        records: 4,
        value_bytes: 4096,
        batch: 4,
        indexes_per_record: 4,
        page: 8,
        ttl_ms: 60_000,
    }
}
fn binding() -> Binding {
    Binding {
        community: "parity".into(),
        member: "member".into(),
        device: [7; 32],
        epoch: 1,
        schema: 1,
    }
}
fn current() -> Current {
    Current {
        binding: binding(),
        authority_until: WallClock.now().unwrap() + 30_000,
    }
}
fn admission() -> Admission {
    Admission {
        binding: binding(),
        authority_until: WallClock.now().unwrap() + 30_000,
        publication: Publication {
            signed: vec![1, 2],
            ciphertext: vec![3, 4],
        },
    }
}
fn board<S: Store>(store: S) -> Switchboard<S, WallClock, Sequence> {
    Switchboard::new(
        store,
        WallClock,
        Sequence(AtomicU64::new(1)),
        "parity".into(),
        Limits {
            lease_ms: 10_000,
            publication_bytes: 100,
            ciphertext_bytes: 100,
        },
    )
    .unwrap()
}
async fn connect() -> RedisNetwork {
    let client =
        redis::Client::open(std::env::var("VALKEY_URL").expect("Disposable Valkey is required"))
            .unwrap();
    let connection = client.get_multiplexed_async_connection().await.unwrap();
    RedisNetwork::new(connection, Duration::from_secs(3)).unwrap()
}

async fn transitions<S: Store>(store: S) {
    let board = board(store);
    let (session, live) = board.enter(admission()).await.unwrap();
    let fresh = current();
    let (a, b) = tokio::join!(
        board.heartbeat(&session, &fresh, live.revision),
        board.heartbeat(&session, &fresh, live.revision)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    for failed in [a, b].into_iter().filter_map(Result::err) {
        assert!(matches!(
            failed,
            Error::Stale | Error::Storage(cmmr::Error::Conflict)
        ));
    }
    let before = board.read(&session, &fresh).await.unwrap();
    let mut replacement = admission();
    replacement.publication.ciphertext = vec![9];
    let after = board
        .replace(&session, &fresh, before.revision, replacement)
        .await
        .unwrap();
    assert_eq!(after.publication.ciphertext, vec![9]);
    let (next, _) = board.enter(admission()).await.unwrap();
    assert!(matches!(
        board.read(&session, &fresh).await,
        Err(Error::Stale)
    ));
    assert_eq!(board.depart(&session).await.unwrap(), 0);
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
    let mut changed = current();
    changed.binding.epoch = 2;
    assert!(matches!(
        board.read(&next, &changed).await,
        Err(Error::Stale)
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
    let mut short = admission();
    short.authority_until = WallClock.now().unwrap() + 500;
    let (expired, live) = board.enter(short).await.unwrap();
    assert!(
        board
            .heartbeat(&expired, &fresh, live.revision)
            .await
            .unwrap()
            .deadline
            <= live.deadline
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(matches!(
        board.read(&expired, &fresh).await,
        Err(Error::Absent | Error::Expired)
    ));
    board.expire().await.unwrap();
    for id in 0..4 {
        let mut input = admission();
        input.binding.member = format!("member{id}");
        board.enter(input).await.unwrap();
    }
    assert!(matches!(
        board.enter(admission()).await,
        Err(Error::Storage(cmmr::Error::Capacity))
    ));
    assert_eq!(
        board
            .store
            .page("swb_present", None, 8)
            .await
            .unwrap()
            .records
            .len(),
        4
    );
    board.store.close();
    assert!(matches!(
        board.expire().await,
        Err(Error::Storage(cmmr::Error::Closed))
    ));
}

#[tokio::test]
async fn memory_and_valkey_share_presence_vectors() {
    transitions(
        cmmr::Memory::new(
            cmmr::Scope::new("parity", "memory").unwrap(),
            limits(),
            WallClock,
        )
        .unwrap(),
    )
    .await;
    let store = cvlk::Valkey::open(
        Arc::new(connect().await),
        cmmr::Scope::new("parity", "valkey").unwrap(),
        limits(),
        WallClock,
    )
    .await
    .unwrap();
    transitions(store).await;
}

/// Drop only the reply, after the actual atomic script completed.
struct LostReply {
    real: RedisNetwork,
    lose: AtomicBool,
}
impl Network for LostReply {
    async fn health(&self) -> Result<cvlk::Health, cmmr::Error> {
        self.real.health().await
    }
    async fn invoke(
        &self,
        script: &'static str,
        key: &str,
        request: &str,
    ) -> Result<String, cmmr::Error> {
        let reply = self.real.invoke(script, key, request).await?;
        let value: serde_json::Value = serde_json::from_str(request).unwrap();
        if value["mode"] == "cas" && self.lose.swap(false, Ordering::SeqCst) {
            return Err(cmmr::Error::Unavailable);
        }
        Ok(reply)
    }
}
#[tokio::test]
async fn lost_valkey_write_reply_requires_reopen_and_current_revision() {
    let network = Arc::new(LostReply {
        real: connect().await,
        lose: AtomicBool::new(false),
    });
    let store = Arc::new(
        cvlk::Valkey::open(
            network.clone(),
            cmmr::Scope::new("parity", "lost").unwrap(),
            limits(),
            WallClock,
        )
        .await
        .unwrap(),
    );
    let board = board(store.clone());
    let (session, before) = board.enter(admission()).await.unwrap();
    network.lose.store(true, Ordering::SeqCst);
    let fresh = current();
    let mut input = admission();
    input.publication.ciphertext = vec![42];
    assert!(matches!(
        board
            .replace(&session, &fresh, before.revision, input)
            .await,
        Err(Error::Storage(cmmr::Error::Unavailable))
    ));
    assert!(matches!(
        board.read(&session, &fresh).await,
        Err(Error::Storage(cmmr::Error::Unavailable))
    ));
    store.reopen().await.unwrap();
    let reconciled = board.read(&session, &fresh).await.unwrap();
    assert_ne!(reconciled.revision, before.revision);
    assert_eq!(reconciled.publication.ciphertext, vec![42]);
    assert!(matches!(
        board.heartbeat(&session, &fresh, before.revision).await,
        Err(Error::Stale)
    ));
    assert_eq!(board.depart(&session).await.unwrap(), 1);
}
