//! Barriers and fault injection around the actual owner storage operations.
use super::*;
use cvlk::Network;
use std::sync::atomic::AtomicU8;
use tokio::sync::{Barrier, Notify};

pub(super) fn limits(records: usize) -> cmmr::Limits {
    cmmr::Limits {
        records,
        value_bytes: 262_144,
        batch: 4,
        indexes_per_record: 4,
        page: 8,
        ttl_ms: 600_000,
    }
}
pub(super) struct Gate {
    pub(super) mode: AtomicU8,
    race: Barrier,
    pub(super) paused: Notify,
    pub(super) resume: Notify,
}
impl Gate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            mode: AtomicU8::new(0),
            race: Barrier::new(2),
            paused: Notify::new(),
            resume: Notify::new(),
        })
    }
    async fn pause(&self) {
        self.paused.notify_one();
        self.resume.notified().await;
    }
    async fn before(&self, batch: &[cmmr::Write]) {
        // Pause only real owner consumption writes, after both owner reads and
        // signature checks. The actual Store decides every CAS result.
        if batch
            .iter()
            .any(|write| write.record.key.starts_with("challenge_") && write.record.value == [0])
        {
            match self.mode.load(Ordering::SeqCst) {
                1 => {
                    self.race.wait().await;
                }
                2 => {
                    if self.mode.swap(0, Ordering::SeqCst) == 2 {
                        self.pause().await;
                    }
                }
                _ => {}
            }
        }
    }
}
#[derive(Clone)]
pub(super) struct Gated<S> {
    pub(super) real: S,
    pub(super) gate: Arc<Gate>,
}
impl<S: Store> Store for Gated<S> {
    fn state(&self) -> cmmr::State {
        self.real.state()
    }
    async fn get(&self, key: &str) -> Result<Option<cmmr::Record>, cmmr::Error> {
        let record = self.real.get(key).await?;
        if key == "swb_alice"
            && self
                .gate
                .mode
                .compare_exchange(3, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.gate.pause().await;
        }
        Ok(record)
    }
    async fn check_current(&self, checks: &[cmmr::Check]) -> Result<(), cmmr::Error> {
        self.real.check_current(checks).await
    }
    async fn compare_exchange(&self, batch: &[cmmr::Write]) -> Result<(), cmmr::Error> {
        self.gate.before(batch).await;
        self.real.compare_exchange(batch).await?;
        if batch.len() == 2
            && self
                .gate
                .mode
                .compare_exchange(4, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.gate.pause().await;
        }
        Ok(())
    }
    async fn delete_generation(&self, generation: &str) -> Result<usize, cmmr::Error> {
        self.real.delete_generation(generation).await
    }
    async fn page(
        &self,
        index: &str,
        cursor: Option<&cmmr::Cursor>,
        limit: usize,
    ) -> Result<cmmr::Page, cmmr::Error> {
        self.real.page(index, cursor, limit).await
    }
    async fn maintain(&self) -> Result<usize, cmmr::Error> {
        self.real.maintain().await
    }
    fn close(&self) {
        self.real.close();
    }
}

pub(super) struct ControlledNetwork {
    real: cvlk::RedisNetwork,
    clock: Time,
    pub(super) fault: AtomicU8,
    pub(super) committed: Notify,
    release: Notify,
}
impl Network for ControlledNetwork {
    async fn health(&self) -> Result<cvlk::Health, cmmr::Error> {
        self.real.health().await
    }
    async fn invoke(
        &self,
        script: &'static str,
        key: &str,
        request: &str,
    ) -> Result<String, cmmr::Error> {
        // Replace only primary TIME, following the existing real-backend vectors.
        // Every production CAS, capacity, generation and index command still
        // executes in the actual disposable Valkey instance.
        let now = self.clock.now()?;
        let script = script.replace(
            "local t = redis.call('TIME')",
            &format!("local t = {{{}, {}}}", now / 1000, (now % 1000) * 1000),
        );
        let script = Box::leak(script.into_boxed_str());
        let reply = self.real.invoke(script, key, request).await?;
        let request: serde_json::Value = serde_json::from_str(request).unwrap();
        if request["mode"] == "cas" && request["batch"].as_array().unwrap().len() == 2 {
            match self.fault.swap(0, Ordering::SeqCst) {
                1 => return Err(cmmr::Error::Unavailable),
                2 => {
                    self.committed.notify_one();
                    self.release.notified().await;
                }
                _ => {}
            }
        }
        Ok(reply)
    }
}
pub(super) async fn network(clock: Time) -> Arc<ControlledNetwork> {
    let client =
        redis::Client::open(std::env::var("VALKEY_URL").expect("Disposable Valkey is required"))
            .unwrap();
    Arc::new(ControlledNetwork {
        real: cvlk::RedisNetwork::new(
            client.get_multiplexed_async_connection().await.unwrap(),
            std::time::Duration::from_secs(3),
        )
        .unwrap(),
        clock,
        fault: AtomicU8::new(0),
        committed: Notify::new(),
        release: Notify::new(),
    })
}
pub(super) async fn valkey(
    network: Arc<ControlledNetwork>,
    clock: Time,
    records: usize,
) -> Arc<cvlk::Valkey<ControlledNetwork, Time>> {
    Arc::new(
        cvlk::Valkey::open(
            network,
            cmmr::Scope::new(
                "garden",
                data_encoding::HEXLOWER.encode(&RandomTokens.next().unwrap()),
            )
            .unwrap(),
            limits(records),
            clock,
        )
        .await
        .unwrap(),
    )
}
pub(super) fn wall_future() -> Time {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    Time(Arc::new(AtomicU64::new(now + 120_000)))
}
