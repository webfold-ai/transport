//! One nameserver's moving parts, composed: the replicated database, the serving set, and the
//! loop that turns database events and the passing of time into rebuilt (re-signed) zones.

use crate::authority::Serving;
use crate::build::{build_zone, ServerIdentity, Timings};
use crate::challenge_zone::ChallengeZoneHandler;
use crate::db::{DbEvent, ZoneDb};
use crate::escape::esc;
use crate::keys::KeyProvider;
use crate::metrics::Metrics;
use hickory_proto::rr::Name;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// A running node's shared state.
pub struct Node {
    /// The replicated database.
    pub db: Arc<ZoneDb>,
    /// What is being served.
    pub serving: Arc<Serving>,
    /// Counters.
    pub metrics: Arc<Metrics>,
    identity: ServerIdentity,
    timings: Timings,
    keys: Option<Arc<dyn KeyProvider>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// How long a zone whose keys were unavailable waits before the next rebuild attempt.
const RETRY_AFTER: u64 = 15;

impl Node {
    /// Compose a node. Installs the live challenge zone if the database is configured with one.
    #[must_use]
    pub fn new(
        db: Arc<ZoneDb>,
        metrics: Arc<Metrics>,
        identity: ServerIdentity,
        timings: Timings,
        keys: Option<Arc<dyn KeyProvider>>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Arc<Self> {
        let serving = Arc::new(Serving::new());
        if let Some(cz) = db.config().challenge_zone.clone() {
            let h =
                ChallengeZoneHandler::new(cz.clone(), db.clone(), identity.clone(), clock.clone());
            serving.install_dynamic(&cz, Arc::new(h));
        }
        Arc::new(Node {
            db,
            serving,
            metrics,
            identity,
            timings,
            keys,
            clock,
        })
    }

    /// Rebuild one zone from the database at `now` and install it (or stop serving it).
    pub fn rebuild_zone(&self, apex: &Name, now: u64) {
        let Some(zone) = self.db.zone(apex) else {
            self.serving.remove(apex);
            return;
        };
        match build_zone(
            &zone,
            &self.identity,
            self.keys.as_deref(),
            &self.timings,
            now,
        ) {
            Ok(sz) => {
                if let Err(e) = self.serving.install(sz) {
                    tracing::error!(target: "tas_dns::node", zone = %esc(&apex.to_ascii()), error = %esc(&e), "zone could not be installed");
                    self.metrics.rebuild_failures.inc();
                } else {
                    self.metrics.rebuilds.inc();
                }
            }
            Err(e) => {
                // Fail closed: a zone that must be signed but cannot be is SERVFAIL, never unsigned.
                tracing::error!(target: "tas_dns::node", zone = %esc(&apex.to_ascii()), error = %e, "zone could not be built; serving SERVFAIL");
                self.serving
                    .install_failed(apex, zone.version, now.saturating_add(RETRY_AFTER));
                self.metrics.rebuild_failures.inc();
            }
        }
    }

    /// Rebuild every active zone (startup).
    pub fn rebuild_all(&self) {
        let now = (self.clock)();
        for a in self.db.active_apexes() {
            self.rebuild_zone(&a, now);
        }
    }

    /// Run until `shutdown`: rebuild zones as the database changes and as signatures age.
    pub async fn run(
        self: Arc<Self>,
        mut events: tokio::sync::mpsc::UnboundedReceiver<DbEvent>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let mut changed: HashSet<Name> = HashSet::new();
            tokio::select! {
                () = crate::server::wait_shutdown(&mut shutdown) => return,
                ev = events.recv() => {
                    match ev {
                        Some(DbEvent::Zone(a)) => { changed.insert(a); }
                        Some(DbEvent::Challenge) => {}
                        None => return,
                    }
                    // coalesce a burst (a mesh pull delivers many objects at once)
                    while let Ok(ev) = events.try_recv() {
                        if let DbEvent::Zone(a) = ev {
                            changed.insert(a);
                        }
                    }
                }
                _ = tick.tick() => {
                    let now = (self.clock)();
                    changed.extend(self.serving.due(now));
                }
            }
            if changed.is_empty() {
                continue;
            }
            let me = self.clone();
            let now = (self.clock)();
            let work = tokio::task::spawn_blocking(move || {
                for a in &changed {
                    me.rebuild_zone(a, now);
                }
            });
            let _ = work.await;
        }
    }
}

impl Node {
    /// The DS records a parent should hold for `apex`, as presentation lines
    /// (`<apex>. IN DS <tag> <alg> <digest-type> <HEX>`); empty if the zone is unsigned or unserved.
    #[must_use]
    pub fn ds_records(&self, apex: &Name) -> Vec<String> {
        self.serving
            .info(apex)
            .filter(|i| i.signed && !i.failed)
            .map(|i| {
                i.ds.iter()
                    .map(|d| format!("{} IN DS {d}", apex.to_ascii()))
                    .collect()
            })
            .unwrap_or_default()
    }
}
