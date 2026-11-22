//! rollout — the alias-flip release controller (INV-02 / INV-03).
//!
//! The load-bearing invariant of the derived-invariants build order: a new
//! release MUST NOT become live until its readiness probe passes, and the
//! previously live release MUST NOT be destroyed before that point. A
//! deployment is therefore atomic: either the new unit is live, or the old
//! one is, never neither and never both.
//!
//! The control plane (the saga / deploy driver) calls
//! [`RolloutController::stage`], then [`RolloutController::probe_and_flip`];
//! only a passing probe flips the alias. A rollback is
//! [`RolloutController::rollback`], a pointer flip, never a redeploy, and
//! repeating it walks further back through earlier releases.
//!
//! ## What is durable, and what routing reads
//!
//! The truth for each alias is a [`saga_pipeline::alias::AliasTable`]: an
//! append-only log of promote/rollback flips. Every flip is written to the
//! [`Journal`] **before** it takes effect in memory, so a flip that cannot be
//! recorded does not happen (INV-02) and a restart replays the journal to the
//! same live release. A corrupt journal makes startup fail rather than serve
//! a release nobody can account for. A *staged* unit has not moved traffic and
//! is not journaled: it is lost on restart, which is safe.
//!
//! Routing reads [`RolloutController::live_target`] (see `EdgeLb`'s
//! `request_filter` / `upstream_peer`): a flip therefore changes where
//! traffic goes. Previews are not special: a preview hostname is just another
//! alias.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use saga_pipeline::alias::{AliasEvent, AliasTable};
use serde::{Deserialize, Serialize};

/// Who the journal records as the actor for control-API flips.
const ACTOR: &str = "edge-control";

/// One release unit: the routing target a probe must pass before it can
/// become live.
#[derive(Clone, Debug, PartialEq)]
pub struct ReleaseUnit {
    pub id: String,
    pub target: String,
}

/// The probe result — the ONLY signal that activates a pending unit.
#[derive(Clone, Debug, PartialEq)]
pub enum ProbeResult {
    Ready,
    NotReady,
    ProbeError(String),
}

/// A readiness probe: given the pending unit, decide readiness.
pub type Probe = Box<dyn Fn(&ReleaseUnit) -> ProbeResult + Send + Sync>;

/// The per-alias release state, for observability.
#[derive(Clone, Debug, PartialEq)]
pub enum ReleaseState {
    /// Probing; the alias still points at the live unit (if any). The live
    /// unit rides along as the rollback target.
    Pending {
        unit: ReleaseUnit,
        previous: Option<ReleaseUnit>,
    },
    /// Probe passed; the alias points here. `previous` is what a rollback
    /// would restore.
    Live {
        unit: ReleaseUnit,
        previous: Option<ReleaseUnit>,
    },
}

// ── journal ────────────────────────────────────────────────────────────

/// One durable flip: the alias event plus the routing target of the unit it
/// made live (the event itself only names the release id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub alias: String,
    pub target: String,
    pub event: AliasEvent,
}

/// Durable storage for flips. `append` must not return until the entry is
/// safely stored: the flip is only applied after it returns `Ok`.
pub trait Journal: Send + Sync {
    fn append(&self, entry: &JournalEntry) -> Result<(), String>;
    fn load(&self) -> Result<Vec<JournalEntry>, String>;
}

/// A newline-delimited JSON file, fsynced on every append.
pub struct FileJournal {
    path: PathBuf,
}

impl FileJournal {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Journal for FileJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), String> {
        let mut line =
            serde_json::to_vec(entry).map_err(|e| format!("serialise journal entry: {e}"))?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("open journal {}: {e}", self.path.display()))?;
        f.write_all(&line)
            .map_err(|e| format!("write journal: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync journal: {e}"))
    }

    /// Read every entry. A final line with no trailing newline that does not
    /// parse is a torn write from a crash mid-append: it was never
    /// acknowledged, so it is dropped and the file is truncated back to the
    /// last good entry (otherwise the next append would glue onto it). A bad
    /// line anywhere else is corruption and is an error.
    fn load(&self) -> Result<Vec<JournalEntry>, String> {
        let raw = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("read journal {}: {e}", self.path.display())),
        };
        let ends_clean = raw.last().is_none_or(|b| *b == b'\n');
        let text = String::from_utf8(raw).map_err(|e| format!("journal is not UTF-8: {e}"))?;
        let lines: Vec<&str> = text.split('\n').collect();
        // `split` yields a trailing "" when the file ends with '\n'.
        let last = lines.len().saturating_sub(1);
        let mut out = Vec::new();
        let mut good_bytes = 0usize;
        for (i, line) in lines.iter().enumerate() {
            if line.is_empty() && i == last {
                break;
            }
            match serde_json::from_str::<JournalEntry>(line) {
                Ok(e) => {
                    out.push(e);
                    good_bytes += line.len() + 1;
                }
                Err(_) if i == last && !ends_clean => {
                    let f = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&self.path)
                        .map_err(|e| format!("open journal for repair: {e}"))?;
                    f.set_len(good_bytes as u64)
                        .map_err(|e| format!("truncate torn journal tail: {e}"))?;
                    break;
                }
                Err(e) => return Err(format!("journal line {} is corrupt: {e}", i + 1)),
            }
        }
        Ok(out)
    }
}

// ── controller ─────────────────────────────────────────────────────────

#[derive(Default)]
struct AliasEntry {
    table: AliasTable,
    /// release id -> routing target, for every id that has ever been live.
    targets: HashMap<String, String>,
    pending: Option<ReleaseUnit>,
}

impl AliasEntry {
    fn unit(&self, id: &str) -> Option<ReleaseUnit> {
        self.targets.get(id).map(|t| ReleaseUnit {
            id: id.to_string(),
            target: t.clone(),
        })
    }
    fn live(&self) -> Option<ReleaseUnit> {
        self.table.live().and_then(|id| self.unit(id))
    }
    fn previous(&self) -> Option<ReleaseUnit> {
        self.table.previous().and_then(|id| self.unit(id))
    }
}

/// The edge's release authority: one alias per hostname, atomic flips.
pub struct RolloutController {
    aliases: HashMap<String, AliasEntry>,
    journal: Option<Box<dyn Journal>>,
    probe_timeout: Duration,
}

impl Default for RolloutController {
    fn default() -> Self {
        Self::new()
    }
}

impl RolloutController {
    /// An in-memory controller: flips are not durable.
    pub fn new() -> Self {
        RolloutController {
            aliases: HashMap::new(),
            journal: None,
            probe_timeout: Duration::from_secs(30),
        }
    }

    /// A durable controller: replays `journal` and records every later flip
    /// in it. Fails if the journal cannot be read or does not replay.
    pub fn with_journal(journal: Box<dyn Journal>) -> Result<Self, String> {
        let entries = journal.load()?;
        let mut by_alias: HashMap<String, Vec<JournalEntry>> = HashMap::new();
        for e in entries {
            by_alias.entry(e.alias.clone()).or_default().push(e);
        }
        let mut aliases = HashMap::new();
        for (alias, entries) in by_alias {
            let events: Vec<AliasEvent> = entries.iter().map(|e| e.event.clone()).collect();
            let table = AliasTable::replay(&events)
                .map_err(|e| format!("journal for {alias:?} does not replay: {e}"))?;
            let mut targets = HashMap::new();
            for e in &entries {
                targets.insert(e.event.to.clone(), e.target.clone());
            }
            aliases.insert(
                alias,
                AliasEntry {
                    table,
                    targets,
                    pending: None,
                },
            );
        }
        Ok(RolloutController {
            aliases,
            journal: Some(journal),
            probe_timeout: Duration::from_secs(30),
        })
    }

    pub fn probe_timeout(&self) -> Duration {
        self.probe_timeout
    }

    /// The live target for an alias, if any — what routing consults.
    pub fn live_target(&self, alias: &str) -> Option<&str> {
        let e = self.aliases.get(alias)?;
        let id = e.table.live()?;
        e.targets
            .get(id)
            .map(String::as_str)
            .filter(|t| !t.is_empty())
    }

    /// The current release state for an alias (for status/observability).
    pub fn state(&self, alias: &str) -> Option<ReleaseState> {
        let e = self.aliases.get(alias)?;
        match (&e.pending, e.live()) {
            (Some(unit), live) => Some(ReleaseState::Pending {
                unit: unit.clone(),
                previous: live,
            }),
            (None, Some(unit)) => Some(ReleaseState::Live {
                unit,
                previous: e.previous(),
            }),
            (None, None) => None,
        }
    }

    /// Every alias's release state, as owned copies.
    pub fn snapshot(&self) -> Vec<(String, ReleaseState)> {
        let mut aliases: Vec<&String> = self.aliases.keys().collect();
        aliases.sort();
        aliases
            .into_iter()
            .filter_map(|a| self.state(a).map(|s| (a.clone(), s)))
            .collect()
    }

    /// The staged-but-not-live unit for an alias, if any.
    pub fn pending(&self, alias: &str) -> Option<ReleaseUnit> {
        self.aliases.get(alias)?.pending.clone()
    }

    /// The durable flip history for an alias, oldest first.
    pub fn history(&self, alias: &str) -> Vec<AliasEvent> {
        self.aliases
            .get(alias)
            .map(|e| e.table.log().to_vec())
            .unwrap_or_default()
    }

    /// Introduce a new unit under an alias WITHOUT flipping it (INV-02: the
    /// alias never moves until the probe passes). Re-staging replaces any
    /// earlier pending unit.
    pub fn stage(&mut self, alias: &str, unit: ReleaseUnit) {
        self.aliases.entry(alias.to_string()).or_default().pending = Some(unit);
    }

    fn record(&self, alias: &str, target: &str, event: &AliasEvent) -> Result<(), String> {
        match &self.journal {
            Some(j) => j
                .append(&JournalEntry {
                    alias: alias.to_string(),
                    target: target.to_string(),
                    event: event.clone(),
                })
                .map_err(|e| format!("journal: {e}")),
            None => Ok(()),
        }
    }

    /// Run the readiness probe for a staged unit; on success, flip the alias
    /// atomically. On failure — or if the flip cannot be journaled — the
    /// alias stays put (INV-02).
    pub fn probe_and_flip(&mut self, alias: &str, probe: &Probe) -> Result<ProbeResult, String> {
        let Some(entry) = self.aliases.get(alias) else {
            return Err("no staged release for this alias".to_string());
        };
        let Some(pending) = entry.pending.clone() else {
            return Err(if entry.table.live().is_some() {
                "alias is already live; nothing to probe".to_string()
            } else {
                "no staged release for this alias".to_string()
            });
        };
        match probe(&pending) {
            ProbeResult::Ready => {}
            other => return Ok(other),
        }
        // Apply to a copy, journal it, and only then commit.
        let mut table = entry.table.clone();
        let event = table
            .promote(&pending.id, ACTOR, Utc::now())
            .map_err(|e| e.to_string())?;
        self.record(alias, &pending.target, &event)?;
        let entry = self.aliases.entry(alias.to_string()).or_default();
        entry.table = table;
        entry.targets.insert(pending.id.clone(), pending.target);
        entry.pending = None;
        Ok(ProbeResult::Ready)
    }

    /// Roll back an alias to the release that was live before the current
    /// one — a pointer flip, never a redeploy (INV-03). Repeating walks
    /// further back. Returns the restored unit.
    pub fn rollback(&mut self, alias: &str) -> Result<ReleaseUnit, String> {
        const NONE: &str = "no previous live unit to roll back to";
        let entry = self.aliases.get(alias).ok_or_else(|| NONE.to_string())?;
        let mut table = entry.table.clone();
        let event = table
            .rollback(ACTOR, Utc::now())
            .map_err(|_| NONE.to_string())?;
        let unit = entry.unit(&event.to).ok_or_else(|| NONE.to_string())?;
        self.record(alias, &unit.target, &event)?;
        if let Some(entry) = self.aliases.get_mut(alias) {
            entry.table = table;
        }
        Ok(unit)
    }

    /// Take an alias out of service (a torn-down preview): nothing is live afterwards, routing
    /// stops serving the hostname, and any staged unit is dropped. Journaled before it takes
    /// effect, like every flip. Returns the unit that was live.
    pub fn retire(&mut self, alias: &str) -> Result<ReleaseUnit, String> {
        const NONE: &str = "no live release to retire";
        let entry = self.aliases.get(alias).ok_or_else(|| NONE.to_string())?;
        let live = entry.live().ok_or_else(|| NONE.to_string())?;
        let mut table = entry.table.clone();
        let event = table
            .retire(ACTOR, Utc::now())
            .map_err(|_| NONE.to_string())?;
        self.record(alias, &live.target, &event)?;
        self.aliases.remove(alias);
        Ok(live)
    }

    /// Cancel a staged (pending) release: the alias never moves, and a live
    /// unit stays live.
    pub fn cancel(&mut self, alias: &str) -> bool {
        let Some(entry) = self.aliases.get_mut(alias) else {
            return false;
        };
        let had = entry.pending.take().is_some();
        if entry.table.live().is_none() && entry.pending.is_none() {
            self.aliases.remove(alias);
        }
        had
    }
}

/// Split an `http://host:port` rollout target into its parts. Only plain
/// HTTP upstreams are routable from a rollout target today.
#[must_use]
pub fn http_target(target: &str) -> Option<(String, u16)> {
    let rest = target.strip_prefix("http://")?.trim_end_matches('/');
    let (host, port) = rest.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    (!host.is_empty() && !host.contains('/')).then(|| (host.to_string(), port))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use std::sync::{Arc, Mutex};

    use super::*;

    fn probe(ok: bool) -> Probe {
        Box::new(move |_| {
            if ok {
                ProbeResult::Ready
            } else {
                ProbeResult::NotReady
            }
        })
    }

    fn unit(id: &str) -> ReleaseUnit {
        ReleaseUnit {
            id: id.into(),
            target: format!("http://{id}:9001"),
        }
    }

    fn release(rc: &mut RolloutController, alias: &str, id: &str) {
        rc.stage(alias, unit(id));
        assert_eq!(
            rc.probe_and_flip(alias, &probe(true)).unwrap(),
            ProbeResult::Ready
        );
    }

    #[test]
    fn staging_never_moves_the_alias() {
        let mut rc = RolloutController::new();
        rc.stage("app", unit("u1"));
        assert_eq!(rc.live_target("app"), None);
    }

    #[test]
    fn probe_failure_keeps_alias_put() {
        let mut rc = RolloutController::new();
        release(&mut rc, "app", "u1");
        rc.stage("app", unit("u2"));
        assert_eq!(
            rc.probe_and_flip("app", &probe(false)).unwrap(),
            ProbeResult::NotReady
        );
        assert_eq!(
            rc.live_target("app"),
            Some("http://u1:9001"),
            "the old release keeps serving"
        );
    }

    #[test]
    fn ready_probe_flips_atomically() {
        let mut rc = RolloutController::new();
        rc.stage("app", unit("u1"));
        assert_eq!(
            rc.probe_and_flip("app", &probe(true)).unwrap(),
            ProbeResult::Ready
        );
        assert_eq!(rc.live_target("app"), Some("http://u1:9001"));
    }

    #[test]
    fn rollback_is_a_pointer_flip_to_previous_and_walks_back() {
        let mut rc = RolloutController::new();
        for id in ["u1", "u2", "u3"] {
            release(&mut rc, "app", id);
        }
        assert_eq!(rc.rollback("app").unwrap().id, "u2");
        assert_eq!(rc.live_target("app"), Some("http://u2:9001"));
        assert_eq!(rc.rollback("app").unwrap().id, "u1");
        assert!(
            rc.rollback("app").is_err(),
            "nothing earlier than the first release"
        );
    }

    #[test]
    fn rollback_with_no_previous_fails_with_the_documented_message() {
        let mut rc = RolloutController::new();
        release(&mut rc, "app", "u1");
        let e = rc.rollback("app").unwrap_err();
        assert!(e.contains("no previous"), "{e}");
        assert!(RolloutController::new()
            .rollback("ghost")
            .unwrap_err()
            .contains("no previous"));
    }

    #[test]
    fn probing_with_nothing_staged_uses_the_documented_messages() {
        let mut rc = RolloutController::new();
        assert!(rc
            .probe_and_flip("app", &probe(true))
            .unwrap_err()
            .contains("no staged"));
        release(&mut rc, "app", "u1");
        assert!(rc
            .probe_and_flip("app", &probe(true))
            .unwrap_err()
            .contains("already live"));
    }

    #[test]
    fn cancel_pending_never_moves_alias_and_keeps_the_live_unit() {
        let mut rc = RolloutController::new();
        rc.stage("app", unit("u1"));
        assert!(rc.cancel("app"));
        assert_eq!(rc.live_target("app"), None);
        assert!(!rc.cancel("app"));

        release(&mut rc, "app", "u1");
        rc.stage("app", unit("u2"));
        assert!(rc.cancel("app"));
        assert_eq!(rc.live_target("app"), Some("http://u1:9001"));
    }

    #[test]
    fn state_reports_pending_with_the_live_unit_as_rollback_target() {
        let mut rc = RolloutController::new();
        release(&mut rc, "app", "u1");
        rc.stage("app", unit("u2"));
        assert_eq!(
            rc.state("app"),
            Some(ReleaseState::Pending {
                unit: unit("u2"),
                previous: Some(unit("u1"))
            })
        );
        release(&mut rc, "app", "u2");
        assert_eq!(
            rc.state("app"),
            Some(ReleaseState::Live {
                unit: unit("u2"),
                previous: Some(unit("u1"))
            })
        );
    }

    #[test]
    fn a_promote_after_rollback_starts_a_new_line() {
        let mut rc = RolloutController::new();
        for id in ["u1", "u2"] {
            release(&mut rc, "app", id);
        }
        rc.rollback("app").unwrap();
        release(&mut rc, "app", "u3");
        assert_eq!(rc.live_target("app"), Some("http://u3:9001"));
        assert_eq!(
            rc.rollback("app").unwrap().id,
            "u1",
            "u2 was rolled back, not a rollback target"
        );
    }

    #[test]
    fn previews_are_just_aliases_with_independent_histories() {
        let mut rc = RolloutController::new();
        release(&mut rc, "site.example.com", "prod-1");
        release(&mut rc, "site--feat-x.tascloud.dev", "prev-1");
        release(&mut rc, "site--feat-x.tascloud.dev", "prev-2");
        assert_eq!(
            rc.live_target("site.example.com"),
            Some("http://prod-1:9001")
        );
        assert_eq!(rc.history("site--feat-x.tascloud.dev").len(), 2);
        assert_eq!(rc.history("site.example.com").len(), 1);
    }

    // ── durability ────────────────────────────────────────────────────

    #[derive(Clone, Default)]
    struct MemJournal {
        entries: Arc<Mutex<Vec<JournalEntry>>>,
        fail: Arc<Mutex<bool>>,
    }

    impl Journal for MemJournal {
        fn append(&self, e: &JournalEntry) -> Result<(), String> {
            if *self.fail.lock().unwrap() {
                return Err("disk full".into());
            }
            self.entries.lock().unwrap().push(e.clone());
            Ok(())
        }
        fn load(&self) -> Result<Vec<JournalEntry>, String> {
            Ok(self.entries.lock().unwrap().clone())
        }
    }

    #[test]
    fn a_restart_serves_the_same_release() {
        let j = MemJournal::default();
        let mut rc = RolloutController::with_journal(Box::new(j.clone())).unwrap();
        for id in ["u1", "u2", "u3"] {
            release(&mut rc, "app", id);
        }
        rc.rollback("app").unwrap();
        drop(rc);

        let mut rc = RolloutController::with_journal(Box::new(j)).unwrap();
        assert_eq!(rc.live_target("app"), Some("http://u2:9001"));
        assert_eq!(
            rc.rollback("app").unwrap().id,
            "u1",
            "history survived the restart"
        );
    }

    #[test]
    fn a_flip_that_cannot_be_journaled_does_not_happen() {
        let j = MemJournal::default();
        let mut rc = RolloutController::with_journal(Box::new(j.clone())).unwrap();
        release(&mut rc, "app", "u1");
        *j.fail.lock().unwrap() = true;

        rc.stage("app", unit("u2"));
        let e = rc.probe_and_flip("app", &probe(true)).unwrap_err();
        assert!(e.contains("journal"), "{e}");
        assert_eq!(
            rc.live_target("app"),
            Some("http://u1:9001"),
            "old release still serves"
        );
        assert_eq!(rc.history("app").len(), 1);

        assert!(rc.rollback("app").is_err());
        *j.fail.lock().unwrap() = false;
        assert_eq!(
            rc.probe_and_flip("app", &probe(true)).unwrap(),
            ProbeResult::Ready,
            "the staged unit is still pending"
        );
    }

    #[test]
    fn a_journal_that_does_not_replay_refuses_to_start() {
        let j = MemJournal::default();
        let mut rc = RolloutController::with_journal(Box::new(j.clone())).unwrap();
        release(&mut rc, "app", "u1");
        release(&mut rc, "app", "u2");
        j.entries.lock().unwrap()[1].event.from = Some("forged".into());
        assert!(RolloutController::with_journal(Box::new(j)).is_err());
    }

    #[test]
    fn the_file_journal_round_trips_and_survives_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("releases.jsonl");
        let mut rc = RolloutController::with_journal(Box::new(FileJournal::new(&path))).unwrap();
        release(&mut rc, "app", "u1");
        release(&mut rc, "app", "u2");
        drop(rc);

        // A crash mid-append leaves half a line with no newline.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(br#"{"alias":"app","target":"http://u3:9001","event":{"seq":3,"at":"#)
            .unwrap();
        drop(f);

        let mut rc = RolloutController::with_journal(Box::new(FileJournal::new(&path))).unwrap();
        assert_eq!(
            rc.live_target("app"),
            Some("http://u2:9001"),
            "the unacknowledged flip is not applied"
        );
        release(&mut rc, "app", "u3");
        drop(rc);

        // The torn tail was cut off, so the next append did not glue onto it.
        let rc = RolloutController::with_journal(Box::new(FileJournal::new(&path))).unwrap();
        assert_eq!(rc.live_target("app"), Some("http://u3:9001"));
        assert_eq!(rc.history("app").len(), 3);
    }

    #[test]
    fn corruption_in_the_middle_of_the_file_is_an_error_not_a_skip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("releases.jsonl");
        let mut rc = RolloutController::with_journal(Box::new(FileJournal::new(&path))).unwrap();
        release(&mut rc, "app", "u1");
        release(&mut rc, "app", "u2");
        drop(rc);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines[0] = "{ not json";
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(RolloutController::with_journal(Box::new(FileJournal::new(&path))).is_err());
    }

    #[test]
    fn a_missing_journal_file_is_an_empty_journal() {
        let dir = tempfile::tempdir().unwrap();
        let rc =
            RolloutController::with_journal(Box::new(FileJournal::new(dir.path().join("none"))))
                .unwrap();
        assert!(rc.snapshot().is_empty());
    }

    #[test]
    fn retiring_stops_routing_and_a_restart_agrees() {
        let j = MemJournal::default();
        let mut rc = RolloutController::with_journal(Box::new(j.clone())).unwrap();
        release(&mut rc, "prev.tascloud.dev", "u1");
        release(&mut rc, "other.tascloud.dev", "u2");
        rc.stage("prev.tascloud.dev", unit("u3"));
        assert_eq!(rc.retire("prev.tascloud.dev").unwrap().id, "u1");
        assert_eq!(rc.live_target("prev.tascloud.dev"), None);
        assert_eq!(
            rc.pending("prev.tascloud.dev"),
            None,
            "a staged unit does not outlive its alias"
        );
        assert_eq!(
            rc.live_target("other.tascloud.dev"),
            Some("http://u2:9001"),
            "other aliases are untouched"
        );
        assert!(rc
            .retire("prev.tascloud.dev")
            .unwrap_err()
            .contains("no live release"));
        assert!(rc.rollback("prev.tascloud.dev").is_err());

        let rc = RolloutController::with_journal(Box::new(j)).unwrap();
        assert_eq!(
            rc.live_target("prev.tascloud.dev"),
            None,
            "still retired after a restart"
        );
        assert_eq!(rc.live_target("other.tascloud.dev"), Some("http://u2:9001"));
    }

    #[test]
    fn a_retire_that_cannot_be_journaled_does_not_happen() {
        let j = MemJournal::default();
        let mut rc = RolloutController::with_journal(Box::new(j.clone())).unwrap();
        release(&mut rc, "prev.tascloud.dev", "u1");
        *j.fail.lock().unwrap() = true;
        assert!(rc
            .retire("prev.tascloud.dev")
            .unwrap_err()
            .contains("journal"));
        assert_eq!(
            rc.live_target("prev.tascloud.dev"),
            Some("http://u1:9001"),
            "still serving"
        );
    }

    #[test]
    fn http_targets_parse_and_everything_else_does_not() {
        assert_eq!(
            http_target("http://10.0.0.5:8080"),
            Some(("10.0.0.5".into(), 8080))
        );
        assert_eq!(http_target("http://u1:9001/"), Some(("u1".into(), 9001)));
        for bad in [
            "https://x:1",
            "http://x",
            "http://x:0",
            "http://:80",
            "dialkey://k#s",
            "http://a/b:80",
            "http://x:99999",
        ] {
            assert_eq!(http_target(bad), None, "{bad}");
        }
    }
}
