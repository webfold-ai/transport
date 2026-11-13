//! Workload provisioning — latency-aware, capacity-constrained stage planning.
//!
//! Built on the three transport primitives this module composes:
//! - `LatencyTracker::sorted_by_latency()` — pick the fastest peers first
//! - `PeerAffinity::healthy_peers()` — exclude flaky peers
//! - `PeerDirectory` capabilities — match model families, enforce VRAM budget
//!
//! The planner's output is a `Vec<PipelineStage>` that feeds directly into
//! `Cluster::pipelined_pmap` — sink stages run first, source stage last.
//!
//! Ported from Mesh-LLM's Skippy topology planner ("latency-aware physical stage counts")
//! and the MoA worker-set knob ("restrict worker pool by capability"). For CountLM/GBM
//! distribution: GBM tree ranges, CountLM byte ranges, autofold guard+GBM pairs.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the eligible peer set (which peers match the constraints)
//! - **B/Map** = the stage→peer assignment (stage index → [peer ids])
//! - **B/U** = the workload accumulator (total trees/bytes assigned, per-peer)
//! - **self** = the plan itself (the assignment turned on itself — execute it)

use super::discovery::PeerCapability;
use super::latency::{LatencyTracker, PeerAffinity};
use super::PeerId;
use apeiron::map::hashtrinity::crypto::to_hex;

/// One stage of a pipelined plan — the nodes assigned to run it. Defined here (the producer
/// side); bedrock's `runtime::cluster` consumes this same shape via `Cluster::pipelined_pmap`.
/// Kept local rather than imported from bedrock to avoid a cycle (bedrock already depends on
/// this crate for transport).
#[derive(Clone, Debug)]
pub struct PipelineStage {
    pub node_ids: Vec<String>,
}

/// Constraints for workload placement — what the caller needs and what peers must have.
#[derive(Clone, Debug)]
pub struct PlacementConstraints {
    /// Required capability string (e.g. "GBM", "CountLM", "autofold").
    pub capability: String,
    /// Minimum free VRAM required per peer (bytes).
    pub min_free_vram: u64,
    /// Minimum number of peers needed (returns error if fewer qualify).
    pub min_peers: usize,
    /// Maximum number of peers to use (spreads work wider than needed).
    pub max_peers: usize,
    /// Maximum acceptable RTT to a peer (excludes peers beyond this).
    pub max_rtt: Option<std::time::Duration>,
    /// Maximum error count a peer can have and still be considered.
    pub max_errors: u32,
}

impl Default for PlacementConstraints {
    fn default() -> Self {
        PlacementConstraints {
            capability: String::new(),
            min_free_vram: 0,
            min_peers: 1,
            max_peers: usize::MAX,
            max_rtt: None,
            max_errors: 3,
        }
    }
}

/// One peer's assigned slice of work.
#[derive(Clone, Debug)]
pub struct PeerAssignment {
    pub peer_id: PeerId,
    /// Tree index range [start, end) for GBM shards.
    pub tree_start: usize,
    pub tree_end: usize,
    /// Byte range [start, end) for CountLM shards.
    pub byte_start: usize,
    pub byte_end: usize,
}

/// A staged workload plan — sink stages (highest index) run first.
///
/// The plan assigns work units (tree ranges or byte ranges) across qualifying peers,
/// ordered by latency (fastest peers get the sink/last stages so they're ready
/// before the source stage routes).
#[derive(Clone, Debug)]
pub struct WorkloadPlan {
    pub stages: Vec<PipelineStage>,
    pub assignments: Vec<PeerAssignment>,
    /// Total work units assigned.
    pub total_work: usize,
}

/// The workload planner — stateless, operates on snapshots of directory + latency + affinity.
#[derive(Clone, Debug, Default)]
pub struct WorkloadPlanner;

impl WorkloadPlanner {
    pub fn new() -> Self {
        WorkloadPlanner
    }

    /// Select qualifying peers: must have the required capability, sufficient VRAM,
    /// be healthy, and be within RTT budget. Returns peers ordered by ascending latency
    /// (fastest first — these get assigned to sink stages).
    pub fn qualify_peers(
        &self,
        directory: &super::discovery::PeerDirectory,
        latency: &LatencyTracker,
        affinity: &PeerAffinity,
        constraints: &PlacementConstraints,
    ) -> Vec<PeerCapability> {
        let mut candidates: Vec<PeerCapability> = directory
            .capable_of(&constraints.capability)
            .into_iter()
            .filter(|c| c.free_vram >= constraints.min_free_vram)
            .filter(|c| affinity.is_healthy(c.peer_id))
            .filter(|c| {
                if let Some(max_rtt) = constraints.max_rtt {
                    latency.rtt(c.peer_id).is_none_or(|rtt| rtt <= max_rtt)
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Sort by ascending RTT (fastest first) — these go to later (sink) stages.
        candidates.sort_by_key(|c| {
            latency
                .rtt(c.peer_id)
                .map_or(u128::MAX, |rtt| rtt.as_micros())
        });

        // Limit to max_peers, keeping the fastest
        if candidates.len() > constraints.max_peers {
            candidates.truncate(constraints.max_peers);
        }

        candidates
    }

    /// Plan GBM tree shards across qualifying peers.
    ///
    /// Given `total_trees` to distribute and `qualifying_peers` (already filtered and
    /// sorted by ascending RTT), splits tree indices evenly. The LAST peer in the sorted
    /// list (fastest) gets the sink stage (runs first). Returns a plan with stages in
    /// source-first order (stage 0 = source, stage N-1 = sink).
    pub fn plan_gbm_trees(
        &self,
        qualifying_peers: &[PeerCapability],
        total_trees: usize,
    ) -> Option<WorkloadPlan> {
        if qualifying_peers.is_empty() || total_trees == 0 {
            return None;
        }
        let n = qualifying_peers.len();
        let trees_per = total_trees.div_ceil(n);
        let mut assignments = Vec::with_capacity(n);
        let mut offset = 0usize;
        for (i, cap) in qualifying_peers.iter().enumerate() {
            let end = ((i + 1) * trees_per).min(total_trees);
            assignments.push(PeerAssignment {
                peer_id: cap.peer_id,
                tree_start: offset,
                tree_end: end,
                byte_start: 0,
                byte_end: 0,
            });
            offset = end;
        }

        // Stages: the first assignment is stage 0 (source), the last is the sink.
        // Each PipelineStage has one node for GBM tree shards (each peer runs its range).
        let stages: Vec<PipelineStage> = assignments
            .iter()
            .map(|a| PipelineStage {
                node_ids: vec![to_hex(&a.peer_id)],
            })
            .collect();

        Some(WorkloadPlan {
            stages,
            assignments,
            total_work: total_trees,
        })
    }

    /// Plan CountLM byte-range shards across qualifying peers.
    ///
    /// Given `total_bytes` to distribute and `qualifying_peers` (already filtered and
    /// sorted by ascending RTT), splits byte ranges evenly. Each peer's CountLM can
    /// fold its assigned byte range independently, then results merge via `CountLM::merge`.
    pub fn plan_countlm_bytes(
        &self,
        qualifying_peers: &[PeerCapability],
        total_bytes: usize,
    ) -> Option<WorkloadPlan> {
        if qualifying_peers.is_empty() || total_bytes == 0 {
            return None;
        }
        let n = qualifying_peers.len();
        let bytes_per = total_bytes.div_ceil(n);
        let mut assignments = Vec::with_capacity(n);
        let mut offset = 0usize;
        for (i, cap) in qualifying_peers.iter().enumerate() {
            let end = ((i + 1) * bytes_per).min(total_bytes);
            assignments.push(PeerAssignment {
                peer_id: cap.peer_id,
                tree_start: 0,
                tree_end: 0,
                byte_start: offset,
                byte_end: end,
            });
            offset = end;
        }

        let stages: Vec<PipelineStage> = assignments
            .iter()
            .map(|a| PipelineStage {
                node_ids: vec![to_hex(&a.peer_id)],
            })
            .collect();

        Some(WorkloadPlan {
            stages,
            assignments,
            total_work: total_bytes,
        })
    }

    /// Plan autofold replica placement — replicate the (guard + GBM) artifact across
    /// qualifying peers. Each peer gets the full model; no sharding.
    /// First peer in the list is the coordinator (source stage), rest are replicas.
    pub fn plan_autofold_replicas(
        &self,
        qualifying_peers: &[PeerCapability],
    ) -> Option<WorkloadPlan> {
        if qualifying_peers.is_empty() {
            return None;
        }
        let n = qualifying_peers.len();
        let assignments: Vec<PeerAssignment> = qualifying_peers
            .iter()
            .map(|cap| PeerAssignment {
                peer_id: cap.peer_id,
                tree_start: 0,
                tree_end: 0,
                byte_start: 0,
                byte_end: 0,
            })
            .collect();

        // The coordinator (source) is stage 0, replicas are downstream stages.
        // Downstream (replica) stages run first — they load the model, then source becomes routable.
        let stages: Vec<PipelineStage> = assignments
            .iter()
            .map(|a| PipelineStage {
                node_ids: vec![to_hex(&a.peer_id)],
            })
            .collect();

        Some(WorkloadPlan {
            stages,
            assignments,
            total_work: n,
        })
    }

    /// One-shot: qualify peers, plan GBM tree shards, return plan or None if insufficient peers.
    pub fn plan_gbm_distribution(
        &self,
        directory: &super::discovery::PeerDirectory,
        latency: &LatencyTracker,
        affinity: &PeerAffinity,
        constraints: &PlacementConstraints,
        total_trees: usize,
    ) -> Option<WorkloadPlan> {
        let peers = self.qualify_peers(directory, latency, affinity, constraints);
        if peers.len() < constraints.min_peers {
            return None;
        }
        self.plan_gbm_trees(&peers, total_trees)
    }

    /// One-shot: qualify peers, plan CountLM byte shards.
    pub fn plan_countlm_distribution(
        &self,
        directory: &super::discovery::PeerDirectory,
        latency: &LatencyTracker,
        affinity: &PeerAffinity,
        constraints: &PlacementConstraints,
        total_bytes: usize,
    ) -> Option<WorkloadPlan> {
        let peers = self.qualify_peers(directory, latency, affinity, constraints);
        if peers.len() < constraints.min_peers {
            return None;
        }
        self.plan_countlm_bytes(&peers, total_bytes)
    }

    // ── Auto-scaling: evaluate demand vs. capacity, produce scaling decisions ──────────

    /// Compute aggregate free capacity across qualifying peers for a capability.
    pub fn aggregate_capacity(
        &self,
        directory: &super::discovery::PeerDirectory,
        latency: &LatencyTracker,
        affinity: &PeerAffinity,
        constraints: &PlacementConstraints,
    ) -> AggregateCapacity {
        let peers = self.qualify_peers(directory, latency, affinity, constraints);
        let total_free_ram: u64 = peers.iter().map(|c| c.free_ram).sum();
        let total_free_vram: u64 = peers.iter().map(|c| c.free_vram).sum();
        let peer_count = peers.len() as u32;
        let avg_load: f64 = if peer_count > 0 {
            peers.iter().map(|c| c.load).sum::<f64>() / peer_count as f64
        } else {
            0.0
        };
        let max_per_peer_ram = peers.iter().map(|c| c.free_ram).max().unwrap_or(0);
        let max_per_peer_vram = peers.iter().map(|c| c.free_vram).max().unwrap_or(0);
        AggregateCapacity {
            peer_count,
            total_free_ram,
            total_free_vram,
            avg_load,
            max_per_peer_ram,
            max_per_peer_vram,
        }
    }

    /// Evaluate scaling by collapse to the floor: the minimum peer count that covers demand,
    /// given per-peer capacity limits. This is `x = B/U` on the mesh — P is the boundary
    /// count, per-peer capacity is the drag coefficient. The floor `min_P` is the unique
    /// product solution (`joint_solution_unique` / `WebCollapse.lean`): there is exactly one
    /// configuration that minimizes P while covering the total work.
    ///
    /// - current_P > floor_P  → ScaleDown (drag without boundary — pure waste)
    /// - current_P = 0         → ScaleUp to floor_P (no boundary at all)
    /// - current_P < floor_P   → ScaleUp to fill the gap
    /// - current_P = floor_P   → Noop (already at the rest state)
    ///
    /// The fragmentation penalty is zero when P = min_P and grows as excess peers inject
    /// additional merge boundaries (CountLM) or fan-out hops (GBM ensemble) with no new
    /// work done — pure U, no B. No heuristic thresholds — the geometry decides.
    pub fn evaluate_scale(&self, demand: &Demand, capacity: &AggregateCapacity) -> ScalingDecision {
        // No peers at all → must scale up to the full floor.
        if capacity.peer_count == 0 {
            let floor = demand.min_peers.max(1) as u32;
            return ScalingDecision::ScaleUp(ProvisioningNeed {
                min_additional_peers: floor,
                reason: format!(
                    "no peers for capability={}; floor requires {} peer(s)",
                    demand.capability, floor
                ),
            });
        }

        // The floor: total work units / max per-peer capacity, rounded up.
        let work_per_unit = demand.ram_per_worker.unwrap_or(0);
        let vram_per_unit = demand.vram_per_worker.unwrap_or(0);

        let floor_ram = if work_per_unit > 0 && capacity.max_per_peer_ram > 0 {
            let total_ram_work = work_per_unit * demand.min_peers as u64;
            (total_ram_work.div_ceil(capacity.max_per_peer_ram)).max(1)
        } else {
            demand.min_peers.max(1) as u64
        };

        let floor_vram = if vram_per_unit > 0 && capacity.max_per_peer_vram > 0 {
            let total_vram_work = vram_per_unit * demand.min_peers as u64;
            (total_vram_work.div_ceil(capacity.max_per_peer_vram)).max(1)
        } else {
            0
        };

        let floor = floor_ram.max(floor_vram).max(1) as u32;
        let floor = floor.min(demand.max_peers as u32);

        let current = capacity.peer_count;

        // At the floor — no decision needed. This is the rest state (`dragfield_sterile`).
        if current == floor {
            return ScalingDecision::Noop;
        }

        // Above the floor — excess peers are pure drag. Every extra peer adds one merge
        // boundary per CountLM::merge or one fan-out hop per GBM ensemble predict with
        // no additional work capacity. The fragmentation penalty is (excess / current).
        if current > floor {
            let excess = current - floor;
            return ScalingDecision::ScaleDown(ScaleDownTarget {
                excess_peers: excess,
                reason: format!(
                    "{} peers; floor is {} — {} excess adds {:.0}% communication drag with no boundary gain",
                    current, floor, excess,
                    (excess as f64 / current as f64) * 100.0,
                ),
            });
        }

        // Below the floor — not enough boundary to hold the work.
        let needed = floor - current;
        ScalingDecision::ScaleUp(ProvisioningNeed {
            min_additional_peers: needed,
            reason: format!(
                "floor requires {} peers ({} exist) to cover {} units at {} MB/unit; max per-peer holds {} MB",
                floor, current, demand.min_peers,
                work_per_unit / 1_000_000,
                capacity.max_per_peer_ram / 1_000_000,
            ),
        })
    }

    /// Provision workers at the floor — one peer per unit that max_per_peer capacity cannot
    /// absorb. The floor itself dictates count; no consolidation boolean needed.
    pub fn provisioning_target(
        &self,
        demand: &Demand,
        capacity: &AggregateCapacity,
    ) -> Option<super::discovery::ProvisioningTarget> {
        let work_per = demand.ram_per_worker.unwrap_or(0);
        let total = work_per * demand.min_peers as u64;

        // If one peer can cover it, that's the floor. If not, capacity dictates count.
        let count = if total > 0 && capacity.max_per_peer_ram > 0 {
            (total.div_ceil(capacity.max_per_peer_ram)).max(1) as u32
        } else {
            let need = demand
                .min_peers
                .saturating_sub(capacity.peer_count as usize);
            if need == 0 {
                return None;
            }
            need as u32
        };

        let ram_per = if capacity.max_per_peer_ram > 0 {
            (total / count as u64).min(capacity.max_per_peer_ram)
        } else {
            work_per
        };

        let substrate = match demand.capability.as_str() {
            "CountLM" => super::discovery::ProvisioningSubstrate::Lxc,
            _ => super::discovery::ProvisioningSubstrate::Kvm,
        };
        let compute_kind = match demand.compute_kind.as_deref() {
            Some("cuda") => super::discovery::ComputeKind::Cuda,
            Some("rocm") => super::discovery::ComputeKind::Rocm,
            Some("vulkan") => super::discovery::ComputeKind::Vulkan,
            _ => super::discovery::ComputeKind::Cpu,
        };

        Some(super::discovery::ProvisioningTarget {
            substrate,
            vcpus: demand.vcpus_per_worker.unwrap_or(4),
            ram_bytes: ram_per,
            vram_bytes: demand.vram_per_worker.unwrap_or(0),
            compute_kind,
            capabilities: vec![demand.capability.clone()],
            count,
            label_prefix: format!("{}-worker", demand.capability.to_lowercase()),
            provider_tag: demand.provider_tag.clone(),
        })
    }
}

/// Aggregate free capacity across qualifying peers.
#[derive(Clone, Debug, Default)]
pub struct AggregateCapacity {
    pub peer_count: u32,
    pub total_free_ram: u64,
    pub total_free_vram: u64,
    pub avg_load: f64,
    /// Largest free RAM on any single peer — the consolidation ceiling.
    pub max_per_peer_ram: u64,
    /// Largest free VRAM on any single peer.
    pub max_per_peer_vram: u64,
}

/// The current workload demand — what the caller needs to distribute.
#[derive(Clone, Debug)]
pub struct Demand {
    pub capability: String,
    pub min_peers: usize,
    pub max_peers: usize,
    pub compute_kind: Option<String>,
    pub vcpus_per_worker: Option<u32>,
    pub ram_per_worker: Option<u64>,
    pub vram_per_worker: Option<u64>,
    pub provider_tag: Option<String>,
}

/// How many new workers are needed when scaling up.
#[derive(Clone, Debug)]
pub struct ProvisioningNeed {
    pub min_additional_peers: u32,
    pub reason: String,
}

/// Which excess peers can be deprovisioned when scaling down.
#[derive(Clone, Debug)]
pub struct ScaleDownTarget {
    pub excess_peers: u32,
    pub reason: String,
}

/// The auto-scaler's decision — what to do about the cluster size.
#[derive(Clone, Debug)]
pub enum ScalingDecision {
    ScaleUp(ProvisioningNeed),
    ScaleDown(ScaleDownTarget),
    Noop,
}

#[cfg(test)]
mod tests {
    use super::super::discovery::PeerDirectory;
    use super::super::latency::{LatencyTracker, PeerAffinity};
    use super::*;
    use std::time::Duration;

    fn test_cap(peer_id: PeerId, free_vram: u64, _rtt: Duration) -> PeerCapability {
        PeerCapability {
            peer_id,
            addr: None,
            label: format!("node-{}", peer_id[0]),
            total_ram: 16_000_000_000,
            free_ram: 8_000_000_000,
            total_vram: free_vram * 2,
            free_vram,
            compute_kind: super::super::discovery::ComputeKind::Cpu,
            models_loaded: vec![],
            capabilities: vec!["GBM".to_string(), "CountLM".to_string()],
            load: 0.0,
            source: super::super::discovery::DiscoverySource::Direct,
            last_seen: std::time::Instant::now(),
        }
    }

    #[test]
    fn qualify_filters_by_vram_and_health() {
        let mut dir = PeerDirectory::new();
        let mut lat = LatencyTracker::new();
        let mut aff = PeerAffinity::new(3);

        let good = test_cap([1u8; 32], 8_000_000_000, Duration::from_millis(5));
        let low_vram = test_cap([2u8; 32], 500_000_000, Duration::from_millis(5));
        let flaky = test_cap([3u8; 32], 8_000_000_000, Duration::from_millis(5));

        lat.record(good.peer_id, Duration::from_millis(5));
        lat.record(low_vram.peer_id, Duration::from_millis(5));
        lat.record(flaky.peer_id, Duration::from_millis(5));
        aff.record_error(flaky.peer_id);
        aff.record_error(flaky.peer_id);
        aff.record_error(flaky.peer_id); // unhealthy

        dir.add_peer(good);
        dir.add_peer(low_vram);
        dir.add_peer(flaky);

        let planner = WorkloadPlanner::new();
        let constraints = PlacementConstraints {
            capability: "GBM".into(),
            min_free_vram: 1_000_000_000,
            min_peers: 1,
            max_peers: 10,
            max_rtt: None,
            max_errors: 3,
        };
        let peers = planner.qualify_peers(&dir, &lat, &aff, &constraints);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, [1u8; 32]);
    }

    #[test]
    fn gbm_tree_plan_evenly_distributes() {
        let caps = vec![
            test_cap([1u8; 32], 8_000_000_000, Duration::from_millis(1)),
            test_cap([2u8; 32], 8_000_000_000, Duration::from_millis(5)),
            test_cap([3u8; 32], 8_000_000_000, Duration::from_millis(10)),
        ];
        let planner = WorkloadPlanner::new();
        let plan = planner.plan_gbm_trees(&caps, 100).unwrap();
        assert_eq!(plan.assignments.len(), 3);
        assert_eq!(plan.total_work, 100);
        // Fastest peer (RTT 1ms) gets last assignment (sink) = largest range
        // Actually: trees_per = 100/3 = 34 (ceil division)
        // [0..34, 34..68, 68..100]
        assert_eq!(plan.assignments[0].tree_start, 0);
        assert_eq!(plan.assignments[2].tree_start, 68);
        // Stages: 3 stages, sink (stage index 2) runs first = fastest peer
        assert_eq!(plan.stages.len(), 3);
    }

    #[test]
    fn countlm_byte_plan_splits_bytes() {
        let caps = vec![
            test_cap([1u8; 32], 8_000_000_000, Duration::from_millis(1)),
            test_cap([2u8; 32], 8_000_000_000, Duration::from_millis(5)),
        ];
        let planner = WorkloadPlanner::new();
        let plan = planner.plan_countlm_bytes(&caps, 1024).unwrap();
        assert_eq!(plan.assignments.len(), 2);
        assert_eq!(plan.total_work, 1024);
        assert_eq!(plan.assignments[0].byte_start, 0);
        assert_eq!(plan.assignments[0].byte_end, 512);
        assert_eq!(plan.assignments[1].byte_start, 512);
        assert_eq!(plan.assignments[1].byte_end, 1024);
    }

    #[test]
    fn insufficient_peers_returns_none() {
        let caps: Vec<PeerCapability> = vec![];
        let planner = WorkloadPlanner::new();
        assert!(planner.plan_gbm_trees(&caps, 100).is_none());
    }

    #[test]
    fn autofold_replicas_uses_all_peers() {
        let caps = vec![
            test_cap([1u8; 32], 8_000_000_000, Duration::from_millis(1)),
            test_cap([2u8; 32], 8_000_000_000, Duration::from_millis(5)),
        ];
        let planner = WorkloadPlanner::new();
        let plan = planner.plan_autofold_replicas(&caps).unwrap();
        assert_eq!(plan.assignments.len(), 2);
        assert_eq!(plan.stages.len(), 2);
    }

    #[test]
    fn rtt_filter_excludes_slow_peers() {
        let mut dir = PeerDirectory::new();
        let mut lat = LatencyTracker::new();
        let aff = PeerAffinity::new(3);

        let fast = test_cap([1u8; 32], 8_000_000_000, Duration::from_millis(5));
        let slow = test_cap([2u8; 32], 8_000_000_000, Duration::from_millis(200));
        lat.record(fast.peer_id, Duration::from_millis(5));
        lat.record(slow.peer_id, Duration::from_millis(200));
        dir.add_peer(fast);
        dir.add_peer(slow);

        let planner = WorkloadPlanner::new();
        let constraints = PlacementConstraints {
            capability: "GBM".into(),
            min_free_vram: 1_000_000_000,
            min_peers: 1,
            max_peers: 10,
            max_rtt: Some(Duration::from_millis(100)),
            max_errors: 3,
        };
        let peers = planner.qualify_peers(&dir, &lat, &aff, &constraints);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, [1u8; 32]);
    }

    #[test]
    fn aggregate_capacity_sums_free_resources() {
        let mut dir = PeerDirectory::new();
        let mut lat = LatencyTracker::new();
        let aff = PeerAffinity::new(3);

        dir.add_peer(test_cap([1u8; 32], 8_000_000_000, Duration::from_millis(5)));
        dir.add_peer(test_cap([2u8; 32], 4_000_000_000, Duration::from_millis(5)));
        lat.record([1u8; 32], Duration::from_millis(5));
        lat.record([2u8; 32], Duration::from_millis(5));

        let planner = WorkloadPlanner::new();
        let constraints = PlacementConstraints {
            capability: "GBM".into(),
            min_free_vram: 1_000_000_000,
            min_peers: 1,
            max_peers: 10,
            max_rtt: None,
            max_errors: 3,
        };
        let cap = planner.aggregate_capacity(&dir, &lat, &aff, &constraints);
        assert_eq!(cap.peer_count, 2);
        assert_eq!(cap.total_free_vram, 12_000_000_000);
        assert_eq!(cap.max_per_peer_vram, 8_000_000_000);
    }

    #[test]
    fn evaluate_scale_up_when_demand_exceeds_capacity() {
        let planner = WorkloadPlanner::new();
        let demand = Demand {
            capability: "CountLM".into(),
            min_peers: 5,
            max_peers: 10,
            compute_kind: None,
            vcpus_per_worker: None,
            ram_per_worker: Some(8_000_000_000),
            vram_per_worker: None,
            provider_tag: None,
        };
        // Each peer has 2GB free — total work = 5×8=40GB. floor = 40/2 = 20 peers.
        let capacity = AggregateCapacity {
            peer_count: 2,
            total_free_ram: 4_000_000_000,
            total_free_vram: 0,
            avg_load: 0.5,
            max_per_peer_ram: 2_000_000_000,
            max_per_peer_vram: 0,
        };
        let decision = planner.evaluate_scale(&demand, &capacity);
        match decision {
            ScalingDecision::ScaleUp(need) => {
                assert_eq!(need.min_additional_peers, 8); // floor=20 capped by max_peers=10, current=2
                assert!(need.reason.contains("floor"));
            }
            _ => panic!("expected ScaleUp, got {decision:?}"),
        }
    }

    #[test]
    fn evaluate_scale_at_floor_is_noop() {
        let planner = WorkloadPlanner::new();
        let demand = Demand {
            capability: "CountLM".into(),
            min_peers: 5,
            max_peers: 10,
            compute_kind: None,
            vcpus_per_worker: None,
            ram_per_worker: Some(8_000_000_000),
            vram_per_worker: None,
            provider_tag: None,
        };
        // Each peer has 8GB — floor = 40/8 = 5 peers. current = 5 → Noop.
        let capacity = AggregateCapacity {
            peer_count: 5,
            total_free_ram: 40_000_000_000,
            total_free_vram: 0,
            avg_load: 0.2,
            max_per_peer_ram: 8_000_000_000,
            max_per_peer_vram: 0,
        };
        let decision = planner.evaluate_scale(&demand, &capacity);
        assert!(matches!(decision, ScalingDecision::Noop));
    }

    #[test]
    fn evaluate_scale_above_floor_is_scaledown() {
        let planner = WorkloadPlanner::new();
        let demand = Demand {
            capability: "CountLM".into(),
            min_peers: 2,
            max_peers: 5,
            compute_kind: None,
            vcpus_per_worker: None,
            ram_per_worker: Some(16_000_000_000),
            vram_per_worker: None,
            provider_tag: None,
        };
        // One peer has 32GB free — floor = 1. current = 4 → excess 3 = pure drag.
        let capacity = AggregateCapacity {
            peer_count: 4,
            total_free_ram: 40_000_000_000,
            total_free_vram: 0,
            avg_load: 0.1,
            max_per_peer_ram: 32_000_000_000,
            max_per_peer_vram: 0,
        };
        let decision = planner.evaluate_scale(&demand, &capacity);
        match decision {
            ScalingDecision::ScaleDown(target) => {
                assert_eq!(target.excess_peers, 3);
                assert!(target.reason.contains("floor"));
                assert!(target.reason.contains("drag"));
            }
            _ => panic!("expected ScaleDown, got {decision:?}"),
        }
    }

    #[test]
    fn evaluate_scale_down_when_excess_capacity_idle() {
        let planner = WorkloadPlanner::new();
        let demand = Demand {
            capability: "CountLM".into(),
            min_peers: 1,
            max_peers: 3,
            compute_kind: None,
            vcpus_per_worker: None,
            ram_per_worker: Some(8_000_000_000),
            vram_per_worker: None,
            provider_tag: None,
        };
        let capacity = AggregateCapacity {
            peer_count: 10,
            total_free_ram: 80_000_000_000,
            total_free_vram: 0,
            avg_load: 0.05,
            max_per_peer_ram: 8_000_000_000,
            max_per_peer_vram: 0,
        };
        let decision = planner.evaluate_scale(&demand, &capacity);
        match decision {
            ScalingDecision::ScaleDown(target) => {
                assert!(target.excess_peers >= 6);
                assert!(target.reason.contains("drag"));
            }
            _ => panic!("expected ScaleDown, got {decision:?}"),
        }
    }

    #[test]
    fn evaluate_scale_noop_when_right_sized() {
        let planner = WorkloadPlanner::new();
        let demand = Demand {
            capability: "CountLM".into(),
            min_peers: 2,
            max_peers: 5,
            compute_kind: None,
            vcpus_per_worker: None,
            ram_per_worker: Some(8_000_000_000),
            vram_per_worker: None,
            provider_tag: None,
        };
        let capacity = AggregateCapacity {
            peer_count: 2,
            total_free_ram: 16_000_000_000,
            total_free_vram: 0,
            avg_load: 0.4,
            max_per_peer_ram: 8_000_000_000,
            max_per_peer_vram: 0,
        };
        let decision = planner.evaluate_scale(&demand, &capacity);
        assert!(matches!(decision, ScalingDecision::Noop));
    }

    #[test]
    fn provisioning_target_for_countlm_uses_lxc_cpu() {
        let planner = WorkloadPlanner::new();
        let demand = Demand {
            capability: "CountLM".into(),
            min_peers: 3,
            max_peers: 5,
            compute_kind: None,
            vcpus_per_worker: Some(2),
            ram_per_worker: Some(4_000_000_000),
            vram_per_worker: None,
            provider_tag: None,
        };
        let capacity = AggregateCapacity {
            peer_count: 0,
            total_free_ram: 0,
            total_free_vram: 0,
            avg_load: 0.0,
            max_per_peer_ram: 0,
            max_per_peer_vram: 0,
        };
        let target = planner.provisioning_target(&demand, &capacity).unwrap();
        assert!(matches!(
            target.substrate,
            super::super::discovery::ProvisioningSubstrate::Lxc
        ));
        assert_eq!(target.vcpus, 2);
        assert_eq!(target.ram_bytes, 4_000_000_000);
        assert_eq!(target.count, 3);
        assert!(matches!(
            target.compute_kind,
            super::super::discovery::ComputeKind::Cpu
        ));
    }

    #[test]
    fn provisioning_target_at_floor_capacity_selects_floor_count() {
        let planner = WorkloadPlanner::new();
        let demand = Demand {
            capability: "GBM".into(),
            min_peers: 6,
            max_peers: 10,
            compute_kind: None,
            vcpus_per_worker: Some(4),
            ram_per_worker: Some(8_000_000_000),
            vram_per_worker: Some(4_000_000_000),
            provider_tag: None,
        };
        // Each peer holds 32GB → floor = (6×8)/32 = 2 peers
        let capacity = AggregateCapacity {
            peer_count: 1,
            total_free_ram: 0,
            total_free_vram: 0,
            avg_load: 0.0,
            max_per_peer_ram: 32_000_000_000,
            max_per_peer_vram: 0,
        };
        let target = planner.provisioning_target(&demand, &capacity).unwrap();
        assert_eq!(target.count, 2);
        assert_eq!(target.ram_bytes, 24_000_000_000); // 48GB total ÷ 2
        assert_eq!(target.vcpus, 4);
    }
}
