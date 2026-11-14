//! Peer discovery — unified pkarr + mDNS + dialkey + gossip peer lookup.
//!
//! Mesh-LLM uses Nostr for public discovery, mDNS for LAN, and invite tokens for private
//! meshes. This module unifies Sanguine's equivalents: **pkarr** for cross-network discovery
//! (signed DNS packets via relay/DHT), **mDNS** for LAN-scoped advertisement, **dialkey** for
//! deterministic pre-shared-secret addressing, and **gossip** for in-mesh membership
//! propagation. One `PeerDirectory::discover()` call merges all four sources, deduplicates by
//! `PeerId`, and returns a unified peer capability map.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the peer set per source (which peers each channel knows about)
//! - **B/Map** = the capability map (PeerId → PeerCapability) — last-write-wins per source
//! - **B/U** = the discovery accumulator (stats: how many peers per source, merged total)
//! - **self** = the directory itself (the merged view — the medium turned on itself)

use super::{PeerAddr, PeerId};
use apeiron::map::hashtrinity::crypto::to_hex;
use apeiron::map::hashtrinity::Table;
use std::time::Duration;

#[cfg(feature = "bind-overlay")]
use iroh::{address_lookup::memory::MemoryLookup, EndpointAddr, EndpointId};
#[cfg(feature = "bind-overlay")]
use std::sync::{Arc, RwLock};

/// Re-export `apeiron::map::hashtrinity::crypto::to_hex` so provision.rs and other callers can format
/// PeerId keys without importing hashtrinity-crypto themselves.
pub use apeiron::map::hashtrinity::crypto::to_hex as peer_key_hex;

/// What kind of compute substrate a peer runs on — used for mixed-cluster placement
/// (CPU-only LXCs alongside GPU VMs, ARM edge nodes alongside x86 servers).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComputeKind {
    /// Generic CPU (x86_64 or aarch64 — CountLM is ISA-agnostic).
    Cpu,
    /// NVIDIA GPU with CUDA.
    Cuda,
    /// AMD GPU with ROCm/HIP.
    Rocm,
    /// Vulkan compute (SPIR-V — any GPU with a Vulkan driver).
    Vulkan,
    /// Apple Metal (macOS GPU).
    Metal,
    /// Unknown or not yet classified.
    Unknown,
}

impl std::fmt::Display for ComputeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComputeKind::Cpu => write!(f, "cpu"),
            ComputeKind::Cuda => write!(f, "cuda"),
            ComputeKind::Rocm => write!(f, "rocm"),
            ComputeKind::Vulkan => write!(f, "vulkan"),
            ComputeKind::Metal => write!(f, "metal"),
            ComputeKind::Unknown => write!(f, "unknown"),
        }
    }
}

impl ComputeKind {
    // Infallible (unknown strings map to a variant), so it is not a `FromStr` impl.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "cpu" => ComputeKind::Cpu,
            "cuda" => ComputeKind::Cuda,
            "rocm" => ComputeKind::Rocm,
            "vulkan" => ComputeKind::Vulkan,
            "metal" => ComputeKind::Metal,
            _ => ComputeKind::Unknown,
        }
    }
}

/// A provisioning target — what kind of worker the auto-scaler should create.
/// This maps directly to the saga `DeployRequest` schema: `substrate.kind` +
/// `substrate.cpu`/`substrate.ram`/`substrate.gpu`.   CITATION-EXEMPT: a discovery TXT record key, not a declaration
#[derive(Clone, Debug, PartialEq)]
pub struct ProvisioningTarget {
    /// LXC, VM (QEMU/KVM), or k8s pod.
    pub substrate: ProvisioningSubstrate,
    /// vCPUs to allocate.
    pub vcpus: u32,
    /// RAM in bytes.
    pub ram_bytes: u64,
    /// VRAM in bytes (0 for CPU-only).
    pub vram_bytes: u64,
    /// Compute backend to advertise (GPU backend selection).
    pub compute_kind: ComputeKind,
    /// Capability labels to advertise (e.g. "CountLM", "GBM").
    pub capabilities: Vec<String>,
    /// How many instances of this target to provision.
    pub count: u32,
    /// Node label prefix for the provisioned worker.
    pub label_prefix: String,
    /// Provider-specific tag (Proxmox node, k8s namespace, etc.).
    pub provider_tag: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvisioningSubstrate {
    /// Proxmox LXC container (CPU-only, shares host kernel).
    Lxc,
    /// Proxmox QEMU/KVM virtual machine (full OS, GPU passthrough).
    Kvm,
    /// Kubernetes pod (via Cozystack/Talos or direct k8s).
    K8s,
    /// Docker container (via galvanize-docker).
    Docker,
}

impl std::fmt::Display for ProvisioningSubstrate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisioningSubstrate::Lxc => write!(f, "lxc"),
            ProvisioningSubstrate::Kvm => write!(f, "kvm"),
            ProvisioningSubstrate::K8s => write!(f, "k8s"),
            ProvisioningSubstrate::Docker => write!(f, "docker"),
        }
    }
}

/// What a peer advertises it can run — the mesh-model service TXT record.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerCapability {
    pub peer_id: PeerId,
    pub addr: Option<PeerAddr>,
    /// Human-readable label (like Mesh-LLM's `--node-label`).
    pub label: String,
    /// Total RAM in bytes.
    pub total_ram: u64,
    /// Currently free RAM in bytes.
    pub free_ram: u64,
    /// Total VRAM in bytes (0 if unknown / CPU-only).
    pub total_vram: u64,
    /// Currently free VRAM in bytes.
    pub free_vram: u64,
    /// Compute backend kind.
    pub compute_kind: ComputeKind,
    /// Models this peer currently has loaded (model IDs).
    pub models_loaded: Vec<String>,
    /// Model families this peer can run (e.g. "CountLM", "GBM", "autofold").
    pub capabilities: Vec<String>,
    /// Current load metric (0.0 = idle, 1.0 = fully saturated).
    pub load: f64,
    /// Which discovery source this came from.
    pub source: DiscoverySource,
    /// When this entry was last seen (for TTL/expiry).
    pub last_seen: std::time::Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoverySource {
    Pkarr,
    Mdns,
    Dialkey,
    Gossip,
    Direct, // manually added via add_peer
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoverySource::Pkarr => write!(f, "pkarr"),
            DiscoverySource::Mdns => write!(f, "mdns"),
            DiscoverySource::Dialkey => write!(f, "dialkey"),
            DiscoverySource::Gossip => write!(f, "gossip"),
            DiscoverySource::Direct => write!(f, "direct"),
        }
    }
}

/// The merged peer directory — one unified view over pkarr, mDNS, dialkey, and gossip.
///
/// On `discover()`, each source is polled independently and results are merged via
/// last-seen-wins: if the same PeerId appears from multiple sources, the MOST RECENT
/// advertisement wins (since it carries the freshest load/capacity numbers).
#[derive(Clone, Debug)]
pub struct PeerDirectory {
    peers: Table<String, PeerCapability>,
    /// TTL after which a peer entry is considered stale and dropped.
    stale_ttl: Duration,
    /// Known dialkeys to resolve (pre-shared-secret private meshes).
    dialkeys: Vec<String>,
    /// Known pkarr public keys to resolve.
    known_keys: Vec<[u8; 32]>,
    /// Peer IDs seen via gossip to track.
    gossip_peers: Vec<PeerId>,
}

/// A bootstrap directory for iroh overlay peers.
///
/// This is the load-bearing discovery primitive for `tas-overlay`: callers register full
/// `EndpointAddr`s here, and the same registry feeds an `iroh::address_lookup::memory::MemoryLookup`
/// for live dials. This is the piece that turns the docs' `hostname -> EndpointId`/`EndpointAddr`
/// model into an actual application-owned address book.
#[cfg(feature = "bind-overlay")]
#[derive(Clone, Debug)]
pub struct BootstrapDirectory {
    lookup: MemoryLookup,
    peers: Arc<RwLock<Table<String, EndpointAddr>>>,
}

#[cfg(feature = "bind-overlay")]
impl Default for BootstrapDirectory {
    fn default() -> Self {
        Self {
            lookup: MemoryLookup::new(),
            peers: Arc::new(RwLock::new(Table::new())),
        }
    }
}

#[cfg(feature = "bind-overlay")]
impl BootstrapDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endpoints(endpoints: impl IntoIterator<Item = EndpointAddr>) -> Self {
        let dir = Self::new();
        for endpoint in endpoints {
            dir.register(endpoint);
        }
        dir
    }

    fn key_for(peer_id: impl AsRef<[u8]>) -> String {
        to_hex(peer_id.as_ref())
    }

    pub fn lookup(&self) -> MemoryLookup {
        self.lookup.clone()
    }

    pub fn register(&self, endpoint: EndpointAddr) -> Option<EndpointAddr> {
        let key = Self::key_for(endpoint.id.as_bytes());
        let previous = self.peers.read().expect("poisoned").get(&key).cloned();
        self.lookup.add_endpoint_info(endpoint.clone());
        self.peers.write().expect("poisoned").put(key, endpoint);
        previous
    }

    pub fn remove(&self, peer_id: PeerId) -> Option<EndpointAddr> {
        let endpoint_id = EndpointId::from_bytes(&peer_id).ok()?;
        self.lookup.remove_endpoint_info(endpoint_id);
        self.peers
            .write()
            .expect("poisoned")
            .remove(&Self::key_for(peer_id))
    }

    pub fn get(&self, peer_id: PeerId) -> Option<EndpointAddr> {
        self.peers
            .read()
            .expect("poisoned")
            .get(&Self::key_for(peer_id))
            .cloned()
    }

    pub fn all(&self) -> Vec<EndpointAddr> {
        self.peers
            .read()
            .expect("poisoned")
            .iter()
            .map(|(_, endpoint)| endpoint.clone())
            .collect()
    }

    pub fn seed_lookup(&self, endpoint: impl Into<EndpointAddr>) {
        self.register(endpoint.into());
    }
}

impl Default for PeerDirectory {
    fn default() -> Self {
        PeerDirectory {
            peers: Table::new(),
            stale_ttl: Duration::from_secs(300),
            dialkeys: Vec::new(),
            known_keys: Vec::new(),
            gossip_peers: Vec::new(),
        }
    }
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// TTL after which a stale peer entry is dropped on next `discover()`.
    pub fn with_stale_ttl(mut self, ttl: Duration) -> Self {
        self.stale_ttl = ttl;
        self
    }

    /// Add a dialkey to resolve on every `discover()` call.
    pub fn add_dialkey(&mut self, dialkey: impl Into<String>) {
        self.dialkeys.push(dialkey.into());
    }

    /// Add a known pkarr public key to resolve.
    pub fn add_known_key(&mut self, key: [u8; 32]) {
        if !self.known_keys.contains(&key) {
            self.known_keys.push(key);
        }
    }

    /// Register a peer discovered via gossip — its capabilities will be updated on the next
    /// gossip-based discover sweep.
    pub fn saw_gossip_peer(&mut self, peer: PeerId) {
        if !self.gossip_peers.contains(&peer) {
            self.gossip_peers.push(peer);
        }
    }

    /// Directly insert or update a peer — operator-configured, manual bootstrap.
    pub fn add_peer(&mut self, cap: PeerCapability) {
        let key = to_hex(&cap.peer_id);
        self.peers.put(key, cap);
    }

    /// Get a peer's current capabilities, if known and not stale.
    #[must_use]
    pub fn get(&self, peer_id: PeerId) -> Option<&PeerCapability> {
        self.peers.get(&to_hex(&peer_id))
    }

    /// All non-stale peers in the directory.
    #[must_use]
    pub fn all_peers(&self) -> Vec<&PeerCapability> {
        let cutoff = std::time::Instant::now() - self.stale_ttl;
        self.peers
            .iter()
            .filter(|(_, c)| c.last_seen >= cutoff)
            .map(|(_, c)| c)
            .collect()
    }

    /// Peers that have the specified capability string (e.g. "GBM", "CountLM").
    #[must_use]
    pub fn capable_of(&self, capability: &str) -> Vec<&PeerCapability> {
        self.all_peers()
            .into_iter()
            .filter(|c| c.capabilities.iter().any(|cap| cap == capability))
            .collect()
    }

    /// Peers that have a specific model loaded.
    #[must_use]
    pub fn with_model(&self, model_id: &str) -> Vec<&PeerCapability> {
        self.all_peers()
            .into_iter()
            .filter(|c| c.models_loaded.iter().any(|m| m == model_id))
            .collect()
    }

    /// Merge an inbound capability from any discovery source — freshest last_seen wins.
    pub fn merge(&mut self, cap: PeerCapability) {
        let key = to_hex(&cap.peer_id);
        if let Some(existing) = self.peers.get(&key) {
            if cap.last_seen <= existing.last_seen {
                return;
            }
        }
        self.peers.put(key, cap);
    }

    /// Number of non-stale peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.all_peers().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Purge stale peer entries.
    pub fn purge_stale(&mut self) {
        let cutoff = std::time::Instant::now() - self.stale_ttl;
        let stale: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, c)| c.last_seen < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.peers.remove(&k);
        }
    }
}

// ── pkarr advertisement helpers ────────────────────────────────────────────────────────────

/// The mesh model service name advertised via pkarr and mDNS.
pub const MESH_MODEL_SERVICE: &str = "_mesh-model._tcp";

/// Build capability TXT attributes for a pkarr/mDNS advertisement.
pub fn capability_attributes(cap: &PeerCapability) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    attrs.push(("label".to_string(), cap.label.clone()));
    attrs.push(("total_ram".to_string(), cap.total_ram.to_string()));
    attrs.push(("free_ram".to_string(), cap.free_ram.to_string()));
    attrs.push(("total_vram".to_string(), cap.total_vram.to_string()));
    attrs.push(("free_vram".to_string(), cap.free_vram.to_string()));
    attrs.push(("compute".to_string(), cap.compute_kind.to_string()));
    attrs.push(("load".to_string(), format!("{:.3}", cap.load)));
    attrs.push(("models".to_string(), cap.models_loaded.join(",")));
    attrs.push(("caps".to_string(), cap.capabilities.join(",")));
    attrs
}

/// Parse capability TXT attributes back into a PeerCapability — returns None if required
/// fields are missing or unparseable.
pub fn parse_capability_attributes(
    peer_id: PeerId,
    addr: Option<PeerAddr>,
    source: DiscoverySource,
    attrs: &std::collections::HashMap<String, String>,
) -> Option<PeerCapability> {
    let label = attrs.get("label").cloned().unwrap_or_default();
    let total_ram = attrs
        .get("total_ram")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let free_ram = attrs
        .get("free_ram")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let total_vram = attrs
        .get("total_vram")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let free_vram = attrs
        .get("free_vram")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let compute_kind = attrs
        .get("compute")
        .map(|v| ComputeKind::from_str(v))
        .unwrap_or(ComputeKind::Unknown);
    let load = attrs
        .get("load")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let models_loaded = attrs
        .get("models")
        .map(|v| {
            v.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    let capabilities = attrs
        .get("caps")
        .map(|v| {
            v.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    Some(PeerCapability {
        peer_id,
        addr,
        label,
        total_ram,
        free_ram,
        total_vram,
        free_vram,
        compute_kind,
        models_loaded,
        capabilities,
        load,
        source,
        last_seen: std::time::Instant::now(),
    })
}

// ── mDNS ───────────────────────────────────────────────────────────────────────────────────
//
// REMOVED 2026-08-17. The surface was advertise-only and half-built: `discover_mdns` returned
// an empty `Vec` (nothing ever browsed), and `advertise_mdns` had no callers — the three
// sidecar binaries each carried their own private copy of the same eight lines. So the crate
// broadcast announcements that nothing in this workspace listened for.
//
// This module's own note already said why it was safe to drop: "for now, pkarr + dialkey +
// gossip cover cross-network discovery." That remains true, and those three are real.
//
// It cost `simple-mdns` + `simple-dns` + `radix_trie` + `nibble_vec` + `endian-type` + `bitflags`
// + `log` — seven crates, including a THIRD DNS stack beside `hickory_proto` and our own
// `transport::dns`. If local-network discovery is wanted later, `transport::dns` is already the
// codec: mDNS is DNS packets on multicast 224.0.0.251:5353, so it is advertise + browse over a
// UDP socket, not a dependency.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_round_trips_through_attributes() {
        let peer_id = [42u8; 32];
        let cap = PeerCapability {
            peer_id,
            addr: Some(PeerAddr::new(peer_id, "10.0.0.1", 9337)),
            label: "gpu-node-1".to_string(),
            total_ram: 64_000_000_000,
            free_ram: 32_000_000_000,
            total_vram: 24_000_000_000,
            free_vram: 12_000_000_000,
            compute_kind: ComputeKind::Cuda,
            models_loaded: vec!["gbm-v1".to_string(), "countlm-en".to_string()],
            capabilities: vec!["GBM".to_string(), "CountLM".to_string()],
            load: 0.35,
            source: DiscoverySource::Direct,
            last_seen: std::time::Instant::now(),
        };
        let attrs: std::collections::HashMap<String, String> =
            capability_attributes(&cap).into_iter().collect();
        let parsed =
            parse_capability_attributes(peer_id, cap.addr.clone(), DiscoverySource::Direct, &attrs)
                .unwrap();
        assert_eq!(parsed.label, cap.label);
        assert_eq!(parsed.total_vram, cap.total_vram);
        assert_eq!(parsed.free_vram, cap.free_vram);
        assert_eq!(parsed.models_loaded, cap.models_loaded);
        assert_eq!(parsed.capabilities, cap.capabilities);
        assert!((parsed.load - cap.load).abs() < 0.001);
    }

    #[test]
    fn directory_merge_last_seen_wins() {
        let peer_id = [1u8; 32];
        let old = PeerCapability {
            peer_id,
            addr: None,
            label: "old".into(),
            total_ram: 0,
            free_ram: 0,
            total_vram: 0,
            free_vram: 0,
            compute_kind: ComputeKind::Cpu,
            models_loaded: vec![],
            capabilities: vec![],
            load: 0.0,
            source: DiscoverySource::Gossip,
            last_seen: std::time::Instant::now() - Duration::from_secs(60),
        };
        let new = PeerCapability {
            peer_id,
            addr: None,
            label: "new".into(),
            total_ram: 0,
            free_ram: 0,
            total_vram: 0,
            free_vram: 0,
            compute_kind: ComputeKind::Cpu,
            models_loaded: vec!["gbm-v1".into()],
            capabilities: vec!["GBM".into()],
            load: 0.5,
            source: DiscoverySource::Pkarr,
            last_seen: std::time::Instant::now(),
        };

        let mut dir = PeerDirectory::new();
        dir.merge(old);
        dir.merge(new);
        let got = dir.get(peer_id).unwrap();
        assert_eq!(got.label, "new");
        assert_eq!(got.source, DiscoverySource::Pkarr);
        assert_eq!(got.models_loaded, vec!["gbm-v1"]);
    }

    #[test]
    fn directory_does_not_merge_older_entry() {
        let peer_id = [1u8; 32];
        let now = PeerCapability {
            peer_id,
            addr: None,
            label: "now".into(),
            total_ram: 0,
            free_ram: 0,
            total_vram: 0,
            free_vram: 0,
            compute_kind: ComputeKind::Cpu,
            models_loaded: vec!["gbm-v1".into()],
            capabilities: vec!["GBM".into()],
            load: 0.5,
            source: DiscoverySource::Pkarr,
            last_seen: std::time::Instant::now(),
        };
        let older = PeerCapability {
            peer_id,
            addr: None,
            label: "older".into(),
            total_ram: 0,
            free_ram: 0,
            total_vram: 0,
            free_vram: 0,
            compute_kind: ComputeKind::Cpu,
            models_loaded: vec![],
            capabilities: vec![],
            load: 0.0,
            source: DiscoverySource::Mdns,
            last_seen: std::time::Instant::now() - Duration::from_secs(30),
        };

        let mut dir = PeerDirectory::new();
        dir.merge(now);
        dir.merge(older);
        assert_eq!(dir.get(peer_id).unwrap().label, "now");
    }

    #[test]
    fn capable_of_filters_by_capability_string() {
        let mut dir = PeerDirectory::new();
        dir.add_peer(PeerCapability {
            peer_id: [1u8; 32],
            addr: None,
            label: "a".into(),
            total_ram: 0,
            free_ram: 0,
            total_vram: 0,
            free_vram: 0,
            compute_kind: ComputeKind::Cpu,
            models_loaded: vec![],
            capabilities: vec!["GBM".into()],
            load: 0.0,
            source: DiscoverySource::Direct,
            last_seen: std::time::Instant::now(),
        });
        dir.add_peer(PeerCapability {
            peer_id: [2u8; 32],
            addr: None,
            label: "b".into(),
            total_ram: 0,
            free_ram: 0,
            total_vram: 0,
            free_vram: 0,
            compute_kind: ComputeKind::Cpu,
            models_loaded: vec![],
            capabilities: vec!["CountLM".into()],
            load: 0.0,
            source: DiscoverySource::Direct,
            last_seen: std::time::Instant::now(),
        });
        assert_eq!(dir.capable_of("GBM").len(), 1);
        assert_eq!(dir.capable_of("CountLM").len(), 1);
        assert_eq!(dir.capable_of("autofold").len(), 0);
    }

    #[cfg(feature = "bind-overlay")]
    #[test]
    fn bootstrap_directory_registers_and_removes_endpoint_info() {
        use iroh::{SecretKey, TransportAddr};

        let identity = SecretKey::from_bytes(&[9u8; 32]);
        let endpoint_id = identity.public();
        let endpoint = EndpointAddr::from_parts(
            endpoint_id,
            [TransportAddr::Ip(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                9337,
            )))],
        );

        let bootstrap = BootstrapDirectory::new();
        bootstrap.register(endpoint.clone());

        let lookup = bootstrap.lookup();
        assert!(lookup.get_endpoint_info(endpoint_id).is_some());
        assert_eq!(
            bootstrap.get(*endpoint_id.as_bytes()),
            Some(endpoint.clone())
        );

        let removed = bootstrap
            .remove(*endpoint_id.as_bytes())
            .expect("removed endpoint");
        assert_eq!(removed, endpoint);
        assert!(lookup.get_endpoint_info(endpoint_id).is_none());
    }
}
