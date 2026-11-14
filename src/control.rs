//! Overlay control surface for the hosting runtime.
//!
//! This is the small API layer the runtime can call to publish overlay identity, attach or
//! detach peers, and hand `iroh` a live address book for bootstrapping. The actual transport
//! stays in `bindings::overlay`; this module is the control-plane wrapper around the same
//! endpoint/address model.
//!
//! The important part is tenancy: every registry is partitioned by tenant id, so no tenant can
//! see or mutate another tenant's overlay state through this surface.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use apeiron::map::hashtrinity::crypto::to_hex;
use apeiron::map::hashtrinity::Table;
use iroh::{EndpointAddr, EndpointId};

use super::discovery::{BootstrapDirectory, DiscoverySource, PeerCapability, PeerDirectory};
use super::PeerId;

pub type Result<T> = std::result::Result<T, crate::Error>;

fn endpoint_id_for(peer_id: PeerId) -> Result<EndpointId> {
    EndpointId::from_bytes(&peer_id)
        .map_err(|e| crate::Error::Overlay(format!("invalid peer id: {e}")))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayPeerState {
    Attached,
    Detached,
}

#[derive(Clone, Debug)]
pub struct OverlayPeerRecord {
    pub capability: PeerCapability,
    pub endpoint: EndpointAddr,
    pub state: OverlayPeerState,
    pub published_at: Instant,
}

#[derive(Clone, Debug)]
struct TenantOverlayState {
    bootstrap: BootstrapDirectory,
    directory: PeerDirectory,
    records: Table<String, OverlayPeerRecord>,
}

impl Default for TenantOverlayState {
    fn default() -> Self {
        Self {
            bootstrap: BootstrapDirectory::new(),
            directory: PeerDirectory::new(),
            records: Table::new(),
        }
    }
}

/// A runtime-facing overlay control surface.
///
/// Tenants are isolated by partitioning their overlay state into independent per-tenant records.
#[derive(Clone, Debug)]
pub struct OverlayControlPlane {
    tenants: Arc<RwLock<Table<String, TenantOverlayState>>>,
}

impl Default for OverlayControlPlane {
    fn default() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(Table::new())),
        }
    }
}

impl OverlayControlPlane {
    pub fn new() -> Self {
        Self::default()
    }

    fn tenant_state(&self, tenant_id: &str) -> TenantOverlayState {
        let mut tenants = self.tenants.write().expect("poisoned");
        tenants
            .get(&tenant_id.to_string())
            .cloned()
            .unwrap_or_else(|| {
                let state = TenantOverlayState::default();
                tenants.put(tenant_id.to_string(), state.clone());
                state
            })
    }

    fn update_tenant_state(
        &self,
        tenant_id: &str,
        f: impl FnOnce(&mut TenantOverlayState) -> Result<()>,
    ) -> Result<()> {
        let mut tenants = self.tenants.write().expect("poisoned");
        let state = tenants
            .get(&tenant_id.to_string())
            .cloned()
            .unwrap_or_default();
        let mut state = state;
        f(&mut state)?;
        tenants.put(tenant_id.to_string(), state);
        Ok(())
    }

    pub fn tenant(&self, tenant_id: impl Into<String>) -> OverlayTenantControl {
        OverlayTenantControl {
            tenant_id: tenant_id.into(),
            plane: self.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OverlayTenantControl {
    tenant_id: String,
    plane: OverlayControlPlane,
}

impl OverlayTenantControl {
    fn state(&self) -> TenantOverlayState {
        self.plane.tenant_state(&self.tenant_id)
    }

    pub fn bootstrap(&self) -> BootstrapDirectory {
        self.state().bootstrap
    }

    pub fn address_lookup(&self) -> iroh::address_lookup::memory::MemoryLookup {
        self.state().bootstrap.lookup()
    }

    pub fn snapshot(&self) -> Vec<OverlayPeerRecord> {
        self.state()
            .records
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }

    pub fn known_peers(&self) -> Vec<PeerCapability> {
        self.state()
            .directory
            .all_peers()
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn get(&self, peer_id: PeerId) -> Option<OverlayPeerRecord> {
        self.state().records.get(&to_hex(&peer_id)).cloned()
    }

    pub fn publish_peer(
        &self,
        capability: PeerCapability,
        endpoint: EndpointAddr,
    ) -> Result<OverlayPeerRecord> {
        self.attach_peer(capability, endpoint)
    }

    pub fn attach_peer(
        &self,
        capability: PeerCapability,
        endpoint: EndpointAddr,
    ) -> Result<OverlayPeerRecord> {
        if capability.peer_id != *endpoint.id.as_bytes() {
            return Err(crate::Error::Overlay(
                "peer id mismatch between capability and endpoint address".into(),
            ));
        }

        let record = OverlayPeerRecord {
            capability: capability.clone(),
            endpoint: endpoint.clone(),
            state: OverlayPeerState::Attached,
            published_at: Instant::now(),
        };

        self.plane.update_tenant_state(&self.tenant_id, |state| {
            state.bootstrap.register(endpoint);
            state.directory.merge(capability);
            state
                .records
                .put(to_hex(&record.capability.peer_id), record.clone());
            Ok(())
        })?;

        Ok(record)
    }

    pub fn detach_peer(&self, peer_id: PeerId) -> Result<Option<OverlayPeerRecord>> {
        let endpoint_id = endpoint_id_for(peer_id)?;
        let mut removed = None;

        self.plane.update_tenant_state(&self.tenant_id, |state| {
            state.bootstrap.remove(peer_id);
            removed = state.records.remove(&to_hex(&peer_id));
            state.bootstrap.lookup().remove_endpoint_info(endpoint_id);
            if let Some(record) = removed.as_mut() {
                record.state = OverlayPeerState::Detached;
            }
            Ok(())
        })?;

        Ok(removed)
    }

    pub fn attach_endpoint(&self, endpoint: EndpointAddr) -> Result<OverlayPeerRecord> {
        let peer_id = *endpoint.id.as_bytes();
        let capability = PeerCapability {
            peer_id,
            addr: None,
            label: String::new(),
            total_ram: 0,
            free_ram: 0,
            total_vram: 0,
            free_vram: 0,
            compute_kind: super::discovery::ComputeKind::Unknown,
            models_loaded: Vec::new(),
            capabilities: Vec::new(),
            load: 0.0,
            source: DiscoverySource::Direct,
            last_seen: Instant::now(),
        };
        self.attach_peer(capability, endpoint)
    }
}

#[cfg(all(test, feature = "bind-overlay"))]
mod tests {
    use super::*;
    use iroh::{SecretKey, TransportAddr};

    fn endpoint_addr(port: u16) -> EndpointAddr {
        let identity = SecretKey::from_bytes(&[7u8; 32]);
        let id = identity.public();
        EndpointAddr::from_parts(
            id,
            [TransportAddr::Ip(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                port,
            )))],
        )
    }

    #[test]
    fn publish_and_detach_update_bootstrap_and_snapshot() {
        let control = OverlayControlPlane::new();
        let tenant = control.tenant("tenant-a");
        let endpoint = endpoint_addr(9337);
        let peer_id = *endpoint.id.as_bytes();
        let capability = PeerCapability {
            peer_id,
            addr: None,
            label: "edge-1".into(),
            total_ram: 16,
            free_ram: 8,
            total_vram: 0,
            free_vram: 0,
            compute_kind: super::super::discovery::ComputeKind::Cpu,
            models_loaded: vec!["tas-edge".into()],
            capabilities: vec!["overlay".into()],
            load: 0.25,
            source: DiscoverySource::Direct,
            last_seen: Instant::now(),
        };

        let record = tenant.publish_peer(capability, endpoint.clone()).unwrap();
        assert_eq!(record.endpoint.id, endpoint.id);
        assert_eq!(tenant.snapshot().len(), 1);
        assert!(tenant
            .bootstrap()
            .lookup()
            .get_endpoint_info(endpoint.id)
            .is_some());
        assert_eq!(tenant.known_peers().len(), 1);

        let detached = tenant.detach_peer(peer_id).unwrap().expect("record");
        assert_eq!(detached.state, OverlayPeerState::Detached);
        assert!(tenant.snapshot().is_empty());
        assert!(tenant
            .bootstrap()
            .lookup()
            .get_endpoint_info(endpoint.id)
            .is_none());
    }

    #[test]
    fn tenant_state_is_partitioned() {
        let control = OverlayControlPlane::new();
        let tenant_a = control.tenant("tenant-a");
        let tenant_b = control.tenant("tenant-b");

        let endpoint = endpoint_addr(9338);
        let peer_id = *endpoint.id.as_bytes();
        let capability = PeerCapability {
            peer_id,
            addr: None,
            label: "edge-tenant-a".into(),
            total_ram: 8,
            free_ram: 4,
            total_vram: 0,
            free_vram: 0,
            compute_kind: super::super::discovery::ComputeKind::Cpu,
            models_loaded: vec![],
            capabilities: vec!["overlay".into()],
            load: 0.1,
            source: DiscoverySource::Direct,
            last_seen: Instant::now(),
        };

        tenant_a.publish_peer(capability, endpoint.clone()).unwrap();

        assert_eq!(tenant_a.snapshot().len(), 1);
        assert!(tenant_b.snapshot().is_empty());
        assert!(tenant_b
            .bootstrap()
            .lookup()
            .get_endpoint_info(endpoint.id)
            .is_none());
    }
}
