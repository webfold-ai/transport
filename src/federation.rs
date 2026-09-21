//! # federation — one dialkey provisions a whole group of services.
//!
//! The provisioning-group layer over `transport::dialkey`: a server publishes its services
//! (message queue, RESP db, cache, S3, vector, lorelake, logging, …) under ONE dialkey — one
//! pkarr packet, one SRV record per service with TXT metadata (region, buckets, endpoint) —
//! and a client mounts that dialkey to get typed handles for exactly the services it needs.
//!
//! ```
//! // publish side — one dialkey advertises the whole stack
//! let group = FederationGroup::new("knee-cluster")
//!     .s3(3905, "garage", &["rsna", "models", "submissions"])
//!     .mqtt(1883)
//!     .resp(6379)
//!     .meili(7700)
//!     .lorelake(4433, "/v1/lake")
//!     .logging(4318);
//! group.publish(&pkarr, my_ip).await?;
//!
//! // mount side — the same dialkey resolves typed handles on any other node
//! let mount = Federation::mount(&pkarr, "knee-cluster", &["s3", "mqtt"]).await?;
//! let s3_endpoint = mount.endpoint("s3")?;          // 10.0.63.12:3905
//! let buckets = mount.buckets("s3")?;               // ["rsna", "models", "submissions"]
//! let queue = mount.get("mqtt");                    // DialkeyService -> MqttClient::connect
//! ```
//!
//! Service names follow the dialkey convention (`<service>.<dialkey-peer-key>`): `s3`, `mqtt`,
//! `queue` (alias), `resp`, `cache`, `meili`/`vector` (alias), `lorelake`, `logging`.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the service set (which services a dialkey advertises — presence)
//! - **B/Map** = the service map (service name → port/metadata — replace on re-publish)
//! - **B/U** = the peer directory (dialkey → services — the flow of a mount)
//! - **self** = the group (the mount turned on itself — one dialkey, many endpoints)

use crate::dialkey::{self, DialkeyService, DialkeyServiceInfo};
use crate::{PeerAddr, PeerId};
use pkarr::dns::rdata::RData;
use pkarr::Client;
use std::collections::HashMap;
use std::net::IpAddr;

/// Canonical service names.
pub mod svc {
    pub const S3: &str = "s3";
    pub const MQTT: &str = "mqtt";
    pub const QUEUE: &str = "queue";
    pub const RESP: &str = "resp";
    pub const CACHE: &str = "cache";
    pub const VECTOR: &str = "vector";
    pub const MEILI: &str = "meili";
    pub const LORELAKE: &str = "lorelake";
    pub const LOGGING: &str = "logging";
    /// An OpenAI-compatible completion endpoint (`/v1/chat/completions`, `/v1/models`).
    ///
    /// The same name whether the backend is `bedrock::serve::server` (native, the `Engine` over
    /// `modelfold`) or a llama.cpp `llama-server` — a mounting client dials an endpoint, not an
    /// implementation. `meta::BACKEND` says which, for a client that genuinely needs to know.
    pub const INFERENCE: &str = "inference";
}

/// Metadata keys the mount understands.
pub mod meta {
    /// `bucket=<name>` — one per bucket the group's S3 mounts. The "whatever buckets you need"
    /// list a provisioning group carries.
    pub const BUCKET: &str = "bucket";
    /// `region=<name>` — the S3 region the backend expects.
    pub const REGION: &str = "region";
    /// `endpoint=<path>` — an HTTP path prefix for services mounted under a subpath.
    pub const ENDPOINT: &str = "endpoint";
    /// `model=<id>` — the served model's identifier, as `/v1/models` reports it.
    pub const MODEL: &str = "model";
    /// `quant=<name>` — the weight format actually loaded (`Q4_K_M`, `bf16`, …). A router that
    /// picks between two nodes serving the same model needs this; the model id alone hides it.
    pub const QUANT: &str = "quant";
    /// `context=<tokens>` — the context window the endpoint was started with, not the model's
    /// theoretical maximum. A caller that trusts the config instead of the launch flag will
    /// overflow a server started with a smaller window.
    pub const CONTEXT: &str = "context";
    /// `backend=<name>` — `servefold`, `llama.cpp`, … See [`svc::INFERENCE`].
    pub const BACKEND: &str = "backend";
}

/// Build one service advertisement. `port` is the port the service listens on; `metadata`
/// lands in the TXT record and is what a mounting client reads back.
pub fn service(name: &str, port: u16, metadata: &[(String, String)]) -> DialkeyServiceInfo {
    let mut map = HashMap::new();
    for (k, v) in metadata {
        map.insert(k.clone(), v.clone());
    }
    DialkeyServiceInfo {
        service: name.to_string(),
        port,
        metadata: map,
    }
}

/// The publish side — a named group of services advertised under one dialkey.
#[derive(Clone, Debug)]
pub struct FederationGroup {
    dialkey: String,
    services: Vec<DialkeyServiceInfo>,
}

impl FederationGroup {
    /// A group owned by `dialkey` (any shared secret; every member derives the same PeerId
    /// and pkarr signing key from it).
    pub fn new(dialkey: &str) -> Self {
        FederationGroup {
            dialkey: dialkey.to_string(),
            services: Vec::new(),
        }
    }

    /// Attach an arbitrary service advertisement.
    pub fn service(mut self, name: &str, port: u16, metadata: &[(String, String)]) -> Self {
        self.services.push(service(name, port, metadata));
        self
    }

    /// The S3 gateway service. `buckets` is the "what do you want mounted" list — each becomes
    /// a `bucket=` TXT entry a mounting client reads back via `Mount::buckets`.
    pub fn s3(self, port: u16, region: &str, buckets: &[&str]) -> Self {
        let mut meta: Vec<(String, String)> =
            vec![(meta::REGION.to_string(), region.to_string())];
        for b in buckets {
            meta.push((meta::BUCKET.to_string(), b.to_string()));
        }
        self.service(svc::S3, port, &meta)
    }

    /// The message queue service (a `sangdb::mqtt` listener).
    pub fn mqtt(self, port: u16) -> Self {
        self.service(svc::MQTT, port, &[])
    }

    /// `queue` — alias of `mqtt`, for consumers that think of it as a queue.
    pub fn queue(self, port: u16) -> Self {
        self.service(
            svc::QUEUE,
            port,
            &[(meta::ENDPOINT.to_string(), svc::MQTT.to_string())],
        )
    }

    /// The RESP (Redis-compatible, `sangdb::resp`) database service.
    pub fn resp(self, port: u16) -> Self {
        self.service(svc::RESP, port, &[])
    }

    /// The cache service (`native_lib::cache` face, pingora-cache shaped).
    pub fn cache(self, port: u16) -> Self {
        self.service(svc::CACHE, port, &[])
    }

    /// The vector service (`sangdb::meili` / LSH face).
    pub fn vector(self, port: u16) -> Self {
        self.service(svc::VECTOR, port, &[])
    }

    /// `meili` — alias of `vector`, for consumers that expect the meili face by name.
    pub fn meili(self, port: u16) -> Self {
        self.service(
            svc::MEILI,
            port,
            &[(meta::ENDPOINT.to_string(), svc::VECTOR.to_string())],
        )
    }

    /// The lorelake dataset/model versioning service (content-addressed chunks).
    pub fn lorelake(self, port: u16, endpoint: &str) -> Self {
        self.service(
            svc::LORELAKE,
            port,
            &[(meta::ENDPOINT.to_string(), endpoint.to_string())],
        )
    }

    /// The inference service — an OpenAI-compatible completion endpoint.
    ///
    /// `model` is the id `/v1/models` reports, `quant` the weight format actually loaded,
    /// `context` the window the server was STARTED with (not the config's maximum), and
    /// `backend` the implementation. All four ride in TXT so a mounting client can route on them
    /// without a second round-trip to the endpoint itself.
    pub fn inference(
        self,
        port: u16,
        model: &str,
        quant: &str,
        context: u32,
        backend: &str,
    ) -> Self {
        self.service(
            svc::INFERENCE,
            port,
            &[
                (meta::MODEL.to_string(), model.to_string()),
                (meta::QUANT.to_string(), quant.to_string()),
                (meta::CONTEXT.to_string(), context.to_string()),
                (meta::BACKEND.to_string(), backend.to_string()),
            ],
        )
    }

    /// The OTLP logging/tracing ingest service.
    pub fn logging(self, port: u16) -> Self {
        self.service(svc::LOGGING, port, &[])
    }

    /// Publish the whole group under the dialkey — `transport::dialkey::publish` does the one
    /// packet, one SRV record per service, TXT metadata per record. `ip` is this host's
    /// address; re-publishing replaces the A/AAAA record with the current one.
    pub async fn publish(
        &self,
        client: &Client,
        ip: IpAddr,
    ) -> Result<(), pkarr::errors::PublishError> {
        dialkey::publish(client, &self.dialkey, ip, &self.services).await
    }

    pub fn dialkey(&self) -> &str {
        &self.dialkey
    }

    pub fn services(&self) -> &[DialkeyServiceInfo] {
        &self.services
    }
}

/// The mount side — a resolved provisioning group. Holds every service the dialkey advertises,
/// so one pkarr lookup yields typed access to the whole stack.
#[derive(Clone, Debug)]
pub struct Mount {
    dialkey: String,
    peer_id: PeerId,
    peer_addr: PeerAddr,
    /// Service name → resolved endpoint (one packet, all services).
    services: HashMap<String, DialkeyService>,
}

impl Mount {
    /// Resolve `dialkey` from pkarr: fetch the packet once, walk every SRV/TXT pair.
    pub async fn mount(client: &Client, dialkey: &str, want: &[&str]) -> Option<Mount> {
        let keypair = dialkey::keypair(dialkey);
        let packet = client
            .resolve(&keypair.public_key(), pkarr::ResolvePolicy::CacheFirst)
            .await
            .ok()?;
        let public_key_str = keypair.public_key().to_string();

        // The one address record in the packet is the publisher's (the apex A/AAAA).
        let ip = packet.all_resource_records().find_map(|r| match &r.rdata {
            RData::A(a) => Some(IpAddr::V4(a.address.into())),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.address.into())),
            _ => None,
        })?;

        let mut services: HashMap<String, DialkeyService> = HashMap::new();
        for service in want {
            let service_name_str = format!("{service}.{public_key_str}");
            let mut port = None;
            let mut metadata = HashMap::new();
            for record in packet.all_resource_records() {
                if record.name.to_string() != service_name_str {
                    continue;
                }
                match &record.rdata {
                    RData::SRV(srv) => port = Some(srv.port),
                    RData::TXT(txt) => {
                        for (k, v) in txt.attributes() {
                            if let Some(v) = v {
                                metadata.insert(k.to_string(), v.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            let port = port?;
            services.insert(
                service.to_string(),
                DialkeyService {
                    peer_addr: PeerAddr::new(dialkey::peer_id(dialkey), ip.to_string(), port),
                    service: service.to_string(),
                    metadata,
                },
            );
        }

        Some(Mount {
            dialkey: dialkey.to_string(),
            peer_id: dialkey::peer_id(dialkey),
            peer_addr: PeerAddr::new(dialkey::peer_id(dialkey), ip.to_string(), 0),
            services,
        })
    }

    /// The dialkey this mount resolved.
    pub fn dialkey(&self) -> &str {
        &self.dialkey
    }

    /// The group's derived peer identity.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The host every service advertised (all services share the publisher's address).
    pub fn peer_addr(&self) -> &PeerAddr {
        &self.peer_addr
    }

    /// The resolved service, if the dialkey advertises it.
    pub fn get(&self, name: &str) -> Option<&DialkeyService> {
        self.services.get(name)
    }

    /// Every service this dialkey advertised (and we asked for).
    pub fn services(&self) -> impl Iterator<Item = &DialkeyService> {
        self.services.values()
    }

    /// `host:port` of a service — the endpoint string for a client (`syncfold s3`,
    /// `MqttClient`, RESP client, …). The peer's IP is whatever the publisher's A/AAAA says.
    pub fn endpoint(&self, name: &str) -> Option<String> {
        let s = self.services.get(name)?;
        Some(format!("{}:{}", s.peer_addr.host, s.peer_addr.port))
    }

    /// The `bucket=` metadata entries of a service — the buckets a provisioning group mounts.
    pub fn buckets(&self, name: &str) -> Vec<String> {
        self.services
            .get(name)
            .map(|s| {
                s.metadata
                    .iter()
                    .filter(|(k, _)| k.as_str() == meta::BUCKET)
                    .map(|(_, v)| v.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// One metadata value of a service, if present.
    pub fn meta(&self, name: &str, key: &str) -> Option<&str> {
        self.services
            .get(name)?
            .metadata
            .get(key)
            .map(String::as_str)
    }

    /// The inference endpoint as a base URL a client can POST to directly.
    ///
    /// `http://` because a dialkey-resolved peer is reached over the group's own transport; a
    /// caller terminating TLS elsewhere should build the URL from [`Self::endpoint`] instead of
    /// string-editing this one.
    pub fn inference_url(&self) -> Option<String> {
        Some(format!("http://{}/v1", self.endpoint(svc::INFERENCE)?))
    }

    /// Everything a router needs to choose this inference node:
    /// `(base url, model, quant, context tokens, backend)`.
    ///
    /// `context` is `None` when the publisher advertised a value that is not a number, rather
    /// than silently defaulting — a wrong window is an overflow, and a guessed one is worse than
    /// an absent one.
    pub fn inference(&self) -> Option<(String, String, String, Option<u32>, String)> {
        let url = self.inference_url()?;
        let model = self
            .meta(svc::INFERENCE, meta::MODEL)
            .unwrap_or_default()
            .to_string();
        let quant = self
            .meta(svc::INFERENCE, meta::QUANT)
            .unwrap_or_default()
            .to_string();
        let context = self
            .meta(svc::INFERENCE, meta::CONTEXT)
            .and_then(|c| c.parse::<u32>().ok());
        let backend = self
            .meta(svc::INFERENCE, meta::BACKEND)
            .unwrap_or_default()
            .to_string();
        Some((url, model, quant, context, backend))
    }

    /// Convenience: the S3 service's endpoint + buckets in one call.
    pub fn s3(&self) -> Option<(String, Vec<String>)> {
        let endpoint = self.endpoint(svc::S3)?;
        let buckets = self.buckets(svc::S3);
        Some((endpoint, buckets))
    }
}

/// The federation face — mount a dialkey, publish a group. One entry point, both sides.
pub struct Federation;

impl Federation {
    /// Publish a group under its dialkey.
    pub async fn publish(
        group: &FederationGroup,
        client: &Client,
        ip: IpAddr,
    ) -> Result<(), pkarr::errors::PublishError> {
        group.publish(client, ip).await
    }

    /// Mount a dialkey, asking for exactly the services needed.
    pub async fn mount(client: &Client, dialkey: &str, want: &[&str]) -> Option<Mount> {
        Mount::mount(client, dialkey, want).await
    }
}

#[cfg(test)]
mod inference_face_tests {
    use super::*;

    #[test]
    fn an_inference_group_advertises_what_a_router_needs() {
        let g = FederationGroup::new("nervous-system")
            .inference(8081, "LFM2.5-8B-A1B", "Q4_K_M", 32768, "llama.cpp")
            .lorelake(4433, "/v1/lake");
        let svc = g
            .services()
            .iter()
            .find(|s| s.service == svc::INFERENCE)
            .expect("the inference service is advertised");
        assert_eq!(svc.port, 8081);
        assert_eq!(
            svc.metadata.get(meta::MODEL).map(String::as_str),
            Some("LFM2.5-8B-A1B")
        );
        assert_eq!(
            svc.metadata.get(meta::QUANT).map(String::as_str),
            Some("Q4_K_M")
        );
        assert_eq!(
            svc.metadata.get(meta::CONTEXT).map(String::as_str),
            Some("32768")
        );
        assert_eq!(
            svc.metadata.get(meta::BACKEND).map(String::as_str),
            Some("llama.cpp")
        );
    }

    #[test]
    fn quant_is_carried_because_the_model_id_alone_hides_it() {
        // Two nodes, same model, different weights. A router that reads only `model` cannot
        // tell them apart, which is the reason `quant` is a first-class metadata key.
        let a = FederationGroup::new("node-a").inference(
            8081,
            "LFM2.5-8B-A1B",
            "Q4_K_M",
            32768,
            "llama.cpp",
        );
        let b = FederationGroup::new("node-b").inference(
            8081,
            "LFM2.5-8B-A1B",
            "bf16",
            32768,
            "servefold",
        );
        let q = |g: &FederationGroup| {
            g.services()
                .iter()
                .find(|s| s.service == svc::INFERENCE)
                .and_then(|s| s.metadata.get(meta::QUANT).cloned())
                .unwrap_or_default()
        };
        assert_ne!(q(&a), q(&b));
    }

    #[test]
    fn one_dialkey_carries_inference_beside_every_other_service() {
        let g = FederationGroup::new("nervous-system")
            .inference(8081, "LFM2.5-8B-A1B", "Q4_K_M", 32768, "llama.cpp")
            .lorelake(4433, "/v1/lake")
            .s3(3905, "garage", &["models"]);
        let names: Vec<&str> = g.services().iter().map(|s| s.service.as_str()).collect();
        assert!(names.contains(&svc::INFERENCE));
        assert!(names.contains(&svc::LORELAKE));
        assert!(names.contains(&svc::S3));
    }
}
