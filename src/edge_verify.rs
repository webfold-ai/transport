//! Proof-of-control checks for BYO custom hostnames — the outbound half of `transport::edge`.
//!
//! `edge_dns` is the authority we *serve*; this is the recursive client we *ask*. Before the
//! edge will serve `app.acme.com.au` it must observe, in the customer's own DNS, either the
//! challenge TXT or a CNAME pointing at the managed hostname we handed them
//! ([`super::edge::Challenge`]).
//!
//! ## Why this must not consult our own authority
//!
//! The whole point of the check is that the answer comes from the *customer's* nameservers,
//! reached the way the public internet reaches them. Resolving through a split-horizon view,
//! a local hosts file, or our own [`super::edge_dns::ZoneAuthority`] would let a name we
//! already control satisfy a challenge about a name we do not — which is the entire
//! vulnerability class this check exists to close. [`HickoryProbe::public`] therefore builds
//! a resolver from an explicit public recursive configuration rather than the host's
//! `/etc/resolv.conf`, and [`HickoryProbe::from_system`] exists only for operators who
//! deliberately run their own trusted recursor.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the observed record set (what the customer's DNS actually publishes)
//! - **B/Map** = the sweep result (hostname → resulting state)
//! - **B/U** = the probe counter, kept by the registry
//! - **self** = the challenge (a DNS name proving control of a DNS name)

use super::edge::{Challenge, EdgeRegistry, HostnameState};
use super::BoxFuture;

/// What one probe saw in the customer's DNS for a challenge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// TXT strings found at `challenge.txt_name`.
    pub txt: Vec<String>,
    /// CNAME targets found at `challenge.fqdn`.
    pub cname: Vec<String>,
}

impl Observed {
    /// Whether what we saw satisfies `challenge` by either accepted proof.
    #[must_use]
    pub fn proves(&self, challenge: &Challenge) -> bool {
        challenge.satisfied_by_txt(&self.txt) || challenge.satisfied_by_cname(&self.cname)
    }
}

/// The DNS lookups a validation sweep needs. A trait so the sweep is testable without a
/// network — the alternative is a validation path only ever exercised in production.
pub trait DnsProbe: Send + Sync {
    /// Look up the challenge's TXT name and the hostname's CNAME, in the customer's DNS.
    fn observe<'a>(&'a self, challenge: &'a Challenge) -> BoxFuture<'a, Observed>;
}

/// Run one validation pass over every hostname awaiting proof.
///
/// Returns each hostname's resulting state so a caller can log or notify. `max_probes` caps
/// how many failed checks a hostname absorbs before it is failed outright — see
/// [`EdgeRegistry::record_probe`].
pub async fn sweep(
    probe: &dyn DnsProbe,
    registry: &mut EdgeRegistry,
    max_probes: i64,
) -> Vec<(String, HostnameState)> {
    let pending = registry.pending_validation();
    let mut results = Vec::with_capacity(pending.len());
    for record in pending {
        let Some(challenge) = record.challenge.as_ref() else {
            continue;
        };
        let observed = probe.observe(challenge).await;
        let proven = observed.proves(challenge);
        if let Ok(state) = registry.record_probe(&record.fqdn, proven, max_probes) {
            results.push((record.fqdn, state));
        }
    }
    results
}

// ── The hickory-backed probe ──────────────────────────────────────────────────────────────

#[cfg(feature = "bind-edge-dns")]
mod hickory_probe {
    use super::{Challenge, DnsProbe, Observed};
    use crate::transport::BoxFuture;

    use hickory_proto::rr::{RData, RecordType};
    use hickory_resolver::config::{ResolverConfig, CLOUDFLARE, GOOGLE};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::{Resolver, TokioResolver};

    /// A real recursive-resolver probe.
    pub struct HickoryProbe {
        resolver: TokioResolver,
    }

    impl HickoryProbe {
        /// A probe that resolves through public recursive resolvers, deliberately ignoring
        /// this host's own resolver configuration. See the module doc: a validation check
        /// that can be satisfied through our own split-horizon view is not a check.
        ///
        /// Two independent operators (Cloudflare and Google), because a single one being
        /// unreachable would fail every pending validation at once and look like every
        /// customer suddenly misconfiguring their DNS.
        pub fn public() -> Result<Self, crate::Error> {
            let mut config = ResolverConfig::udp_and_tcp(&CLOUDFLARE);
            for name_server in ResolverConfig::udp_and_tcp(&GOOGLE).into_parts().2 {
                config.add_name_server(name_server);
            }
            let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
                .build()
                .map_err(|e| crate::Error::Overlay(format!("resolver init: {e}")))?;
            Ok(HickoryProbe { resolver })
        }

        /// A probe using the host's `/etc/resolv.conf`. Only correct where the operator runs
        /// a trusted recursor with no split-horizon view of customer domains.
        pub fn from_system() -> Result<Self, crate::Error> {
            let resolver = Resolver::builder_tokio()
                .map_err(|e| crate::Error::Overlay(format!("resolver init: {e}")))?
                .build()
                .map_err(|e| crate::Error::Overlay(format!("resolver build: {e}")))?;
            Ok(HickoryProbe { resolver })
        }
    }

    impl DnsProbe for HickoryProbe {
        fn observe<'a>(&'a self, challenge: &'a Challenge) -> BoxFuture<'a, Observed> {
            Box::pin(async move {
                let mut observed = Observed::default();

                // TXT at `_twn-challenge.<fqdn>`. A TXT record is a SEQUENCE of <=255-byte
                // strings on the wire; a value longer than that arrives split, so the
                // segments are joined before comparison rather than compared one by one.
                if let Ok(lookup) = self
                    .resolver
                    .lookup(format!("{}.", challenge.txt_name), RecordType::TXT)
                    .await
                {
                    for record in lookup.answers() {
                        if let RData::TXT(txt) = &record.data {
                            let joined: String = txt
                                .txt_data
                                .iter()
                                .map(|seg| String::from_utf8_lossy(seg).into_owned())
                                .collect();
                            observed.txt.push(joined);
                        }
                    }
                }

                // CNAME at the hostname itself. Asked for explicitly (rather than following
                // an address lookup) so we see the alias, not what it eventually resolves to.
                if let Ok(lookup) = self
                    .resolver
                    .lookup(format!("{}.", challenge.fqdn), RecordType::CNAME)
                    .await
                {
                    for record in lookup.answers() {
                        if let RData::CNAME(cname) = &record.data {
                            observed.cname.push(cname.0.to_ascii());
                        }
                    }
                }

                observed
            })
        }
    }
}

#[cfg(feature = "bind-edge-dns")]
pub use hickory_probe::HickoryProbe;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::edge::{HostnameState, Route};
    use hashtrinity::Table;

    /// A probe answering from a fixed table — the customer's DNS as we would find it.
    struct StaticProbe {
        txt: Table<String, Vec<String>>,
        cname: Table<String, Vec<String>>,
    }

    impl StaticProbe {
        fn new() -> Self {
            StaticProbe { txt: Table::new(), cname: Table::new() }
        }
        fn with_txt(mut self, name: &str, values: Vec<&str>) -> Self {
            self.txt.put(name.to_string(), values.into_iter().map(String::from).collect());
            self
        }
        fn with_cname(mut self, name: &str, targets: Vec<&str>) -> Self {
            self.cname.put(name.to_string(), targets.into_iter().map(String::from).collect());
            self
        }
    }

    impl DnsProbe for StaticProbe {
        fn observe<'a>(&'a self, challenge: &'a Challenge) -> BoxFuture<'a, Observed> {
            Box::pin(async move {
                Observed {
                    txt: self.txt.get(&challenge.txt_name).cloned().unwrap_or_default(),
                    cname: self.cname.get(&challenge.fqdn).cloned().unwrap_or_default(),
                }
            })
        }
    }

    fn route() -> Route {
        Route {
            tenant_id: "acme".to_string(),
            tunnel_id: "tun-1".to_string(),
            peer: crate::transport::dialkey::peer_id("tun-1"),
            origin_port: 8080,
        }
    }

    fn registry_with_pending() -> (EdgeRegistry, Challenge) {
        let mut reg = EdgeRegistry::new(b"secret".to_vec());
        let rec = reg
            .add_custom("app.example.com.au", "amber-wren-1a2b3c.twnstack.app", route())
            .unwrap();
        let challenge = rec.challenge.clone().unwrap();
        (reg, challenge)
    }

    #[tokio::test]
    async fn the_txt_proof_validates() {
        let (mut reg, challenge) = registry_with_pending();
        let probe = StaticProbe::new().with_txt(&challenge.txt_name, vec![&challenge.token]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, HostnameState::PendingCert);
    }

    #[tokio::test]
    async fn the_cname_proof_validates() {
        let (mut reg, challenge) = registry_with_pending();
        let probe = StaticProbe::new().with_cname(&challenge.fqdn, vec![&challenge.cname_target]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results[0].1, HostnameState::PendingCert);
    }

    #[tokio::test]
    async fn a_cname_to_someone_elses_hostname_does_not_validate() {
        let (mut reg, challenge) = registry_with_pending();
        // Pointing at a DIFFERENT tenant's managed hostname must not prove anything — it is
        // still "a CNAME into our zone", which a naive suffix check would accept.
        let probe = StaticProbe::new().with_cname(&challenge.fqdn, vec!["someone-else-9f8e7d.twnstack.app"]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results[0].1, HostnameState::PendingDns, "must still be unproven");
    }

    #[tokio::test]
    async fn a_token_issued_for_another_domain_does_not_validate() {
        let (mut reg, challenge) = registry_with_pending();
        let foreign = Challenge::derive("app.other.com.au", "acme", "x.twnstack.app", b"secret");
        let probe = StaticProbe::new().with_txt(&challenge.txt_name, vec![&foreign.token]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results[0].1, HostnameState::PendingDns);
    }

    #[tokio::test]
    async fn an_unconfigured_domain_eventually_fails_rather_than_polling_forever() {
        let (mut reg, _challenge) = registry_with_pending();
        let probe = StaticProbe::new();

        for _ in 0..2 {
            assert_eq!(sweep(&probe, &mut reg, 3).await[0].1, HostnameState::PendingDns);
        }
        let last = sweep(&probe, &mut reg, 3).await;
        assert!(matches!(last[0].1, HostnameState::Failed(_)));
        assert!(sweep(&probe, &mut reg, 3).await.is_empty(), "a failed hostname leaves the sweep");
    }

    #[tokio::test]
    async fn a_sweep_over_nothing_pending_is_a_no_op() {
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        assert!(sweep(&StaticProbe::new(), &mut reg, 5).await.is_empty());
    }

    #[tokio::test]
    async fn extra_unrelated_txt_records_do_not_prevent_validation() {
        // Real zones carry SPF, DMARC, verification tokens from five other vendors. The
        // proof must be "one of these matches", not "the only record is ours".
        let (mut reg, challenge) = registry_with_pending();
        let probe = StaticProbe::new().with_txt(
            &challenge.txt_name,
            vec!["v=spf1 include:_spf.google.com ~all", "some-other-vendor=abc123", &challenge.token],
        );

        assert_eq!(sweep(&probe, &mut reg, 5).await[0].1, HostnameState::PendingCert);
    }
}
