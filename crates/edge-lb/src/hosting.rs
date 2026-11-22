//! Certificate hosting: everything the edge needs to own its certificates end to end.
//!
//! When `EDGE_LB_CERT_DIR` is set the edge
//!
//! 1. keeps certificates in a durable [`FileCertStore`] (atomic writes, 0600) and presents them
//!    per SNI ([`EdgeCertResolver`]) — no static PEM pair;
//! 2. runs the [`RenewalEngine`]: apex wildcards at boot, one certificate per custom hostname as
//!    its proof of control lands, renewal at two thirds of lifetime, backoff with the CA's
//!    `Retry-After`, last-known-good kept on failure;
//! 3. serves the apexes as an **authoritative DNS server** (UDP + TCP) so DNS-01 for wildcards is
//!    answered by us, and publishes CAA bound to our ACME account (RFC 8657 `accounturi`, DNS-01
//!    only);
//! 4. answers HTTP-01 on `:80` for customers' own names;
//! 5. runs the proof-of-control sweep for pending custom hostnames, journaling what it validates;
//! 6. revokes the certificate of a released custom hostname: [`EdgeState`] queues it in a durable
//!    [`RevocationQueue`] (`<cert dir>/revocations`) and a worker started here retries the CA
//!    until it is revoked, with backoff and without ever blocking the release;
//! 7. checks DNS health periodically (DNSSEC chain and signature lifetime, CAA policy, NS/SOA) and
//!    reports it through `/control/metrics` and `/control/health` — see [`crate::metrics`];
//! 8. is **resilient to a CA losing browser trust**: certificates are ordered only from the CAs on
//!    an operator-configured allow-list (`EDGE_LB_CA_POLICY`, or the single CA the legacy
//!    `EDGE_LB_ACME_*` variables describe), each with its own ACME account; CAA is published as the
//!    union of the CAs that may issue; an order falls back to a standby CA when the preferred one
//!    fails; and a root-program watch and a CT monitor say when to move — see [`crate::ca`] and
//!    `docs/runbooks/edge-ca-distrust.md`.
//!
//! Nothing here is on the request path: the data plane only reads the store.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};
use transport::acme::{AccountKey, ClientOptions};
use transport::acme_renew::{
    apex_wildcards, process_revocations, CertStore, FileCertStore, RenewalEngine, RenewalPolicy,
    RevocationPolicy, RevocationQueue,
};
use transport::ca_policy::{CaPolicy, EabSpec};
use transport::ca_resilience::{AcmeCaConnector, MultiCaIssuer, StatePaths};
use transport::ca_trust::TrustWatch;
use transport::ct_monitor::{CrtSh, CtMonitor};
use transport::dns_health::NetLookup;
use transport::edge::{CertSource, APEXES};
use transport::edge_dns::{
    AuthorityHandler, CaaRecords, Dns01Authority, ZoneAuthority, ZoneConfig,
};
use transport::edge_proxy::EdgeCertResolver;
use transport::edge_verify::{NativeProbe, ProofPolicy};

use crate::edge_state::EdgeState;

/// Operator-supplied inputs. Parsed from the environment by [`HostingConfig::from_lookup`].
#[derive(Clone, Debug)]
pub struct HostingConfig {
    /// Where certificates live (`EDGE_LB_CERT_DIR`).
    pub cert_dir: PathBuf,
    /// ACME directory URL (`EDGE_LB_ACME_DIRECTORY`). There is deliberately no default: pointing a
    /// production edge at a staging CA, or a test edge at production, should be a decision. With
    /// `EDGE_LB_CA_POLICY` this is the first eligible CA's directory (informational).
    pub acme_directory: String,
    /// Where the ACME account key lives (`EDGE_LB_ACME_ACCOUNT_KEY`); created on first run. With
    /// `EDGE_LB_CA_POLICY` this is the first eligible CA's key file (every CA has its own).
    pub account_key_file: PathBuf,
    /// ACME contact address (`EDGE_LB_ACME_CONTACT`).
    pub contact: Option<String>,
    /// External Account Binding for CAs that require it (Google, ZeroSSL): the CA-issued key id
    /// (`EDGE_LB_ACME_EAB_KID`) and the path of a file holding the base64url HMAC key
    /// (`EDGE_LB_ACME_EAB_HMAC_KEY_FILE`). Both or neither; the key is never read from the
    /// environment itself.
    pub eab: Option<(String, PathBuf)>,
    /// Authoritative DNS listen address, UDP and TCP (`EDGE_LB_DNS_BIND`, e.g. `0.0.0.0:53`).
    /// Required in practice: without it the edge cannot answer DNS-01 for its own wildcards.
    pub dns_bind: Option<String>,
    /// NS names published for every apex (`EDGE_LB_DNS_NS`, comma separated).
    pub nameservers: Vec<String>,
    /// The edge's public addresses, answered for managed hostnames (`EDGE_LB_EDGE_V4/V6`).
    pub edge_v4: Vec<Ipv4Addr>,
    pub edge_v6: Vec<Ipv6Addr>,
    /// CAA `issue` domains (`EDGE_LB_CAA_ISSUERS`, default `letsencrypt.org`); with
    /// `EDGE_LB_CA_POLICY`, the issuer domains of the CAs that may issue.
    pub caa_issuers: Vec<String>,
    /// The CA allow-list in force: loaded from `EDGE_LB_CA_POLICY`, or built from the single CA the
    /// legacy variables describe.
    pub ca_policy: CaPolicy,
    /// The allow-list file, polled for changes (`None`: the policy came from the legacy variables).
    pub ca_policy_file: Option<PathBuf>,
    /// Where the CA journal, ledger, account book and health live (`EDGE_LB_CA_STATE_DIR`, default
    /// `<cert dir>/ca-state`).
    pub ca_state_dir: PathBuf,
    /// Watch the root programs (Mozilla CCADB, Chrome Root Store) for distrust of the CAs we use
    /// (`EDGE_LB_CA_TRUST`, `on` by default) every `ca_trust_interval`
    /// (`EDGE_LB_CA_TRUST_INTERVAL_SECS`, default 21600).
    pub ca_trust: bool,
    pub ca_trust_interval: Duration,
    /// Watch Certificate Transparency for certificates for our names that we did not order
    /// (`EDGE_LB_CT_MONITOR`, `on` by default) every `ct_interval` (`EDGE_LB_CT_INTERVAL_SECS`,
    /// default 21600).
    pub ct_monitor: bool,
    pub ct_interval: Duration,
    /// Require embedded SCTs in what the CAs issue (`EDGE_LB_REQUIRE_SCTS`: `on`, `off`, or `auto`,
    /// the default: on unless every CA is a loopback/localhost test CA, which does not log).
    pub require_scts: bool,
    /// How often the policy file is polled and CAA reconciled with it (`EDGE_LB_CA_POLL_SECS`, default 30).
    pub ca_poll: Duration,
    pub renew_interval: Duration,
    pub sweep_interval: Duration,
    /// Failed proof checks before a pending custom hostname is failed (`EDGE_LB_MAX_PROBES`).
    pub max_probes: i64,
    pub proof: ProofPolicy,
    /// Run the periodic DNS health checks (`EDGE_LB_HEALTH`, `on` by default, `off` to disable).
    pub health: bool,
    /// How often (`EDGE_LB_HEALTH_INTERVAL_SECS`, default 900).
    pub health_interval: Duration,
    /// Recursive resolvers the health checks ask (`EDGE_LB_HEALTH_RESOLVERS`, comma separated
    /// `ip` or `ip:port`); empty means the public resolvers.
    pub health_resolvers: Vec<SocketAddr>,
}

/// The one-CA policy the legacy `EDGE_LB_ACME_*` variables describe, with what is known about the
/// CA (its issuer names and the roots to watch) filled in when its directory is a well-known one.
/// Such a deployment has no fallback; [`CaPolicy::lint`] says so.
fn legacy_policy(
    directory: &str,
    caa_domain: &str,
    key_file: &str,
    eab: Option<&(String, PathBuf)>,
    contact: Option<String>,
) -> Result<CaPolicy, String> {
    let known = transport::ca_policy::known_ca(directory);
    let mut policy = CaPolicy::single(
        "default",
        directory,
        caa_domain,
        known.map(|k| k.issuer_names()).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;
    if let Some(ca) = policy.cas.first_mut() {
        ca.account_key_file = Some(key_file.to_string());
        ca.eab = eab.map(|(kid, file)| EabSpec {
            kid: kid.clone(),
            hmac_key_file: file.to_string_lossy().into_owned(),
        });
        ca.contact = contact;
        if let Some(k) = known {
            ca.trust_roots = k.trust_roots();
        }
    }
    policy.validate().map_err(|e| e.to_string())?;
    Ok(policy)
}

fn list(raw: Option<String>) -> Vec<String> {
    raw.map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

impl HostingConfig {
    /// `Ok(None)` when `EDGE_LB_CERT_DIR` is unset (hosting off).
    ///
    /// # Errors
    /// A malformed or inconsistent setting — refused at boot, never at renewal time.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let Some(cert_dir) = get("EDGE_LB_CERT_DIR") else {
            return Ok(None);
        };
        let policy_file = get("EDGE_LB_CA_POLICY");
        if policy_file.is_some() {
            // One source of truth for which CAs exist: never both.
            for legacy in [
                "EDGE_LB_ACME_DIRECTORY",
                "EDGE_LB_ACME_ACCOUNT_KEY",
                "EDGE_LB_ACME_EAB_KID",
                "EDGE_LB_ACME_EAB_HMAC_KEY_FILE",
                "EDGE_LB_CAA_ISSUERS",
            ] {
                if get(legacy).is_some() {
                    return Err(format!(
                        "{legacy} must not be set together with EDGE_LB_CA_POLICY: the policy file names every CA, its directory, account key, EAB and CAA domain"
                    ));
                }
            }
        }
        let acme_directory = match (&policy_file, get("EDGE_LB_ACME_DIRECTORY")) {
            (Some(_), _) => String::new(),
            (None, Some(d)) => d,
            (None, None) => return Err("EDGE_LB_ACME_DIRECTORY (or EDGE_LB_CA_POLICY) is required when EDGE_LB_CERT_DIR is set (no default CA)".to_string()),
        };
        if policy_file.is_none()
            && !acme_directory.starts_with("https://")
            && !acme_directory.starts_with("http://127.0.0.1")
            && !acme_directory.starts_with("http://localhost")
        {
            return Err(
                "EDGE_LB_ACME_DIRECTORY must be https:// (plain http only for loopback test CAs)"
                    .into(),
            );
        }
        let account_key_file = match (&policy_file, get("EDGE_LB_ACME_ACCOUNT_KEY")) {
            (Some(_), _) => String::new(),
            (None, Some(k)) => k,
            (None, None) => {
                return Err(
                    "EDGE_LB_ACME_ACCOUNT_KEY is required (path of the ACME account key)"
                        .to_string(),
                )
            }
        };
        let nameservers = list(get("EDGE_LB_DNS_NS"));
        let dns_bind = get("EDGE_LB_DNS_BIND");
        if dns_bind.is_some() && nameservers.is_empty() {
            return Err("EDGE_LB_DNS_BIND needs EDGE_LB_DNS_NS (the NS names to publish)".into());
        }
        let parse = |k: &str| -> Result<Vec<String>, String> { Ok(list(get(k))) };
        let edge_v4 = parse("EDGE_LB_EDGE_V4")?
            .iter()
            .map(|s| {
                s.parse()
                    .map_err(|_| format!("EDGE_LB_EDGE_V4: '{s}' is not an IPv4 address"))
            })
            .collect::<Result<_, _>>()?;
        let edge_v6 = parse("EDGE_LB_EDGE_V6")?
            .iter()
            .map(|s| {
                s.parse()
                    .map_err(|_| format!("EDGE_LB_EDGE_V6: '{s}' is not an IPv6 address"))
            })
            .collect::<Result<_, _>>()?;
        let mut caa_issuers = list(get("EDGE_LB_CAA_ISSUERS"));
        if caa_issuers.is_empty() {
            caa_issuers.push(transport::ca_policy::known_ca(&acme_directory).map_or_else(
                || "letsencrypt.org".to_string(),
                |k| k.caa_domain.to_string(),
            ));
        }
        let secs = |k: &str, default: u64| -> Result<Duration, String> {
            get(k).map_or(Ok(Duration::from_secs(default)), |v| {
                v.parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .map(Duration::from_secs)
                    .ok_or_else(|| format!("{k} must be a positive number of seconds"))
            })
        };
        let proof = match get("EDGE_LB_PROOF_POLICY").as_deref() {
            None | Some("txt") => ProofPolicy::TxtOnly,
            Some("txt_or_cname") => ProofPolicy::TxtOrCname,
            Some(other) => {
                return Err(format!(
                    "EDGE_LB_PROOF_POLICY must be 'txt' or 'txt_or_cname', not '{other}'"
                ))
            }
        };
        let health = match get("EDGE_LB_HEALTH").as_deref() {
            None | Some("on") => true,
            Some("off") => false,
            Some(other) => {
                return Err(format!(
                    "EDGE_LB_HEALTH must be 'on' or 'off', not '{other}'"
                ))
            }
        };
        let health_resolvers = list(get("EDGE_LB_HEALTH_RESOLVERS"))
            .iter()
            .map(|r| {
                r.parse::<SocketAddr>()
                    .or_else(|_| {
                        r.parse::<std::net::IpAddr>()
                            .map(|ip| SocketAddr::new(ip, 53))
                    })
                    .map_err(|_| {
                        format!("EDGE_LB_HEALTH_RESOLVERS: '{r}' is not an IP address or ip:port")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let eab =
            match (
                get("EDGE_LB_ACME_EAB_KID"),
                get("EDGE_LB_ACME_EAB_HMAC_KEY_FILE"),
            ) {
                (Some(kid), Some(file)) => Some((kid, PathBuf::from(file))),
                (None, None) => None,
                _ => return Err(
                    "EDGE_LB_ACME_EAB_KID and EDGE_LB_ACME_EAB_HMAC_KEY_FILE must be set together"
                        .into(),
                ),
            };
        let on_off = |k: &str, default: bool| -> Result<bool, String> {
            match get(k).as_deref() {
                None => Ok(default),
                Some("on") => Ok(true),
                Some("off") => Ok(false),
                Some(other) => Err(format!("{k} must be 'on' or 'off', not '{other}'")),
            }
        };
        let cert_dir: PathBuf = cert_dir.into();
        // ── the CA allow-list: from the file, or the one CA the legacy variables describe
        let (ca_policy, ca_policy_file) = match &policy_file {
            Some(path) => {
                let path = PathBuf::from(path);
                let policy = CaPolicy::load(&path)
                    .map_err(|e| format!("EDGE_LB_CA_POLICY {}: {e}", path.display()))?;
                if let Some(bad) = policy
                    .cas
                    .iter()
                    .find(|c| c.status.may_issue() && c.account_key_file.is_none())
                {
                    return Err(format!("CA '{}' may issue but has no account_key_file: every CA needs its own ACME account key", bad.name));
                }
                if policy.cas.iter().all(|c| !c.status.may_issue()) {
                    return Err(
                        "EDGE_LB_CA_POLICY: no CA is active or standby, so nothing could be issued"
                            .into(),
                    );
                }
                (policy, Some(path))
            }
            None => {
                if caa_issuers.len() > 1 {
                    return Err("EDGE_LB_CAA_ISSUERS names several CAs, but one ACME account cannot be valid at several CAs; list each CA, with its own account, in an EDGE_LB_CA_POLICY file".into());
                }
                (
                    legacy_policy(
                        &acme_directory,
                        &caa_issuers[0],
                        &account_key_file,
                        eab.as_ref(),
                        get("EDGE_LB_ACME_CONTACT")
                            .map(|c| c.strip_prefix("mailto:").unwrap_or(&c).to_string()),
                    )?,
                    None,
                )
            }
        };
        let first = ca_policy
            .cas
            .iter()
            .find(|c| c.status.may_issue())
            .unwrap_or(&ca_policy.cas[0]);
        let (acme_directory, account_key_file, caa_issuers, eab) = if policy_file.is_some() {
            (
                first.directory_url.clone(),
                first.account_key_file.clone().unwrap_or_default(),
                ca_policy
                    .cas
                    .iter()
                    .filter(|c| c.status.may_issue())
                    .map(|c| c.caa_domain.clone())
                    .collect(),
                first
                    .eab
                    .as_ref()
                    .map(|e| (e.kid.clone(), PathBuf::from(&e.hmac_key_file))),
            )
        } else {
            (acme_directory, account_key_file, caa_issuers, eab)
        };
        let all_loopback = ca_policy.cas.iter().all(|c| {
            let rest = c.directory_url.split_once("://").map_or("", |(_, r)| r);
            rest.starts_with("localhost") || rest.starts_with("127.0.0.1")
        });
        let require_scts = match get("EDGE_LB_REQUIRE_SCTS").as_deref() {
            None | Some("auto") => !all_loopback,
            Some("on") => true,
            Some("off") => false,
            Some(other) => {
                return Err(format!(
                    "EDGE_LB_REQUIRE_SCTS must be 'on', 'off' or 'auto', not '{other}'"
                ))
            }
        };
        Ok(Some(HostingConfig {
            ca_state_dir: get("EDGE_LB_CA_STATE_DIR")
                .map_or_else(|| cert_dir.join("ca-state"), PathBuf::from),
            ca_trust: on_off("EDGE_LB_CA_TRUST", true)?,
            ca_trust_interval: secs("EDGE_LB_CA_TRUST_INTERVAL_SECS", 21_600)?,
            ct_monitor: on_off("EDGE_LB_CT_MONITOR", true)?,
            ct_interval: secs("EDGE_LB_CT_INTERVAL_SECS", 21_600)?,
            require_scts,
            ca_poll: secs("EDGE_LB_CA_POLL_SECS", 30)?,
            ca_policy,
            ca_policy_file,
            cert_dir,
            acme_directory,
            account_key_file: account_key_file.into(),
            eab,
            // The ACME client adds the `mailto:` scheme itself; accept it either way.
            contact: get("EDGE_LB_ACME_CONTACT")
                .map(|c| c.strip_prefix("mailto:").unwrap_or(&c).to_string()),
            dns_bind,
            nameservers,
            edge_v4,
            edge_v6,
            caa_issuers,
            renew_interval: secs("EDGE_LB_RENEW_INTERVAL_SECS", 3600)?,
            sweep_interval: secs("EDGE_LB_SWEEP_INTERVAL_SECS", 60)?,
            health,
            health_interval: secs("EDGE_LB_HEALTH_INTERVAL_SECS", 900)?,
            health_resolvers,
            max_probes: get("EDGE_LB_MAX_PROBES").map_or(Ok(60), |v| {
                v.parse::<i64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("EDGE_LB_MAX_PROBES must be a positive integer")
            })?,
            proof,
        }))
    }
}

/// What a running hosting setup hands the rest of the edge.
pub struct Hosting {
    /// The TLS server config presenting per-SNI certificates from the store.
    pub server_config: Arc<rustls::ServerConfig>,
    pub store: Arc<FileCertStore>,
    /// Certificates waiting to be revoked (released custom hostnames), durable beside the store.
    pub revocations: Arc<RevocationQueue>,
    /// The multi-CA issuer: choice between CAs, fail-over, attribution, root-program standing.
    pub issuer: Arc<MultiCaIssuer>,
}

/// How long the revocation worker sleeps between passes when nothing wakes it. A release wakes it
/// at once; this only bounds how late a *retry* can be after the backoff has elapsed.
const REVOCATION_TICK: Duration = Duration::from_secs(30);

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Load the 32-byte ACME account key, creating it (0600, atomically, from the system RNG) on first
/// run.
///
/// # Errors
/// I/O failure, a malformed file or an RNG failure. A damaged key is never silently replaced: a new
/// key is a new ACME account, which would orphan the CAA `accounturi` we publish.
pub fn load_or_create_account_key(path: &Path) -> Result<AccountKey, String> {
    transport::acme::load_or_create_account_key(path).map_err(|e| e.to_string())
}

/// The zones the edge is authoritative for: every apex, publishing `caa` as its CAA policy.
fn zone_authority(cfg: &HostingConfig, caa: &CaaRecords) -> ZoneAuthority {
    let zones = APEXES
        .iter()
        .map(|apex| {
            let ns = if cfg.nameservers.is_empty() {
                vec![format!("ns1.{}", apex.zone)]
            } else {
                cfg.nameservers.clone()
            };
            ZoneConfig::new(apex.zone, ns).with_caa_records(caa.clone())
        })
        .collect();
    ZoneAuthority::new(zones, cfg.edge_v4.clone(), cfg.edge_v6.clone())
}

/// How long the start-up RNG self-check may take (`getrandom` can block on a host that has not
/// gathered entropy yet; a hung start is worse than a refused one).
const RNG_SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(20);

/// Start certificate hosting: check the RNG, open the store, register the ACME account at every CA
/// that may issue, serve DNS, spawn the renewal, sweep, CA-policy, root-program and CT loops.
/// Returns once everything that can fail at boot has succeeded.
///
/// # Errors
/// An RNG that fails its self-check, store, account-key or listener failures, or *no* CA that may
/// issue being reachable at boot (the edge refuses to start rather than run with certificates it
/// cannot renew; a standby that is down is only a warning).
pub async fn start(cfg: HostingConfig, state: Arc<EdgeState>) -> Result<Hosting, String> {
    // Every key, nonce and token below comes from the system RNG. Refuse to start on one that
    // fails or returns garbage, before any key is generated.
    match transport::entropy::startup_self_check(RNG_SELF_CHECK_TIMEOUT) {
        Ok(()) => state.ca.record_rng_selfcheck(true),
        Err(e) => {
            state.ca.record_rng_selfcheck(false);
            return Err(format!("system RNG self-check failed: {e}"));
        }
    }
    let store = Arc::new(
        FileCertStore::open(&cfg.cert_dir)
            .map_err(|e| format!("cert store {}: {e}", cfg.cert_dir.display()))?,
    );
    state.set_cert_source(store.clone() as Arc<dyn CertSource>);
    let resolver = Arc::new(EdgeCertResolver::new(store.clone() as Arc<dyn CertSource>));
    let server_config = resolver.server_config()?;

    // The zones answer CAA "nobody may issue" until the accounts are known: the policy is
    // published below, before DNS is served and before the first order.
    let authority = Arc::new(tokio::sync::Mutex::new(zone_authority(
        &cfg,
        &CaaRecords::default().finish(),
    )));
    std::fs::create_dir_all(&cfg.ca_state_dir)
        .map_err(|e| format!("CA state dir {}: {e}", cfg.ca_state_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg.ca_state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("CA state dir {}: {e}", cfg.ca_state_dir.display()))?;
    }
    let connector = Arc::new(AcmeCaConnector {
        dns01: Arc::new(Dns01Authority(authority.clone())),
        http01: Some(state.challenges.clone()),
        options: ClientOptions::default(),
        default_contact: cfg.contact.clone(),
    });
    let issuer = Arc::new(MultiCaIssuer::new(
        cfg.ca_policy.clone(),
        connector,
        &StatePaths::in_dir(&cfg.ca_state_dir),
    )?);
    for finding in cfg.ca_policy.lint() {
        warn!(ca = ?finding.ca, severity = ?finding.severity, "CA policy: {}", finding.message);
    }
    let failed = issuer.connect_all().await;
    for (ca, why) in &failed {
        warn!(%ca, error = %why, "could not register at this CA; it is retried at its first order");
    }
    let accounts = issuer.accounts();
    let reachable = issuer
        .eligible_names()
        .into_iter()
        .filter(|n| accounts.contains_key(n))
        .count();
    if reachable == 0 {
        return Err(format!(
            "no CA that may issue could be registered with ({}); refusing to start rather than run with certificates that cannot be renewed",
            failed.iter().map(|(c, e)| format!("{c}: {e}")).collect::<Vec<_>>().join("; ")
        ));
    }
    info!(accounts = ?accounts, "ACME accounts ready");

    let plan = issuer.caa_plan(&[crate::ca::CAA_VALIDATION_METHOD.to_string()]);
    authority.lock().await.set_caa_records(&plan.records);
    let live_caa = Arc::new(std::sync::RwLock::new(
        plan.health_policy(Some(crate::ca::CUSTOMER_VALIDATION_METHOD)),
    ));
    if let Some(bind) = &cfg.dns_bind {
        let handler: Arc<dyn transport::edge_dns::DnsHandler> = Arc::new(AuthorityHandler {
            authority: authority.clone(),
            registry: state.registry.clone(),
        });
        // Bind both before returning so a port clash fails the boot, not a renewal at 3am.
        let udp = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| format!("DNS udp {bind}: {e}"))?;
        drop(udp);
        let tcp = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|e| format!("DNS tcp {bind}: {e}"))?;
        drop(tcp);
        let (h1, h2, b1, b2) = (handler.clone(), handler, bind.clone(), bind.clone());
        tokio::spawn(async move {
            if let Err(e) = transport::edge_dns::serve_udp_with(&b1, h1).await {
                warn!(error = %e, "authoritative DNS (udp) stopped");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = transport::edge_dns::serve_tcp_with(&b2, h2).await {
                warn!(error = %e, "authoritative DNS (tcp) stopped");
            }
        });
    } else {
        warn!("EDGE_LB_DNS_BIND unset — this edge cannot answer DNS-01, so apex wildcards will not issue unless another server hosts the zones");
    }

    // Revocation: the queue lives beside the certificates (0700, ignored by the cert store), the
    // release path and the engine's prune both queue into it, and one worker drains it promptly.
    // A certificate is revoked at the CA that issued it, whatever that CA's standing.
    let revocations = Arc::new(
        RevocationQueue::open(cfg.cert_dir.join("revocations"))
            .map_err(|e| format!("revocation queue: {e}"))?,
    );
    state.set_revoker(store.clone() as Arc<dyn CertStore>, revocations.clone());
    if !revocations.is_empty() {
        warn!(
            pending = revocations.len(),
            "certificates are still waiting to be revoked from before the restart"
        );
    }
    {
        let (queue, issuer) = (revocations.clone(), issuer.clone());
        tokio::spawn(async move {
            let wake = queue.wakeup();
            let policy = RevocationPolicy::default();
            loop {
                process_revocations(&queue, issuer.as_ref(), unix_now(), &policy).await;
                tokio::select! {
                    () = wake.notified() => {}
                    () = tokio::time::sleep(REVOCATION_TICK) => {}
                }
            }
        });
    }

    state.metrics.set_hosting(true);
    state.metrics.set_account_key_created(
        std::fs::metadata(&cfg.account_key_file)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
    );
    state
        .ca
        .set_enabled(cfg.ca_trust, cfg.ct_monitor, cfg.require_scts, unix_now());

    // What the loops may see of the store.
    let held: crate::ca::HeldCerts = {
        let store = store.clone();
        Arc::new(move || {
            store
                .names()
                .into_iter()
                .filter_map(|n| store.cert_for(&n).map(|m| (n, m)))
                .collect()
        })
    };

    if cfg.health {
        let lookup: Arc<dyn transport::dns_health::DnsLookup> =
            Arc::new(if cfg.health_resolvers.is_empty() {
                NetLookup::public()
            } else {
                NetLookup::new(cfg.health_resolvers.clone())
            });
        // The CAA the health run holds the zones to follows the CA policy as it changes.
        let (state, live, interval) = (state.clone(), live_caa.clone(), cfg.health_interval);
        tokio::spawn(async move {
            loop {
                let settings = crate::metrics::HealthSettings {
                    caa: live
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                    ..crate::metrics::HealthSettings::default()
                };
                if let Some(report) =
                    crate::metrics::run_health_once(&state, lookup.as_ref(), &settings, unix_now())
                        .await
                {
                    info!(
                        findings = report.findings.len(),
                        worst = report
                            .max_severity()
                            .map_or("none", transport::dns_health::Severity::as_str),
                        "dns health run"
                    );
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
    {
        let (issuer, authority, live) = (issuer.clone(), authority.clone(), live_caa.clone());
        tokio::spawn(crate::ca::caa_sync_loop(
            issuer,
            authority,
            live,
            cfg.ca_poll,
        ));
    }
    if let Some(path) = cfg.ca_policy_file.clone() {
        tokio::spawn(crate::ca::policy_reload_loop(
            path,
            issuer.clone(),
            state.clone(),
            cfg.ca_poll,
        ));
    }
    if cfg.ca_trust {
        tokio::spawn(crate::ca::trust_loop(
            state.clone(),
            issuer.clone(),
            TrustWatch::https(),
            held.clone(),
            cfg.ca_trust_interval,
        ));
    }
    let mut ct = CtMonitor::new(Arc::new(CrtSh::https()));
    ct.scts_required = cfg.require_scts;
    if cfg.ct_monitor {
        let mut monitor = CtMonitor::new(Arc::new(CrtSh::https()));
        monitor.scts_required = cfg.require_scts;
        tokio::spawn(crate::ca::ct_loop(
            state.clone(),
            issuer.clone(),
            monitor,
            held.clone(),
            cfg.ct_interval,
        ));
    }

    let engine = RenewalEngine::new(store.clone(), issuer.clone(), RenewalPolicy::default())
        .with_baseline(apex_wildcards())
        .with_revocations(revocations.clone());
    {
        let (registry, state, issuer, held) = (
            state.registry.clone(),
            state.clone(),
            issuer.clone(),
            held.clone(),
        );
        let interval = cfg.renew_interval;
        tokio::spawn(async move {
            engine
                .run_forever_with(registry, interval, move |_report, status| {
                    state.ca.refresh(&issuer, &status, unix_now());
                    crate::ca::check_held(&state, &ct, &held);
                    state.set_cert_status(status);
                })
                .await;
        });
    }
    {
        let (state, interval, max) = (state.clone(), cfg.sweep_interval, cfg.max_probes);
        tokio::spawn(async move {
            let probe = NativeProbe::public();
            loop {
                for (fqdn, new_state) in state.sweep(&probe, max).await {
                    info!(%fqdn, state = ?new_state, "proof-of-control sweep");
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
    Ok(Hosting {
        server_config,
        store,
        revocations,
        issuer,
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use std::collections::HashMap;
    use transport::ca_policy::CaStatus;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn hosting_is_off_unless_a_cert_dir_is_set() {
        assert!(HostingConfig::from_lookup(env(&[])).unwrap().is_none());
        assert!(
            HostingConfig::from_lookup(env(&[("EDGE_LB_CERT_DIR", "  ")]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn required_settings_and_cross_checks_are_enforced_at_boot() {
        let base = [
            ("EDGE_LB_CERT_DIR", "/c"),
            ("EDGE_LB_ACME_DIRECTORY", "https://ca/dir"),
            ("EDGE_LB_ACME_ACCOUNT_KEY", "/k"),
        ];
        let cfg = HostingConfig::from_lookup(env(&base)).unwrap().unwrap();
        assert_eq!(cfg.caa_issuers, ["letsencrypt.org"]);
        assert_eq!(
            cfg.proof,
            ProofPolicy::TxtOnly,
            "CNAME-only proof is opt-in"
        );
        assert_eq!(cfg.max_probes, 60);
        assert!(cfg.eab.is_none());
        let with_eab = |extra: &[(&'static str, &'static str)]| {
            HostingConfig::from_lookup(env(&base
                .iter()
                .copied()
                .chain(extra.iter().copied())
                .collect::<Vec<_>>()))
        };
        assert!(
            with_eab(&[("EDGE_LB_ACME_EAB_KID", "kid-1")]).is_err(),
            "kid without key file"
        );
        assert!(
            with_eab(&[("EDGE_LB_ACME_EAB_HMAC_KEY_FILE", "/k")]).is_err(),
            "key file without kid"
        );
        assert_eq!(
            with_eab(&[
                ("EDGE_LB_ACME_EAB_KID", "kid-1"),
                ("EDGE_LB_ACME_EAB_HMAC_KEY_FILE", "/k")
            ])
            .unwrap()
            .unwrap()
            .eab,
            Some(("kid-1".to_string(), PathBuf::from("/k")))
        );
        let with_contact = |c: &'static str| {
            HostingConfig::from_lookup(env(&[
                base[0],
                base[1],
                base[2],
                ("EDGE_LB_ACME_CONTACT", c),
            ]))
            .unwrap()
            .unwrap()
            .contact
        };
        assert_eq!(
            with_contact("mailto:ops@example.test").as_deref(),
            Some("ops@example.test"),
            "scheme is added by the client, not doubled"
        );
        assert_eq!(
            with_contact("ops@example.test").as_deref(),
            Some("ops@example.test")
        );

        let without = |drop: &str| -> Vec<(&str, &str)> {
            base.iter().copied().filter(|(k, _)| *k != drop).collect()
        };
        assert!(
            HostingConfig::from_lookup(env(&without("EDGE_LB_ACME_DIRECTORY"))).is_err(),
            "no default CA"
        );
        assert!(HostingConfig::from_lookup(env(&without("EDGE_LB_ACME_ACCOUNT_KEY"))).is_err());

        let with = |extra: &[(&'static str, &'static str)]| -> Vec<(&str, &str)> {
            base.iter().copied().chain(extra.iter().copied()).collect()
        };
        assert!(
            HostingConfig::from_lookup(env(&with(&[(
                "EDGE_LB_ACME_DIRECTORY",
                "http://ca.example/dir"
            )])))
            .is_err(),
            "plain-http CA"
        );
        assert!(
            HostingConfig::from_lookup(env(&with(&[(
                "EDGE_LB_ACME_DIRECTORY",
                "http://127.0.0.1:14000/dir"
            )])))
            .is_ok(),
            "loopback test CA is fine"
        );
        assert!(
            HostingConfig::from_lookup(env(&with(&[("EDGE_LB_DNS_BIND", "0.0.0.0:53")]))).is_err(),
            "DNS without NS names"
        );
        assert_eq!(
            HostingConfig::from_lookup(env(&with(&[
                ("EDGE_LB_DNS_BIND", "0.0.0.0:53"),
                ("EDGE_LB_DNS_NS", "ns1.tascloud.app, ns2.tascloud.app")
            ])))
            .unwrap()
            .unwrap()
            .nameservers
            .len(),
            2
        );
        assert!(
            HostingConfig::from_lookup(env(&with(&[("EDGE_LB_EDGE_V4", "999.1.1.1")]))).is_err()
        );
        assert!(
            HostingConfig::from_lookup(env(&with(&[("EDGE_LB_PROOF_POLICY", "anything")])))
                .is_err()
        );
        assert!(
            HostingConfig::from_lookup(env(&with(&[("EDGE_LB_RENEW_INTERVAL_SECS", "0")])))
                .is_err()
        );
        assert_eq!(
            HostingConfig::from_lookup(env(&with(&[("EDGE_LB_PROOF_POLICY", "txt_or_cname")])))
                .unwrap()
                .unwrap()
                .proof,
            ProofPolicy::TxtOrCname
        );
    }

    #[test]
    fn the_account_key_is_created_once_private_and_never_silently_replaced() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("acct.key");
        let a = load_or_create_account_key(&path).unwrap();
        let b = load_or_create_account_key(&path).unwrap();
        assert_eq!(
            a.to_bytes().unwrap(),
            b.to_bytes().unwrap(),
            "same account across restarts"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::write(&path, b"short").unwrap();
        assert!(
            load_or_create_account_key(&path).is_err(),
            "a damaged key must not be replaced by a new account"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    #[test]
    fn every_apex_gets_a_zone_with_caa_from_the_policy() {
        let cfg = HostingConfig::from_lookup(env(&[
            ("EDGE_LB_CERT_DIR", "/c"),
            ("EDGE_LB_ACME_DIRECTORY", "https://ca/dir"),
            ("EDGE_LB_ACME_ACCOUNT_KEY", "/k"),
            ("EDGE_LB_DNS_NS", "ns1.tascloud.app"),
        ]))
        .unwrap()
        .unwrap();
        // Constructing it must not panic for any apex; the zone content is covered in transport.
        let records = CaaRecords {
            issue: vec![transport::edge_dns::CaaIssuer {
                domain: "letsencrypt.org".into(),
                account_uri: Some("https://ca/acct/1".into()),
                validation_methods: vec!["dns-01".into()],
            }],
            ..CaaRecords::default()
        }
        .finish();
        let _ = zone_authority(&cfg, &records);
    }

    #[test]
    fn the_legacy_variables_become_a_one_ca_policy_filled_in_for_well_known_cas() {
        let base = [
            ("EDGE_LB_CERT_DIR", "/c"),
            ("EDGE_LB_ACME_ACCOUNT_KEY", "/k"),
        ];
        let le = HostingConfig::from_lookup(env(&[
            base[0],
            base[1],
            (
                "EDGE_LB_ACME_DIRECTORY",
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
            ("EDGE_LB_ACME_CONTACT", "mailto:ops@example.test"),
            ("EDGE_LB_ACME_EAB_KID", "kid"),
            ("EDGE_LB_ACME_EAB_HMAC_KEY_FILE", "/eab"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(le.ca_policy.cas.len(), 1);
        let ca = &le.ca_policy.cas[0];
        assert_eq!((ca.name.as_str(), ca.status), ("default", CaStatus::Active));
        assert_eq!(ca.caa_domain, "letsencrypt.org");
        assert_eq!(ca.account_key_file.as_deref(), Some("/k"));
        assert_eq!(ca.contact.as_deref(), Some("ops@example.test"));
        assert_eq!(ca.eab.as_ref().map(|e| e.kid.as_str()), Some("kid"));
        assert!(
            ca.issuer_names.iter().any(|n| n.contains("Let's Encrypt")),
            "{ca:?}"
        );
        assert!(
            !ca.trust_roots.is_empty(),
            "the well-known CA's roots are watched"
        );
        assert!(le.ca_policy_file.is_none());
        assert!(
            le.ca_trust && le.ct_monitor && le.require_scts,
            "everything on by default for a real CA"
        );
        // An unknown CA gets a policy too, just without the filled-in watch inputs.
        let other = HostingConfig::from_lookup(env(&[
            base[0],
            base[1],
            ("EDGE_LB_ACME_DIRECTORY", "https://ca.example/dir"),
        ]))
        .unwrap()
        .unwrap();
        assert!(
            other.ca_policy.cas[0].trust_roots.is_empty()
                && other.ca_policy.cas[0].issuer_names.is_empty()
        );
        // Several CAA issuers cannot share one account: refused with a pointer to the policy file.
        let e = HostingConfig::from_lookup(env(&[
            base[0],
            base[1],
            ("EDGE_LB_ACME_DIRECTORY", "https://ca.example/dir"),
            ("EDGE_LB_CAA_ISSUERS", "a.test,b.test"),
        ]))
        .unwrap_err();
        assert!(e.contains("EDGE_LB_CA_POLICY"), "{e}");
        // A loopback test CA does not log to CT, so SCTs are not required of it unless asked.
        let pebble = HostingConfig::from_lookup(env(&[
            base[0],
            base[1],
            ("EDGE_LB_ACME_DIRECTORY", "https://localhost:14000/dir"),
        ]))
        .unwrap()
        .unwrap();
        assert!(!pebble.require_scts);
        let forced = HostingConfig::from_lookup(env(&[
            base[0],
            base[1],
            ("EDGE_LB_ACME_DIRECTORY", "https://localhost:14000/dir"),
            ("EDGE_LB_REQUIRE_SCTS", "on"),
        ]))
        .unwrap()
        .unwrap();
        assert!(forced.require_scts);
        assert!(HostingConfig::from_lookup(env(&[
            base[0],
            base[1],
            ("EDGE_LB_ACME_DIRECTORY", "https://ca.example/dir"),
            ("EDGE_LB_REQUIRE_SCTS", "sometimes")
        ]))
        .is_err());
    }

    const TWO_CAS: &str = r#"{"version":1,"cas":[
      {"name":"le","directory_url":"https://acme-v02.api.letsencrypt.org/directory","caa_domain":"letsencrypt.org","status":"active","account_key_file":"/etc/edge/le.key","issuer_names":["Let's Encrypt"],"trust_roots":[{"name":"ISRG Root X1"}]},
      {"name":"gts","directory_url":"https://dv.acme-v02.api.pki.goog/directory","caa_domain":"pki.goog","status":"standby","account_key_file":"/etc/edge/gts.key","eab":{"kid":"k","hmac_key_file":"/etc/edge/gts.eab"},"issuer_names":["Google Trust Services"],"trust_roots":[{"name":"GTS Root R1"}]}]}"#;

    #[test]
    fn a_policy_file_defines_the_cas_and_cannot_be_mixed_with_the_single_ca_variables() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("ca.json");
        std::fs::write(&path, TWO_CAS).unwrap();
        let p = path.to_str().unwrap().to_string();
        let lookup = |extra: Vec<(&'static str, String)>| {
            let mut m: HashMap<String, String> = [
                ("EDGE_LB_CERT_DIR", "/c".to_string()),
                ("EDGE_LB_CA_POLICY", p.clone()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
            m.extend(extra.into_iter().map(|(k, v)| (k.to_string(), v)));
            HostingConfig::from_lookup(move |k| m.get(k).cloned())
        };
        let cfg = lookup(vec![]).unwrap().unwrap();
        assert_eq!(cfg.ca_policy.cas.len(), 2);
        assert_eq!(cfg.ca_policy_file.as_deref(), Some(path.as_path()));
        assert_eq!(
            cfg.caa_issuers,
            ["letsencrypt.org", "pki.goog"],
            "CAA domains follow the CAs that may issue"
        );
        assert_eq!(
            cfg.acme_directory,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(cfg.account_key_file, PathBuf::from("/etc/edge/le.key"));
        assert_eq!(cfg.ca_state_dir, PathBuf::from("/c/ca-state"));
        // One source of truth: any of the single-CA variables alongside the file is refused, by name.
        for (var, val) in [
            ("EDGE_LB_ACME_DIRECTORY", "https://x/dir"),
            ("EDGE_LB_ACME_ACCOUNT_KEY", "/k"),
            ("EDGE_LB_ACME_EAB_KID", "k"),
            ("EDGE_LB_ACME_EAB_HMAC_KEY_FILE", "/f"),
            ("EDGE_LB_CAA_ISSUERS", "letsencrypt.org"),
        ] {
            let e = lookup(vec![(var, val.to_string())]).unwrap_err();
            assert!(
                e.contains(var) && e.contains("EDGE_LB_CA_POLICY"),
                "{var}: {e}"
            );
        }
        // A broken or unsafe file is refused at boot, naming the problem.
        std::fs::write(
            &path,
            TWO_CAS.replace("\"status\":\"active\"", "\"status\":\"actve\""),
        )
        .unwrap();
        assert!(lookup(vec![]).unwrap_err().contains("EDGE_LB_CA_POLICY"));
        std::fs::write(
            &path,
            TWO_CAS.replace("\"account_key_file\":\"/etc/edge/le.key\",", ""),
        )
        .unwrap();
        assert!(
            lookup(vec![]).unwrap_err().contains("account_key_file"),
            "a CA that may issue needs its own account key"
        );
        std::fs::write(
            &path,
            TWO_CAS
                .replace("\"active\"", "\"retiring\"")
                .replace("\"standby\"", "\"distrusted\""),
        )
        .unwrap();
        assert!(lookup(vec![])
            .unwrap_err()
            .contains("nothing could be issued"));
        std::fs::write(
            &path,
            TWO_CAS.replace(
                "https://acme-v02.api.letsencrypt.org/directory",
                "http://acme.example/dir",
            ),
        )
        .unwrap();
        assert!(lookup(vec![]).is_err(), "plain-http CA");
        assert!(lookup(vec![("EDGE_LB_CA_POLICY", "/no/such/file".to_string())]).is_err());
        // The watch and monitor switches validate like the other on/off settings.
        std::fs::write(&path, TWO_CAS).unwrap();
        assert!(lookup(vec![("EDGE_LB_CA_TRUST", "maybe".to_string())]).is_err());
        let off = lookup(vec![
            ("EDGE_LB_CA_TRUST", "off".to_string()),
            ("EDGE_LB_CT_MONITOR", "off".to_string()),
            ("EDGE_LB_CA_TRUST_INTERVAL_SECS", "60".to_string()),
        ])
        .unwrap()
        .unwrap();
        assert!(!off.ca_trust && !off.ct_monitor);
        assert_eq!(off.ca_trust_interval, Duration::from_secs(60));
        assert!(lookup(vec![("EDGE_LB_CT_INTERVAL_SECS", "0".to_string())]).is_err());
    }

    #[test]
    fn the_dns_health_settings_are_validated_at_boot() {
        let base = [
            ("EDGE_LB_CERT_DIR", "/c"),
            ("EDGE_LB_ACME_DIRECTORY", "https://ca/dir"),
            ("EDGE_LB_ACME_ACCOUNT_KEY", "/k"),
        ];
        let with = |extra: &[(&'static str, &'static str)]| {
            HostingConfig::from_lookup(env(&base
                .iter()
                .copied()
                .chain(extra.iter().copied())
                .collect::<Vec<_>>()))
        };
        let cfg = with(&[]).unwrap().unwrap();
        assert!(
            cfg.health && cfg.health_resolvers.is_empty(),
            "on by default, against the public resolvers"
        );
        assert_eq!(cfg.health_interval, Duration::from_secs(900));
        assert!(!with(&[("EDGE_LB_HEALTH", "off")]).unwrap().unwrap().health);
        assert!(with(&[("EDGE_LB_HEALTH", "maybe")]).is_err());
        assert!(with(&[("EDGE_LB_HEALTH_INTERVAL_SECS", "0")]).is_err());
        let r = with(&[(
            "EDGE_LB_HEALTH_RESOLVERS",
            "9.9.9.9, [2620:fe::fe]:5353 ,127.0.0.1:5300",
        )])
        .unwrap()
        .unwrap()
        .health_resolvers;
        assert_eq!(
            r,
            [
                "9.9.9.9:53".parse().unwrap(),
                "[2620:fe::fe]:5353".parse().unwrap(),
                "127.0.0.1:5300".parse().unwrap()
            ]
            .to_vec() as Vec<SocketAddr>
        );
        assert!(
            with(&[("EDGE_LB_HEALTH_RESOLVERS", "dns.example")]).is_err(),
            "a name is not an address"
        );
    }
}
