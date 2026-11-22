//! Environment configuration, parsed from a map so it is testable without touching the process
//! environment. Secrets are never read from the environment itself: the mesh dialkey and the DNSSEC
//! master are *file paths* (0600), so they stay out of `/proc/<pid>/environ` and process listings.

use crate::build::Timings;
use crate::mesh::{parse_peer, parse_peer_id};
use crate::names::parse_fqdn_no_wildcard;
use crate::server::ServerLimits;
use hickory_proto::rr::Name;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use transport::{PeerAddr, PeerId};

/// A configuration problem. Messages name the variable, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Mesh settings as configured.
#[derive(Debug, Clone)]
pub struct MeshSettings {
    /// Listen address.
    pub bind: String,
    /// Path to the file holding the dialkey secret.
    pub dialkey_file: PathBuf,
    /// Pinned peers.
    pub peers: Vec<PeerAddr>,
    /// Pinned publishers.
    pub publishers: Vec<PeerId>,
    /// Seconds between anti-entropy rounds.
    pub pull_secs: u64,
}

/// Everything `main` needs.
#[derive(Debug, Clone)]
pub struct Config {
    /// DNS UDP bind.
    pub udp_bind: SocketAddr,
    /// DNS TCP bind.
    pub tcp_bind: SocketAddr,
    /// Internal metrics bind (loopback/private only).
    pub metrics_bind: SocketAddr,
    /// Directory for the persisted signed objects.
    pub data_dir: PathBuf,
    /// DNSSEC master secret file (None: signed zones are SERVFAIL).
    pub key_master_file: Option<PathBuf>,
    /// Our nameserver names.
    pub nameservers: Vec<Name>,
    /// SOA RNAME.
    pub hostmaster: Name,
    /// Registrar public key.
    pub registrar: [u8; 32],
    /// Challenge zone apex.
    pub challenge_zone: Option<Name>,
    /// Challenge authority public key.
    pub challenge_authority: Option<[u8; 32]>,
    /// Apexes tenants may never register.
    pub reserved: Vec<Name>,
    /// Zones one tenant may hold.
    pub max_zones_per_tenant: usize,
    /// Mesh settings (None: single node).
    pub mesh: Option<MeshSettings>,
    /// Wire limits.
    pub limits: ServerLimits,
    /// Signing timings.
    pub timings: Timings,
    /// Log filter.
    pub log_filter: String,
    /// JSON logs.
    pub log_json: bool,
}

fn get<'a>(m: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    m.get(k)
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
}

fn need<'a>(m: &'a HashMap<String, String>, k: &str) -> Result<&'a str, ConfigError> {
    get(m, k).ok_or_else(|| ConfigError(format!("{k} is required")))
}

fn num<T: std::str::FromStr>(
    m: &HashMap<String, String>,
    k: &str,
    default: T,
) -> Result<T, ConfigError> {
    match get(m, k) {
        None => Ok(default),
        Some(s) => s
            .trim()
            .parse()
            .map_err(|_| ConfigError(format!("{k} is not a valid number"))),
    }
}

fn key32(m: &HashMap<String, String>, k: &str) -> Result<[u8; 32], ConfigError> {
    let s = need(m, k)?;
    parse_peer_id(s.trim()).ok_or_else(|| ConfigError(format!("{k} must be 64 hex digits")))
}

fn names(m: &HashMap<String, String>, k: &str) -> Result<Vec<Name>, ConfigError> {
    get(m, k).map_or_else(
        || Ok(Vec::new()),
        |s| {
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(|x| {
                    parse_fqdn_no_wildcard(x)
                        .map_err(|_| ConfigError(format!("{k} contains an invalid name")))
                })
                .collect()
        },
    )
}

/// Whether `ip` may host the metrics listener: loopback, RFC 1918, ULA, link-local or CGNAT
/// (100.64/10, the `NetBird` range). Never a public or unspecified address.
#[must_use]
pub fn internal_only(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

impl Config {
    /// Parse from a variable map.
    #[expect(
        clippy::too_many_lines,
        reason = "one linear sequence; splitting it would obscure the order of the steps"
    )]
    pub fn from_map(m: &HashMap<String, String>) -> Result<Config, ConfigError> {
        let sock = |k: &str, d: &str| -> Result<SocketAddr, ConfigError> {
            get(m, k)
                .unwrap_or(d)
                .trim()
                .parse()
                .map_err(|_| ConfigError(format!("{k} is not a socket address")))
        };
        let udp_bind = sock("TAS_DNS_UDP_BIND", "127.0.0.1:5353")?;
        let tcp_bind = sock("TAS_DNS_TCP_BIND", &udp_bind.to_string())?;
        let metrics_bind = sock("TAS_DNS_METRICS_BIND", "127.0.0.1:9153")?;
        if !internal_only(metrics_bind.ip()) {
            return Err(ConfigError("TAS_DNS_METRICS_BIND must be a loopback or private address: the metrics listener is internal-only".into()));
        }
        let nameservers = names(m, "TAS_DNS_NAMESERVERS")?;
        if nameservers.is_empty() {
            return Err(ConfigError("TAS_DNS_NAMESERVERS is required".into()));
        }
        let hostmaster = parse_fqdn_no_wildcard(need(m, "TAS_DNS_HOSTMASTER")?)
            .map_err(|_| ConfigError("TAS_DNS_HOSTMASTER is not a valid name".into()))?;
        let challenge_zone = get(m, "TAS_DNS_CHALLENGE_ZONE")
            .map(|s| {
                parse_fqdn_no_wildcard(s.trim())
                    .map_err(|_| ConfigError("TAS_DNS_CHALLENGE_ZONE is not a valid name".into()))
            })
            .transpose()?;
        let challenge_authority = get(m, "TAS_DNS_CHALLENGE_AUTHORITY_KEY")
            .map(|_| key32(m, "TAS_DNS_CHALLENGE_AUTHORITY_KEY"))
            .transpose()?;
        if challenge_zone.is_some() != challenge_authority.is_some() {
            return Err(ConfigError(
                "TAS_DNS_CHALLENGE_ZONE and TAS_DNS_CHALLENGE_AUTHORITY_KEY go together".into(),
            ));
        }
        let mesh = match get(m, "TAS_DNS_MESH_BIND") {
            None => None,
            Some(bind) => {
                let peers = get(m, "TAS_DNS_MESH_PEERS").map_or_else(
                    || Ok(Vec::new()),
                    |s| {
                        s.split(',')
                            .map(str::trim)
                            .filter(|x| !x.is_empty())
                            .map(|x| {
                                parse_peer(x).ok_or_else(|| {
                                    ConfigError(
                                        "TAS_DNS_MESH_PEERS entries must be <64-hex-id>@host:port"
                                            .into(),
                                    )
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    },
                )?;
                let publishers = get(m, "TAS_DNS_MESH_PUBLISHERS").map_or_else(
                    || Ok(Vec::new()),
                    |s| {
                        s.split(',')
                            .map(str::trim)
                            .filter(|x| !x.is_empty())
                            .map(|x| {
                                parse_peer_id(x).ok_or_else(|| {
                                    ConfigError(
                                        "TAS_DNS_MESH_PUBLISHERS entries must be 64 hex digits"
                                            .into(),
                                    )
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    },
                )?;
                Some(MeshSettings {
                    bind: bind.trim().to_string(),
                    dialkey_file: PathBuf::from(need(m, "TAS_DNS_MESH_DIALKEY_FILE")?),
                    peers,
                    publishers,
                    pull_secs: num(m, "TAS_DNS_MESH_PULL_SECS", 10)?,
                })
            }
        };
        let mut limits = ServerLimits::default();
        limits.budget_rate = num(m, "TAS_DNS_BUDGET_QPS", limits.budget_rate)?;
        limits.budget_burst = num(m, "TAS_DNS_BUDGET_BURST", limits.budget_burst)?;
        limits.rrl_rate = num(m, "TAS_DNS_RRL_RPS", limits.rrl_rate)?;
        limits.rrl_burst = num(m, "TAS_DNS_RRL_BURST", limits.rrl_burst)?;
        limits.rrl_slip = num(m, "TAS_DNS_RRL_SLIP", limits.rrl_slip)?;
        limits.tcp_max_conns = num(m, "TAS_DNS_TCP_MAX_CONNS", limits.tcp_max_conns)?;
        limits.tcp_per_ip = num(m, "TAS_DNS_TCP_PER_IP", limits.tcp_per_ip)?;
        limits.max_in_flight = num(m, "TAS_DNS_MAX_IN_FLIGHT", limits.max_in_flight)?;
        limits.tcp_idle =
            Duration::from_secs(num(m, "TAS_DNS_TCP_IDLE_SECS", limits.tcp_idle.as_secs())?);
        let timings = Timings::default();
        timings
            .validate()
            .map_err(|e| ConfigError(format!("timings: {e}")))?;
        Ok(Config {
            udp_bind,
            tcp_bind,
            metrics_bind,
            data_dir: PathBuf::from(need(m, "TAS_DNS_DATA_DIR")?),
            key_master_file: get(m, "TAS_DNS_KEY_MASTER_FILE").map(PathBuf::from),
            nameservers,
            hostmaster,
            registrar: key32(m, "TAS_DNS_REGISTRAR_KEY")?,
            challenge_zone,
            challenge_authority,
            reserved: names(m, "TAS_DNS_RESERVED")?,
            max_zones_per_tenant: num(m, "TAS_DNS_MAX_ZONES_PER_TENANT", 100)?,
            mesh,
            limits,
            timings,
            // hickory logs every query name at info; the default filter keeps its chatter out of
            // our logs so a query name never reaches a log line from that path
            log_filter: get(m, "TAS_DNS_LOG")
                .unwrap_or("info,hickory_server=error,hickory_net=error,hickory_proto=error")
                .to_string(),
            log_json: get(m, "TAS_DNS_LOG_JSON") == Some("1"),
        })
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "test assertions on fixtures")]

    use super::*;

    fn base() -> HashMap<String, String> {
        [
            ("TAS_DNS_DATA_DIR", "/var/lib/tas-dns"),
            ("TAS_DNS_NAMESERVERS", "ns1.tas.example, ns2.tas.example"),
            ("TAS_DNS_HOSTMASTER", "hostmaster.tas.example"),
            ("TAS_DNS_REGISTRAR_KEY", &"ab".repeat(32)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn minimal_config_has_safe_defaults() {
        let c = Config::from_map(&base()).unwrap();
        assert_eq!(c.udp_bind.to_string(), "127.0.0.1:5353");
        assert_eq!(c.metrics_bind.to_string(), "127.0.0.1:9153");
        assert_eq!(c.nameservers.len(), 2);
        assert!(c.mesh.is_none() && c.key_master_file.is_none() && c.challenge_zone.is_none());
        assert!(c.log_filter.contains("hickory_server=error"));
    }

    #[test]
    fn the_metrics_listener_is_refused_on_public_or_wildcard_addresses() {
        for bad in ["0.0.0.0:9153", "203.0.113.5:9153", "[::]:9153", "8.8.8.8:1"] {
            let mut m = base();
            m.insert("TAS_DNS_METRICS_BIND".into(), bad.into());
            assert!(Config::from_map(&m).is_err(), "{bad}");
        }
        for ok in [
            "127.0.0.1:1",
            "10.1.2.3:1",
            "192.168.0.1:1",
            "100.64.1.1:1",
            "[::1]:1",
            "[fd00::1]:1",
        ] {
            let mut m = base();
            m.insert("TAS_DNS_METRICS_BIND".into(), ok.into());
            assert!(Config::from_map(&m).is_ok(), "{ok}");
        }
    }

    #[test]
    fn required_and_paired_settings_are_enforced_and_errors_do_not_echo_values() {
        for k in [
            "TAS_DNS_DATA_DIR",
            "TAS_DNS_NAMESERVERS",
            "TAS_DNS_HOSTMASTER",
            "TAS_DNS_REGISTRAR_KEY",
        ] {
            let mut m = base();
            m.remove(k);
            assert!(Config::from_map(&m).is_err(), "{k}");
        }
        let mut m = base();
        m.insert("TAS_DNS_REGISTRAR_KEY".into(), "not-hex-SECRET".into());
        let e = Config::from_map(&m).unwrap_err().to_string();
        assert!(!e.contains("SECRET"), "{e}");
        let mut m = base();
        m.insert("TAS_DNS_CHALLENGE_ZONE".into(), "chal.tas.example".into());
        assert!(Config::from_map(&m).is_err(), "zone without authority key");
        m.insert("TAS_DNS_CHALLENGE_AUTHORITY_KEY".into(), "cd".repeat(32));
        assert!(Config::from_map(&m).is_ok());
        let mut m = base();
        m.insert("TAS_DNS_MESH_BIND".into(), "0.0.0.0:7443".into());
        assert!(Config::from_map(&m).is_err(), "mesh needs a dialkey file");
        m.insert(
            "TAS_DNS_MESH_DIALKEY_FILE".into(),
            "/etc/tas-dns/dialkey".into(),
        );
        m.insert(
            "TAS_DNS_MESH_PEERS".into(),
            format!("{}@10.0.0.2:7443", "01".repeat(32)),
        );
        m.insert("TAS_DNS_MESH_PUBLISHERS".into(), "02".repeat(32));
        let c = Config::from_map(&m).unwrap();
        assert_eq!(c.mesh.unwrap().peers.len(), 1);
        let mut m = base();
        m.insert("TAS_DNS_MESH_PEERS".into(), "nonsense".into());
        m.insert("TAS_DNS_MESH_BIND".into(), "0.0.0.0:1".into());
        m.insert("TAS_DNS_MESH_DIALKEY_FILE".into(), "/x".into());
        assert!(Config::from_map(&m).is_err());
    }
}
