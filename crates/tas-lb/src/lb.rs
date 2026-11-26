//! Assembly: bind everything, start the loops, and shut down gracefully.

use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt as _;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use transport::native::NativeEndpoint;
use transport::Transport as _;

use crate::config::{parse_signer_key, ListenerProto, StaticConfig};
use crate::control::{self, Applier};
use crate::identity;
use crate::signed_config::{ConfigError, ConfigStore};
use crate::tcp::{self, ListenerCtx};
use crate::userspace::Shared;
use crate::{admin, probe, udp};

/// Why the LB could not start. Starting is all-or-nothing: a listener that cannot bind is a
/// failed start, not a degraded one.
#[derive(Debug)]
pub struct StartError(pub String);

impl core::fmt::Display for StartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "tas-lb start: {}", self.0)
    }
}

impl std::error::Error for StartError {}

fn err<E: core::fmt::Display>(what: &str) -> impl FnOnce(E) -> StartError + '_ {
    move |e| StartError(format!("{what}: {e}"))
}

/// A bound customer listener.
#[derive(Debug, Clone)]
pub struct BoundListener {
    /// Config name.
    pub name: String,
    /// TCP or UDP.
    pub proto: ListenerProto,
    /// The actual address (port 0 resolved).
    pub addr: SocketAddr,
}

/// A running LB.
pub struct RunningLb {
    /// Customer listeners.
    pub listeners: Vec<BoundListener>,
    /// Internal metrics / health listener.
    pub metrics_addr: SocketAddr,
    /// Control (mesh) listener address and the LB's transport public key, if configured.
    pub control: Option<(String, [u8; 32])>,
    shared: Arc<Shared>,
    applier: Arc<Applier>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningLb {
    /// The shared state (tests and embedders read flows, metrics, the Director).
    #[must_use]
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Apply a signed envelope exactly as a mesh push would (library embedding, tests).
    ///
    /// # Errors
    /// [`ConfigError`] when refused; the last good config stays in force.
    pub fn apply_signed(&self, envelope: &[u8]) -> Result<u64, ConfigError> {
        self.applier.apply(envelope)
    }

    /// Sequence number of the config in force.
    #[must_use]
    pub fn config_seq(&self) -> u64 {
        self.applier.last_seq()
    }

    /// Graceful shutdown: stop accepting, let flows finish for up to `shutdown_grace_secs`, then
    /// reset whatever remains.
    pub async fn shutdown(self) {
        let grace = Duration::from_secs(self.shared.limits.shutdown_grace_secs);
        self.shared.shutting_down.store(true, Ordering::SeqCst);
        let _ = self.shutdown.send(true);
        let deadline = Instant::now() + grace;
        while !self.shared.flows.is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let reset = self.shared.flows.reset_all();
        if reset > 0 {
            tracing::warn!(
                flows = reset,
                "shutdown grace expired; resetting remaining flows"
            );
        }
        let settle = Instant::now() + Duration::from_secs(2);
        while !self.shared.flows.is_empty() && Instant::now() < settle {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Bind and start everything described by `cfg`.
///
/// # Errors
/// [`StartError`] if any socket cannot be bound or the identity / state directory is unusable.
pub async fn start(cfg: StaticConfig) -> Result<RunningLb, StartError> {
    cfg.validate().map_err(err("static config"))?;
    let signer = parse_signer_key(&cfg.signer_key).map_err(err("signer_key"))?;

    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&cfg.state_dir)
    {
        Ok(()) => {}
        Err(e) => return Err(StartError(format!("state_dir: {e}"))),
    }

    let default_port = cfg
        .listeners
        .iter()
        .find(|l| l.proto == ListenerProto::Tcp)
        .or(cfg.listeners.first())
        .map_or(443, |l| l.backend_port);
    let shared = Shared::new(cfg.limits.clone(), default_port);
    let store = ConfigStore::new(
        signer,
        cfg.cluster.clone(),
        cfg.allow_loopback_backends,
        Some(cfg.state_dir.clone()),
        cfg.min_config_seq,
    );
    let applier = Arc::new(Applier::new(store, shared.clone()));
    applier.load_persisted();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    let mut bound = Vec::new();

    tracing::info!(
        max_flows = cfg.limits.max_flows,
        worst_case_buffer_mib = cfg.limits.worst_case_buffer_bytes() / (1024 * 1024),
        "memory bound for copy buffers"
    );

    for (i, l) in cfg.listeners.iter().enumerate() {
        let index = u16::try_from(i).map_err(err("listener index"))?;
        let ctx = Arc::new(ListenerCtx::new(index, l).map_err(err("trusted_proxy_cidrs"))?);
        match l.proto {
            ListenerProto::Tcp => {
                let listener = tcp::bind(l.bind, cfg.limits.accept_backlog)
                    .map_err(err(&format!("bind {}", l.name)))?;
                let addr = listener.local_addr().map_err(err("local_addr"))?;
                bound.push(BoundListener {
                    name: l.name.clone(),
                    proto: l.proto,
                    addr,
                });
                tracing::info!(listener = %l.name, %addr, proto = "tcp", trusted_proxy_senders = !ctx.trusted.is_empty(), "listening");
                tasks.push(tokio::spawn(tcp::serve(
                    listener,
                    ctx,
                    shared.clone(),
                    shutdown_rx.clone(),
                )));
            }
            ListenerProto::Udp => {
                let sock = Arc::new(
                    udp::bind(l.bind)
                        .await
                        .map_err(err(&format!("bind {}", l.name)))?,
                );
                let addr = sock.local_addr().map_err(err("local_addr"))?;
                bound.push(BoundListener {
                    name: l.name.clone(),
                    proto: l.proto,
                    addr,
                });
                tracing::info!(listener = %l.name, %addr, proto = "udp", "listening");
                tasks.push(tokio::spawn(udp::serve(
                    sock,
                    ctx,
                    shared.clone(),
                    shutdown_rx.clone(),
                )));
            }
        }
    }

    let admin_listener = TcpListener::bind(cfg.metrics_bind)
        .await
        .map_err(err("bind metrics"))?;
    let metrics_addr = admin_listener
        .local_addr()
        .map_err(err("metrics local_addr"))?;
    tracing::info!(addr = %metrics_addr, "metrics listening");
    tasks.push(tokio::spawn(admin::serve(
        admin_listener,
        shared.clone(),
        shutdown_rx.clone(),
    )));

    let mut control_info = None;
    if let Some(c) = &cfg.control {
        let seed = identity::load_or_create(&cfg.state_dir.join("identity.key"))
            .map_err(err("identity"))?;
        let endpoint = NativeEndpoint::bind_with_key(&c.bind.to_string(), seed)
            .await
            .map_err(err("bind control"))?;
        let addr = endpoint.local_addr().map_err(err("control local_addr"))?;
        let id = endpoint.id();
        let hex = crate::backend::hex_encode(&id);
        tracing::info!(%addr, lb_identity = %hex, "control listening (pin lb_identity in the control plane)");
        control_info = Some((addr, id));
        tasks.push(tokio::spawn(control::serve(
            Arc::new(endpoint),
            *signer.as_bytes(),
            applier.clone(),
            shutdown_rx.clone(),
        )));
    }

    // Supervisor: start probers for new backends, advance drain clocks, expire idle UDP flows.
    {
        let shared = shared.clone();
        let mut stop = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let udp_idle = Duration::from_secs(shared.limits.udp_idle_timeout_secs);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.changed() => return,
                }
                for b in shared.director.take_unprobed() {
                    tokio::spawn(probe::run(shared.clone(), b, stop.clone()));
                }
                shared.director.tick(Instant::now());
                shared.flows.expire_idle_udp(udp_idle);
            }
        }));
    }

    Ok(RunningLb {
        listeners: bound,
        metrics_addr,
        control: control_info,
        shared,
        applier,
        shutdown: shutdown_tx,
        tasks,
    })
}
