//! The userspace data plane: shared state and the [`Forwarder`] implementation over the
//! connection-tracking table. The TCP and UDP loops live in [`crate::tcp`] and [`crate::udp`].

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::backend::Backend;
use crate::config::LimitsConfig;
use crate::director::{Director, Forwarder, ForwarderError, Generation};
use crate::flows::{FlowTable, Limits};
use crate::loglimit::LogLimiter;
use crate::metrics::Metrics;
use crate::ratelimit::SourceRateLimiter;

/// The userspace plane as a [`Forwarder`]: the Director's table generations need no installation
/// (the loops read the Director directly), flow counts and resets come from the tracking table.
pub struct UserspaceForwarder {
    flows: Arc<FlowTable>,
}

impl UserspaceForwarder {
    /// Wrap a flow table.
    #[must_use]
    pub fn new(flows: Arc<FlowTable>) -> Self {
        UserspaceForwarder { flows }
    }
}

impl Forwarder for UserspaceForwarder {
    fn name(&self) -> &'static str {
        "userspace"
    }

    fn install(&self, _generation: &Generation) -> Result<(), ForwarderError> {
        Ok(())
    }

    fn reset_backend(&self, backend: &Backend) -> usize {
        self.flows.reset_backend(backend)
    }

    fn active_flows(&self, backend: &Backend) -> u64 {
        backend.flows()
    }
}

/// Everything the per-listener loops share.
pub struct Shared {
    /// Bounds.
    pub limits: LimitsConfig,
    /// Decisions.
    pub director: Arc<Director>,
    /// Connection tracking.
    pub flows: Arc<FlowTable>,
    /// Counters.
    pub metrics: Arc<Metrics>,
    /// Per-source new-flow limiter.
    pub rate: SourceRateLimiter,
    /// Limiter for attacker-triggerable log lines.
    pub logs: LogLimiter,
    /// Set when shutdown has begun (new flows refused; resets are shutdown resets).
    pub shutting_down: AtomicBool,
    /// Probe port used when the signed set does not name one.
    pub default_health_port: u16,
}

impl Shared {
    /// Build the shared state and the Director wired to the userspace forwarder.
    #[must_use]
    pub fn new(limits: LimitsConfig, default_health_port: u16) -> Arc<Self> {
        let metrics = Arc::new(Metrics::default());
        let flows = FlowTable::new(Limits {
            max_flows: limits.max_flows,
            max_flows_per_source: limits.max_flows_per_source,
        });
        let director = Arc::new(Director::new(
            Arc::new(UserspaceForwarder::new(flows.clone())),
            metrics.clone(),
        ));
        Arc::new(Shared {
            rate: SourceRateLimiter::new(limits.new_flows_per_source_per_sec),
            logs: LogLimiter::new(10),
            limits,
            director,
            flows,
            metrics,
            shutting_down: AtomicBool::new(false),
            default_health_port,
        })
    }
}
