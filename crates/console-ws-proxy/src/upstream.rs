//! Upstream-side connectors. One module per console flavour.
//!
//! The job of an upstream connector:
//!   1. Translate `(deployment_id, ConsoleKind)` → an upstream URL and the
//!      auth headers / cookies the upstream expects
//!   2. Open the upstream WebSocket
//!   3. Hand the resulting `WebSocketStream` to [`crate::pump`]
//!
//! The split lets us add new console kinds (`KubeVirt` VNC, `BinaryLane`
//! serial, …) without touching the core ticket / pump code.

pub mod proxmox;
