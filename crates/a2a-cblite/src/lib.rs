//! # a2a-cblite
//!
//! An [A2A](https://a2a-protocol.org) 1.0 server whose state *and transport*
//! are Couchbase Lite. Agents on different machines form a mesh by
//! replicating three collections peer-to-peer (no Sync Gateway, no broker);
//! a task sent to any node is routed to the node that hosts the target agent,
//! executed there, and the result replicates back.
//!
//! * [`docs`]     â€“ the Couchbase Lite actor and the three collections
//! * [`hub`]      â€“ routing, task lifecycle, streaming diffs
//! * [`executor`] â€“ implement [`executor::Executor`] to bring your own agent
//! * [`server`]   â€“ the HTTP/JSON-RPC/SSE surface
//! * [`p2p`]      â€“ listener + replicator for headless nodes

pub mod docs;
pub mod executor;
pub mod hub;
#[cfg(all(feature = "litert", not(windows)))]
pub mod llm;
#[cfg(feature = "enterprise")]
pub mod p2p;
pub mod protocol;
pub mod rules;
pub mod server;
pub mod trust;

use protocol::*;

/// A card with the JSON-RPC interface at `base_url` and no skills (the
/// executor's skills are filled in by [`hub::Hub::start`]).
pub fn default_card(name: &str, description: &str, base_url: &str) -> AgentCard {
    AgentCard {
        name: name.into(),
        description: description.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        supported_interfaces: vec![AgentInterface {
            url: base_url.into(),
            protocol_binding: "JSONRPC".into(),
            protocol_version: "1.0".into(),
            tenant: None,
        }],
        capabilities: AgentCapabilities { streaming: true, push_notifications: false, extended_agent_card: false },
        skills: vec![],
        default_input_modes: vec!["text/plain".into()],
        default_output_modes: vec!["text/plain".into()],
    }
}
