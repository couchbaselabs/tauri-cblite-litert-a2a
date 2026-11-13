//! Couchbase Lite peer-to-peer plumbing for a standalone node.
//!
//! Inside the Tauri app none of this is needed: `tauri-plugin-cblite` already
//! exposes `start_peer_listener` and `start_replication`. This module is the
//! same thing for a headless process (and for tests), built directly on the
//! `couchbase_lite` crate. Handles are not `Send`; keep a `P2p` on one thread.
//!
//! Like the plugin, it is deliberately unauthenticated and unencrypted:
//! right for a trusted LAN, wrong for anything else.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use couchbase_lite::tls_identity::TLSIdentity;
use couchbase_lite::url_endpoint_listener::{ListenerAuthenticator, ListenerConfiguration, UrlEndpointListener};
use couchbase_lite::{
    Authenticator, Database, Endpoint, MutableArray, MutableDict, ReplicationCollection, ReplicationConfigurationContext,
    Replicator, ReplicatorConfiguration, ReplicatorType,
};

use crate::docs::{Coll, SCOPE};
use crate::trust::Trust;

/// Transport security for the P2P link.
///
/// The documents are signed regardless (see `trust`); this layer adds *confidentiality* (TLS)
/// and *admission* (only nodes holding a valid token may connect at all).
#[derive(Default, Clone)]
pub struct P2pSecurity {
    /// Serve over TLS (`wss://`) with a self-signed certificate, and allow dialing `wss://` URLs.
    pub tls: bool,
    /// This node's id, used as the certificate's common name.
    pub node_id: String,
    /// Where to write the listener's certificate (PEM) so peers can pin it. A new certificate is
    /// made every time the listener starts (the binding cannot persist an identity on Linux).
    pub cert_out: Option<PathBuf>,
    /// A peer certificate (PEM or DER) to pin when dialing. Without one a dialer accepts any
    /// self-signed certificate: the link is encrypted but the server is not authenticated.
    pub pinned_cert: Option<Vec<u8>>,
    /// Biscuit mode only. Listener: refuse connections that do not present a valid, unrevoked
    /// token. Dialer: present this node's token.
    pub trust: Option<Arc<Trust>>,
    pub admission: bool,
}

pub struct P2p {
    db: Database,
    listener: Option<UrlEndpointListener>,
    replicators: Vec<(String, Replicator)>,
    sec: P2pSecurity,
    /// Every peer URL given to [P2p::connect], so [P2p::reconnect] can dial them again.
    urls: Vec<String>,
}

impl P2p {
    pub fn new(db: Database) -> Self {
        P2p { db, listener: None, replicators: vec![], sec: P2pSecurity::default(), urls: vec![] }
    }

    /// Turn on TLS and/or connection admission.
    pub fn with_security(mut self, sec: P2pSecurity) -> Self {
        self.sec = sec;
        self
    }

    fn collections(&self) -> Result<Vec<couchbase_lite::collection::Collection>, String> {
        Coll::ALL
            .iter()
            .map(|c| {
                self.db
                    .create_collection(c.name().to_string(), SCOPE.to_string())
                    .map_err(|e| e.to_string())
            })
            .collect()
    }

    /// Accept replication connections from peers. Returns `(port, urls)`.
    pub fn listen(&mut self, port: u16) -> Result<(u16, Vec<String>), String> {
        let tls_identity = if self.sec.tls {
            let mut attrs = MutableDict::new();
            attrs.at("CN").put_string(&self.sec.node_id);
            let id = TLSIdentity::create(true, &attrs, None, None).map_err(|e| format!("TLS identity: {e}"))?;
            if let Some(path) = &self.sec.cert_out {
                std::fs::write(path, id.certificates().data(true)).map_err(|e| format!("{}: {e}", path.display()))?;
            }
            Some(id)
        } else {
            None
        };
        let authenticator = if self.sec.admission {
            let t = match &self.sec.trust {
                Some(t) if t.mode() == "biscuit" => t.clone(),
                _ => return Err("connection admission needs Biscuit mode (--root-key and --token)".into()),
            };
            Some(ListenerAuthenticator::password(move |user, token| t.admit(&user, &token)))
        } else {
            None
        };
        let l = UrlEndpointListener::new(ListenerConfiguration {
            collections: self.collections()?,
            port,
            network_interface: None,
            tls_identity,
            authenticator,
            read_only: false,
            enable_delta_sync: false,
        })
        .map_err(|e| e.to_string())?;
        l.start().map_err(|e| e.to_string())?;
        // The library reports ws:// even for a TLS listener; a dialer needs wss://.
        let urls = if self.sec.tls { l.urls().into_iter().map(|u| u.replacen("ws://", "wss://", 1)).collect() } else { l.urls() };
        let out = (l.port(), urls);
        self.listener = Some(l);
        Ok(out)
    }

    /// Continuously push and pull the three A2A collections with the peer at
    /// `url` (a `ws://host:port/db` URL as reported by the peer's `listen`).
    pub fn connect(&mut self, url: &str) -> Result<(), String> {
        if !self.urls.iter().any(|u| u == url) {
            self.urls.push(url.to_string());
        }
        self.dial(url)
    }

    /// Stop dialing every peer. The listener keeps running; [P2p::reconnect] dials again.
    pub fn disconnect(&mut self) {
        for (_, r) in self.replicators.iter_mut() {
            r.stop(None);
        }
        self.replicators.clear();
    }

    /// Dial every peer given to [P2p::connect] again (no-op while connected).
    pub fn reconnect(&mut self) -> Result<(), String> {
        if !self.replicators.is_empty() {
            return Ok(());
        }
        for url in self.urls.clone() {
            self.dial(&url)?;
        }
        Ok(())
    }

    fn dial(&mut self, url: &str) -> Result<(), String> {
        let endpoint = Endpoint::new_with_url(url).map_err(|e| e.to_string())?;
        let collections = self
            .collections()?
            .into_iter()
            .map(|collection| ReplicationCollection {
                collection,
                conflict_resolver: None,
                push_filter: None,
                pull_filter: None,
                // Null, not empty: an allocated empty array is a *filter*, and a
                // URL-endpoint listener answers filtered pulls with
                // "LiteCore 19: Filtering not supported".
                channels: MutableArray::default(),
                document_ids: MutableArray::default(),
            })
            .collect();
        let wss = url.starts_with("wss://");
        if wss && self.sec.pinned_cert.is_none() {
            log::warn!("dialing {url} without a pinned certificate: encrypted, but the server is not authenticated");
        }
        let pinned = self.sec.pinned_cert.clone();
        // Present this node's token only when the mesh uses admission (never over plain ws:// for nothing).
        let authenticator = match (&self.sec.trust, self.sec.admission) {
            (Some(t), true) => t.credential().map(|(user, token)| Authenticator::create_password(&user, &token)),
            _ => None,
        };
        let cfg = ReplicatorConfiguration {
            database: None,
            endpoint,
            replicator_type: ReplicatorType::PushAndPull,
            continuous: true,
            disable_auto_purge: false,
            max_attempts: 0, // retry forever: a peer may come and go
            max_attempt_wait_time: 10,
            // NOTE: this does not fix the known link flapping (see README,
            // "Known issues"): the listener still drops the connection ~1 s
            // after it goes Idle ("No response received after 0 sec").
            heartbeat: 30,
            authenticator,
            proxy: None,
            headers: HashMap::new(),
            pinned_server_certificate: pinned,
            trusted_root_certificates: None,
            channels: MutableArray::default(),
            document_ids: MutableArray::default(),
            collections: Some(collections),
            accept_parent_domain_cookies: false,
            #[cfg(feature = "enterprise")]
            accept_only_self_signed_server_certificate: wss && self.sec.pinned_cert.is_none(),
        };
        let label = url.to_string();
        let mut r = Replicator::new(cfg, Box::new(ReplicationConfigurationContext::default()))
            .map_err(|e| e.to_string())?
            .add_change_listener(Box::new({
                let label = label.clone();
                move |status| log::info!("replication {label}: {:?}", status.activity)
            }));
        r.start(false);
        self.replicators.push((label, r));
        Ok(())
    }
}

impl Drop for P2p {
    fn drop(&mut self) {
        for (_, r) in self.replicators.iter_mut() {
            r.stop(None);
        }
        if let Some(l) = &self.listener {
            l.stop();
        }
    }
}


