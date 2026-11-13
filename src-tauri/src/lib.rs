//! Desktop A2A node.
//!
//! Division of labour:
//!
//! * `tauri-plugin-cblite` owns the database, the P2P listener
//!   (`start_peer_listener`) and the replicators (`start_replication`). The
//!   frontend drives those through the plugin's own commands.
//! * `a2a-cblite` owns the protocol. It borrows the plugin's open database
//!   (`Database::clone` is a ref-count bump on the same underlying handle),
//!   so the A2A collections the hub writes are exactly the ones the plugin's
//!   listener serves and its replicators sync.
//!
//! The one thing this app adds is [`a2a_start`], which wires the two together.

// On-device LLM agents (tauri-plugin-litert). Not compiled on Windows: Google
// ships no LiteRT-LM runtime for it, and merely linking the plugin there makes
// the executable import a `libLiteRt.dll` that does not exist, so the app would
// not even start (loader error 0xC0000135).
#[cfg(not(windows))]
mod litert_agent;
#[cfg(not(windows))]
use litert_agent::llm_executor;

#[cfg(windows)]
async fn llm_executor(
    _handle: &tauri::AppHandle,
    _node_id: &str,
    _model_path: String,
    _role: Option<String>,
    _persona: Option<String>,
    _template: Option<String>,
) -> Result<(Arc<dyn Executor>, String), String> {
    Err("On-device LLM agents are not available on Windows: Google ships no LiteRT-LM runtime \
         for it. Start this node without a model (demo echo agent) or run it on Linux/macOS."
        .into())
}

use std::sync::{Arc, Mutex};

use a2a_cblite::{
    default_card,
    docs::Docs,
    executor::{EchoExecutor, Executor},
    hub::{settled, AgentDoc, Hub},
    protocol::{Message, Part, Role, SendMessageRequest, Task},
    server,
    trust::Trust,
};
use serde::Serialize;
use tauri::State;
use tauri_plugin_cblite::PluginState;

/// The plugin's managed state. (Its alias is private; the type is public.)
type PluginStateArc = Arc<Mutex<Option<PluginState>>>;

#[derive(Default)]
struct A2aApp(tokio::sync::Mutex<Option<Arc<Hub>>>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct A2aInfo {
    node_id: String,
    url: String,
    card_url: String,
    security: String,
    public_key: Option<String>,
}

/// Start the A2A node on top of the database the frontend already opened
/// with `plugin:cblite|open_database` (collections `a2a.inbox`, `a2a.tasks`,
/// `a2a.agents`).
///
/// With `model_path` (a `.litertlm` file) the node is a **real agent**: a local
/// LLM loaded through `tauri-plugin-litert`, answering as `persona`. Without
/// it the node runs the demo echo agent.
#[tauri::command]
async fn a2a_start(
    handle: tauri::AppHandle,
    plugin: State<'_, PluginStateArc>,
    a2a: State<'_, A2aApp>,
    name: String,
    http_port: Option<u16>,
    model_path: Option<String>,
    role: Option<String>,
    persona: Option<String>,
    template: Option<String>,
    security: Option<String>,
    trust_file: Option<String>,
    root_key: Option<String>,
    token_file: Option<String>,
    revoked_file: Option<String>,
) -> Result<A2aInfo, String> {
    use tauri::Manager;
    let mut slot = a2a.0.lock().await;
    if slot.is_some() {
        return Err("A2A node already running".into());
    }
    let some = |o: Option<String>| o.filter(|s| !s.trim().is_empty());

    // Build the executor first: loading a model can fail or take a while, and
    // nothing else should be started until it has worked.
    let node_id = name.to_lowercase().replace(' ', "-");
    let (executor, description): (Arc<dyn Executor>, String) = match model_path.filter(|m| !m.trim().is_empty()) {
        Some(path) => llm_executor(&handle, &node_id, path, role, persona, template).await?,
        None => (Arc::new(EchoExecutor), format!("A2A agent '{name}' on Couchbase Lite (demo echo)")),
    };

    // Security: sign every document and only act on documents from trusted peers.
    //   allowlist: peers listed in a trust file {"nodes": {"alice": "<base64 key>"}}
    //   biscuit:   peers holding a token issued by one authority (see `a2a-admin`)
    let trust: Option<Arc<Trust>> = match security.as_deref().unwrap_or("off") {
        "off" | "" => None,
        mode @ ("allowlist" | "biscuit") => {
            let dir = handle.path().app_data_dir().map_err(|e| e.to_string())?.join("keys").join(&node_id);
            let t = Trust::load_or_create(&dir, &node_id)?;
            let t = if mode == "biscuit" {
                let root = some(root_key).ok_or("Biscuit mode needs the authority's public key")?;
                let tf = some(token_file).ok_or("Biscuit mode needs this node's token file")?;
                let token = std::fs::read_to_string(&tf).map_err(|e| format!("{tf}: {e}"))?;
                let t = t.with_biscuit(&root, &token)?;
                if let Some(r) = some(revoked_file) {
                    t.load_revocations(std::path::Path::new(&r))?;
                }
                t
            } else {
                if let Some(f) = some(trust_file) {
                    t.load_trust_file(std::path::Path::new(&f))?;
                }
                t
            };
            Some(Arc::new(t))
        }
        other => return Err(format!("unknown security mode '{other}' (use off, allowlist or biscuit)")),
    };

    // Connection admission for the plugin's peer listener: let a peer in only if its token checks out.
    // Needs the `peer-security` feature (and the plugin branch that has `set_peer_admission`).
    #[cfg(feature = "peer-security")]
    if let Some(t) = &trust {
        if t.mode() == "biscuit" {
            let t = t.clone();
            tauri_plugin_cblite::peer::set_peer_admission(
                &*handle.state::<tauri_plugin_cblite::peer::PeerStateArc>(),
                Some(Arc::new(move |user: &str, token: &str| t.admit(user, token))),
            );
        }
    }
    // Borrow the plugin's database. No await while the mutex is held.
    let docs = {
        let guard = plugin.lock().map_err(|e| e.to_string())?;
        let state = guard.as_ref().ok_or("open the database first (plugin:cblite|open_database)")?;
        match &trust {
            Some(t) => Docs::spawn_secure(state.db.clone(), t.clone())?,
            None => Docs::spawn(state.db.clone())?,
        }
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", http_port.unwrap_or(0)))
        .await
        .map_err(|e| e.to_string())?;
    let base = format!("http://127.0.0.1:{}", listener.local_addr().map_err(|e| e.to_string())?.port());
    let card = default_card(&name, &description, &base);
    let hub = Hub::start(docs, node_id.clone(), card, executor).await?;

    let h = hub.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = server::serve(h, listener).await {
            eprintln!("A2A server stopped: {e}");
        }
    });

    *slot = Some(hub);
    Ok(A2aInfo {
        card_url: format!("{base}/.well-known/agent-card.json"),
        url: base,
        node_id,
        security: trust.as_ref().map_or("off", |t| t.mode()).to_string(),
        public_key: trust.as_ref().map(|t| t.public_key()),
    })
}

/// Trust status of this node: mode, its public key (to give to the peers that should trust it),
/// who is enrolled, and every document it refused or had to restore.
#[tauri::command]
async fn a2a_security(app: State<'_, A2aApp>) -> Result<serde_json::Value, String> {
    let hub = app.0.lock().await.clone().ok_or("A2A node not started")?;
    Ok(match hub.docs.trust() {
        None => serde_json::json!({ "secure": false }),
        Some(t) => serde_json::json!({
            "secure": true, "mode": t.mode(), "nodeId": t.node_id(), "publicKey": t.public_key(),
            "enrolled": t.enrolled(), "rejections": t.rejections(),
        }),
    })
}

/// Agents known to this node's replica (its own card plus peers').
#[tauri::command]
async fn a2a_agents(app: State<'_, A2aApp>) -> Result<Vec<serde_json::Value>, String> {
    let hub = app.0.lock().await.clone().ok_or("A2A node not started")?;
    let agents: Vec<AgentDoc> = hub.agents().await?;
    Ok(agents
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "nodeId": a.node_id,
                "self": a.node_id == hub.node_id,
                "online": a.node_id == hub.node_id || a.online(),
                "name": a.card.name,
                "skills": a.card.skills.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            })
        })
        .collect())
}

/// Send `text` to `tenant` (a node id; empty = this node) and wait for the task
/// to settle. The same path an A2A client takes through `SendMessage`.
#[tauri::command]
async fn a2a_send(app: State<'_, A2aApp>, tenant: Option<String>, text: String) -> Result<Task, String> {
    let hub = app.0.lock().await.clone().ok_or("A2A node not started")?;
    let req = SendMessageRequest {
        tenant: tenant.filter(|t| !t.is_empty()),
        message: Message {
            message_id: uuid_like(),
            role: Role::User,
            parts: vec![Part::text(text)],
            context_id: None,
            task_id: None,
            metadata: None,
            extensions: vec![],
            reference_task_ids: vec![],
        },
        configuration: None,
        metadata: None,
    };
    let mut rx = hub.subscribe();
    let (tid, baseline) = hub.send_message(&req).await.map_err(|e| e.message)?;
    hub.wait_for(&tid, &mut rx, std::time::Duration::from_secs(60), |t| settled(t, baseline.as_deref()))
        .await?
        .ok_or_else(|| "task vanished".to_string())
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("ui-{n:x}")
}

/// The `(node id, token)` this node presents when it dials a peer that requires credentials (Biscuit mode).
#[tauri::command]
async fn a2a_credential(app: State<'_, A2aApp>) -> Result<serde_json::Value, String> {
    let hub = app.0.lock().await.clone().ok_or("A2A node not started")?;
    let (username, token) = hub
        .docs
        .trust()
        .and_then(|t| t.credential())
        .ok_or("this node has no token: credentials need Biscuit mode")?;
    Ok(serde_json::json!({ "username": username, "password": token }))
}

/// Write the listener's certificate (PEM) next to the database so it can be handed to peers that pin it.
#[tauri::command]
fn a2a_save_cert(app: tauri::AppHandle, pem: String) -> Result<String, String> {
    use tauri::Manager;
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("tls.cert.pem");
    std::fs::write(&path, pem).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}
/// Test/automation hook: `A2A_AUTOSTART='{"name":"scribe","httpPort":8081,"model":"...","template":"chatml","host":true}'`
/// makes the UI fill its fields and press *Start node* (and *Host*) on load.
#[tauri::command]
fn a2a_autostart() -> Option<serde_json::Value> {
    let mut v: serde_json::Value = std::env::var("A2A_AUTOSTART").ok().and_then(|s| serde_json::from_str(&s).ok())?;
    // `pinCertFile` is read here because the webview cannot read files: it becomes `pinCert`.
    if let Some(f) = v.get("pinCertFile").and_then(|f| f.as_str()) {
        if let Ok(pem) = std::fs::read_to_string(f) {
            v["pinCert"] = serde_json::Value::String(pem);
        }
    }
    Some(v)
}

#[tauri::command]
fn a2a_data_dir(app: tauri::AppHandle) -> Result<String, String> {
    use tauri::Manager;
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.to_string_lossy().into_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default().plugin(tauri_plugin_cblite::init());
    #[cfg(not(windows))]
    let builder = builder.plugin(tauri_plugin_litert::init());
    builder
        .manage(A2aApp::default())
        .invoke_handler(tauri::generate_handler![a2a_start, a2a_agents, a2a_send, a2a_data_dir, a2a_autostart, a2a_security, a2a_credential, a2a_save_cert])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
