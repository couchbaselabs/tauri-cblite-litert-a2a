//! Headless A2A node: A2A HTTP server + Couchbase Lite P2P listener/replicators.
//!
//! ```text
//! a2a-node --name alice --data ./alice --http-port 8081
//! a2a-node --name bob   --data ./bob   --http-port 8082 --connect ws://127.0.0.1:<alice p2p port>/a2a
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a_cblite::{
    default_card,
    docs::Docs,
    executor::{EchoExecutor, Executor},
    hub::{Hub, LinkControl},
    p2p::{P2p, P2pSecurity},
    server,
    trust::Trust,
};
use couchbase_lite::{Database, DatabaseConfiguration};

struct Args {
    name: String,
    id: String,
    data: PathBuf,
    http_port: u16,
    p2p_port: u16,
    connect: Vec<String>,
    /// `.litertlm` model: makes this a real LLM agent (needs `--features litert`).
    model: Option<String>,
    role: String,
    persona: String,
    max_tokens: Option<i32>,
    /// Run the model on the GPU backend (some .litertlm files only load there).
    gpu: bool,
    /// Build ChatML prompts ourselves instead of using LiteRT-LM's chat-template layer.
    chatml: bool,
    /// Sign every document and only act on documents from enrolled peers.
    secure: bool,
    /// JSON file `{"nodes": {"alice": "<base64 public key>"}}` of trusted peers.
    trust_file: Option<PathBuf>,
    /// `name=<base64 public key>`, repeatable.
    trust_peers: Vec<String>,
    /// Create this node's key if needed, print `<id> <public key>` and exit.
    print_pubkey: bool,
    /// Biscuit mode: the mesh authority's public key (base64). Peers are trusted through
    /// tokens it issued (see `a2a-admin`) instead of a list of keys.
    root_key: Option<String>,
    /// This node's token file (required with `--root-key`).
    token_file: Option<PathBuf>,
    /// Revoked token ids, one hex id per line.
    revoked_file: Option<PathBuf>,
    /// Built-in agent when no model is given: echo, reviewer (checks inspection reports) or claims (files them).
    agent: String,
    /// Serve P2P over TLS (wss://) and allow dialing wss:// peers.
    tls: bool,
    /// A peer's certificate (PEM) to pin when dialing.
    pin_cert: Option<PathBuf>,
    /// Biscuit mode: only nodes with a valid token may connect.
    admit: bool,
    /// Name of an environment variable holding the database encryption password.
    db_key_env: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        name: "node".into(),
        id: String::new(),
        data: PathBuf::from("./a2a-data"),
        http_port: 8080,
        p2p_port: 0,
        connect: vec![],
        model: None,
        role: "assistant".into(),
        persona: "You are a concise, helpful assistant.".into(),
        max_tokens: None,
        gpu: false,
        chatml: false,
        secure: false,
        trust_file: None,
        trust_peers: vec![],
        print_pubkey: false,
        root_key: None,
        token_file: None,
        revoked_file: None,
        agent: "echo".into(),
        tls: false,
        pin_cert: None,
        admit: false,
        db_key_env: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().ok_or(format!("{k} needs a value"));
        match k.as_str() {
            "--name" => a.name = v()?,
            "--id" => a.id = v()?,
            "--data" => a.data = PathBuf::from(v()?),
            "--http-port" => a.http_port = v()?.parse().map_err(|e| format!("--http-port: {e}"))?,
            "--p2p-port" => a.p2p_port = v()?.parse().map_err(|e| format!("--p2p-port: {e}"))?,
            "--connect" => a.connect.push(v()?),
            "--model" => a.model = Some(v()?),
            "--role" => a.role = v()?,
            "--persona" => a.persona = v()?,
            "--template" => {
                a.chatml = match v()?.as_str() {
                    "chatml" => true,
                    "auto" => false,
                    other => return Err(format!("--template must be auto or chatml, got {other}")),
                }
            }
            "--backend" => {
                a.gpu = match v()?.as_str() {
                    "gpu" => true,
                    "cpu" => false,
                    other => return Err(format!("--backend must be cpu or gpu, got {other}")),
                }
            }
            "--max-tokens" => a.max_tokens = Some(v()?.parse().map_err(|e| format!("--max-tokens: {e}"))?),
            "--secure" => a.secure = true,
            "--trust" => {
                a.trust_file = Some(PathBuf::from(v()?));
                a.secure = true;
            }
            "--trust-peer" => {
                a.trust_peers.push(v()?);
                a.secure = true;
            }
            "--print-pubkey" => a.print_pubkey = true,
            "--root-key" => {
                a.root_key = Some(v()?);
                a.secure = true;
            }
            "--token" => a.token_file = Some(PathBuf::from(v()?)),
            "--revoked" => a.revoked_file = Some(PathBuf::from(v()?)),
            "--agent" => a.agent = v()?,
            "--tls" => a.tls = true,
            "--pin-cert" => a.pin_cert = Some(PathBuf::from(v()?)),
            "--admit" => a.admit = true,
            "--db-key-env" => a.db_key_env = Some(v()?),
            "-h" | "--help" => {
                return Err("usage: a2a-node [--name N] [--id ID] [--data DIR] [--http-port P] [--p2p-port P] [--connect ws://host:port/a2a]...\n       LLM agent (build with --features litert, Linux/macOS): [--model FILE.litertlm] [--role R] [--persona TEXT] [--max-tokens N]\n       Security: [--secure] [--trust trust.json] [--trust-peer name=PUBKEY]... [--print-pubkey]\n       Biscuit:  [--root-key ROOT_PUBKEY --token FILE [--revoked FILE]]  (tokens come from a2a-admin)\n       Built-in agent: [--agent echo|reviewer|claims]\n       Transport/at rest: [--tls] [--pin-cert PEM] [--admit] [--db-key-env VAR]".into())
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.id.is_empty() {
        a.id = a.name.to_lowercase().replace(' ', "-");
    }
    Ok(a)
}

/// A database handle moved onto the thread that owns the P2P state.
struct SendDb(Database);
// SAFETY: the handle is moved, not shared, and used on exactly one thread afterwards. `CBLDatabase` is
// internally synchronised and reference counted; `Database::clone` just retains it (see `a2a_cblite::docs`).
unsafe impl Send for SendDb {}

enum LinkMsg {
    Set(bool, std::sync::mpsc::Sender<Result<(), String>>),
}

/// The HTTP side's handle on the P2P thread: cut or restore this node's outgoing connections.
struct NodeLink {
    tx: Mutex<std::sync::mpsc::Sender<LinkMsg>>,
    up: AtomicBool,
}

impl LinkControl for NodeLink {
    fn set(&self, up: bool) -> Result<(), String> {
        let (r_tx, r_rx) = std::sync::mpsc::channel();
        self.tx.lock().unwrap().send(LinkMsg::Set(up, r_tx)).map_err(|_| "the P2P thread stopped".to_string())?;
        let r = r_rx.recv_timeout(Duration::from_secs(20)).map_err(|_| "the P2P thread did not answer".to_string())?;
        if r.is_ok() {
            self.up.store(up, Ordering::SeqCst);
        }
        r
    }

    fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }
}

/// Start the P2P listener and dial `connect`, on a thread of its own that lives as long as the process
/// (the handles are not `Send`, so nothing else may touch them). Returns the link handle, the port and URLs.
fn spawn_p2p(db: Database, sec: P2pSecurity, port: u16, connect: Vec<String>) -> Result<(Arc<NodeLink>, u16, Vec<String>), String> {
    let db = SendDb(db);
    let (tx, rx) = std::sync::mpsc::channel::<LinkMsg>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(u16, Vec<String>), String>>();
    std::thread::Builder::new()
        .name("a2a-p2p".into())
        .spawn(move || {
            let db = db; // capture the whole wrapper, not just its (non-Send) field
            let mut p2p = P2p::new(db.0).with_security(sec);
            let started = p2p.listen(port).and_then(|(p, urls)| {
                for url in &connect {
                    p2p.connect(url)?;
                }
                Ok((p, urls))
            });
            let _ = ready_tx.send(started);
            while let Ok(LinkMsg::Set(up, reply)) = rx.recv() {
                let r = if up {
                    p2p.reconnect()
                } else {
                    p2p.disconnect();
                    Ok(())
                };
                let _ = reply.send(r);
            }
        })
        .map_err(|e| e.to_string())?;
    let (p, urls) = ready_rx.recv().map_err(|e| e.to_string())??;
    Ok((Arc::new(NodeLink { tx: Mutex::new(tx), up: AtomicBool::new(true) }), p, urls))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // A2A_CBL_LOG=debug|verbose turns on LiteCore's own console log (all domains).
    if let Ok(l) = std::env::var("A2A_CBL_LOG") {
        use couchbase_lite::logging::{set_console_log_sink, ConsoleLogSink, DomainMask, Level};
        let level = if l == "debug" { Level::Debug } else { Level::Verbose };
        set_console_log_sink(ConsoleLogSink { level, domains: DomainMask::ALL });
    }
    let args = parse_args().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    std::fs::create_dir_all(&args.data)?;

    // Secure mode: this node's signing key (created on first use) and the peers it trusts.
    let trust = if args.secure || args.print_pubkey {
        let t = Trust::load_or_create(&args.data, &args.id)?;
        let t = match (&args.root_key, args.print_pubkey) {
            (Some(root), false) => {
                let f = args.token_file.as_ref().ok_or("--root-key needs this node's token: --token FILE (see a2a-admin issue)")?;
                let token = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
                if args.trust_file.is_some() || !args.trust_peers.is_empty() {
                    eprintln!("note: with --root-key peers are trusted through tokens; --trust / --trust-peer are ignored");
                }
                let t = t.with_biscuit(root, &token)?;
                if let Some(r) = &args.revoked_file {
                    t.load_revocations(r)?;
                }
                t
            }
            _ => {
                if let Some(f) = &args.trust_file {
                    t.load_trust_file(f)?;
                }
                for p in &args.trust_peers {
                    let (name, key) = p.split_once('=').ok_or_else(|| format!("--trust-peer wants name=PUBKEY, got {p}"))?;
                    t.enroll(name, key)?;
                }
                t
            }
        };
        Some(Arc::new(t))
    } else {
        None
    };
    if args.print_pubkey {
        println!("{} {}", args.id, trust.as_ref().unwrap().public_key());
        return Ok(());
    }

    // Encrypt the database at rest with a key derived from a password held in an environment
    // variable (not on the command line, where it would show up in process listings).
    #[cfg(feature = "enterprise")]
    let encryption_key = match &args.db_key_env {
        Some(var) => {
            let pwd = std::env::var(var).map_err(|_| format!("--db-key-env: environment variable {var} is not set"))?;
            Some(
                couchbase_lite::EncryptionKey::new_from_password(couchbase_lite::EncryptionAlgorithm::AES256, &pwd)
                    .ok_or("could not derive a database encryption key")?,
            )
        }
        None => None,
    };
    #[cfg(not(feature = "enterprise"))]
    if args.db_key_env.is_some() {
        return Err("--db-key-env needs a Couchbase Lite Enterprise build".into());
    }
    let db = Database::open(
        "a2a",
        Some(DatabaseConfiguration {
            directory: &args.data,
            #[cfg(feature = "enterprise")]
            encryption_key,
        }),
    )?;

    let docs = match &trust {
        Some(t) => Docs::spawn_secure(db.clone(), t.clone())?,
        None => Docs::spawn(db.clone())?,
    };

    // Load the model before anything is advertised to peers.
    let (executor, description): (Arc<dyn Executor>, String) = match args.model.as_deref() {
        #[cfg(all(feature = "litert", not(windows)))]
        Some(path) => {
            let cache = args.data.join("litert-cache");
            let llm = a2a_cblite::llm::LlmExecutor::load(
                path,
                args.role.clone(),
                args.persona.clone(),
                args.max_tokens,
                cache.to_str(),
                args.gpu,
                args.chatml,
            )?;
            let d = llm.description();
            (Arc::new(llm), d)
        }
        #[cfg(not(all(feature = "litert", not(windows))))]
        Some(_) => {
            return Err("--model needs a build with `--features litert` on Linux or macOS \
                        (Google ships no LiteRT-LM runtime for Windows)"
                .into())
        }
        None => match args.agent.as_str() {
            "echo" => (Arc::new(EchoExecutor), format!("A2A agent '{}' on Couchbase Lite (demo echo)", args.name)),
            "reviewer" => (Arc::new(a2a_cblite::rules::ReviewExecutor), "Checks field inspection reports have an asset, findings, a risk level and an action".to_string()),
            "claims" => (Arc::new(a2a_cblite::rules::ClaimsExecutor), "Files approved inspection reports and returns a claim number".to_string()),
            other => return Err(format!("--agent must be echo, reviewer or claims, got {other}").into()),
        },
    };

    let http = tokio::net::TcpListener::bind(("0.0.0.0", args.http_port)).await?;
    let base_url = format!("http://127.0.0.1:{}", http.local_addr()?.port());
    let card = default_card(&args.name, &description, &base_url);
    let hub: Arc<Hub> = Hub::start(docs, args.id.clone(), card, executor).await?;

    // Keep `p2p` alive for the life of the process (it stops on drop).
    let cert_path = args.data.join("tls.cert.pem");
    let sec = P2pSecurity {
        tls: args.tls,
        node_id: args.id.clone(),
        cert_out: args.tls.then(|| cert_path.clone()),
        pinned_cert: args.pin_cert.as_ref().map(|f| std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))).transpose()?,
        trust: trust.clone(),
        admission: args.admit,
    };
    let (link, port, urls) = spawn_p2p(db, sec, args.p2p_port, args.connect.clone())?;
    hub.set_link_control(link);
    hub.set_posture(serde_json::json!({
        "tls": args.tls,
        "pinned": args.pin_cert.is_some(),
        "admission": args.admit,
        "encryptedAtRest": args.db_key_env.is_some(),
    }));

    println!("node      {} ({})", args.name, args.id);
    println!("A2A       {base_url}   card: {base_url}/.well-known/agent-card.json");
    match &trust {
        Some(t) if t.mode() == "biscuit" => println!("security  signed + verified; peers trusted through Biscuit tokens; public key {}", t.public_key()),
        Some(t) => println!("security  signed + verified; {} enrolled peer(s); public key {}", t.enrolled().len(), t.public_key()),
        None => println!("security  OFF (every replicated document is believed)"),
    }
    if args.tls {
        println!("transport TLS; certificate {}  ({})", cert_path.display(), if args.pin_cert.is_some() { "dialing with a pinned peer certificate" } else { "dialers accept any self-signed certificate" });
    }
    if args.admit {
        println!("admission only nodes with a valid, unrevoked token may connect");
    }
    if args.db_key_env.is_some() {
        println!("at rest   database encrypted (AES-256)");
    }
    println!("P2P port  {port}");
    for u in urls {
        println!("P2P url   {u}");
    }

    server::serve(hub, http).await?;
    Ok(())
}
