//! Document access to Couchbase Lite through a single actor thread.
//!
//! Couchbase Lite handles (`Database`, `Collection`, listeners) are not `Send`
//! in the Rust binding even though the C library is thread-safe. Rather than
//! scatter `unsafe impl Send` around, every handle this crate uses lives on one
//! dedicated thread and the rest of the program talks to it with messages.
//!
//! The only `unsafe` here is moving the *initial* `Database` handle onto that
//! thread (`SendDb`). That is sound for the same reason `tauri-plugin-cblite`
//! shares one behind a mutex: `CBLDatabase` is internally synchronised and
//! reference counted, and `Database::clone` just retains it.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use couchbase_lite::collection::{Collection, CollectionChangeListener};
use couchbase_lite::error::{CouchbaseLiteError, ErrorCode};
use couchbase_lite::{Database, Document, Listener, Query, QueryLanguage};
use serde_json::Value;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use crate::trust::Trust;

pub const SCOPE: &str = "a2a";

/// The three replicated collections.
///
/// Each is **single-writer per document**, so peers never produce conflicting
/// revisions and no arbiter is needed:
/// * `Inbox`  – commands (send / follow-up / cancel); written only by the node
///   that received the request from a client (the *origin*).
/// * `Tasks`  – task state; written only by the node that *owns* the task.
/// * `Agents` – one agent card per node; written only by that node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coll {
    Inbox,
    Tasks,
    Agents,
    /// Authority-signed token revocations (Biscuit mode); written by whoever receives one.
    Revocations,
}

impl Coll {
    pub const ALL: [Coll; 4] = [Coll::Inbox, Coll::Tasks, Coll::Agents, Coll::Revocations];
    pub fn name(self) -> &'static str {
        match self {
            Coll::Inbox => "inbox",
            Coll::Tasks => "tasks",
            Coll::Agents => "agents",
            Coll::Revocations => "revocations",
        }
    }
    /// `scope.collection`, the spelling `tauri-plugin-cblite` uses.
    pub fn qualified(self) -> String {
        format!("{SCOPE}.{}", self.name())
    }
}

type Reply<T> = oneshot::Sender<Result<T, String>>;

enum Op {
    Get(Coll, String, Reply<Option<Value>>),
    Put(Coll, String, Value, Reply<()>),
    /// Store as given, without signing (documents whose proof is not this node's signature).
    PutRaw(Coll, String, Value, Reply<()>),
    List(Coll, Reply<Vec<(String, Value)>>),
    Watch(Coll, UnboundedSender<String>, Reply<()>),
    /// Verify a document that just changed (and restore it if it was tampered with).
    Check(Coll, String),
}

struct SendDb(Database);
// SAFETY: see module docs. The handle is used on exactly one thread afterwards.
unsafe impl Send for SendDb {}

/// Cheap, cloneable, thread-safe handle to the actor.
#[derive(Clone)]
pub struct Docs {
    tx: mpsc::Sender<Op>,
    trust: Option<Arc<Trust>>,
}

impl Docs {
    /// Create the collections if needed and start the actor on `db`.
    ///
    /// Pass a *clone* of an already-open database to share it with other code
    /// (for example the Tauri plugin's open database).
    ///
    /// Documents are stored as they are and every document is believed: use
    /// [`Docs::spawn_secure`] when peers are not fully trusted.
    pub fn spawn(db: Database) -> Result<Docs, String> {
        Self::spawn_inner(db, None)
    }

    /// Like [`Docs::spawn`], but every write is signed by this node and every
    /// read is checked by `trust`: documents that fail verification are treated
    /// as absent (and recorded in [`Trust::rejections`]).
    pub fn spawn_secure(db: Database, trust: Arc<Trust>) -> Result<Docs, String> {
        Self::spawn_inner(db, Some(trust))
    }

    fn spawn_inner(db: Database, trust: Option<Arc<Trust>>) -> Result<Docs, String> {
        let (tx, rx) = mpsc::channel::<Op>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let db = SendDb(db);
        let actor_trust = trust.clone();
        let self_tx = tx.clone();
        std::thread::Builder::new()
            .name("a2a-cblite".into())
            .spawn(move || actor(db, rx, ready_tx, actor_trust, self_tx))
            .map_err(|e| e.to_string())?;
        ready_rx.recv().map_err(|e| e.to_string())??;
        Ok(Docs { tx, trust })
    }

    /// The trust store, when running in secure mode.
    pub fn trust(&self) -> Option<&Arc<Trust>> {
        self.trust.as_ref()
    }

    async fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Op) -> Result<T, String> {
        let (r_tx, r_rx) = oneshot::channel();
        self.tx.send(make(r_tx)).map_err(|_| "store actor stopped".to_string())?;
        r_rx.await.map_err(|_| "store actor dropped reply".to_string())?
    }

    pub async fn get(&self, coll: Coll, id: &str) -> Result<Option<Value>, String> {
        let id = id.to_string();
        self.call(|r| Op::Get(coll, id, r)).await
    }

    pub async fn put(&self, coll: Coll, id: &str, body: Value) -> Result<(), String> {
        let id = id.to_string();
        self.call(|r| Op::Put(coll, id, body, r)).await
    }

    /// Store `body` exactly as given. For documents that carry their own proof, such as an
    /// authority-signed revocation; anything else should use [`Docs::put`].
    pub async fn put_raw(&self, coll: Coll, id: &str, body: Value) -> Result<(), String> {
        let id = id.to_string();
        self.call(|r| Op::PutRaw(coll, id, body, r)).await
    }

    pub async fn list(&self, coll: Coll) -> Result<Vec<(String, Value)>, String> {
        self.call(|r| Op::List(coll, r)).await
    }

    /// Receive the id of every document that changes in `coll`, whether the
    /// change was made locally or arrived through replication.
    pub async fn watch(&self, coll: Coll, tx: UnboundedSender<String>) -> Result<(), String> {
        self.call(|r| Op::Watch(coll, tx, r)).await
    }
}

fn is_not_found(e: &couchbase_lite::Error) -> bool {
    e.code == ErrorCode::CouchbaseLite(CouchbaseLiteError::NotFound)
}

/// Do not restore the same document more often than this (a peer that keeps
/// overwriting it would otherwise make us rewrite it in a tight loop).
const RESTORE_EVERY: Duration = Duration::from_secs(2);

/// The last verified copy of every document this node has read or written, and
/// when each was last restored. Memory only: it protects a running node.
#[derive(Default)]
struct Guard {
    good: HashMap<(Coll, String), Value>,
    restored_at: HashMap<(Coll, String), Instant>,
}

/// Store `body` as it is, with no signing.
fn write_raw(colls: &mut HashMap<Coll, Collection>, c: Coll, id: &str, body: &Value) -> Result<(), String> {
    let coll = colls.get_mut(&c).unwrap();
    let mut doc = match coll.get_document(id) {
        Ok(d) => d,
        Err(e) if is_not_found(&e) => Document::new_with_id(id),
        Err(e) => return Err(e.to_string()),
    };
    doc.set_properties_as_json(&body.to_string()).map_err(|e| e.to_string())?;
    coll.save_document(&mut doc).map_err(|e| e.to_string())
}

/// Read `id`, believing only what verifies.
///
/// Without a trust store this is a plain read. With one, a document that was
/// overwritten with something that does not verify (or deleted) by a peer is
/// answered from the last verified copy, which is also written back *unchanged*.
/// Its signature travels inside it, so any honest node can restore it, not only
/// its author; a peer cannot forge a "newer" copy because it cannot sign one.
fn read_checked(
    colls: &mut HashMap<Coll, Collection>,
    trust: &Option<Arc<Trust>>,
    guard: &mut Guard,
    c: Coll,
    id: &str,
) -> Result<Option<Value>, String> {
    let raw = match colls[&c].get_document(id) {
        Ok(doc) => Some(serde_json::from_str::<Value>(&doc.properties_as_json()).map_err(|e| e.to_string())?),
        Err(e) if is_not_found(&e) => None,
        Err(e) => return Err(e.to_string()),
    };
    let Some(t) = trust else { return Ok(raw) };
    let key = (c, id.to_string());
    let deleted = raw.is_none();
    if let Some(v) = raw {
        if t.verify(c, id, &v).is_ok() {
            guard.good.insert(key, v.clone());
            return Ok(Some(v));
        }
    }
    // Invalid, or gone. Fall back to what we last verified, if we ever did.
    let Some(good) = guard.good.get(&key).cloned() else { return Ok(None) };
    // The saved copy must still be acceptable *now*: its author's token may have been revoked or
    // may have expired since. Then the document is not tampered with, it is no longer valid, and
    // it must neither be served nor written back.
    if t.verify(c, id, &good).is_err() {
        guard.good.remove(&key);
        return Ok(None);
    }
    if guard.restored_at.get(&key).map_or(true, |at| at.elapsed() >= RESTORE_EVERY) {
        guard.restored_at.insert(key, Instant::now());
        match write_raw(colls, c, id, &good) {
            Ok(()) => t.note_restored(c, id, deleted),
            Err(e) => log::warn!("could not restore {}/{id}: {e}", c.name()),
        }
    }
    Ok(Some(good))
}

fn actor(
    db: SendDb,
    rx: mpsc::Receiver<Op>,
    ready: mpsc::Sender<Result<(), String>>,
    trust: Option<Arc<Trust>>,
    self_tx: mpsc::Sender<Op>,
) {
    let db = db.0;
    let mut guard = Guard::default();

    // Declared before `listeners` so it drops after them: a listener must not
    // outlive the Collection it was registered on.
    let mut colls: HashMap<Coll, Collection> = HashMap::new();
    let mut listeners: Vec<Listener<CollectionChangeListener>> = Vec::new();

    for c in Coll::ALL {
        match db.create_collection(c.name().to_string(), SCOPE.to_string()) {
            Ok(coll) => {
                colls.insert(c, coll);
            }
            Err(e) => {
                let _ = ready.send(Err(format!("create collection {}: {e}", c.qualified())));
                return;
            }
        }
    }
    let _ = ready.send(Ok(()));

    if trust.as_ref().map_or(false, |t| t.mode() == "biscuit") {
        // Apply the revocations already stored, then watch for new ones, so a revocation that
        // arrived while nobody was reading still takes effect.
        let sql = format!("SELECT META().id AS id FROM {}.{}", SCOPE, Coll::Revocations.name());
        if let Ok(q) = Query::new(&db, QueryLanguage::N1QL, &sql) {
            if let Ok(rs) = q.execute() {
                let ids: Vec<String> = rs.into_iter().filter_map(|row| row.get(0).as_string().map(str::to_owned)).collect();
                for id in ids {
                    let _ = read_checked(&mut colls, &trust, &mut guard, Coll::Revocations, &id);
                }
            }
        }
        let check_tx = self_tx.clone();
        let coll = colls.get_mut(&Coll::Revocations).unwrap();
        listeners.push(coll.add_listener(Box::new(move |_c, ids| {
            for id in ids {
            let _ = check_tx.send(Op::Check(Coll::Revocations, id));
            }
        })));
    }

    while let Ok(op) = rx.recv() {
        match op {
            Op::Get(c, id, reply) => {
                let _ = reply.send(read_checked(&mut colls, &trust, &mut guard, c, &id));
            }
            Op::Put(c, id, mut body, reply) => {
                let r = (|| -> Result<(), String> {
                    let coll = colls.get_mut(&c).unwrap();
                    let mut doc = match coll.get_document(&id) {
                        Ok(d) => d,
                        Err(e) if is_not_found(&e) => Document::new_with_id(&id),
                        Err(e) => return Err(e.to_string()),
                    };
                    if let Some(t) = &trust {
                        // The sequence number continues from the stored revision, so it keeps
                        // rising even if this node's clock was set back.
                        let prev = serde_json::from_str::<Value>(&doc.properties_as_json()).ok().and_then(|v| Trust::seq_of(&v));
                        t.sign_next(c, &id, &mut body, prev);
                    }
                    doc.set_properties_as_json(&body.to_string()).map_err(|e| e.to_string())?;
                    coll.save_document(&mut doc).map_err(|e| e.to_string())?;
                    if trust.is_some() {
                        guard.good.insert((c, id.clone()), body.clone());
                    }
                    Ok(())
                })();
                let _ = reply.send(r);
            }
            Op::PutRaw(c, id, body, reply) => {
                let r = write_raw(&mut colls, c, &id, &body);
                if r.is_ok() && trust.is_some() {
                    guard.good.insert((c, id), body);
                }
                let _ = reply.send(r);
            }
            Op::List(c, reply) => {
                let r = (|| -> Result<Vec<(String, Value)>, String> {
                    let sql = format!("SELECT META().id AS id FROM {}.{}", SCOPE, c.name());
                    let q = Query::new(&db, QueryLanguage::N1QL, &sql).map_err(|e| e.to_string())?;
                    let rs = q.execute().map_err(|e| e.to_string())?;
                    let ids: Vec<String> =
                        rs.into_iter().filter_map(|row| row.get(0).as_string().map(str::to_owned)).collect();
                    let mut seen: HashSet<String> = HashSet::new();
                    let mut out = Vec::with_capacity(ids.len());
                    for id in ids {
                        seen.insert(id.clone());
                        if let Some(v) = read_checked(&mut colls, &trust, &mut guard, c, &id)? {
                            out.push((id, v));
                        }
                    }
                    // Documents we hold a verified copy of that are no longer there were deleted.
                    if trust.is_some() {
                        let gone: Vec<String> = guard
                            .good
                            .keys()
                            .filter(|(gc, gid)| *gc == c && !seen.contains(gid))
                            .map(|(_, gid)| gid.clone())
                            .collect();
                        for id in gone {
                            if let Some(v) = read_checked(&mut colls, &trust, &mut guard, c, &id)? {
                                out.push((id, v));
                            }
                        }
                    }
                    Ok(out)
                })();
                let _ = reply.send(r);
            }
            Op::Watch(c, tx, reply) => {
                let coll = colls.get_mut(&c).unwrap();
                let secure = trust.is_some();
                let check_tx = self_tx.clone();
                let l = coll.add_listener(Box::new(move |_coll, ids| {
                    for id in ids {
                        if secure {
                            // Look at every change straight away, so tampering is noticed (and
                            // repaired) even when nobody is reading the document.
                            let _ = check_tx.send(Op::Check(c, id.clone()));
                        }
                        let _ = tx.send(id);
                    }
                }));
                listeners.push(l);
                let _ = reply.send(Ok(()));
            }
            Op::Check(c, id) => {
                let _ = read_checked(&mut colls, &trust, &mut guard, c, &id);
            }
        }
    }
}