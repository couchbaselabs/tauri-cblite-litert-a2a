//! Message-level trust for the replicated collections.
//!
//! Couchbase Lite replication moves documents between peers, but once a peer is
//! allowed to replicate it can write *any* document in the shared collections.
//! This module closes that gap on the receiving side: every document is signed
//! by the node that wrote it, and a node only acts on documents that pass
//! [`Trust::verify`].
//!
//! A document is accepted when
//! 1. its signature is valid for the claimed author,
//! 2. the author is this node or an *enrolled* peer (the allowlist),
//! 3. the author is allowed to write *this kind* of document (below), and
//! 4. it is not an older revision than one already accepted (rollback).
//!
//! Authorization rules follow the single-writer design of the collections:
//! * `agents`  – doc id and `nodeId` must equal the author (a node publishes only its own card)
//! * `tasks`   – `owner` must equal the author (only the executing node writes task state)
//! * `inbox`   – `from` must equal the author (a node cannot forge another node's commands)
//!
//! What this does **not** do: stop an enrolled peer from overwriting or deleting
//! a document at the database level. That is detected (the bad revision is
//! ignored and logged), not prevented. A compromised enrolled node can still
//! sign lies *about itself*; revoking its key limits the damage.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use a2a_authz::{Claim, Revocation};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

use crate::docs::Coll;

const DOMAIN: &str = "a2a-cblite/v1";
/// The one top-level field [`Trust::sign`] adds (`{author, seq, sig}`); never part
/// of the signed content. It must not start with `_`: Couchbase Lite replication
/// strips reserved underscore-prefixed top-level properties from replicated docs.
const META: &str = "trust";
const MAX_REJECTIONS: usize = 200;

/// Why a document was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    Unsigned,
    Malformed(&'static str),
    UnknownAuthor(String),
    BadSignature,
    NotAuthorized(String),
    Rollback { newest: i64, got: i64 },
    /// Biscuit mode: the author presented no token.
    NoCredential(String),
    /// Biscuit mode: the token is invalid, expired, revoked, or does not allow this.
    BadCredential(String),
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reject::Unsigned => write!(f, "unsigned document"),
            Reject::Malformed(m) => write!(f, "malformed: {m}"),
            Reject::UnknownAuthor(a) => write!(f, "author '{a}' is not enrolled"),
            Reject::BadSignature => write!(f, "signature does not match the content"),
            Reject::NotAuthorized(m) => write!(f, "not authorized: {m}"),
            Reject::Rollback { newest, got } => write!(f, "older revision than accepted (seq {got} < {newest})"),
            Reject::NoCredential(a) => write!(f, "author '{a}' presented no token"),
            Reject::BadCredential(m) => write!(f, "credential refused: {m}"),
        }
    }
}

/// One distinct rejection, with how often it was seen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rejection {
    pub first_at: i64,
    pub last_at: i64,
    pub count: u64,
    pub collection: String,
    pub doc_id: String,
    pub author: Option<String>,
    pub reason: String,
}

/// How long a successful token check is reused (tokens expire, so not forever).
const TOKEN_CACHE_TTL: Duration = Duration::from_secs(30);

/// Biscuit mode: peers are trusted through tokens issued by one authority, not
/// through a list of keys.
struct BiscuitMode {
    root: a2a_authz::PublicKey,
    /// This node's own token, attached to every document it writes.
    token: String,
    /// Hex revocation ids that are no longer accepted.
    revoked: Mutex<HashSet<String>>,
    /// Recent successful checks: key -> (when, revocation ids).
    cache: Mutex<HashMap<String, (Instant, Vec<String>)>>,
}

impl BiscuitMode {
    /// Is `token` valid, unexpired and does it let `author` (holding `key_b64`) write this
    /// kind of document? Returns the token's revocation ids.
    fn check(&self, token: &str, author: &str, key_b64: &str, coll: Coll, target: Option<&str>) -> Result<Vec<String>, String> {
        let ck = format!("{token}|{author}|{key_b64}|{}|{}", coll.name(), target.unwrap_or(""));
        if let Some((at, ids)) = self.cache.lock().unwrap().get(&ck) {
            if at.elapsed() < TOKEN_CACHE_TTL {
                return Ok(ids.clone());
            }
        }
        let ok = a2a_authz::authorize(
            token,
            &self.root,
            &Claim { node: author, key_b64, collection: coll.name(), target },
        )?;
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 2048 {
            cache.clear();
        }
        cache.insert(ck, (Instant::now(), ok.revocation_ids.clone()));
        Ok(ok.revocation_ids)
    }
}

impl BiscuitMode {
    /// Cached admission check, see [`Trust::admit`].
    fn admit(&self, token: &str, node: &str) -> Result<Vec<String>, String> {
        let ck = format!("admit|{token}|{node}");
        if let Some((at, ids)) = self.cache.lock().unwrap().get(&ck) {
            if at.elapsed() < TOKEN_CACHE_TTL {
                return Ok(ids.clone());
            }
        }
        let ok = a2a_authz::admit(token, &self.root, node)?;
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 2048 {
            cache.clear();
        }
        cache.insert(ck, (Instant::now(), ok.revocation_ids.clone()));
        Ok(ok.revocation_ids)
    }
}
pub struct Trust {
    node_id: String,
    biscuit: Option<BiscuitMode>,
    key: SigningKey,
    /// Enrolled peers (never contains this node).
    peers: Mutex<HashMap<String, VerifyingKey>>,
    /// Newest accepted sequence number per document, for rollback detection (in memory).
    newest: Mutex<HashMap<(Coll, String), i64>>,
    rejections: Mutex<Vec<Rejection>>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Trust {
    pub fn new(node_id: impl Into<String>, key: SigningKey) -> Trust {
        Trust {
            node_id: node_id.into(),
            biscuit: None,
            key,
            peers: Mutex::new(HashMap::new()),
            newest: Mutex::new(HashMap::new()),
            rejections: Mutex::new(Vec::new()),
        }
    }

    /// Load this node's key from `<dir>/node.key`, creating it (and `node.pub`)
    /// on first use. The key file is the base64 of a 32-byte Ed25519 seed.
    pub fn load_or_create(dir: &Path, node_id: &str) -> Result<Trust, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let key_path = dir.join("node.key");
        let key = if key_path.exists() {
            let text = std::fs::read_to_string(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
            let raw = B64.decode(text.trim()).map_err(|e| format!("{}: {e}", key_path.display()))?;
            let seed: [u8; 32] = raw.try_into().map_err(|_| format!("{}: expected a 32-byte seed", key_path.display()))?;
            SigningKey::from_bytes(&seed)
        } else {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| format!("no randomness available: {e}"))?;
            std::fs::write(&key_path, B64.encode(seed)).map_err(|e| format!("{}: {e}", key_path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            SigningKey::from_bytes(&seed)
        };
        let t = Trust::new(node_id, key);
        std::fs::write(dir.join("node.pub"), t.public_key()).map_err(|e| e.to_string())?;
        Ok(t)
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Switch to Biscuit mode: trust any peer holding a token issued by the authority
    /// whose public key is `root_pub_b64`. `own_token` (base64) is this node's token;
    /// it must name this node and its key and be valid now, or the node could not
    /// write anything its peers would accept.
    pub fn with_biscuit(mut self, root_pub_b64: &str, own_token: &str) -> Result<Trust, String> {
        let root = a2a_authz::parse_public_key(root_pub_b64)?;
        let own_key = self.public_key();
        for coll in [Coll::Agents, Coll::Tasks] {
            a2a_authz::authorize(
                own_token.trim(),
                &root,
                &Claim { node: &self.node_id, key_b64: &own_key, collection: coll.name(), target: None },
            )
            .map_err(|e| format!("this node's token is not usable for '{}': {e}", self.node_id))?;
        }
        self.biscuit = Some(BiscuitMode {
            root,
            token: own_token.trim().to_string(),
            revoked: Mutex::new(HashSet::new()),
            cache: Mutex::new(HashMap::new()),
        });
        Ok(self)
    }

    /// `"biscuit"` or `"allowlist"`.
    pub fn mode(&self) -> &'static str {
        if self.biscuit.is_some() {
            "biscuit"
        } else {
            "allowlist"
        }
    }

    /// Refuse tokens with this revocation id (hex, see `a2a-admin inspect`).
    pub fn revoke_token(&self, revocation_id: &str) {
        if let Some(b) = &self.biscuit {
            b.revoked.lock().unwrap().insert(revocation_id.trim().to_lowercase());
        }
    }

    /// Load a deny-list: one hex revocation id per line, `#` comments allowed.
    pub fn load_revocations(&self, path: &Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut n = 0;
        for line in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty()) {
            self.revoke_token(line);
            n += 1;
        }
        Ok(n)
    }

    /// This node's public key, base64. Hand it to the peers that should trust it.
    pub fn public_key(&self) -> String {
        B64.encode(self.key.verifying_key().to_bytes())
    }

    /// Trust `node_id` with the given base64 public key. Replaces an earlier key.
    pub fn enroll(&self, node_id: &str, public_key_b64: &str) -> Result<(), String> {
        let raw = B64.decode(public_key_b64.trim()).map_err(|e| format!("key for '{node_id}': {e}"))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| format!("key for '{node_id}': expected 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(&bytes).map_err(|e| format!("key for '{node_id}': {e}"))?;
        if node_id == self.node_id {
            return if vk == self.key.verifying_key() {
                Ok(())
            } else {
                Err(format!("trust list has a different key for this node ('{node_id}')"))
            };
        }
        self.peers.lock().unwrap().insert(node_id.to_string(), vk);
        Ok(())
    }

    /// Stop trusting a node. Documents it already wrote stay in the database but
    /// are ignored from now on.
    pub fn revoke(&self, node_id: &str) {
        self.peers.lock().unwrap().remove(node_id);
    }

    /// Load `{"nodes": {"alice": "<base64 key>", ...}}` (or the bare map).
    pub fn load_trust_file(&self, path: &Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let nodes = v.get("nodes").unwrap_or(&v).as_object().ok_or_else(|| format!("{}: expected an object", path.display()))?;
        for (id, key) in nodes {
            let key = key.as_str().ok_or_else(|| format!("{}: key for '{id}' must be a string", path.display()))?;
            self.enroll(id, key)?;
        }
        Ok(nodes.len())
    }

    pub fn enrolled(&self) -> Vec<String> {
        let mut v: Vec<String> = self.peers.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }

    pub fn rejections(&self) -> Vec<Rejection> {
        self.rejections.lock().unwrap().clone()
    }

    /// Sign `body` (which must be a JSON object) as this node, in place.
    pub fn sign(&self, coll: Coll, id: &str, body: &mut Value) {
        self.sign_next(coll, id, body, None);
    }

    /// Sign `body` as the next revision of a document whose stored revision carried sequence
    /// number `prev_seq`. The sequence is `max(prev_seq + 1, now)`: it always rises, even if
    /// this node's clock was set back, and for a brand-new document it starts from the clock.
    pub fn sign_next(&self, coll: Coll, id: &str, body: &mut Value, prev_seq: Option<i64>) {
        let seq = prev_seq.map_or_else(now_ms, |p| (p + 1).max(now_ms()));
        self.sign_at(coll, id, body, seq);
    }

    /// The sequence number a stored, signed document carries.
    pub fn seq_of(doc: &Value) -> Option<i64> {
        doc.pointer("/trust/seq").and_then(Value::as_i64)
    }
    #[doc(hidden)] // for tests and tooling that need a specific sequence number
    pub fn sign_at(&self, coll: Coll, id: &str, body: &mut Value, ts: i64) {
        if let Value::Object(m) = body {
            m.remove(META);
        } else {
            return; // left unsigned; verification will reject it
        }
        let sig = self.key.sign(message(coll, id, &self.node_id, ts, &canonical_str(body)).as_bytes());
        if let Value::Object(m) = body {
            let mut meta = serde_json::json!({ "author": self.node_id, "seq": ts, "sig": B64.encode(sig.to_bytes()) });
            if let Some(b) = &self.biscuit {
                // The credential travels with the document: receivers need nothing but the
                // authority's public key to check it.
                meta["token"] = Value::String(b.token.clone());
                meta["key"] = Value::String(self.public_key());
            }
            m.insert(META.into(), meta);
        }
    }

    /// Check a document read from the database. Returns the author on success;
    /// on failure the reason is also recorded (see [`Trust::rejections`]).
    pub fn verify(&self, coll: Coll, id: &str, body: &Value) -> Result<String, Reject> {
        let r = self.verify_inner(coll, id, body);
        if let Err(e) = &r {
            let author = body.pointer("/trust/author").and_then(Value::as_str).map(str::to_owned);
            self.note(coll, id, author, e);
        }
        r
    }

    fn verify_inner(&self, coll: Coll, id: &str, body: &Value) -> Result<String, Reject> {
        if coll == Coll::Revocations {
            // Not a node's document: its proof is the authority's signature.
            return self.verify_revocation_doc(id, body).map(|_| "authority".to_string());
        }
        let m = body.as_object().ok_or(Reject::Malformed("not an object"))?;
        let meta = m.get(META).ok_or(Reject::Unsigned)?;
        let sig_b64 = meta.get("sig").and_then(Value::as_str).ok_or(Reject::Malformed("missing signature"))?;
        let author = meta.get("author").and_then(Value::as_str).ok_or(Reject::Malformed("missing author"))?;
        let ts = meta.get("seq").and_then(Value::as_i64).ok_or(Reject::Malformed("missing seq"))?;

        let mut content = m.clone();
        content.remove(META);
        let content = Value::Object(content);

        let key = self.resolve_key(coll, author, meta, &content)?;
        let raw = B64.decode(sig_b64).map_err(|_| Reject::Malformed("signature encoding"))?;
        let arr: [u8; 64] = raw.try_into().map_err(|_| Reject::Malformed("signature length"))?;
        let sig = Signature::from_bytes(&arr);

        key.verify_strict(message(coll, id, author, ts, &canonical_str(&content)).as_bytes(), &sig)
            .map_err(|_| Reject::BadSignature)?;

        authorize(coll, id, &content, author)?;

        let mut newest = self.newest.lock().unwrap();
        let seen = newest.entry((coll, id.to_string())).or_insert(i64::MIN);
        if ts < *seen {
            return Err(Reject::Rollback { newest: *seen, got: ts });
        }
        *seen = ts;
        Ok(author.to_string())
    }

    /// Check a revocation document and, if it is genuine, start refusing the token it names.
    fn verify_revocation_doc(&self, id: &str, body: &Value) -> Result<(), Reject> {
        let Some(b) = &self.biscuit else {
            return Err(Reject::NotAuthorized("revocations need Biscuit mode".into()));
        };
        let rev = Revocation::from_json(body).map_err(Reject::BadCredential)?;
        if !rev.revoked.eq_ignore_ascii_case(id) {
            return Err(Reject::NotAuthorized("revocation id does not match its document id".into()));
        }
        a2a_authz::verify_revocation(&rev, &b.root).map_err(Reject::BadCredential)?;
        b.revoked.lock().unwrap().insert(rev.revoked.to_lowercase());
        Ok(())
    }

    /// Verify a revocation received out of band (the HTTP endpoint) and apply it.
    pub fn accept_revocation(&self, rev: &Revocation) -> Result<(), String> {
        let b = self.biscuit.as_ref().ok_or("revocations need Biscuit mode")?;
        a2a_authz::verify_revocation(rev, &b.root)?;
        b.revoked.lock().unwrap().insert(rev.revoked.to_lowercase());
        Ok(())
    }

    /// Hex ids of the tokens this node refuses.
    pub fn revoked_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.biscuit.as_ref().map(|b| b.revoked.lock().unwrap().iter().cloned().collect()).unwrap_or_default();
        v.sort();
        v
    }

    /// Biscuit mode: may a peer that presents `password` (its token) as `user` (its node id)
    /// open a connection? Always `false` outside Biscuit mode (there is nothing to check).
    pub fn admit(&self, user: &str, password: &str) -> bool {
        let Some(b) = &self.biscuit else { return false };
        let result = b.admit(password.trim(), user).and_then(|ids| {
            let revoked = b.revoked.lock().unwrap();
            match ids.iter().find(|i| revoked.contains(*i)) {
                Some(id) => Err(format!("token revoked ({id})")),
                None => Ok(()),
            }
        });
        match result {
            Ok(()) => true,
            Err(e) => {
                self.note_raw("connection", user, None, format!("connection refused: {e}"));
                false
            }
        }
    }

    /// Biscuit mode: the `(node id, token)` this node presents when it dials a peer.
    pub fn credential(&self) -> Option<(String, String)> {
        self.biscuit.as_ref().map(|b| (self.node_id.clone(), b.token.clone()))
    }
    /// The key to verify `author`'s signature with: our own, the enrolled key
    /// (allowlist mode), or the key named by a valid token (Biscuit mode).
    fn resolve_key(&self, coll: Coll, author: &str, meta: &Value, content: &Value) -> Result<VerifyingKey, Reject> {
        if author == self.node_id {
            return Ok(self.key.verifying_key());
        }
        let Some(b) = &self.biscuit else {
            return self.key_for(author).ok_or_else(|| Reject::UnknownAuthor(author.to_string()));
        };
        let token = meta.get("token").and_then(Value::as_str).ok_or_else(|| Reject::NoCredential(author.to_string()))?;
        let key_b64 = meta.get("key").and_then(Value::as_str).ok_or(Reject::Malformed("missing key"))?;
        let target = if coll == Coll::Inbox { content.get("to").and_then(Value::as_str) } else { None };
        let ids = b.check(token, author, key_b64, coll, target).map_err(Reject::BadCredential)?;
        {
            let revoked = b.revoked.lock().unwrap();
            if let Some(id) = ids.iter().find(|i| revoked.contains(*i)) {
                return Err(Reject::BadCredential(format!("token revoked ({id})")));
            }
        }
        let raw = B64.decode(key_b64).map_err(|_| Reject::Malformed("key encoding"))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| Reject::Malformed("key length"))?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| Reject::Malformed("key"))
    }

    fn key_for(&self, author: &str) -> Option<VerifyingKey> {
        if author == self.node_id {
            Some(self.key.verifying_key())
        } else {
            self.peers.lock().unwrap().get(author).copied()
        }
    }

    fn note(&self, coll: Coll, id: &str, author: Option<String>, why: &Reject) {
        self.note_reason(coll, id, author, why.to_string());
    }
    /// Record that a tampered or deleted document was answered from, and rewritten as,
    /// the last verified copy.
    pub fn note_restored(&self, coll: Coll, id: &str, deleted: bool) {
        let reason = if deleted {
            "deleted by a peer; restored the last verified copy"
        } else {
            "overwritten by an invalid revision; restored the last verified copy"
        };
        self.note_reason(coll, id, None, reason.to_string());
    }

    fn note_reason(&self, coll: Coll, id: &str, author: Option<String>, reason: String) {
        self.note_raw(coll.name(), id, author, reason);
    }

    fn note_raw(&self, collection: &str, id: &str, author: Option<String>, reason: String) {
        let now = now_ms();
        let mut list = self.rejections.lock().unwrap();
        if let Some(r) = list
            .iter_mut()
            .find(|r| r.collection == collection && r.doc_id == id && r.reason == reason && r.author == author)
        {
            r.count += 1;
            r.last_at = now;
            return;
        }
        log::warn!("rejected {collection}/{id}{}: {reason}", author.as_deref().map(|a| format!(" (author {a})")).unwrap_or_default());
        if list.len() >= MAX_REJECTIONS {
            list.remove(0);
        }
        list.push(Rejection {
            first_at: now,
            last_at: now,
            count: 1,
            collection: collection.into(),
            doc_id: id.into(),
            author,
            reason,
        });
    }
}

/// May `author` write this kind of document?
fn authorize(coll: Coll, id: &str, content: &Value, author: &str) -> Result<(), Reject> {
    let field = |name: &str| content.get(name).and_then(Value::as_str);
    let ok = |cond: bool, msg: String| if cond { Ok(()) } else { Err(Reject::NotAuthorized(msg)) };
    match coll {
        Coll::Agents => ok(
            id == author && field("nodeId") == Some(author),
            format!("'{author}' may only publish its own agent card, not '{id}'"),
        ),
        Coll::Tasks => ok(
            field("owner") == Some(author),
            format!("'{author}' is not the owner of this task ({:?})", field("owner")),
        ),
        Coll::Revocations => Ok(()), // checked by `verify_revocation_doc` before this is reached
        Coll::Inbox => ok(
            field("from") == Some(author),
            format!("'{author}' cannot issue a command from '{}'", field("from").unwrap_or("?")),
        ),
    }
}

/// The exact bytes that are signed. Binds the collection and id (so a document
/// cannot be copied to another id) and the author and timestamp.
fn message(coll: Coll, id: &str, author: &str, ts: i64, canon: &str) -> String {
    format!("{DOMAIN}\n{}\n{id}\n{author}\n{ts}\n{canon}", coll.name())
}

fn canonical_str(v: &Value) -> String {
    let mut s = String::new();
    canonical(v, &mut s);
    s
}

/// Deterministic JSON: object keys sorted, no whitespace, and whole-number
/// floats written as integers (Fleece may store `1.0` as `1`).
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                if let Some(f) = n.as_f64() {
                    if f.fract() == 0.0 && f.abs() < 9.0e15 {
                        out.push_str(&(f as i64).to_string());
                        return;
                    }
                }
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap()),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                canonical(&m[*k], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(name: &str, seed: u8) -> Trust {
        Trust::new(name, SigningKey::from_bytes(&[seed; 32]))
    }

    /// bob trusts alice (and only alice).
    fn pair() -> (Trust, Trust) {
        let (alice, bob) = (node("alice", 1), node("bob", 2));
        bob.enroll("alice", &alice.public_key()).unwrap();
        alice.enroll("bob", &bob.public_key()).unwrap();
        (alice, bob)
    }

    fn command(from: &str, to: &str) -> Value {
        json!({ "kind": "send", "taskId": "t1", "contextId": "c1", "to": to, "from": from, "ts": 5 })
    }

    #[test]
    fn accepts_a_signed_document_from_an_enrolled_peer() {
        let (alice, bob) = pair();
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Ok("alice".into()));
    }

    #[test]
    fn accepts_own_documents() {
        let (alice, _) = pair();
        let mut d = json!({ "nodeId": "alice", "ts": 1 });
        alice.sign(Coll::Agents, "alice", &mut d);
        assert_eq!(alice.verify(Coll::Agents, "alice", &d), Ok("alice".into()));
    }

    #[test]
    fn rejects_unsigned_documents() {
        let (_, bob) = pair();
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &command("alice", "bob")), Err(Reject::Unsigned));
    }

    #[test]
    fn rejects_a_forged_document_from_an_unenrolled_node() {
        let (_, bob) = pair();
        let mallory = node("mallory", 9);
        let mut d = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::UnknownAuthor("mallory".into())));
    }

    #[test]
    fn rejects_an_impersonator_signing_as_alice_with_their_own_key() {
        let (_, bob) = pair();
        // mallory claims to be alice but only has her own key
        let mallory = Trust::new("alice", SigningKey::from_bytes(&[9; 32]));
        let mut d = command("alice", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::BadSignature));
    }

    #[test]
    fn rejects_a_tampered_document() {
        let (alice, bob) = pair();
        let mut d = json!({ "owner": "alice", "task": { "state": "TASK_STATE_WORKING" } });
        alice.sign(Coll::Tasks, "t1", &mut d);
        d["task"]["state"] = json!("TASK_STATE_COMPLETED");
        assert_eq!(bob.verify(Coll::Tasks, "t1", &d), Err(Reject::BadSignature));
    }

    #[test]
    fn rejects_a_document_copied_to_another_id_or_collection() {
        let (alice, bob) = pair();
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert_eq!(bob.verify(Coll::Inbox, "send::t2", &d), Err(Reject::BadSignature));
        assert!(bob.verify(Coll::Tasks, "send::t1", &d).is_err());
    }

    #[test]
    fn enforces_who_may_write_what() {
        let (alice, bob) = pair();
        // an agent card for someone else
        let mut card = json!({ "nodeId": "bob", "card": {} });
        alice.sign(Coll::Agents, "bob", &mut card);
        assert!(matches!(bob.verify(Coll::Agents, "bob", &card), Err(Reject::NotAuthorized(_))));
        // a task claiming bob as owner
        let mut task = json!({ "owner": "bob", "task": {} });
        alice.sign(Coll::Tasks, "t1", &mut task);
        assert!(matches!(bob.verify(Coll::Tasks, "t1", &task), Err(Reject::NotAuthorized(_))));
        // a command issued "from" bob
        let mut cmd = command("bob", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &cmd), Err(Reject::NotAuthorized(_))));
    }

    #[test]
    fn detects_a_rollback_to_an_older_revision() {
        let (alice, bob) = pair();
        let mut old = json!({ "owner": "alice", "n": 1 });
        let mut new = json!({ "owner": "alice", "n": 2 });
        alice.sign_at(Coll::Tasks, "t1", &mut old, 1000);
        alice.sign_at(Coll::Tasks, "t1", &mut new, 2000);
        assert!(bob.verify(Coll::Tasks, "t1", &new).is_ok());
        assert_eq!(bob.verify(Coll::Tasks, "t1", &old), Err(Reject::Rollback { newest: 2000, got: 1000 }));
        assert!(bob.verify(Coll::Tasks, "t1", &new).is_ok(), "the current revision still verifies");
    }

    #[test]
    fn a_clock_set_back_does_not_make_a_node_look_like_a_rollback() {
        let (alice, bob) = pair();
        // a revision written while alice's clock ran an hour ahead
        let ahead = now_ms() + 3_600_000;
        let mut first = json!({ "owner": "alice", "n": 1 });
        alice.sign_at(Coll::Tasks, "t1", &mut first, ahead);
        assert!(bob.verify(Coll::Tasks, "t1", &first).is_ok());

        // alice restarts with the clock back to normal; the next revision continues from the stored one
        let mut next = json!({ "owner": "alice", "n": 2 });
        alice.sign_next(Coll::Tasks, "t1", &mut next, Trust::seq_of(&first));
        assert_eq!(Trust::seq_of(&next), Some(ahead + 1));
        assert!(bob.verify(Coll::Tasks, "t1", &next).is_ok());

        // the clock alone would have been rejected as a rollback
        let mut by_clock = json!({ "owner": "alice", "n": 3 });
        alice.sign_at(Coll::Tasks, "t1", &mut by_clock, now_ms());
        assert!(matches!(bob.verify(Coll::Tasks, "t1", &by_clock), Err(Reject::Rollback { .. })));

        // a document with no stored revision (fresh database) starts from the clock
        let mut fresh = json!({ "owner": "alice" });
        alice.sign_next(Coll::Tasks, "t2", &mut fresh, None);
        assert!(Trust::seq_of(&fresh).unwrap() >= now_ms() - 5_000);
    }

    #[test]
    fn revoking_a_node_stops_accepting_its_documents() {
        let (alice, bob) = pair();
        let mut d = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut d);
        assert!(bob.verify(Coll::Inbox, "send::t1", &d).is_ok());
        bob.revoke("alice");
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &d), Err(Reject::UnknownAuthor("alice".into())));
    }

    #[test]
    fn records_each_distinct_rejection_once_with_a_count() {
        let (_, bob) = pair();
        let d = command("alice", "bob");
        for _ in 0..3 {
            let _ = bob.verify(Coll::Inbox, "send::t1", &d);
        }
        let r = bob.rejections();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].count, 3);
        assert_eq!(r[0].reason, "unsigned document");
    }

    #[test]
    fn signatures_survive_key_reordering_and_integer_floats() {
        let (alice, bob) = pair();
        let mut d: Value = serde_json::from_str(r#"{"owner":"alice","b":1.0,"a":{"y":2,"x":[1,2.0]}}"#).unwrap();
        alice.sign(Coll::Tasks, "t1", &mut d);
        // what the database might hand back: other key order, floats stored as ints
        let mut back: Value = serde_json::from_str(r#"{"a":{"x":[1,2],"y":2},"b":1,"owner":"alice"}"#).unwrap();
        back["trust"] = d["trust"].clone();
        assert!(bob.verify(Coll::Tasks, "t1", &back).is_ok());
    }

    #[test]
    fn keys_and_trust_files_round_trip() {
        let dir = std::env::temp_dir().join(format!("a2a-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = Trust::load_or_create(&dir, "alice").unwrap();
        let again = Trust::load_or_create(&dir, "alice").unwrap();
        assert_eq!(a.public_key(), again.public_key(), "the key is persisted");

        let file = dir.join("trust.json");
        std::fs::write(&file, format!(r#"{{"nodes":{{"bob":"{}","alice":"{}"}}}}"#, node("bob", 2).public_key(), a.public_key())).unwrap();
        assert_eq!(a.load_trust_file(&file).unwrap(), 2);
        assert_eq!(a.enrolled(), vec!["bob".to_string()], "this node is not listed as a peer");

        std::fs::write(&file, format!(r#"{{"alice":"{}"}}"#, node("x", 7).public_key())).unwrap();
        assert!(a.load_trust_file(&file).is_err(), "a different key for our own id is refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Biscuit mode --------------------------------------------------------

    use a2a_authz::{attenuate, Attenuation, Authority, Grant};

    fn grant_for(t: &Trust, targets: &[&str]) -> Grant {
        Grant {
            node: t.node_id().into(),
            node_key_b64: t.public_key(),
            inbox_targets: targets.iter().map(|s| s.to_string()).collect(),
            expires: None,
        }
    }

    /// A node holding a token from `auth` that lets it message `targets`.
    fn token_node(auth: &Authority, name: &str, seed: u8, targets: &[&str]) -> Trust {
        let t = node(name, seed);
        let token = auth.issue(&grant_for(&t, targets)).unwrap();
        t.with_biscuit(&auth.public_b64(), &token).unwrap()
    }

    #[test]
    fn biscuit_accepts_a_peer_whose_token_allows_the_document() {
        let auth = Authority::generate();
        let (alice, bob) = (token_node(&auth, "alice", 1, &["bob"]), token_node(&auth, "bob", 2, &["alice"]));
        assert_eq!(bob.mode(), "biscuit");
        assert!(bob.rejections().is_empty());

        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &cmd), Ok("alice".into()));

        let mut card = json!({ "nodeId": "alice", "card": {} });
        alice.sign(Coll::Agents, "alice", &mut card);
        assert!(bob.verify(Coll::Agents, "alice", &card).is_ok());
    }

    #[test]
    fn biscuit_refuses_a_peer_with_no_token() {
        let auth = Authority::generate();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mallory = node("mallory", 9); // signs, but has no credential
        let mut cmd = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &cmd), Err(Reject::NoCredential("mallory".into())));
    }

    #[test]
    fn biscuit_refuses_a_token_from_a_different_authority() {
        let real = Authority::generate();
        let fake = Authority::generate();
        let bob = token_node(&real, "bob", 2, &["*"]);
        let mallory = token_node(&fake, "mallory", 9, &["*"]);
        let mut cmd = command("mallory", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &cmd), Err(Reject::BadCredential(_))));
    }

    #[test]
    fn biscuit_limits_who_a_node_may_message() {
        let auth = Authority::generate();
        let carol = token_node(&auth, "carol", 3, &["bob"]); // may only message bob
        let (alice, bob) = (token_node(&auth, "alice", 1, &["*"]), token_node(&auth, "bob", 2, &["*"]));
        let mut to_bob = command("carol", "bob");
        carol.sign(Coll::Inbox, "send::t1", &mut to_bob);
        assert!(bob.verify(Coll::Inbox, "send::t1", &to_bob).is_ok());
        let mut to_alice = command("carol", "alice");
        carol.sign(Coll::Inbox, "send::t2", &mut to_alice);
        let r = alice.verify(Coll::Inbox, "send::t2", &to_alice);
        assert!(matches!(r, Err(Reject::BadCredential(_))), "{r:?}");
        // and she still may publish her own card and task state
        let mut card = json!({ "nodeId": "carol", "card": {} });
        carol.sign(Coll::Agents, "carol", &mut card);
        assert!(alice.verify(Coll::Agents, "carol", &card).is_ok());
    }

    #[test]
    fn a_stolen_token_is_useless_without_the_key() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut real = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut real);
        let stolen_token = real["trust"]["token"].clone();
        let alice_key = real["trust"]["key"].clone();

        // mallory poses as alice with her own key and alice's token
        let mallory = Trust::new("alice", SigningKey::from_bytes(&[9; 32]));
        let mut forged = command("alice", "bob");
        mallory.sign(Coll::Inbox, "send::t1", &mut forged);
        forged["trust"]["token"] = stolen_token.clone();
        forged["trust"]["key"] = Value::String(mallory.public_key());
        assert!(matches!(bob.verify(Coll::Inbox, "send::t1", &forged), Err(Reject::BadCredential(_))), "token names alice's key");

        forged["trust"]["key"] = alice_key; // claim alice's key instead: the signature then fails
        assert_eq!(bob.verify(Coll::Inbox, "send::t1", &forged), Err(Reject::BadSignature));
    }

    #[test]
    fn biscuit_revocation_cuts_a_node_off() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(bob.verify(Coll::Inbox, "send::t1", &cmd).is_ok());

        let id = a2a_authz::authorize(
            cmd["trust"]["token"].as_str().unwrap(),
            &a2a_authz::parse_public_key(&auth.public_b64()).unwrap(),
            &a2a_authz::Claim { node: "alice", key_b64: &alice.public_key(), collection: "tasks", target: None },
        )
        .unwrap()
        .revocation_ids[0]
            .clone();
        bob.revoke_token(&id);
        let r = bob.verify(Coll::Inbox, "send::t1", &cmd);
        assert!(matches!(&r, Err(Reject::BadCredential(m)) if m.contains("revoked")), "{r:?}");
    }

    #[test]
    fn a_node_cannot_start_with_a_token_it_could_not_use() {
        let auth = Authority::generate();
        let a = node("alice", 1);
        // expired
        let mut g = grant_for(&a, &["*"]);
        g.expires = Some(std::time::SystemTime::now() - Duration::from_secs(60));
        assert!(node("alice", 1).with_biscuit(&auth.public_b64(), &auth.issue(&g).unwrap()).is_err());
        // issued for someone else's key
        let other = node("alice", 7);
        let t = auth.issue(&grant_for(&other, &["*"])).unwrap();
        assert!(node("alice", 1).with_biscuit(&auth.public_b64(), &t).is_err());
        // issued for another node id
        let t = auth.issue(&grant_for(&node("zed", 1), &["*"])).unwrap();
        assert!(node("alice", 1).with_biscuit(&auth.public_b64(), &t).is_err());
    }

    #[test]
    fn a_narrowed_token_is_enforced_by_receivers() {
        let auth = Authority::generate();
        let a = node("alice", 1);
        let full = auth.issue(&grant_for(&a, &["*"])).unwrap();
        let root = a2a_authz::parse_public_key(&auth.public_b64()).unwrap();
        // alice hands herself (or a helper) a token that only reaches hq
        let narrowed = attenuate(&full, &root, &Attenuation { inbox_targets: Some(vec!["hq".into()]), ..Default::default() }).unwrap();
        let alice = node("alice", 1).with_biscuit(&auth.public_b64(), &narrowed).unwrap();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut to_hq = command("alice", "hq");
        alice.sign(Coll::Inbox, "send::t1", &mut to_hq);
        assert!(bob.verify(Coll::Inbox, "send::t1", &to_hq).is_ok());
        let mut to_bob = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t2", &mut to_bob);
        assert!(matches!(bob.verify(Coll::Inbox, "send::t2", &to_bob), Err(Reject::BadCredential(_))));
    }

    #[test]
    fn an_authority_signed_revocation_document_cuts_a_node_off() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        assert!(bob.verify(Coll::Inbox, "send::t1", &cmd).is_ok());
        assert!(bob.revoked_ids().is_empty());

        // the authority revokes alice's token; the document reaches bob by replication
        let rev = auth.revoke(cmd["trust"]["token"].as_str().unwrap(), "tablet lost").unwrap();
        let doc = rev.to_json();
        assert_eq!(bob.verify(Coll::Revocations, &rev.revoked, &doc), Ok("authority".into()));
        assert_eq!(bob.revoked_ids(), vec![rev.revoked.clone()]);

        let r = bob.verify(Coll::Inbox, "send::t1", &cmd);
        assert!(matches!(&r, Err(Reject::BadCredential(m)) if m.contains("revoked")), "{r:?}");
    }

    #[test]
    fn a_forged_misplaced_or_unsupported_revocation_is_ignored() {
        let auth = Authority::generate();
        let impostor = Authority::generate();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let mut cmd = command("alice", "bob");
        alice.sign(Coll::Inbox, "send::t1", &mut cmd);
        let token = cmd["trust"]["token"].as_str().unwrap().to_string();

        // signed by someone who is not the authority
        let id = auth.revoke(&token, "x").unwrap().revoked;
        let forged = impostor.revoke_id(&id, "mallory says so").unwrap();
        assert!(matches!(bob.verify(Coll::Revocations, &id, &forged.to_json()), Err(Reject::BadCredential(_))));
        // a genuine one stored under a different document id
        let real = auth.revoke(&token, "x").unwrap();
        assert!(matches!(bob.verify(Coll::Revocations, "somethingelse", &real.to_json()), Err(Reject::NotAuthorized(_))));
        assert!(bob.revoked_ids().is_empty(), "nothing was applied");
        assert!(bob.verify(Coll::Inbox, "send::t1", &cmd).is_ok(), "alice is still accepted");

        // allowlist mode has no authority, so it never honours revocation documents
        let plain = node("carol", 3);
        assert!(matches!(plain.verify(Coll::Revocations, &real.revoked, &real.to_json()), Err(Reject::NotAuthorized(_))));
    }

    #[test]
    fn admission_accepts_valid_tokens_and_refuses_revoked_or_foreign_ones() {
        let auth = Authority::generate();
        let alice = token_node(&auth, "alice", 1, &["*"]);
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let (user, token) = alice.credential().unwrap();
        assert_eq!(user, "alice");
        assert!(bob.admit(&user, &token), "a genuine token admits its node");
        assert!(!bob.admit("mallory", &token), "someone else's token is not admitted under another name");
        assert!(!bob.admit(&user, "not a token"));
        let fake = token_node(&Authority::generate(), "alice", 1, &["*"]);
        assert!(!bob.admit("alice", &fake.credential().unwrap().1), "token from another authority");

        bob.accept_revocation(&auth.revoke(&token, "lost").unwrap()).unwrap();
        assert!(!bob.admit(&user, &token), "a revoked token is refused at the door");
        assert!(bob.rejections().iter().any(|r| r.collection == "connection" && r.reason.contains("revoked")));
        // and there is nothing to admit against without Biscuit
        assert!(!node("zed", 9).admit("zed", &token));
        assert!(node("zed", 9).credential().is_none());
    }
    #[test]
    fn revocation_lists_load_from_a_file() {
        let auth = Authority::generate();
        let bob = token_node(&auth, "bob", 2, &["*"]);
        let dir = std::env::temp_dir().join(format!("a2a-revoked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("revoked.txt");
        std::fs::write(&f, "# lost tablet\nAABBCC # inline comment\n\nddeeff\n").unwrap();
        assert_eq!(bob.load_revocations(&f).unwrap(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
