//! A peer that is allowed to replicate can overwrite or delete documents. These
//! tests play the peer by writing to the database directly (which is exactly
//! what replication does to it) and check that a secured node keeps answering
//! from, and restores, the last verified copy.

use std::sync::Arc;
use std::time::Duration;

use a2a_cblite::docs::{Coll, Docs, SCOPE};
use a2a_cblite::trust::Trust;
use couchbase_lite::{Database, DatabaseConfiguration, Document};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

fn raw_write(db: &Database, c: Coll, id: &str, body: &Value) {
    let mut coll = db.create_collection(c.name().to_string(), SCOPE.to_string()).unwrap();
    let mut doc = coll.get_document(id).unwrap_or_else(|_| Document::new_with_id(id));
    doc.set_properties_as_json(&body.to_string()).unwrap();
    coll.save_document(&mut doc).unwrap();
}

fn raw_read(db: &Database, c: Coll, id: &str) -> Option<Value> {
    let coll = db.create_collection(c.name().to_string(), SCOPE.to_string()).unwrap();
    coll.get_document(id).ok().map(|d| serde_json::from_str(&d.properties_as_json()).unwrap())
}

fn raw_delete(db: &Database, c: Coll, id: &str) {
    let mut coll = db.create_collection(c.name().to_string(), SCOPE.to_string()).unwrap();
    let doc = coll.get_document(id).unwrap();
    coll.delete_document(&doc).unwrap();
}

fn restored_events(t: &Trust) -> usize {
    t.rejections().iter().filter(|r| r.reason.contains("restored the last verified copy")).count()
}

struct Env {
    db: Database,
    docs: Docs,
    alice: Arc<Trust>,
    bob: Trust,
    dir: std::path::PathBuf,
}

fn setup(tag: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("a2a-tamper-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Database::open(
        "t",
        Some(DatabaseConfiguration {
            directory: &dir,
            #[cfg(feature = "enterprise")]
            encryption_key: None,
        }),
    )
    .unwrap();
    let alice = Arc::new(Trust::new("alice", SigningKey::from_bytes(&[1; 32])));
    let bob = Trust::new("bob", SigningKey::from_bytes(&[2; 32]));
    alice.enroll("bob", &bob.public_key()).unwrap();
    let docs = Docs::spawn_secure(db.clone(), alice.clone()).unwrap();
    Env { db, docs, alice, bob, dir }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn an_overwritten_own_document_is_served_and_restored() {
    let e = setup("own-overwrite");
    e.docs.put(Coll::Tasks, "t1", json!({ "owner": "alice", "n": 1 })).await.unwrap();
    let original = raw_read(&e.db, Coll::Tasks, "t1").unwrap();

    raw_write(&e.db, Coll::Tasks, "t1", &json!({ "owner": "alice", "n": 999 })); // unsigned
    let got = e.docs.get(Coll::Tasks, "t1").await.unwrap().unwrap();
    assert_eq!(got["n"], 1, "answered from the last verified copy");
    assert_eq!(raw_read(&e.db, Coll::Tasks, "t1").unwrap(), original, "and written back unchanged");
    assert!(restored_events(&e.alice) >= 1);
}

#[tokio::test]
async fn a_deleted_own_document_comes_back() {
    let e = setup("own-delete");
    e.docs.put(Coll::Tasks, "t2", json!({ "owner": "alice", "n": 2 })).await.unwrap();
    let original = raw_read(&e.db, Coll::Tasks, "t2").unwrap();

    raw_delete(&e.db, Coll::Tasks, "t2");
    // a deleted document reads back as absent or as an empty tombstone body, depending on the binding`n    assert!(raw_read(&e.db, Coll::Tasks, "t2").map_or(true, |v| v.as_object().map_or(true, |o| o.is_empty())));
    let got = e.docs.get(Coll::Tasks, "t2").await.unwrap().unwrap();
    assert_eq!(got["n"], 2);
    assert_eq!(raw_read(&e.db, Coll::Tasks, "t2").unwrap(), original);
}

#[tokio::test]
async fn any_honest_node_restores_a_peers_document_without_its_key() {
    let e = setup("peer");
    let mut card = json!({ "nodeId": "bob", "card": { "name": "bob" } });
    e.bob.sign(Coll::Agents, "bob", &mut card);
    raw_write(&e.db, Coll::Agents, "bob", &card); // as if replicated from bob
    assert_eq!(e.docs.get(Coll::Agents, "bob").await.unwrap().unwrap(), card);

    raw_write(&e.db, Coll::Agents, "bob", &json!({ "nodeId": "bob", "card": { "evil": true } }));
    let got = e.docs.get(Coll::Agents, "bob").await.unwrap().unwrap();
    assert_eq!(got, card, "alice answers with bob's original, signed by bob");
    assert_eq!(raw_read(&e.db, Coll::Agents, "bob").unwrap(), card, "alice wrote bob's own signed bytes back; she never needed bob's key");
}

#[tokio::test]
async fn a_rollback_to_an_older_valid_revision_is_undone() {
    let e = setup("rollback");
    let mut old = json!({ "nodeId": "bob2", "card": { "v": 1 } });
    let mut new = json!({ "nodeId": "bob2", "card": { "v": 2 } });
    // bob2 is not enrolled, so use bob's own id for the card but different document ids per revision
    old["nodeId"] = json!("bob");
    new["nodeId"] = json!("bob");
    e.bob.sign_at(Coll::Agents, "bob", &mut old, 1000);
    e.bob.sign_at(Coll::Agents, "bob", &mut new, 2000);
    raw_write(&e.db, Coll::Agents, "bob", &new);
    assert_eq!(e.docs.get(Coll::Agents, "bob").await.unwrap().unwrap()["card"]["v"], 2);

    raw_write(&e.db, Coll::Agents, "bob", &old); // validly signed, but older
    assert_eq!(e.docs.get(Coll::Agents, "bob").await.unwrap().unwrap()["card"]["v"], 2);
    assert_eq!(raw_read(&e.db, Coll::Agents, "bob").unwrap()["card"]["v"], 2);
}

#[tokio::test]
async fn a_deleted_peer_document_still_appears_in_listings_and_returns() {
    let e = setup("list");
    let mut card = json!({ "nodeId": "bob", "card": {} });
    e.bob.sign(Coll::Agents, "bob", &mut card);
    raw_write(&e.db, Coll::Agents, "bob", &card);
    assert_eq!(e.docs.list(Coll::Agents).await.unwrap().len(), 1);

    raw_delete(&e.db, Coll::Agents, "bob");
    let listed = e.docs.list(Coll::Agents).await.unwrap();
    assert_eq!(listed.len(), 1, "the deleted card is still listed");
    assert_eq!(listed[0].1, card);
    assert_eq!(raw_read(&e.db, Coll::Agents, "bob").unwrap(), card, "and it was put back");
}

#[tokio::test]
async fn tampering_is_repaired_even_when_nobody_reads_the_document() {
    let e = setup("watch");
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    e.docs.watch(Coll::Tasks, tx).await.unwrap();
    e.docs.put(Coll::Tasks, "t3", json!({ "owner": "alice", "n": 3 })).await.unwrap();
    let original = raw_read(&e.db, Coll::Tasks, "t3").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    raw_write(&e.db, Coll::Tasks, "t3", &json!({ "owner": "alice", "n": 666 }));
    tokio::time::sleep(Duration::from_millis(800)).await; // no get(): only the change notification
    assert_eq!(raw_read(&e.db, Coll::Tasks, "t3").unwrap(), original);
}

#[tokio::test]
async fn a_revoked_authors_documents_stop_being_served_and_are_not_restored() {
    use a2a_authz::{Authority, Grant};
    let dir = std::env::temp_dir().join(format!("a2a-tamper-revoked-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Database::open(
        "t",
        Some(DatabaseConfiguration {
            directory: &dir,
            #[cfg(feature = "enterprise")]
            encryption_key: None,
        }),
    )
    .unwrap();
    let auth = Authority::generate();
    let node = |name: &str, seed: u8| {
        let t = Trust::new(name, SigningKey::from_bytes(&[seed; 32]));
        let token = auth
            .issue(&Grant { node: name.into(), node_key_b64: t.public_key(), inbox_targets: vec!["*".into()], expires: None })
            .unwrap();
        (t.with_biscuit(&auth.public_b64(), &token).unwrap(), token)
    };
    let (alice, _) = node("alice", 1);
    let (bob, bob_token) = node("bob", 2);
    let alice = Arc::new(alice);
    let docs = Docs::spawn_secure(db.clone(), alice.clone()).unwrap();

    let mut card = json!({ "nodeId": "bob", "card": {} });
    bob.sign(Coll::Agents, "bob", &mut card);
    raw_write(&db, Coll::Agents, "bob", &card);
    assert_eq!(docs.get(Coll::Agents, "bob").await.unwrap().unwrap(), card);

    // the authority revokes bob's token; alice learns of it
    alice.accept_revocation(&auth.revoke(&bob_token, "lost").unwrap()).unwrap();

    // bob's card is now invalid, not tampered with: it must not be served from the saved copy
    assert!(docs.get(Coll::Agents, "bob").await.unwrap().is_none());
    assert!(docs.list(Coll::Agents).await.unwrap().is_empty());
    assert_eq!(raw_read(&db, Coll::Agents, "bob").unwrap(), card, "and nothing was rewritten");
    assert_eq!(restored_events(&alice), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_document_we_never_verified_cannot_be_conjured_up() {
    let e = setup("never");
    // garbage that arrives before any good copy exists is just absent
    raw_write(&e.db, Coll::Tasks, "ghost", &json!({ "owner": "alice", "n": 1 }));
    assert!(e.docs.get(Coll::Tasks, "ghost").await.unwrap().is_none());
    assert!(e.docs.list(Coll::Tasks).await.unwrap().is_empty());
}
