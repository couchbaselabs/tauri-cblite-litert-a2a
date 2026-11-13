//! The A2A task engine: routing between nodes through replicated collections.
//!
//! ```text
//!   client ──SendMessage──▶ node A (origin)
//!                              │ writes  inbox/send::<task>   (to = B)
//!                              ▼            ... Couchbase Lite P2P replication ...
//!                           node B (owner)  sees the inbox doc, runs its executor,
//!                              │ writes  tasks/<task>  on every state change
//!                              ▼            ... replication back ...
//!   client ◀─GetTask/stream── node A  serves the task from its own replica
//! ```
//!
//! Because the transport is a replicated database, requests are
//! store-and-forward: if B is offline when A writes the request, B picks it up
//! when the two next connect.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, watch};

use crate::docs::{Coll, Docs};
use crate::executor::{ExecContext, ExecEvent, Executor};
use crate::protocol::*;

const HEARTBEAT: Duration = Duration::from_secs(30);
/// An agent is shown as online if its card was refreshed this recently.
pub const ONLINE_WINDOW_MS: i64 = 90_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskDoc {
    task: Task,
    owner: String,
    origin: String,
    #[serde(default)]
    processed_cmds: Vec<String>,
    ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Command {
    /// `send` | `message` | `cancel`
    kind: String,
    task_id: String,
    context_id: String,
    to: String,
    from: String,
    #[serde(default)]
    message: Option<Message>,
    ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDoc {
    pub node_id: String,
    pub card: AgentCard,
    pub ts: i64,
}

impl AgentDoc {
    pub fn online(&self) -> bool {
        now_ms() - self.ts < ONLINE_WINDOW_MS
    }
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Lets the HTTP side cut and restore this node's outgoing peer connections while it keeps running
/// (the node binary implements it; a library user with no P2P simply never sets one).
pub trait LinkControl: Send + Sync {
    /// `false`: stop dialing every peer. `true`: dial them again.
    fn set(&self, up: bool) -> Result<(), String>;
    fn is_up(&self) -> bool;
}

pub struct Hub {
    pub node_id: String,
    pub docs: Docs,
    card: AgentCard,
    executor: Arc<dyn Executor>,
    changes: broadcast::Sender<String>,
    write_lock: tokio::sync::Mutex<()>,
    running: Mutex<HashMap<String, watch::Sender<bool>>>,
    seen_cmds: Mutex<HashSet<String>>,
    link: Mutex<Option<Arc<dyn LinkControl>>>,
    posture: Mutex<Value>,
}

impl Hub {
    /// Start the node: publish its card, begin processing the inbox and
    /// forwarding task changes.
    pub async fn start(
        docs: Docs,
        node_id: String,
        mut card: AgentCard,
        executor: Arc<dyn Executor>,
    ) -> Result<Arc<Hub>, String> {
        card.skills = executor.skills();
        let (changes, _) = broadcast::channel(1024);
        let hub = Arc::new(Hub {
            node_id,
            docs,
            card,
            executor,
            changes,
            write_lock: tokio::sync::Mutex::new(()),
            running: Mutex::new(HashMap::new()),
            seen_cmds: Mutex::new(HashSet::new()),
            link: Mutex::new(None),
            posture: Mutex::new(Value::Null),
        });

        // Task changes (local or replicated) -> broadcast for waiters/streams.
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        hub.docs.watch(Coll::Tasks, tx).await?;
        let h = hub.clone();
        tokio::spawn(async move {
            while let Some(id) = rx.recv().await {
                let _ = h.changes.send(id);
            }
        });

        // Inbox: register the watcher first, then scan what is already there, so
        // nothing that arrives in between is missed.
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        hub.docs.watch(Coll::Inbox, tx).await?;
        let h = hub.clone();
        tokio::spawn(async move {
            match h.docs.list(Coll::Inbox).await {
                Ok(existing) => {
                    for (id, v) in existing {
                        h.clone().process_cmd(id, v).await;
                    }
                }
                Err(e) => log::error!("inbox scan failed: {e}"),
            }
            while let Some(id) = rx.recv().await {
                if let Ok(Some(v)) = h.docs.get(Coll::Inbox, &id).await {
                    h.clone().process_cmd(id, v).await;
                }
            }
        });

        // Publish the card now and keep it fresh.
        hub.publish_card().await?;
        let h = hub.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT).await;
                if let Err(e) = h.publish_card().await {
                    log::warn!("card heartbeat failed: {e}");
                }
            }
        });

        Ok(hub)
    }

    pub fn set_link_control(&self, l: Arc<dyn LinkControl>) {
        *self.link.lock().unwrap() = Some(l);
    }

    /// What protects this node beyond the signed documents (TLS, pinning, admission, encryption at rest),
    /// reported by the node binary and shown by the dashboard and `GET /security`.
    pub fn set_posture(&self, v: Value) {
        *self.posture.lock().unwrap() = v;
    }

    pub fn posture(&self) -> Value {
        self.posture.lock().unwrap().clone()
    }

    pub fn link(&self) -> Option<Arc<dyn LinkControl>> {
        self.link.lock().unwrap().clone()
    }

    pub fn card(&self) -> &AgentCard {
        &self.card
    }

    async fn publish_card(&self) -> Result<(), String> {
        let doc = AgentDoc { node_id: self.node_id.clone(), card: self.card.clone(), ts: now_ms() };
        self.docs.put(Coll::Agents, &self.node_id, serde_json::to_value(doc).unwrap()).await
    }

    /// Every agent known to this node's replica, including itself.
    pub async fn agents(&self) -> Result<Vec<AgentDoc>, String> {
        let mut out: Vec<AgentDoc> = self
            .docs
            .list(Coll::Agents)
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_value(v).ok())
            .collect();
        out.sort_by(|a, b| a.card.name.cmp(&b.card.name));
        Ok(out)
    }

    /// Accept an authority-signed revocation (verified here) and replicate it to the mesh.
    /// Returns the revoked token id.
    pub async fn publish_revocation(&self, bundle: &Value) -> Result<String, String> {
        let trust = self.docs.trust().ok_or("security is off")?;
        let rev = a2a_authz::Revocation::from_json(bundle)?;
        trust.accept_revocation(&rev)?;
        let id = rev.revoked.to_lowercase();
        self.docs.put_raw(Coll::Revocations, &id, rev.to_json()).await?;
        Ok(id)
    }
    pub async fn agent(&self, node_id: &str) -> Result<Option<AgentDoc>, String> {
        Ok(self.docs.get(Coll::Agents, node_id).await?.and_then(|v| serde_json::from_value(v).ok()))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.changes.subscribe()
    }

    // ── Origin side: what the HTTP server calls ─────────────────────────────

    /// Accept a `SendMessage`. Returns the task id once the command is stored;
    /// the task itself materialises when the owner picks the command up.
    ///
    /// For a follow-up, also returns the timestamp of the status the task had
    /// when the message was sent (see [`settled`]).
    pub async fn send_message(&self, req: &SendMessageRequest) -> Result<(String, Option<String>), RpcError> {
        let mut msg = req.message.clone();
        if msg.parts.is_empty() {
            return Err(RpcError::new(ERR_INVALID_PARAMS, "message.parts must not be empty"));
        }

        let mut baseline: Option<String> = None;
        let (kind, task_id, context_id, to, cmd_id) = match msg.task_id.clone() {
            // Continuing an existing task (e.g. answering INPUT_REQUIRED).
            Some(tid) => {
                let (task, owner) = self
                    .load_task(&tid)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::task_not_found(&tid))?;
                if task.status.state.is_terminal() {
                    return Err(RpcError::new(
                        ERR_UNSUPPORTED_OPERATION,
                        format!("task {tid} is already in a terminal state"),
                    ));
                }
                let cmd_id = format!("msg::{tid}::{}", uuid::Uuid::new_v4());
                baseline = task.status.timestamp.clone();
                ("message", tid, task.context_id, owner, cmd_id)
            }
            None => {
                let target = match req.tenant.as_deref() {
                    None | Some("") => self.node_id.clone(),
                    Some(t) => t.to_string(),
                };
                if target != self.node_id && self.agent(&target).await.map_err(RpcError::internal)?.is_none() {
                    return Err(RpcError::new(
                        ERR_INVALID_PARAMS,
                        format!("unknown agent '{target}' (tenant); see GET /agents"),
                    ));
                }
                let tid = uuid::Uuid::new_v4().to_string();
                let ctx = msg.context_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let cmd_id = format!("send::{tid}");
                ("send", tid, ctx, target, cmd_id)
            }
        };

        msg.task_id = Some(task_id.clone());
        msg.context_id = Some(context_id.clone());
        let cmd = Command {
            kind: kind.into(),
            task_id: task_id.clone(),
            context_id,
            to,
            from: self.node_id.clone(),
            message: Some(msg),
            ts: now_ms(),
        };
        self.docs
            .put(Coll::Inbox, &cmd_id, serde_json::to_value(&cmd).unwrap())
            .await
            .map_err(RpcError::internal)?;
        Ok((task_id, baseline))
    }

    /// The task as this node currently sees it. Before the owner has picked up
    /// a freshly sent command it is synthesised as `SUBMITTED`.
    pub async fn get_task(&self, id: &str) -> Result<Option<Task>, String> {
        Ok(self.load_task(id).await?.map(|(t, _)| t))
    }

    async fn load_task(&self, id: &str) -> Result<Option<(Task, String)>, String> {
        if let Some(v) = self.docs.get(Coll::Tasks, id).await? {
            let d: TaskDoc = serde_json::from_value(v).map_err(|e| e.to_string())?;
            return Ok(Some((d.task, d.owner)));
        }
        if let Some(v) = self.docs.get(Coll::Inbox, &format!("send::{id}")).await? {
            let c: Command = serde_json::from_value(v).map_err(|e| e.to_string())?;
            let history = c.message.clone().into_iter().collect();
            let task = Task {
                id: c.task_id,
                context_id: c.context_id,
                status: TaskStatus::new(TaskState::Submitted, None),
                artifacts: vec![],
                history,
                metadata: None,
            };
            return Ok(Some((task, c.to)));
        }
        Ok(None)
    }

    pub async fn list_tasks(
        &self,
        context_id: Option<&str>,
        state: Option<TaskState>,
        page_size: usize,
        offset: usize,
        history_length: Option<i32>,
    ) -> Result<(Vec<Task>, usize), String> {
        // Only tasks this node originated or owns: the replicated collection
        // also holds other nodes' tasks.
        let mut all: Vec<Task> = self
            .docs
            .list(Coll::Tasks)
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_value::<TaskDoc>(v).ok())
            .filter(|d| d.owner == self.node_id || d.origin == self.node_id)
            .map(|d| d.task)
            .filter(|t| context_id.map_or(true, |c| t.context_id == c))
            .filter(|t| state.map_or(true, |s| t.status.state == s))
            .collect();
        all.sort_by(|a, b| b.status.timestamp.cmp(&a.status.timestamp));
        let total = all.len();
        let page = all
            .into_iter()
            .skip(offset)
            .take(page_size)
            .map(|t| t.with_history_length(history_length))
            .collect();
        Ok((page, total))
    }

    /// Ask the owner to cancel, then wait briefly for it to take effect.
    pub async fn cancel_task(&self, id: &str) -> Result<Task, RpcError> {
        let (task, owner) = self
            .load_task(id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::task_not_found(id))?;
        if task.status.state.is_terminal() {
            return Err(RpcError::new(ERR_TASK_NOT_CANCELABLE, format!("task {id} is already {:?}", task.status.state)));
        }
        let mut rx = self.subscribe();
        let cmd = Command {
            kind: "cancel".into(),
            task_id: id.into(),
            context_id: task.context_id.clone(),
            to: owner,
            from: self.node_id.clone(),
            message: None,
            ts: now_ms(),
        };
        self.docs
            .put(Coll::Inbox, &format!("cancel::{id}"), serde_json::to_value(&cmd).unwrap())
            .await
            .map_err(RpcError::internal)?;
        self.wait_for(id, &mut rx, Duration::from_secs(10), |t| t.status.state.is_terminal())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::task_not_found(id))
    }

    /// Block until the task satisfies `done` or `timeout` elapses; returns the
    /// latest view either way. `rx` must have been created *before* the
    /// command was written so no update is missed.
    pub async fn wait_for(
        &self,
        id: &str,
        rx: &mut broadcast::Receiver<String>,
        timeout: Duration,
        done: impl Fn(&Task) -> bool,
    ) -> Result<Option<Task>, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let cur = self.get_task(id).await?;
            if let Some(t) = &cur {
                if done(t) {
                    return Ok(cur);
                }
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Ok(cur);
            }
            // Wake on a change notification, or poll every 250 ms as a backstop
            // (a lagged broadcast receiver may have dropped the one we wanted).
            let _ = tokio::time::timeout(left.min(Duration::from_millis(250)), rx.recv()).await;
        }
    }

    // ── Owner side ──────────────────────────────────────────────────────────

    async fn process_cmd(self: Arc<Self>, id: String, v: Value) {
        let cmd: Command = match serde_json::from_value(v) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("ignoring malformed inbox doc {id}: {e}");
                return;
            }
        };
        if cmd.to != self.node_id {
            return;
        }
        if !self.seen_cmds.lock().unwrap().insert(id.clone()) {
            return;
        }
        let r = match cmd.kind.as_str() {
            "send" => self.handle_send(&id, cmd).await,
            "message" => self.handle_message(&id, cmd).await,
            "cancel" => self.handle_cancel(cmd).await,
            other => Err(format!("unknown command kind {other}")),
        };
        if let Err(e) = r {
            log::error!("inbox command {id} failed: {e}");
        }
    }

    async fn handle_send(self: &Arc<Self>, cmd_id: &str, cmd: Command) -> Result<(), String> {
        let msg = cmd.message.clone().ok_or("send without message")?;
        {
            let _g = self.write_lock.lock().await;
            if self.docs.get(Coll::Tasks, &cmd.task_id).await?.is_some() {
                return Ok(()); // already taken (restart, or replayed doc)
            }
            let doc = TaskDoc {
                task: Task {
                    id: cmd.task_id.clone(),
                    context_id: cmd.context_id.clone(),
                    status: TaskStatus::new(TaskState::Submitted, None),
                    artifacts: vec![],
                    history: vec![msg.clone()],
                    metadata: None,
                },
                owner: self.node_id.clone(),
                origin: cmd.from.clone(),
                processed_cmds: vec![cmd_id.to_string()],
                ts: now_ms(),
            };
            self.docs.put(Coll::Tasks, &cmd.task_id, serde_json::to_value(&doc).unwrap()).await?;
        }
        self.spawn_run(cmd.task_id, msg);
        Ok(())
    }

    async fn handle_message(self: &Arc<Self>, cmd_id: &str, cmd: Command) -> Result<(), String> {
        let msg = cmd.message.clone().ok_or("message without payload")?;
        {
            let _g = self.write_lock.lock().await;
            let Some(mut doc) = self.read_task_doc(&cmd.task_id).await? else {
                return Err(format!("follow-up for unknown task {}", cmd.task_id));
            };
            if doc.processed_cmds.iter().any(|c| c == cmd_id) || doc.task.status.state.is_terminal() {
                return Ok(());
            }
            doc.processed_cmds.push(cmd_id.to_string());
            doc.task.history.push(msg.clone());
            doc.ts = now_ms();
            self.docs.put(Coll::Tasks, &cmd.task_id, serde_json::to_value(&doc).unwrap()).await?;
        }
        self.spawn_run(cmd.task_id, msg);
        Ok(())
    }

    async fn handle_cancel(self: &Arc<Self>, cmd: Command) -> Result<(), String> {
        let _g = self.write_lock.lock().await;
        let Some(mut doc) = self.read_task_doc(&cmd.task_id).await? else { return Ok(()) };
        if doc.task.status.state.is_terminal() {
            return Ok(());
        }
        if let Some(tx) = self.running.lock().unwrap().get(&cmd.task_id) {
            let _ = tx.send(true);
        }
        doc.task.status = TaskStatus::new(TaskState::Canceled, None);
        doc.ts = now_ms();
        self.docs.put(Coll::Tasks, &cmd.task_id, serde_json::to_value(&doc).unwrap()).await
    }

    async fn read_task_doc(&self, id: &str) -> Result<Option<TaskDoc>, String> {
        match self.docs.get(Coll::Tasks, id).await? {
            Some(v) => serde_json::from_value(v).map(Some).map_err(|e| e.to_string()),
            None => Ok(None),
        }
    }

    fn spawn_run(self: &Arc<Self>, task_id: String, message: Message) {
        let hub = self.clone();
        tokio::spawn(async move {
            if let Err(e) = hub.run_executor(&task_id, message).await {
                log::error!("task {task_id} run failed: {e}");
                let _ = hub
                    .apply(&task_id, |d| {
                        d.task.status =
                            TaskStatus::new(TaskState::Failed, Some(Message::agent_text(format!("internal error: {e}"))));
                    })
                    .await;
            }
        });
    }

    async fn run_executor(self: &Arc<Self>, task_id: &str, message: Message) -> Result<(), String> {
        self.apply(task_id, |d| d.task.status = TaskStatus::new(TaskState::Working, None)).await?;
        let snapshot = self.read_task_doc(task_id).await?.ok_or("task vanished")?.task;

        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        self.running.lock().unwrap().insert(task_id.to_string(), cancel_tx);

        let fut = self.executor.execute(ExecContext { task: snapshot, message, events: ev_tx, cancelled: cancel_rx });
        tokio::spawn(fut);

        let mut settled = false;
        while let Some(ev) = ev_rx.recv().await {
            let stop = matches!(&ev, ExecEvent::Status(s, _) if s.is_terminal() || s.is_interrupted());
            self.apply(task_id, move |d| {
                if d.task.status.state.is_terminal() {
                    return; // e.g. canceled while the executor was still emitting
                }
                match ev {
                    ExecEvent::Status(state, msg) => {
                        if let Some(m) = &msg {
                            let mut m = m.clone();
                            m.task_id = Some(d.task.id.clone());
                            m.context_id = Some(d.task.context_id.clone());
                            d.task.history.push(m);
                        }
                        d.task.status = TaskStatus::new(state, msg);
                    }
                    ExecEvent::Artifact { artifact, append } => {
                        match d.task.artifacts.iter_mut().find(|a| a.artifact_id == artifact.artifact_id) {
                            Some(existing) if append => existing.parts.extend(artifact.parts),
                            Some(existing) => *existing = artifact,
                            None => d.task.artifacts.push(artifact),
                        }
                    }
                }
            })
            .await?;
            if stop {
                settled = true;
                break;
            }
        }
        self.running.lock().unwrap().remove(task_id);

        if !settled {
            // Executor returned without a final status: treat as completed unless canceled.
            self.apply(task_id, |d| {
                if !d.task.status.state.is_terminal() {
                    d.task.status = TaskStatus::new(TaskState::Completed, None);
                }
            })
            .await?;
        }
        Ok(())
    }

    /// Serialised read-modify-write of a task document.
    async fn apply(&self, id: &str, f: impl FnOnce(&mut TaskDoc)) -> Result<(), String> {
        let _g = self.write_lock.lock().await;
        let mut doc = self.read_task_doc(id).await?.ok_or_else(|| format!("task {id} not found"))?;
        f(&mut doc);
        doc.ts = now_ms();
        self.docs.put(Coll::Tasks, id, serde_json::to_value(&doc).unwrap()).await
    }
}

/// Has the task reached a state a blocking call or stream should stop at
/// (terminal, or waiting for input)? `baseline` is the status timestamp the
/// task had *before* a follow-up message was sent: a task that is still
/// sitting in the `INPUT_REQUIRED` we are answering has not settled yet.
pub fn settled(t: &Task, baseline: Option<&str>) -> bool {
    (t.status.state.is_terminal() || t.status.state.is_interrupted())
        && baseline.map_or(true, |b| t.status.timestamp.as_deref() != Some(b))
}

/// StreamResponse payloads describing how `cur` differs from `prev`.
pub fn diff_events(prev: &Task, cur: &Task) -> Vec<Value> {
    let mut out = vec![];
    for a in &cur.artifacts {
        match prev.artifacts.iter().find(|p| p.artifact_id == a.artifact_id) {
            None => out.push(json!({ "artifactUpdate": TaskArtifactUpdateEvent {
                task_id: cur.id.clone(), context_id: cur.context_id.clone(),
                artifact: a.clone(), append: false, last_chunk: false, metadata: None } })),
            Some(p) if p.parts.len() < a.parts.len() => {
                let delta = Artifact { parts: a.parts[p.parts.len()..].to_vec(), ..a.clone() };
                out.push(json!({ "artifactUpdate": TaskArtifactUpdateEvent {
                    task_id: cur.id.clone(), context_id: cur.context_id.clone(),
                    artifact: delta, append: true, last_chunk: false, metadata: None } }));
            }
            _ => {}
        }
    }
    if prev.status != cur.status {
        out.push(json!({ "statusUpdate": TaskStatusUpdateEvent {
            task_id: cur.id.clone(), context_id: cur.context_id.clone(),
            status: cur.status.clone(), metadata: None } }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(parts: &[&str], state: TaskState) -> Task {
        Task {
            id: "t".into(),
            context_id: "c".into(),
            status: TaskStatus { state, message: None, timestamp: Some("x".into()) },
            artifacts: vec![Artifact {
                artifact_id: "a".into(),
                name: None,
                description: None,
                parts: parts.iter().map(|p| Part::text(*p)).collect(),
                metadata: None,
            }],
            history: vec![],
            metadata: None,
        }
    }

    #[test]
    fn diff_emits_append_delta_and_status() {
        let prev = task(&["a"], TaskState::Working);
        let cur = task(&["a", "b"], TaskState::Completed);
        let ev = diff_events(&prev, &cur);
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0]["artifactUpdate"]["append"], true);
        assert_eq!(ev[0]["artifactUpdate"]["artifact"]["parts"].as_array().unwrap().len(), 1);
        assert_eq!(ev[1]["statusUpdate"]["status"]["state"], "TASK_STATE_COMPLETED");
    }
}
