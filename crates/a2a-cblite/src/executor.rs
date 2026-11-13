//! The pluggable "brain" of an A2A node.
//!
//! An [`Executor`] receives a task's latest user message and reports progress
//! through [`ExecContext::events`]. Everything else - persistence, routing
//! between peers, streaming - is handled by the [`Hub`](crate::hub::Hub).

use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::sync::{mpsc::UnboundedSender, watch};

use crate::protocol::*;

pub enum ExecEvent {
    /// Move the task to `state`, optionally with an agent message. A terminal or
    /// interrupted state ends the run.
    Status(TaskState, Option<Message>),
    /// Add or extend an artifact. With `append`, `artifact.parts` are added to
    /// the artifact with the same id instead of replacing it.
    Artifact { artifact: Artifact, append: bool },
}

pub struct ExecContext {
    /// Snapshot of the task, `history` already containing `message`.
    pub task: Task,
    /// The user message that triggered this run.
    pub message: Message,
    pub events: UnboundedSender<ExecEvent>,
    /// Flips to `true` when the task is canceled.
    pub cancelled: watch::Receiver<bool>,
}

impl ExecContext {
    pub fn status(&self, state: TaskState, message: Option<Message>) {
        let _ = self.events.send(ExecEvent::Status(state, message));
    }
    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }
}

/// Turn a task's history into a single prompt for a one-shot LLM call. One
/// message is passed through as is; for a follow-up the earlier turns are
/// replayed as a transcript so the model has context.
pub fn transcript_prompt(history: &[Message]) -> String {
    if history.len() <= 1 {
        return history.last().map(Message::text).unwrap_or_default();
    }
    let mut s = String::from("Conversation so far:\n");
    for m in history {
        let who = if m.role == Role::Agent { "Assistant" } else { "User" };
        s.push_str(&format!("{who}: {}\n", m.text()));
    }
    s.push_str("\nReply to the last User message.");
    s
}

pub trait Executor: Send + Sync + 'static {
    fn skills(&self) -> Vec<AgentSkill>;
    fn execute(&self, ctx: ExecContext) -> BoxFuture<'static, ()>;
}

/// Demo agent. Streams the user's words back one at a time.
///
/// Magic inputs, to exercise the protocol's state machine:
/// * `ask`  -> `INPUT_REQUIRED`; the follow-up message is then echoed.
/// * `fail` -> `FAILED`.
/// * `slow` -> works for 30 s, honouring cancellation.
pub struct EchoExecutor;

impl Executor for EchoExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        vec![AgentSkill {
            id: "echo".into(),
            name: "Echo".into(),
            description: "Streams the message back word by word. Try 'ask', 'fail' or 'slow'.".into(),
            tags: vec!["demo".into()],
            examples: vec!["hello world".into()],
        }]
    }

    fn execute(&self, mut ctx: ExecContext) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let text = ctx.message.text();
            let agent_turns = ctx.task.history.iter().filter(|m| m.role == Role::Agent).count();

            if text.trim() == "ask" && agent_turns == 0 {
                ctx.status(TaskState::InputRequired, Some(Message::agent_text("What should I echo?")));
                return;
            }
            if text.trim() == "fail" {
                ctx.status(TaskState::Failed, Some(Message::agent_text("you asked me to fail")));
                return;
            }
            if text.trim() == "slow" {
                for _ in 0..300 {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                        _ = ctx.cancelled.changed() => { return; }
                    }
                }
                ctx.status(TaskState::Completed, None);
                return;
            }

            let artifact_id = format!("echo-{}", uuid::Uuid::new_v4());
            let words: Vec<&str> = text.split_whitespace().collect();
            for (i, w) in words.iter().enumerate() {
                if ctx.is_cancelled() {
                    return;
                }
                let chunk = if i == 0 { w.to_string() } else { format!(" {w}") };
                let _ = ctx.events.send(ExecEvent::Artifact {
                    artifact: Artifact {
                        artifact_id: artifact_id.clone(),
                        name: Some("echo".into()),
                        description: None,
                        parts: vec![Part::text(chunk)],
                        metadata: None,
                    },
                    append: i > 0,
                });
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
            ctx.status(TaskState::Completed, None);
        })
    }
}
