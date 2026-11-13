//! A real agent: an A2A [`Executor`] backed by an on-device LLM through
//! `tauri-plugin-litert` (LiteRT-LM, `.litertlm` models).
//!
//! Each node is one agent = one local model + one persona (system instruction).
//! Run several nodes with different personas and the A2A mesh routes tasks
//! between them, with every token generated locally.
//!
//! The plugin's streaming API reports tokens as Tauri events
//! (`litert-lm://chunk`) that carry a model id but no request id, and LiteRT-LM
//! allows one active conversation per engine anyway. So generations are
//! serialised with `gate`, which is what makes "the chunks I hear belong to my
//! request" true.

use std::sync::Arc;

use a2a_cblite::{
    executor::{ExecContext, ExecEvent, Executor},
    protocol::{Artifact, AgentSkill, Message, Part, Role, TaskState},
};
use futures_util::future::BoxFuture;
use tauri::{AppHandle, Listener, Wry};
use tauri_plugin_litert::{GenerateInput, LiteRtLmExt, SamplerOptions, StreamChunk};
use tokio::sync::{mpsc, Mutex};

const CHUNK_EVENT: &str = "litert-lm://chunk";

#[derive(Clone)]
pub struct Persona {
    /// Skill id advertised on the agent card, e.g. `summarizer`.
    pub role: String,
    /// System instruction: who this agent is and how it answers.
    pub instruction: String,
}

pub struct LiteRtExecutor {
    app: AppHandle<Wry>,
    model_id: String,
    persona: Persona,
    gate: Arc<Mutex<()>>,
}

impl LiteRtExecutor {
    pub fn new(app: AppHandle<Wry>, model_id: String, persona: Persona) -> Self {
        Self { app, model_id, persona, gate: Arc::new(Mutex::new(())) }
    }
}

/// Load the model with the plugin and build the executor. Returns the executor
/// and a one-line description for the agent card.
pub async fn llm_executor(
    handle: &AppHandle<Wry>,
    node_id: &str,
    model_path: String,
    role: Option<String>,
    persona: Option<String>,
    template: Option<String>,
) -> Result<(Arc<dyn Executor>, String), String> {
    use tauri::Manager;

    let persona = Persona {
        role: role.filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "assistant".into()),
        instruction: persona
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| "You are a concise, helpful assistant.".into()),
    };
    let model_id = format!("{node_id}-lm");
    let cache_dir = handle
        .path()
        .app_cache_dir()
        .map(|d| d.join("litert").to_string_lossy().into_owned())
        .ok();

    // `chatml`: skip the plugin's Conversation layer, which loses the user's message
    // for Qwen-family models (LiteRT-LM 0.13.1), and drive the model through the
    // library's own executor (raw session + hand-built ChatML prompt) instead.
    if template.as_deref() == Some("chatml") {
        let (role, instruction) = (persona.role.clone(), persona.instruction.clone());
        let llm = tauri::async_runtime::spawn_blocking(move || {
            a2a_cblite::llm::LlmExecutor::load(&model_path, role, instruction, None, cache_dir.as_deref(), false, true)
        })
        .await
        .map_err(|e| e.to_string())??;
        let description = llm.description();
        return Ok((Arc::new(llm), description));
    }

    let h = handle.clone();
    let mid = model_id.clone();
    // Engine creation is a long blocking call.
    tauri::async_runtime::spawn_blocking(move || {
        h.litert_lm().load_lm_model(tauri_plugin_litert::LoadLmModelOptions {
            model_path,
            model_id: mid,
            accelerator: Default::default(),
            max_tokens: None,
            prefill_chunk_size: None,
            cache_dir,
            vision: false,
        })
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("loading model: {e}"))?;

    let description = persona.instruction.lines().next().unwrap_or_default().to_string();
    Ok((Arc::new(LiteRtExecutor::new(handle.clone(), model_id, persona)), description))
}

/// The model sees one user turn. For a follow-up (e.g. after the task was
/// parked) the earlier turns are replayed as a transcript so it has context.
fn render_prompt(history: &[Message]) -> String {
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

impl Executor for LiteRtExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        let first_line = self.persona.instruction.lines().next().unwrap_or("").to_string();
        vec![AgentSkill {
            id: self.persona.role.clone(),
            name: self.persona.role.clone(),
            description: first_line,
            tags: vec!["llm".into(), "litert".into(), "on-device".into()],
            examples: vec![],
        }]
    }

    fn execute(&self, mut ctx: ExecContext) -> BoxFuture<'static, ()> {
        let app = self.app.clone();
        let model_id = self.model_id.clone();
        let system = self.persona.instruction.clone();
        let gate = self.gate.clone();

        Box::pin(async move {
            // One generation at a time (see module docs).
            let _turn = gate.lock().await;

            // Register the listener *before* starting, as the plugin advises.
            let (tx, mut rx) = mpsc::unbounded_channel::<StreamChunk>();
            let want = model_id.clone();
            let listener = app.listen(CHUNK_EVENT, move |ev| {
                if let Ok(c) = serde_json::from_str::<StreamChunk>(ev.payload()) {
                    if c.model_id == want {
                        let _ = tx.send(c);
                    }
                }
            });

            let input = GenerateInput {
                model_id: model_id.clone(),
                prompt: render_prompt(&ctx.task.history),
                sampler: SamplerOptions::default(),
                system_instruction: Some(system),
                image: None,
            };
            if let Err(e) = app.litert_lm().generate_stream(input) {
                app.unlisten(listener);
                ctx.status(TaskState::Failed, Some(Message::agent_text(format!("model error: {e}"))));
                return;
            }

            let artifact_id = format!("answer-{}", ctx.task.id);
            let mut first = true;
            let mut canceled = false;
            let mut failure: Option<String> = None;

            loop {
                tokio::select! {
                    chunk = rx.recv() => match chunk {
                        None => break,
                        Some(c) if c.done => { failure = c.error; break; }
                        Some(c) if canceled || c.chunk.is_empty() => { let _ = c; }
                        Some(c) => {
                            let _ = ctx.events.send(ExecEvent::Artifact {
                                artifact: Artifact {
                                    artifact_id: artifact_id.clone(),
                                    name: Some("answer".into()),
                                    description: None,
                                    parts: vec![Part::text(c.chunk)],
                                    metadata: None,
                                },
                                append: !first,
                            });
                            first = false;
                        }
                    },
                    // LiteRT-LM has no cancel call: stop *reporting*, but keep
                    // draining until the engine finishes so `gate` is only
                    // released when the next generation can really start.
                    _ = ctx.cancelled.changed(), if !canceled => { canceled = true; }
                }
            }
            app.unlisten(listener);

            if canceled {
                return; // the hub already recorded CANCELED
            }
            match failure {
                Some(e) => ctx.status(TaskState::Failed, Some(Message::agent_text(format!("model error: {e}")))),
                None => ctx.status(TaskState::Completed, None),
            }
        })
    }
}
