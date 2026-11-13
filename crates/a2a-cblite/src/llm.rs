//! A real agent for the headless node: an on-device LLM through LiteRT-LM
//! (the `litertlm` crate, `.litertlm` models), no Tauri involved.
//!
//! One node = one model + one persona. Tokens stream into the A2A task as
//! appended artifact parts. LiteRT-LM allows one conversation per engine, so
//! generations are serialised by `gate`; it also has no cancel call, so a
//! canceled task stops *reporting* while the engine finishes its answer.

use std::sync::{Arc, Mutex};

use crate::{
    executor::{transcript_prompt, ExecContext, ExecEvent, Executor},
    protocol::{AgentSkill, Artifact, Message, Part, Role, TaskState},
};
use futures_util::future::BoxFuture;
use litertlm::{Backend, Engine, EngineSettings, SamplerParams};

/// LiteRT-LM streams plain text for the answer, but reasoning models (Qwen3)
/// also emit JSON messages such as `{"role":"assistant","channels":{"thought":"Okay"}}`.
/// Returns `(is_thought, text)`.
fn classify(chunk: &str) -> (bool, String) {
    if chunk.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(chunk) {
            if let Some(t) = v.pointer("/channels/thought").and_then(|t| t.as_str()) {
                return (true, t.to_string());
            }
        }
    }
    (false, chunk.to_string())
}

/// Track `<think>…</think>` across chunks: returns `(inside_thinking, text_without_tags)`.
fn think_filter(in_think: &mut bool, text: String) -> (bool, String) {
    let mut t = text;
    if t.contains("<think>") {
        *in_think = true;
        t = t.replace("<think>", "");
    }
    let closes = t.contains("</think>");
    if closes {
        t = t.replace("</think>", "");
    }
    let inside = *in_think;
    if closes {
        *in_think = false;
    }
    (inside, t)
}

pub struct LlmExecutor {
    engine: Arc<Engine>,
    role: String,
    instruction: String,
    gpu: bool,
    chatml: bool,
    gate: Arc<Mutex<()>>,
}

/// A task's history as real ChatML turns (`<|im_start|>role ... <|im_end|>`),
/// ending with an open assistant turn for the model to complete.
fn chatml_prompt(system: &str, history: &[Message]) -> String {
    let mut s = format!("<|im_start|>system\n{system}<|im_end|>\n");
    for m in history {
        let role = if m.role == Role::Agent { "assistant" } else { "user" };
        s.push_str(&format!("<|im_start|>{role}\n{}<|im_end|>\n", m.text()));
    }
    s.push_str("<|im_start|>assistant\n");
    s
}

impl LlmExecutor {
    /// Load the model (slow: seconds to minutes) on the CPU backend.
    pub fn load(
        model_path: &str,
        role: String,
        instruction: String,
        max_tokens: Option<i32>,
        cache_dir: Option<&str>,
        gpu: bool,
        chatml: bool,
    ) -> Result<Self, String> {
        let mut settings =
            EngineSettings::new(model_path).backend(if gpu { Backend::Gpu } else { Backend::Cpu });
        if let Some(n) = max_tokens {
            settings = settings.max_num_tokens(n);
        }
        if let Some(dir) = cache_dir {
            std::fs::create_dir_all(dir).map_err(|e| format!("cache dir {dir}: {e}"))?;
            settings = settings.cache_dir(dir);
        }
        let engine = Engine::new(settings).map_err(|e| format!("loading {model_path}: {e}"))?;
        Ok(Self { engine: Arc::new(engine), role, instruction, gpu, chatml, gate: Arc::new(Mutex::new(())) })
    }

    pub fn description(&self) -> String {
        self.instruction.lines().next().unwrap_or_default().to_string()
    }
}

impl Executor for LlmExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        vec![AgentSkill {
            id: self.role.clone(),
            name: self.role.clone(),
            description: self.description(),
            tags: vec!["llm".into(), "litert".into(), "on-device".into()],
            examples: vec![],
        }]
    }

    fn execute(&self, ctx: ExecContext) -> BoxFuture<'static, ()> {
        let engine = self.engine.clone();
        let gate = self.gate.clone();
        let system = self.instruction.clone();
        let gpu = self.gpu;
        let chatml = self.chatml;

        Box::pin(async move {
            let prompt = transcript_prompt(&ctx.task.history);
            let raw_prompt = chatml.then(|| chatml_prompt(&system, &ctx.task.history));
            let events = ctx.events.clone();
            let cancelled = ctx.cancelled.clone();
            let artifact_id = format!("answer-{}", ctx.task.id);
            let task_id = ctx.task.id.clone();
            let show_thinking = std::env::var("A2A_SHOW_THINKING").is_ok();

            // Generation is blocking and CPU-heavy: keep it off the async workers.
            let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let _turn = gate.lock().unwrap();
                // On GPU the sampler must be greedy: top-k/top-p need CPU access to GPU
                // tensors (same constraint the tauri-plugin-litert notes).
                let params = if gpu {
                    SamplerParams::default().temperature(0.8).greedy()
                } else {
                    SamplerParams::default().temperature(0.8).top_k(40).top_p(0.95)
                };
                let mut in_think = false;
                let mut answer_first = true;
                let mut thinking_first = true;
                let mut on_chunk = |chunk: &str| {
                    if chunk.is_empty() || *cancelled.borrow() {
                        return;
                    }
                    let (is_thought, text) = classify(chunk);
                    // Raw-session output (Qwen3) carries `<think>…</think>` inline.
                    let (is_thought, text) = if is_thought { (true, text) } else { think_filter(&mut in_think, text) };
                    if text.is_empty() || (is_thought && !show_thinking) {
                        return;
                    }
                    let (id, name, first) = if is_thought {
                        (format!("thinking-{}", task_id), "thinking", &mut thinking_first)
                    } else {
                        (artifact_id.clone(), "answer", &mut answer_first)
                    };
                    let _ = events.send(ExecEvent::Artifact {
                        artifact: Artifact {
                            artifact_id: id,
                            name: Some(name.into()),
                            description: None,
                            parts: vec![Part::text(text)],
                            metadata: None,
                        },
                        append: !*first,
                    });
                    *first = false;
                };
                // `--template chatml`: bypass the crate's Conversation/chat-template layer
                // and drive a raw Session with a hand-built ChatML prompt. Needed for the
                // Qwen family, where the Conversation layer (LiteRT-LM 0.13.1) loses the
                // user's message.
                if let Some(full) = raw_prompt {
                    let mut session = engine
                        .create_session(params)
                        .map_err(|e| format!("create_session: {e}"))?;
                    return session
                        .generate_stream(&full, |c| {
                            on_chunk(c);
                            // Returning false is meant to cancel, but litertlm 0.2.1's
                            // trampoline ignores the return value, so it does nothing.
                            true
                        })
                        .map_err(|e| format!("generation: {e}"));
                }
                let mut conv = engine
                    .create_conversation_with_system(params, &system)
                    .map_err(|e| format!("create_conversation: {e}"))?;
                conv.send_message_stream(&prompt, &mut on_chunk).map_err(|e| format!("generation: {e}"))
            })
            .await;

            if ctx.is_cancelled() {
                return; // the hub already recorded CANCELED
            }
            match result {
                Ok(Ok(())) => ctx.status(TaskState::Completed, None),
                Ok(Err(e)) => ctx.status(TaskState::Failed, Some(Message::agent_text(format!("model error: {e}")))),
                Err(e) => ctx.status(TaskState::Failed, Some(Message::agent_text(format!("model crashed: {e}")))),
            }
        })
    }
}
