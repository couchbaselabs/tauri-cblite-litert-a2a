//! HTTP surface: agent card, mesh directory and the A2A 1.0 JSON-RPC endpoint.
//!
//! * `GET  /.well-known/agent-card.json`    this node's card
//! * `GET  /agents`                          every agent in the mesh (replicated cards)
//! * `GET  /agents/{node}/agent-card.json`   a peer's card, rewritten so that a
//!                                           standard client talks to *this*
//!                                           gateway with `tenant = {node}`
//! * `POST /`                                JSON-RPC 2.0

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::{wrappers::UnboundedReceiverStream, StreamExt};

use crate::hub::{diff_events, settled, Hub};
use crate::protocol::*;

const SEND_WAIT: Duration = Duration::from_secs(120);
const STREAM_MAX: Duration = Duration::from_secs(600);

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/.well-known/agent-card.json", get(own_card))
        .route("/agents", get(list_agents))
        .route("/security", get(security))
        .route("/link", get(link_status).post(link_set))
        .route("/demo", get(demo_page))
        .route("/demo/all", get(demo_all_page))
        .route("/security/revocations", post(post_revocation))
        .route("/agents/:node/agent-card.json", get(peer_card))
        .route("/", post(rpc))
        .with_state(hub)
}

pub async fn serve(hub: Arc<Hub>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    axum::serve(listener, router(hub)).await
}

/// Trust status: whether documents are signed and verified, who is enrolled,
/// and every document this node refused (with how often).
async fn security(State(hub): State<Arc<Hub>>) -> Json<Value> {
    Json(match hub.docs.trust() {
        None => json!({ "secure": false, "posture": hub.posture() }),
        Some(t) => json!({
            "secure": true,
            "mode": t.mode(),
            "nodeId": t.node_id(),
            "publicKey": t.public_key(),
            "enrolled": t.enrolled(),
            "revokedTokens": t.revoked_ids(),
            "posture": hub.posture(),
            "rejections": t.rejections(),
        }),
    })
}

/// Publish a revocation (the output of `a2a-admin revoke`). Only a bundle signed by the authority is accepted;
/// it is stored in the replicated `revocations` collection so the whole mesh learns of it.
async fn post_revocation(State(hub): State<Arc<Hub>>, body: Bytes) -> Response {
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match hub.publish_revocation(&v).await {
        Ok(id) => Json(json!({ "revoked": id })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

/// The field-inspection demo dashboard (see the README); served by every node, it shows that node's view.
async fn demo_page() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("demo.html"))
}

/// The control-room view: the three devices side by side with a live topology (see `demo-all.html`).
async fn demo_all_page() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("demo-all.html"))
}

/// Whether this node can cut its peer connections, and whether they are up.
async fn link_status(State(hub): State<Arc<Hub>>) -> Json<Value> {
    Json(match hub.link() {
        Some(l) => json!({ "available": true, "up": l.is_up() }),
        None => json!({ "available": false, "up": null }),
    })
}

/// `POST /link {"up": false}` cuts this node's outgoing peer connections, `true` restores them. The node
/// keeps running and keeps answering local requests while the link is down.
async fn link_set(State(hub): State<Arc<Hub>>, body: Bytes) -> Response {
    let up = match serde_json::from_slice::<Value>(&body).ok().and_then(|v| v.get("up").and_then(Value::as_bool)) {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, "expected {\"up\": true|false}").into_response(),
    };
    let Some(link) = hub.link() else {
        return (StatusCode::NOT_FOUND, "this node has no link control").into_response();
    };
    match tokio::task::spawn_blocking(move || link.set(up)).await {
        Ok(Ok(())) => Json(json!({ "available": true, "up": up })).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn own_card(State(hub): State<Arc<Hub>>) -> Json<AgentCard> {
    Json(hub.card().clone())
}

async fn list_agents(State(hub): State<Arc<Hub>>) -> Response {
    match hub.agents().await {
        Ok(a) => {
            let v: Vec<Value> = a
                .iter()
                .map(|d| {
                    json!({ "nodeId": d.node_id, "self": d.node_id == hub.node_id,
                            "online": d.node_id == hub.node_id || d.online(),
                            "lastSeen": d.ts, "card": d.card })
                })
                .collect();
            Json(v).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn peer_card(State(hub): State<Arc<Hub>>, Path(node): Path<String>) -> Response {
    match hub.agent(&node).await {
        Ok(Some(d)) => {
            let mut card = d.card;
            let base = hub.card().supported_interfaces.first().map(|i| i.url.clone()).unwrap_or_default();
            card.supported_interfaces = vec![AgentInterface {
                url: base,
                protocol_binding: "JSONRPC".into(),
                protocol_version: "1.0".into(),
                tenant: Some(node),
            }];
            Json(card).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn rpc(State(hub): State<Arc<Hub>>, body: Bytes) -> Response {
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Json(rpc_err(&Value::Null, &RpcError::new(ERR_PARSE, e.to_string()))).into_response(),
    };
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = v.get("method").and_then(Value::as_str) else {
        return Json(rpc_err(&id, &RpcError::new(ERR_INVALID_REQUEST, "missing method"))).into_response();
    };
    let params = v.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "SendStreamingMessage" => match start_send_stream(&hub, &params).await {
            Ok((prev, baseline, rx)) => sse(hub, id, prev, baseline, rx).into_response(),
            Err(e) => Json(rpc_err(&id, &e)).into_response(),
        },
        "SubscribeToTask" => match start_subscribe(&hub, &params).await {
            Ok((prev, rx)) => sse(hub, id, prev, None, rx).into_response(),
            Err(e) => Json(rpc_err(&id, &e)).into_response(),
        },
        _ => match unary(&hub, method, params).await {
            Ok(result) => Json(rpc_ok(&id, result)).into_response(),
            Err(e) => Json(rpc_err(&id, &e)).into_response(),
        },
    }
}

fn parse<T: serde::de::DeserializeOwned>(params: &Value) -> Result<T, RpcError> {
    serde_json::from_value(params.clone()).map_err(|e| RpcError::new(ERR_INVALID_PARAMS, e.to_string()))
}

async fn unary(hub: &Arc<Hub>, method: &str, params: Value) -> Result<Value, RpcError> {
    match method {
        "SendMessage" => {
            let req: SendMessageRequest = parse(&params)?;
            let cfg = req.configuration.clone().unwrap_or_default();
            let mut rx = hub.subscribe(); // before the write: miss nothing
            let (tid, baseline) = hub.send_message(&req).await?;
            let task = if cfg.return_immediately {
                hub.get_task(&tid).await
            } else {
                hub.wait_for(&tid, &mut rx, SEND_WAIT, |t| settled(t, baseline.as_deref())).await
            }
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::task_not_found(&tid))?;
            Ok(json!({ "task": task.with_history_length(cfg.history_length) }))
        }
        "GetTask" => {
            let id = params.get("id").and_then(Value::as_str).ok_or_else(|| RpcError::new(ERR_INVALID_PARAMS, "id required"))?;
            let hl = params.get("historyLength").and_then(Value::as_i64).map(|n| n as i32);
            let t = hub.get_task(id).await.map_err(RpcError::internal)?.ok_or_else(|| RpcError::task_not_found(id))?;
            Ok(serde_json::to_value(t.with_history_length(hl)).unwrap())
        }
        "ListTasks" => {
            let ctx = params.get("contextId").and_then(Value::as_str);
            let state: Option<TaskState> = match params.get("status") {
                Some(s) if !s.is_null() => Some(parse(s)?),
                _ => None,
            };
            let page_size = params.get("pageSize").and_then(Value::as_u64).unwrap_or(50).clamp(1, 100) as usize;
            let offset = params.get("pageToken").and_then(Value::as_str).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let hl = params.get("historyLength").and_then(Value::as_i64).map(|n| n as i32);
            let (tasks, total) =
                hub.list_tasks(ctx, state, page_size, offset, hl).await.map_err(RpcError::internal)?;
            let next = if offset + tasks.len() < total { (offset + tasks.len()).to_string() } else { String::new() };
            Ok(json!({ "tasks": tasks, "nextPageToken": next, "pageSize": tasks.len(), "totalSize": total }))
        }
        "CancelTask" => {
            let id = params.get("id").and_then(Value::as_str).ok_or_else(|| RpcError::new(ERR_INVALID_PARAMS, "id required"))?;
            Ok(serde_json::to_value(hub.cancel_task(id).await?).unwrap())
        }
        "GetExtendedAgentCard" => {
            Err(RpcError::new(-32007, "this agent has no extended agent card"))
        }
        m if m.contains("PushNotificationConfig") => {
            Err(RpcError::new(ERR_PUSH_UNSUPPORTED, "push notifications are not supported"))
        }
        m => Err(RpcError::new(ERR_METHOD_NOT_FOUND, format!("method not found: {m}"))),
    }
}

async fn start_send_stream(
    hub: &Arc<Hub>,
    params: &Value,
) -> Result<(Task, Option<String>, broadcast::Receiver<String>), RpcError> {
    let req: SendMessageRequest = parse(params)?;
    let rx = hub.subscribe();
    let (tid, baseline) = hub.send_message(&req).await?;
    let task = hub.get_task(&tid).await.map_err(RpcError::internal)?.ok_or_else(|| RpcError::task_not_found(&tid))?;
    Ok((task, baseline, rx))
}

async fn start_subscribe(
    hub: &Arc<Hub>,
    params: &Value,
) -> Result<(Task, broadcast::Receiver<String>), RpcError> {
    let id = params.get("id").and_then(Value::as_str).ok_or_else(|| RpcError::new(ERR_INVALID_PARAMS, "id required"))?;
    let rx = hub.subscribe();
    let task = hub.get_task(id).await.map_err(RpcError::internal)?.ok_or_else(|| RpcError::task_not_found(id))?;
    if task.status.state.is_terminal() {
        return Err(RpcError::new(ERR_UNSUPPORTED_OPERATION, "task is in a terminal state; nothing to subscribe to"));
    }
    Ok((task, rx))
}

/// Emit the initial `task`, then status/artifact updates as the (replicated)
/// task document changes, until the task is terminal or needs input.
fn sse(
    hub: Arc<Hub>,
    id: Value,
    initial: Task,
    baseline: Option<String>,
    mut rx: broadcast::Receiver<String>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let (tx, out) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        let mut prev = initial;
        if tx.send(rpc_ok(&id, json!({ "task": prev }))).is_err() {
            return;
        }
        let deadline = tokio::time::Instant::now() + STREAM_MAX;
        while !settled(&prev, baseline.as_deref()) {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await;
            let Ok(Some(cur)) = hub.get_task(&prev.id).await else { continue };
            for payload in diff_events(&prev, &cur) {
                if tx.send(rpc_ok(&id, payload)).is_err() {
                    return; // client went away
                }
            }
            prev = cur;
        }
    });
    Sse::new(UnboundedReceiverStream::new(out).map(|v| Ok(Event::default().data(v.to_string()))))
        .keep_alive(KeepAlive::default())
}
