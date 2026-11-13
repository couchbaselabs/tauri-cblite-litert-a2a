# A2A on Couchbase Lite

An [A2A](https://a2a-protocol.org) **1.0** server whose state *and transport* are Couchbase Lite.
Agents form a mesh by replicating three collections peer-to-peer (`URLEndpointListener`, no Sync Gateway,
no broker). A task sent to any node is routed to the node that hosts the target agent, executed there,
and the result replicates back.

```
 client ──SendMessage(tenant=bob)──▶ node A (origin)
                                        │ writes   a2a.inbox / send::<task>   to=bob
                                        ▼            ═══ Couchbase Lite P2P replication ═══
                                     node B (owner)  sees the inbox doc, runs its executor,
                                        │ writes   a2a.tasks / <task>   on every state change
                                        ▼            ═══ replication back ═══
 client ◀── task / SSE stream ───── node A serves it from its own replica
```

Because the transport is a database, requests are **store-and-forward**: if B is offline when A writes the
request, B picks it up when the two next connect (tested, see `scripts/e2e.ps1`).

## Layout

| Path | What |
|---|---|
| `crates/a2a-cblite` | The library: protocol types, Couchbase Lite actor, routing hub, executor trait, axum server, P2P helper |
| `crates/a2a-node` | Headless node: A2A HTTP server + P2P listener/replicators (used by the e2e test) |
| `src-tauri` | Desktop app on [`tauri-plugin-cblite`](https://github.com/ldoguin/tauri-plugin-cblite): the plugin owns the DB, listener and replicators, the A2A hub borrows its database |
| `scripts/e2e.ps1` | Two real nodes, 22 checks |

## Design

**Three collections, each single-writer per document**, so peers never create conflicting revisions and
no arbiter is needed:

| Collection | Doc id | Written only by |
|---|---|---|
| `a2a.inbox` | `send::<task>`, `msg::<task>::<uuid>`, `cancel::<task>` | the **origin** (node that got the client request) |
| `a2a.tasks` | `<task>` | the **owner** (node whose agent runs it) |
| `a2a.agents` | `<nodeId>` | that node (card + heartbeat every 30 s) |

* **Routing** uses the A2A `tenant` field: `tenant` = target node id (empty = this node). A peer's card is
  served by the local gateway at `/agents/{node}/agent-card.json` with the interface rewritten to
  `{gateway url, tenant: node}`, so a stock A2A client can address any agent in the mesh through any node.
* **Discovery** is just the replicated `a2a.agents` collection. You still need to tell a node where to
  *dial* once (`--connect ws://host:port/a2a`); after that, the whole mesh's cards flow through it.
* **Executors**: implement `a2a_cblite::executor::Executor` to bring your own agent. `EchoExecutor` is a demo
  (`ask` → `INPUT_REQUIRED`, `fail`, `slow` + cancel).
* All Couchbase Lite handles live on **one actor thread** (`docs.rs`), so no `Send`/`Sync` hacks around the
  non-`Send` binding types. In the Tauri app the actor receives a `Database::clone()` of the plugin's
  open database: same underlying handle, so the plugin's listener serves what the hub writes.

### A2A surface

`GET /.well-known/agent-card.json` · `GET /agents` · `GET /agents/{node}/agent-card.json` · `POST /` (JSON-RPC 2.0):
`SendMessage`, `SendStreamingMessage` (SSE), `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask` (SSE).
Push-notification methods return `-32003`; `GetExtendedAgentCard` returns `-32007`. The REST/gRPC bindings are not implemented.

## Run (headless)

```powershell
cargo build -p a2a-node
# terminal 1
a2a-node --name alice --data ./alice --http-port 8081      # prints "P2P port NNNN"
# terminal 2
a2a-node --name bob   --data ./bob   --http-port 8082 --connect ws://127.0.0.1:NNNN/a2a

curl http://127.0.0.1:8081/agents
curl -s http://127.0.0.1:8081/ -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"tenant":"bob","message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"hello"}]}}}'
```

On Windows the runtime needs `cblite.dll` next to the executable (cargo puts it in
`target/debug/build/couchbase_lite-*/out/`).

## Run (desktop app)

```
cd src-tauri && cargo tauri dev
```

The UI calls `plugin:cblite|open_database` (creating the three collections), then `a2a_start`; **Host** calls
the plugin's `start_peer_listener`; **Connect** calls its `start_replication` with the three collections in one
replicator.

## Real agents: on-device LLMs with `tauri-plugin-litert`

`src-tauri/src/litert_agent.rs` is an A2A `Executor` backed by [`tauri-plugin-litert`](https://github.com/ldoguin/tauri-plugin-litert)
(LiteRT-LM, `.litertlm` models). Each node is **one agent = one local model + one persona**; start several nodes with
different personas (summariser, reviewer, translator…) and the mesh routes tasks between them, every token generated locally.

* In the app, fill **Model** (path to a `.litertlm`), **Role** and **Persona** before *Start node*. Without a model the
  node runs the demo echo agent.
* Tokens stream to A2A clients as `artifactUpdate` events (the plugin's `litert-lm://chunk` events become appended
  artifact parts).
* Generations are serialised per node (LiteRT-LM allows one conversation per engine; the plugin's chunk events carry no
  request id). LiteRT-LM has no cancel call, so a canceled task stops reporting but the engine finishes the current answer.
* Follow-up turns replay the task history as a transcript in the prompt.
* **Windows has no LLM runtime, so the plugin is compiled out there** (`cfg(not(windows))` in `Cargo.toml` and `lib.rs`).
  `litert-lm-sys` ships prebuilts for Linux and macOS only. On Windows it links a stub, and linking it makes the
  executable import a `libLiteRt.dll` that doesn't exist, so the app **fails to start** (loader error `0xC0000135`).
  On Windows, *Start node* with a model returns an explanatory error and the node can run the demo echo agent. Run
  LLM agent nodes on Linux/macOS (or build with `LITERT_LM_LIB_DIR` pointing at a custom `LiteRtLmC.dll`).
* Verified: the LiteRT code compiles (type-checked in a temporary ungated build on Windows) and the Windows build
  starts normally. **Not verified:** an actual generation, and the Linux/macOS Tauri build (no model file, and no
  webkit2gtk in the WSL distro).

### Headless LLM agent (Linux/macOS): `a2a-node --features litert`

`crates/a2a-node/src/llm.rs` is the same idea without Tauri, using the `litertlm` crate directly. **Verified end to end
in Ubuntu (WSL2)** with `SmolLM2_135M_Instruct.litertlm`: node `front` (echo) sent a task with `tenant: scribe` over
Couchbase Lite P2P; `scribe` generated the answer on-device (CPU) and it replicated back as a `COMPLETED` task, ~15 s.

```bash
cargo build -p a2a-node --features litert      # first build downloads libLiteRtLmC.so / libLiteRt.so into ~/.cache
export LD_LIBRARY_PATH=<out dir with libcblite.so>:~/.cache/litert-lm-sys/<ver>/<triple>:~/.cache/litert-sys/<ver>/<triple>
a2a-node --name scribe --data ./scribe --http-port 8081 --p2p-port 45201 \
  --role poet --persona "You are a poet. Answer every request with a two-line rhyming poem." \
  --model ./Qwen3-0.6B.litertlm --max-tokens 512
a2a-node --name front --data ./front --http-port 8082 --connect ws://127.0.0.1:45201/a2a
# then SendMessage to http://127.0.0.1:8082 with "tenant": "scribe"
```

* Models: `.litertlm` files, e.g. from <https://huggingface.co/litert-community> (Qwen3-0.6B 585 MB, SmolLM2-135M 136 MB, ungated).
* The binary does not carry an rpath to the LiteRT libraries, hence `LD_LIBRARY_PATH`.
* Reasoning models (Qwen3) stream their "thinking" as JSON chunks (`{"role":"assistant","channels":{"thought":"…"}}`).
  The node parses these: the answer goes to the `answer-<task>` artifact, and thinking is dropped unless you set
  `A2A_SHOW_THINKING=1` (then it goes to a separate `thinking-<task>` artifact).
* **`--template chatml` (needed for Qwen models).** With LiteRT-LM 0.13.1's default Conversation layer, Qwen models
  never see the user's message (identical reply for any prompt). `--template chatml` bypasses it: the node builds the
  ChatML prompt itself (history as real `<|im_start|>role` turns) and drives a raw `Session`. **Verified with
  `Qwen2.5-1.5B-Instruct` q8 (1.5 GB, CPU):** routed `front → scribe` over P2P, the poet persona is followed
  ("Monday mornings, grey and bleak, / Cry out, let down, and start the week."), ~25 s to load, ~5 s per short answer,
  streaming starts ~2.7 s in (22 chunks). Qwen3-0.6B with chatml also sees the prompt now and follows the instruction,
  with `<think>` text routed to the thinking channel (code added, the final run was not repeated).
* **No real cancel.** `CancelTask` marks the task `CANCELED` and stops reporting, but the engine keeps generating to
  the end (scribe's CPU time kept rising after the cancel; the next request waits behind it). litertlm 0.2.1's session
  trampoline ignores the callback's return value, and the C API's only cancel call is for conversations, which the
  Rust wrapper does not expose.
* **Model quality, measured earlier (default template):**
  * `SmolLM2-135M` reacts to the prompt (a question about the sea got an answer about the sea) but **ignores the persona**
    (an essay instead of a two-line poem).
  * `Qwen3-0.6B.litertlm` (585 MB, LiteRT-LM 0.13.1, Linux CPU) **never saw the user's message**: it produced the
    identical answer ("Hello! I can help you verify your identity…") for "The sea at night.", "A cat on a roof.",
    "What is 2+2?" and "Name the capital of France.". That held with the crate's plain call, with a plain-string user
    content, with no system turn, with the persona inlined into the user text, with the blocking call, and with no
    `--max-tokens` / no cache dir. So it is not this project's prompt handling; it points at the model file's chat
    template or the runtime. Not yet tried: the other Qwen3 file (`…_dynamic_wi4b32_afp32.litertlm`), other models, GPU.
  * `Qwen3-0.6B_dynamic_wi4b32_afp32.litertlm` (328 MB, int4 weights) **does not load here**. On CPU:
    `Weights section offset is only supported for GPU backend`. On `--backend gpu` (WSL2, `/dev/dxg` + Mesa Vulkan):
    the GPU delegate rejects it (`FULLY_CONNECTED: Tensor type(INT4) is not supported`, `EMBEDDING_LOOKUP` not
    quantized). It likely needs a real GPU/driver stack; untested on one.
  * The A2A side (routing, streaming 143 chunks over time, completion) works regardless of the model.
  * `--backend cpu|gpu` selects the LiteRT-LM backend (GPU uses a greedy sampler).
* `--model` on a build without `--features litert` (and on Windows) fails with a clear error.

### The Tauri app on Linux, with a real LLM agent

**Verified in Ubuntu 24.04 (WSL2 + WSLg):** the Tauri app builds and runs; with `template: chatml` it loads
`Qwen2.5-1.5B-Instruct` q8, serves its A2A card (poet persona), answers a local `SendMessage` with a rhyming poem, and a
separate headless `a2a-node` that dialed the app's **plugin-owned P2P listener** discovered it and routed a task to it
(`COMPLETED`, "A train at dawn, its wheels a-whirr, / Chasing shadows, bound for the light."). **0 link drops** in that
run, so the Windows listener flapping is Windows-specific. The window itself was not inspected (WSLg), only the A2A
server and logs.

```bash
sudo apt install pkg-config build-essential libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev libxdo-dev
rustup toolchain install stable --profile minimal        # distro rustc was too old for a dependency
cd src-tauri && cargo +stable build --features custom-protocol
export LD_LIBRARY_PATH=<out dir with libcblite.so>:~/.cache/litert-lm-sys/<ver>/<triple>:~/.cache/litert-sys/<ver>/<triple>
A2A_AUTOSTART='{"name":"scribe","httpPort":8081,"role":"poet","template":"chatml","host":true,"persona":"You are a poet. ...","model":"/path/Qwen2.5-1.5B-Instruct_multi-prefill-seq_q8_ekv4096.litertlm"}' \
  WEBKIT_DISABLE_DMABUF_RENDERER=1 target/debug/cblite-a2a-app
```

* **UI, driven under Xvfb** (`xdotool` + ImageMagick `import`; set `GDK_BACKEND=x11`, unset `WAYLAND_DISPLAY`, and keep one
  `wsl` session open or WSL kills background processes): the form filled with the chatml template
  ([docs/ui-filled.png](docs/ui-filled.png)); a task sent from the UI to the peer `front` over P2P
  ([docs/ui-routed-to-peer.png](docs/ui-routed-to-peer.png)); a task to the local Qwen poet
  ([docs/ui-poet-result.png](docs/ui-poet-result.png): "Raindrops on the tin roof, / Clinging tight as life's rough.").
* `A2A_AUTOSTART` (JSON) makes the UI fill its fields and press *Start node* / *Host* / *Connect*: handy for scripts and tests.
* Linux needs `src-tauri/icons/icon.png` as well as `icon.ico`.
* **Template choice in the app:** `auto` uses the plugin's own LiteRT path, which loses the user message for Qwen models;
  `chatml` uses the library's executor (`a2a_cblite::llm`, raw session + ChatML) and works.

## Build notes (Windows, GNU toolchain)

* The vendored Couchbase Lite C library is `x86_64-pc-windows-gnu`, so use the GNU Rust toolchain.
* `bindgen` needs clang's builtin headers:
  `$env:BINDGEN_EXTRA_CLANG_ARGS = "-IC:/path/to/llvm/lib/clang/<ver>/include"`.
* Use a short `CARGO_TARGET_DIR` (e.g. `C:\cbt`); the default path blows Windows' 260-char limit.
* P2P (`URLEndpointListener`) is **Couchbase Lite Enterprise**: evaluation is free, production needs a licence.

## Business demo: field inspection that survives no signal

An inspector works in a basement with no signal. Three devices, no cloud:

| Device | Does | How |
|---|---|---|
| **tablet** | turns a messy note into a structured report | a real on-device LLM (Qwen2.5-1.5B), works offline |
| **branch** | checks the report has an asset, findings, a risk level and an action; escalates high risk | rules (`--agent reviewer`) |
| **hq** | files an approved report and returns a claim number | rules (`--agent claims`) |

All three run the whole hardened setup: Biscuit tokens (the tablet may only message the branch and head office), TLS with a
pinned certificate, connection admission and encrypted databases.

```bash
MODEL=/path/Qwen2.5-1.5B-Instruct_multi-prefill-seq_q8_ekv4096.litertlm scripts/demo-field-inspection.sh
# then open http://localhost:18801/demo (tablet) and http://localhost:18803/demo (head office)
```

Each node serves a dashboard at `/demo` (its own view of the mesh, the connection, the tasks it holds and the security
panel). On the tablet: submit an inspection and watch the three steps (write, review, file); press **Lose signal**
and submit another: the report is still written on the device and the review waits in the queue; press **Restore signal**
and it is delivered, reviewed and filed. Head office's page shows the claims arrive.

**Verified.** `DEMO_SMOKE=1 scripts/demo-field-inspection.sh` runs the scenario with `curl` and checks it (11 checks on
Linux with the real model: report written, reviewed, filed; link cut, report written offline, queued not lost, delivered
after reconnecting; **no document refused anywhere during normal operation**; a device with a token from another authority
sees nothing of the mesh and the branch logs it; the tablet cannot message nodes its token does not allow). I also drove the
real dashboard in a browser through the whole story: [docs/field-inspection-demo.mp4](docs/field-inspection-demo.mp4) is a
25-second captioned storyboard of those screens (stills: `docs/demo-*.jpg`). The reviewer and claims rules have unit tests.

**What the demo found.** Running it exposed a bug the earlier tests missed: the tablet's own local tasks are commands
addressed to itself, they replicate like any document, and peers refused them because the tablet's token lists only
`branch` and `hq` ("×2 tablet: credential refused" on head office's security panel). A node may always address itself now,
and the smoke test asserts that nothing is refused during normal operation.

**Limits to be upfront about**

* The tablet **page** drives the three steps. Queued work survives in the node (it is stored and delivered when the link
  returns), but if the page is closed before the review comes back, head office is not asked to file it.
* *Lose signal* cuts the node's **outgoing** connections (`POST /link {"up": false}`); a node that other nodes dial into
  keeps those connections.
* A 1.5B model followed the four-line format in every run I did (several, not a benchmark); the rules reject reports that
  do not, and say what is missing. Quality is "plain but correct", not production summarisation.
* LLM agents need Linux or macOS (no LiteRT-LM runtime for Windows). The dashboard and rules agents work anywhere.
* The video is a storyboard of screenshots, not a screen recording.
## Security: signed documents, scoped tokens (Biscuit)

Replication lets any connected peer write any document in the shared collections. This layer closes that on the
**receiving** side: every document is signed by the node that wrote it, and a node only acts on documents that pass
verification. Documents that fail are treated as absent and listed (with counts) at `GET /security`.

A document is accepted when its signature is valid, its author is trusted, the author may write *that kind* of document
(`agents`: only its own card; `tasks`: only tasks it owns; `inbox`: only commands "from" itself) and it is not an older
revision than one already accepted.

Two ways to say who is trusted:

| | Allowlist | Biscuit tokens |
|---|---|---|
| Flags | `--trust trust.json` (or `--trust-peer name=KEY`) | `--root-key ROOT_PUBKEY --token FILE [--revoked FILE]` |
| Trust is | a list of node public keys | tokens signed by one authority |
| Scope | enrolled = may do everything its role allows | per node: which nodes it may message, expiry |
| Delegation | none | a holder can narrow a token offline (`a2a-admin attenuate`) |
| Good for | a few fixed nodes | many nodes, time-limited or limited-purpose access |

```bash
a2a-admin root-keygen --out root.key                       # prints the root PUBLIC key; keep root.key offline
a2a-node --name tablet7 --data ./tablet7 --print-pubkey    # creates the node's key (tablet7/node.pub)
a2a-admin issue --root root.key --node tablet7 --node-dir ./tablet7 --inbox-to branch-1,hq --days 30 --out tablet7.token
a2a-node --name tablet7 --data ./tablet7 --root-key <ROOT_PUBKEY> --token tablet7.token --connect ws://...
a2a-admin attenuate --root-pub <ROOT_PUBKEY> --token tablet7.token --inbox-to hq --minutes 60   # hand a helper less
a2a-admin inspect   --root-pub <ROOT_PUBKEY> --token tablet7.token                              # shows revocation ids
```

A token is a bearer credential, so it is bound to the node's own signing key: every document carries the token **and**
a signature by that key. A stolen token without the key is useless.

### Revocation

`a2a-admin revoke --root root.key --token tablet7.token --reason "tablet lost" --out revoke.json`, then
`curl -X POST --data @revoke.json http://<any node>/security/revocations`. The bundle is signed by the **authority**, not
by a node, so no node can forge one. The receiving node verifies it and stores it in a fourth replicated collection
(`revocations`); every other node picks it up the next time it syncs, **including nodes that were offline when it was
issued**, applies it when it reads the document, and keeps it in its database across restarts. A revoked token is refused
at the connection (with `--admit`) and its documents stop verifying, so the node's earlier cards disappear from the agent
list. Revoking the authority block of a token also kills every attenuated copy of it. (`--revoked FILE` is a local,
hand-edited deny-list for the same ids.)

### Overwrites and deletes

Replication cannot stop an enrolled peer from overwriting or deleting a document, so each secured node keeps the **last
verified copy** of every document it reads or writes. If the stored document later fails verification (overwritten with
something invalid or older) or is deleted, the node answers from the saved copy and **writes it back unchanged**. The
author's signature is inside the document, so any honest node can restore it, not only its author, and a peer cannot
forge a "newer" copy because it cannot sign one. Changes are checked as they arrive, so tampering is repaired even when
nobody is reading the document. A saved copy is re-verified before it is served, so a *revoked* or *expired* author's
documents are not resurrected.

### Clock skew

Each document carries a sequence number that is `max(previous + 1, clock)`, read from the stored revision, so it keeps
rising even if a node's clock is set back and across restarts. (A node whose database is wiped starts again from its
clock; peers that saw a higher number refuse its documents until the clock passes it.)

### Encryption and admission

| Layer | Flag | What it gives |
|---|---|---|
| Link | `--tls` (listener) and `wss://` URLs (dialers) | the P2P link is encrypted (TLS with a self-signed certificate) |
| Server identity | `--pin-cert tls.cert.pem` | a dialer only trusts that exact certificate; without it any self-signed certificate is accepted (encrypted, **not authenticated**) |
| Admission | `--admit` (Biscuit mode) | the listener checks the connecting node's token (valid, unexpired, unrevoked, for that node name); revoked or foreign nodes cannot even connect |
| At rest | `--db-key-env VAR` | the database is encrypted (AES-256) with a key derived from the password in `$VAR`; a wrong key fails to open |

Each listener start makes a **new** certificate (the binding cannot persist an identity on Linux) and writes it to
`<data>/tls.cert.pem`, so a pinned peer must be given the new file after a restart. The listener reports `ws://` URLs even
with TLS on; the node prints `wss://`.

### Tauri app

The app has the same document-level layers: *Security* (off, key list, or Biscuit tokens), a database password, and a
*Security* panel with the node's public key, who is trusted, and what it refused or restored.

**TLS, admission and certificate pinning** need a change to `tauri-plugin-cblite` (its listener used to be plain and
unauthenticated). That change is on the `a2a-p2p-security` branch of the plugin (local branch, not pushed): opt-in`tls` / `requireCredentials` on `startPeerListener`, `pinnedCertificate` / `acceptSelfSigned` on `startReplication`, and a Rust hook`set_peer_admission` for the admission check. To use it, point the app's `tauri-plugin-cblite` dependency at that branch and build with`--features peer-security`; the *TLS* and *require credentials* checkboxes and the *pinned certificate* box then work (the listener's
certificate is saved to `<app data>/tls.cert.pem`).

The app **fails closed**: built against the plugin's `main`, which ignores those options, asking for TLS or credentials stops the
listener and shows an error instead of quietly running unprotected (verified: no P2P port is left open).

### Verified

* Unit tests: `a2a-authz` 13, trust layer 29, and 8 integration tests against the real database that overwrite and delete
  documents the way a replicating peer would (own document, peer document restored without its key, rollback, deleted
  and still listed, repaired with nobody reading, revoked author not resurrected). They pass on Windows and Linux.
* End-to-end on real nodes, Windows: `scripts/e2e.ps1` plain 22, `-Secure` 37, `-Biscuit` 52 (forged revocation refused,
  a node that was offline learns a revocation after syncing, the revoked node is cut off); `scripts/e2e-hardened.ps1`
  23 (TLS + admission + tokens + encrypted databases: plaintext `ws://` refused, a fake authority's node refused at the
  door, no-token node refused, wrong pinned certificate refused, revoked node cannot reconnect, the secret text is not
  in the database files, **control:** it *is* in an unencrypted one, wrong key fails to open).
* Linux (Ubuntu in WSL2): the same hardened scenario with headless nodes, and **two Tauri apps** in Biscuit mode with a
  database password: tasks routed, a revocation posted to one app is learned by the other by replication, and the secret
  text is not in either encrypted database. With the plugin branch the two apps also talk **over TLS with credentials and a
  pinned certificate** (11 checks: plaintext dial, fake authority, no credentials and a wrong pinned certificate are all
  refused; the same node with the right pin connects).
* **Controls:** with security off the same outsider's task runs to `COMPLETED`, so the tests are not vacuous.

### Not covered

* A trusted-but-rogue peer can still keep overwriting a document; we repair it (at most every 2 s per document) but cannot
  stop it, so it is a denial-of-service nuisance, not forgery. The saved copies are in memory: a node that was down while
  a document was tampered with has nothing to restore from until an honest peer that held it restores it.
* A compromised *enrolled* node can still sign lies about itself; revoke its token. Revocation takes effect on a node only
  when it syncs.
* TLS is self-signed (and, in the Tauri app, needs the plugin branch above). Pin the certificate (`--pin-cert`) for server authentication, and expect to redistribute it after a
  listener restart. Admission is bearer-token based (no signature at connection time), so it is admission control, not
  authentication; every document is still signed.
* The password-derived database key means the password is the secret; there is no key management or rotation.
* Allowlist mode has no authority, so no replicated revocation (use Biscuit mode).
* A task an agent runs is whatever text it was sent: tokens decide *who may send*, not whether the text is safe for an LLM
  (prompt injection). Keep agents tool-less or allowlisted.

### Gotchas worth knowing (all found by testing)

1. Couchbase Lite **replication strips top-level properties that start with `_`**. The first design stored the signature as
   `_sig`; unit tests passed and the real two-node run showed every document arriving unsigned. The metadata now lives in
   one non-reserved field, `trust`.
2. Biscuit's authorizer has a **default time budget of 1 ms**. On a loaded or slow machine a perfectly valid token was
   rejected at random ("Reached Datalog execution limits", 1 failure in 40 runs). It is set to 100 ms.
3. A deleted document reads back from Couchbase Lite as an **empty body**, not "not found". The restore logic treats an
   empty or invalid body the same way.
4. "Restore the last verified copy" and **revocation interact**: a revoked author's untouched document fails verification
   too, and would be mistaken for tampering and restored forever. The saved copy is therefore re-verified before use.
## Known issues

* **P2P link flaps every ~3 s on Windows (root cause not found; Linux is fine).** Same code, same Couchbase Lite
  4.1.0 build, Ubuntu 24.04 under WSL2: 0 drops in 12 s and the replicator stays `Idle`. On Windows
  (`x86_64-pc-windows-gnu` library): 3 drops in 9 s. So it is specific to the Windows build of the C library or
  its socket layer, not to this project, the plugin or the settings below. With a continuous push+pull replicator against a
  `URLEndpointListener`, the *listener* drops the connection about a second after it goes `Idle`
  (`No response received after 0 sec -- disconnecting`, WebSocket 1006). The dialer logs
  `Transient error … attempt #2 in 2 sec` and reconnects. Reproduced headless-to-headless and with the
  Tauri app as listener, so it is not specific to either. Sync still completes in each short window
  (the e2e suite passes), but expect log noise and a peer that can look briefly offline.
  Library: Couchbase Lite C 4.1.0 (build 11), Windows x86_64 GNU. The C API exposes no listener-side
  timeout/heartbeat setting. Each of these made **no difference** (3 drops per 9 s in every case): client
  `heartbeat` 0 vs 30, `disable_auto_purge`, the plugin's `Accept` header, `accept_parent_domain_cookies`,
  `max_attempts` 0 vs 5, and loopback vs LAN address (so the plugin's own `start_replication`, which uses
  those settings, flaps identically). LiteCore's verbose/debug console log adds nothing beyond the errors.
  Not yet tried: another Couchbase Lite version, macOS, a Windows MSVC build of the C library.
  `A2A_CBL_LOG=debug a2a-node …` enables LiteCore's console log.

## Known limits

* **Security**: the P2P listener is unauthenticated and unencrypted (`tls_identity: None`, `authenticator: None`,
  same as the plugin). Fine for a trusted LAN. The mesh is one trust domain: every node replicates every task.
  `ListTasks` only shows tasks a node originated or owns, but `GetTask` by id works for any replicated task.
* The A2A HTTP endpoint itself has no auth and no CORS.
* Inbox documents are never purged (add a TTL with `set_document_expiration`, or purge after the owner acks).
* Streaming artifact events don't set `lastChunk`.
* Peer addresses are not discovered automatically (no mDNS yet).
