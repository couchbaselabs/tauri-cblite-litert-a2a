#!/usr/bin/env bash
# Field inspection that survives no signal: a runnable business demo (Linux/macOS).
#
#   tablet  an inspector in a basement. An on-device LLM turns a messy note into a structured report.
#   branch  the branch office. Rules check the report has what it must have and escalate high risk.
#   hq      head office. Files an approved report and returns a claim number.
#
# Everything runs on the devices: no cloud. The three nodes use the whole hardened setup: Biscuit tokens
# (the tablet may only message branch and hq), TLS with a pinned certificate, connection admission and
# encrypted databases.
#
#   MODEL=/path/Qwen2.5-1.5B-Instruct_multi-prefill-seq_q8_ekv4096.litertlm scripts/demo-field-inspection.sh
#
# Then open   http://localhost:18801/demo   (tablet)   and   http://localhost:18803/demo   (head office).
# On the tablet page, "Lose signal" cuts the tablet's connection: new reports are still written on the
# device and wait; "Restore signal" and they flow to the branch and head office.
#
#   DEMO_SMOKE=1 ...   runs the whole scenario with curl instead, prints PASS/FAIL, and exits.
#
# Needs: a2a-node built with --features litert (a2a-admin from the same workspace) and, for the LLM,
# LD_LIBRARY_PATH containing the LiteRT-LM and Couchbase Lite libraries (see README).
set -u
BIN=${A2A_BIN:-target/debug}
NODE=$BIN/a2a-node
ADMIN=$BIN/a2a-admin
MODEL=${MODEL:?set MODEL to a .litertlm file}
WORK=${WORK:-./demo-field}
TABLET=${TABLET_HTTP:-18801}; BRANCH=${BRANCH_HTTP:-18802}; HQ=${HQ_HTTP:-18803}
export A2A_DB_KEY=${A2A_DB_KEY:-demo database password}
export RUST_LOG=${RUST_LOG:-warn}

PERSONA='You write field inspection reports from rough notes.
Reply with exactly four lines and nothing else, in this form:
Asset: <the equipment or place>
Findings: <what was found, in one sentence>
Risk: <Low, Medium or High>
Action: <what to do, and by when>'

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

rm -rf "$WORK" && mkdir -p "$WORK"
root_pub() { sed -n 's/.*root public key: //p'; }
ROOT=$($ADMIN root-keygen --out "$WORK/root.key" | root_pub)
for n in tablet branch hq; do $NODE --name $n --data "$WORK/$n" --print-pubkey > /dev/null; done
# the tablet may message only the branch and head office; the others may message anyone
$ADMIN issue --root "$WORK/root.key" --node tablet --node-dir "$WORK/tablet" --inbox-to branch,hq --out "$WORK/tablet.token" > /dev/null
$ADMIN issue --root "$WORK/root.key" --node branch --node-dir "$WORK/branch" --inbox-to '*' --out "$WORK/branch.token" > /dev/null
$ADMIN issue --root "$WORK/root.key" --node hq     --node-dir "$WORK/hq"     --inbox-to '*' --out "$WORK/hq.token" > /dev/null
HARD() { echo --root-key "$ROOT" --token "$WORK/$1.token" --tls --admit --db-key-env A2A_DB_KEY; }

echo "starting the branch office (listens), head office and tablet (dial the branch)..."
$NODE --name branch --data "$WORK/branch" --http-port "$BRANCH" --agent reviewer $(HARD branch) > "$WORK/branch.out" 2> "$WORK/branch.err" &
pids+=($!)
for i in $(seq 1 30); do grep -q 'P2P port' "$WORK/branch.out" 2>/dev/null && break; sleep 1; done
PORT=$(grep -oP 'P2P port\s+\K\d+' "$WORK/branch.out")
[ -n "$PORT" ] || { echo "the branch node did not start; see $WORK/branch.err"; exit 1; }
URL="wss://127.0.0.1:$PORT/a2a"; PIN="$WORK/branch/tls.cert.pem"
$NODE --name hq --data "$WORK/hq" --http-port "$HQ" --agent claims $(HARD hq) --pin-cert "$PIN" --connect "$URL" > "$WORK/hq.out" 2> "$WORK/hq.err" &
pids+=($!)
$NODE --name tablet --data "$WORK/tablet" --http-port "$TABLET" --model "$MODEL" --role inspector --template chatml \
  --max-tokens 1024 --persona "$PERSONA" $(HARD tablet) --pin-cert "$PIN" --connect "$URL" > "$WORK/tablet.out" 2> "$WORK/tablet.err" &
pids+=($!)

agents() { curl -s --max-time 3 http://127.0.0.1:$1/agents | python3 -c 'import sys,json;print(" ".join(a["nodeId"] for a in json.load(sys.stdin)))' 2>/dev/null; }
echo -n "waiting for the three devices to find each other"
for i in $(seq 1 90); do
  a=" $(agents $TABLET) "; [[ "$a" == *" branch "* && "$a" == *" hq "* ]] && break; echo -n .; sleep 1
done
echo
[[ "$a" == *" branch "* && "$a" == *" hq "* ]] || { echo "the tablet did not see branch and hq; see $WORK/*.err"; exit 1; }

if [ -z "${DEMO_SMOKE:-}" ]; then
  cat <<EOF

  Tablet        http://localhost:$TABLET/demo
  Head office   http://localhost:$HQ/demo
  Branch office http://localhost:$BRANCH/demo

  Try: submit the "Boiler leak" example on the tablet page. Then press "Lose signal", submit another, and watch
  it wait; press "Restore signal". Ctrl-C stops everything.
EOF
  wait
  exit 0
fi

# ── scripted scenario ───────────────────────────────────────────────────────────────────────────────────
ok=0; bad=0
chk() { if [ "$2" = "1" ]; then echo "  PASS  $1"; ok=$((ok+1)); else echo "  FAIL  $1  $3"; bad=$((bad+1)); fi; }
rpc() { curl -s --max-time "${3:-120}" http://127.0.0.1:$1/ -H 'content-type: application/json' -d "$2"; }
send() { # port tenant text [immediate] -> raw JSON
  python3 - "$@" <<'PY'
import sys, json, urllib.request, uuid
port, tenant, text = sys.argv[1], sys.argv[2], sys.argv[3]
params = {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}}
if tenant != "-": params["tenant"] = tenant
if len(sys.argv) > 4: params["configuration"] = {"returnImmediately": True}
req = urllib.request.Request(f"http://127.0.0.1:{port}/", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": params}).encode(), {"content-type": "application/json"})
print(urllib.request.urlopen(req, timeout=180).read().decode())
PY
}
state() { python3 -c 'import sys,json;d=json.load(sys.stdin);t=(d.get("result") or {});t=t.get("task",t);print(t["status"]["state"].replace("TASK_STATE_","") if t else "ERR "+str(d.get("error")))'; }
text()  { python3 -c 'import sys,json;d=json.load(sys.stdin);t=(d.get("result") or {});t=t.get("task",t);print("".join(p.get("text","") for a in t.get("artifacts",[]) for p in a["parts"]))'; }
link()  { curl -s -X POST http://127.0.0.1:$TABLET/link -d "{\"up\":$1}" > /dev/null; }

echo "== the scenario"
NOTE="Plant room B, boiler 3. Feed pipe is corroded near the flange and there is a small leak at the isolation valve. Floor is wet. Needs sorting this week, it could fail."
echo "-- 1. connected: the tablet writes the report on the device"
R=$(send $TABLET - "$NOTE"); REPORT=$(echo "$R" | text)
chk "the on-device model writes a report" $([ "$(echo "$R" | state)" = "COMPLETED" ] && [ -n "$REPORT" ] && echo 1 || echo 0) "$(echo "$R" | state)"
echo "$REPORT" | sed 's/^/        /'
RV=$(send $TABLET branch "$REPORT"); REVIEW=$(echo "$RV" | text)
chk "the branch reviews it" $([ "$(echo "$RV" | state)" = "COMPLETED" ] && echo "$REVIEW" | grep -q '^REVIEW:' && echo 1 || echo 0) "$REVIEW"
echo "$REVIEW" | sed 's/^/        /'
HQR=$(send $TABLET hq "$REPORT"$'\n\n'"$REVIEW"); CLAIM=$(echo "$HQR" | text)
echo "$CLAIM" | sed 's/^/        /'
chk "head office answers (files it if approved)" $(echo "$CLAIM" | grep -qE 'CLAIM FILED|NOT FILED' && echo 1 || echo 0) "$CLAIM"

echo "-- 2. the signal is lost"
link false; sleep 2
chk "the tablet reports its link as down" $(curl -s http://127.0.0.1:$TABLET/link | python3 -c 'import sys,json;print(1 if json.load(sys.stdin)["up"] is False else 0)')
R2=$(send $TABLET - "Warehouse roof vent 12. Seals look good, no water ingress, nothing to do."); REPORT2=$(echo "$R2" | text)
chk "offline, the tablet still writes a report on the device" $([ "$(echo "$R2" | state)" = "COMPLETED" ] && [ -n "$REPORT2" ] && echo 1 || echo 0) "$(echo "$R2" | state)"
echo "$REPORT2" | sed 's/^/        /'
Q=$(send $TABLET branch "$REPORT2" immediate); QID=$(echo "$Q" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["task"]["id"])')
sleep 6
chk "the report for the branch waits: queued, not lost" $([ "$(rpc $TABLET "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"GetTask\",\"params\":{\"id\":\"$QID\"}}" 20 | state)" = "SUBMITTED" ] && echo 1 || echo 0)

echo "-- 3. the signal returns"
link true
D=0; for i in $(seq 1 60); do [ "$(rpc $TABLET "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"GetTask\",\"params\":{\"id\":\"$QID\"}}" 20 | state)" = "COMPLETED" ] && D=1 && break; sleep 1; done
chk "the queued report is delivered and reviewed after reconnecting" $D
chk "nothing was refused anywhere during normal operation (no false alarms)" $(for p in $TABLET $BRANCH $HQ; do curl -s http://127.0.0.1:$p/security | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["rejections"]))'; done | awk '{s+=$1} END {print (s==0)?1:0}')

echo "-- 4. an unauthorised device tries to join"
$NODE --name mallory --data "$WORK/mallory" --print-pubkey > /dev/null
FAKE=$($ADMIN root-keygen --out "$WORK/fake.key" | root_pub)
$ADMIN issue --root "$WORK/fake.key" --node mallory --node-dir "$WORK/mallory" --inbox-to '*' --out "$WORK/mallory.token" > /dev/null
$NODE --name mallory --data "$WORK/mallory" --http-port 18809 --root-key "$FAKE" --token "$WORK/mallory.token" --tls --admit --db-key-env A2A_DB_KEY --connect "$URL" > "$WORK/mallory.out" 2> "$WORK/mallory.err" &
pids+=($!)
sleep 10
chk "a device with a token from another authority sees nothing of the mesh" $([[ " $(agents 18809) " != *" branch "* ]] && echo 1 || echo 0) "$(agents 18809)"
chk "the branch logged the refused connection" $(curl -s http://127.0.0.1:$BRANCH/security | python3 -c 'import sys,json;print(1 if any(r["collection"]=="connection" and r["docId"]=="mallory" for r in json.load(sys.stdin)["rejections"]) else 0)')
chk "the tablet cannot be used to message anyone it has no right to (scoped token)" $(python3 - <<PY
import json,urllib.request
req=urllib.request.Request("http://127.0.0.1:$TABLET/",json.dumps({"jsonrpc":"2.0","id":9,"method":"SendMessage","params":{"tenant":"nobody","message":{"messageId":"x","role":"ROLE_USER","parts":[{"text":"x"}]}}}).encode(),{"content-type":"application/json"})
d=json.loads(urllib.request.urlopen(req,timeout=20).read()); print(1 if d.get("error") else 0)
PY
)

echo "RESULT pass=$ok fail=$bad"
[ "$bad" = 0 ]
