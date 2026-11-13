# End-to-end test: two a2a-node processes replicate peer-to-peer; every request is
# sent to ALICE and routed to BOB (tenant = "bob") through Couchbase Lite.
#
#   pwsh scripts/e2e.ps1 -Exe C:\cbt\debug\a2a-node.exe
#
# With -Secure every document is signed and verified (alice and bob trust each other), and two
# outsiders try to get in: "mallory" (own key, not enrolled) and "legacy" (no signing at all).
#
#   pwsh scripts/e2e.ps1 -Exe C:\cbt\debug\a2a-node.exe -Secure
#
# With -Biscuit nodes are trusted through Biscuit tokens issued by one authority (a2a-admin) instead of
# a key list. Besides "mallory" (token from a FAKE authority) and "legacy" (unsigned), "carol" holds a
# real token that only lets her message bob: she can task bob but not alice.
#
#   pwsh scripts/e2e.ps1 -Exe C:\cbt\debug\a2a-node.exe -Admin C:\cbt\debug\a2a-admin.exe -Biscuit
param(
  [string]$Exe = "C:\cbt\debug\a2a-node.exe",
  [string]$Admin = "C:\cbt\debug\a2a-admin.exe",
  [string]$Work = "C:\cbt\e2e",
  [switch]$Secure,
  [switch]$Biscuit
)
if ($Biscuit) { $Secure = $true }
$ErrorActionPreference = "Stop"
$fail = 0
function Check($name, $cond, $detail = "") {
  if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
  else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fail++ }
}
function Rpc($port, $method, $params) {
  $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Depth 20
  Invoke-RestMethod -Uri "http://127.0.0.1:$port/" -Method Post -ContentType "application/json" -Body $body
}
function Msg($text, $taskId = $null) {
  $m = @{ messageId = [guid]::NewGuid().ToString(); role = "ROLE_USER"; parts = @(@{ text = $text }) }
  if ($taskId) { $m.taskId = $taskId }
  $m
}
function StartNode($name, $http, $extra = @()) {
  $out = "$Work\$name.out.txt"; $err = "$Work\$name.err.txt"
  $extra = @($extra | Where-Object { $null -ne $_ })   # SecFor returns nothing (not an empty array) when unsecured
  $p = Start-Process $Exe -ArgumentList (@("--name", $name, "--data", "$Work\$name", "--http-port", $http) + $extra) `
        -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  for ($i = 0; $i -lt 50; $i++) {
    if ((Test-Path $out) -and ((Get-Content $out -ErrorAction SilentlyContinue | Measure-Object).Count -ge 3)) { break }
    Start-Sleep -Milliseconds 200
  }
  $p
}

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:RUST_LOG = "warn"

function PubKey($name) { ((& $Exe --name $name --data "$Work\$name" --print-pubkey) -split '\s+')[1] }
function TrustFile($path, $names) {
  $nodes = [ordered]@{}; foreach ($n in $names) { $nodes[$n] = PubKey $n }
  [IO.File]::WriteAllText($path, (@{ nodes = $nodes } | ConvertTo-Json))
}

function RootKey($name) {
  $o = (& $Admin root-keygen --out "$Work\$name.key") -join "`n"
  ([regex]::Match($o, 'root public key:\s*(\S+)')).Groups[1].Value
}
function IssueToken($rootName, $node, $inboxTo) {
  [void](& $Admin issue --root "$Work\$rootName.key" --node $node --node-dir "$Work\$node" --inbox-to $inboxTo --out "$Work\$node.token")
}

# command-line security options for one node
function SecFor($node) {
  if ($Biscuit) { return @("--root-key", $script:rootPub, "--token", "$Work\$node.token") }
  if ($Secure) { return @("--trust", "$Work\trust.json") }
  @()
}

if ($Biscuit) {
  Write-Host "BISCUIT MODE: authority, node keys and tokens"
  $rootPub = RootKey "root"       # the real mesh authority
  $fakePub = RootKey "fake"       # an impostor authority (mallory's)
  foreach ($n in @("alice", "bob", "carol", "mallory")) { [void](PubKey $n) }   # creates each node's key
  IssueToken "root" "alice" "*"
  IssueToken "root" "bob" "*"
  IssueToken "root" "carol" "bob"   # carol may only message bob
  IssueToken "fake" "mallory" "*"   # signed by the impostor authority
}
elseif ($Secure) {
  Write-Host "SECURE MODE: generating keys and trust lists"
  TrustFile "$Work\trust.json" @("alice", "bob")          # alice and bob trust only each other
  TrustFile "$Work\trust-mallory.json" @("alice", "bob")  # mallory trusts them, they do not trust her
}

Write-Host "Starting alice and bob"
$alice = StartNode "alice" 18081 (SecFor "alice")
$port = ((Get-Content "$Work\alice.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
$bob = StartNode "bob" 18082 (@("--connect", "ws://127.0.0.1:$port/a2a") + (SecFor "bob"))
$mallory = $null; $legacy = $null; $carol = $null

try {
  if ($Secure) {
    $s = Invoke-RestMethod "http://127.0.0.1:18081/security"
    if ($Biscuit) { Check "alice reports Biscuit mode" ($s.secure -eq $true -and $s.mode -eq "biscuit") }
    else { Check "alice reports secure mode with bob enrolled" ($s.secure -eq $true -and ($s.enrolled -contains "bob") -and -not ($s.enrolled -contains "mallory")) }
  }

  # ── discovery: agent cards replicate ──────────────────────────────────────
  Write-Host "Discovery"
  $ok = $false
  for ($i = 0; $i -lt 50 -and -not $ok; $i++) {
    Start-Sleep -Milliseconds 300
    $a = Invoke-RestMethod "http://127.0.0.1:18081/agents"
    $ok = ($a | Where-Object { $_.nodeId -eq "bob" }) -ne $null
  }
  Check "alice learns bob's card over P2P" $ok
  $card = Invoke-RestMethod "http://127.0.0.1:18081/agents/bob/agent-card.json"
  Check "peer card is rewritten to alice's gateway + tenant" ($card.supportedInterfaces[0].tenant -eq "bob" -and $card.supportedInterfaces[0].url -like "*18081*")

  # ── routed SendMessage (blocking) ────────────────────────────────────────
  Write-Host "SendMessage alice -> bob"
  $r = Rpc 18081 "SendMessage" @{ tenant = "bob"; message = (Msg "hello from alice") }
  $t = $r.result.task
  Check "task COMPLETED" ($t.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 10 -Compress)
  Check "artifact streamed back through replication" (($t.artifacts[0].parts | ForEach-Object { $_.text }) -join "" -eq "hello from alice")
  $rb = Rpc 18082 "GetTask" @{ id = $t.id }
  Check "bob (owner) has the task too" ($rb.result.id -eq $t.id)
  $rl = Rpc 18081 "ListTasks" @{}
  Check "ListTasks on origin" ($rl.result.totalSize -ge 1)

  # ── local (no tenant) ─────────────────────────────────────────────────────
  Write-Host "SendMessage local"
  $r = Rpc 18081 "SendMessage" @{ message = (Msg "local run") }
  Check "alice runs its own task" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED")

  # ── input-required round trip ─────────────────────────────────────────────
  Write-Host "INPUT_REQUIRED"
  $r = Rpc 18081 "SendMessage" @{ tenant = "bob"; message = (Msg "ask") }
  Check "INPUT_REQUIRED" ($r.result.task.status.state -eq "TASK_STATE_INPUT_REQUIRED")
  $tid = $r.result.task.id
  $r = Rpc 18081 "SendMessage" @{ message = (Msg "forty two" $tid) }
  Check "follow-up completes the same task" ($r.result.task.id -eq $tid -and $r.result.task.status.state -eq "TASK_STATE_COMPLETED")
  Check "history holds both user turns + agent question" ($r.result.task.history.Count -ge 3)

  # ── streaming ─────────────────────────────────────────────────────────────
  Write-Host "SendStreamingMessage"
  $body = @{ jsonrpc = "2.0"; id = 7; method = "SendStreamingMessage"; params = @{ tenant = "bob"; message = (Msg "one two three four") } } | ConvertTo-Json -Depth 10 -Compress
  [IO.File]::WriteAllText("$Work\stream.json", $body)
  $sse = & curl.exe -sN --max-time 20 -H "Content-Type: application/json" --data-binary "@$Work\stream.json" http://127.0.0.1:18081/
  $events = @($sse -split "`n" | Where-Object { $_ -like "data:*" } | ForEach-Object { ($_ -replace '^data:\s*', '') | ConvertFrom-Json })
  if ($events.Count -eq 0) { Write-Host "  raw SSE output: $sse" }
  $kinds = @($events | ForEach-Object { ($_.result | Get-Member -MemberType NoteProperty).Name })
  Check "first event is the task" ($kinds[0] -eq "task")
  Check "artifactUpdate events arrive" (($kinds | Where-Object { $_ -eq "artifactUpdate" }).Count -ge 2) ($kinds -join ",")
  Check "stream ends with COMPLETED statusUpdate" ($events[-1].result.statusUpdate.status.state -eq "TASK_STATE_COMPLETED")

  # ── cancel ────────────────────────────────────────────────────────────────
  Write-Host "CancelTask"
  $r = Rpc 18081 "SendMessage" @{ tenant = "bob"; message = (Msg "slow"); configuration = @{ returnImmediately = $true } }
  $tid = $r.result.task.id
  Check "returnImmediately gives a non-terminal task" ($r.result.task.status.state -in @("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING"))
  Start-Sleep -Milliseconds 800
  $c = Rpc 18081 "CancelTask" @{ id = $tid }
  Check "remote task canceled" ($c.result.status.state -eq "TASK_STATE_CANCELED") ($c | ConvertTo-Json -Depth 10 -Compress)
  $c2 = Rpc 18081 "CancelTask" @{ id = $tid }
  Check "cancel of terminal task -> -32002" ($c2.error.code -eq -32002)

  # ── errors ────────────────────────────────────────────────────────────────
  Write-Host "Errors"
  Check "unknown task -> -32001" ((Rpc 18081 "GetTask" @{ id = "nope" }).error.code -eq -32001)
  Check "unknown method -> -32601" ((Rpc 18081 "Nope" @{}).error.code -eq -32601)
  Check "unknown tenant -> -32602" ((Rpc 18081 "SendMessage" @{ tenant = "zed"; message = (Msg "x") }).error.code -eq -32602)

  # ── outsiders (secure mode only) ──────────────────────────────────────────
  if ($Secure) {
    Write-Host "Outsiders: mallory (not enrolled) and legacy (unsigned) dial alice"
    $tasksBefore = (Rpc 18081 "ListTasks" @{}).result.totalSize
    $malArgs = if ($Biscuit) { @("--root-key", $fakePub, "--token", "$Work\mallory.token") } else { @("--trust", "$Work\trust-mallory.json") }
    $mallory = StartNode "mallory" 18083 (@("--connect", "ws://127.0.0.1:$port/a2a") + $malArgs)
    $legacy = StartNode "legacy" 18084 @("--connect", "ws://127.0.0.1:$port/a2a")
    $seen = $false
    if ($Biscuit) {
      # mallory trusts only her own (fake) authority, so she cannot read alice's cards; her
      # connection is proven by alice receiving, and refusing, her documents
      for ($i = 0; $i -lt 60 -and -not $seen; $i++) {
        Start-Sleep -Milliseconds 300
        [void](Invoke-RestMethod "http://127.0.0.1:18081/agents")   # a document is only checked when it is read
        $seen = ((Invoke-RestMethod "http://127.0.0.1:18081/security").rejections | Where-Object { $_.author -eq "mallory" }) -ne $null
      }
      Check "mallory is connected and replicating (alice has received and refused her documents)" $seen
    }
    else {
      # mallory trusts alice, so she must see alice: proves she is connected and replicating
      for ($i = 0; $i -lt 60 -and -not $seen; $i++) {
        Start-Sleep -Milliseconds 300
        $seen = ((Invoke-RestMethod "http://127.0.0.1:18083/agents") | Where-Object { $_.nodeId -eq "alice" }) -ne $null
      }
      Check "mallory is connected and sees alice (so any refusal is about trust, not connectivity)" $seen
    }
    $rm = Rpc 18083 "SendMessage" @{ tenant = "alice"; message = (Msg "mallory wants to run something"); configuration = @{ returnImmediately = $true } }
    $rl = Rpc 18084 "SendMessage" @{ tenant = "alice"; message = (Msg "legacy wants to run something"); configuration = @{ returnImmediately = $true } }
    Start-Sleep -Seconds 6
    $actors = @(@{ n = "legacy"; port = 18084; r = $rl })
    if ($Biscuit) {
      # trusting only her own authority, mallory cannot verify alice's card, so she cannot even address her
      Check "mallory cannot address alice (her authority does not vouch for alice's card)" ($rm.error.code -eq -32602) ($rm | ConvertTo-Json -Compress -Depth 5)
    }
    else { $actors = @(@{ n = "mallory"; port = 18083; r = $rm }) + $actors }
    foreach ($who in $actors) {
      $tid = $who.r.result.task.id
      Check "$($who.n)'s task never ran (still SUBMITTED on $($who.n))" ((Rpc $who.port "GetTask" @{ id = $tid }).result.status.state -eq "TASK_STATE_SUBMITTED")
      Check "alice has no record of $($who.n)'s task" ((Rpc 18081 "GetTask" @{ id = $tid }).error.code -eq -32001)
      Check "bob has no record of it either" ((Rpc 18082 "GetTask" @{ id = $tid }).result.status.state -ne "TASK_STATE_COMPLETED")
    }
    Check "alice's task list is unchanged" ((Rpc 18081 "ListTasks" @{}).result.totalSize -eq $tasksBefore)
    foreach ($port2 in @(18081, 18082)) {
      $names = (Invoke-RestMethod "http://127.0.0.1:$port2/agents") | ForEach-Object { $_.nodeId }
      Check "node on :$port2 does not list mallory or legacy as agents" (-not ($names -contains "mallory") -and -not ($names -contains "legacy")) ($names -join ",")
    }
    foreach ($port2 in @(18081, 18082)) {
      $rej = (Invoke-RestMethod "http://127.0.0.1:$port2/security").rejections
      $why = if ($Biscuit) { "credential refused*" } else { "*not enrolled*" }
      Check "node on :$port2 logged mallory ($(if ($Biscuit) { 'token from a fake authority' } else { 'not enrolled' }))" (($rej | Where-Object { $_.author -eq "mallory" -and $_.reason -like $why }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
      Check "node on :$port2 logged legacy's documents as unsigned" (($rej | Where-Object { $_.reason -eq "unsigned document" }) -ne $null)
    }
    foreach ($p in @($mallory, $legacy)) { if ($p -and -not $p.HasExited) { $p.Kill() } }

    # ── carol: a genuine token, but only for bob (Biscuit mode) ───────────────
    if ($Biscuit) {
      Write-Host "Scoped token: carol may message bob, not alice"
      $carol = StartNode "carol" 18085 (@("--connect", "ws://127.0.0.1:$port/a2a") + (SecFor "carol"))
      $sees = $false
      for ($i = 0; $i -lt 80 -and -not $sees; $i++) {
        Start-Sleep -Milliseconds 300
        $n = (Invoke-RestMethod "http://127.0.0.1:18085/agents") | ForEach-Object { $_.nodeId }
        $sees = ($n -contains "alice") -and ($n -contains "bob")
      }
      Check "carol's token is accepted: she joins the mesh and sees alice and bob" $sees ($n -join ",")
      Check "alice lists carol as an agent" ((((Invoke-RestMethod "http://127.0.0.1:18081/agents") | ForEach-Object { $_.nodeId }) -contains "carol"))
      $r = Rpc 18085 "SendMessage" @{ tenant = "bob"; message = (Msg "carol asks bob") }
      Check "carol -> bob COMPLETES (her token allows bob)" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)
      $r = Rpc 18085 "SendMessage" @{ tenant = "alice"; message = (Msg "carol asks alice"); configuration = @{ returnImmediately = $true } }
      $ctid = $r.result.task.id
      Start-Sleep -Seconds 6
      Check "carol -> alice never runs (her token does not allow alice)" ((Rpc 18085 "GetTask" @{ id = $ctid }).result.status.state -eq "TASK_STATE_SUBMITTED")
      Check "alice has no record of that task" ((Rpc 18081 "GetTask" @{ id = $ctid }).error.code -eq -32001)
      $rej = (Invoke-RestMethod "http://127.0.0.1:18081/security").rejections
      Check "alice logged carol's command: credential refused" (($rej | Where-Object { $_.author -eq "carol" -and $_.collection -eq "inbox" -and $_.reason -like "credential refused*" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
      if ($carol -and -not $carol.HasExited) { $carol.Kill() }
    }
  }

  # ── store and forward: bob offline ────────────────────────────────────────
  Write-Host "Store-and-forward (bob offline)"
  $bob.Kill(); $bob.WaitForExit()
  Start-Sleep -Milliseconds 500
  $r = Rpc 18081 "SendMessage" @{ tenant = "bob"; message = (Msg "sent while bob was away"); configuration = @{ returnImmediately = $true } }
  $tid = $r.result.task.id
  Check "alice accepts it as SUBMITTED" ($r.result.task.status.state -eq "TASK_STATE_SUBMITTED")
  Start-Sleep -Seconds 2
  Check "still SUBMITTED while bob is down" ((Rpc 18081 "GetTask" @{ id = $tid }).result.status.state -eq "TASK_STATE_SUBMITTED")

  # ── revocation, issued while bob is offline (Biscuit mode) ────────────────
  if ($Biscuit) {
    Write-Host "Revocation of carol's token while bob is offline"
    $insp = (& $Admin inspect --root-pub $rootPub --token "$Work\carol.token") -join "`n"
    $cid = ([regex]::Match($insp, 'revocation ids:\s*([0-9a-f]+)')).Groups[1].Value
    Check "carol's token has a revocation id" ($cid.Length -ge 32)
    $post = {
      param($file)
      try { $r = Invoke-RestMethod -Uri "http://127.0.0.1:18081/security/revocations" -Method Post -ContentType "application/json" -InFile $file; @{ code = 200; body = $r } }
      catch { @{ code = [int]$_.Exception.Response.StatusCode; body = $null } }
    }
    # an impostor authority tries to revoke carol (or anyone): refused
    [void](& $Admin revoke --root "$Work\fake.key" --id $cid --reason "forged" --out "$Work\forged-revoke.json")
    Check "a revocation signed by a fake authority is refused (HTTP 400)" ((& $post "$Work\forged-revoke.json").code -eq 400)
    Check "...and nothing was revoked" (@((Invoke-RestMethod "http://127.0.0.1:18081/security").revokedTokens).Count -eq 0)
    # the real authority revokes it
    [void](& $Admin revoke --root "$Work\root.key" --token "$Work\carol.token" --reason "tablet lost" --out "$Work\carol-revoke.json")
    $res = & $post "$Work\carol-revoke.json"
    Check "alice accepts the authority's revocation" ($res.code -eq 200 -and $res.body.revoked -eq $cid)
    Check "alice now lists the token as revoked" ((Invoke-RestMethod "http://127.0.0.1:18081/security").revokedTokens -contains $cid)
  }
  $bob = StartNode "bob" 18082 (@("--connect", "ws://127.0.0.1:$port/a2a") + (SecFor "bob"))  # same data dir: resumes where it left off
  $done = $false
  for ($i = 0; $i -lt 60 -and -not $done; $i++) {
    Start-Sleep -Milliseconds 500
    $done = (Rpc 18081 "GetTask" @{ id = $tid }).result.status.state -eq "TASK_STATE_COMPLETED"
  }
  Check "bob comes back, pulls the inbox, completes it" $done

  if ($Biscuit) {
    # bob was offline when the revocation was issued: he must learn of it by syncing
    $learned = $false
    for ($i = 0; $i -lt 60 -and -not $learned; $i++) {
      Start-Sleep -Milliseconds 400
      $learned = (Invoke-RestMethod "http://127.0.0.1:18082/security").revokedTokens -contains $cid
    }
    Check "bob, offline when it was issued, learns the revocation after syncing" $learned

    Write-Host "Revoked carol comes back"
    $carol = StartNode "carol" 18085 (@("--connect", "ws://127.0.0.1:$port/a2a") + (SecFor "carol"))
    Start-Sleep -Seconds 8
    foreach ($port2 in @(18081, 18082)) {
      $n = (Invoke-RestMethod "http://127.0.0.1:$port2/agents") | ForEach-Object { $_.nodeId }
      Check "node on :$port2 no longer lists carol (her earlier card is not served from a saved copy)" (-not ($n -contains "carol")) ($n -join ",")
    }
    $r = Rpc 18085 "SendMessage" @{ tenant = "bob"; message = (Msg "revoked carol tries bob"); configuration = @{ returnImmediately = $true } }
    $rtid = $r.result.task.id
    Start-Sleep -Seconds 6
    Check "revoked carol's task to bob never runs" ((Rpc 18085 "GetTask" @{ id = $rtid }).result.status.state -eq "TASK_STATE_SUBMITTED")
    Check "bob has no record of it" ((Rpc 18082 "GetTask" @{ id = $rtid }).error.code -eq -32001)
    $rej = (Invoke-RestMethod "http://127.0.0.1:18082/security").rejections
    Check "bob logged carol: token revoked" (($rej | Where-Object { $_.author -eq "carol" -and $_.reason -like "*revoked*" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
    if ($carol -and -not $carol.HasExited) { $carol.Kill() }
  }
}
finally {
  foreach ($p in @($alice, $bob, $mallory, $legacy, $carol)) { if ($p -and -not $p.HasExited) { $p.Kill() } }
}
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }
