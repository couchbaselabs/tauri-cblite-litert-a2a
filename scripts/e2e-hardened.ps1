# End-to-end test of the whole hardened setup on real nodes:
#   Biscuit tokens + TLS (wss://) + connection admission + an encrypted database.
# Each layer gets an attacker that the layer alone must stop.
#
#   pwsh scripts/e2e-hardened.ps1 -Exe C:\cbt\debug\a2a-node.exe -Admin C:\cbt\debug\a2a-admin.exe
param(
  [string]$Exe = "C:\cbt\debug\a2a-node.exe",
  [string]$Admin = "C:\cbt\debug\a2a-admin.exe",
  [string]$Work = "C:\cbt\e2e-hard"
)
$ErrorActionPreference = "Stop"
$fail = 0
$MARKER = "TOP-SECRET-MARKER-7421"
function Check($name, $cond, $detail = "") {
  if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
  else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fail++ }
}
function Rpc($port, $method, $params) {
  $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Depth 20
  Invoke-RestMethod -Uri "http://127.0.0.1:$port/" -Method Post -ContentType "application/json" -Body $body
}
function Msg($text) { @{ messageId = [guid]::NewGuid().ToString(); role = "ROLE_USER"; parts = @(@{ text = $text }) } }
function StartNode($name, $http, $extra = @()) {
  $out = "$Work\$name.out.txt"; $err = "$Work\$name.err.txt"
  $extra = @($extra | Where-Object { $null -ne $_ })
  $p = Start-Process $Exe -ArgumentList (@("--name", $name, "--data", "$Work\$name", "--http-port", $http) + $extra) `
        -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  for ($i = 0; $i -lt 50; $i++) {
    if ((Test-Path $out) -and ((Get-Content $out -ErrorAction SilentlyContinue | Measure-Object).Count -ge 3)) { break }
    Start-Sleep -Milliseconds 200
  }
  $p
}
function Agents($port) { try { @((Invoke-RestMethod "http://127.0.0.1:$port/agents") | ForEach-Object { $_.nodeId }) } catch { @() } }
function WaitSees($port, $name, $secs = 15) {
  for ($i = 0; $i -lt ($secs * 3); $i++) { if ((Agents $port) -contains $name) { return $true }; Start-Sleep -Milliseconds 330 }
  $false
}
function PubKey($name) { ((& $Exe --name $name --data "$Work\$name" --print-pubkey) -split '\s+')[1] }
function RootKey($name) {
  $o = (& $Admin root-keygen --out "$Work\$name.key") -join "`n"
  ([regex]::Match($o, 'root public key:\s*(\S+)')).Groups[1].Value
}
function IssueToken($rootName, $node, $inboxTo) {
  [void](& $Admin issue --root "$Work\$rootName.key" --node $node --node-dir "$Work\$node" --inbox-to $inboxTo --out "$Work\$node.token")
}
function Hard($node, $pubRoot) { @("--root-key", $pubRoot, "--token", "$Work\$node.token", "--tls", "--admit", "--db-key-env", "A2A_DB_KEY") }
function FileContains($dir, $text) {
  $needle = [Text.Encoding]::ASCII.GetBytes($text)
  foreach ($f in Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $s = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    if ($s.Contains($text)) { return $f.FullName }
  }
  $null
}
function Kill($p) { if ($p -and -not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:RUST_LOG = "warn"
$env:A2A_DB_KEY = "correct horse battery staple"

Write-Host "Setup: authority, node keys, tokens"
$rootPub = RootKey "root"; $fakePub = RootKey "fake"
foreach ($n in @("alice", "bob", "carol", "dave", "mallory")) { [void](PubKey $n) }
IssueToken "root" "alice" "*"; IssueToken "root" "bob" "*"
IssueToken "root" "carol" "bob"; IssueToken "root" "dave" "bob"
IssueToken "fake" "mallory" "*"

$procs = @()
try {
  Write-Host "Hardened mesh: alice (listener) and bob (dialer) over wss://, tokens, encrypted databases"
  $alice = StartNode "alice" 18601 (Hard "alice" $rootPub); $procs += $alice
  $port = ((Get-Content "$Work\alice.out.txt") | Select-String 'P2P port\s+(\d+)').Matches[0].Groups[1].Value
  $url = "wss://127.0.0.1:$port/a2a"
  $aliceOut = (Get-Content "$Work\alice.out.txt") -join "`n"
  Check "alice reports TLS, admission and an encrypted database" ($aliceOut -match 'transport TLS' -and $aliceOut -match 'admission' -and $aliceOut -match 'database encrypted')
  Check "alice's listener URLs are wss://" ($aliceOut -match 'P2P url\s+wss://')
  Check "alice wrote her certificate for peers to pin" (Test-Path "$Work\alice\tls.cert.pem")
  $bob = StartNode "bob" 18602 (@("--connect", $url) + (Hard "bob" $rootPub)); $procs += $bob
  Check "bob (with a valid token) joins over TLS and sees alice" (WaitSees 18602 "alice")
  Check "alice sees bob" (WaitSees 18601 "bob")
  $r = Rpc 18601 "SendMessage" @{ tenant = "bob"; message = (Msg "routed through TLS, admission and an encrypted database: $MARKER") }
  Check "a task alice -> bob completes over the hardened link" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED") ($r | ConvertTo-Json -Depth 6 -Compress)

  Write-Host "Attackers"
  # 1. plaintext: a node with a REAL token but no TLS dials ws:// on the TLS listener
  $plain = StartNode "carol" 18603 @("--connect", "ws://127.0.0.1:$port/a2a", "--root-key", $rootPub, "--token", "$Work\carol.token", "--db-key-env", "A2A_DB_KEY"); $procs += $plain
  Start-Sleep -Seconds 8
  Check "plaintext ws:// to the TLS listener is refused (carol never sees alice)" (-not ((Agents 18603) -contains "alice")) ((Agents 18603) -join ",")
  Check "...and alice never sees carol" (-not ((Agents 18601) -contains "carol"))
  Kill $plain

  # 2. a node from a fake authority, over TLS: admission refuses it at the door
  $mal = StartNode "mallory" 18604 (@("--connect", $url) + (Hard "mallory" $fakePub)); $procs += $mal
  Start-Sleep -Seconds 8
  Check "a fake authority's token does not get mallory in" (-not ((Agents 18604) -contains "alice"))
  $rej = (Invoke-RestMethod "http://127.0.0.1:18601/security").rejections
  Check "alice logged the refused connection for mallory" (($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "mallory" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
  Check "no mallory document ever reached alice" (-not ((Agents 18601) -contains "mallory"))
  Kill $mal

  # 3. TLS but no credentials at all
  $anon = StartNode "anon" 18605 @("--connect", $url, "--tls"); $procs += $anon
  Start-Sleep -Seconds 8
  Check "a node with TLS but no token is refused (anon never sees alice)" (-not ((Agents 18605) -contains "alice"))
  Kill $anon

  # 4. certificate pinning
  Copy-Item "$Work\mallory\tls.cert.pem" "$Work\wrong.cert.pem"
  $dave = StartNode "dave" 18606 (@("--connect", $url, "--pin-cert", "$Work\wrong.cert.pem") + (Hard "dave" $rootPub)); $procs += $dave
  Start-Sleep -Seconds 8
  Check "pinning the wrong certificate: dave cannot connect (even with a valid token)" (-not ((Agents 18606) -contains "alice")) ((Agents 18606) -join ",")
  Kill $dave
  $dave = StartNode "dave" 18606 (@("--connect", $url, "--pin-cert", "$Work\alice\tls.cert.pem") + (Hard "dave" $rootPub)); $procs += $dave
  Check "pinning alice's real certificate: dave connects" (WaitSees 18606 "alice")
  $r = Rpc 18606 "SendMessage" @{ tenant = "bob"; message = (Msg "dave via a pinned link") }
  Check "dave (token: bob only) can task bob" ($r.result.task.status.state -eq "TASK_STATE_COMPLETED")
  Kill $dave

  # 5. revocation also closes the door
  $carol = StartNode "carol" 18603 (@("--connect", $url) + (Hard "carol" $rootPub)); $procs += $carol
  Check "carol (valid token, TLS) joins" (WaitSees 18603 "alice")
  Kill $carol
  [void](& $Admin revoke --root "$Work\root.key" --token "$Work\carol.token" --reason "tablet lost" --out "$Work\carol-revoke.json")
  $res = Invoke-RestMethod -Uri "http://127.0.0.1:18601/security/revocations" -Method Post -ContentType "application/json" -InFile "$Work\carol-revoke.json"
  Check "the authority's revocation is accepted" ($res.revoked.Length -ge 32)
  $carol = StartNode "carol" 18603 (@("--connect", $url) + (Hard "carol" $rootPub)); $procs += $carol
  $r = Rpc 18603 "SendMessage" @{ tenant = "bob"; message = (Msg "revoked carol tries again"); configuration = @{ returnImmediately = $true } }
  $ctid = $r.result.task.id
  Start-Sleep -Seconds 8
  Check "revoked carol cannot get her task out (it never reaches bob)" ((Rpc 18603 "GetTask" @{ id = $ctid }).result.status.state -eq "TASK_STATE_SUBMITTED" -and (Rpc 18602 "GetTask" @{ id = $ctid }).error.code -eq -32001)
  $rej = (Invoke-RestMethod "http://127.0.0.1:18601/security").rejections
  Check "alice logged the refused connection: token revoked" (($rej | Where-Object { $_.collection -eq "connection" -and $_.docId -eq "carol" -and $_.reason -like "*revoked*" }) -ne $null) (($rej | ConvertTo-Json -Compress -Depth 4))
  Kill $carol

  # 6. at rest
  Write-Host "At rest"
  Kill $bob; Kill $alice
  Start-Sleep -Seconds 1
  Check "the secret text is NOT readable in alice's database files" ($null -eq (FileContains "$Work\alice" $MARKER))
  Check "the secret text is NOT readable in bob's database files" ($null -eq (FileContains "$Work\bob" $MARKER))
  # control: the same search must find it in an unencrypted database, or it proves nothing
  Remove-Item Env:\A2A_DB_KEY
  $ctl = StartNode "ctl" 18607 @(); $procs += $ctl
  [void](Rpc 18607 "SendMessage" @{ message = (Msg "plain database: $MARKER") })
  Kill $ctl; Start-Sleep -Seconds 1
  Check "CONTROL: the same text IS readable in an unencrypted database" ($null -ne (FileContains "$Work\ctl" $MARKER))
  # wrong key
  $env:A2A_DB_KEY = "wrong password"
  $bad = Start-Process $Exe -ArgumentList @("--name", "alice", "--data", "$Work\alice", "--http-port", "18601", "--db-key-env", "A2A_DB_KEY") -NoNewWindow -PassThru -RedirectStandardOutput "$Work\bad.out" -RedirectStandardError "$Work\bad.err"
  $exited = $bad.WaitForExit(15000)
  Check "opening alice's database with the wrong key fails" ($exited -and $bad.ExitCode -ne 0) "exited=$exited code=$($bad.ExitCode)"
  if (-not $exited) { Kill $bad }
}
finally {
  foreach ($p in $procs) { Kill $p }
}
if ($fail -eq 0) { Write-Host "`nALL PASSED" -ForegroundColor Green } else { Write-Host "`n$fail FAILED" -ForegroundColor Red; exit 1 }
