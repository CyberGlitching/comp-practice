<#
Hunt.ps1 - READ-ONLY triage + persistence + AI-agent hunt for Windows Server 2016.
Run in an elevated PowerShell:  powershell -ep bypass -f .\Hunt.ps1
Report saved to C:\ProgramData\blue\hunt-<ts>.txt.  [!] = look at this.
#>
. "$PSScriptRoot\common.ps1"
$out = Join-Path $BlueDir "hunt-$TS.txt"
Start-Transcript -Path $out | Out-Null

Hdr "HOST"
$os = Get-CimInstance Win32_OperatingSystem
"$env:COMPUTERNAME | $($os.Caption) $($os.Version) | DC=$(Is-DC) | boot $($os.LastBootUpTime)"

# ------------------------------------------------------------------ sessions
Hdr "SESSIONS (logoff <id> to kick)"
quser 2>$null
Info "Your own Proxmox console shows as 'console'. RDP sessions from IPs you don't own = red team."

# ------------------------------------------------------------------ accounts
Hdr "LOCAL ACCOUNTS"
if (-not (Is-DC)) {
  Get-LocalUser | ForEach-Object {
    $tag = ''; if (Is-Scored $_.Name) { $tag='(scored)' } elseif (Is-Kept $_.Name) { $tag='(builtin/ours)' }
    $line = "{0,-22} enabled={1,-5} lastlogon={2} {3}" -f $_.Name,$_.Enabled,$_.LastLogon,$tag
    if (-not $tag -and $_.Enabled) { Warn "Unlisted enabled user: $line" } else { "    $line" }
  }
  Hdr "LOCAL ADMINISTRATORS / RDP USERS"
  foreach ($g in 'Administrators','Remote Desktop Users','Remote Management Users','Backup Operators') {
    try { Get-LocalGroupMember $g -ErrorAction Stop | ForEach-Object { "    $g : $($_.Name)" } } catch {}
  }
} else {
  Info "This is a DC - run .\Audit-AD.ps1 for users/groups/ACLs/ADCS."
}
$g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
if ($g -and $g.Enabled) { Warn "Guest account is ENABLED" }
# Names ending in $ hide from 'net user'
Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.Name -like '*$' } | ForEach-Object { Warn "Hidden-style local account: $($_.Name)" }

# ------------------------------------------------------------------ autoruns
Hdr "RUN KEYS / WINLOGON / IFEO / APPINIT / LSA"
$runKeys = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
foreach ($k in $runKeys) {
  if (Test-Path $k) {
    $p = Get-ItemProperty $k
    $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $exe = Get-ExePath $_.Value
      if ($_.Value -match $SusRe -or ($exe -and (Test-Path $exe) -and -not (Test-MsSigned $exe))) { Warn "$k : $($_.Name) = $($_.Value)" }
      else { "    $k : $($_.Name) = $($_.Value)" }
    }
  }
}
# every user's hive that's loaded
Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match 'S-1-5-21-[\d-]+$' } | ForEach-Object {
  $k = "Registry::$($_.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $k) { (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Warn "HKU run ($k): $($_.Name) = $($_.Value)" } }
}
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Warn "Winlogon Userinit = $($wl.Userinit)" } else { "    Userinit OK" }
if ($wl.Shell -ne 'explorer.exe') { Warn "Winlogon Shell = $($wl.Shell)" } else { "    Shell OK" }
$ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
if ($ai.AppInit_DLLs) { Warn "AppInit_DLLs = $($ai.AppInit_DLLs) (LoadAppInit=$($ai.LoadAppInit_DLLs))" }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
  $d = (Get-ItemProperty $_.PSPath).Debugger
  if ($d) { Warn "IFEO Debugger: $($_.PSChildName) -> $d   (sethc/utilman/osk here = sticky-keys backdoor)" }
}
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
  Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' | ForEach-Object { Warn "SilentProcessExit monitor: $($_.PSChildName) -> $((Get-ItemProperty $_.PSPath).MonitorProcess)" }
}
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
"    LSA Authentication Packages: $($lsa.'Authentication Packages' -join ',')"
"    LSA Notification Packages:   $($lsa.'Notification Packages' -join ',')   (default: scecli + maybe rassfm)"
"    LSA Security Packages:       $($lsa.'Security Packages' -join ',')"
$lsa.'Notification Packages' | Where-Object { $_ -notin @('scecli','rassfm','') } | ForEach-Object { Warn "Unusual LSA notification package (password filter = cleartext pw stealer): $_" }
if ($lsa.RunAsPPL -ne 1) { Info "LSA protection (RunAsPPL) is off" }
$wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
if ($wd.UseLogonCredential -eq 1) { Warn "WDigest UseLogonCredential=1 (cleartext passwords in LSASS)" }
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\NetSh' -ErrorAction SilentlyContinue | ForEach-Object {
  $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value -notmatch '^(ifmon|rasmontr|authfwcfg|dhcpcmonitor|dot3cfg|fwcfg|hnetmon|netiohlp|nettrace|nshhttp|nshipsec|nshwfp|p2pnetsh|rpcnsh|WcnNetsh|whhelper|wlancfg|wshelper|wwancfg|peerdistsh)\.dll$' } | ForEach-Object { Warn "Netsh helper DLL: $($_.Name) = $($_.Value)" }
}

Hdr "ACCESSIBILITY BINARIES (replaced = SYSTEM shell at login screen)"
foreach ($b in 'sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe') {
  $p = "C:\Windows\System32\$b"
  if (Test-Path $p) {
    $v = (Get-Item $p).VersionInfo
    if (-not (Test-MsSigned $p) -or $v.OriginalFilename -notmatch [regex]::Escape($b.Replace('.exe',''))) { Warn "$b looks REPLACED (orig name: $($v.OriginalFilename))" } else { "    $b OK" }
  }
}

Hdr "STARTUP FOLDERS"
@("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") + (Get-ChildItem C:\Users -Directory | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" }) |
  Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem $_ -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { Warn "Startup item: $($_.FullName)" } }

Hdr "SCHEDULED TASKS (non-Microsoft path or suspicious action)"
Get-ScheduledTask | ForEach-Object {
  $t = $_
  foreach ($a in $t.Actions) {
    $cmd = "$($a.Execute) $($a.Arguments)".Trim()
    if (-not $cmd) { continue }
    if ($t.TaskPath -notlike '\Microsoft\*' -or $cmd -match $SusRe) {
      $who = $t.Principal.UserId; $state = $t.State
      if ($cmd -match $SusRe) { Warn "$($t.TaskPath)$($t.TaskName) [$state as $who] -> $cmd" }
      else { "    $($t.TaskPath)$($t.TaskName) [$state as $who] -> $cmd" }
    }
  }
}

Hdr "SERVICES (non-Microsoft binary, odd path, or suspicious command)"
Get-CimInstance Win32_Service | ForEach-Object {
  $exe = Get-ExePath $_.PathName
  $odd = ($_.PathName -match $SusRe) -or ($exe -and $exe -notmatch '^(C:\\Windows\\|C:\\Program Files)' -and $exe -notmatch '^\\?\??\\?C:\\Windows')
  $unsigned = $exe -and (Test-Path $exe) -and -not (Test-MsSigned $exe)
  if ($odd) { Warn "$($_.Name) [$($_.State)/$($_.StartMode) as $($_.StartName)] $($_.PathName)" }
  elseif ($unsigned -and $_.StartMode -ne 'Disabled') { "    unsigned: $($_.Name) [$($_.State)] $($_.PathName)" }
}

Hdr "WMI EVENT SUBSCRIPTIONS (fileless persistence)"
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Filter' } | ForEach-Object { Warn "Filter: $($_.Name) :: $($_.Query)" }
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { Warn "CmdConsumer: $($_.Name) :: $($_.CommandLineTemplate)" }
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { Warn "ScriptConsumer: $($_.Name)" }
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -notmatch 'SCM Event Log' } | ForEach-Object { Warn "Binding: $($_.Filter) -> $($_.Consumer)" }

Hdr "POWERSHELL PROFILES"
@($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1') + (Get-ChildItem C:\Users -Directory | ForEach-Object { "$($_.FullName)\Documents\WindowsPowerShell\profile.ps1"; "$($_.FullName)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" }) |
  Select-Object -Unique | Where-Object { Test-Path $_ } | ForEach-Object { Warn "Profile exists: $_"; Get-Content $_ -TotalCount 5 | ForEach-Object { "        $_" } }

Hdr "BITS JOBS"
Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | ForEach-Object { Warn "BITS: $($_.DisplayName) $($_.JobState) $($_.FileList.RemoteName)" }

# ------------------------------------------------------------------ defenses
Hdr "DEFENDER"
try {
  $mp = Get-MpPreference; $st = Get-MpComputerStatus
  if (-not $st.RealTimeProtectionEnabled) { Warn "Real-time protection OFF" } else { "    Real-time ON" }
  if ($st.AntivirusSignatureLastUpdated) { "    Signatures: $($st.AntivirusSignatureLastUpdated)" }
  $mp.ExclusionPath | Where-Object { $_ } | ForEach-Object { Warn "Exclusion path: $_" }
  $mp.ExclusionProcess | Where-Object { $_ } | ForEach-Object { Warn "Exclusion process: $_" }
  $mp.ExclusionExtension | Where-Object { $_ } | ForEach-Object { Warn "Exclusion ext: $_" }
  if ($mp.DisableRealtimeMonitoring) { Warn "DisableRealtimeMonitoring = True" }
} catch { Warn "Defender cmdlets failed - feature removed or service stopped: $_" }
$pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
if (Test-Path $pol) { Get-ChildItem $pol -Recurse -ErrorAction SilentlyContinue | ForEach-Object { (Get-ItemProperty $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Warn "Defender policy $($_.Name)=$($_.Value)" } }
  (Get-ItemProperty $pol).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Warn "Defender policy $($_.Name)=$($_.Value)" } }

Hdr "FIREWALL"
Get-NetFirewallProfile | ForEach-Object {
  $l = "{0,-8} enabled={1} inbound={2} outbound={3}" -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction
  if (-not $_.Enabled) { Warn $l } else { "    $l" }
}
Info "Enabled inbound ALLOW rules that are not part of a built-in group:"
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { -not $_.Group } | ForEach-Object {
  $pf = $_ | Get-NetFirewallPortFilter; $af = $_ | Get-NetFirewallApplicationFilter
  "    {0} | {1} {2} | {3}" -f $_.DisplayName,$pf.Protocol,$pf.LocalPort,$af.Program
}

Hdr "NETWORK"
Info "Listening:"
Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  "    {0,-6} {1,-15} {2} ({3})" -f $_.LocalPort,$_.LocalAddress,$p.ProcessName,$_.OwningProcess
}
Info "Established to non-private addresses / odd processes:"
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  $l = "    {0}:{1} -> {2}:{3}  {4}({5})" -f $_.LocalAddress,$_.LocalPort,$_.RemoteAddress,$_.RemotePort,$p.ProcessName,$_.OwningProcess
  if ($p.ProcessName -match 'powershell|cmd|rundll32|regsvr32|mshta|wscript|cscript|nc|ncat|python|node') { Warn $l } else { $l }
}
Hdr "SHARES"
Get-SmbShare | ForEach-Object {
  $acc = (Get-SmbShareAccess $_.Name | Where-Object { $_.AccountName -match 'Everyone|Authenticated Users|Guest|ANONYMOUS' -and $_.AccessRight -ne 'Read' }).AccountName
  if ($_.Name -notmatch '^(ADMIN\$|C\$|IPC\$|NETLOGON|SYSVOL|CertEnroll|print\$)$' -or $acc) { Warn "Share $($_.Name) -> $($_.Path) $acc" } else { "    $($_.Name) -> $($_.Path)" }
}
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($smb1) { Warn "SMBv1 enabled" }

# ------------------------------------------------------------------ processes
Hdr "PROCESSES (unsigned, or running from user-writable paths)"
Get-CimInstance Win32_Process | ForEach-Object {
  $p = $_.ExecutablePath
  if ($p -and ($p -match '\\(Temp|AppData|ProgramData|Users\\Public|Downloads|PerfLogs)\\' -or $_.CommandLine -match $SusRe)) {
    Warn "pid $($_.ProcessId) parent $($_.ParentProcessId) $p :: $($_.CommandLine)"
  }
}

Hdr "RECENT EXECUTABLES/SCRIPTS IN WRITABLE PLACES (last 3 days)"
foreach ($d in 'C:\Users\Public','C:\ProgramData','C:\Windows\Temp','C:\PerfLogs','C:\inetpub\wwwroot') {
  if (Test-Path $d) { Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue -Include *.exe,*.dll,*.ps1,*.bat,*.cmd,*.vbs,*.js,*.hta,*.aspx,*.asp,*.ashx,*.php,*.jsp |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) -and $_.FullName -notlike "$BlueDir*" -and $_.FullName -notmatch '\\Microsoft\\Windows Defender\\' } | Select-Object -First 30 | ForEach-Object { Warn "$($_.LastWriteTime) $($_.FullName)" } }
}

Hdr "RANSOMWARE SIGNS"
foreach ($d in 'C:\inetpub','C:\Users','C:\Shares','C:\Data','C:\CertEnroll') {
  if (Test-Path $d) { Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.(enc|locked|crypt|crypted|encrypted|dog|pwned|wncry)$' -or $_.Name -match 'README.*(DECRYPT|RESTORE)|HOW_TO_DECRYPT|RECOVER' } | Select-Object -First 20 | ForEach-Object { Warn $_.FullName } }
}
Info "Shadow copies (vssadmin list shadows) - deleted shadows + ransom note = it was real ransomware:"
vssadmin list shadows 2>$null | Select-String 'Shadow Copy Volume|creation time' | Select-Object -First 6

# ------------------------------------------------------------------ AI agents
Hdr "AI AGENTS (OpenClaw / Claude Code / Codex / Aider / ZeroClaw / Ollama ...)"
$agentRe = 'zeroclaw|openclaw|clawdbot|moltbot|claude|aider|opencode|codex|gemini|goose|ollama|cursor-agent|open-interpreter|n8n'
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match $agentRe -or $_.Name -match $agentRe } | ForEach-Object { Warn "agent process pid $($_.ProcessId): $($_.CommandLine)" }
Get-ChildItem C:\Users -Directory -Force | ForEach-Object {
  foreach ($d in '.zeroclaw','.openclaw','.claude','.claude.json','.codex','.gemini','.aider.conf.yml','.ollama','.config\opencode','AppData\Roaming\npm\node_modules\@anthropic-ai','AppData\Roaming\npm\node_modules\openclaw','AppData\Local\Programs\Ollama') {
    $p = Join-Path $_.FullName $d; if (Test-Path $p) { Warn "agent footprint: $p" }
  }
}
Get-ScheduledTask | Where-Object { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -match $agentRe } | ForEach-Object { Warn "task launches agent: $($_.TaskPath)$($_.TaskName)" }
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match $agentRe -or $_.Name -match $agentRe } | ForEach-Object { Warn "service runs agent: $($_.Name) $($_.PathName)" }
foreach ($scope in 'Machine','User') {
  [Environment]::GetEnvironmentVariables($scope).GetEnumerator() | Where-Object { $_.Key -match '(ANTHROPIC|OPENAI|OPENROUTER|GEMINI|GOOGLE|GROQ|DEEPSEEK)_API_KEY' } | ForEach-Object { Warn "$scope env $($_.Key) is set (agent fuel)" }
}
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in 42617,8585,18789,18790,11434 } | ForEach-Object { Warn "agent-style port listening: $($_.LocalPort) pid $($_.OwningProcess)" }

Stop-Transcript | Out-Null
$n = (Select-String -Path $out -Pattern '\[!\]').Count
Ok "Report: $out  ($n findings flagged)"
