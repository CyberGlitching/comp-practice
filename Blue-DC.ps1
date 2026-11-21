<#
.SYNOPSIS
  Blue-DC.ps1 - GDDC Team 7 Windows DC (172.16.7.40) hardening / IR. PowerShell 5.1, Server 2016/2022.

.DESCRIPTION
  Default -Mode audit (read-only). Changes only with -Mode apply, per phase.
  Every change asks y/N unless -Yes. Never touches the scoring user.

.EXAMPLE
  powershell -ep bypass -File .\Blue-DC.ps1 -ScoringUser <name>                                  # audit everything
  powershell -ep bypass -File .\Blue-DC.ps1 -ScoringUser <name> -Mode apply -Phase firewall
  powershell -ep bypass -File .\Blue-DC.ps1 -ScoringUser <name> -Mode apply -Phase creds,ad,persistence,defender
#>
[CmdletBinding()]
param(
  [ValidateSet('audit','apply')][string]$Mode = 'audit',
  [ValidateSet('firewall','ad','creds','persistence','defender','all')][string[]]$Phase = @('all'),
  [string]$ScoringUser = $env:SCORING_USER,
  [switch]$Yes,
  [int]$RollbackSeconds = 90
)

# ----------------------------- EDIT / OVERRIDE ------------------------------
$SCORING_USER = $ScoringUser                         # REQUIRED for apply. Never removed/disabled/rotated.
$Team         = 7
$ExpectIP     = "172.16.$Team.40"
$ScoredUsers  = @('amarino','mdesocio','lsmith','acapece','johnlinux','linuswindows','alvin','simon','theodore','abauer')
$ScoredPw     = 'bb123#123'
# allowed members per privileged group (sAMAccountName). SCORING_USER is always allowed.
$PrivAllow = @{
  'Domain Admins'               = @('Administrator')
  'Enterprise Admins'           = @('Administrator')
  'Schema Admins'               = @('Administrator')
  'Administrators'              = @('Administrator','Domain Admins','Enterprise Admins')
  'DnsAdmins'                   = @()
  'Group Policy Creator Owners' = @('Administrator')
  'Account Operators'           = @()
  'Backup Operators'            = @()
  'Server Operators'            = @()
}
$TcpAllow = @(22,53,88,135,389,445,464,636,3268,3269,5985,5986)
$UdpAllow = @(53,88,123,389,464)
# ----------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$TS   = Get-Date -Format 'yyyyMMdd-HHmmss'
$Root = 'C:\blue'
$Q    = "$Root\quarantine\$TS"
$Bak  = "$Root\backup\$TS"
New-Item -ItemType Directory -Force -Path $Root,$Q,$Bak | Out-Null
Start-Transcript -Path "$Root\blue-dc-$env:COMPUTERNAME-$TS.log" -Append | Out-Null
$Apply = ($Mode -eq 'apply')
$script:Findings = 0

function Section($t){ Write-Host "`n==== $t ====" -ForegroundColor White }
function Ok($t){ Write-Host "  [OK] $t" -ForegroundColor Green }
function Info($t){ Write-Host "  $t" }
function Warn($t){ Write-Host "  [WARN] $t" -ForegroundColor Yellow }
function Alert($t){ Write-Host "  [ALERT] $t" -ForegroundColor Red; $script:Findings++ }
function Done($t){ Write-Host "  [DONE] $t" -ForegroundColor Green }
function Want($t){
  if (-not $Apply) { Write-Host "  [WOULD] $t" -ForegroundColor Cyan; return $false }
  if ($Yes) { return $true }
  $a = Read-Host "  ? $t [y/N]"
  if ($a -match '^[yY]') { return $true }
  Info "skipped: $t"; return $false
}
function Is-Scoring($n){ return ($SCORING_USER -and ($n -ieq $SCORING_USER)) }
function Quarantine-File($p){
  if (-not (Test-Path -LiteralPath $p)) { return }
  $dest = Join-Path $Q (($p -replace ':','') -replace '^\\+','')
  New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
  Move-Item -LiteralPath $p -Destination $dest -Force -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath $dest) { Done "quarantined $p -> $dest" } else { Alert "could not move $p" }
}
function Export-Key($k){ $f = Join-Path $Bak (($k -replace '[\\:]','_') + '.reg'); & reg.exe export $k $f /y 2>$null | Out-Null }

# ----------------------------- guards ---------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Run elevated.' -ForegroundColor Red; exit 1 }
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
if ($ips -notcontains $ExpectIP) { Write-Host "WRONG BOX: expected $ExpectIP, this host ($env:COMPUTERNAME) has $($ips -join ', ')" -ForegroundColor Red; exit 1 }
if ($Apply -and -not $SCORING_USER) { Write-Host 'SCORING_USER is not set (-ScoringUser <name>). Refusing to apply.' -ForegroundColor Red; exit 1 }
if ($Phase -contains 'all') { $Phase = @('firewall','ad','creds','persistence','defender') }
if ($Apply -and $Phase.Count -eq 5 -and -not $PSBoundParameters.ContainsKey('Phase')) { Write-Host 'Apply needs -Phase' -ForegroundColor Red; exit 1 }
Write-Host "Blue-DC.ps1 host=$env:COMPUTERNAME mode=$Mode phases=$($Phase -join ',') scoring=$SCORING_USER" -ForegroundColor White
Info "log: $Root\blue-dc-$env:COMPUTERNAME-$TS.log  quarantine: $Q  backups: $Bak"
$HaveAD = $false
try { Import-Module ActiveDirectory -ErrorAction Stop; $HaveAD = $true; $Dom = Get-ADDomain; $DomDN = $Dom.DistinguishedName } catch { Alert "ActiveDirectory module unavailable: $_" }

# =============================================================================
# FIREWALL
# =============================================================================
function Phase-Firewall {
  Section 'FIREWALL: profiles'
  Get-NetFirewallProfile | ForEach-Object {
    Info ("{0,-8} Enabled={1} In={2} Out={3} AllowLocalRules={4}" -f $_.Name,$_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction,$_.AllowLocalFirewallRules)
    if ($_.DefaultOutboundAction -eq 'Block') { Alert "$($_.Name) profile default OUTBOUND = Block" }
  }
  Section 'FIREWALL: enabled Block rules (red team)'
  $blocks = @(Get-NetFirewallRule -Enabled True -Action Block -ErrorAction SilentlyContinue)
  $gpo    = @(Get-NetFirewallRule -PolicyStore RSOP -ErrorAction SilentlyContinue | Where-Object { $_.Action -eq 'Block' -and $_.Enabled -eq 'True' })
  foreach ($r in $gpo) { Alert "GPO-delivered block rule (fix in the GPO, not locally): $($r.DisplayName)" }
  if ($blocks.Count -eq 0) { Ok 'no enabled block rules' }
  $pf = @{}
  foreach ($r in $blocks) {
    $p = $r | Get-NetFirewallPortFilter; $a = $r | Get-NetFirewallAddressFilter
    Alert ("{0} | {1} | {2} | proto={3} lport={4} rport={5} remote={6} store={7}" -f $r.DisplayName,$r.Direction,$r.Profile,$p.Protocol,($p.LocalPort -join ','),($p.RemotePort -join ','),($a.RemoteAddress -join ','),$r.PolicyStoreSourceType)
  }
  Section 'FIREWALL: portproxy / IPsec'
  $pp = (& netsh interface portproxy show all) -join "`n"
  if ($pp -match '\d+\.\d+\.\d+\.\d+') { Alert "netsh portproxy entries:`n$pp" } else { Ok 'no portproxy' }
  Get-NetIPsecRule -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | ForEach-Object { Alert "IPsec rule: $($_.DisplayName) action=$($_.Action)" }

  if (-not $Apply) {
    Info "would: disable each block rule above, add BLUE-Allow rules (ICMPv4 echo, TCP $($TcpAllow -join ','), UDP $($UdpAllow -join ',')), with ${RollbackSeconds}s auto-rollback"
  } else {
    if (Want "Apply firewall changes with ${RollbackSeconds}s auto-rollback (netsh import of current policy)") {
      $wfw = "$Bak\fw-before.wfw"
      & netsh advfirewall export $wfw | Out-Null
      $task = 'BlueFwRollback'
      Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
      $act = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument "advfirewall import `"$wfw`""
      $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($RollbackSeconds)
      Register-ScheduledTask -TaskName $task -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
      Done "rollback armed: scheduled task $task at +${RollbackSeconds}s"

      foreach ($r in $blocks) { if (Want "Disable block rule '$($r.DisplayName)'") { $r | Disable-NetFirewallRule; Done "disabled $($r.DisplayName)" } }
      Get-NetFirewallProfile | Where-Object DefaultOutboundAction -eq 'Block' | ForEach-Object { if (Want "Set $($_.Name) default outbound Allow") { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction Allow } }
      if ($pp -match '\d+\.\d+\.\d+\.\d+') { if (Want 'netsh interface portproxy reset') { & netsh interface portproxy reset | Out-Null; Done 'portproxy reset' } }
      if (-not (Get-NetFirewallRule -Name 'BLUE-ICMPv4' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'BLUE-ICMPv4' -DisplayName 'BLUE Allow ICMPv4 echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null; Done 'ICMPv4 echo allowed'
      }
      foreach ($p in $TcpAllow) { $n = "BLUE-TCP-$p"; if (-not (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $n -DisplayName "BLUE Allow TCP $p" -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any | Out-Null } }
      foreach ($p in $UdpAllow) { $n = "BLUE-UDP-$p"; if (-not (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $n -DisplayName "BLUE Allow UDP $p" -Direction Inbound -Protocol UDP -LocalPort $p -Action Allow -Profile Any | Out-Null } }
      $n = 'BLUE-RPC-Dynamic'; if (-not (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $n -DisplayName 'BLUE Allow RPC dynamic' -Direction Inbound -Protocol TCP -LocalPort RPC -Action Allow -Profile Any | Out-Null }
      Done 'BLUE allow rules present'
      Set-NetFirewallProfile -All -Enabled True
      Test-Scored
      Write-Host "  Test from Kali now (pfsense/pf-check.sh --probe). Type CONFIRM to keep, anything else rolls back now:" -ForegroundColor Yellow
      $ans = Read-Host '  '
      if ($ans -ceq 'CONFIRM') { Unregister-ScheduledTask -TaskName $task -Confirm:$false; Done "kept. Manual rollback: netsh advfirewall import `"$wfw`"" }
      else { & netsh advfirewall import $wfw | Out-Null; Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue; Warn 'rolled back' }
    }
  }
  Section 'SERVICES: scored + AD core'
  foreach ($s in 'NTDS','DNS','Netlogon','Kdc','W32Time','ADWS','sshd','WinRM','LanmanServer','DFSR') {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if (-not $svc) { if ($s -eq 'sshd') { Alert 'sshd service missing (OpenSSH Server not installed?)' } else { Warn "$s not present" }; continue }
    $start = (Get-CimInstance Win32_Service -Filter "Name='$s'").StartMode
    if ($svc.Status -eq 'Running' -and $start -eq 'Auto') { Ok "$s running/auto" }
    else {
      Alert "$s status=$($svc.Status) start=$start"
      if (Want "Set $s automatic, start it, restart-on-failure") {
        Set-Service -Name $s -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $s -ErrorAction SilentlyContinue
        & sc.exe failure $s reset= 60 actions= restart/3000/restart/3000/restart/3000 | Out-Null
        Done "$s -> $((Get-Service $s).Status)"
      }
    }
  }
  $listeners = (& winrm enumerate winrm/config/listener 2>&1) -join "`n"
  if ($listeners -notmatch 'Transport = HTTP') { Alert 'no WinRM HTTP listener'; if (Want 'winrm quickconfig -quiet') { & winrm quickconfig -quiet | Out-Null } } else { Ok 'WinRM HTTP listener present' }
  Test-Scored
}

function Test-Scored {
  Section 'VERIFY: scored ports (local)'
  foreach ($p in 22,389,5985,53,88,445) {
    $c = New-Object Net.Sockets.TcpClient
    try { $iar = $c.BeginConnect($ExpectIP,$p,$null,$null); if ($iar.AsyncWaitHandle.WaitOne(2000) -and $c.Connected) { Ok "tcp $p open on $ExpectIP" } else { Alert "tcp $p NOT answering on $ExpectIP" } } catch { Alert "tcp $p error $_" } finally { $c.Close() }
  }
  try { Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null; Ok 'Test-WSMan localhost' } catch { Alert "WinRM: $_" }
  if ($HaveAD) { try { $d = [ADSI]"LDAP://$ExpectIP/$DomDN"; if ($d.distinguishedName) { Ok "LDAP bind ok ($($d.distinguishedName))" } else { Alert 'LDAP bind returned nothing' } } catch { Alert "LDAP: $_" } }
}

# =============================================================================
# AD
# =============================================================================
function Phase-AD {
  if (-not $HaveAD) { Alert 'skipping AD phase'; return }
  Section 'AD: privileged groups vs allow-list'
  foreach ($g in $PrivAllow.Keys) {
    $grp = Get-ADGroup -Identity $g -ErrorAction SilentlyContinue
    if (-not $grp) { continue }
    foreach ($m in @(Get-ADGroupMember -Identity $grp -ErrorAction SilentlyContinue)) {
      $n = $m.SamAccountName
      if ($PrivAllow[$g] -contains $n) { Info "$g : $n (allowed)"; continue }
      if (Is-Scoring $n) { Warn "$g : $n is SCORING_USER - left alone"; continue }
      Alert "$g : unexpected member $n ($($m.objectClass))"
      if ($ScoredUsers -contains $n) { Warn "  $n is a scored user (public password). Removing; adding to Remote Management Users so WinRM checks keep working." }
      if (Want "Remove $n from $g") {
        if ($ScoredUsers -contains $n) { Add-ADGroupMember -Identity 'Remote Management Users' -Members $n -ErrorAction SilentlyContinue }
        Remove-ADGroupMember -Identity $grp -Members $m -Confirm:$false; Done "removed $n from $g"
      }
    }
  }
  Section 'AD: accounts created/changed in the last 2 days'
  $since = (Get-Date).AddDays(-2)
  Get-ADUser -Filter { whenCreated -ge $since } -Properties whenCreated,Enabled,MemberOf | ForEach-Object { Alert "new user $($_.SamAccountName) created $($_.whenCreated) enabled=$($_.Enabled)" }
  Get-ADUser -Filter { whenChanged -ge $since } -Properties whenChanged | ForEach-Object { Info "changed: $($_.SamAccountName) $($_.whenChanged)" }
  Get-ADComputer -Filter { whenCreated -ge $since } -Properties whenCreated | ForEach-Object { Alert "new computer account $($_.SamAccountName) $($_.whenCreated)" }
  Get-ADGroup -Filter { whenChanged -ge $since } -Properties whenChanged | ForEach-Object { Info "group changed: $($_.Name) $($_.whenChanged)" }

  Section 'AD: roastable / weak flags'
  $users = Get-ADUser -Filter * -Properties ServicePrincipalName,DoesNotRequirePreAuth,PasswordNeverExpires,PasswordNotRequired,AllowReversiblePasswordEncryption,AdminCount,SIDHistory,Enabled,TrustedForDelegation
  foreach ($u in $users) {
    $n = $u.SamAccountName
    if ($u.ServicePrincipalName -and $n -ne 'krbtgt') { Alert "SPN (kerberoastable): $n -> $($u.ServicePrincipalName -join ', ')" }
    if ($u.DoesNotRequirePreAuth) { Alert "AS-REP roastable: $n"; if (-not (Is-Scoring $n) -and (Want "Require pre-auth for $n")) { Set-ADAccountControl -Identity $u -DoesNotRequirePreAuth $false; Done $n } }
    if ($u.PasswordNotRequired) { Alert "PASSWD_NOTREQD: $n"; if (-not (Is-Scoring $n) -and (Want "Clear PasswordNotRequired on $n")) { Set-ADAccountControl -Identity $u -PasswordNotRequired $false; Done $n } }
    if ($u.AllowReversiblePasswordEncryption) { Alert "reversible encryption: $n"; if (-not (Is-Scoring $n) -and (Want "Clear reversible encryption on $n")) { Set-ADAccountControl -Identity $u -AllowReversiblePasswordEncryption $false } }
    if ($u.PasswordNeverExpires -and $u.Enabled) { Info "password never expires: $n" }
    if ($u.SIDHistory.Count -gt 0) { Alert "SIDHistory set on $n" }
    if ($u.TrustedForDelegation) { Alert "unconstrained delegation on user $n" }
    if ($u.AdminCount -eq 1 -and -not ($PrivAllow.Values | ForEach-Object { $_ } | Where-Object { $_ -eq $n })) { Warn "adminCount=1 (was privileged at some point): $n" }
  }
  Section 'AD: AdminSDHolder + domain root ACL (DCSync)'
  $okIds = 'NT AUTHORITY\\|BUILTIN\\|\\Domain Admins$|\\Enterprise Admins$|\\Administrators$|\\Cert Publishers$|\\Windows Authorization Access Group$|\\Terminal Server License Servers$|\\Pre-Windows 2000 Compatible Access$|\\Enterprise Domain Controllers$|\\Domain Controllers$|\\Enterprise Read-only Domain Controllers$|\\Read-only Domain Controllers$|\\Key Admins$|\\Enterprise Key Admins$|^Everyone$|\\Schema Admins$|\\Cloneable Domain Controllers$'
  try {
    Set-Location AD: -ErrorAction Stop
    (Get-Acl "AD:CN=AdminSDHolder,CN=System,$DomDN").Access | Where-Object { $_.IdentityReference -notmatch $okIds } | ForEach-Object { Alert "AdminSDHolder ACE: $($_.IdentityReference) $($_.ActiveDirectoryRights) $($_.AccessControlType)" }
    $repl = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'
    (Get-Acl "AD:$DomDN").Access | Where-Object { $repl -contains $_.ObjectType.ToString() -and $_.IdentityReference -notmatch $okIds } | ForEach-Object { Alert "DCSync right on domain root: $($_.IdentityReference) ($($_.ObjectType))  -> fix: dsacls `"$DomDN`" /R `"$($_.IdentityReference)`"" }
    Set-Location C:\
  } catch { Warn "ACL check failed: $_"; Set-Location C:\ }
  Section 'AD: GPOs changed in the last 2 days'
  try { Get-GPO -All | Where-Object { $_.ModificationTime -ge $since } | ForEach-Object { Alert "GPO modified: $($_.DisplayName) $($_.ModificationTime)  (Get-GPOReport -Name '$($_.DisplayName)' -ReportType Html -Path C:\blue\gpo.html)" } } catch { Warn "Get-GPO: $_" }
  $krb = Get-ADUser krbtgt -Properties PasswordLastSet
  Info "krbtgt PasswordLastSet: $($krb.PasswordLastSet)  (golden-ticket concern: reset twice, 10h apart, only if you see DCSync/NTDS theft)"
}

# =============================================================================
# CREDS
# =============================================================================
function Test-DomainPw($user,$pw){
  try { Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain')
        return $ctx.ValidateCredentials($user,$pw,[System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate) } catch { return $false } }
function Phase-Creds {
  if (-not $HaveAD) { Alert 'skipping creds phase'; return }
  Section 'CREDS: scored users in AD'
  foreach ($n in $ScoredUsers) {
    $u = Get-ADUser -Filter "SamAccountName -eq '$n'" -Properties Enabled,LockedOut,AccountExpirationDate,PasswordExpired -ErrorAction SilentlyContinue
    if (-not $u) { Warn "$n not in AD (may be Linux-only)"; continue }
    $issues = @()
    if (-not $u.Enabled) { $issues += 'disabled' }
    if ($u.LockedOut) { $issues += 'locked' }
    if ($u.AccountExpirationDate -and $u.AccountExpirationDate -lt (Get-Date)) { $issues += 'expired' }
    if ($u.PasswordExpired) { $issues += 'pw-expired' }
    if (-not (Test-DomainPw $n $ScoredPw)) { $issues += 'password' }
    if ($issues.Count -eq 0) { Ok $n; continue }
    Alert "$n : $($issues -join ' ')"
    if (Want "Restore $n (enable, unlock, no expiry, default password)") {
      Enable-ADAccount $u; Unlock-ADAccount $u; Clear-ADAccountExpiration $u
      if ($issues -contains 'password' -or $issues -contains 'pw-expired') { Set-ADAccountPassword $u -Reset -NewPassword (ConvertTo-SecureString $ScoredPw -AsPlainText -Force); Set-ADUser $u -ChangePasswordAtLogon $false }
      Done "$n restored"
    }
  }
  Section 'CREDS: Administrator password'
  Warn 'If the WinRM/SSH/LDAP scorer authenticates as Administrator, rotating breaks that check. Watch the scoreboard after rotating.'
  if ($Apply) {
    $a = if ($Yes) { 'y' } else { Read-Host '  ? Rotate the domain Administrator password now? [y/N]' }
    if ($a -match '^[yY]') {
      $p1 = Read-Host '  New password' -AsSecureString; $p2 = Read-Host '  Again' -AsSecureString
      $b1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
      $b2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
      if ($b1 -and $b1 -ceq $b2 -and $b1 -ne $ScoredPw) { Set-ADAccountPassword -Identity Administrator -Reset -NewPassword $p1; Done 'Administrator rotated' } else { Warn 'empty/mismatch/default - not rotated' }
      $b1 = $null; $b2 = $null
    }
  } else { Write-Host '  [WOULD] prompt for and rotate the Administrator password' -ForegroundColor Cyan }
}

# =============================================================================
# PERSISTENCE
# =============================================================================
function Phase-Persistence {
  Section 'PERSISTENCE: scheduled tasks'
  foreach ($t in Get-ScheduledTask) {
    if ($t.TaskName -eq 'BlueFwRollback') { continue }
    $acts = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
    $susp = ($t.TaskPath -notlike '\Microsoft\*') -or ($acts -match '(?i)powershell|cmd(\.exe)? /c|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|\\Temp\\|\\Users\\|ProgramData|http|-enc|frombase64')
    if (-not $susp) { continue }
    Alert "task $($t.TaskPath)$($t.TaskName) [$($t.State)] runas=$($t.Principal.UserId) : $acts"
    if (Want "Export + disable + unregister task $($t.TaskName)") {
      Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File "$Q\task-$($t.TaskName).xml"
      Disable-ScheduledTask -InputObject $t | Out-Null; Unregister-ScheduledTask -InputObject $t -Confirm:$false; Done "task $($t.TaskName) removed"
    }
  }
  Section 'PERSISTENCE: services with odd binaries'
  foreach ($s in Get-CimInstance Win32_Service) {
    $p = [string]$s.PathName
    if (-not $p) { continue }
    $odd = ($p -notmatch '(?i)^"?(C:\\Windows\\|C:\\Program Files)') -or ($p -match '(?i)powershell|cmd(\.exe)? /c|mshta|rundll32 |regsvr32|\\Temp\\|\\Users\\|ProgramData|-enc')
    $unq = ($p -notmatch '^"') -and ($p -match '^[^ ]+ [^-/]') -and ($p -match '(?i)\.exe') -and ($p.Substring(0,$p.ToLower().IndexOf('.exe')) -match ' ')
    if ($odd -or $unq) {
      Alert "service $($s.Name) [$($s.State)/$($s.StartMode)] $p$(if($unq){' (UNQUOTED path with spaces)'})"
      if ($s.Name -in 'sshd','WinRM','NTDS','DNS') { continue }
      if ($odd -and (Want "Stop + disable service $($s.Name)")) { Stop-Service $s.Name -Force -ErrorAction SilentlyContinue; Set-Service $s.Name -StartupType Disabled; Done "$($s.Name) disabled" }
    }
  }
  Section 'PERSISTENCE: Run keys / Winlogon / IFEO / LSA'
  $hives = @('HKLM:') + @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[\d-]+$' } | ForEach-Object { "Registry::$($_.Name)" })
  $sub = 'Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\Microsoft\Windows\CurrentVersion\RunServices','Software\Microsoft\Windows\CurrentVersion\RunServicesOnce','Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run','Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce','Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
  foreach ($h in $hives) { foreach ($s in $sub) {
    $k = "$h\$s"; if (-not (Test-Path $k)) { continue }
    $props = Get-ItemProperty $k
    foreach ($v in $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
      Alert "$k : $($v.Name) = $($v.Value)"
      if (Want "Remove Run value '$($v.Name)'") { Export-Key ($k -replace '^HKLM:','HKLM' -replace '^Registry::','') ; Remove-ItemProperty -Path $k -Name $v.Name; Done "removed $($v.Name)" }
    } } }
  $wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
  if ($wl.Userinit -notmatch '^(?i)C:\\Windows\\system32\\userinit\.exe,?$') { Alert "Winlogon Userinit = $($wl.Userinit)"; if (Want 'Reset Userinit') { Export-Key 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Set-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' Userinit 'C:\Windows\system32\userinit.exe,' } }
  if ($wl.Shell -and $wl.Shell -notmatch '^(?i)explorer\.exe$') { Alert "Winlogon Shell = $($wl.Shell)"; if (Want 'Reset Shell to explorer.exe') { Set-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' Shell 'explorer.exe' } }
  $win = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
  if ($win.AppInit_DLLs) { Alert "AppInit_DLLs = $($win.AppInit_DLLs) (LoadAppInit_DLLs=$($win.LoadAppInit_DLLs))"; if (Want 'Clear AppInit_DLLs') { Set-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' AppInit_DLLs ''; Set-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' LoadAppInit_DLLs 0 } }
  $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  Info "LSA Security Packages: $($lsa.'Security Packages' -join ',')  Authentication Packages: $($lsa.'Authentication Packages' -join ',')  Notification Packages: $($lsa.'Notification Packages' -join ',')"
  if (($lsa.'Notification Packages' | Where-Object { $_ -notmatch '^(?i)(scecli|rassfm)$' })) { Alert 'non-default LSA Notification Packages (password filter backdoor?)' }
  if (($lsa.'Security Packages' | Where-Object { $_ -and $_ -notmatch '^(?i)(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|""|)$' })) { Alert 'non-default LSA Security Packages (SSP backdoor?)' }
  if ($lsa.RunAsPPL -ne 1) { Info 'LSA RunAsPPL not enabled' }
  $wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
  if ($wd.UseLogonCredential -eq 1) { Alert 'WDigest UseLogonCredential=1 (cleartext creds in LSASS)'; if (Want 'Set UseLogonCredential=0') { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0 } }

  Section 'PERSISTENCE: accessibility backdoors (sethc/utilman/...)'
  $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
  $cmdHash = (Get-FileHash C:\Windows\System32\cmd.exe).Hash; $psHash = (Get-FileHash C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe).Hash
  foreach ($b in 'sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe') {
    $k = "$ifeo\$b"
    if ((Test-Path $k) -and (Get-ItemProperty $k).Debugger) { Alert "IFEO Debugger on $b = $((Get-ItemProperty $k).Debugger)"; if (Want "Remove IFEO Debugger for $b") { Export-Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$b"; Remove-ItemProperty $k -Name Debugger; Done $b } }
    $f = "C:\Windows\System32\$b"; if (-not (Test-Path $f)) { continue }
    $h = (Get-FileHash $f).Hash; $sig = Get-AuthenticodeSignature $f; $orig = (Get-Item $f).VersionInfo.OriginalFilename
    if ($h -eq $cmdHash -or $h -eq $psHash -or $sig.Status -ne 'Valid' -or ($orig -and $orig -notmatch [regex]::Escape(($b -replace '\.exe$','')))) {
      Alert "$f replaced? sig=$($sig.Status) original=$orig"
      if (Want "sfc /scanfile=$f") { & sfc.exe /scanfile=$f | Out-Null; Done "sfc ran on $b" }
    }
  }
  Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object { $d = (Get-ItemProperty $_.PSPath).Debugger; if ($d) { Alert "IFEO Debugger: $($_.PSChildName) -> $d" } }
  Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object { Alert "SilentProcessExit monitor: $($_.PSChildName) -> $((Get-ItemProperty $_.PSPath).MonitorProcess)" }

  Section 'PERSISTENCE: WMI subscriptions'
  $legit = 'SCM Event Log Filter','SCM Event Log Consumer','BVTFilter','BVTConsumer'
  foreach ($cls in '__FilterToConsumerBinding','CommandLineEventConsumer','ActiveScriptEventConsumer','__EventFilter') {
    foreach ($o in @(Get-CimInstance -Namespace root\subscription -ClassName $cls -ErrorAction SilentlyContinue)) {
      $name = if ($o.Name) { $o.Name } else { [string]$o.Filter }
      if ($legit | Where-Object { $name -like "*$_*" }) { continue }
      Alert "WMI $cls : $name $($o.CommandLineTemplate)$($o.ScriptText)$($o.Query)"
      if (Want "Remove WMI $cls '$name'") { $o | Remove-CimInstance; Done "removed $name" }
    }
  }
  Section 'PERSISTENCE: startup folders'
  $dirs = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp') + @(Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
  foreach ($d in $dirs) { Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { Alert "startup item $($_.FullName)"; if (Want "Quarantine $($_.FullName)") { Quarantine-File $_.FullName } } }

  Section 'PERSISTENCE: OpenSSH'
  $sshd = 'C:\ProgramData\ssh\sshd_config'
  if (Test-Path $sshd) {
    $lines = Get-Content $sshd
    $bad = $lines | Select-String -Pattern '^\s*(AllowUsers|DenyUsers|AllowGroups|DenyGroups|ForceCommand|AuthorizedKeysCommand|PasswordAuthentication\s+no|PermitEmptyPasswords\s+yes|Port\s+(?!22\b)\d+|ListenAddress|Match\s+(?!Group administrators))'
    $bad | ForEach-Object { Alert "sshd_config: $($_.Line)" }
    if ($bad -and (Want 'Comment out those sshd_config lines, set PasswordAuthentication yes, restart sshd')) {
      Copy-Item $sshd "$Bak\sshd_config"
      $new = foreach ($l in $lines) {
        if ($l -match '^\s*(AllowUsers|DenyUsers|AllowGroups|DenyGroups|ForceCommand|AuthorizedKeysCommand|ListenAddress|Port\s+(?!22\b)\d+|PermitEmptyPasswords)') { "#BLUE# $l" }
        elseif ($l -match '^\s*PasswordAuthentication') { 'PasswordAuthentication yes' } else { $l } }
      $new | Set-Content $sshd -Encoding ascii
      $exe = @('C:\Windows\System32\OpenSSH\sshd.exe',"$env:ProgramFiles\OpenSSH\sshd.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
      if ($exe) { & $exe -t; if ($LASTEXITCODE -ne 0) { Alert 'sshd -t failed, restoring'; Copy-Item "$Bak\sshd_config" $sshd -Force } }
      Restart-Service sshd -ErrorAction SilentlyContinue; Done 'sshd restarted'
    }
  } else { Warn "$sshd not found" }
  $ds = (Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -ErrorAction SilentlyContinue).DefaultShell
  if ($ds) { Warn "OpenSSH DefaultShell = $ds" }
  $keyfiles = @('C:\ProgramData\ssh\administrators_authorized_keys') + @(Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName)\.ssh\authorized_keys" })
  foreach ($kf in $keyfiles) {
    if (-not (Test-Path $kf)) { continue }
    $c = Get-Content $kf | Where-Object { $_ -and $_ -notmatch '^\s*#' }
    if (-not $c) { continue }
    Alert "$kf : $(@($c).Count) key(s)"; $c | ForEach-Object { Info ("      " + ($_ -replace '^(\S+\s+\S{0,20})\S*(.*)$','$1...$2')) }
    if ($SCORING_USER -and $kf -match "\\Users\\$([regex]::Escape($SCORING_USER))\\") { Warn 'SCORING_USER keys - left alone'; continue }
    if (Want "Quarantine $kf") { Quarantine-File $kf }
  }

  Section 'PERSISTENCE: local accounts / shares'
  Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue | ForEach-Object { Info "local account: $($_.Name) disabled=$($_.Disabled)" }
  Get-SmbShare | Where-Object { $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$|NETLOGON|SYSVOL|[A-Z]\$)$' } | ForEach-Object { Warn "share $($_.Name) -> $($_.Path)" }
}

# =============================================================================
# DEFENDER
# =============================================================================
function Phase-Defender {
  Section 'DEFENDER'
  $feat = Get-WindowsFeature -Name 'Windows-Defender*' -ErrorAction SilentlyContinue
  if ($feat -and -not ($feat | Where-Object Installed)) { Alert 'Windows Defender feature is UNINSTALLED (Install-WindowsFeature Windows-Defender needs a reboot - decide manually)'; return }
  $svc = Get-Service WinDefend -ErrorAction SilentlyContinue
  if (-not $svc -or $svc.Status -ne 'Running') { Alert "WinDefend status: $($svc.Status)"; if (Want 'Start WinDefend') { Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service WinDefend -ErrorAction SilentlyContinue } }
  $polk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
  if (Test-Path $polk) {
    Get-ChildItem $polk -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-ItemProperty $_.PSPath; $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { Alert "Defender policy $($_.Name)=$($_.Value)" } }
    $root = Get-ItemProperty $polk; $root.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { Alert "Defender policy $($_.Name)=$($_.Value)" }
    if (Want 'Delete the Defender policy key (red team uses it to disable AV/add exclusions)') { Export-Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'; Remove-Item $polk -Recurse -Force; Done 'policy key removed' }
  }
  try { $pref = Get-MpPreference -ErrorAction Stop } catch { Alert "Get-MpPreference failed: $_"; return }
  foreach ($n in 'DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning','DisableIntrusionPreventionSystem','DisableArchiveScanning','DisableBlockAtFirstSeen') {
    if ($pref.$n) { Alert "$n = True"; if (Want "Set $n false") { $h = @{}; $h[$n] = $false; Set-MpPreference @h; Done $n } }
  }
  foreach ($kind in 'ExclusionPath','ExclusionExtension','ExclusionProcess','ExclusionIpAddress') {
    foreach ($e in @($pref.$kind)) { if (-not $e) { continue }; Alert "$kind : $e"; if (Want "Remove $kind $e") { $h = @{}; $h[$kind] = $e; Remove-MpPreference @h; Done "removed $e" } }
  }
  if ($Apply) {
    try { Update-MpSignature -ErrorAction Stop; Done 'signatures updated' } catch { try { Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop; Done 'signatures updated (MU)' } catch { Warn "signature update failed (offline?): $_" } }
    if (Want 'Start a QuickScan (runs in background)') { Start-MpScan -ScanType QuickScan -AsJob | Out-Null; Done 'QuickScan started; check: Get-MpThreatDetection' }
  }
  $st = Get-MpComputerStatus; Info "RealTime=$($st.RealTimeProtectionEnabled) AV sigs=$($st.AntivirusSignatureLastUpdated) Engine=$($st.AMEngineVersion)"
  Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object { Alert "Defender detection: $($_.Resources -join ', ') at $($_.InitialDetectionTime)" }
}

foreach ($p in $Phase) {
  switch ($p) { 'firewall' { Phase-Firewall } 'ad' { Phase-AD } 'creds' { Phase-Creds } 'persistence' { Phase-Persistence } 'defender' { Phase-Defender } }
}
Section 'DONE'
Info "findings: $script:Findings   log: $Root   quarantine: $Q"
Stop-Transcript | Out-Null
