<#
Harden.ps1 - first-15-minutes hardening for the Windows DCs. Asks before each step.
  powershell -ep bypass -f .\Harden.ps1 -Role DC1      (LDAP, WinRM, RDP, DNS, AD)
  powershell -ep bypass -f .\Harden.ps1 -Role DC2      (IIS, RDP, CA, AD)
  $env:AUTO_YES='1' first to skip prompts (only once drilled).
Scored (Spring '26): DC1 = ICMP, LDAP, WinRM, RDP.  DC2 = ICMP, IIS, RDP, CA.
Things this script deliberately does NOT do, because they break scoring checks:
  - require LDAP signing / channel binding  (breaks plain LDAP simple binds the checker may use)
  - disable WinRM, NTLM, or RDP
  - change scored users' passwords (ask White Team first; use Rotate-Passwords.ps1 -IncludeScored if allowed)
#>
param([Parameter(Mandatory=$true)][ValidateSet('DC1','DC2','Member')][string]$Role)
. "$PSScriptRoot\common.ps1"
Start-Transcript -Path (Join-Path $BlueDir "harden-$TS.txt") | Out-Null
Log-Action "Harden.ps1 start role=$Role"
$isDC = Is-DC

# ---------------------------------------------------------------- 1 backup
Hdr "1. BACKUP (no snapshots allowed)"
$bk = Join-Path $BlueDir "bk-$TS"; New-Item -ItemType Directory -Force $bk | Out-Null
netsh advfirewall export "$bk\firewall.wfw" | Out-Null
reg export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' "$bk\run.reg" /y | Out-Null
if ($isDC) {
  Import-Module ActiveDirectory
  Get-ADUser -Filter * -Properties MemberOf,Enabled | Select-Object SamAccountName,Enabled,@{n='Groups';e={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ';'}} | Export-Csv "$bk\ad-users.csv" -NoTypeInformation
  try { Import-Module GroupPolicy; Backup-GPO -All -Path (New-Item -ItemType Directory -Force "$bk\gpo").FullName | Out-Null; Ok "GPOs backed up" } catch { Warn "GPO backup failed: $_" }
  try { Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object { dnscmd /zoneexport $_.ZoneName "blue-$($_.ZoneName)-$TS.dns" | Out-Null }; Ok "DNS zones exported to C:\Windows\System32\dns\" } catch {}
}
if ($Role -eq 'DC2') {
  if (Get-Command Backup-WebConfiguration -ErrorAction SilentlyContinue) { Import-Module WebAdministration; Backup-WebConfiguration -Name "blue-$TS" | Out-Null; Ok "IIS config backup blue-$TS (Restore-WebConfiguration -Name blue-$TS)" }
  if (Test-Path C:\inetpub\wwwroot) { Compress-Archive -Path C:\inetpub\wwwroot -DestinationPath "$bk\wwwroot.zip" -Force; Ok "wwwroot zipped" }
  try { Backup-CARoleService -Path "$bk\ca" -DatabaseOnly -ErrorAction Stop; Ok "CA database backed up" } catch { Info "CA backup skipped: $_" }
}
Ok "Backups in $bk"; Log-Action "backup $bk"

# ---------------------------------------------------------------- 2 our creds
Hdr "2. PASSWORDS FOR ACCOUNTS WE OWN (dog, Administrator)"
foreach ($u in 'dog','Administrator') {
  if (Ask "Set a new password for $u?") {
    $p = Read-Host "New password for $u" -AsSecureString
    try {
      if ($isDC) { Set-ADAccountPassword -Identity $u -Reset -NewPassword $p } else { Set-LocalUser -Name $u -Password $p }
      Ok "$u changed"; Log-Action "password changed $u"
    } catch { Warn "Failed for ${u}: $_" }
  }
}
Info "Unlisted/backdoor users: run .\Rotate-Passwords.ps1 (randomises + optionally disables them)."

# ---------------------------------------------------------------- 3 privileged groups
Hdr "3. PRIVILEGED GROUPS"
if ($isDC) {
  foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners') {
    try { $m = Get-ADGroupMember $g -ErrorAction Stop } catch { continue }
    foreach ($x in $m) {
      if ($PrivAllow -contains $x.SamAccountName) { continue }
      if (Ask "Remove $($x.SamAccountName) from '$g'?") { Remove-ADGroupMember -Identity $g -Members $x -Confirm:$false; Log-Action "removed $($x.SamAccountName) from $g"; Ok "removed" }
    }
  }
} else {
  Get-LocalGroupMember Administrators | Where-Object { ($_.Name -split '\\')[-1] -notin $PrivAllow } | ForEach-Object {
    if (Ask "Remove $($_.Name) from local Administrators?") { Remove-LocalGroupMember Administrators -Member $_.Name; Log-Action "removed $($_.Name) from local admins" }
  }
}
if ($isDC) {
  $g = Get-ADUser Guest; if ($g.Enabled -and (Ask "Disable domain Guest?")) { Disable-ADAccount Guest; Log-Action "disabled Guest" }
  $roast = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'
  if ($roast -and (Ask "Re-enable Kerberos pre-auth for $($roast.SamAccountName -join ', ') (kills AS-REP roasting; doesn't change passwords)?")) {
    $roast | Set-ADAccountControl -DoesNotRequirePreAuth $false; Log-Action "preauth fixed $($roast.SamAccountName -join ',')" }
  $pnr = Get-ADUser -Filter 'PasswordNotRequired -eq $true' | Where-Object { $_.SamAccountName -ne 'Guest' }
  if ($pnr -and (Ask "Clear PASSWD_NOTREQD on $($pnr.SamAccountName -join ', ')?")) { $pnr | Set-ADAccountControl -PasswordNotRequired $false; Log-Action "passwd_notreqd fixed" }
  $rev = Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true'
  if ($rev -and (Ask "Turn off reversible encryption on $($rev.SamAccountName -join ', ')?")) { $rev | Set-ADAccountControl -AllowReversiblePasswordEncryption $false }
} else {
  $g = Get-LocalUser Guest -ErrorAction SilentlyContinue; if ($g.Enabled -and (Ask "Disable local Guest?")) { Disable-LocalUser Guest }
}

# ---------------------------------------------------------------- 4 sticky keys / IFEO
Hdr "4. ACCESSIBILITY BACKDOORS + IFEO"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
  $d = (Get-ItemProperty $_.PSPath).Debugger
  if ($d -and (Ask "Remove IFEO Debugger on $($_.PSChildName) ($d)?")) { Remove-ItemProperty $_.PSPath -Name Debugger; Log-Action "IFEO removed $($_.PSChildName)" }
}
foreach ($b in 'sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe') {
  $p = "C:\Windows\System32\$b"
  if ((Test-Path $p) -and -not (Test-MsSigned $p)) {
    Warn "$b is not MS-signed"
    if (Ask "Restore $b with sfc /scanfile?") { takeown /f $p | Out-Null; icacls $p /grant Administrators:F | Out-Null; sfc /scanfile=$p; Log-Action "sfc $b" }
  }
}

# ---------------------------------------------------------------- 5 defender
Hdr "5. DEFENDER"
if (Ask "Turn Defender back on, remove ALL exclusions and Defender-disabling policies?") {
  $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
  if (Test-Path $pol) { reg export 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' "$bk\defender-policy.reg" /y | Out-Null; Remove-Item $pol -Recurse -Force; New-Item $pol | Out-Null }
  Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service WinDefend -ErrorAction SilentlyContinue
  $mp = Get-MpPreference
  $mp.ExclusionPath | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionPath $_ }
  $mp.ExclusionProcess | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionProcess $_ }
  $mp.ExclusionExtension | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ }
  Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent 1 -ErrorAction SilentlyContinue
  try { Update-MpSignature -ErrorAction Stop } catch { Info "Signature update failed (no internet?)" }
  Ok "Defender: RT=$((Get-MpComputerStatus).RealTimeProtectionEnabled)"; Log-Action "defender restored"
  Info "Scan the usual drop spots: Start-MpScan -ScanType CustomScan -ScanPath C:\ProgramData"
}

# ---------------------------------------------------------------- 6 firewall
Hdr "6. WINDOWS FIREWALL (built-in rule groups, so AD replication keeps working)"
$groups = @('Core Networking','File and Printer Sharing','Remote Desktop','Windows Remote Management','Windows Management Instrumentation (WMI)')
if ($isDC) { $groups += 'Active Directory Domain Services','DNS Service','Kerberos Key Distribution Center','DFS Replication','Netlogon Service','Remote Event Log Management' }
if ($Role -eq 'DC2') { $groups += 'World Wide Web Services (HTTP)','Secure World Wide Web Services (HTTPS)','Certification Authority','Certificate Services' }
Info "Will enable groups: $($groups -join ', ')"
Info "Then: inbound default = BLOCK on all profiles, outbound = allow."
if (Ask "Apply firewall?") {
  foreach ($g in $groups) { Get-NetFirewallRule -DisplayGroup $g -Direction Inbound -ErrorAction SilentlyContinue | Enable-NetFirewallRule }
  # explicit, in case group names differ on this build
  New-NetFirewallRule -DisplayName 'BLUE ICMPv4 echo' -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Out-Null
  $tcp = @(3389,5985,5986)
  if ($isDC) { $tcp += 53,88,135,389,445,464,636,3268,3269,9389 }
  if ($Role -eq 'DC2') { $tcp += 80,443 }
  New-NetFirewallRule -DisplayName 'BLUE scored TCP' -Protocol TCP -LocalPort $tcp -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Out-Null
  if ($isDC) { New-NetFirewallRule -DisplayName 'BLUE DC UDP' -Protocol UDP -LocalPort 53,88,123,389,464 -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Out-Null
               New-NetFirewallRule -DisplayName 'BLUE RPC dynamic' -Protocol TCP -LocalPort RPC -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Out-Null
               New-NetFirewallRule -DisplayName 'BLUE RPC epmap' -Protocol TCP -LocalPort RPCEPMap -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Out-Null }
  Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
  Ok "Firewall on."; Log-Action "firewall applied"
  Info "Non-group allow rules (red team adds these - review & Disable-NetFirewallRule -DisplayName ...):"
  Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { -not $_.Group -and $_.DisplayName -notlike 'BLUE *' } | ForEach-Object { Warn "  $($_.DisplayName)" }
}

# ---------------------------------------------------------------- 7 credential/protocol hardening
Hdr "7. CREDENTIAL + PROTOCOL HARDENING"
if (Ask "WDigest off, LSA protection on (after reboot), NTLMv2 only, LM hash off, SMBv1 off, LLMNR off?") {
  $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Force | Out-Null
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0 -Type DWord
  Set-ItemProperty $lsa RunAsPPL 1 -Type DWord
  Set-ItemProperty $lsa LmCompatibilityLevel 5 -Type DWord
  Set-ItemProperty $lsa NoLMHash 1 -Type DWord
  Set-ItemProperty $lsa RestrictAnonymous 1 -Type DWord
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0 -Type DWord
  Log-Action "cred/protocol hardening"; Ok "Done (RunAsPPL needs a reboot - only reboot when the team agrees: it's downtime)"
}
if ($isDC -and (Get-Service Spooler -ErrorAction SilentlyContinue).Status -eq 'Running') {
  if (Ask "Stop + disable Print Spooler on this DC (PrintNightmare / printer-bug coercion)?") { Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled; Log-Action "spooler disabled" }
}
if (Ask "Require NLA for RDP?") { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1; Log-Action "RDP NLA on" }
Info "If the RDP scoring check fails after NLA, set it back: UserAuthentication 0."

# ---------------------------------------------------------------- 8 logging
Hdr "8. LOGGING (so you can SEE the next attack - and write the inject report)"
if (Ask "Enable process-creation cmdline logging, PowerShell script block logging, key audit policies?") {
  auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
  auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Security Group Management" /success:enable | Out-Null
  auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Other Object Access Events" /success:enable | Out-Null
  auditpol /set /subcategory:"Directory Service Changes" /success:enable 2>$null | Out-Null
  New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1 -Type DWord
  New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1 -Type DWord
  wevtutil sl Security /ms:524288000 | Out-Null
  Log-Action "logging enabled"; Ok "Logging on. 4688=process, 4720=user created, 4728/4732/4756=group add, 4104=PS script block"
}
$sysmon = Join-Path $PSScriptRoot 'tools\Sysmon64.exe'
if ((Test-Path $sysmon) -and (Ask "Install Sysmon with tools\sysmonconfig.xml?")) { & $sysmon -accepteula -i (Join-Path $PSScriptRoot 'tools\sysmonconfig.xml'); Log-Action "sysmon installed" }

# ---------------------------------------------------------------- 9 role specific
Hdr "9. ROLE: $Role"
if ($Role -eq 'DC2') {
  Import-Module WebAdministration -ErrorAction SilentlyContinue
  Get-Website | ForEach-Object { "    site $($_.Name) [$($_.State)] $($_.PhysicalPath) bindings: $($_.Bindings.Collection.bindingInformation -join ', ')" }
  Get-WebApplication | ForEach-Object { "    app $($_.Path) -> $($_.PhysicalPath)" }
  Get-ChildItem C:\inetpub\wwwroot -Recurse -Force -Include *.aspx,*.asp,*.ashx,*.asmx,*.php,*.config -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) } | ForEach-Object { Warn "Recent web file (webshell?): $($_.FullName)" }
  Get-ChildItem C:\inetpub\wwwroot -Recurse -Force -Include *.aspx,*.asp,*.ashx -ErrorAction SilentlyContinue | Select-String -Pattern 'Process\.Start|cmd\.exe|eval\(|Request\.(Form|QueryString)\[.{0,20}\].*Execute' -List | ForEach-Object { Warn "Webshell pattern: $($_.Path)" }
  if (Get-WebApplication -Name certsrv -ErrorAction SilentlyContinue) { Warn "/certsrv (CA web enrollment) present. ESC8 risk if HTTP+NTLM. Require SSL on it (IIS > certsrv > SSL Settings) once you confirm the CA check doesn't use plain HTTP." }
  foreach ($s in 'W3SVC','WAS','CertSvc') { $sv = Get-Service $s -ErrorAction SilentlyContinue; if ($sv -and $sv.Status -ne 'Running') { Warn "$s is $($sv.Status)"; if (Ask "Start $s?") { Set-Service $s -StartupType Automatic; Start-Service $s } } elseif ($sv) { Ok "$s running" } }
  Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | ForEach-Object { if ($_.State -ne 'Started') { Warn "AppPool $($_.Name) $($_.State)"; if (Ask "Start pool $($_.Name)?") { Start-WebAppPool $_.Name } } }
}
if ($Role -eq 'DC1') {
  foreach ($s in 'NTDS','DNS','Kdc','Netlogon','WinRM','TermService') { $sv = Get-Service $s -ErrorAction SilentlyContinue; if ($sv -and $sv.Status -ne 'Running') { Warn "$s is $($sv.Status)"; if (Ask "Start $s?") { Set-Service $s -StartupType Automatic; Start-Service $s } } elseif ($sv) { Ok "$s running" } }
  winrm enumerate winrm/config/listener 2>$null | Select-String 'Transport|Port|Enabled'
  $wr = Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue
  if ($wr.Value -eq 'true') { Warn "WinRM AllowUnencrypted=true"; if (Ask "Set AllowUnencrypted=false? (test the WinRM score right after)") { Set-Item WSMan:\localhost\Service\AllowUnencrypted false } }
  $ba = Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction SilentlyContinue
  if ($ba.Value -eq 'true') { Warn "WinRM Basic auth enabled (cleartext creds over HTTP)" }
}
foreach ($s in 'TermService') { $sv = Get-Service $s; if ($sv.Status -ne 'Running') { Warn "RDP service stopped"; if (Ask "Start RDP?") { Set-Service $s -StartupType Automatic; Start-Service $s } } }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -ne 0) { Warn "RDP is DISABLED in registry"; if (Ask "Enable RDP?") { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0 } }

Stop-Transcript | Out-Null
Ok "Done. Actions: $ActionLog. Next: .\Hunt.ps1 (and .\Audit-AD.ps1 on DC1), then .\Watch.ps1 in its own window."
