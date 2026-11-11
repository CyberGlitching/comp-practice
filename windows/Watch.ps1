<#
Watch.ps1 - leave running in its own PowerShell window after hardening.
Baselines users, privileged groups, services, tasks, run keys, listeners, firewall/Defender state,
then alerts on changes every N seconds. -AutoFix turns the firewall + Defender back on immediately.
  powershell -ep bypass -f .\Watch.ps1 [-Interval 20] [-AutoFix]
Log: C:\ProgramData\blue\watch.log  (timestamps = your incident timeline for inject reports)
#>
param([int]$Interval = 20, [switch]$AutoFix)
. "$PSScriptRoot\common.ps1"
$log = Join-Path $BlueDir 'watch.log'
$isDC = Is-DC
if ($isDC) { Import-Module ActiveDirectory }

function Snap {
  $s = @{}
  if ($isDC) {
    $s.users = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName | Sort-Object
    $s.groups = foreach ($g in 'Domain Admins','Enterprise Admins','Administrators','Schema Admins','Backup Operators','Account Operators','DnsAdmins','Remote Desktop Users','Remote Management Users') { try { Get-ADGroupMember $g -Recursive | ForEach-Object { "$g : $($_.SamAccountName)" } } catch {} }
    $s.enabled = Get-ADUser -Filter 'Enabled -eq $true' | Select-Object -ExpandProperty SamAccountName | Sort-Object
  } else {
    $s.users = Get-LocalUser | Select-Object -ExpandProperty Name | Sort-Object
    $s.groups = Get-LocalGroupMember Administrators | ForEach-Object { "Administrators : $($_.Name)" }
    $s.enabled = Get-LocalUser | Where-Object Enabled | Select-Object -ExpandProperty Name | Sort-Object
  }
  $s.services = Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name) | $($_.PathName)" } | Sort-Object
  $s.tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" } | Sort-Object
  $s.run = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') { if (Test-Path $k) { (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$($_.Name)=$($_.Value)" } } }
  $s.ifeo = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | Where-Object { (Get-ItemProperty $_.PSPath).Debugger } | ForEach-Object { $_.PSChildName }
  $s.listen = Get-NetTCPConnection -State Listen | ForEach-Object { "$($_.LocalPort)" } | Sort-Object -Unique
  $s.wmi = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Filter)" }
  $s.fwrules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { -not $_.Group } | ForEach-Object { $_.DisplayName } | Sort-Object
  return $s
}
function Alert($m) { $l = "$(Get-Date -Format 'HH:mm:ss') [$env:COMPUTERNAME] $m"; Write-Host $l -ForegroundColor Red; Add-Content $log $l; [console]::Beep(900,150) }

$base = Snap; Ok "Baseline taken. Watching every ${Interval}s. AutoFix=$AutoFix. Ctrl-C to stop."
$seen = @{}
while ($true) {
  $now = Snap
  foreach ($k in $base.Keys) {
    $d = Compare-Object @($base[$k] | Where-Object { $_ }) @($now[$k] | Where-Object { $_ }) -ErrorAction SilentlyContinue
    foreach ($x in $d) {
      $sig = "$k|$($x.SideIndicator)|$($x.InputObject)"
      if ($seen.ContainsKey($sig)) { continue }; $seen[$sig] = 1
      $what = if ($x.SideIndicator -eq '=>') { 'ADDED' } else { 'REMOVED' }
      Alert "$k $what : $($x.InputObject)"
    }
  }
  # state checks every loop
  Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object {
    Alert "Firewall profile $($_.Name) DISABLED"
    if ($AutoFix) { Set-NetFirewallProfile -Name $_.Name -Enabled True; Alert "AUTOFIX: firewall $($_.Name) re-enabled - now find the task/service doing this" }
  }
  try { if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) { Alert "Defender real-time OFF"; if ($AutoFix) { Set-MpPreference -DisableRealtimeMonitoring $false; Alert "AUTOFIX: Defender RT on" } } } catch {}
  quser 2>$null | Select-Object -Skip 1 | ForEach-Object {
    $u = ($_ -replace '^\s*>?','' -split '\s+')[0]
    if ($u -and $u -notin @('dog','administrator') -and -not $seen.ContainsKey("sess|$u")) { $seen["sess|$u"] = 1; Alert "Session: $_" }
  }
  Start-Sleep -Seconds $Interval
}
