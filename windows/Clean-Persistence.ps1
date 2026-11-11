<#
Clean-Persistence.ps1 - interactive removal of the persistence Hunt.ps1 flags.
Every item is exported/backed up before removal (C:\ProgramData\blue\clean-<ts>\).
  powershell -ep bypass -f .\Clean-Persistence.ps1
Kill the loop BEFORE the symptom: a scheduled task that re-disables the firewall will keep
winning until the task is gone. Order here: WMI -> tasks -> services -> run keys -> startup -> profiles -> processes.
#>
. "$PSScriptRoot\common.ps1"
$bk = Join-Path $BlueDir "clean-$TS"; New-Item -ItemType Directory -Force $bk | Out-Null

Hdr "WMI SUBSCRIPTIONS"
$f = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Filter' }
$c = @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue) + @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
$b = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -notmatch 'SCM Event Log' }
if ($f -or $c -or $b) {
  ($f, $c, $b) | Out-File "$bk\wmi.txt"
  $f | ForEach-Object { "  filter: $($_.Name) :: $($_.Query)" }; $c | Where-Object { $_ } | ForEach-Object { "  consumer: $($_.Name) :: $($_.CommandLineTemplate)" }
  if (Ask "Remove ALL of these WMI filters/consumers/bindings?") { $b | Remove-CimInstance; $c | Where-Object { $_ } | Remove-CimInstance; $f | Remove-CimInstance; Log-Action "WMI persistence removed"; Ok "removed" }
} else { Ok "none" }

Hdr "SCHEDULED TASKS (non-Microsoft or suspicious)"
Get-ScheduledTask | ForEach-Object {
  $t = $_; $cmd = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
  if ($t.TaskPath -like '\Microsoft\*' -and $cmd -notmatch $SusRe) { return }
  if (-not $cmd.Trim()) { return }
  Write-Host "`n  $($t.TaskPath)$($t.TaskName)  [$($t.State)] as $($t.Principal.UserId)`n    -> $cmd"
  if (Ask "  Export + unregister this task?") {
    Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File "$bk\task-$($t.TaskName).xml"
    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false; Log-Action "task removed $($t.TaskPath)$($t.TaskName) :: $cmd"
  }
}

Hdr "SERVICES (odd path / suspicious command)"
Get-CimInstance Win32_Service | ForEach-Object {
  $exe = Get-ExePath $_.PathName
  $odd = ($_.PathName -match $SusRe) -or ($exe -and $exe -notmatch '^(C:\\Windows\\|C:\\Program Files)')
  if (-not $odd) { return }
  Write-Host "`n  $($_.Name) [$($_.State)/$($_.StartMode)] $($_.PathName)"
  if (Ask "  Stop + disable $($_.Name)? (NOT a scored service?)") {
    "$($_.Name) | $($_.PathName) | $($_.StartMode)" | Add-Content "$bk\services.txt"
    Stop-Service $_.Name -Force -ErrorAction SilentlyContinue; Set-Service $_.Name -StartupType Disabled
    if (Ask "  Also delete the service entirely (sc.exe delete)?") { sc.exe delete $_.Name | Out-Null }
    Log-Action "service disabled $($_.Name) :: $($_.PathName)"
  }
}

Hdr "RUN KEYS"
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
foreach ($k in $runKeys) {
  if (-not (Test-Path $k)) { continue }
  (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    Write-Host "  $k : $($_.Name) = $($_.Value)"
    if (Ask "  Remove?") { "$k|$($_.Name)|$($_.Value)" | Add-Content "$bk\runkeys.txt"; Remove-ItemProperty $k -Name $_.Name; Log-Action "run key removed $($_.Name) = $($_.Value)" }
  }
}
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; $w = Get-ItemProperty $wl
if ($w.Userinit -ne 'C:\Windows\system32\userinit.exe,' -and (Ask "Reset Userinit (now: $($w.Userinit))?")) { Set-ItemProperty $wl Userinit 'C:\Windows\system32\userinit.exe,'; Log-Action "userinit reset" }
if ($w.Shell -ne 'explorer.exe' -and (Ask "Reset Shell (now: $($w.Shell))?")) { Set-ItemProperty $wl Shell 'explorer.exe'; Log-Action "shell reset" }

Hdr "STARTUP FOLDERS + PS PROFILES"
$paths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") + (Get-ChildItem C:\Users -Directory | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
$items = $paths | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem $_ -Force | Where-Object { $_.Name -ne 'desktop.ini' } }
$profiles = @('C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1','C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1') + (Get-ChildItem C:\Users -Directory | ForEach-Object { "$($_.FullName)\Documents\WindowsPowerShell\profile.ps1"; "$($_.FullName)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" })
$items += $profiles | Where-Object { Test-Path $_ } | ForEach-Object { Get-Item $_ }
foreach ($i in $items) {
  if (Ask "Quarantine $($i.FullName)?") { Move-Item $i.FullName (Join-Path $bk ($i.FullName -replace '[:\\]','_')) -Force; Log-Action "quarantined $($i.FullName)" }
}

Hdr "BITS JOBS"
Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | ForEach-Object { if (Ask "Remove BITS job $($_.DisplayName)?") { $_ | Remove-BitsTransfer; Log-Action "bits removed $($_.DisplayName)" } }

Hdr "SUSPICIOUS PROCESSES"
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match $SusRe -and $_.ProcessId -ne $PID } | ForEach-Object {
  Write-Host "  pid $($_.ProcessId) (parent $($_.ParentProcessId)) $($_.CommandLine)"
  if (Ask "  Kill it (and its children)?") { taskkill /PID $_.ProcessId /T /F | Out-Null; Log-Action "killed $($_.ProcessId) $($_.CommandLine)" }
}
Ok "Backups of everything removed: $bk. Re-run Hunt.ps1 to confirm, and keep Watch.ps1 running."
