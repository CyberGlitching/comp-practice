<#
Chaos-Windows.ps1 - LAB ONLY practice harness for a throwaway Windows practice VM.
Plants INERT decoys + real misconfigurations that Hunt.ps1 / Audit-AD.ps1 are built to find,
then grades your cleanup. Nothing here is a weapon:
  - No reverse shells / C2. The "suspicious" Run key and task launch a harmless marker (cmd /c exit).
  - No credential theft. WDigest/exclusions/etc. are config flags to flip back.
  - No real ransomware. Files are backed up, then renamed to *.dog (reversible). No encryption.
  - The "sticky keys backdoor" is simulated with an IFEO Debugger pointing at a harmless marker,
    NOT by replacing sethc.exe. The "webshell" is an inert signature-matching marker file.
Each item is something a defender must find and undo; none grants an attacker access.

  1. On the practice VM:  New-Item C:\dog-lab -ItemType File
  2. Snapshot it in Proxmox.
  3. powershell -ep bypass -f .\Chaos-Windows.ps1 -Mode plant -IKnowThisIsALab [-N 10] [-Service Spooler]
  4. Clean up with Hunt.ps1 / Clean-Persistence.ps1 / Harden.ps1.
  5. powershell -ep bypass -f .\Chaos-Windows.ps1 -Mode grade [-Hints]
  6. powershell -ep bypass -f .\Chaos-Windows.ps1 -Mode restore   (or roll back the snapshot)
#>
param([ValidateSet('plant','grade','restore','help')][string]$Mode='help',[switch]$IKnowThisIsALab,[int]$N=0,[string]$Service='',[switch]$Hints)
$ErrorActionPreference='SilentlyContinue'
$ST='C:\ProgramData\.doglab'; $Man="$ST\planted.txt"
$marker='C:\ProgramData\doglab-marker.txt'   # inert target for decoy autoruns
$isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)
if ($isDC) { Import-Module ActiveDirectory }

# name -> @{Desc; Hint; Plant; Check}  (Check returns $true when FIXED)
$S = [ordered]@{}
function Add-S($n,$d,$h,$p,$c){ $S[$n]=@{Desc=$d;Hint=$h;Plant=$p;Check=$c} }

Add-S localadmin 'Rogue local admin user "svc_backup" (disabled)' 'Get-LocalGroupMember Administrators' `
  { if(-not $isDC){ net user svc_backup 'P@ssw0rd!' /add 2>$null; net localgroup Administrators svc_backup /add 2>$null; Disable-LocalUser svc_backup } } `
  { if($isDC){return $true}; -not ((Get-LocalGroupMember Administrators).Name -match 'svc_backup$') }
Add-S domainadmin 'Extra Domain Admin "svc_sql" (disabled)' 'Get-ADGroupMember "Domain Admins"' `
  { if($isDC){ New-ADUser -Name svc_sql -SamAccountName svc_sql -AccountPassword (ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force) -Enabled $false; Add-ADGroupMember 'Domain Admins' svc_sql } } `
  { if(-not $isDC){return $true}; -not ((Get-ADGroupMember 'Domain Admins').SamAccountName -contains 'svc_sql') }
Add-S asrep 'dog user flagged AS-REP roastable (no preauth)' 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}' `
  { if($isDC){ Set-ADAccountControl dog -DoesNotRequirePreAuth $true } } `
  { if(-not $isDC){return $true}; -not (Get-ADUser dog -Properties DoesNotRequirePreAuth).DoesNotRequirePreAuth }
Add-S runkey 'HKLM Run key launching a marker (stands in for a loader)' 'reg query "HKLM\...\CurrentVersion\Run"' `
  { New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveSync' -Value "cmd /c type $marker" -PropertyType String -Force } `
  { -not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveSync' -EA SilentlyContinue) }
Add-S task 'Scheduled task every 5 min (inert marker action)' 'Get-ScheduledTask | ? TaskPath -notlike "\Microsoft\*"' `
  { $a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c type $marker"; $t=New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5); Register-ScheduledTask -TaskName 'Windows Update Sync' -Action $a -Trigger $t -User SYSTEM -RunLevel Highest -Force } `
  { -not (Get-ScheduledTask -TaskName 'Windows Update Sync' -EA SilentlyContinue) }
Add-S ifeo 'IFEO "sticky keys" debugger on sethc.exe (points at marker, sethc UNTOUCHED)' 'HKLM\...\Image File Execution Options\sethc.exe' `
  { New-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Force | Out-Null; New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger -Value "cmd.exe /c type $marker" -PropertyType String -Force } `
  { -not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger -EA SilentlyContinue) }
Add-S svcpersist 'Odd auto-start service running a marker loop' 'Get-CimInstance Win32_Service | ? {bad path}' `
  { New-Service -Name 'WinDefendHelper' -BinaryPathName 'cmd.exe /c for /l %i in () do (ping -n 60 127.0.0.1 >nul)' -StartupType Automatic -DisplayName 'Windows Defender Helper' 2>$null; Start-Service WinDefendHelper 2>$null } `
  { -not (Get-Service WinDefendHelper -EA SilentlyContinue) }
Add-S wmi 'WMI permanent event subscription (inert consumer)' 'Get-CimInstance -Namespace root\subscription __FilterToConsumerBinding' `
  { $f=Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='DogFilter';EventNamespace='root\cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_LocalTime'"};
    $c=Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='DogConsumer';CommandLineTemplate="cmd.exe /c type $marker"};
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c} | Out-Null } `
  { -not (Get-CimInstance -Namespace root\subscription __EventFilter -Filter "Name='DogFilter'" -EA SilentlyContinue) }
Add-S defender 'Defender real-time off + C:\ exclusion' 'Get-MpPreference | select Exclusion*, Get-MpComputerStatus' `
  { Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\','C:\Users\Public' } `
  { $mp=Get-MpPreference; -not ($mp.ExclusionPath -contains 'C:\') -and -not (Get-MpPreference).DisableRealtimeMonitoring }
Add-S wdigest 'WDigest UseLogonCredential=1 (plaintext creds in LSASS)' 'reg query ...\WDigest' `
  { New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Force|Out-Null; Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 1 -Type DWord } `
  { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential -ne 1 }
Add-S firewall 'All firewall profiles disabled' 'Get-NetFirewallProfile' `
  { Set-NetFirewallProfile -All -Enabled False } `
  { -not ((Get-NetFirewallProfile).Enabled -contains $false) }
Add-S guest 'Guest account enabled + in Administrators' 'Get-LocalUser Guest' `
  { if(-not $isDC){ Enable-LocalUser Guest; net localgroup Administrators Guest /add 2>$null } else { Enable-ADAccount Guest } } `
  { if($isDC){ -not (Get-ADUser Guest).Enabled } else { -not (Get-LocalUser Guest).Enabled } }
Add-S share 'World-writable SMB share "Backups"' 'Get-SmbShare' `
  { New-Item C:\Backups -ItemType Directory -Force|Out-Null; New-SmbShare -Name Backups -Path C:\Backups -FullAccess Everyone 2>$null } `
  { -not (Get-SmbShare -Name Backups -EA SilentlyContinue) }
Add-S webshell 'Inert webshell-signature marker in wwwroot' 'Get-ChildItem C:\inetpub\wwwroot -Include *.aspx' `
  { if(Test-Path C:\inetpub\wwwroot){ '<%-- LAB DECOY inert. Scanner signature only, nothing runs: eval(Request.Form["c"]) Process.Start("cmd.exe") --%>' | Out-File C:\inetpub\wwwroot\upload.aspx -Encoding ascii } } `
  { -not (Test-Path C:\inetpub\wwwroot\upload.aspx) }
Add-S ransom 'Decoy ransom note + files renamed to *.dog (reversible)' 'dir /s *.dog ; README_DOG.txt' `
  { $d='C:\Shares\Finance'; if(-not(Test-Path $d)){ New-Item $d -ItemType Directory -Force|Out-Null; 1..5|%{ "Report $_ DOG confidential" | Out-File "$d\report$_.txt" } }
    "$d" | Out-File "$ST\ransom.dir" -Encoding ascii; Compress-Archive "$d\*" "$ST\ransom-backup.zip" -Force
    (Get-ChildItem $d -File | ? Extension -ne '.dog').Count | Out-File "$ST\ransom.count" -Encoding ascii
    Get-ChildItem $d -File | ? Extension -ne '.dog' | Rename-Item -NewName { $_.Name + '.dog' }
    'Your files were renamed by APT-DOGE. (LAB DECOY - not real ransomware.)' | Out-File "$d\README_DOG.txt" } `
  { $d=Get-Content "$ST\ransom.dir"; (-not (Get-ChildItem $d -Filter *.dog)) -and (-not (Test-Path "$d\README_DOG.txt")) }
Add-S svcdown 'Scored service stopped + disabled' 'Get-Service <svc>' `
  { if($Service){ $Service|Out-File "$ST\svc" -Encoding ascii; Stop-Service $Service -Force; Set-Service $Service -StartupType Disabled } } `
  { $s=Get-Content "$ST\svc" -EA SilentlyContinue; if(-not $s){return $true}; (Get-Service $s).Status -eq 'Running' }

function Restore-All {
  net localgroup Administrators svc_backup /del 2>$null; net user svc_backup /del 2>$null
  if($isDC){ Remove-ADUser svc_sql -Confirm:$false 2>$null; Set-ADAccountControl dog -DoesNotRequirePreAuth $false 2>$null; Disable-ADAccount Guest 2>$null } else { Disable-LocalUser Guest 2>$null; net localgroup Administrators Guest /del 2>$null }
  Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name OneDriveSync 2>$null
  Unregister-ScheduledTask -TaskName 'Windows Update Sync' -Confirm:$false 2>$null
  Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Recurse 2>$null
  Stop-Service WinDefendHelper 2>$null; sc.exe delete WinDefendHelper 2>$null
  Get-CimInstance -Namespace root\subscription __FilterToConsumerBinding | ? { $_.Filter -match 'DogFilter' } | Remove-CimInstance 2>$null
  Get-CimInstance -Namespace root\subscription __EventFilter -Filter "Name='DogFilter'" | Remove-CimInstance 2>$null
  Get-CimInstance -Namespace root\subscription CommandLineEventConsumer -Filter "Name='DogConsumer'" | Remove-CimInstance 2>$null
  Set-MpPreference -DisableRealtimeMonitoring $false 2>$null; 'C:\','C:\Users\Public' | % { Remove-MpPreference -ExclusionPath $_ 2>$null }
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0 -Type DWord 2>$null
  Set-NetFirewallProfile -All -Enabled True 2>$null
  Remove-SmbShare -Name Backups -Force 2>$null
  Remove-Item C:\inetpub\wwwroot\upload.aspx 2>$null
  if(Test-Path "$ST\ransom.dir"){ $d=Get-Content "$ST\ransom.dir"; Get-ChildItem $d -Filter *.dog | Rename-Item -NewName { $_.Name -replace '\.dog$','' } 2>$null; Remove-Item "$d\README_DOG.txt" 2>$null }
  $s=Get-Content "$ST\svc" -EA SilentlyContinue; if($s){ Set-Service $s -StartupType Automatic; Start-Service $s 2>$null }
  Write-Host '[+] Restore attempted. Verify: Chaos-Windows.ps1 -Mode grade' -ForegroundColor Green
}

switch ($Mode) {
  plant {
    if (-not (Test-Path 'C:\dog-lab')) { Write-Host 'Refusing: C:\dog-lab marker not found. Use a throwaway LAB VM, then: New-Item C:\dog-lab -ItemType File' -ForegroundColor Red; break }
    if (-not $IKnowThisIsALab) { Write-Host 'Add -IKnowThisIsALab to confirm. Snapshot the VM first.' -ForegroundColor Red; break }
    New-Item $ST -ItemType Directory -Force | Out-Null; 'inert lab marker' | Out-File $marker -Encoding ascii
    $names = $S.Keys | Where-Object { $_ -ne 'svcdown' -or $Service }
    if (-not $isDC) { $names = $names | Where-Object { $_ -notin 'domainadmin','asrep' } }
    if ($N -gt 0) { $names = $names | Get-Random -Count ([Math]::Min($N,@($names).Count)) }
    $names | Out-File $Man -Encoding ascii
    foreach ($n in $names) { try { & $S[$n].Plant; Write-Host "[plant] $n - $($S[$n].Desc)" -ForegroundColor Yellow } catch { Write-Host "[skip ] $n ($_)" } }
    Write-Host "`nPlanted $(@($names).Count). Clean the box, then: Chaos-Windows.ps1 -Mode grade" -ForegroundColor Cyan
  }
  grade {
    if (-not (Test-Path $Man)) { Write-Host 'Nothing planted. Run plant first.' -ForegroundColor Red; break }
    $fixed=0; $tot=0
    Write-Host '=== GRADE ==='
    foreach ($n in (Get-Content $Man)) {
      if (-not $S[$n]) { continue }; $tot++
      $ok = $false; try { $ok = [bool](& $S[$n].Check) } catch {}
      if ($ok) { Write-Host "  [FIXED]   $($S[$n].Desc)" -ForegroundColor Green; $fixed++ }
      else { Write-Host "  [MISSED]  $($S[$n].Desc)" -ForegroundColor Red; if ($Hints) { Write-Host "            hint: $($S[$n].Hint)" -ForegroundColor DarkGray } }
    }
    Write-Host "-----------------------------------`nScore: $fixed / $tot" -ForegroundColor Cyan
    if ($fixed -eq $tot) { Write-Host 'Clean sweep. Snapshot-reset and raise -N.' -ForegroundColor Green }
  }
  restore { Restore-All }
  default { Get-Content $PSCommandPath | Select-String '^#|^\s*<#|#>' | Select-Object -First 28 | ForEach-Object { $_.Line -replace '^#\s?','' } }
}
