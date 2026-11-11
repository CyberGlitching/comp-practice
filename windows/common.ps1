# common.ps1 - dot-sourced by the other scripts:  . "$PSScriptRoot\common.ps1"
# Windows PowerShell 5.1 compatible (Server 2016). Update lists from the new packet.

$Global:ScoredUsers = @('amarino','mdesocio','lsmith','acapece','johnlinux','linuswindows','alvin','simon','theodore','abauer',
                        'analyst1','analyst2','analyst3','analyst4','analyst5','analyst6','analyst7','analyst8')
$Global:KeepUsers   = @('dog','Administrator','krbtgt','Guest','DefaultAccount','WDAGUtilityAccount')
# Accounts allowed in privileged groups. Everyone else in Domain Admins etc. gets flagged.
$Global:PrivAllow   = @('Administrator','dog','Domain Admins','Enterprise Admins','Enterprise Key Admins','Key Admins')

$Global:BlueDir = 'C:\ProgramData\blue'
New-Item -ItemType Directory -Force -Path $BlueDir | Out-Null
$Global:TS = Get-Date -Format 'yyyyMMdd-HHmmss'
$Global:ActionLog = Join-Path $BlueDir 'actions.log'

function Hdr($t)  { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "[+] $t" -ForegroundColor Green }
function Warn($t) { Write-Host "[!] $t" -ForegroundColor Red }
function Info($t) { Write-Host "[*] $t" -ForegroundColor Yellow }
function Log-Action($t) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $env:COMPUTERNAME $t" | Add-Content $ActionLog }

function Ask($q) {
  if ($env:AUTO_YES -eq '1') { return $true }
  $a = Read-Host "[?] $q [y/N]"
  return ($a -match '^[Yy]')
}
function Is-Scored($u) { return $ScoredUsers -contains $u }
function Is-Kept($u)   { return $KeepUsers -contains $u }
function Is-DC { return ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) }

function New-StrongPassword([int]$len = 18) {
  $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'.ToCharArray()
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $bytes = New-Object byte[] $len; $rng.GetBytes($bytes)
  $p = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
  return $p + '!' + (Get-Random -Minimum 10 -Maximum 99)
}

# Is a file signed by Microsoft?
function Test-MsSigned($path) {
  try {
    $s = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    return ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Microsoft')
  } catch { return $false }
}

# Pull an exe path out of a command line
function Get-ExePath($cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($c -match '^"([^"]+)"') { return $Matches[1] }
  if ($c -match '^(\S+\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr))') { return $Matches[1] }
  return ($c -split '\s')[0]
}

$Global:SusRe = 'powershell.*(-enc|-e |-w(indowstyle)? h|iex|downloadstring|frombase64|invoke-expression|net\.webclient|bypass)|cmd(\.exe)? /c.*(powershell|certutil|bitsadmin|mshta)|mshta|rundll32.*(javascript|http)|regsvr32.*(/i:http|scrobj)|certutil.*(-urlcache|-decode)|bitsadmin|\\(temp|tmp|public|appdata|programdata\\[^\\]+\.(exe|ps1|bat|vbs))|\\users\\public\\|wscript|cscript|nc(at)?\.exe|net user .* /add|netsh advfirewall set .* off|sc (config|create)'
