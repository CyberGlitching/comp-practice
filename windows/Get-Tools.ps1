<#
Get-Tools.ps1 - pull the public tools onto a Windows box into .\tools (needs internet).
  powershell -ep bypass -f .\Get-Tools.ps1
All are public (Microsoft Sysinternals + SwiftOnSecurity sysmon-config on GitHub).
#>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12   # Server 2016 defaults to TLS 1.0
$t = Join-Path $PSScriptRoot 'tools'; New-Item -ItemType Directory -Force $t | Out-Null
$zips = @{
  'Autoruns'        = 'https://download.sysinternals.com/files/Autoruns.zip'
  'ProcessExplorer' = 'https://download.sysinternals.com/files/ProcessExplorer.zip'
  'TCPView'         = 'https://download.sysinternals.com/files/TCPView.zip'
  'Sysmon'          = 'https://download.sysinternals.com/files/Sysmon.zip'
  'PSTools'         = 'https://download.sysinternals.com/files/PSTools.zip'
}
foreach ($k in $zips.Keys) {
  try {
    $z = Join-Path $t "$k.zip"
    Invoke-WebRequest -Uri $zips[$k] -OutFile $z -UseBasicParsing
    Expand-Archive $z -DestinationPath $t -Force; Remove-Item $z
    Write-Host "[+] $k" -ForegroundColor Green
  } catch { Write-Host "[!] $k failed: $_" -ForegroundColor Red }
}
try {
  Invoke-WebRequest 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile (Join-Path $t 'sysmonconfig.xml') -UseBasicParsing
  Write-Host "[+] sysmonconfig.xml" -ForegroundColor Green
} catch { Write-Host "[!] sysmon config failed" -ForegroundColor Red }
Get-ChildItem $t -Filter *.exe | ForEach-Object { Unblock-File $_.FullName }
Write-Host "`nAutoruns: .\tools\Autoruns64.exe -accepteula  (Options > Hide Microsoft entries; pink = unsigned)"
Write-Host "Sysmon:   .\tools\Sysmon64.exe -accepteula -i .\tools\sysmonconfig.xml"
