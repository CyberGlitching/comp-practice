<#
Rotate-Passwords.ps1 - random passwords for every domain (or local) user that isn't scored/builtin,
optionally disables them. Writes a CSV you keep (and hand to White Team if they ask).
  .\Rotate-Passwords.ps1                 # unlisted users: new random pw, then asks to disable each
  .\Rotate-Passwords.ps1 -IncludeScored  # ALSO scored users - only if White Team said it's allowed
                                         # and you know how to report the new creds to scoring
  .\Rotate-Passwords.ps1 -Krbtgt         # reset krbtgt (run twice, ~10+ min apart, to kill golden tickets)
#>
param([switch]$IncludeScored, [switch]$Krbtgt, [switch]$NoDisable)
. "$PSScriptRoot\common.ps1"
$csv = Join-Path $BlueDir "passwords-$TS.csv"
$rows = @()
$isDC = Is-DC
if ($isDC) { Import-Module ActiveDirectory; $users = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName }
else { $users = Get-LocalUser | Select-Object -ExpandProperty Name }

foreach ($u in $users) {
  if (Is-Kept $u) { continue }
  $scored = Is-Scored $u
  if ($scored -and -not $IncludeScored) { continue }
  $pw = New-StrongPassword
  $sec = ConvertTo-SecureString $pw -AsPlainText -Force
  try {
    if ($isDC) { Set-ADAccountPassword -Identity $u -Reset -NewPassword $sec } else { Set-LocalUser -Name $u -Password $sec }
    $rows += [pscustomobject]@{User=$u; Password=$pw; Scored=$scored}
    Ok "$u rotated"; Log-Action "rotated $u"
  } catch { Warn "${u}: $_" }
  if (-not $scored -and -not $NoDisable) {
    if (Ask "  Disable unlisted user $u too?") {
      if ($isDC) { Disable-ADAccount $u } else { Disable-LocalUser $u }
      Log-Action "disabled $u"
    }
  }
}
if ($rows) { $rows | Export-Csv $csv -NoTypeInformation; Ok "Saved $csv - copy it somewhere safe, then delete it from this box" }

if ($Krbtgt -and $isDC) {
  if (Ask "Reset krbtgt now? (do it a second time after replication to DC2 completes)") {
    Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString (New-StrongPassword 32) -AsPlainText -Force)
    Log-Action "krbtgt reset"; Ok "krbtgt reset. Force replication: repadmin /syncall /AdeP   then run again in ~10 min."
  }
}
