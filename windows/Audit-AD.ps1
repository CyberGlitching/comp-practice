<#
Audit-AD.ps1 - READ-ONLY Active Directory + AD CS audit. Run on DC1 (elevated).
  powershell -ep bypass -f .\Audit-AD.ps1 [-Days 3]
What red team does in AD at these comps, and what this looks for:
  new/hidden users, extra Domain Admins, AS-REP roast / kerberoast setups, DCSync rights,
  AdminSDHolder ACL backdoors, unconstrained delegation, SIDHistory, GPO-based persistence,
  vulnerable certificate templates (ESC1) and web enrollment (ESC8) on the CA (DC2).
#>
param([int]$Days = 3)
. "$PSScriptRoot\common.ps1"
Import-Module ActiveDirectory -ErrorAction Stop
$out = Join-Path $BlueDir "ad-audit-$TS.txt"
Start-Transcript -Path $out | Out-Null
$dom = Get-ADDomain; $root = $dom.DistinguishedName
$since = (Get-Date).AddDays(-$Days)

Hdr "DOMAIN $($dom.DNSRoot)  DCs: $((Get-ADDomainController -Filter *).HostName -join ', ')"

Hdr "ALL USERS (scored / ours / UNLISTED)"
$users = Get-ADUser -Filter * -Properties whenCreated,LastLogonDate,adminCount,DoesNotRequirePreAuth,PasswordNotRequired,PasswordNeverExpires,AllowReversiblePasswordEncryption,ServicePrincipalName,SIDHistory,TrustedForDelegation,TrustedToAuthForDelegation,Description
foreach ($u in $users | Sort-Object SamAccountName) {
  $n = $u.SamAccountName
  $tag = if (Is-Scored $n) {'scored'} elseif (Is-Kept $n) {'ours'} else {'UNLISTED'}
  $flags = @()
  if ($u.whenCreated -gt $since) { $flags += "NEW($($u.whenCreated))" }
  if ($u.DoesNotRequirePreAuth) { $flags += 'ASREP-ROASTABLE' }
  if ($u.PasswordNotRequired) { $flags += 'PASSWD_NOTREQD' }
  if ($u.AllowReversiblePasswordEncryption) { $flags += 'REVERSIBLE-ENC' }
  if ($u.ServicePrincipalName -and $n -ne 'krbtgt') { $flags += "SPN(kerberoastable):$($u.ServicePrincipalName -join ';')" }
  if ($u.SIDHistory) { $flags += 'SIDHISTORY' }
  if ($u.TrustedForDelegation) { $flags += 'UNCONSTRAINED-DELEG' }
  if ($u.adminCount -eq 1 -and -not (Is-Kept $n)) { $flags += 'adminCount=1' }
  if ($u.Description -match 'pass|pwd|cred') { $flags += "DESC:'$($u.Description)'" }
  $line = "{0,-20} {1,-9} enabled={2,-5} {3}" -f $n,$tag,$u.Enabled,($flags -join ' ')
  if ($tag -eq 'UNLISTED' -and $u.Enabled -or $flags.Count) { Warn $line } else { "    $line" }
}
$guest = Get-ADUser Guest; if ($guest.Enabled) { Warn "Domain Guest is ENABLED" }
"    krbtgt password last set: $((Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet)"

Hdr "PRIVILEGED GROUP MEMBERSHIP (recursive)"
$priv = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Cert Publishers','Remote Desktop Users','Remote Management Users'
foreach ($g in $priv) {
  try {
    $m = Get-ADGroupMember $g -Recursive -ErrorAction Stop
    foreach ($x in $m) {
      $ok = ($PrivAllow -contains $x.SamAccountName) -or ($g -eq 'Cert Publishers' -and $x.objectClass -eq 'computer') -or ($g -match 'Remote' -and (Is-Scored $x.SamAccountName))
      if ($ok) { "    $g : $($x.SamAccountName)" } else { Warn "$g : $($x.SamAccountName) ($($x.objectClass))" }
    }
  } catch {}
}
Info "Remote Desktop/Management Users may legitimately hold scored users - RDP/WinRM checks might log in as them."

Hdr "COMPUTERS (new or with unconstrained delegation)"
Get-ADComputer -Filter * -Properties whenCreated,TrustedForDelegation,OperatingSystem | ForEach-Object {
  $f = @(); if ($_.whenCreated -gt $since) { $f += 'NEW' }
  if ($_.TrustedForDelegation -and $_.DistinguishedName -notmatch 'OU=Domain Controllers') { $f += 'UNCONSTRAINED' }
  $l = "{0,-18} {1} {2}" -f $_.Name,$_.OperatingSystem,($f -join ' ')
  if ($f) { Warn $l } else { "    $l" }
}

Hdr "DCSYNC RIGHTS ON DOMAIN ROOT (only DCs / Administrators / Enterprise DCs should have these)"
$repl = @{'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'='Replicating-Changes';'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'='Replicating-Changes-All';'89e95b76-444d-4c62-991a-0facbeda640c'='Replicating-Changes-In-Filtered-Set'}
$acl = Get-Acl "AD:\$root"
$acl.Access | Where-Object { $repl.ContainsKey($_.ObjectType.ToString()) -and $_.AccessControlType -eq 'Allow' } | ForEach-Object {
  $id = $_.IdentityReference.ToString()
  if ($id -match 'Domain Controllers|Enterprise Domain Controllers|Administrators|ENTERPRISE DOMAIN CONTROLLERS|Enterprise Read-only|SYSTEM') { "    $id : $($repl[$_.ObjectType.ToString()])" }
  else { Warn "$id has $($repl[$_.ObjectType.ToString()])  <-- DCSync backdoor" }
}
$acl.Access | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -and $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|Key Admins|Enterprise Key Admins|CREATOR OWNER' } | ForEach-Object { Warn "Domain root: $($_.IdentityReference) has $($_.ActiveDirectoryRights)" }

Hdr "ADMINSDHOLDER ACL (gets copied onto every admin account hourly)"
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,$root").Access | Where-Object {
  $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight' -and
  $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|SELF|Cert Publishers|Windows Authorization Access|Terminal Server License|Pre-Windows 2000|Everyone|Authenticated Users|Key Admins|Enterprise Key Admins'
} | ForEach-Object { Warn "AdminSDHolder: $($_.IdentityReference) $($_.ActiveDirectoryRights)" }

Hdr "GPOs (recently modified = check for scheduled tasks / scripts / local admin adds)"
Import-Module GroupPolicy -ErrorAction SilentlyContinue
Get-GPO -All | Sort-Object ModificationTime -Descending | ForEach-Object {
  $l = "{0,-45} modified {1}" -f $_.DisplayName,$_.ModificationTime
  if ($_.ModificationTime -gt $since) { Warn $l } else { "    $l" }
}
$sysvol = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
Get-ChildItem $sysvol -Recurse -Force -ErrorAction SilentlyContinue -Include ScheduledTasks.xml,Groups.xml,Services.xml,*.ps1,*.bat,*.cmd,*.vbs,*.exe,scripts.ini,psscripts.ini |
  ForEach-Object { Warn "SYSVOL: $($_.FullName) ($($_.LastWriteTime))" }
Get-ChildItem $sysvol -Recurse -Include Groups.xml -ErrorAction SilentlyContinue | Select-String 'cpassword' | ForEach-Object { Warn "GPP cpassword (readable by all users): $($_.Path)" }
Get-ChildItem "\\$($dom.DNSRoot)\NETLOGON" -Force -ErrorAction SilentlyContinue | ForEach-Object { "    NETLOGON: $($_.Name) ($($_.LastWriteTime))" }

Hdr "PASSWORD POLICY"
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength,ComplexityEnabled,LockoutThreshold,MaxPasswordAge,ReversibleEncryptionEnabled | Out-String | Write-Host
Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue | ForEach-Object { Warn "Fine-grained policy: $($_.Name) applies to $($_.AppliesTo)" }

Hdr "DNS (scored via DCs - check for rogue records)"
try {
  Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated } | ForEach-Object { "    zone $($_.ZoneName) dynamic=$($_.DynamicUpdate)" ; if ($_.DynamicUpdate -eq 'NonsecureAndSecure') { Warn "Zone $($_.ZoneName) allows NONSECURE dynamic updates" } }
  Get-DnsServerResourceRecord -ZoneName $dom.DNSRoot -RRType A | Where-Object { $_.HostName -match '^(wpad|isatap|\*)$' } | ForEach-Object { Warn "Suspicious DNS record: $($_.HostName) -> $($_.RecordData.IPv4Address)" }
} catch { Info "DnsServer module not available here" }

Hdr "AD CS (DC2 hosts the CA - ESC1/ESC8 are the classic paths to Domain Admin)"
$cfg = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$root"
$enrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'; $autoGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$cas = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$root" -Filter * -Properties certificateTemplates,dNSHostName -ErrorAction SilentlyContinue
$published = $cas.certificateTemplates
"    CAs: $($cas.Name -join ', ') on $($cas.dNSHostName -join ', ')"
Get-ADObject -SearchBase $cfg -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties 'msPKI-Certificate-Name-Flag','pKIExtendedKeyUsage','msPKI-Enrollment-Flag','msPKI-RA-Signature',whenChanged | ForEach-Object {
  $t = $_
  if ($published -notcontains $t.Name) { return }
  $supplies = ($t.'msPKI-Certificate-Name-Flag' -band 1) -eq 1
  $eku = $t.pKIExtendedKeyUsage
  $authEku = (-not $eku) -or ($eku -match '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0')
  $approval = ($t.'msPKI-Enrollment-Flag' -band 2) -eq 2
  $lowPrivEnroll = (Get-Acl "AD:\$($t.DistinguishedName)").Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -match 'Domain Users|Authenticated Users|Everyone|Domain Computers' -and
    ($_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -or ($_.ActiveDirectoryRights -match 'ExtendedRight' -and $_.ObjectType -in $enrollGuid,$autoGuid,'00000000-0000-0000-0000-000000000000'))
  }
  $writable = (Get-Acl "AD:\$($t.DistinguishedName)").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty' -and $_.IdentityReference -match 'Domain Users|Authenticated Users|Everyone|Domain Computers' }
  if ($supplies -and $authEku -and -not $approval -and $lowPrivEnroll) { Warn "ESC1 template '$($t.Name)': enrollee supplies subject + auth EKU + low-priv enroll. Fix: untick 'Supply in the request' or remove Domain Users enroll." }
  elseif ($writable) { Warn "ESC4 template '$($t.Name)': low-priv users can EDIT it ($($writable.IdentityReference -join ','))" }
  else { "    template $($t.Name) (published) ok-ish" }
  if ($t.whenChanged -gt $since) { Warn "Template $($t.Name) changed $($t.whenChanged)" }
}
Info "ESC8: on DC2 check IIS for /certsrv. If web enrollment is on over HTTP with NTLM, NTLM relay -> DC cert -> DCSync."
Info "  Fix on DC2: require SSL + Extended Protection on /certsrv, or remove Web Enrollment if the CA check doesn't need it."

Stop-Transcript | Out-Null
Ok "Report: $out ($((Select-String -Path $out -Pattern '\[!\]').Count) flagged)"
