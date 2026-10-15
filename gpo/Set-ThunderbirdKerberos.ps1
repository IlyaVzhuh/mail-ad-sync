<#
.SYNOPSIS
    GPO user logon script: Thunderbird logs in to mail.example.com with Kerberos (the Windows logon) when it
    can, and with the mailbox password when it can't (off-site, no ticket, mailbox not linked to AD).

.DESCRIPTION
    Runs as the logged-on user, needs no admin rights. On every logon it:
      1. Reads the user's own AD object (mail, displayName). Mailbox = AD `mail` if it is on one of
         our mail domains, else sAMAccountName@example.com. DC unreachable -> changes nothing.
      2. Finds the Thunderbird profile (%APPDATA%\Thunderbird). No profile -> creates one.
      3. No account for this mailbox yet -> adds one (IMAP 993 SSL + SMTP 465 SSL on mail.example.com,
         Kerberos-then-password, name/address from AD, Russian special folders). Only when Thunderbird is closed;
         otherwise it retries at the next logon.
      4. Existing accounts on mail.example.com for this mailbox -> sets incoming auth to "anything"
         (authMethod 9) through user.js, re-applied every time Thunderbird starts. Thunderbird's IMAP code
         then tries GSSAPI first; if that fails it marks it failed and falls back to PLAIN with the
         saved/prompted password (nsImapProtocol.cpp: ChooseAuthMethod / MarkAuthMethodAsFailed).
         Pure GSSAPI (authMethod 5) is NOT used: it has no password fallback.
      5. Allows remote content (pictures) in messages for the whole profile, also through user.js
         (Settings > Privacy & Security > "Allow remote content in messages").
      6. Sends every message as HTML plus a plain-text copy (Settings > Composition > Sending Format >
         "Both HTML and Plain Text"), also through user.js. The default "Automatic" turns unformatted
         messages into plain text only, and those get the mail server's footer without the logo.
      7. Sending (SMTP 465): Kerberos (authMethod 5) only when this logon can really get a ticket for
         smtp/mail.example.com (klist get) and the PC is not a laptop; otherwise the mailbox password
         (authMethod 3). Thunderbird's SMTP client has no fallback, and "anything" there means no auth
         at all (SmtpClient.sys.mjs), so the choice is made here, at every logon, and enforced through
         user.js. A PC that can't get a ticket at the next logon goes back to the password by itself.
         Laptops stay on the password (a cached ticket expires off-site, and then sending just fails)
         unless -KerberosSmtpOnLaptops is given. Server side: smtp-kerberos.sh (GSSAPI on 465 only).
    Other accounts (shared mailboxes, other servers) are left alone and keep their passwords.

    Log: %LOCALAPPDATA%\thunderbird-kerberos.log

.PARAMETER WhatIf
    Log what would change, write nothing.

.PARAMETER KerberosSmtpOnLaptops
    Also send with Kerberos on PCs that have a battery.

.NOTES
    GPO: User Configuration > Policies > Windows Settings > Scripts (Logon) > "Scripts" tab:
         Script name:       %windir%\System32\WindowsPowerShell\v1.0\powershell.exe
         Script parameters: -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "\\corp.example.com\NETLOGON\Thunderbird\Set-ThunderbirdKerberos.ps1"
    Plus Computer Configuration > Administrative Templates > System > Group Policy >
         "Configure Logon Script Delay" = Enabled, 0 minutes (the Windows default is 5 minutes,
         and the user may already have Thunderbird open by then).
    This file must stay UTF-8 *with BOM* (Windows PowerShell 5.1 needs it for the Cyrillic folder names).
#>
[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$KerberosSmtpOnLaptops,
    [string]$MailHost      = 'mail.example.com',
    [string[]]$MailDomains = @('example.com', 'example.org'),
    [string]$DefaultDomain = 'example.com'
)

$ErrorActionPreference = 'Stop'
$AUTH_ANY      = 9      # nsMsgAuthMethod: 9 = anything the server offers (IMAP: GSSAPI first, then password)
$AUTH_PASSWORD = 3      # 3 = normal password
$AUTH_GSSAPI   = 5      # 5 = Kerberos only (no password fallback)
$SOCKET_SSL    = 3      # SSL/TLS from the start (993 / 465)
$SEND_BOTH     = 1      # mail.default_send_format: 0 = automatic, 1 = HTML + plain text, 2 = HTML only, 3 = plain text only
$FOLDERS = @{ Sent = 'Отправленные'; Drafts = 'Черновики'; Trash = 'Удаленные'; Junk = 'Спам' }
$MARK_BEGIN = '// BEGIN mail-kerberos (GPO, rewritten at every logon)'
$MARK_END   = '// END mail-kerberos'
$Utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
$LogFile    = Join-Path $env:LOCALAPPDATA 'thunderbird-kerberos.log'

function Log([string]$msg) {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $msg
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 512KB) { Remove-Item $LogFile -Force }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
    Write-Verbose $line
}

# ---------- prefs.js helpers ----------
# Thunderbird pref files are lines of: user_pref("name", value);  (UTF-8, no BOM)
$PrefLine = '^\s*user_pref\("((?:[^"\\]|\\.)+)",\s*(.+?)\);\s*$'

function Read-Prefs([string]$path) {
    $prefs = [ordered]@{}
    if (Test-Path $path) {
        foreach ($l in [IO.File]::ReadAllLines($path, $Utf8NoBom)) {
            if ($l -match $PrefLine) { $prefs[$Matches[1]] = $Matches[2] }
        }
    }
    return $prefs
}

function Get-PrefString($prefs, [string]$name) {
    # Returns the unquoted string value, or $null.
    if (-not $prefs.Contains($name)) { return $null }
    $raw = $prefs[$name]
    if ($raw -match '^"(.*)"$') { return ($Matches[1] -replace '\\(.)', '$1') }
    return $raw
}

function Format-Pref([string]$name, $value) {
    if ($value -is [bool])   { $v = $value.ToString().ToLower() }
    elseif ($value -is [int]) { $v = [string]$value }
    else { $v = '"' + (([string]$value) -replace '\\', '\\' -replace '"', '\"') + '"' }
    return ('user_pref("{0}", {1});' -f $name, $v)
}

function Get-NextId($prefs, [string]$pattern) {
    $max = 0
    foreach ($k in $prefs.Keys) {
        if ($k -match $pattern) { $n = [int]$Matches[1]; if ($n -gt $max) { $max = $n } }
    }
    return $max + 1
}

function Add-ToList([string]$list, [string]$item) {
    if ([string]::IsNullOrWhiteSpace($list)) { return $item }
    $items = @($list -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($items -contains $item) { return ($items -join ',') }
    return (@($items + $item) -join ',')
}

function Get-FolderUri([string]$user, [string]$folder) {
    # Thunderbird stores IMAP folder URIs percent-encoded: imap://user%40domain@host/%D0%9E...
    return 'imap://{0}@{1}/{2}' -f [Uri]::EscapeDataString($user), $MailHost, [Uri]::EscapeDataString($folder)
}

# ---------- 1. who is logged on ----------
try {
    if ($env:USERDOMAIN -eq $env:COMPUTERNAME) { Log "Local account $env:USERNAME, nothing to do."; return }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$env:USERNAME))"
    'mail', 'displayName', 'sAMAccountName', 'givenName', 'sn' | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
    $searcher.ClientTimeout = [TimeSpan]::FromSeconds(15)
    $ad = $searcher.FindOne()
} catch {
    Log "AD not reachable ($($_.Exception.Message)); nothing changed."
    return
}
if (-not $ad) { Log "User $env:USERNAME not found in AD; nothing changed."; return }

$sam  = [string]$ad.Properties['samaccountname'][0]
$mail = if ($ad.Properties['mail'].Count) { ([string]$ad.Properties['mail'][0]).Trim().ToLower() } else { '' }
$name = if ($ad.Properties['displayname'].Count) { [string]$ad.Properties['displayname'][0] } else { $sam }

$mailDomain = if ($mail -match '@(.+)$') { $Matches[1] } else { '' }
$mailbox = if ($mail -and ($MailDomains -contains $mailDomain)) { $mail } else { "$($sam.ToLower())@$DefaultDomain" }
Log "User $sam -> mailbox $mailbox ($name). WhatIf=$WhatIf"

# ---------- 1b. can this logon send with Kerberos? ----------
$isLaptop = [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
$smtpKerberos = $false
if ($isLaptop -and -not $KerberosSmtpOnLaptops) {
    $smtpWhy = 'laptop'
} else {
    # Asks the DC for the service ticket Thunderbird would use; exit code 0 = got it.
    & "$env:windir\System32\klist.exe" get "smtp/$MailHost" *> $null
    $smtpKerberos = ($LASTEXITCODE -eq 0)
    $smtpWhy = if ($smtpKerberos) { 'ticket OK' } else { "no ticket (klist exit $LASTEXITCODE)" }
}
$smtpAuth = if ($smtpKerberos) { $AUTH_GSSAPI } else { $AUTH_PASSWORD }
Log "Outgoing auth: $(if ($smtpKerberos) { 'Kerberos' } else { 'password' }) ($smtpWhy)."

# ---------- 2. Thunderbird installed? ----------
$tbExe = @(
    "$env:ProgramFiles\Mozilla Thunderbird\thunderbird.exe",
    "${env:ProgramFiles(x86)}\Mozilla Thunderbird\thunderbird.exe",
    "$env:LOCALAPPDATA\Mozilla Thunderbird\thunderbird.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $tbExe) { Log 'Thunderbird is not installed; nothing changed.'; return }

# ---------- 3. find or create the profile ----------
$tbRoot  = Join-Path $env:APPDATA 'Thunderbird'
$iniPath = Join-Path $tbRoot 'profiles.ini'
$profileDir = $null

if (Test-Path $iniPath) {
    $sections = [ordered]@{}; $cur = $null
    foreach ($l in [IO.File]::ReadAllLines($iniPath)) {
        if ($l -match '^\[(.+)\]$') { $cur = $Matches[1]; $sections[$cur] = @{} }
        elseif ($cur -and $l -match '^([^=]+)=(.*)$') { $sections[$cur][$Matches[1]] = $Matches[2] }
    }
    $pick = $null
    # Thunderbird 68+ keeps the default profile per install in [Install<hash>] Default=<path>
    $inst = $sections.Keys | Where-Object { $_ -like 'Install*' -and $sections[$_]['Default'] } | Select-Object -First 1
    if ($inst) {
        $p = $sections[$inst]['Default']
        $sec = $sections.Values | Where-Object { $_['Path'] -eq $p } | Select-Object -First 1
        $pick = if ($sec) { $sec } else { @{ Path = $p; IsRelative = '1' } }
    }
    if (-not $pick) { $pick = $sections.Keys | Where-Object { $_ -like 'Profile*' -and $sections[$_]['Default'] -eq '1' } | ForEach-Object { $sections[$_] } | Select-Object -First 1 }
    if (-not $pick) { $pick = $sections.Keys | Where-Object { $_ -like 'Profile*' } | ForEach-Object { $sections[$_] } | Select-Object -First 1 }
    if ($pick) {
        $rel = $pick['Path'] -replace '/', '\'
        $profileDir = if ($pick['IsRelative'] -eq '1') { Join-Path $tbRoot $rel } else { $rel }
    }
}

$tbRunning = [bool](Get-Process -Name thunderbird -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId })

if (-not $profileDir -or -not (Test-Path $profileDir)) {
    if ($tbRunning) { Log 'Thunderbird is running without a known profile; will retry at next logon.'; return }
    $rand = -join ((48..57) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    $rel = "Profiles/$rand.default-release"
    $profileDir = Join-Path $tbRoot ($rel -replace '/', '\')
    Log "No Thunderbird profile; creating $profileDir"
    if (-not $WhatIf) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        # No [Install...] section: on first start Thunderbird adopts the Default=1 profile for this install.
        $ini = "[Profile0]`r`nName=default-release`r`nIsRelative=1`r`nPath=$rel`r`nDefault=1`r`n`r`n[General]`r`nStartWithLastProfile=1`r`nVersion=2`r`n"
        [IO.File]::WriteAllText($iniPath, $ini, $Utf8NoBom)
    }
}

$prefsPath  = Join-Path $profileDir 'prefs.js'
$userJsPath = Join-Path $profileDir 'user.js'
$prefs = Read-Prefs $prefsPath

# ---------- 4. existing accounts for this mailbox ----------
$incoming = @()
foreach ($k in @($prefs.Keys)) {
    if ($k -match '^mail\.server\.(server\d+)\.hostname$' -and (Get-PrefString $prefs $k) -ieq $MailHost) {
        $sid  = $Matches[1]
        $type = Get-PrefString $prefs "mail.server.$sid.type"
        $user = Get-PrefString $prefs "mail.server.$sid.userName"
        if ($type -in 'imap', 'pop3' -and $user -ieq $mailbox) { $incoming += $sid }
    }
}
$outgoing = @()
foreach ($k in @($prefs.Keys)) {
    if ($k -match '^mail\.smtpserver\.(smtp\d+)\.hostname$' -and (Get-PrefString $prefs $k) -ieq $MailHost) {
        $smid = $Matches[1]
        if ((Get-PrefString $prefs "mail.smtpserver.$smid.username") -ieq $mailbox) { $outgoing += $smid }
    }
}

# ---------- 5. create the account if missing ----------
if (-not $incoming) {
    if ($tbRunning) {
        Log 'No account for this mailbox, but Thunderbird is open; will add it at next logon.'
    } else {
        $acc  = 'account' + (Get-NextId $prefs '^mail\.account\.account(\d+)\.')
        $srv  = 'server'  + (Get-NextId $prefs '^mail\.server\.server(\d+)\.')
        $idn  = 'id'      + (Get-NextId $prefs '^mail\.identity\.id(\d+)\.')
        # Reuse an existing SMTP entry for this mailbox, else make one.
        $smtp = if ($outgoing) { $outgoing[0] } else { 'smtp' + (Get-NextId $prefs '^mail\.smtpserver\.smtp(\d+)\.') }
        Log "Adding account $acc / $srv / $idn / $smtp for $mailbox"

        $new = [ordered]@{
            "mail.server.$srv.type"                 = 'imap'
            "mail.server.$srv.hostname"             = $MailHost
            "mail.server.$srv.port"                 = 993
            "mail.server.$srv.socketType"           = $SOCKET_SSL
            "mail.server.$srv.authMethod"           = $AUTH_ANY
            "mail.server.$srv.userName"             = $mailbox
            "mail.server.$srv.name"                 = $mailbox
            "mail.server.$srv.login_at_startup"     = $true
            "mail.server.$srv.check_new_mail"       = $true
            "mail.server.$srv.check_all_folders_for_new" = $true
            "mail.server.$srv.trash_folder_name"    = $FOLDERS.Trash
            "mail.server.$srv.spamActionTargetAccount" = "imap://$([Uri]::EscapeDataString($mailbox))@$MailHost"
            "mail.server.$srv.spamActionTargetFolder"  = (Get-FolderUri $mailbox $FOLDERS.Junk)
            "mail.identity.$idn.useremail"          = $mailbox
            "mail.identity.$idn.fullName"           = $name
            "mail.identity.$idn.valid"              = $true
            "mail.identity.$idn.smtpServer"         = $smtp
            "mail.identity.$idn.fcc"                = $true
            "mail.identity.$idn.fcc_folder"         = (Get-FolderUri $mailbox $FOLDERS.Sent)
            "mail.identity.$idn.fcc_folder_picker_mode"   = '1'
            "mail.identity.$idn.draft_folder"       = (Get-FolderUri $mailbox $FOLDERS.Drafts)
            "mail.identity.$idn.drafts_folder_picker_mode" = '1'
            "mail.account.$acc.server"              = $srv
            "mail.account.$acc.identities"          = $idn
            "mail.accountmanager.accounts"          = (Add-ToList (Get-PrefString $prefs 'mail.accountmanager.accounts') $acc)
        }
        if (-not (Get-PrefString $prefs 'mail.accountmanager.defaultaccount')) { $new['mail.accountmanager.defaultaccount'] = $acc }
        if (-not $outgoing) {
            $new["mail.smtpserver.$smtp.hostname"]    = $MailHost
            $new["mail.smtpserver.$smtp.port"]        = 465
            $new["mail.smtpserver.$smtp.try_ssl"]     = $SOCKET_SSL
            $new["mail.smtpserver.$smtp.authMethod"]  = $smtpAuth
            $new["mail.smtpserver.$smtp.username"]    = $mailbox
            $new["mail.smtpserver.$smtp.description"] = $MailHost
            $new['mail.smtpservers'] = Add-ToList (Get-PrefString $prefs 'mail.smtpservers') $smtp
            if (-not (Get-PrefString $prefs 'mail.smtp.defaultserver')) { $new['mail.smtp.defaultserver'] = $smtp }
        }
        if ($prefs.Count -eq 0) {
            # Fresh profile: skip the first-run noise.
            $new['mail.shell.checkDefaultClient'] = $false
            $new['mail.provider.enabled']         = $false
            $new['mailnews.start_page.enabled']   = $false
        }

        # prefs.js is read top to bottom, later lines win; Thunderbird rewrites it cleanly on exit.
        $stamp = '// added by GPO logon script ' + (Get-Date).ToString('s')
        $lines = @('', $stamp)
        foreach ($k in $new.Keys) { $lines += Format-Pref $k $new[$k] }
        if (-not $WhatIf) {
            if (-not (Test-Path $prefsPath)) { [IO.File]::WriteAllText($prefsPath, "// Mozilla User Preferences`r`n", $Utf8NoBom) }
            [IO.File]::AppendAllText($prefsPath, (($lines -join "`r`n") + "`r`n"), $Utf8NoBom)
        }
        $incoming = @($srv)
        if (-not $outgoing) { $outgoing = @($smtp) }
    }
}

# ---------- 6. enforce Kerberos-then-password through user.js (re-applied at every Thunderbird start) ----------
$enforce = @()
foreach ($sid in $incoming) { $enforce += Format-Pref "mail.server.$sid.authMethod" $AUTH_ANY }
# Outgoing: Kerberos or password, decided above for this logon (no fallback inside Thunderbird).
foreach ($smid in $outgoing) { $enforce += Format-Pref "mail.smtpserver.$smid.authMethod" $smtpAuth }
# Windows SSPI does the Kerberos part; make sure nobody switched it off.
$enforce += Format-Pref 'network.auth.use-sspi' $true
# Show remote content (pictures) in messages without the "blocked remote content" bar.
$enforce += Format-Pref 'mailnews.message_display.disable_remote_image' $false
# Always send an HTML part, so the server-side footer (logo) is added to every message.
$enforce += Format-Pref 'mail.default_send_format' $SEND_BOTH

$kept = @()
if (Test-Path $userJsPath) {
    $inBlock = $false
    foreach ($l in [IO.File]::ReadAllLines($userJsPath, $Utf8NoBom)) {
        if ($l -eq $MARK_BEGIN) { $inBlock = $true; continue }
        if ($l -eq $MARK_END)   { $inBlock = $false; continue }
        if (-not $inBlock) { $kept += $l }
    }
}
$userJs = @($kept | Where-Object { $_ -ne '' }) + $MARK_BEGIN + $enforce + $MARK_END
if (-not $WhatIf) { [IO.File]::WriteAllText($userJsPath, (($userJs -join "`r`n") + "`r`n"), $Utf8NoBom) }

Log ("Kerberos-then-password on incoming [{0}], {1} on outgoing [{2}], remote content allowed, send format HTML + plain text{3}." -f ($incoming -join ','),
     $(if ($smtpKerberos) { 'Kerberos' } else { 'password' }),
     ($outgoing -join ','),
     $(if ($tbRunning) { ' (takes effect when Thunderbird restarts)' } else { '' }))
