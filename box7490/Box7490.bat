<# : Box7490 - batch launcher (keep this first line exactly as it is)
@echo off
setlocal
set "PSModulePath="
set "OW_BAT=%~f0"
title Box7490 - trappola e sonda per FRITZ!Box 7490
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PSEXE=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PSEXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "&([ScriptBlock]::Create([IO.File]::ReadAllText($env:OW_BAT, [Text.Encoding]::UTF8)))"
if errorlevel 1 pause
exit /b
#>
<#
  Box7490.bat - runs OpenWrt on an AVM FRITZ!Box 7490: in RAM only, or installed on the flash,
  and turns it into a LAN trap or a monitoring probe.
  Requirements: Windows 10/11 with the OpenSSH client, an administrator account (to set the IP
  addresses of the wired adapter), a cable to a LAN port of the box.

  Images come only from downloads.openwrt.org (checked against the official sha256sums) or from the
  official build service sysupgrade.openwrt.org (checked against the hash it returns).
  The upload to the EVA bootloader uses the official scripts/flashing/eva_ramboot.py of OpenWrt,
  run by the embeddable Python from python.org (no installation).
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ToolVersion = '0.1.0'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

# ============================== CONSTANTS ==============================
$Root = Split-Path -Parent $env:OW_BAT
$Dirs = @{
    Cache    = Join-Path $Root 'cache'
    State    = Join-Path $Root 'stato'
    Log      = Join-Path $Root 'log'
    Profiles = Join-Path $Root 'profili'
}
$EvaIp = '192.168.178.1'
$RamIp = '192.168.1.1'
$BenchIps = @(@{ Ip = '192.168.178.2'; Prefix = 24 }, @{ Ip = '192.168.1.2'; Prefix = 24 })
$Target = 'lantiq/xrx200'
$BoardProfiles = @{ micron = 'avm_fritz7490-micron'; standard = 'avm_fritz7490' }
$DefaultVersion = '25.12.6'
$Downloads = 'https://downloads.openwrt.org/releases'
$AsuUrl = 'https://sysupgrade.openwrt.org'
$Python = @{
    Version = '3.14.9'
    Url     = 'https://www.python.org/ftp/python/3.14.9/python-3.14.9-embed-amd64.zip'
    Sha256  = '3c01d7cfc666f746a6f064f60fb2156ab0ec464d3d738ab796371a46a9bb24a2'
}
$Eva = @{
    Url    = 'https://raw.githubusercontent.com/openwrt/openwrt/cb642c0818358972a31620f583627cd35aa354a1/scripts/flashing/eva_ramboot.py'
    Sha256 = '6cae3171b78b96ce77a9255afe80d2e038652192b61d1e802b3f4b4214a11c88'
}
$ImagePackages = @{
    trap  = @('wireguard-tools', 'kmod-wireguard')
    probe = @('wireguard-tools', 'kmod-wireguard', 'iperf3', 'tcpdump', 'mtr-nojson', 'zabbix-agentd',
              'prometheus-node-exporter-lua', 'prometheus-node-exporter-lua-netstat')
}
$TrapPorts = '21 23 139 445 1433 3306 3389 5900 8080'
$SshExe = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
$SshKeygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
$KeyPath = Join-Path $env:USERPROFILE '.ssh\box7490_ed25519'

# ============================== ADMINISTRATOR ==============================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ''
    Write-Host '  Servono i diritti di amministratore per impostare gli IP della scheda di rete.' -ForegroundColor Yellow
    Write-Host '  Conferma la richiesta di Windows che sta per comparire.'
    try { Start-Process -FilePath $env:OW_BAT -Verb RunAs | Out-Null } catch { Write-Host '  Avvio come amministratore annullato.' -ForegroundColor Red; Start-Sleep 3 }
    return
}
if (-not (Test-Path $SshExe)) {
    Write-Host '  Manca il client OpenSSH di Windows (Impostazioni > App > Funzionalità facoltative > Client OpenSSH).' -ForegroundColor Red
    Write-Host '  Premi un tasto per uscire...'; [void][Console]::ReadKey($true); return
}
foreach ($d in 'Cache', 'State', 'Log') { if (-not (Test-Path $Dirs[$d])) { New-Item -ItemType Directory -Path $Dirs[$d] | Out-Null } }
try { Start-Transcript -Path (Join-Path $Dirs.Log ((Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')) | Out-Null } catch { }

# ============================== SETTINGS ==============================
$SettingsFile = Join-Path $Dirs.State 'impostazioni.json'
$Settings = @{ BoxIp = $RamIp; Adapter = ''; Version = ''; LastVariant = '' }
if (Test-Path $SettingsFile) {
    try {
        $j = [IO.File]::ReadAllText($SettingsFile) | ConvertFrom-Json
        foreach ($p in $j.PSObject.Properties) { $Settings[$p.Name] = "$($p.Value)" }
    } catch { }
}
function Save-Settings { [IO.File]::WriteAllText($SettingsFile, ($Settings | ConvertTo-Json), (New-Object Text.UTF8Encoding($false))) }

# ============================== CONSOLE ==============================
function Clear-KeyBuffer { try { $Host.UI.RawUI.FlushInputBuffer() } catch { try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { } } }
function Wait-Key([string]$msg = '  Premi un tasto per tornare al menu...') {
    Write-Host ''
    Write-Host $msg -ForegroundColor DarkGray
    Clear-KeyBuffer
    try { [void][Console]::ReadKey($true) } catch { }
}
function Say([string]$t) { Write-Host "  $t" }
function Step([string]$t) { Write-Host ''; Write-Host "  == $t" -ForegroundColor Cyan }
function Ok([string]$t) { Write-Host "  OK  $t" -ForegroundColor Green }
function Warn([string]$t) { Write-Host "  !!  $t" -ForegroundColor Yellow }
function Fail([string]$t) { Write-Host "  XX  $t" -ForegroundColor Red }

function Write-At([int]$row, [string]$text, [string]$fg = 'Gray') {
    $w = 79
    try { $w = [Math]::Max(20, [Console]::WindowWidth - 1) } catch { }
    if ($text.Length -gt $w) { $text = $text.Substring(0, $w) }
    [Console]::SetCursorPosition(0, $row)
    Write-Host $text.PadRight($w) -ForegroundColor $fg -NoNewline
}

function Split-Words([string]$text, [int]$width) {
    $lines = @(); $cur = ''
    foreach ($word in ($text -split ' ')) {
        if (($cur + ' ' + $word).Trim().Length -gt $width) { $lines += $cur; $cur = $word } else { $cur = ($cur + ' ' + $word).Trim() }
    }
    if ($cur) { $lines += $cur }
    return ,$lines
}

function Show-Header([int]$W) {
    Clear-Host
    $ver = $Settings.Version; if (-not $ver) { $ver = '(da scegliere)' }
    $ad = $Settings.Adapter; if (-not $ad) { $ad = '(da scegliere)' }
    Write-Host ''
    Write-Host ('  ' + ('=' * $W)) -ForegroundColor Cyan
    Write-Host ('  ' + (' ' * [Math]::Max(0, [int](($W - 26) / 2))) + 'BOX7490 - TRAPPOLA E SONDA') -ForegroundColor White
    $sub = "Box $($Settings.BoxIp)  -  scheda PC: $ad  -  OpenWrt $ver"
    Write-Host ('  ' + (' ' * [Math]::Max(0, [int](($W - $sub.Length) / 2))) + $sub) -ForegroundColor DarkGray
    Write-Host ('  ' + ('=' * $W)) -ForegroundColor Cyan
    Write-Host ''
}

function Show-Menu([string]$title, [object[]]$items, [int]$start = 0) {
    # vertical menu: arrows or number keys move, Enter confirms, Esc returns 'exit'
    $ww = 80
    try { $ww = [Console]::WindowWidth } catch { }
    $W = [Math]::Min(70, [Math]::Max(50, $ww - 6))
    $sep = '  ' + ('-' * $W)
    Show-Header $W
    Write-Host ('  ' + $title) -ForegroundColor White
    Write-Host ''
    $top = [Console]::CursorTop
    $panel = $top + $items.Count + 1
    $help = $panel + 7
    for ($r = $top; $r -le $help + 1; $r++) { Write-Host '' }
    $top = [Console]::CursorTop - ($help + 2 - $top); $panel = $top + $items.Count + 1; $help = $panel + 7
    $sel = [Math]::Min([Math]::Max(0, $start), $items.Count - 1)
    $maxKey = [Math]::Min(9, $items.Count)
    try { [Console]::CursorVisible = $false } catch { }
    Clear-KeyBuffer
    try {
        while ($true) {
            for ($i = 0; $i -lt $items.Count; $i++) {
                $label = '{0})  {1}' -f ($i + 1), $items[$i].Label
                if ($i -eq $sel) {
                    Write-At ($top + $i) ''
                    [Console]::SetCursorPosition(3, $top + $i)
                    Write-Host (' > ' + $label.PadRight(30)) -ForegroundColor Black -BackgroundColor Cyan -NoNewline
                } else { Write-At ($top + $i) ('      ' + $label) 'Gray' }
            }
            $it = $items[$sel]
            Write-At $panel $sep 'DarkCyan'
            $desc = Split-Words $it.Desc ($W - 2)
            $color = 'White'; if ($it.Warn) { $color = 'Yellow' }
            for ($j = 0; $j -lt 3; $j++) { $t = ''; if ($j -lt $desc.Count) { $t = '   ' + $desc[$j] }; Write-At ($panel + 1 + $j) $t $color }
            $t = ''; if ($it.Info) { $t = '   ' + $it.Info }; Write-At ($panel + 4) $t 'DarkGray'
            Write-At ($panel + 5) $sep 'DarkCyan'
            Write-At $help ("   Su/Giu: scegli     Invio: conferma     1-$($maxKey): voce     Esc: indietro") 'DarkGray'
            $k = [Console]::ReadKey($true)
            $key = $k.Key.ToString()
            if ($key -eq 'UpArrow') { $sel = ($sel - 1 + $items.Count) % $items.Count }
            elseif ($key -eq 'DownArrow') { $sel = ($sel + 1) % $items.Count }
            elseif ($key -match '^(D|NumPad)([1-9])$') { $n = [int]$matches[2] - 1; if ($n -lt $items.Count) { $sel = $n } }
            elseif ($key -eq 'Enter') { [Console]::SetCursorPosition(0, $help + 2); return $items[$sel].Key }
            elseif ($key -eq 'Escape') { [Console]::SetCursorPosition(0, $help + 2); return 'exit' }
        }
    } finally { try { [Console]::CursorVisible = $true } catch { } }
}

function Item([string]$key, [string]$label, [string]$desc, [string]$info = '', [switch]$Warn) {
    return @{ Key = $key; Label = $label; Desc = $desc; Info = $info; Warn = [bool]$Warn }
}

# ============================== INPUT ==============================
function Test-Ipv4([string]$s) {
    $ip = $null
    return ($s -match '^\d{1,3}(\.\d{1,3}){3}$') -and [Net.IPAddress]::TryParse($s, [ref]$ip)
}
function Test-Cidr4([string]$s) {
    if ($s -match '^(.+)/(\d{1,2})$') { return (Test-Ipv4 $matches[1]) -and ([int]$matches[2] -le 32) }
    return (Test-Ipv4 $s)
}
function Split-List([string]$s) { return @($s -split '[\s,;]+' | Where-Object { $_ }) }
function Test-IpList([string]$s) {
    foreach ($x in (Split-List $s)) { if (-not (Test-Cidr4 $x)) { return $false } }
    return $true
}
function Test-Hostname([string]$s) { return $s -match '^[A-Za-z0-9][A-Za-z0-9-]{0,62}$' }
function Test-DnsName([string]$s) { return $s -match '^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$' }
function Test-Ipv4List([string]$s) {
    foreach ($x in (Split-List $s)) { if (-not (Test-Ipv4 $x)) { return $false } }
    return $true
}
function Test-HostList([string]$s) {
    foreach ($x in (Split-List $s)) { if (-not ((Test-Ipv4 $x) -or (Test-DnsName $x))) { return $false } }
    return $true
}
function Test-PortNumber([string]$s) { return ($s -match '^\d{1,5}$') -and ([int]$s -ge 1) -and ([int]$s -le 65535) }
function Test-TrapPorts([string]$s) {
    # port 22 stays out: it is the management SSH
    foreach ($x in (Split-List $s)) { if (-not (Test-PortNumber $x) -or [int]$x -eq 22) { return $false } }
    return $true
}
function Test-WgKey([string]$s) { return $s -match '^[A-Za-z0-9+/]{43}=$' }
function Get-PubKeys([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    return @([IO.File]::ReadAllLines($path) | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+=*( .*)?$' })
}
function ConvertTo-UInt32([string]$ip) { $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [Array]::Reverse($b); return [BitConverter]::ToUInt32($b, 0) }
function Test-SameSubnet([string]$a, [string]$b, [int]$prefix) {
    if (-not ((Test-Ipv4 $a) -and (Test-Ipv4 $b))) { return $false }
    $mask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $prefix))
    return ((ConvertTo-UInt32 $a) -band $mask) -eq ((ConvertTo-UInt32 $b) -band $mask)
}
function Join-List([string]$s) { return ((Split-List $s) -join ' ') }
function Pick([string]$a, [string]$b) { if ($a) { return $a }; return $b }

function Read-Value([string]$prompt, [string]$default = '', [scriptblock]$valid = $null, [switch]$AllowEmpty) {
    while ($true) {
        $p = "  $prompt"
        if ($default) { $p += " [$default]" }
        Clear-KeyBuffer
        $v = "$(Read-Host $p)".Trim()
        if (-not $v) { $v = $default }
        if (-not $v) {
            if ($AllowEmpty) { return '' }
            Warn 'Valore obbligatorio.'; continue
        }
        if ($v -eq '-' -and $AllowEmpty) { return '' }
        if ($valid -and -not (& $valid $v)) { Warn 'Valore non valido, riprova.'; continue }
        return $v
    }
}
function Read-YesNo([string]$prompt, [bool]$default = $false) {
    $d = 's/N'; if ($default) { $d = 'S/n' }
    while ($true) {
        Clear-KeyBuffer
        $v = "$(Read-Host "  $prompt ($d)")".Trim().ToLower()
        if (-not $v) { return $default }
        if ($v -match '^(s|si|sì|y|yes)$') { return $true }
        if ($v -match '^(n|no)$') { return $false }
    }
}
function Read-Phrase([string]$phrase) {
    Clear-KeyBuffer
    $v = Read-Host "  Per continuare scrivi esattamente: $phrase"
    return ("$v".Trim() -ceq $phrase)
}
function Read-Password([bool]$required) {
    while ($true) {
        Clear-KeyBuffer
        $a = Read-Host '  Password di root del box (Invio = nessuna modifica)' -AsSecureString
        $pa = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
        if (-not $pa) {
            if ($required) { Warn 'Sulla flash la password di root è obbligatoria.'; continue }
            return ''
        }
        if ($pa.Length -lt 8) { Warn 'Almeno 8 caratteri.'; continue }
        $b = Read-Host '  Ripeti la password' -AsSecureString
        $pb = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        if ($pa -cne $pb) { Warn 'Le due password sono diverse.'; continue }
        return $pa
    }
}
function Select-One([string]$title, [object[]]$items, [int]$start = 0) {
    $k = Show-Menu $title $items $start
    Write-Host ''
    return $k
}

# ============================== DOWNLOADS ==============================
function Get-Sha256([string]$path) { return (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower() }
function Get-WebText([string]$url) {
    $c = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60).Content
    if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }
    return [string]$c
}
function Get-WebFile([string]$url, [string]$path) {
    $tmp = "$path.part"
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -TimeoutSec 600
    Move-Item -Path $tmp -Destination $path -Force
}
function New-Dir([string]$path) { if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }; return $path }

function Get-LatestRelease {
    try {
        $html = Get-WebText "$Downloads/"
        $v = [regex]::Matches($html, 'href="(\d+\.\d+\.\d+)/"') | ForEach-Object { $_.Groups[1].Value } |
            Sort-Object { [version]$_ } | Select-Object -Last 1
        if ($v) { return $v }
    } catch { }
    return $null
}
function Get-Version {
    if ($Settings.Version) { return $Settings.Version }
    $v = Get-LatestRelease
    if (-not $v) { $v = $DefaultVersion }
    $Settings.Version = $v; Save-Settings
    return $v
}

function Get-OfficialImage([string]$variant, [string]$kind) {
    # kind: initramfs-kernel or squashfs-sysupgrade
    $ver = Get-Version
    $name = "openwrt-$ver-lantiq-xrx200-$($BoardProfiles[$variant])-$kind.bin"
    $dir = New-Dir (Join-Path $Dirs.Cache $ver)
    $path = Join-Path $dir $name
    $hashFile = "$path.sha256"
    $base = "$Downloads/$ver/targets/$Target"
    Step "Immagine ufficiale $name"
    $expected = $null
    try {
        $sums = Get-WebText "$base/sha256sums"
        $line = ($sums -split "`n") | Where-Object { $_.TrimEnd() -match ('\*' + [regex]::Escape($name) + '$') } | Select-Object -First 1
        if (-not $line) { throw "L'immagine $name non compare nel file sha256sums ufficiale della $ver." }
        $expected = ($line -split '\s+')[0].ToLower()
    } catch {
        if ((Test-Path $path) -and (Test-Path $hashFile)) {
            $saved = ([IO.File]::ReadAllText($hashFile)).Trim()
            if ((Get-Sha256 $path) -eq $saved) {
                Warn 'downloads.openwrt.org non raggiungibile: uso la copia già scaricata, verificata con l''hash ufficiale salvato al download.'
                return $path
            }
        }
        throw
    }
    if ((Test-Path $path) -and (Get-Sha256 $path) -eq $expected) {
        Ok "già scaricata, SHA256 uguale a quello ufficiale ($($expected.Substring(0, 16))...)"
        return $path
    }
    Say 'Scarico da downloads.openwrt.org...'
    Get-WebFile "$base/$name" $path
    if ((Get-Sha256 $path) -ne $expected) { Remove-Item $path -Force; throw 'SHA256 diverso da quello ufficiale: file scartato.' }
    [IO.File]::WriteAllText($hashFile, $expected)
    Ok "scaricata, SHA256 uguale a quello ufficiale ($($expected.Substring(0, 16))...)"
    return $path
}

function Invoke-Asu([string]$method, [string]$url, [string]$body) {
    $code = 0; $text = ''
    try {
        if ($method -eq 'POST') { $r = Invoke-WebRequest -Uri $url -Method Post -Body $body -ContentType 'application/json' -UseBasicParsing -TimeoutSec 60 }
        else { $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60 }
        $code = [int]$r.StatusCode; $text = $r.Content
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if (-not $resp) { throw }
        $code = [int]$resp.StatusCode
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        $text = $sr.ReadToEnd(); $sr.Close()
    }
    if ($text -is [byte[]]) { $text = [Text.Encoding]::UTF8.GetString($text) }
    $json = $null
    try { $json = $text | ConvertFrom-Json } catch { }
    return @{ Code = $code; Json = $json; Text = [string]$text }
}

function Get-AsuImage([string]$variant, [string[]]$packages, [string]$label) {
    $ver = Get-Version
    $profile = $BoardProfiles[$variant]
    Step "Immagine $label costruita dal servizio ufficiale sysupgrade.openwrt.org"
    Say ('Pacchetti aggiunti a quelli standard: ' + ($packages -join ', '))
    $body = @{ version = $ver; target = $Target; profile = $profile; packages = $packages; diff_packages = $false; client = "box7490/$ToolVersion" } | ConvertTo-Json
    $r = Invoke-Asu 'POST' "$AsuUrl/api/v1/build" $body
    $deadline = (Get-Date).AddMinutes(30)
    $hash = $null
    if ($r.Json) { $hash = $r.Json.request_hash }
    while ($r.Code -eq 202) {
        $pos = ''; if ($r.Json.queue_position) { $pos = ", posizione in coda $($r.Json.queue_position)" }
        Say "build: $($r.Json.detail)$pos"
        if ((Get-Date) -gt $deadline) { throw 'La build non è finita entro 30 minuti.' }
        Start-Sleep -Seconds 10
        if ($r.Json.request_hash) { $hash = $r.Json.request_hash }
        $r = Invoke-Asu 'GET' "$AsuUrl/api/v1/build/$hash" ''
    }
    if ($r.Code -ne 200 -or -not $r.Json -or -not $r.Json.images) {
        $msg = $r.Text
        if ($r.Json -and $r.Json.detail) { $msg = $r.Json.detail }
        throw "Il servizio di build ha risposto $($r.Code): $msg"
    }
    $manifest = @(); if ($r.Json.manifest) { $manifest = @($r.Json.manifest.PSObject.Properties.Name) }
    foreach ($p in $packages) { if ($manifest -and ($manifest -notcontains $p)) { throw "Il pacchetto $p non è nell'immagine costruita." } }
    $img = @($r.Json.images | Where-Object { $_.type -eq 'sysupgrade' })[0]
    if (-not $img -or -not $img.sha256) { throw 'Il servizio non ha restituito un''immagine sysupgrade con il suo SHA256.' }
    $dir = New-Dir (Join-Path $Dirs.Cache $ver)
    $path = Join-Path $dir ("asu-" + $label + '-' + $img.name)
    $expected = "$($img.sha256)".ToLower()
    if (-not ((Test-Path $path) -and (Get-Sha256 $path) -eq $expected)) {
        Say "Scarico $($img.name)..."
        Get-WebFile "$AsuUrl/store/$($r.Json.bin_dir)/$($img.name)" $path
        if ((Get-Sha256 $path) -ne $expected) { Remove-Item $path -Force; throw 'SHA256 diverso da quello restituito dal servizio: file scartato.' }
    }
    Ok "immagine pronta, SHA256 uguale a quello del servizio ($($expected.Substring(0, 16))...)"
    return $path
}

function Get-PythonExe {
    $dir = Join-Path $Dirs.Cache "python-$($Python.Version)"
    $exe = Join-Path $dir 'python.exe'
    if (-not (Test-Path $exe)) {
        Step "Python $($Python.Version) embeddable da python.org (nessuna installazione)"
        $zip = Join-Path $Dirs.Cache "python-$($Python.Version)-embed-amd64.zip"
        if (-not ((Test-Path $zip) -and (Get-Sha256 $zip) -eq $Python.Sha256)) { Get-WebFile $Python.Url $zip }
        if ((Get-Sha256 $zip) -ne $Python.Sha256) { Remove-Item $zip -Force; throw 'Lo zip di Python non corrisponde all''hash atteso.' }
        Expand-Archive -Path $zip -DestinationPath $dir -Force
        Remove-Item $zip -Force
    }
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne 'Valid' -or "$($sig.SignerCertificate.Subject)" -notmatch 'Python Software Foundation') {
        throw "La firma di python.exe non è valida ($($sig.Status))."
    }
    return $exe
}

function Get-EvaScript {
    $path = Join-Path $Dirs.Cache 'eva_ramboot.py'
    if (-not ((Test-Path $path) -and (Get-Sha256 $path) -eq $Eva.Sha256)) {
        Step 'eva_ramboot.py dal repository ufficiale di OpenWrt'
        Get-WebFile $Eva.Url $path
        if ((Get-Sha256 $path) -ne $Eva.Sha256) { Remove-Item $path -Force; throw 'eva_ramboot.py non corrisponde all''hash atteso.' }
        Ok 'scaricato e verificato'
    }
    return $path
}

# ============================== PC NETWORK ==============================
function Select-Adapter {
    $list = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.MediaType -eq '802.3' } | Sort-Object Name)
    if (-not $list) { throw 'Nessuna scheda di rete cablata trovata.' }
    $items = @()
    foreach ($a in $list) {
        $ips = @(Get-NetIPAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }) -join ', '
        $items += Item $a.Name $a.Name 'La scheda collegata con il cavo a una porta LAN del FRITZ!Box.' "$($a.InterfaceDescription) - $($a.Status) - $ips"
    }
    $items += Item 'exit' 'Annulla' 'Torna indietro.'
    $k = Select-One 'Quale scheda di rete è collegata al FRITZ!Box?' $items 0
    if ($k -eq 'exit') { return $null }
    $Settings.Adapter = $k; Save-Settings
    return $k
}
function Get-AdapterAlias {
    if ($Settings.Adapter -and (Get-NetAdapter -Name $Settings.Adapter -ErrorAction SilentlyContinue)) { return $Settings.Adapter }
    return (Select-Adapter)
}
function Get-BackupPath([string]$alias) { return Join-Path $Dirs.State ('rete-' + ($alias -replace '[^\w-]', '_') + '.json') }
function Test-BenchNetwork([string]$alias) {
    $have = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
    foreach ($b in $BenchIps) { if ($have -notcontains $b.Ip) { return $false } }
    $gw = @(Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    return ($gw.Count -eq 0)
}
function Set-BenchNetwork([string]$alias) {
    $bk = Get-BackupPath $alias
    if (-not (Test-Path $bk)) {
        $if4 = Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4
        $saved = [ordered]@{
            Alias           = $alias
            Saved           = (Get-Date).ToString('s')
            Dhcp            = "$($if4.Dhcp)"
            AutomaticMetric = "$($if4.AutomaticMetric)"
            Metric          = [int]$if4.InterfaceMetric
            Addresses       = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' } | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
            Gateways        = @(Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop })
            Dns             = @((Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
        }
        [IO.File]::WriteAllText($bk, ($saved | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
        Ok "configurazione attuale della scheda salvata in $bk"
    }
    Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Disabled
    Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses
    foreach ($b in $BenchIps) { New-NetIPAddress -InterfaceAlias $alias -IPAddress $b.Ip -PrefixLength $b.Prefix | Out-Null }
    Set-NetIPInterface -InterfaceAlias $alias -InterfaceMetric 500
    Ok "scheda ${alias}: 192.168.178.2/24 e 192.168.1.2/24, nessun gateway, priorità più bassa del Wi-Fi"
}
function Restore-PcNetwork([string]$alias) {
    $bk = Get-BackupPath $alias
    $saved = $null
    if (Test-Path $bk) { $saved = [IO.File]::ReadAllText($bk) | ConvertFrom-Json }
    Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    if (-not $saved -or $saved.Dhcp -eq 'Enabled') {
        Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Enabled
        Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses
        $what = 'DHCP'
    } else {
        foreach ($a in @($saved.Addresses)) { $ip, $len = $a -split '/'; New-NetIPAddress -InterfaceAlias $alias -IPAddress $ip -PrefixLength ([int]$len) | Out-Null }
        foreach ($g in @($saved.Gateways)) { if ($g) { New-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -NextHop $g | Out-Null } }
        if (@($saved.Dns).Count) { Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @($saved.Dns) } else { Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses }
        $what = 'gli indirizzi fissi di prima'
    }
    if (-not $saved -or $saved.AutomaticMetric -eq 'Enabled') { Set-NetIPInterface -InterfaceAlias $alias -AutomaticMetric Enabled }
    else { Set-NetIPInterface -InterfaceAlias $alias -InterfaceMetric ([int]$saved.Metric) }
    if (Test-Path $bk) { Remove-Item $bk -Force }
    Ok "scheda $alias riportata a $what"
}
function Confirm-BenchNetwork {
    $alias = Get-AdapterAlias
    if (-not $alias) { return $false }
    if (Test-BenchNetwork $alias) { return $true }
    Warn "La scheda $alias non ha gli indirizzi per lavorare con il FRITZ!Box (192.168.178.2 e 192.168.1.2, senza gateway)."
    if (-not (Read-YesNo 'La configuro adesso? La configurazione attuale viene salvata e si ripristina dal menu Rete del PC' $true)) { return $false }
    Set-BenchNetwork $alias
    Start-Sleep -Seconds 2
    return $true
}

# ============================== CONNECTIONS ==============================
function Test-Port([string]$ip, [int]$port, [int]$ms = 500) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($ip, $port, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne($ms) -and $c.Connected) { $c.EndConnect($ar); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}
function Wait-Port([string]$ip, [int]$port, [int]$seconds, [switch]$Closed) {
    # waits until the port is open (or closed with -Closed); Esc cancels
    $end = (Get-Date).AddSeconds($seconds); $n = 0
    while ((Get-Date) -lt $end) {
        $open = Test-Port $ip $port 500
        if ($open -ne [bool]$Closed) { Write-Host ''; return $true }
        try { if ([Console]::KeyAvailable -and [Console]::ReadKey($true).Key -eq 'Escape') { Write-Host ''; return $false } } catch { }
        if ($n % 10 -eq 0) { Write-Host '.' -NoNewline }
        $n++
        Start-Sleep -Milliseconds 200
    }
    Write-Host ''
    return $false
}

function Quote-Sh([string]$s) { return "'" + ($s -replace "'", "'\''") + "'" }
function Join-Args([string[]]$a) { return ($a | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ' }

function Invoke-Box([string]$Command = 'sh -s', [string]$Script = $null, [string]$InputFile = $null, [switch]$Capture, [switch]$Batch) {
    # runs a command on the box over SSH; the script or file goes to its standard input
    $a = @('-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL', '-o', 'ConnectTimeout=8',
           '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3', '-o', 'LogLevel=ERROR')
    if ($Batch) { $a += @('-o', 'BatchMode=yes') }
    if (Test-Path $KeyPath) { $a += @('-i', $KeyPath) }
    $a += @("root@$($Settings.BoxIp)", $Command)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $SshExe
    $psi.Arguments = Join-Args $a
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = [bool]$Capture
    $psi.RedirectStandardError = [bool]$Capture
    if ($Capture) { $psi.StandardOutputEncoding = [Text.Encoding]::UTF8; $psi.StandardErrorEncoding = [Text.Encoding]::UTF8 }
    $p = [Diagnostics.Process]::Start($psi)
    $so = $null; $se = $null
    if ($Capture) { $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync() }
    $in = $p.StandardInput.BaseStream
    try {
        if ($InputFile) { $fs = [IO.File]::OpenRead($InputFile); try { $fs.CopyTo($in) } finally { $fs.Close() } }
        elseif ($Script) { $b = (New-Object Text.UTF8Encoding($false)).GetBytes(($Script -replace "`r`n", "`n")); $in.Write($b, 0, $b.Length) }
    } catch { } finally { try { $in.Close() } catch { } }
    $p.WaitForExit()
    $r = @{ Code = $p.ExitCode; Out = ''; Err = '' }
    if ($Capture) { $r.Out = $so.Result; $r.Err = $se.Result }
    return $r
}

function Get-SshPublicKey {
    if (-not (Test-Path $KeyPath)) {
        New-Dir (Split-Path $KeyPath) | Out-Null
        & $SshKeygen -q -t ed25519 -N '""' -C "box7490@$env:COMPUTERNAME" -f $KeyPath | Out-Null
        if (-not (Test-Path "$KeyPath.pub")) { throw 'Creazione della chiave SSH non riuscita.' }
        Ok "nuova chiave SSH del programma: $KeyPath"
    }
    return ([IO.File]::ReadAllText("$KeyPath.pub")).Trim()
}

# ============================== BOX ==============================
$InfoScript = @'
echo "board=$(cat /tmp/sysinfo/board_name 2>/dev/null)"
echo "model=$(cat /tmp/sysinfo/model 2>/dev/null)"
echo "rootfs=$(ubus call system board 2>/dev/null | jsonfilter -e '@.rootfs_type' 2>/dev/null)"
. /etc/openwrt_release 2>/dev/null; echo "version=$DISTRIB_RELEASE"
echo "hostname=$(uci -q get system.@system[0].hostname)"
echo "mac=$(cat /sys/class/net/br-lan/address 2>/dev/null)"
echo "nand=$(dmesg | grep -m1 'nand: device found')"
echo "chip=$(dmesg | grep -m1 -E 'nand: [A-Z][A-Za-z]+ [A-Z0-9]+$' | sed 's/.*nand: //')"
dmesg | grep -iE 'bad eraseblock|ecc (error|fail)|bitflip|uncorrectable|ubi error|ubifs error|mtd.*error' | grep -v 'no valid UBI magic' | sed 's/^/issue=/'
dmesg | grep -i 'no valid UBI magic' | head -n 1 | sed 's/^/ubinote=/'
'@

function Get-BoxInfo([switch]$Quiet) {
    if (-not (Test-Port $Settings.BoxIp 22 1500)) {
        if (-not $Quiet) { Warn "Nessun box OpenWrt risponde in SSH su $($Settings.BoxIp)." }
        return $null
    }
    $r = Invoke-Box -Script $InfoScript -Capture -Batch
    if (-not $r.Out) {
        if (-not $Quiet) { Warn "Il box non ha risposto ai comandi: $($r.Err.Trim())" }
        return $null
    }
    $i = @{ Issues = @() }
    foreach ($l in ($r.Out -split "`n")) {
        if ($l -match '^(\w+)=(.*)$') {
            if ($matches[1] -eq 'issue') { $i.Issues += $matches[2].Trim() } else { $i[$matches[1]] = $matches[2].Trim() }
        }
    }
    $i.MfrId = ''
    if ($i.nand -match 'Manufacturer ID: (0x[0-9a-fA-F]+)') { $i.MfrId = $matches[1].ToLower() }
    $i.Micron = ($i.MfrId -eq '0x2c')
    $i.NandVariant = ''
    if ($i.MfrId) { if ($i.Micron) { $i.NandVariant = 'micron' } else { $i.NandVariant = 'standard' } }
    $i.BoardVariant = ''
    if ($i.board -match 'fritz7490-micron') { $i.BoardVariant = 'micron' } elseif ($i.board -match 'fritz7490') { $i.BoardVariant = 'standard' }
    return $i
}

function Get-VariantName([string]$v) { if ($v -eq 'micron') { return 'Micron' } elseif ($v -eq 'standard') { return 'non Micron' } else { return 'sconosciuta' } }

function Show-BoxInfo($i) {
    $where = 'installato sulla flash'
    if ($i.rootfs -eq 'initramfs') { $where = 'in RAM (si perde spegnendo il box)' }
    Say "Modello:  $($i.model)"
    Say "OpenWrt:  $($i.version), $where"
    if ($i.MfrId) { Say "NAND:     $($i.chip) (ID $($i.MfrId), immagine $(Get-VariantName $i.NandVariant))" }
    else { Say 'NAND:     le righe del rilevamento non sono più nel dmesg (box acceso da tempo)' }
    Say "Variante in esecuzione: $(Get-VariantName $i.BoardVariant)"
    if ($i.ubinote) { Say 'UBI:      "no valid UBI magic" (normale se nel NAND c''è ancora FRITZ!OS)' }
    if ($i.Issues.Count) {
        Fail 'Nel dmesg ci sono segnali di problemi sul NAND:'
        foreach ($x in $i.Issues) { Write-Host "       $x" -ForegroundColor Red }
    } else {
        Ok 'dmesg: nessun bad block, errore ECC, bitflip o errore UBI'
    }
}

function Select-Variant {
    $items = @(
        (Item 'unknown' 'Non lo so' 'Avvio con l''immagine non Micron e leggo il NAND dal dmesg. Per installare sulla flash, se serve, ti farò riavviare con la variante giusta.')
        (Item 'micron' 'NAND Micron' 'Il produttore letto nei dati di supporto di FRITZ!OS ("NAND device") è Micron, ID 0x2c.')
        (Item 'standard' 'NAND non Micron' 'Toshiba, Hynix, Samsung, Macronix o altri produttori.')
        (Item 'exit' 'Annulla' 'Torna al menu.')
    )
    $start = 0
    if ($Settings.LastVariant -eq 'micron') { $start = 1 } elseif ($Settings.LastVariant -eq 'standard') { $start = 2 }
    $k = Select-One 'Che NAND ha questo FRITZ!Box?' $items $start
    if ($k -eq 'exit') { return $null }
    if ($k -eq 'unknown') { return 'standard' }
    return $k
}

function Start-RamBoot([string]$variant) {
    if (-not $variant) { $variant = Select-Variant }
    if (-not $variant) { return $null }
    if (-not (Confirm-BenchNetwork)) { return $null }
    $img = Get-OfficialImage $variant 'initramfs-kernel'
    $py = Get-PythonExe
    $eva = Get-EvaScript
    Step "Avvio in RAM (immagine $(Get-VariantName $variant))"
    if (Test-Port $EvaIp 21 800) {
        Warn "Su $EvaIp risponde ancora un server FTP (FRITZ!OS): spegni il FRITZ!Box."
        Write-Host '  Aspetto che si spenga (Esc per annullare)' -NoNewline
        if (-not (Wait-Port $EvaIp 21 600 -Closed)) { Fail 'Annullato.'; return $null }
    }
    Write-Host ''
    Write-Host '  Ora SPEGNI il FRITZ!Box, aspetta 5 secondi e RIACCENDILO.' -ForegroundColor Yellow
    Write-Host '  Aspetto il bootloader EVA (Esc per annullare)' -NoNewline
    if (-not (Wait-Port $EvaIp 21 900)) { Fail 'EVA non ha risposto, oppure hai annullato.'; return $null }
    Ok 'EVA ha risposto: carico l''immagine in RAM (il NAND non viene scritto)'
    & $py -I $eva $EvaIp $img
    if ($LASTEXITCODE -ne 0) { Fail "eva_ramboot.py ha restituito ${LASTEXITCODE}: spegni e riaccendi il box e riprova."; return $null }
    $Settings.BoxIp = $RamIp; Save-Settings
    Write-Host '  Aspetto che OpenWrt risponda su 192.168.1.1 (1-2 minuti)' -NoNewline
    if (-not (Wait-Port $RamIp 22 360)) { Fail 'OpenWrt non risponde in SSH.'; return $null }
    Start-Sleep -Seconds 3
    $i = Get-BoxInfo
    if (-not $i) { return $null }
    Step 'OpenWrt è partito in RAM'
    Show-BoxInfo $i
    if ($i.NandVariant) { $Settings.LastVariant = $i.NandVariant; Save-Settings }
    if ($i.NandVariant -and $i.BoardVariant -and $i.NandVariant -ne $i.BoardVariant) {
        Warn "Il NAND vuole l'immagine $(Get-VariantName $i.NandVariant): per provare va bene, per installare sulla flash riavvierò con quella."
    }
    return $i
}

# ============================== ACTIONS ==============================
function Invoke-RamBoot {
    $i = Start-RamBoot $null
    if ($i -and (Read-YesNo 'Apro LuCI nel browser? (utente root, password vuota)' $false)) { Start-Process "http://$RamIp/" }
}

function Install-Flash {
    $items = @(
        (Item 'base' 'Immagine base' 'L''immagine ufficiale di downloads.openwrt.org, come quella provata in RAM. I pacchetti si aggiungono dopo, con internet sul box.')
        (Item 'trap' 'Immagine per la trappola' 'Costruita dal servizio ufficiale sysupgrade.openwrt.org con WireGuard già dentro, per collegarsi al ricevitore anche senza internet al momento della configurazione.')
        (Item 'probe' 'Immagine per la sonda' 'Costruita dal servizio ufficiale con WireGuard, agente Zabbix, Prometheus node exporter, iperf3, tcpdump e mtr già dentro.')
        (Item 'exit' 'Annulla' 'Torna al menu.')
    )
    $kind = Select-One 'Quale immagine vuoi installare sulla flash?' $items 0
    if ($kind -eq 'exit') { return }

    Step 'Controllo del box'
    $i = Get-BoxInfo -Quiet
    if (-not $i -or $i.rootfs -ne 'initramfs') {
        Say 'Per installare, OpenWrt deve prima partire in RAM.'
        $i = Start-RamBoot $null
        if (-not $i) { return }
    } else { Show-BoxInfo $i }
    if (-not $i.MfrId) { Fail 'Non riesco a leggere il produttore del NAND dal dmesg: mi fermo.'; return }
    if ($i.BoardVariant -ne $i.NandVariant) {
        Warn "Il NAND vuole l'immagine $(Get-VariantName $i.NandVariant), ma in RAM gira la variante $(Get-VariantName $i.BoardVariant)."
        Say 'Per scrivere la flash serve la variante giusta: riavvio in RAM con quella.'
        $i = Start-RamBoot $i.NandVariant
        if (-not $i) { return }
        if ($i.BoardVariant -ne $i.NandVariant) { Fail 'La variante è ancora diversa: mi fermo.'; return }
    }
    if ($i.Issues.Count) { Fail 'Ci sono segnali di problemi sul NAND: non scrivo la flash.'; return }
    if ($i.Micron) {
        Write-Host ''
        Warn 'Questo FRITZ!Box ha un NAND Micron.'
        Say 'Sui NAND Micron sono stati segnalati errori con alcune versioni di OpenWrt. Se la scrittura va'
        Say 'male, il box si recupera dal bootloader EVA, ma potresti dover rimettere FRITZ!OS a mano.'
        Say 'La regola di prudenza è fare il primo flash su un 7490 non Micron.'
        if (-not (Read-Phrase 'ACCETTO IL RISCHIO')) { Say 'Installazione annullata: il box resta com''era.'; return }
    }

    switch ($kind) {
        'base'  { $img = Get-OfficialImage $i.NandVariant 'squashfs-sysupgrade' }
        'trap'  { $img = Get-AsuImage $i.NandVariant $ImagePackages.trap 'trappola' }
        'probe' { $img = Get-AsuImage $i.NandVariant $ImagePackages.probe 'sonda' }
    }

    Step 'Copio l''immagine nel box'
    $r = Invoke-Box -Command 'cat > /tmp/openwrt.bin' -InputFile $img -Batch
    if ($r.Code -ne 0) { Fail 'Copia non riuscita.'; return }
    $local = Get-Sha256 $img
    $r = Invoke-Box -Command 'sha256sum /tmp/openwrt.bin; sysupgrade -T /tmp/openwrt.bin >/dev/null 2>&1 && echo IMMAGINE_VALIDA' -Capture -Batch
    if ($r.Out -notmatch [regex]::Escape($local)) { Fail 'L''immagine nel box non ha lo stesso SHA256 del file scaricato: mi fermo.'; return }
    Ok "SHA256 nel box uguale al file ($($local.Substring(0, 16))...)"
    if ($r.Out -notmatch 'IMMAGINE_VALIDA') { Fail 'sysupgrade -T dice che l''immagine non va bene per questo box: mi fermo.'; return }
    Ok 'sysupgrade -T: immagine valida per questo box'

    Write-Host ''
    Warn 'Ultimo passo: sysupgrade -n sostituisce FRITZ!OS con OpenWrt. Non spegnere il box durante la scrittura.'
    if (-not (Read-Phrase 'INSTALLA')) { Say 'Installazione annullata: il box resta in RAM e il NAND non è stato toccato.'; return }
    Step 'Scrittura della flash'
    [void](Invoke-Box -Command 'sysupgrade -n /tmp/openwrt.bin' -Batch)
    Write-Host '  Il box si riavvia (il LED Info lampeggia). Aspetto che si spenga' -NoNewline
    [void](Wait-Port $RamIp 22 120 -Closed)
    Write-Host '  Aspetto OpenWrt installato su 192.168.1.1 (fino a 8 minuti)' -NoNewline
    if (-not (Wait-Port $RamIp 22 480)) { Fail 'Il box non risponde ancora: controlla i LED e riprova con Stato del box tra qualche minuto.'; return }
    Start-Sleep -Seconds 5
    $i = Get-BoxInfo
    if ($i) {
        Show-BoxInfo $i
        if ($i.rootfs -ne 'initramfs') { Ok 'OpenWrt è installato sulla flash.'; Say 'Ora configura il box come trappola o come sonda.' }
        else { Warn 'Il box risponde ma gira ancora in RAM: l''installazione non sembra riuscita.' }
    }
}

function Get-LocalIpFor([string]$boxIp) {
    try {
        $route = Find-NetRoute -RemoteIPAddress $boxIp -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($route) { return "$($route.IPAddress)" }
    } catch { }
    return ''
}

function Connect-Box {
    # returns the box info, after offering the bench addresses when the box is not reachable on 192.168.1.1
    if (-not (Test-Port $Settings.BoxIp 22 1500) -and $Settings.BoxIp -eq $RamIp) {
        if (-not (Confirm-BenchNetwork)) { return $null }
    }
    $i = Get-BoxInfo
    if (-not $i) { Say 'Avvia OpenWrt in RAM o installalo, oppure correggi l''IP del box in Impostazioni.' }
    return $i
}

# ============================== CONFIGURATION ==============================
# values already on the box, read only when the box was configured by this tool
$CurrentScript = @'
if uci -q get firewall.box_lan_dhcp >/dev/null; then
	echo "LAN_MODE=$(uci -q get network.lan.proto)"
	echo "LAN_IP=$(uci -q get network.lan.ipaddr)"
	echo "LAN_GW=$(uci -q get network.lan.gateway)"
	echo "LAN_DNS=$(uci -q get network.lan.dns)"
	echo "MGMT_IPS=$(uci -q get firewall.box_lan_ssh.src_ip)"
	echo "NTP_SERVERS=$(uci -q get system.ntp.server)"
	echo "KEEP_LUCI=$(/etc/init.d/uhttpd enabled 2>/dev/null && echo 1 || echo 0)"
fi
echo "WG_ADDRESS=$(uci -q get network.mgmt.addresses)"
if [ -f /etc/nftables.d/10-lantrap.nft ]; then
	echo "TRAP_EXCLUDE=$(tr '\n\t' '  ' < /etc/nftables.d/10-lantrap.nft | sed -n 's/^.*set lantrap_exclude {[^}]*elements = { \([^}]*\) }.*$/\1/p' | tr -d ',')"
fi
true
'@

# answers about our side (receiver, WireGuard server, monitoring) reused as defaults next time
$RememberKeys = @('NTP_SERVERS', 'EXTRA_KEY_FILE', 'TRAP_PORTS', 'TRAP_RATE', 'LOG_IP', 'LOG_PORT', 'LOG_PROTO',
                  'WG_ENDPOINT_HOST', 'WG_ENDPOINT_PORT', 'WG_SERVER_PUBKEY', 'WG_ALLOWED', 'WG_KEEPALIVE',
                  'VPN_TO_LAN', 'MONITOR', 'ZABBIX_SERVER')

$Labels = @{
    HOSTNAME_BOX = 'Nome del box'; LAN_MODE = 'Indirizzo LAN'; LAN_IP = 'IP del box'; LAN_PREFIX = 'Prefisso'
    LAN_GW = 'Gateway'; LAN_DNS = 'DNS'; MGMT_IPS = 'SSH dalla LAN da'; ROOT_PW = 'Password di root'
    SSH_PUBKEY = 'Chiavi SSH'; EXTRA_KEY_FILE = 'Altra chiave da'; KEEP_LUCI = 'LuCI acceso'; NTP_SERVERS = 'Server NTP'
    TRAP_PORTS = 'Porte sorvegliate'; TRAP_EXCLUDE = 'Non segnalati'; TRAP_RATE = 'Righe al minuto'
    LOG_IP = 'Ricevitore dei log'; LOG_PORT = 'Porta dei log'; LOG_PROTO = 'Protocollo dei log'
    WG_ENDPOINT_HOST = 'Server WireGuard'; WG_ENDPOINT_PORT = 'Porta UDP'; WG_SERVER_PUBKEY = 'Chiave del server'
    WG_ADDRESS = 'IP nel tunnel'; WG_ALLOWED = 'Reti di gestione'; WG_KEEPALIVE = 'Keepalive (s)'
    VPN_TO_LAN = 'Dal tunnel alla LAN'; MONITOR = 'Monitoraggio'; ZABBIX_SERVER = 'Server Zabbix'
    INSTALL_ONLINE = 'Pacchetti da internet'
}

$MainProfile = @'
profile_check || exit 1
base_prepare || exit 1
profile_apply || exit 1
base_apply
echo CONFIGURAZIONE_APPLICATA
'@

function Get-BoxCurrent {
    $c = @{}
    $r = Invoke-Box -Script $CurrentScript -Capture -Batch
    foreach ($l in ("$($r.Out)" -split "`n")) { if ($l -match '^([A-Z_]+)=(.*)$') { $c[$matches[1]] = $matches[2].Trim() } }
    if ($c.LAN_IP -match '^(.+)/(\d+)$') { $c.LAN_IP = $matches[1]; $c.LAN_PREFIX = $matches[2] }
    if ($c.LAN_MODE -eq 'static') { $c.LAN_MODE = 'fisso' }
    if ($c.WG_ADDRESS) { $c.WG_ADDRESS = @(Split-List $c.WG_ADDRESS)[0] }
    return $c
}

function Get-LastValues([string]$role) {
    $h = @{}
    $f = Join-Path $Dirs.State "ultimi-valori-$role.json"
    if (Test-Path $f) {
        try {
            $j = [IO.File]::ReadAllText($f) | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) { $h[$p.Name] = "$($p.Value)" }
        } catch { }
    }
    return $h
}
function Save-LastValues([string]$role, $values) {
    $keep = [ordered]@{}
    foreach ($k in $RememberKeys) { if ($values.Contains($k)) { $keep[$k] = $values[$k] } }
    [IO.File]::WriteAllText((Join-Path $Dirs.State "ultimi-valori-$role.json"), ($keep | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
}

function Read-CommonSettings([string]$role, $info, $cur, $last) {
    # validators run inside Read-Value: they must not use its variable names ($v, $p, $prompt, $default, $valid)
    $onFlash = ($info.rootfs -ne 'initramfs')
    $v = [ordered]@{}
    Step 'Impostazioni comuni'
    $defHost = 'sonda'; if ($role -eq 'trap') { $defHost = 'trappola' }
    if ($info.hostname -and $info.hostname -ne 'OpenWrt') { $defHost = $info.hostname }
    $v.HOSTNAME_BOX = Read-Value 'Nome del box (codice cliente o sede: lettere, numeri e trattini)' $defHost { param($x) Test-Hostname $x }

    $defMode = 'fisso'; if ($cur.LAN_MODE -eq 'dhcp') { $defMode = 'dhcp' }
    $mode = Read-Value 'Indirizzo del box nella LAN del cliente: fisso o dhcp' $defMode { param($x) $x -in @('fisso', 'dhcp') }
    $v.LAN_MODE = 'dhcp'; $v.LAN_IP = ''; $v.LAN_PREFIX = ''; $v.LAN_GW = ''; $v.LAN_DNS = ''
    if ($mode -eq 'fisso') {
        $v.LAN_MODE = 'static'
        $v.LAN_IP = Read-Value 'IP del box nella LAN' $cur.LAN_IP { param($x) Test-Ipv4 $x }
        $v.LAN_PREFIX = Read-Value 'Lunghezza del prefisso (24 = 255.255.255.0)' (Pick $cur.LAN_PREFIX '24') { param($x) ($x -match '^\d{1,2}$') -and ([int]$x -ge 8) -and ([int]$x -le 30) }
        $lanIp = $v.LAN_IP; $lanPrefix = [int]$v.LAN_PREFIX
        $gwText = 'Gateway della LAN, nella stessa rete del box (- = nessuno)'
        if ($role -eq 'probe') { $gwText = 'Gateway della LAN (serve alla sonda per raggiungere il server WireGuard)' }
        $v.LAN_GW = Read-Value $gwText $cur.LAN_GW { param($x) (Test-Ipv4 $x) -and ($x -ne $lanIp) -and (Test-SameSubnet $x $lanIp $lanPrefix) } -AllowEmpty:($role -ne 'probe')
        $v.LAN_DNS = Join-List (Read-Value 'Server DNS, separati da spazio (- = nessuno)' (Pick $cur.LAN_DNS $v.LAN_GW) { param($x) Test-Ipv4List $x } -AllowEmpty)
    } elseif (-not $onFlash) {
        Warn 'Con il DHCP, in RAM sul banco il box non prende un indirizzo e non si raggiunge più fino allo spegnimento.'
    }

    $mgmtDef = $cur.MGMT_IPS
    if (-not $mgmtDef -and -not $onFlash) { $mgmtDef = Get-LocalIpFor $Settings.BoxIp }
    $v.MGMT_IPS = Join-List (Read-Value 'IP o reti della LAN che possono entrare in SSH, separati da spazio (- = nessuno)' $mgmtDef { param($x) Test-IpList $x } -AllowEmpty)
    if (-not $v.MGMT_IPS -and $role -eq 'trap') { Warn 'Senza IP di gestione, nella trappola si entra solo con il failsafe di OpenWrt.' }

    if ($onFlash) { Say 'OpenWrt è installato sulla flash: serve una password di root di almeno 8 caratteri.' }
    $v.ROOT_PW = Read-Password $onFlash

    $keys = @(Get-SshPublicKey)
    $extraFile = Read-Value 'File .pub di un''altra chiave SSH da autorizzare (- = nessuna)' $last.EXTRA_KEY_FILE { param($x) @(Get-PubKeys ($x.Trim('"'))).Count -gt 0 } -AllowEmpty
    $v.EXTRA_KEY_FILE = $extraFile.Trim('"')
    if ($v.EXTRA_KEY_FILE) { $keys += Get-PubKeys $v.EXTRA_KEY_FILE }
    $v.SSH_PUBKEY = (@($keys | Select-Object -Unique)) -join "`n"

    $v.KEEP_LUCI = '0'
    if ($role -eq 'probe' -and (Read-YesNo 'Lascio acceso LuCI? Si raggiunge solo dal tunnel di gestione' ($cur.KEEP_LUCI -eq '1'))) { $v.KEEP_LUCI = '1' }

    $v.NTP_SERVERS = Join-List (Read-Value 'Server NTP, separati da spazio (- = quelli predefiniti di OpenWrt)' (Pick $cur.NTP_SERVERS $last.NTP_SERVERS) { param($x) Test-HostList $x } -AllowEmpty)
    if ($v.LAN_MODE -eq 'static' -and -not $v.LAN_GW -and -not $v.NTP_SERVERS) {
        Warn 'Senza gateway e senza un server NTP nella LAN, l''ora del box resta sbagliata e con lei gli orari dei log.'
    }
    return $v
}

function Read-LogSettings($v, $last, [string]$role) {
    $text = 'IP del ricevitore dei log (LAN Trap Receiver o altro syslog; - = log solo nel box)'
    if ($role -eq 'probe') { $text = 'IP del server syslog che riceve il log del box (- = log solo nel box)' }
    $v.LOG_IP = Read-Value $text $last.LOG_IP { param($x) Test-Ipv4 $x } -AllowEmpty
    $v.LOG_PORT = ''; $v.LOG_PROTO = ''
    if ($v.LOG_IP) {
        $v.LOG_PORT = Read-Value 'Porta del ricevitore dei log' (Pick $last.LOG_PORT '5514') { param($x) Test-PortNumber $x }
        $v.LOG_PROTO = (Read-Value 'Protocollo dei log: udp o tcp' (Pick $last.LOG_PROTO 'udp') { param($x) $x -in @('udp', 'tcp') }).ToLower()
    }
}

function Read-TrapSettings($v, $cur, $last) {
    Step 'Trappola'
    $v.TRAP_PORTS = Join-List (Read-Value 'Porte TCP da sorvegliare, separate da spazio (non la 22)' (Pick $last.TRAP_PORTS $TrapPorts) { param($x) Test-TrapPorts $x })
    $v.TRAP_EXCLUDE = Join-List (Read-Value 'IP o reti da non segnalare, per esempio scanner o monitoraggio (- = nessuno)' $cur.TRAP_EXCLUDE { param($x) Test-IpList $x } -AllowEmpty)
    $v.TRAP_RATE = Read-Value 'Righe di log al massimo al minuto' (Pick $last.TRAP_RATE '60') { param($x) ($x -match '^\d{1,4}$') -and ([int]$x -ge 1) }
    Read-LogSettings $v $last 'trap'
}

function Read-ProbeSettings($v, $cur, $last) {
    Step 'Tunnel WireGuard di gestione'
    $v.WG_ENDPOINT_HOST = Read-Value 'Indirizzo pubblico del server WireGuard (nome o IP)' $last.WG_ENDPOINT_HOST { param($x) (Test-Ipv4 $x) -or (Test-DnsName $x) }
    $v.WG_ENDPOINT_PORT = Read-Value 'Porta UDP del server WireGuard' (Pick $last.WG_ENDPOINT_PORT '51820') { param($x) Test-PortNumber $x }
    $v.WG_SERVER_PUBKEY = Read-Value 'Chiave pubblica del server WireGuard' $last.WG_SERVER_PUBKEY { param($x) Test-WgKey $x }
    $v.WG_ADDRESS = Read-Value 'IP del box nel tunnel, con prefisso (per esempio 10.99.0.20/32)' $cur.WG_ADDRESS { param($x) ($x -match '/') -and (Test-Cidr4 $x) }
    $v.WG_ALLOWED = Join-List (Read-Value 'Reti di gestione raggiungibili dal tunnel, separate da spazio (per esempio 10.99.0.0/24)' $last.WG_ALLOWED { param($x) Test-IpList $x })
    $v.WG_KEEPALIVE = Read-Value 'Keepalive in secondi (0 = spento)' (Pick $last.WG_KEEPALIVE '25') { param($x) $x -match '^\d{1,3}$' }
    $v.VPN_TO_LAN = '0'
    if (Read-YesNo 'Dal tunnel si raggiunge anche la LAN del cliente (con NAT)?' ($last.VPN_TO_LAN -eq '1')) { $v.VPN_TO_LAN = '1' }

    Step 'Monitoraggio'
    $v.MONITOR = (Read-Value 'Agente: zabbix, prometheus o nessuno' (Pick $last.MONITOR 'nessuno') { param($x) $x -in @('zabbix', 'prometheus', 'nessuno') }).ToLower()
    $v.ZABBIX_SERVER = ''
    if ($v.MONITOR -eq 'zabbix') {
        $v.ZABBIX_SERVER = Read-Value 'IP o nome del server (o proxy) Zabbix, raggiungibile dal tunnel' $last.ZABBIX_SERVER { param($x) (Test-Ipv4 $x) -or (Test-DnsName $x) }
    }
    Read-LogSettings $v $last 'probe'
    $v.INSTALL_ONLINE = '0'
    if (Read-YesNo 'Se mancano pacchetti della sonda li installo da internet? Serve internet sul box adesso' $false) { $v.INSTALL_ONLINE = '1' }
}

function Read-ReceiverScript {
    Step 'Script del LAN Trap Receiver'
    Say 'Sul ricevitore si crea con: lantrap openwrt <trappola> -o trappola.sh'
    $path = Read-Value 'Percorso dello script (si può trascinare qui il file; - = annulla)' '' { param($x) Test-Path -LiteralPath ($x.Trim('"')) -PathType Leaf } -AllowEmpty
    if (-not $path) { return $null }
    $text = [IO.File]::ReadAllText($path.Trim('"'))
    if ($text -notmatch 'LAN Trap Receiver' -or $text -notmatch '/etc/nftables\.d/10-lantrap\.nft') { Fail 'Il file non sembra uno script del LAN Trap Receiver.'; return $null }
    if ($text -match '(?m)^LANTRAP_RICEVITORE_FINE\s*$') { Fail 'Il file contiene la riga che il programma usa come terminatore: non lo invio.'; return $null }
    $head = @($text -split "`n" | Where-Object { $_ -match '^# LAN Trap Receiver' })[0]
    if ($head) { Ok $head.Trim().TrimStart('#').Trim() }
    if ($text -match 'proto=.wireguard') { Say 'Lo script configura anche il tunnel WireGuard verso il ricevitore e alla fine stampa il blocco [Peer].' }
    return $text
}

function Get-ReceiverMain([string]$text) {
    # the receiver script runs first: if it stops, the base configuration is not touched
    $body = ($text -replace "`r`n", "`n").TrimEnd("`n")
    return @"
cat > /tmp/lantrap-ricevitore.sh <<'LANTRAP_RICEVITORE_FINE'
$body
LANTRAP_RICEVITORE_FINE
say "Script del LAN Trap Receiver"
if ! sh /tmp/lantrap-ricevitore.sh; then
	rm -f /tmp/lantrap-ricevitore.sh
	echo "Lo script del ricevitore si è fermato: la configurazione di base non è stata toccata" >&2
	exit 1
fi
rm -f /tmp/lantrap-ricevitore.sh
base_prepare || exit 1
base_apply
echo CONFIGURAZIONE_APPLICATA
"@
}

function Get-ProfileText([string]$name) {
    $path = Join-Path $Dirs.Profiles $name
    if (-not (Test-Path $path)) { throw "Manca il profilo $path." }
    return [IO.File]::ReadAllText($path)
}
function New-BoxScript($vars, [string[]]$profiles, [string]$main) {
    # shell variables first, then the profile functions, then the commands that call them
    $sb = New-Object Text.StringBuilder
    foreach ($k in $vars.Keys) { [void]$sb.Append($k).Append('=').Append((Quote-Sh ([string]$vars[$k]))).Append("`n") }
    foreach ($p in $profiles) { [void]$sb.Append((Get-ProfileText $p)).Append("`n") }
    [void]$sb.Append($main).Append("`n")
    return $sb.ToString()
}

function Show-Summary($v) {
    Step 'Riepilogo'
    foreach ($k in $v.Keys) {
        $val = [string]$v[$k]
        switch ($k) {
            'ROOT_PW' { if ($val) { $val = 'nuova (non mostrata)' } else { $val = 'invariata' } }
            'SSH_PUBKEY' { $val = @($val -split "`n" | ForEach-Object { $f = $_ -split ' '; if ($f.Count -ge 3) { $f[2] } else { $f[0] } }) -join ', ' }
            'LAN_MODE' { if ($val -eq 'dhcp') { $val = 'DHCP del cliente' } else { $val = 'fisso' } }
            { $_ -in @('KEEP_LUCI', 'VPN_TO_LAN', 'INSTALL_ONLINE') } { if ($val -eq '1') { $val = 'sì' } else { $val = 'no' } }
        }
        if (-not $val) { continue }
        $label = $Labels[$k]; if (-not $label) { $label = $k }
        Write-Host ('  {0,-22} {1}' -f $label, $val)
    }
}

function Invoke-BoxProfile([string]$role, $v, [string]$script) {
    Step 'Configurazione del box'
    Say 'Invio la configurazione (se installa pacchetti da internet può volerci qualche minuto)...'
    $r = Invoke-Box -Script $script -Capture -Batch
    $out = "$($r.Out)".TrimEnd()
    $err = "$($r.Err)".TrimEnd()
    foreach ($l in ($out -split "`n")) { if ($l.Trim() -and $l.Trim() -ne 'CONFIGURAZIONE_APPLICATA') { Write-Host "  $($l.TrimEnd())" } }
    if ($err) { foreach ($l in ($err -split "`n")) { Write-Host "  $($l.TrimEnd())" -ForegroundColor Red } }
    $file = Join-Path $Dirs.Log ('{0}-{1}-{2}.txt' -f $v.HOSTNAME_BOX, $role, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [IO.File]::WriteAllText($file, (($out + "`n" + $err).Trim() -replace "`r?`n", "`r`n"), (New-Object Text.UTF8Encoding($false)))
    Write-Host ''
    if ($r.Code -eq 0 -and $out -match 'CONFIGURAZIONE_APPLICATA') { Ok "configurazione applicata, output salvato in $file"; return $true }
    Fail "Configurazione non riuscita (codice $($r.Code)), output salvato in $file"
    if ($err -match 'Permission denied') { Say 'Il box ha già una password o chiavi diverse: questo PC non ha accesso.' }
    return $false
}

function Show-AfterConfigure($info, $v) {
    Write-Host ''
    if ($info.rootfs -eq 'initramfs') { Warn 'Il box è in RAM: applica la configurazione tra 3 secondi, ma spegnendolo si perde tutto.' }
    else { Say 'Il box si riavvia tra 5 secondi per applicare la configurazione.' }
    if ($v.LAN_MODE -ne 'static') {
        Warn 'Il box prenderà l''indirizzo dal DHCP del cliente: quando lo conosci, impostalo in Impostazioni > IP del box.'
        return
    }
    $newIp = $v.LAN_IP; $prefix = [int]$v.LAN_PREFIX
    if ($newIp -ne $Settings.BoxIp) { $Settings.BoxIp = $newIp; Save-Settings; Say "D'ora in poi il programma cerca il box su $newIp." }
    $near = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne $newIp -and (Test-SameSubnet $_.IPAddress $newIp $prefix) })
    if (-not $near) { Say "Questo PC non ha indirizzi nella rete $newIp/${prefix}: da qui il box non si raggiunge, ed è normale se va dal cliente." }
    elseif ($v.MGMT_IPS) { Say "In SSH dalla LAN entrano solo: $($v.MGMT_IPS)" }
    else { Warn 'Nessun IP di gestione: il box non accetta più SSH da questo PC.' }
}

function Invoke-Configure([string]$role) {
    $receiver = $null
    if ($role -eq 'trap') {
        $items = @(
            (Item 'builtin' 'Trappola integrata' 'Porte, eccezioni e ricevitore dei log si scelgono qui. Regola, prefisso LANTRAP e segnale di vita sono quelli del LAN Trap Receiver: il box si collega al ricevitore anche in seguito.')
            (Item 'receiver' 'Script del ricevitore' 'Usa lo script scritto da "lantrap openwrt <trappola>": porte, eccezioni, log remoto e tunnel WireGuard vengono dalla configurazione del ricevitore.')
            (Item 'exit' 'Annulla' 'Torna al menu.')
        )
        $kind = Select-One 'Come configuro la trappola?' $items 0
        if ($kind -eq 'exit') { return }
        if ($kind -eq 'receiver') { $receiver = Read-ReceiverScript; if (-not $receiver) { return } }
    }
    Step 'Controllo del box'
    $i = Connect-Box
    if (-not $i) { return }
    Show-BoxInfo $i
    $cur = Get-BoxCurrent
    $last = Get-LastValues $role
    $v = Read-CommonSettings $role $i $cur $last
    if ($role -eq 'probe') { Read-ProbeSettings $v $cur $last }
    elseif (-not $receiver) { Read-TrapSettings $v $cur $last }
    Show-Summary $v
    Write-Host ''
    if (-not (Read-YesNo 'Applico questa configurazione al box?' $true)) { Say 'Nessuna modifica al box.'; return }
    if ($role -eq 'probe') { $script = New-BoxScript $v @('base-lan.sh', 'sonda.sh') $MainProfile }
    elseif ($receiver) { $script = New-BoxScript $v @('base-lan.sh') (Get-ReceiverMain $receiver) }
    else { $script = New-BoxScript $v @('base-lan.sh', 'trappola.sh') $MainProfile }
    if (-not (Invoke-BoxProfile $role $v $script)) { return }
    Save-LastValues $role $v
    Show-AfterConfigure $i $v
}

# ============================== STATUS AND TOOLS ==============================
$StatusScript = @'
now=$(date +%s)
echo "date=$(date '+%Y-%m-%d %H:%M:%S')"
echo "year=$(date +%Y)"
echo "uptime=$(cut -d. -f1 /proc/uptime)"
echo "lanproto=$(uci -q get network.lan.proto)"
echo "lanip=$(ip -4 -o addr show dev br-lan 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
echo "gw=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
echo "luci=$(/etc/init.d/uhttpd enabled 2>/dev/null && echo 1 || echo 0)"
echo "logip=$(uci -q get system.@system[0].log_ip)"
echo "logport=$(uci -q get system.@system[0].log_port)"
echo "logproto=$(uci -q get system.@system[0].log_proto)"
if [ -f /etc/nftables.d/10-lantrap.nft ]; then
	if nft list chain inet fw4 lantrap >/dev/null 2>&1; then echo "trap=attiva"; else echo "trap=nel file ma non caricata nel firewall"; fi
	echo "trapports=$(tr '\n\t' '  ' < /etc/nftables.d/10-lantrap.nft | sed -n 's/^.*tcp dport { \([^}]*\) }.*$/\1/p' | tr -d ',')"
	echo "trapexclude=$(nft list set inet fw4 lantrap_exclude 2>/dev/null | tr '\n\t' '  ' | sed -n 's/^.*elements = { \([^}]*\) }.*$/\1/p' | tr -d ',')"
	echo "traphits=$(logread 2>/dev/null | grep -c 'LANTRAP:')"
	echo "heartbeat=$(grep -c 'logger -t lantrap heartbeat' /etc/crontabs/root 2>/dev/null)"
	logread 2>/dev/null | grep 'LANTRAP:' | tail -n 5 | sed 's/^/hit=/'
fi
for n in mgmt lantrap; do
	[ "$(uci -q get network.$n.proto)" = wireguard ] || continue
	hs=$(wg show "$n" latest-handshakes 2>/dev/null | awk '{print $2; exit}')
	if [ -n "$hs" ] && [ "$hs" -gt 0 ]; then echo "wg=$n $((now - hs))"; else echo "wg=$n -1"; fi
done
/etc/init.d/zabbix_agentd running 2>/dev/null && echo "agent=Zabbix"
/etc/init.d/prometheus-node-exporter-lua running 2>/dev/null && echo "agent=Prometheus node exporter"
true
'@

# diagnostic dump: no private keys, passwords or pre-shared keys
$DumpScript = @'
echo "===== /proc/version"; cat /proc/version
echo; echo "===== ubus call system board"; ubus call system board
echo; echo "===== /proc/mtd"; cat /proc/mtd
echo; echo "===== ip addr"; ip addr
echo; echo "===== ip route"; ip route
echo; echo "===== uci show (senza segreti)"; uci show 2>/dev/null | grep -v -iE '(private_key|preshared_key|password|secret|psk|\.key)='
echo; echo "===== dmesg"; dmesg
echo; echo "===== logread"; logread
'@

function Show-Status {
    Step 'Box'
    $i = Connect-Box
    if (-not $i) { return }
    Show-BoxInfo $i
    $r = Invoke-Box -Script $StatusScript -Capture -Batch
    $s = @{}; $hits = @(); $tunnels = @(); $agents = @()
    foreach ($l in ("$($r.Out)" -split "`n")) {
        if ($l -notmatch '^(\w+)=(.*)$') { continue }
        $k = $matches[1]; $val = $matches[2].Trim()
        if ($k -eq 'hit') { $hits += $val } elseif ($k -eq 'wg') { $tunnels += $val } elseif ($k -eq 'agent') { $agents += $val } else { $s[$k] = $val }
    }
    Step 'Rete e servizi'
    $proto = 'fisso'; if ($s.lanproto -eq 'dhcp') { $proto = 'DHCP' }
    Say "Nome:      $($i.hostname)"
    Say "LAN:       $(Pick $s.lanip 'nessun indirizzo') ($proto), gateway $(Pick $s.gw 'nessuno')"
    $up = 0; [void][int]::TryParse("$($s.uptime)", [ref]$up)
    Say ('Acceso da: {0} g {1} h {2} min' -f [Math]::Floor($up / 86400), [Math]::Floor(($up % 86400) / 3600), [Math]::Floor(($up % 3600) / 60))
    $year = 0; [void][int]::TryParse("$($s.year)", [ref]$year)
    if ($year -lt 2020) { Warn "Ora del box: $($s.date), non sincronizzata (NTP non raggiunto): gli orari dei log sono sbagliati." }
    else { Say "Ora:       $($s.date)" }
    $luci = 'spento'; if ($s.luci -eq '1') { $luci = 'acceso' }
    Say "LuCI:      $luci"
    if ($s.logip) { Say "Log:       inviato a $($s.logip):$(Pick $s.logport '514') ($(Pick $s.logproto 'udp'))" }
    else { Say 'Log:       solo nel box' }
    foreach ($t in $tunnels) {
        $name, $age = $t -split ' '
        $sec = [int]$age
        if ($sec -lt 0) { Warn "Tunnel ${name}: nessun handshake. Il [Peer] è sul server? Il box raggiunge l'endpoint?" }
        elseif ($sec -gt 180) { Warn "Tunnel ${name}: ultimo handshake $sec secondi fa" }
        else { Ok "tunnel ${name}: ultimo handshake $sec secondi fa" }
    }
    foreach ($a in $agents) { Ok "agente $a in esecuzione" }
    if ($s.trap) {
        Step 'Trappola'
        Say "Regola:    $($s.trap)"
        Say "Porte:     $($s.trapports)"
        Say "Esclusi:   $(Pick $s.trapexclude 'nessuno')"
        $hb = 'no'; if ("$($s.heartbeat)" -match '^[1-9]') { $hb = 'sì' }
        Say "Segnale di vita nel cron: $hb"
        Say "Righe LANTRAP nel log del box: $(Pick $s.traphits '0')"
        foreach ($h in $hits) { Write-Host "    $h" -ForegroundColor DarkGray }
    }
}

function Open-SshConsole {
    if (-not (Test-Port $Settings.BoxIp 22 1500)) { Warn "Nessun box risponde in SSH su $($Settings.BoxIp)."; return }
    Clear-Host
    Write-Host ''
    Write-Host "  Sessione SSH su root@$($Settings.BoxIp). Per tornare al menu scrivi exit." -ForegroundColor Cyan
    Write-Host ''
    $a = @('-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL', '-o', 'LogLevel=ERROR')
    if (Test-Path $KeyPath) { $a += @('-i', $KeyPath) }
    & $SshExe @a "root@$($Settings.BoxIp)"
}

function Save-BoxLogs {
    $i = Connect-Box
    if (-not $i) { return }
    Step 'Salvo dmesg, log e configurazione'
    $r = Invoke-Box -Script $DumpScript -Capture -Batch
    if (-not $r.Out) { Fail "Il box non ha risposto: $("$($r.Err)".Trim())"; return }
    $file = Join-Path $Dirs.Log ('{0}-diagnosi-{1}.txt' -f (Pick $i.hostname 'box'), (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [IO.File]::WriteAllText($file, ($r.Out -replace "`r?`n", "`r`n"), (New-Object Text.UTF8Encoding($false)))
    Ok "salvato in $file"
    if (Read-YesNo 'Lo apro nel Blocco note?' $false) { Start-Process notepad.exe $file }
}

function Restart-Box {
    $i = Connect-Box
    if (-not $i) { return }
    if ($i.rootfs -eq 'initramfs') { Warn 'OpenWrt gira in RAM: dopo il riavvio parte FRITZ!OS dalla flash e OpenWrt va riavviato in RAM.' }
    if (-not (Read-YesNo "Riavvio il box su $($Settings.BoxIp)?" $false)) { return }
    [void](Invoke-Box -Command 'reboot' -Batch)
    Ok 'comando di riavvio inviato'
}

function Show-Tools {
    $sel = 0
    while ($true) {
        $items = @(
            (Item 'ssh' 'Console SSH' 'Apre una sessione SSH come root sul box in questa finestra. Per tornare qui scrivi exit.' "Box: $($Settings.BoxIp)")
            (Item 'luci' 'LuCI nel browser' 'Apre l''interfaccia web del box. Un antivirus con protezione dagli attacchi di rete può bloccare le pagine che eseguono comandi (cgi-exec).' "http://$($Settings.BoxIp)/")
            (Item 'logs' 'Salva dmesg e log' 'Copia dmesg, logread, /proc/mtd, indirizzi e configurazione (senza chiavi e password) in un file della cartella log.')
            (Item 'reboot' 'Riavvia il box' 'Su flash riparte OpenWrt. In RAM il riavvio cancella OpenWrt e riparte FRITZ!OS.' '' -Warn)
            (Item 'exit' 'Indietro' 'Torna al menu principale.')
        )
        $k = Select-One 'Strumenti' $items $sel
        if ($k -eq 'exit') { return }
        $sel = [Array]::IndexOf(@($items | ForEach-Object { $_.Key }), $k)
        try {
            switch ($k) {
                'ssh' { Open-SshConsole }
                'luci' { Start-Process "http://$($Settings.BoxIp)/" }
                'logs' { Save-BoxLogs }
                'reboot' { Restart-Box }
            }
        } catch { Fail $_.Exception.Message }
        if ($k -ne 'luci') { Wait-Key }
    }
}

# ============================== PC NETWORK AND SETTINGS ==============================
function Get-PcNetworkState {
    $alias = $Settings.Adapter
    if (-not $alias) { return 'Nessuna scheda scelta' }
    if (-not (Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue)) { return "La scheda $alias non esiste più" }
    if (Test-BenchNetwork $alias) { return "$alias ha gli IP di lavoro (senza gateway)" }
    $ips = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }) -join ', '
    return "$alias - $(Pick $ips 'nessun IPv4')"
}

function Show-PcNetwork {
    $sel = 0
    while ($true) {
        $state = Get-PcNetworkState
        $items = @(
            (Item 'bench' 'Imposta IP di lavoro' 'Salva la configurazione della scheda e imposta 192.168.178.2/24 e 192.168.1.2/24 senza gateway: internet continua a passare dal Wi-Fi o da un''altra scheda.' $state)
            (Item 'restore' 'Ripristina la scheda' 'Rimette la configurazione salvata prima. Se non c''è niente di salvato rimette il DHCP.' $state)
            (Item 'adapter' 'Scegli la scheda' 'Cambia la scheda di rete collegata al FRITZ!Box.' $state)
            (Item 'exit' 'Indietro' 'Torna al menu principale.')
        )
        $k = Select-One 'Rete del PC' $items $sel
        if ($k -eq 'exit') { return }
        $sel = [Array]::IndexOf(@($items | ForEach-Object { $_.Key }), $k)
        try {
            switch ($k) {
                'bench' { $a = Get-AdapterAlias; if ($a) { Set-BenchNetwork $a; Wait-Key } }
                'restore' {
                    $a = Get-AdapterAlias
                    if ($a) {
                        if (-not (Test-Path (Get-BackupPath $a))) { Warn "Nessuna configurazione salvata per ${a}: la rimetto in DHCP." }
                        Restore-PcNetwork $a; Wait-Key
                    }
                }
                'adapter' { [void](Select-Adapter) }
            }
        } catch { Fail $_.Exception.Message; Wait-Key }
    }
}

function Show-Settings {
    $sel = 0
    while ($true) {
        $items = @(
            (Item 'boxip' 'IP del box' 'Dove il programma cerca OpenWrt in SSH. Dopo l''avvio in RAM è 192.168.1.1, dopo la configurazione è l''IP scelto nella LAN del cliente.' "Ora: $($Settings.BoxIp)")
            (Item 'version' 'Versione di OpenWrt' 'La versione delle immagini da scaricare da downloads.openwrt.org. Vuota = la più recente, decisa al primo download.' "Ora: $(Pick $Settings.Version '(la più recente)')")
            (Item 'adapter' 'Scheda di rete' 'La scheda del PC collegata con il cavo al FRITZ!Box.' "Ora: $(Pick $Settings.Adapter '(da scegliere)')")
            (Item 'folder' 'Apri la cartella' 'Immagini scaricate (cache), log delle sessioni e delle configurazioni (log), impostazioni (stato).' $Root)
            (Item 'exit' 'Indietro' 'Torna al menu principale.')
        )
        $k = Select-One 'Impostazioni' $items $sel
        if ($k -eq 'exit') { return }
        $sel = [Array]::IndexOf(@($items | ForEach-Object { $_.Key }), $k)
        try {
            switch ($k) {
                'boxip' { $Settings.BoxIp = Read-Value 'IP del box' $Settings.BoxIp { param($x) Test-Ipv4 $x }; Save-Settings }
                'version' {
                    $latest = Get-LatestRelease
                    Say "Versione più recente su downloads.openwrt.org: $(Pick $latest 'non raggiungibile')"
                    $Settings.Version = Read-Value 'Versione da usare (per esempio 25.12.6; - = la più recente)' $Settings.Version { param($x) $x -match '^\d+\.\d+\.\d+$' } -AllowEmpty
                    Save-Settings
                }
                'adapter' { [void](Select-Adapter) }
                'folder' { Start-Process explorer.exe $Root }
            }
        } catch { Fail $_.Exception.Message; Wait-Key }
    }
}

# ============================== MAIN MENU ==============================
function Show-Main {
    $sel = 0
    while ($true) {
        $items = @(
            (Item 'ram' 'Avvia in RAM' 'Scarica e verifica l''immagine ufficiale e la avvia in RAM dal bootloader EVA. La flash non viene scritta: spegnendo il box riparte FRITZ!OS.')
            (Item 'flash' 'Installa sulla flash' 'Sostituisce FRITZ!OS con OpenWrt (sysupgrade). Prima controlla variante del NAND e dmesg; sui NAND Micron chiede di accettare il rischio.' '' -Warn)
            (Item 'trap' 'Configura come trappola' 'Il box diventa un client della LAN del cliente e registra chi prova a collegarsi a porte come SMB, RDP, Telnet o i database.')
            (Item 'probe' 'Configura come sonda' 'Il box diventa un client della LAN del cliente con tunnel WireGuard di gestione, agente di monitoraggio e strumenti di diagnosi.')
            (Item 'status' 'Stato del box' 'Versione, NAND, rete, ora, trappola, tunnel e agenti del box raggiungibile in SSH.')
            (Item 'tools' 'Strumenti' 'Console SSH, LuCI nel browser, salvataggio di dmesg e log, riavvio del box.')
            (Item 'pcnet' 'Rete del PC' 'Imposta o ripristina gli indirizzi della scheda di rete collegata al FRITZ!Box.' (Get-PcNetworkState))
            (Item 'settings' 'Impostazioni' 'IP del box, versione di OpenWrt, scheda di rete, cartella del programma.')
            (Item 'exit' 'Esci' 'Chiude il programma.')
        )
        $k = Select-One 'Cosa vuoi fare?' $items $sel
        if ($k -eq 'exit') { return }
        $sel = [Array]::IndexOf(@($items | ForEach-Object { $_.Key }), $k)
        if ($k -eq 'tools') { Show-Tools; continue }
        if ($k -eq 'pcnet') { Show-PcNetwork; continue }
        if ($k -eq 'settings') { Show-Settings; continue }
        try {
            switch ($k) {
                'ram' { Invoke-RamBoot }
                'flash' { Install-Flash }
                'trap' { Invoke-Configure 'trap' }
                'probe' { Invoke-Configure 'probe' }
                'status' { Show-Status }
            }
        } catch { Fail $_.Exception.Message }
        Wait-Key
    }
}

function Exit-Tool {
    $alias = $Settings.Adapter
    if ($alias -and (Test-Path (Get-BackupPath $alias)) -and (Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue)) {
        Write-Host ''
        Warn "La scheda $alias ha ancora gli IP di lavoro, senza gateway."
        if (Read-YesNo 'La riporto com''era prima?' $true) {
            try { Restore-PcNetwork $alias } catch { Fail $_.Exception.Message; Start-Sleep 3 }
        }
    }
    try { Stop-Transcript | Out-Null } catch { }
}

Show-Main
Exit-Tool
