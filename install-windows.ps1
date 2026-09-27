# Install NetScan on Windows: nmap + Npcap, Python, PySide6, and Start menu/Desktop shortcuts.
#
# Run from the folder containing netscan.py and netscan_app\, in PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\install-windows.ps1
# It asks for administrator rights (Chocolatey, nmap and Npcap need them).
#
# Package sources:
#   Python  - winget (Python.Python.3.13), Chocolatey (python313) as a fallback
#   nmap    - Chocolatey: it has current nmap and installs Npcap with it. winget's
#             Insecure.Nmap is stuck at 7.80 and skips Npcap, so it's only a last resort.
#   PySide6 - pip, into a private virtual environment

param(
    [string]$UserLocal = $env:LOCALAPPDATA,
    [string]$UserRoaming = $env:APPDATA,
    [string]$UserDesktop = [Environment]::GetFolderPath('Desktop')
)

# Native tools report failure through $LASTEXITCODE, which is checked explicitly.
# ('Stop' would also abort on harmless stderr output in Windows PowerShell 5.1.)
$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Test-Cmd($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }
function Update-SessionPath {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
}
function Stop-Install($msg) {
    Write-Host "`n$msg" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}

if (-not (Test-Path (Join-Path $here 'netscan.py')) -or -not (Test-Path (Join-Path $here 'netscan_app'))) {
    Stop-Install "netscan.py and the netscan_app folder must be next to this script ($here)."
}

# ---- administrator rights ------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Asking for administrator rights (needed for Chocolatey, nmap and Npcap)...'
    # Pass this user's folders along, so the app and shortcuts land in your profile.
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
                 '-UserLocal', "`"$UserLocal`"", '-UserRoaming', "`"$UserRoaming`"",
                 '-UserDesktop', "`"$UserDesktop`"")
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    } catch {
        Write-Host 'Administrator rights were declined; nothing was installed.' -ForegroundColor Red
    }
    exit
}

# ---- package managers ----------------------------------------------------------
function Install-Winget {
    if (Test-Cmd winget) { return }
    Write-Step 'winget not found - installing it (Microsoft.WinGet.Client)...'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -ErrorAction Stop | Out-Null
        Import-Module Microsoft.WinGet.Client -ErrorAction Stop
        Repair-WinGetPackageManager -AllUsers -Latest -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not install winget: $_"
    }
    Update-SessionPath
    $alias = Join-Path $UserLocal 'Microsoft\WindowsApps'
    if (-not (Test-Cmd winget) -and (Test-Path (Join-Path $alias 'winget.exe'))) { $env:Path += ";$alias" }
}

function Install-Choco {
    if (Test-Cmd choco) { return }
    Write-Step 'Chocolatey not found - installing it (official installer from chocolatey.org)...'
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    try {
        Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    } catch {
        Write-Warning "Could not install Chocolatey: $_"
    }
    Update-SessionPath
    $chocoBin = Join-Path $env:ProgramData 'chocolatey\bin'
    if (-not (Test-Cmd choco) -and (Test-Path $chocoBin)) { $env:Path += ";$chocoBin" }
}

# ---- Python --------------------------------------------------------------------
function Find-Python {
    if (Test-Cmd py) {
        foreach ($v in '3.13', '3.12', '3.14') {
            $exe = & py "-$v" -c 'import sys; print(sys.executable)' 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe) { return "$exe".Trim() }
        }
    }
    $candidates = @(
        "$env:ProgramFiles\Python313\python.exe", "$UserLocal\Programs\Python\Python313\python.exe",
        'C:\Python313\python.exe',
        "$env:ProgramFiles\Python312\python.exe", "$UserLocal\Programs\Python\Python312\python.exe",
        'C:\Python312\python.exe'
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    return $null
}

Write-Step 'Checking Python...'
$python = Find-Python
if (-not $python) {
    Install-Winget
    if (Test-Cmd winget) {
        Write-Step 'Installing Python 3.13 with winget...'
        winget install --id Python.Python.3.13 --exact --scope machine --silent `
            --accept-package-agreements --accept-source-agreements
    }
    Update-SessionPath
    $python = Find-Python
}
if (-not $python) {
    Install-Choco
    if (Test-Cmd choco) {
        Write-Step 'Installing Python 3.13 with Chocolatey...'
        choco install python313 -y --no-progress
        Update-SessionPath
        $python = Find-Python
    }
}
if (-not $python) { Stop-Install 'Could not install Python. Install Python 3.13 from python.org, then run this again.' }
Write-Host "Using Python: $python ($(& $python --version))"

# ---- nmap + Npcap --------------------------------------------------------------
function Find-Nmap {
    $cmd = Get-Command nmap -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in "${env:ProgramFiles(x86)}\Nmap\nmap.exe", "$env:ProgramFiles\Nmap\nmap.exe") {
        if (Test-Path $p) { return $p }
    }
    return $null
}
function Test-Npcap { Test-Path (Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll') }

Write-Step 'Checking nmap and Npcap...'
if (-not (Find-Nmap) -or -not (Test-Npcap)) {
    Install-Choco
    if (Test-Cmd choco) {
        Write-Step 'Installing nmap + Npcap with Chocolatey...'
        Write-Host 'Setup windows will open and click through on their own. Please do not touch them.' -ForegroundColor Yellow
        $extra = @()
        if (Find-Nmap) { $extra += '--force' }   # nmap present but no Npcap: reinstall to add it
        choco install nmap -y --no-progress @extra
        Update-SessionPath
    }
    if (-not (Find-Nmap)) {
        Install-Winget
        if (Test-Cmd winget) {
            Write-Step 'Chocolatey failed; installing the older nmap 7.80 from winget...'
            winget install --id Insecure.Nmap --exact --silent --accept-package-agreements --accept-source-agreements
            Update-SessionPath
        }
    }
}
$nmap = Find-Nmap
if (-not $nmap) { Stop-Install 'Could not install nmap. Install it from https://nmap.org/download.html#windows, then run this again.' }
Write-Host "Using nmap: $nmap"
if (-not (Test-Npcap)) {
    Write-Warning ('Npcap is missing, so NetScan will only do basic (unprivileged) scans. ' +
                   'Opening https://npcap.com/#download - install it with the default options.')
    Start-Process 'https://npcap.com/#download'
}

# ---- NetScan -------------------------------------------------------------------
$dest = Join-Path $UserLocal 'NetScan'
$venvPy = Join-Path $dest 'venv\Scripts\python.exe'
Write-Step "Installing NetScan into $dest..."
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item (Join-Path $here 'netscan.py') $dest -Force
$appDir = Join-Path $dest 'netscan_app'
if (Test-Path $appDir) { Remove-Item $appDir -Recurse -Force }  # replace, so removed files don't linger
Copy-Item (Join-Path $here 'netscan_app') $dest -Recurse -Force
Remove-Item (Join-Path $appDir '__pycache__') -Recurse -Force -ErrorAction SilentlyContinue
if (-not (Test-Path $venvPy)) {
    & $python -m venv (Join-Path $dest 'venv')
    if ($LASTEXITCODE -ne 0) { Stop-Install 'Could not create the Python environment.' }
}
Write-Host 'Installing PySide6 (Qt) - this can take a minute...'
& $venvPy -m pip install --quiet --upgrade pip PySide6
if ($LASTEXITCODE -ne 0) { Stop-Install 'pip could not install PySide6.' }

Write-Step 'Creating Start menu and Desktop shortcuts...'
$shell = New-Object -ComObject WScript.Shell
$links = @((Join-Path $UserRoaming 'Microsoft\Windows\Start Menu\Programs\NetScan.lnk'),
           (Join-Path $UserDesktop 'NetScan.lnk'))
foreach ($link in $links) {
    $s = $shell.CreateShortcut($link)
    $s.TargetPath = Join-Path $dest 'venv\Scripts\pythonw.exe'   # pythonw: no console window
    $s.Arguments = "`"$(Join-Path $dest 'netscan.py')`""
    $s.WorkingDirectory = $dest
    $s.IconLocation = "$env:SystemRoot\System32\shell32.dll,18"
    $s.Description = 'Scan the local network for devices (nmap)'
    $s.Save()
}

# ---- verify ----------------------------------------------------------------------
Write-Step 'Checking that everything works...'
& $venvPy (Join-Path $dest 'netscan.py') --self-test
if ($LASTEXITCODE -eq 0) {
    Write-Host "`nDone. Open NetScan from the Start menu or the Desktop shortcut." -ForegroundColor Green
} else {
    Write-Host "`nNetScan is installed, but some checks failed (see above)." -ForegroundColor Yellow
}
Write-Host 'To update later: put the new netscan.py and netscan_app folder next to this script and run it again.'
Read-Host 'Press Enter to close'
