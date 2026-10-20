# Installs the kuukura CLI (ku.exe and kuukura.exe) on Windows (PowerShell 5.1 or 7).
#   irm https://raw.githubusercontent.com/victorlunam/kuukura/main/scripts/install.ps1 | iex
# Environment:
#   KU_VERSION      a release such as 2026.10.2 (default: the latest release)
#   KU_INSTALL_DIR  where to put the programs (default: %LOCALAPPDATA%\Programs\kuukura)
# The archive is checked against the release's checksums.txt before anything is installed.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = 'victorlunam/kuukura'
$dir = if ($env:KU_INSTALL_DIR) { $env:KU_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\kuukura' }

switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "install: unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)' (supported: amd64, arm64)" }
}

$version = $env:KU_VERSION
if (-not $version) {
    # /releases/latest redirects to /releases/tag/vYEAR.MONTH.N
    $req = [Net.WebRequest]::Create("https://github.com/$repo/releases/latest")
    $req.AllowAutoRedirect = $false
    $res = $req.GetResponse()
    $location = $res.Headers['Location']
    $res.Close()
    if (-not $location) { throw 'install: could not find the latest release' }
    $version = $location.Substring($location.LastIndexOf('/v') + 2)
}
$version = $version.TrimStart('v')
if ($version -notmatch '^\d{4}\.\d+\.\d+$') {
    throw "install: '$version' is not a release version (expected YEAR.MONTH.N, for example 2026.10.2)"
}

$file = "kuukura_${version}_windows_${arch}.zip"
$base = "https://github.com/$repo/releases/download/v$version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading kuukura $version for windows/$arch"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$file" -OutFile (Join-Path $tmp $file)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt')

    $line = Get-Content (Join-Path $tmp 'checksums.txt') | Where-Object { $_ -match "^\S+\s+\*?$([regex]::Escape($file))$" } | Select-Object -First 1
    if (-not $line) { throw "install: checksums.txt has no entry for $file" }
    $want = ($line -split '\s+')[0]
    $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $file)).Hash
    if ($got -ne $want.ToUpper()) { throw "install: checksum mismatch for $file; nothing was installed" }

    Expand-Archive -Path (Join-Path $tmp $file) -DestinationPath (Join-Path $tmp 'x') -Force
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    foreach ($p in 'kuukura.exe', 'ku.exe') {
        Copy-Item -Path (Join-Path $tmp "x\$p") -Destination (Join-Path $dir $p) -Force
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', (($userPath, $dir | Where-Object { $_ }) -join ';'), 'User')
    $env:Path = "$env:Path;$dir"
    Write-Host "Added $dir to your user PATH (open a new terminal to use it)."
}
Write-Host "Installed in ${dir}:"
& (Join-Path $dir 'ku.exe') --version
