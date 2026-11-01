# Install the yunmen CLI on Windows from GitHub Releases.
#
#   irm https://raw.githubusercontent.com/txchen/yunmen/master/scripts/install.ps1 | iex
#
# Environment:
#   YUNMEN_VERSION        release tag to install (default: latest)
#   YUNMEN_INSTALL_DIR    target directory (default: %LOCALAPPDATA%\Programs\yunmen)
#   YUNMEN_DOWNLOAD_BASE  override the release download URL (testing)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = 'txchen/yunmen'
# Windows PowerShell 5.1 may not offer TLS 1.2 by default; GitHub requires it.
if ($PSVersionTable.PSVersion.Major -lt 6) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { $arch = 'amd64' }
  'ARM64' { $arch = 'arm64' }
  default { throw "yunmen install: unsupported CPU '$env:PROCESSOR_ARCHITECTURE'; amd64 and arm64 are supported" }
}

$version = $env:YUNMEN_VERSION
if (-not $version) {
  $version = (Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'yunmen-install' }).tag_name
  if (-not $version) { throw 'yunmen install: no published release found' }
}

$base = $env:YUNMEN_DOWNLOAD_BASE
if (-not $base) { $base = "https://github.com/$repo/releases/download/$version" }
$name = "yunmen_${version}_windows_$arch"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("yunmen-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading yunmen $version for windows/$arch"
  $zip = Join-Path $tmp "$name.zip"
  $sums = Join-Path $tmp 'checksums.txt'
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$name.zip" -OutFile $zip
  Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile $sums

  $line = Get-Content $sums | Where-Object { $_ -match " $([regex]::Escape("$name.zip"))$" } | Select-Object -First 1
  if (-not $line) { throw "yunmen install: no checksum listed for $name.zip" }
  $expected = ($line -split '\s+')[0].ToLower()
  $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
  if ($expected -ne $actual) { throw "yunmen install: checksum mismatch for $name.zip" }

  Expand-Archive -Path $zip -DestinationPath $tmp -Force

  $dir = $env:YUNMEN_INSTALL_DIR
  if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\yunmen' }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Copy-Item -Force (Join-Path (Join-Path $tmp $name) 'yunmen.exe') (Join-Path $dir 'yunmen.exe')

  if ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) {
    # Read and write the raw registry value so %VARS% in the user PATH are
    # kept as written instead of being saved expanded.
    $envKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    $userPath = [string]$envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (-not (($userPath -split ';') -contains $dir)) {
      if ($userPath -eq '') { $newPath = $dir } else { $newPath = "$userPath;$dir" }
      $envKey.SetValue('Path', $newPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
      # Setting a variable through .NET broadcasts the change to new terminals.
      [Environment]::SetEnvironmentVariable('YUNMEN_INSTALL_REFRESH', '1', 'User')
      [Environment]::SetEnvironmentVariable('YUNMEN_INSTALL_REFRESH', $null, 'User')
      Write-Host "Added $dir to your user PATH. Open a new terminal to use it."
    }
    $envKey.Close()
  }
  $env:Path = "$env:Path;$dir"
  Write-Host "Installed yunmen $version to $(Join-Path $dir 'yunmen.exe')"
  Write-Host 'Next: yunmen login https://<your-gateway>'
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
