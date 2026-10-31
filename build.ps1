<#
.SYNOPSIS
  Builds Cheat Engine (64-bit) plus the 32/64-bit speedhack DLLs and packages
  the result into a folder named after the build number.

.DESCRIPTION
  The build number lives in "Cheat Engine\cebuild.inc". It shows in the title
  bar ("Cheat Engine 7.5 build N") and in the exe's file version (7.5.N.0).

    .\build.ps1 -NewBuild   bump the build number (then commit the change)
    .\build.ps1             build and package the current build number
    .\build.ps1 -Tag        same, then tag the commit as build-N (needs a clean tree)

  Output: <OutputRoot>\cheat-engine-7.5-buildN\  (the whole bin folder, without
  the large .dbg debug file, plus BUILD-INFO.txt)

.NOTES
  Needs Lazarus 2.2.2 with FPC 3.2.2 and the i386 cross compiler (README.md).
#>
param(
  [switch]$NewBuild,
  [switch]$Tag,
  [string]$Lazbuild = 'C:\lazarus\lazbuild.exe',
  [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'cheat-engine-builds')
)

$ErrorActionPreference = 'Stop'
$repo  = $PSScriptRoot
$ce    = Join-Path $repo 'Cheat Engine'
$inc   = Join-Path $ce 'cebuild.inc'
$lpi   = Join-Path $ce 'cheatengine.lpi'
$ceVersion = '7.5'

function Get-BuildNumber {
  $m = [regex]::Match([IO.File]::ReadAllText($inc), 'cebuildnr\s*=\s*(\d+)')
  if (-not $m.Success) { throw "No cebuildnr in $inc" }
  [int]$m.Groups[1].Value
}

function Write-TextKeepEncoding($path, $text) {
  # the sources are plain ASCII/latin-1 with CRLF: write them back without a BOM
  [IO.File]::WriteAllText($path, $text, [Text.Encoding]::GetEncoding(28591))
}

function Set-BuildNumber([int]$n) {
  $t = [IO.File]::ReadAllText($inc, [Text.Encoding]::GetEncoding(28591))
  $t = [regex]::Replace($t, 'cebuildnr\s*=\s*\d+;', "cebuildnr = $n;")
  $t = [regex]::Replace($t, "cebuildname\s*=\s*'[^']*';", "cebuildname = ' build $n';")
  Write-TextKeepEncoding $inc $t

  # windows version resource of the exe: 7.5.<build>.0
  $l = [IO.File]::ReadAllText($lpi, [Text.Encoding]::GetEncoding(28591))
  if ($l -notmatch '<RevisionNr Value="\d+"/>') {
    $l = $l -replace '(\s*)(<BuildNr Value="\d+"/>)', '$1<RevisionNr Value="0"/>$1$2'
  }
  $l = $l -replace '<RevisionNr Value="\d+"/>', "<RevisionNr Value=`"$n`"/>"
  $l = $l -replace '<BuildNr Value="\d+"/>', '<BuildNr Value="0"/>'
  $l = $l -replace 'ProductVersion="[^"]*"', "ProductVersion=`"$ceVersion build $n`""
  Write-TextKeepEncoding $lpi $l
}

function Invoke-Lazbuild($project, $mode) {
  Write-Host "== lazbuild $(Split-Path $project -Leaf) [$mode]"
  $log = & $Lazbuild "--build-mode=$mode" $project 2>&1
  if ($LASTEXITCODE -ne 0) {
    $log | Select-String -Pattern 'Error|Fatal' | ForEach-Object { Write-Host $_ }
    throw "lazbuild failed for $project ($mode), exit code $LASTEXITCODE"
  }
  $log | Select-String -Pattern 'lines compiled' | ForEach-Object { Write-Host "   $_" }
}

if ($NewBuild) {
  $n = (Get-BuildNumber) + 1
  Set-BuildNumber $n
  Write-Host "Build number is now $n. Commit cebuild.inc and cheatengine.lpi, then run .\build.ps1"
  return
}

if (-not (Test-Path $Lazbuild)) { throw "lazbuild not found at $Lazbuild" }

$n = Get-BuildNumber
Set-BuildNumber $n   # keeps the lpi version info in sync with cebuild.inc (no-op when it already is)

Push-Location $repo
try {
  $commit = (git rev-parse --short HEAD).Trim()
  $dirty  = [bool](git status --porcelain)
} finally { Pop-Location }

Invoke-Lazbuild (Join-Path $ce 'speedhack\speedhack.lpi') '64-bit'
Invoke-Lazbuild (Join-Path $ce 'speedhack\speedhack.lpi') '32-bit'
Invoke-Lazbuild $lpi 'Release 64-Bit'

$name = "cheat-engine-$ceVersion-build$n"
$out  = Join-Path $OutputRoot $name
if (Test-Path $out) { throw "$out already exists. Bump the build number with -NewBuild, or delete the folder." }
New-Item -ItemType Directory -Force $out | Out-Null

robocopy (Join-Path $ce 'bin') $out /E /XF *.dbg /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "copying the build failed (robocopy exit code $LASTEXITCODE)" }

$state = if ($dirty) { "$commit + uncommitted changes" } else { $commit }
@"
Cheat Engine $ceVersion build $n
Commit:  $state
Built:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Exe:     cheatengine-x86_64.exe (file version $ceVersion.$n.0)
"@ | Set-Content -Encoding ascii (Join-Path $out 'BUILD-INFO.txt')

Write-Host "Packaged: $out"

if ($Tag) {
  if ($dirty) { throw "Not tagging: the working tree has uncommitted changes" }
  Push-Location $repo
  try { git tag -a "build-$n" -m "Cheat Engine $ceVersion build $n" } finally { Pop-Location }
  Write-Host "Tagged $commit as build-$n"
}
