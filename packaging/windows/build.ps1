param(
    [Parameter(Mandatory=$true)][ValidatePattern('^\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$')][string]$Version,
    [Parameter(Mandatory=$true)][string]$RuntimeDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$root = (Resolve-Path "$PSScriptRoot/../..").Path
$runtime = (Resolve-Path $RuntimeDirectory).Path
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$output = (Resolve-Path $OutputDirectory).Path
$work = Join-Path $output '.work'
$payload = Join-Path $work 'app'
if (Test-Path $payload) { [IO.Directory]::Delete($payload, $true) }
New-Item -ItemType Directory -Force "$work/tmp",$payload | Out-Null
$env:TEMP="$work/tmp"; $env:TMP=$env:TEMP; $env:TMPDIR=$env:TEMP
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PIP_CACHE_DIR=Join-Path $work 'pip-cache'
function Run([scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Command" }
}
Push-Location $root
try {
    Run { dotnet tool restore }
    Run { dotnet test desktop/windows/Emulator.Core.Tests/Emulator.Core.Tests.csproj -c Release --logger trx --results-directory "$output/test-results" }
    Run { dotnet publish desktop/windows/Emulator.App/Emulator.App.csproj -c Release -r win-x64 -p:Platform=x64 --self-contained true -p:Version=$Version -p:BuildVersion=$Version -p:BuildCommit=$env:BUILD_COMMIT -p:PathMap="$root=/_/" -p:ContinuousIntegrationBuild=true -o $payload }
    Copy-Item "$runtime/bin" $payload -Recurse -Force
    Copy-Item "$root/src" $payload -Recurse -Force
    Copy-Item "$root/LICENSE","$root/THIRD_PARTY_NOTICES.md","$runtime/QEMU_COPYING" $payload
    Copy-Item "$PSScriptRoot/Velopack-LICENSE" $payload
    Copy-Item "$runtime/licenses" $payload -Recurse -Force
    Copy-Item "$runtime/MSYS2_PACKAGES.txt","$runtime/DLLS.txt","$runtime/QEMU_COPYING.LIB" $payload
    $python = Join-Path $payload 'python'
    if (!(Test-Path "$work/python.zip")) {
        Invoke-WebRequest https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip -OutFile "$work/python.zip"
    }
    Expand-Archive "$work/python.zip" $python -Force
    Set-Content "$python/python312._pth" "python312.zip`n.`nLib/site-packages`n../src`nimport site" -Encoding ASCII
    Run { python -m pip install --disable-pip-version-check --no-compile --only-binary=:all: --target "$python/Lib/site-packages" -r requirements.txt }
    # Microsoft's Desktop VC redistributable package supplies the app-local CRT.
    if (!(Test-Path "$work/vclibs.zip")) {
        Invoke-WebRequest https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile "$work/vclibs.zip"
    }
    Expand-Archive "$work/vclibs.zip" "$work/vclibs" -Force
    Get-ChildItem "$work/vclibs" -Filter '*.dll' -Recurse | Copy-Item -Destination $payload -Force
    Copy-Item "$work/vclibs/AppxManifest.xml" "$payload/VC_RUNTIME_MANIFEST.xml"
    foreach ($name in @('MSM5xxx.Desktop.exe','Microsoft.UI.Xaml.dll','coreclr.dll','resources.pri','App.xbf','vcruntime140.dll','msvcp140.dll','bin/qemu-system-arm.exe','python/python.exe','src/msm5xxx_emulator/backend/__main__.py')) {
        if (!(Test-Path (Join-Path $payload $name))) { throw "Missing payload file: $name" }
    }
    Run { & "$python/python.exe" -c 'import capstone, PIL, numpy, msm5xxx_emulator.backend' }
    Run { & "$payload/bin/qemu-system-arm.exe" --version }
    Run { dotnet tool run vpk -- pack --packId MSM5xxx.Desktop --packTitle 'MSM5xxx Emulator' --packAuthors Ancalina --packVersion $Version --packDir $payload --mainExe MSM5xxx.Desktop.exe --icon "$payload/Branding/full.ico" --shortcuts StartMenuRoot --noPortable --outputDir $output --channel win --skip-updates }
    # The install directory must remain separate from LocalAppData/MSM5xxx user data.
    Move-Item "$output/MSM5xxx.Desktop-win-Setup.exe" "$output/MSM5xxx-win-Setup.exe" -Force
} finally { Pop-Location }
Write-Output "WINDOWS PACKAGE OK $Version"
