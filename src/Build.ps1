#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputPath)

$ErrorActionPreference = 'Stop'
if (!$PSBoundParameters.ContainsKey('OutputPath')) {
    $OutputPath = Join-Path $PSScriptRoot 'USB-Audit.exe'
}
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
# Имена ресурсов становятся частью EXE. По этим же именам установщик извлекает рабочие файлы.
$resourceNames = 'Access.ps1','Collector.ps1','Install.ps1','Report.ps1','viewer.html','Maintenance.ps1','Check.ps1'
$source = Join-Path $PSScriptRoot 'Launcher.cs'
$destination = [IO.Path]::GetFullPath($OutputPath)
if ([IO.Path]::GetExtension($destination) -ine '.exe') { throw 'OutputPath must have the .exe extension.' }
if (!(Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'The .NET Framework x64 C# compiler is missing.' }
if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Launcher.cs is missing.' }
$dir = [IO.Path]::GetDirectoryName($destination)
[void][IO.Directory]::CreateDirectory($dir)
# Сборка во временном каталоге сохраняет прежний EXE при ошибке компилятора.
$buildDir = Join-Path $dir ('USB-Audit-build-' + [guid]::NewGuid().ToString('N'))
$temp = Join-Path $buildDir 'USB-Audit.exe'
$options = @('/nologo','/target:winexe','/platform:x64','/optimize+','/warn:4','/warnaserror+','/codepage:65001',
    '/reference:System.dll','/reference:System.Core.dll','/reference:System.Drawing.dll','/reference:System.Windows.Forms.dll',
    '/reference:System.Security.dll','/reference:System.Xml.dll',('/out:' + $temp))
foreach ($name in $resourceNames) {
    $file = Join-Path $PSScriptRoot $name
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw ("Missing source file: " + $name) }
    $options += '/resource:' + $file + ',' + $name
}
try {
    [void](New-Item -ItemType Directory -Path $buildDir -ErrorAction Stop)
    & $compiler @options $source
    if ($LASTEXITCODE -ne 0) { throw ('Compiler exit code ' + $LASTEXITCODE) }
    if ([IO.File]::Exists($destination)) {
        [IO.File]::Replace($temp,$destination,[Management.Automation.Language.NullString]::Value)
    } else {
        [IO.File]::Move($temp,$destination)
    }
    Write-Output $destination
} finally {
    if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    if ([IO.Directory]::Exists($buildDir)) { [IO.Directory]::Delete($buildDir, $false) }
}
