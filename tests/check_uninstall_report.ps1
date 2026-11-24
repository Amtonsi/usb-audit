#requires -Version 5.1
# Проверка от имени обычного читателя без регистрации заданий или изменения установки.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
$source=[IO.File]::ReadAllText((Join-Path $repo 'tools\Uninstall-UsbAudit.ps1'))
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if ($errors) { throw $errors[0] }
$reader=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-FinalReaderReport'},$true)
if (!$reader) { throw 'Функция итогового отчёта отсутствует.' }
$body=$reader.Find({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.StringConstantType -eq 'SingleQuotedHereString' -and $n.Value.Contains('Report.ps1') -and $n.Value.Contains('USB-Audit-status.css')},$true)
if (!$body) { throw 'Встроенный сценарий читателя отсутствует.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Проверку отчёта запускают из обычной Windows PowerShell в сеансе читателя.'
}
$readerCode=$body.Value.Replace('__READER_SID__',$identity.User.Value)
$ps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$root=Join-Path $temp ('usb-reader-final-'+[guid]::NewGuid().ToString('N'))
$oldLocal=$env:LOCALAPPDATA;$oldCommon=$env:ProgramData;$pushed=$false
try {
    $env:LOCALAPPDATA=Join-Path $root 'local';$env:ProgramData=Join-Path $root 'common'
    $data=Join-Path $env:ProgramData 'LocalUsbAudit\Data'
    $log=Join-Path $data 'Active\events.jsonl'
    $html=Join-Path $env:LOCALAPPDATA 'LocalUsbAudit\Reports\USB-Audit.html'
    $signal=Join-Path (Split-Path $html) 'USB-Audit-status.css'
    $app=Join-Path $root 'Программа'
    foreach ($dir in $app,(Split-Path $log),(Join-Path $data 'Archive'),(Split-Path $html)) { [void][IO.Directory]::CreateDirectory($dir) }
    foreach ($file in 'Report.ps1','viewer.html'){[IO.File]::Copy((Join-Path $repo ('src\'+$file)),(Join-Path $app $file))}
    $entry=Join-Path $app 'FinalReader.ps1'
    [IO.File]::WriteAllText($entry,$readerCode,[Text.UTF8Encoding]::new($true))
    $params=@()
    if (([scriptblock]::Create($readerCode)).Ast.ParamBlock.Parameters.Name.VariablePath.UserPath -contains 'ReaderSid') {
        $params=@('-ReaderSid',$identity.User.Value)
    }
    Push-Location -LiteralPath $app;$pushed=$true
    $last='{"type":"status","time":"2026-11-24T10:12:39Z","message":"last event"}'
    [IO.File]::WriteAllText($log,$last)
    [IO.File]::WriteAllText($html,'old HTML')
    [IO.File]::WriteAllText($signal,'old signal')
    & $ps -NoLogo -NoProfile -NonInteractive -File $entry @params
    if ($LASTEXITCODE -ne 0) {throw "Сценарий читателя вернул код $LASTEXITCODE."}
    $actual=[IO.File]::ReadAllText($html)
    $meta=[regex]::Match($actual,'id="report-meta">([^<]+)').Groups[1].Value
    $head=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($meta)) | ConvertFrom-Json
    if ($head.scope -ne 'all' -or $head.liveUri -or $head.generation) { throw 'Ожидался самостоятельный снимок с архивами.' }
    $block=[regex]::Match($actual,'class="log-source"[^>]*>([^<]+)').Groups[1].Value
    if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($block)) -cne $last) { throw 'Утеряна последняя запись.' }
    if ([IO.File]::ReadAllText($signal) -notmatch '--usb-generation:\d+;--usb-heartbeat:\d+;--usb-state:ok') { throw 'Нет сигнала для открытой вкладки.' }
    [IO.File]::Delete($log)
    try {
        $ErrorActionPreference='Continue'
        & $ps -NoLogo -NoProfile -NonInteractive -File $entry @params 2>&1 | Out-Null
    } finally { $ErrorActionPreference='Stop' }
    if ($LASTEXITCODE -eq 0 -or [IO.File]::ReadAllText($html) -cne $actual) { throw 'Ошибка чтения изменила готовый снимок.' }
    if (@(Get-ChildItem -LiteralPath (Split-Path $html) -Filter '.usb-final-*').Count) { throw 'Остались временные файлы.' }
    Write-Output 'Проверен итоговый снимок с последней записью, уведомлением для вкладки и сохранением HTML при ошибке чтения.'
} finally {
    if ($pushed) { Pop-Location }
    $env:LOCALAPPDATA=$oldLocal;$env:ProgramData=$oldCommon
    if ([IO.Path]::GetDirectoryName($root) -ine $temp -or [IO.Path]::GetFileName($root) -notmatch '^usb-reader-final-[0-9a-f]{32}$') {throw 'Неожиданный путь теста.'}
    if ([IO.Directory]::Exists($root)) {Remove-Item -LiteralPath $root -Recurse -Force}
}
