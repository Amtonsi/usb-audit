# Никаких заданий, сеансов ETW и системных настроек на машине тест не меняет.
# Проверяем штатный сценарий на временной папке со своими файлами.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot '..\tools\Uninstall-UsbAudit.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw $errors[0].Message }
function Import-RemovalFunction([string]$Name) {
    $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name},$true)
    [scriptblock]::Create($fn.Extent.Text)
}
. (Import-RemovalFunction 'Assert-AppTask')
. (Import-RemovalFunction 'Assert-PlainPath')
. (Import-RemovalFunction 'Assert-AdminOwned')
. (Import-RemovalFunction 'Get-UsbTraceState')
# Компилируем тот же класс, что поставляется со скриптом, без вызовов ControlTrace.
$typeBody=$ast.Find({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $n.Value.Contains('public static class UninstallTrace')},$true)
Add-Type -TypeDefinition $typeBody.Value
$guid=[guid]'5ecda003-832f-4ea6-8bac-93747995ed7a'
if (![LocalUsbAudit.UninstallTrace]::Owns($guid,0x100) -or ![LocalUsbAudit.UninstallTrace]::Owns($guid,0x800100) -or
    [LocalUsbAudit.UninstallTrace]::Owns([guid]::NewGuid(),0x100) -or [LocalUsbAudit.UninstallTrace]::Owns($guid,0x101)) {
    throw 'Неверная идентификация сеанса ETW.'
}
$text=$ast.Extent.Text
$offset=$text.IndexOf('$tasks = @(Get-AppTasks)',[StringComparison]::Ordinal)
if ($offset -lt 0) {throw 'Не найдена точка входа удаления.'}
$main=[scriptblock]::Create('[CmdletBinding(SupportsShouldProcess)]param()'+[Environment]::NewLine+$text.Substring($offset))
function Check([bool]$Ok,[string]$Label) {if (!$Ok) {throw "Ошибка проверки: $Label"}}
$root=Join-Path ([IO.Path]::GetTempPath()) ('UsbAudit-Remove-QA-'+[guid]::NewGuid().ToString('N'))
$app=Join-Path $root 'application';$store=Join-Path $root 'retained'
$winPS=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$collector='LocalUsbAuditCollector';$maintenance='LocalUsbAuditMaintenance'
$allowedFiles='installation.json','Collector.ps1','KernelFileTrace.cs','setup.lock'
$sidText=& (Join-Path ([Environment]::SystemDirectory) 'schtasks.exe') /showsid /tn "\$collector"
if (($sidText -join ' ') -notmatch '(S-1-5-87-(?:\d+-){4}\d+)') {throw 'Не удалось определить SID тестового имени.'}
$taskSid=$Matches[1]

$sample=[Security.AccessControl.DirectorySecurity]::new()
function Get-Acl([string]$LiteralPath){$script:sample}
function Get-AppTasks { $script:fixtureTasks.Values }
function Get-UsbTraceState([switch]$Stop) {
    if ($Stop -and $script:trace -eq 'Owned') {
        if ($script:replacement) { $script:trace=$script:replacement; return $script:trace }
        if ($script:failStop) { throw 'Test: ETW busy' }
        $script:trace='Absent'
        $script:stops++
        return 'Stopped'
    }
    $script:trace
}
function Restore-DestinationAudit($Folders,[bool]$Apply) {}
function Remove-CollectorReadGrant([string]$TaskSid) {
    $script:removedAcl++
    if ($script:lateFile) {[IO.File]::WriteAllText((Join-Path $app 'late.txt'),'fixture')}
}
function Get-Process {param($Name,$ErrorAction) @()}
function Get-CimInstance {
    param($ClassName,$Filter)
    if ($script:simulateLag) {$script:polls++}
    @()
}
function New-Object {param($ComObject)
    if($ComObject -ne 'Schedule.Service'){throw 'Unexpected COM server'}
    $stub=[pscustomobject]@{}
    $stub | Add-Member ScriptMethod Connect {}
    $stub | Add-Member ScriptMethod GetRunningTasks { param($Flags)
        foreach ($t in $script:fixtureTasks.Values) {if ($t.Live) {[pscustomobject]@{Path=('\'+$t.TaskName)}} }
        if ($script:simulateLag -and $script:polls -eq 1) {[pscustomobject]@{Path=('\'+$collector)}}
    }
    $stub
}
function Disable-ScheduledTask {param($InputObject) $InputObject.State='Disabled'}
function Stop-ScheduledTask {param($InputObject) $InputObject.Live=$false}
function Unregister-ScheduledTask {param($InputObject,[switch]$Confirm) $script:fixtureTasks.Remove($InputObject.TaskName)}
function Enable-ScheduledTask {param($TaskName,$TaskPath) $script:fixtureTasks[$TaskName].State='Ready'}
function Start-ScheduledTask {param($TaskName,$TaskPath) $t=$script:fixtureTasks[$TaskName];$t.State='Running';$t.Live=$true}
function New-FixtureTask([string]$TaskName,[string]$ArgsText,[string]$State) {
    $script:fixtureTasks[$TaskName]=[pscustomobject]@{TaskName=$TaskName;State=$State;Live=($State -eq 'Running')
        Actions=@([pscustomobject]@{Execute=$winPS;Arguments=$ArgsText;WorkingDirectory=$app})}
}
$script:fixtureTasks=@{}; $script:stops=0; $script:removedAcl=0
try {
    [void][IO.Directory]::CreateDirectory($app); [void][IO.Directory]::CreateDirectory($store)
    $sentinel=Join-Path $store 'retained.txt'
    [IO.File]::WriteAllText($sentinel,'history');$digest=(Get-FileHash -LiteralPath $sentinel).Hash
    $marker=Join-Path $app 'installation.json'
    [IO.File]::WriteAllText($marker,(@{format='local-usb-audit-v1';taskSid=$taskSid} | ConvertTo-Json))
    [IO.File]::WriteAllText((Join-Path $app 'Collector.ps1'),'fixture')
    [IO.File]::WriteAllText((Join-Path $app 'setup.lock'),'')
    $sample.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)')
    Assert-AdminOwned $app
    $sample.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;BA)(A;;FW;;;BU)')
    $rejected=$false;try {Assert-AdminOwned $app} catch {$rejected=$true}
    Check $rejected 'отказ для посторонней записи в каталог программы'
    $sample.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    $prefix='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '
    New-FixtureTask $collector ($prefix+'"'+(Join-Path $app 'Collector.ps1')+'"') 'Running'
    New-FixtureTask $maintenance ($prefix+'"'+(Join-Path $app 'Maintenance.ps1')+'" -Action Worker') 'Ready'
    $script:trace='Owned';$script:failStop=$false
    & $main -WhatIf | Out-Null
    Check ($fixtureTasks.Count -eq 2 -and $trace -eq 'Owned' -and !$removedAcl -and [IO.File]::Exists($marker)) 'WhatIf не меняет установку'
    $script:failStop=$true
    $rejected=$false;try {& $main | Out-Null} catch {$rejected=$_.Exception.Message -eq 'Test: ETW busy'}
    Check ($rejected -and $fixtureTasks.Count -eq 2 -and $fixtureTasks[$collector].Live -and $fixtureTasks[$maintenance].State -eq 'Ready' -and
        !$removedAcl -and [IO.File]::Exists($marker)) 'восстановление исходного состояния заданий после ошибки'
    # Изображаем частично удалённый пакет без KernelFileTrace.cs.
    $script:failStop=$false
    & $main | Out-Null
    Check (!$fixtureTasks.Count -and $trace -eq 'Absent' -and $stops -eq 1 -and $removedAcl -eq 1 -and ![IO.Directory]::Exists($app)) 'полное удаление'
    & $main | Out-Null
    Check ($stops -eq 1 -and $removedAcl -eq 1) 'повторное удаление'
    $script:trace='Owned'
    $preview=@(& $main -WhatIf)
    Check ($trace -eq 'Owned' -and !($preview -match 'компоненты USB-Audit отсутствуют')) 'WhatIf при оставшемся сеансе'
    foreach ($replacementState in 'Absent','Foreign') {
        $script:replacement=$replacementState;$script:trace='Owned'
        $result=@(& $main -WarningAction SilentlyContinue)
        Check ($trace -eq $replacementState -and !($result -match '^Остановлен') -and $stops -eq 1) 'смена владельца или остановка между проверками'
    }
    $script:replacement=$null;$script:trace='Owned'
    & $main | Out-Null
    Check ($trace -eq 'Absent' -and $stops -eq 2) 'очистка оставшегося своего сеанса без установленного пакета'
    $script:trace='Foreign'
    & $main | Out-Null
    Check ($trace -eq 'Foreign' -and $stops -eq 2) 'сохранение чужого сеанса'
    [void][IO.Directory]::CreateDirectory($app)
    $preview=@(& $main -WhatIf -WarningAction SilentlyContinue)
    Check ([IO.Directory]::Exists($app) -and !($preview -match 'компоненты USB-Audit отсутствуют')) 'WhatIf для пустого каталога'
    [IO.File]::WriteAllText($marker,(@{format='local-usb-audit-v1';taskSid=$taskSid} | ConvertTo-Json))
    [IO.File]::WriteAllText((Join-Path $app 'Collector.ps1'),'fixture')
    $markerDigest=(Get-FileHash -LiteralPath $marker).Hash
    $aclParts=[Security.AccessControl.AccessControlSections]'Owner,Group,Access'
    $markerAcl=[IO.File]::GetAccessControl($marker).GetSecurityDescriptorSddlForm($aclParts)
    New-FixtureTask $collector ($prefix+'"'+(Join-Path $app 'Collector.ps1')+'"') 'Running'
    $script:trace='Absent'; $script:simulateLag=$true;$script:polls=0;$script:lateFile=$true
    $rejected=$false
    try { & $main | Out-Null } catch { $rejected=$_.Exception.Message -match 'late.txt' }
    Check ($rejected -and $polls -ge 2 -and [IO.File]::Exists($marker) -and [IO.File]::Exists((Join-Path $app 'late.txt'))) 'ожидание экземпляра Планировщика и сохранение метки при появлении файла'
    [IO.File]::Delete((Join-Path $app 'late.txt'))
    $script:simulateLag=$false;$script:lateFile=$false;$script:raceAtMarker=$true
    function Remove-Item {
        param([string]$LiteralPath,[switch]$Force)
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Force:$Force
        if ($script:raceAtMarker -and $LiteralPath -eq $marker) {
            [IO.File]::WriteAllText((Join-Path $app 'late.txt'),'fixture')
        }
    }
    $rejected=$false
    try { & $main | Out-Null } catch { $rejected=$true }
    Check ($rejected -and [IO.File]::Exists((Join-Path $app 'late.txt')) -and
        (Get-FileHash -LiteralPath $marker).Hash -eq $markerDigest -and
        [IO.File]::GetAccessControl($marker).GetSecurityDescriptorSddlForm($aclParts) -ceq $markerAcl) 'возврат исходной метки с её правами после поздней ошибки удаления каталога'
    [IO.File]::Delete((Join-Path $app 'late.txt'))
    $script:raceAtMarker=$false
    & $main | Out-Null
    Check (![IO.Directory]::Exists($app)) 'повторное удаление после поздней ошибки'
    Check ((Get-FileHash -LiteralPath $sentinel).Hash -eq $digest) 'сохранность журнала'
    Write-Output 'Проверены предварительный просмотр, ACL, откат заданий, обе формы сеанса ETW, повторное удаление и сохранность истории.'
} finally {
    foreach($f in 'Collector.ps1','installation.json','setup.lock','late.txt'){ $p=Join-Path $app $f; if([IO.File]::Exists($p)){[IO.File]::Delete($p)} }
    $p=Join-Path $store 'retained.txt';if([IO.File]::Exists($p)){[IO.File]::Delete($p)}
    foreach($dir in $app,$store,$root){if([IO.Directory]::Exists($dir)){[IO.Directory]::Delete($dir,$false)}}
}
