#requires -Version 5.1
<#
.SYNOPSIS
Удаляет установленный USB-Audit, сохраняя журналы, отчёты и права их читателей.
.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Uninstall-UsbAudit.ps1"
.EXAMPLE
.\Uninstall-UsbAudit.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$administrator = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# Для консоли x86 и PowerShell 7 запускаем штатную 64-разрядную Windows PowerShell.
if (!([Environment]::Is64BitOperatingSystem)) { throw 'USB-Audit рассчитан на Windows x64.' }
if (!$administrator -or $PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {
    $systemDir = if ([Environment]::Is64BitProcess) { [Environment]::SystemDirectory }
        else { Join-Path ([Environment]::GetFolderPath('Windows')) 'Sysnative' }
    $powershell = Join-Path $systemDir 'WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    if ($WhatIfPreference) { $arguments += ' -WhatIf' }
    $launch = @{FilePath=$powershell;ArgumentList=$arguments;Wait=$true;PassThru=$true}
    if (!$administrator) { $launch.Verb='RunAs' }
    $exitCode = & { $WhatIfPreference=$false; (Start-Process @launch).ExitCode }
    if ($exitCode -ne 0) { throw "Удаление завершилось с кодом $exitCode." }
    return
}

$app = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'LocalUsbAudit'
$store = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'LocalUsbAudit'
$winPS = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$collector = 'LocalUsbAuditCollector'
$maintenance = 'LocalUsbAuditMaintenance'
$allowedFiles = @('Access.ps1','ArchiveAudit.ps1','Check.ps1','Collector.ps1','DestinationAudit.ps1',
    'Install.ps1','Maintenance.ps1','Report.ps1','TransferAudit.ps1','viewer.html',
    'KernelFileTrace.cs','KernelTransferMatcher.cs','Finalize-UsbAuditReport.ps1','destinations.json','installation.json','installation.json.tmp','setup.lock')

function Assert-PlainPath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        try {
            if ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) {
                throw "В пути обнаружена ссылка или точка повторного анализа: $current"
            }
        } catch [IO.FileNotFoundException] {
        } catch [IO.DirectoryNotFoundException] {
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Assert-AdminOwned([string]$Path) {
    Assert-PlainPath $Path
    $acl = Get-Acl -LiteralPath $Path
    $trustees = @('S-1-5-18','S-1-5-32-544')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustees) {
        throw "Неожиданный владелец: $Path"
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trustees -and
            ([long]$rule.FileSystemRights -band 0xD0156)) { throw "Посторонняя запись разрешена в $Path." }
    }
}

function Get-AppTasks {
    Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object {
        $_.TaskName -in $collector,$maintenance -or $_.TaskName -match '^LocalUsbAudit(?:Report|Final)-S-1-(?:\d+-)+\d+$'
    }
}

function Assert-AppTask($Task) {
    $options = '-NoLogo -NoProfile -NonInteractive'
    $suffix = if ($Task.TaskName -eq $collector) { '-File "' + (Join-Path $app 'Collector.ps1') + '"' }
        elseif ($Task.TaskName -eq $maintenance) { '-File "' + (Join-Path $app 'Maintenance.ps1') + '" -Action Worker' }
        elseif ($Task.TaskName -match '^LocalUsbAuditFinal-(S-1-(?:\d+-)+\d+)$') {
            $reader=$Matches[1]
            if ([string]$Task.Principal.RunLevel -ne 'Limited' -or [string]$Task.Principal.LogonType -ne 'Interactive') {
                throw "Неожиданные права задания $($Task.TaskName)."
            }
            $user=[string]$Task.Principal.UserId
            if ($user -notmatch '^S-1-') {$user=([Security.Principal.NTAccount]::new($user)).Translate([Security.Principal.SecurityIdentifier]).Value}
            if ($user -ne $reader) {throw "Владелец задания $($Task.TaskName) изменился."}
            $options += ' -WindowStyle Hidden'
            '-File "' + (Join-Path $app 'Finalize-UsbAuditReport.ps1') + '" -ReaderSid ' + $reader
        } else {
            $options += ' -WindowStyle Hidden'
            '-File "' + (Join-Path $app 'Report.ps1') + '" -Watch'
        }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or $actions[0].Execute -ine $winPS -or
        $actions[0].Arguments -ine "$options -ExecutionPolicy Bypass $suffix" -or
        $actions[0].WorkingDirectory -ine $app) { throw "У задания $($Task.TaskName) другое действие. Проверьте его назначение." }
}

# Сеанс ядра может пережить завершение задания или потерю установленного .cs.
# Для удаления достаточно одного контроллера ETW с заранее известными именем и GUID.
function Get-UsbTraceState([switch]$Stop) {
    if (!('LocalUsbAudit.UninstallTrace' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace LocalUsbAudit {
    public static class UninstallTrace {
        const string Name = "LocalUsbAuditFileTrace";
        static readonly Guid Owner = new Guid("5ecda003-832f-4ea6-8bac-93747995ed7a");
        [StructLayout(LayoutKind.Explicit, Size=120)]
        struct Properties {
            [FieldOffset(0)] public uint Size;
            [FieldOffset(8)] public ulong Controller;
            [FieldOffset(24)] public Guid Guid;
            [FieldOffset(44)] public uint Flags;
            [FieldOffset(64)] public uint Mode;
            [FieldOffset(112)] public uint FileOffset;
            [FieldOffset(116)] public uint NameOffset;
        }
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
        static extern uint ControlTraceW(ulong session, string name, IntPtr properties, uint control);

        public static bool Owns(Guid guid, uint mode) {
            return guid == Owner && (mode & ~0x00800000u) == 0x100;
        }
        static string Query(IntPtr buf) {
            var p = new Properties {Size=8312, Flags=0x20000, NameOffset=120, FileOffset=4216};
            Marshal.StructureToPtr(p,buf,false);
            uint err=ControlTraceW(0,Name,buf,0);
            if (err==4201) return "Absent";
            if (err!=0) throw new Win32Exception((int)err);
            var actual=(Properties)Marshal.PtrToStructure(buf,typeof(Properties));
            return Owns(actual.Guid,actual.Mode) ? "Owned" : "Foreign";
        }
        public static string Inspect(bool stop) {
            IntPtr buf=Marshal.AllocHGlobal(8312);
            try {
                Marshal.Copy(new byte[8312],0,buf,8312);
                string state=Query(buf);
                if (!stop || state!="Owned") return state;
                bool fresh;
                using (var gate=new Mutex(false,@"Global\UsbAuditKernelTrace-"+Owner.ToString("N"),out fresh)) {
                    if (!fresh) throw new InvalidOperationException("Сборщик USB-Audit ещё удерживает сеанс ETW.");
                    state=Query(buf);
                    if (state!="Owned") return state;
                    // Останавливаем именно проверенный экземпляр, даже если
                    // за это время другой контроллер повторно занял его имя.
                    var actual=(Properties)Marshal.PtrToStructure(buf,typeof(Properties));
                    if (actual.Controller==0) throw new InvalidOperationException("Windows не вернула дескриптор проверенного сеанса ETW.");
                    uint err=ControlTraceW(actual.Controller,null,buf,1);
                    if (err!=0 && err!=4201) throw new Win32Exception((int)err);
                    if (Query(buf)=="Owned") throw new InvalidOperationException("Сеанс ETW USB-Audit продолжает работать.");
                    return "Stopped";
                }
            } finally { Marshal.FreeHGlobal(buf); }
        }
    }
}
'@
    }
    [LocalUsbAudit.UninstallTrace]::Inspect([bool]$Stop)
}

# Снимок пишет сам читатель. Задача без триггеров просит Планировщик использовать его интерактивный токен.
function Invoke-FinalReaderReport {
    [CmdletBinding()]
    param($Task, [bool]$WasRunning, [string]$ApplicationPath, [ValidateRange(1,120)][int]$TimeoutSeconds=60)
    if (!$Task -or !$WasRunning) {
        Write-Warning 'Активный обновитель читателя не обнаружен. Сохраняется последний доступный HTML этого читателя.'
        return
    }
    if ($Task.TaskPath -ne '\' -or $Task.TaskName -notmatch '^LocalUsbAuditReport-(S-1-(?:\d+-)+\d+)$') {
        throw 'Обновитель читателя имеет неизвестное имя или расположение.'
    }
    $readerSid=[Security.Principal.SecurityIdentifier]::new($Matches[1])
    $user=[string]$Task.Principal.UserId
    $principalSid=if ($user -match '^S-1-') { [Security.Principal.SecurityIdentifier]::new($user) }
        else { ([Security.Principal.NTAccount]::new($user)).Translate([Security.Principal.SecurityIdentifier]) }
    if ($principalSid.Value -ne $readerSid.Value -or [string]$Task.Principal.LogonType -ne 'Interactive' -or
        [string]$Task.Principal.RunLevel -ne 'Limited') { throw 'У исходного обновителя другой владелец или уровень запуска.' }
    # Проверка полного пути PowerShell, параметров и рабочего каталога взята из штатного удаления.
    Assert-AppTask $Task
    $appPath=[IO.Path]::GetFullPath($ApplicationPath)
    if ($appPath -ine $Task.Actions[0].WorkingDirectory) { throw 'Каталог завершающего отчёта не совпадает с установленным.' }
    $child=@'
param([Parameter(Mandatory)][string]$ReaderSid)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne $ReaderSid -or
    ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 3 }
$report=Join-Path $PSScriptRoot 'Report.ps1'
$folder=Join-Path $env:LOCALAPPDATA 'LocalUsbAudit\Reports'
$target=Join-Path $folder 'USB-Audit.html'
$signal=Join-Path $folder 'USB-Audit-status.css'
$tag=[guid]::NewGuid().ToString('N')
$draft=Join-Path $folder ('.usb-final-'+$tag+'.html')
$stampFile=Join-Path $folder ('.usb-final-'+$tag+'.css')
function Publish-File($Draft,$Target) {
    if ([IO.File]::Exists($Target)) { [IO.File]::Replace($Draft,$Target,[Management.Automation.Language.NullString]::Value) }
    else { [IO.File]::Move($Draft,$Target) }
}
try {
    # Другой OutputPath отключает режим live. После публикации HTML самодостаточен.
    & $report -OutputPath $draft -NoOpen -RequireComplete | Out-Null
    Publish-File $draft $target
    # Уже открытая вкладка увидит новую версию в течение своего интервала проверки.
    $now=[DateTimeOffset]::UtcNow
    $css=':root{--usb-generation:'+ $now.UtcDateTime.ToFileTimeUtc() +';--usb-heartbeat:'+ $now.ToUnixTimeSeconds() +';--usb-state:ok}'
    [IO.File]::WriteAllText($stampFile,$css,[Text.UTF8Encoding]::new($false))
    Publish-File $stampFile $signal
} finally {
    foreach ($temp in $draft,$stampFile) { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}
'@
    $name='LocalUsbAuditFinal-'+$readerSid.Value
    $helper=Join-Path $appPath 'Finalize-UsbAuditReport.ps1'
    $removeHelper=$false
    $registered=$null
    try {
        Assert-PlainPath $helper
        if ([IO.File]::Exists($helper)) {
            Assert-AdminOwned $helper
            if ([IO.File]::ReadAllText($helper) -cne $child) {throw 'В папке программы уже существует другой сценарий завершения отчёта.'}
        } else {
            # Открытое имя и обычный параметр -File позволяют проверить действие в Планировщике.
            $security=[Security.AccessControl.FileSecurity]::new()
            $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)')
            $handle=[IO.FileStream]::new($helper,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,
                [IO.FileShare]::Read,4096,[IO.FileOptions]::None,$security)
            $removeHelper=$true
            try {
                $writer=[IO.StreamWriter]::new($handle,[Text.UTF8Encoding]::new($true))
                try {$writer.Write($child)} finally {$writer.Dispose()}
            } finally {$handle.Dispose()}
        }
        $service=New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $folder=$service.GetFolder('\')
        $definition=$service.NewTask(0)
        $definition.Principal.UserId=$readerSid.Value
        $definition.Principal.LogonType=3
        $definition.Principal.RunLevel=0
        $definition.Settings.Hidden=$true
        $definition.Settings.DisallowStartIfOnBatteries=$false
        $definition.Settings.StopIfGoingOnBatteries=$false
        $definition.Settings.ExecutionTimeLimit='PT'+$TimeoutSeconds+'S'
        $action=$definition.Actions.Create(0)
        $action.Path=$Task.Actions[0].Execute
        $action.WorkingDirectory=$appPath
        $action.Arguments='-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$helper+'" -ReaderSid '+$readerSid.Value
        # TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE исключает замену существующей задачи и права читателя на её изменение.
        $registered=$folder.RegisterTaskDefinition($name,$definition,18,$readerSid.Value,$null,3,'D:P(A;;GA;;;SY)(A;;GA;;;BA)')
        $before=$registered.LastRunTime
        [void]$registered.Run($null)
        $watch=[Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Milliseconds 200
            if ($registered.LastRunTime -gt $before -and $registered.State -eq 3) {
                if ($registered.LastTaskResult -ne 0) { throw "Код завершения $($registered.LastTaskResult)." }
                Write-Output "Итоговый снимок сохранён для $readerSid."
                return
            }
        } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        throw 'Истекло время ожидания итогового отчёта.'
    } catch {
        Write-Warning "Для $readerSid итоговый снимок не подтверждён. Доступны сохранённый HTML и исходные журналы. $_"
    } finally {
        try {
            if ($registered) {
                try {
                    if ($registered.State -in 2,4) { $registered.Stop(0) }
                } finally { $folder.DeleteTask($name,0) }
            }
        } finally {if ($removeHelper -and [IO.File]::Exists($helper)) {[IO.File]::Delete($helper)}}
    }
}

function Get-AuditText($Security) {
    $value = $Security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
    if ($value) { return $value }
    return 'S:'
}

# Установщик записывает SACL до и после изменения. Более поздние правки администратора сохраняем.
function Restore-DestinationAudit($Folders, [bool]$Apply) {
    foreach ($entry in $Folders) {
        $path = [string]$entry.path
        if ($path -notmatch '^[A-Z]:\\.' -or $path.Substring(2).Contains(':') -or
            [IO.Path]::GetFullPath($path) -ine $path -or !$entry.before -or !$entry.after) {
            throw 'Некорректные настройки папок назначения.'
        }
        Assert-PlainPath $path
        if (![IO.Directory]::Exists($path) -or $entry.before -ceq $entry.after) { continue }
        $audit = [Security.AccessControl.AccessControlSections]::Audit
        $security = [IO.Directory]::GetAccessControl($path,$audit)
        $current = Get-AuditText $security
        if ($current -ceq $entry.before) { continue }
        if ($current -cne $entry.after) {
            if ($Apply) { Write-Warning "Для папки $path сохранены правила аудита, изменённые после установки USB-Audit." }
            continue
        }
        if ($Apply) {
            $security.SetSecurityDescriptorSddlForm([string]$entry.before,$audit)
            [IO.Directory]::SetAccessControl($path,$security)
            if ((Get-AuditText ([IO.Directory]::GetAccessControl($path,$audit))) -cne $entry.before) {
                throw "Не удалось восстановить аудит папки: $path"
            }
            Write-Output "Восстановлены правила аудита: $path"
        }
    }
}

function Remove-CollectorReadGrant([string]$TaskSid) {
    $channel = [Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security')
    try {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($channel.SecurityDescriptor)
        $acl = $descriptor.DiscretionaryAcl
        $changed = $false
        for ($i=$acl.Count-1; $i -ge 0; $i--) {
            $ace = $acl[$i]
            if ($ace.AceType -eq 'AccessAllowed' -and $ace.AceFlags -eq 'None' -and
                $ace.SecurityIdentifier.Value -eq $TaskSid -and $ace.AccessMask -eq 1) {
                $acl.RemoveAce($i)
                $changed=$true
            }
        }
        if ($changed) {
            $channel.SecurityDescriptor = $descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
            $channel.SaveChanges()
        }
    } finally { $channel.Dispose() }
}

$tasks = @(Get-AppTasks)
Assert-PlainPath $app
$marker = Join-Path $app 'installation.json'
if (![IO.File]::Exists($marker)) {
    if ($tasks.Count -or ([IO.Directory]::Exists($app) -and @(Get-ChildItem -Force -LiteralPath $app).Count)) {
        throw "Нет метки installation.json при наличии компонентов. Проверьте $app и задания Планировщика."
    }
    $trace = Get-UsbTraceState
    $pending=$false
    if ($trace -eq 'Owned') {
        if ($PSCmdlet.ShouldProcess('LocalUsbAuditFileTrace','Остановить оставшийся сеанс USB-Audit')) {
            $trace=Get-UsbTraceState -Stop
            if ($trace -eq 'Stopped') { Write-Output 'Остановлен оставшийся сеанс трассировки USB-Audit.' }
            elseif ($trace -notin 'Absent','Foreign') { throw 'Не удалось подтвердить остановку сеанса USB-Audit.' }
        } else { $pending=$true }
    }
    if ($trace -eq 'Foreign') { Write-Warning 'Имя LocalUsbAuditFileTrace занято другим сеансом ETW. Он сохранён.' }
    if ([IO.Directory]::Exists($app)) {
        if ($PSCmdlet.ShouldProcess($app,'Удалить пустой каталог USB-Audit')) {
            Assert-AdminOwned $app
            [IO.Directory]::Delete($app,$false)
        } else { $pending=$true }
    }
    if (!$pending) { Write-Output 'Установленные компоненты USB-Audit отсутствуют.' }
    return
}
Assert-AdminOwned $app
Assert-AdminOwned $marker
$markerText = [IO.File]::ReadAllText($marker)
$config = $markerText | ConvertFrom-Json
$sidOutput = & (Join-Path ([Environment]::SystemDirectory) 'schtasks.exe') /showsid /tn "\$collector"
if ($LASTEXITCODE -ne 0 -or ($sidOutput -join ' ') -notmatch '(S-1-5-87-(?:\d+-){4}\d+)' -or
    $Matches[1] -ne $config.taskSid -or $config.format -cne 'local-usb-audit-v1') {
    throw 'Метка установки или SID сборщика не соответствует USB-Audit.'
}
$files = @(Get-ChildItem -LiteralPath $app -Force)
foreach ($file in $files) {
    if ($file.PSIsContainer -or $file.Name -notin $allowedFiles -or $file.DirectoryName -ine $app) {
        throw "Неизвестный компонент в папке программы: $($file.Name)."
    }
    Assert-PlainPath $file.FullName
}
foreach ($task in $tasks) { Assert-AppTask $task }
$folders = @()
$destinationFile = Join-Path $app 'destinations.json'
$destinationText = $null
if ([IO.File]::Exists($destinationFile)) {
    Assert-AdminOwned $destinationFile
    $destinationText = [IO.File]::ReadAllText($destinationFile)
    $settings = $destinationText | ConvertFrom-Json
    if ($settings.format -cne 'usb-destinations-v1' -or $null -eq $settings.folders) { throw 'Неизвестный формат destinations.json.' }
    $folders = @($settings.folders)
}
Restore-DestinationAudit $folders $false
$trace = Get-UsbTraceState
if ($trace -eq 'Foreign') { Write-Warning 'Имя LocalUsbAuditFileTrace занято другим сеансом ETW. Он будет сохранён.' }
if (!$PSCmdlet.ShouldProcess($app,'Удалить USB-Audit с сохранением журналов, архивов и отчётов')) { return }

$locks = [Collections.Generic.List[IO.FileStream]]::new()
$suspended = [Collections.Generic.List[object]]::new()
$unregistering = $false
try {
    # Порядок совпадает с установкой и обслуживанием. Открытый архивный запрос может завершиться штатно.
    $lockPaths = @(Join-Path $app 'setup.lock')
    $queue = Join-Path $store 'Maintenance'
    $gen = [string]$config.requestGeneration
    if ($gen -and $gen -cnotmatch '^[a-f0-9]{32}$') { throw 'Некорректный идентификатор очереди.' }
    $submitName = if ($gen) { "submit-$gen.lock" } else { 'submit.lock' }
    $lockPaths += (Join-Path $queue $submitName),(Join-Path $queue 'worker.lock')
    foreach ($lockPath in $lockPaths) {
        Assert-PlainPath $lockPath
        if (![IO.File]::Exists($lockPath)) { continue }
        try { $locks.Add([IO.File]::Open($lockPath,'Open','ReadWrite','None')) }
        catch [IO.IOException] { throw 'Установка или обслуживание архива выполняется. Повторите удаление после завершения операции.' }
    }
    # Если закончилась параллельная установка, повторим с её правилами и составом файлов.
    if ([IO.File]::ReadAllText($marker) -cne $markerText -or
        [IO.File]::Exists($destinationFile) -ne ($null -ne $destinationText) -or
        ($null -ne $destinationText -and [IO.File]::ReadAllText($destinationFile) -cne $destinationText)) {
        throw 'Конфигурация изменилась. Повторите удаление.'
    }
    $tasks = @(Get-AppTasks)
    foreach ($task in $tasks) { Assert-AppTask $task }
    $schedule = New-Object -ComObject 'Schedule.Service'
    $schedule.Connect()
    foreach ($task in $tasks) {
        $path='\'+$task.TaskName
        $running=@($schedule.GetRunningTasks(1) | Where-Object { $_.Path -ieq $path }).Count -gt 0
        $suspended.Add([pscustomobject]@{name=$task.TaskName;enabled=$task.State -ne 'Disabled';running=$running})
        [void](Disable-ScheduledTask -InputObject $task)
        if (@($schedule.GetRunningTasks(1) | Where-Object { $_.Path -ieq ('\'+$task.TaskName) }).Count) {
            Stop-ScheduledTask -InputObject $task
        }
    }
    # Ждём завершения процессов задания. Не останавливаем другие экземпляры PowerShell.
    $scriptPattern = '(?i)(?:^|\s)-File\s+"'+[regex]::Escape($app+'\')+'(?:Collector|Maintenance|Report|Finalize-UsbAuditReport)\.ps1"(?:\s|$)'
    $taskPaths = @($tasks | ForEach-Object {'\'+$_.TaskName})
    $until = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $workers = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object {
            $_.ExecutablePath -ieq $winPS -and $_.CommandLine -match $scriptPattern
        })
        # WMI может не вернуть командную строку завершающегося процесса. У самого
        # Планировщика экземпляр задания остаётся виден вплоть до его остановки.
        $instances = @($schedule.GetRunningTasks(1) | Where-Object { $_.Path -in $taskPaths })
        if (!$workers.Count -and !$instances.Count) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $until)
    if ($workers.Count -or $instances.Count) { throw 'Остались запущенные задания или процессы USB-Audit. Повторите удаление после их завершения.' }
    [void](Get-UsbTraceState -Stop)
    foreach ($ui in @(Get-Process -Name 'USB-Audit' -ErrorAction SilentlyContinue)) {
        if ($ui.MainWindowTitle -cne 'Журнал USB' -or !$ui.Path) { continue }
        if ([Reflection.AssemblyName]::GetAssemblyName($ui.Path).Name -ine 'USB-Audit') { continue }
        if (!$ui.CloseMainWindow() -or !$ui.WaitForExit(5000)) { throw 'Закройте открытое окно «Журнал USB» и повторите удаление.' }
    }
    # Сборщик и обновители остановлены. Завершаем отчёт с правами его читателя,
    # пока установленный шаблон и Report.ps1 ещё доступны.
    foreach ($task in $tasks) {
        if ($task.TaskName -notlike 'LocalUsbAuditReport-*') {continue}
        $prior=$suspended | Where-Object {$_.name -eq $task.TaskName} | Select-Object -First 1
        Invoke-FinalReaderReport $task ([bool]$prior.running) $app
    }
    $unregistering = $true
    foreach ($task in $tasks) { Unregister-ScheduledTask -InputObject $task -Confirm:$false }
    Restore-DestinationAudit $folders $true
    Remove-CollectorReadGrant $config.taskSid
    if (@(Get-AppTasks).Count) { throw 'В Планировщике остались задания USB-Audit.' }
    foreach ($file in $files) {
        if ($file.Name -in 'setup.lock','installation.json') { continue }
        Assert-PlainPath $file.FullName
        Remove-Item -LiteralPath $file.FullName -Force
    }
    # Проверяем каталог повторно, пока удерживаем блокировку установки. Новый
    # посторонний файл должен пережить отказ, а метка — остаться для повторного запуска.
    $unexpected = @(Get-ChildItem -LiteralPath $app -Force | Where-Object {
        $_.PSIsContainer -or $_.Name -notin 'setup.lock','installation.json'
    })
    if ($unexpected.Count) { throw "При удалении в каталоге программы появился компонент: $($unexpected[0].Name). Метка установки сохранена." }
} catch {
    # Ошибка остановки ETW или занятого окна не должна оставлять рабочую
    # установку с отключёнными заданиями. После начала снятия регистрации
    # сохраняем метку для безопасного повторного запуска удаления.
    if (!$unregistering) {
        foreach ($prior in $suspended) {
            if (!$prior.enabled) { continue }
            try {
                [void](Enable-ScheduledTask -TaskName $prior.name -TaskPath '\')
                if ($prior.running) { Start-ScheduledTask -TaskName $prior.name -TaskPath '\' }
            } catch { Write-Warning "Не удалось возобновить задание $($prior.name): $_" }
        }
    }
    throw
} finally { foreach ($handle in $locks) { $handle.Dispose() } }

$setupPath = Join-Path $app 'setup.lock'
if ([IO.File]::Exists($setupPath)) { Remove-Item -LiteralPath $setupPath -Force }
$markerBytes=[IO.File]::ReadAllBytes($marker)
$markerSecurity=[IO.File]::GetAccessControl($marker)
Remove-Item -LiteralPath $marker -Force
# Удаляем только пустой проверенный каталог. Вложенные каталоги не обходятся.
try { [IO.Directory]::Delete($app,$false) }
catch {
    # Последнее окно гонки — между снятием метки и удалением каталога. Если,
    # например, другой процесс успел создать файл, возвращаем метку с её ACL.
    if ([IO.Directory]::Exists($app) -and ![IO.File]::Exists($marker)) {
        Assert-AdminOwned $app
        $recovery=[IO.FileStream]::new($marker,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,
            [IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough,$markerSecurity)
        try { $recovery.Write($markerBytes,0,$markerBytes.Length) } finally { $recovery.Dispose() }
        $sections=[Security.AccessControl.AccessControlSections]'Owner,Group,Access'
        $restoredAcl=[Security.AccessControl.FileSecurity]::new()
        $restoredAcl.SetSecurityDescriptorBinaryForm($markerSecurity.GetSecurityDescriptorBinaryForm(),$sections)
        [IO.File]::SetAccessControl($marker,$restoredAcl)
    }
    throw
}
Write-Output "USB-Audit удалён. Журналы и архивы сохранены в $store\Data. HTML-отчёты сохранены в профилях пользователей."
