#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('List','Rotate','Delete','Worker')][string]$Action = 'List',
    [string]$Archive,
    [switch]$InteractiveWindow
)
$ErrorActionPreference = 'Stop'
trap {
    if ($InteractiveWindow) {
        [Console]::Error.WriteLine($_.Exception.Message)
        [Console]::WriteLine('Нажмите Enter, чтобы закрыть окно.')
        try { [void][Console]::ReadLine() } catch {}
        exit 1
    }
    break
}
$savedEnvironment = @{}
try {
# Повышенный процесс не загружает модули и программы из каталогов обычного пользователя.
$sys = [Environment]::SystemDirectory
$win = [Environment]::GetFolderPath('Windows')
$pf = [Environment]::GetFolderPath('ProgramFiles')
$machineEnvironment = @{
    PSModulePath = "$pf\WindowsPowerShell\Modules;$sys\WindowsPowerShell\v1.0\Modules"
    Path = "$sys;$win;$sys\Wbem;$sys\WindowsPowerShell\v1.0"
    SystemRoot = $win; windir = $win; ProgramFiles = $pf
    ProgramData = [Environment]::GetFolderPath('CommonApplicationData'); ComSpec = "$sys\cmd.exe"
}
foreach ($key in $machineEnvironment.Keys) {
    $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key)
    [Environment]::SetEnvironmentVariable($key,$machineEnvironment[$key])
}
. ([IO.Path]::Combine($PSScriptRoot,'Access.ps1'))
. ([IO.Path]::Combine($PSScriptRoot,'ArchiveAudit.ps1'))
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Используйте Windows PowerShell 5.1.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($Action -eq 'Worker' -and $identity -ne 'S-1-5-18') { throw 'Внутренний обработчик запускается Планировщиком.' }
if ($Action -in 'Rotate','Delete') {
    # UAC должен повысить доверенный процесс до обращения к очереди и до любого ввода.
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Обслуживание архива требует повышения прав. Откройте «Архивы» в USB-Audit.exe или запустите Windows PowerShell от имени администратора.'
    }
}
if ($Action -ne 'List') {
    # PowerShell/CodeDOM могут держать вложенные временные каталоги до завершения процесса.
    # Один закрытый каталог на установку обслуживает SYSTEM и повышенных администраторов.
    # Компилятор сам выбирает имена временных файлов. Кэш входит в каталог ПО при демонтаже.
    $compilerDir = Join-Path $stage 'Compiler'
    Set-GuardedDirectory $compilerDir $baseAcl
    foreach ($key in 'TEMP','TMP') {
        $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key)
        [Environment]::SetEnvironmentVariable($key,$compilerDir)
    }
}
$config = Get-Content -LiteralPath $meta -Raw -Encoding UTF8 | ConvertFrom-Json
Set-RequestPaths $config
$archivePattern = '\Ausb-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.jsonl\z'
function Write-Ops([int]$Id,[string]$Message) {
    Write-EventLog -LogName Application -Source $opsSource -EntryType Information -EventId $Id -Message $Message -ErrorAction Stop
}
function Read-Message([string]$Path) {
    # На время чтения запрещаем запись, чтобы разобрать целый запрос.
    $file = [IO.File]::Open($Path,'Open','Read',([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
    try {
        if ($file.Length -eq 0) { return $null }
        if ($file.Length -gt 8192) { throw [IO.InvalidDataException]::new('Служебное сообщение слишком велико.') }
        $reader = [IO.StreamReader]::new($file,$utf8,$true)
        try {
            $raw = $reader.ReadToEnd()
            try { $msg = $raw | ConvertFrom-Json -ErrorAction Stop } catch { throw [IO.InvalidDataException]::new('Повреждено служебное сообщение.') }
            if (!$msg -or $msg -is [array] -or ([string]$msg.id -cnotmatch '^[0-9a-f]{32}$')) {
                throw [IO.InvalidDataException]::new('Повреждён номер служебного запроса.')
            }
            return $msg
        } finally { $reader.Dispose() }
    } finally { $file.Dispose() }
}
function Read-Tolerant([string]$Path) {
    for ($i=0; $i -lt 15; $i++) {
        try { return Read-Message $Path }
        catch [IO.InvalidDataException] {
            Write-Warning $_.Exception.Message
            return $null
        } catch [IO.IOException] {
            if ($i -eq 14) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
}
function Save-Message([string]$Path,$Message,[switch]$Atomic) {
    # SYSTEM атомарно заменяет результат и отметку о начатом удалении.
    # Ответственный записывает запрос в заранее созданный файл текущего назначения.
    $output = if ($Atomic) { $Path + '.tmp' } else { $Path }
    $mode = if ($Atomic) { [IO.FileMode]::Create } else { [IO.FileMode]::Open }
    $bytes = $utf8.GetBytes(($Message | ConvertTo-Json -Compress))
    for ($i=0; $i -lt 15; $i++) {
        try { $handle = [IO.File]::Open($output,$mode,'Write','None'); break }
        catch [IO.IOException] { if ($i -eq 14) { throw }; Start-Sleep -Milliseconds 100 }
    }
    try {
        $handle.SetLength(0)
        $handle.Write($bytes,0,$bytes.Length)
        $handle.Flush($true)
    } finally { $handle.Dispose() }
    if ($Atomic) { [IO.File]::Replace($output,$Path,[Management.Automation.Language.NullString]::Value,$false) }
}
function Complete-Pending([IO.FileInfo]$Pending) {
    $leaf = $Pending.Name.Substring(0,$Pending.Name.Length - '.pending'.Length)
    if ($leaf -cnotmatch $archivePattern) { throw 'Некорректное имя промежуточного архива.' }
    $dest = Join-Path $archives $leaf
    Assert-RegularPath $Pending.FullName
    Assert-RegularPath $dest
    Set-GuardedFile $Pending.FullName (Get-FileRules $config)
    Set-ArchiveAuditRule -Path $Pending.FullName
    [IO.File]::Move($Pending.FullName,$dest)
}
function Get-CustodianAccount($Settings) {
    # Разрешаем имя заново по SID: переименование пользователя не передаёт полномочия тёзке.
    $sid = [Security.Principal.SecurityIdentifier]::new([string]$Settings.custodianSid)
    $name = $sid.Translate([Security.Principal.NTAccount]).Value
    if (!$sid.IsAccountSid() -or !$name.StartsWith(([Environment]::MachineName+'\'),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Назначенная локальная учётная запись больше недоступна.'
    }
    return $name
}
function Confirm-JobActor($Job,$Settings) {
    # Старая установка использовала отдельную УЗ и одну защищённую очередь.
    # В новой каждая запись связана с выбранным SID и поколением его назначения.
    if (!$Settings.custodianMode) { return }
    if ($Settings.custodianMode -cne 'ExistingAdmin' -or $Settings.requestAuthority -cne 'ElevatedAdministrators' -or
        ([string]$Settings.requestGeneration -cnotmatch '\A[0-9a-f]{32}\z') -or
        [string]$Job.actorSid -cne [string]$Settings.custodianSid -or
        [string]$Job.generation -cne [string]$Settings.requestGeneration) {
        throw 'Запрос относится к другому назначению ответственного.'
    }
    [void](Get-SelectedLocalAdmin ([string]$Settings.custodianSid))
}
function Invoke-Worker {
    if ($identity -ne 'S-1-5-18') { throw 'Внутренний обработчик запускается Планировщиком.' }
    $exclusive = Enter-FileLock (Join-Path $stage 'worker.lock')
    try {
        # Установщик использует тот же замок при смене ответственного.
        # После захвата заново читаем назначение и выбираем его очередь.
        $config = Get-Content -LiteralPath $meta -Raw -Encoding UTF8 | ConvertFrom-Json
        Set-RequestPaths $config
        foreach ($pending in @(Get-ChildItem -LiteralPath $stage -File -Filter '*.pending')) { Complete-Pending $pending }
        $job = Read-Tolerant $requestFile
        if (!$job) { return }
        $id = [string]$job.id
        if ($id -cnotmatch '^[0-9a-f]{32}$') { throw 'Некорректный номер запроса.' }
        $old = Read-Tolerant $responseFile
        if ($old -and $old.id -ceq $id) { return }
        $status = 'error'
        $message = ''
        $auditAction = if ($job.action -eq 'Delete') { 'Удаление архива' } else { 'Закрытие журнала' }
        $auditName = ''; $auditAccount = ''; $auditSid = ''
        try {
            $name = [string]$job.archive
            if ($name -cnotmatch $archivePattern) { throw 'Некорректное имя архива.' }
            $auditName = $name
            $target = Join-Path $archives $name
            Assert-RegularPath $target
            Confirm-JobActor $job $config
            $auditAccount = Get-CustodianAccount $config
            $auditSid = [string]$config.custodianSid
            $actor = "$auditAccount [$auditSid]"
            switch -CaseSensitive ([string]$job.action) {
                'Rotate' {
                    if (!$name.EndsWith("-$id.jsonl",[StringComparison]::Ordinal)) { throw 'Имя архива не соответствует запросу.' }
                    Write-Ops 100 "Запрошено закрытие журнала. Сотрудник: $actor. Запрос: $id. Архив: $name"
                    if (![IO.File]::Exists($target)) {
                        $guard = Enter-FileLock $lockFile
                        try {
                            Assert-RegularPath $active
                            $next = Join-Path $stage 'next.journal'
                            Set-GuardedFile $next (Get-FileRules $config -WritableLog)
                            if ((Get-Item -LiteralPath $next).Length -ne 0) { throw 'Новый активный журнал должен быть пустым.' }
                            $pending = Join-Path $stage ($name + '.pending')
                            # Одна операция NTFS заменяет активный файл и сохраняет прежний для архива.
                            [IO.File]::Replace($next,$active,$pending,$false)
                            Complete-Pending (Get-Item -LiteralPath $pending)
                        } finally { $guard.Dispose() }
                    }
                    $message = "Архив создан: $name"
                    Write-Ops 101 "$message. Сотрудник: $actor. Запрос: $id."
                }
                'Delete' {
                    $intent = Read-Tolerant $intentFile
                    if ([IO.File]::Exists($target)) {
                        Write-Ops 110 "Запрошено удаление архива: $name. Сотрудник: $actor. Запрос: $id."
                        Save-Message $intentFile @{id=$id;archive=$name;action='Delete'} -Atomic
                        [IO.File]::Delete($target)
                    } elseif (!$intent -or $intent.id -cne $id -or $intent.archive -cne $name -or $intent.action -cne 'Delete') {
                        throw 'Выбранный архив отсутствует.'
                    }
                    $message = "Архив удалён: $name"
                    Write-Ops 111 "$message. Сотрудник: $actor. Запрос: $id."
                }
                default { throw 'Неизвестная операция.' }
            }
            $status = 'ok'
        } catch {
            $message = $_.Exception.Message
            try { Write-Ops 119 "Ошибка обслуживания. Запрос: $id. $message" } catch {}
        }
        $auditResult = if ($status -eq 'ok') { $message } else { "Ошибка обработки: $message" }
        Write-ArchiveOperationRecord $auditAction $auditName $auditResult $id 'worker' $auditAccount $auditSid
        Save-Message $responseFile @{id=$id;status=$status;message=$message} -Atomic
    } finally { $exclusive.Dispose() }
}
if ($Action -eq 'Worker') { Invoke-Worker; return }
if ($Action -eq 'List') {
    Get-ChildItem -LiteralPath $archives -File -Filter 'usb-*.jsonl' |
        Sort-Object Name -Descending | Select-Object Name,Length,LastWriteTime
    return
}
if ($Action -eq 'Delete') {
    if (!$Archive) {
        $files = @(Get-ChildItem -LiteralPath $archives -File -Filter 'usb-*.jsonl' | Sort-Object Name -Descending)
        if (!$files.Count) { throw 'Закрытых архивов нет. Сначала закройте журнал командой Rotate.' }
        $files | Select-Object Name,Length | Out-Host
        $Archive = Read-Host 'Введите полное имя удаляемого архива'
    }
    if ($Archive -cnotmatch $archivePattern) { throw 'Укажите только точное имя закрытого архива из списка.' }
}
if ($Action -eq 'Rotate' -and $PSBoundParameters.ContainsKey('Archive')) { throw 'Для Rotate имя архива формируется автоматически.' }
function Open-CustodianToken([string]$LocalName,[Security.SecureString]$Password) {
    if (!('LocalUsbAudit.ArchiveLogon' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;
namespace LocalUsbAudit {
    public static class ArchiveLogon {
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern bool LogonUserW(string name, string domain, IntPtr password,
            int type, int provider, out SafeAccessTokenHandle token);

        public static SafeAccessTokenHandle Open(string name, SecureString password) {
            IntPtr buffer = Marshal.SecureStringToGlobalAllocUnicode(password);
            try {
                SafeAccessTokenHandle token;
                // Интерактивный вход проверяет пароль; точка ограничивает поиск локальной базой Windows.
                if (!LogonUserW(name, ".", buffer, 2, 0, out token))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return token;
            } finally { Marshal.ZeroFreeGlobalAllocUnicode(buffer); }
        }
    }
}
'@
    }
    return [LocalUsbAudit.ArchiveLogon]::Open($LocalName,$Password)
}
function Assert-CurrentAssignment($Settings) {
    $current = Get-Content -LiteralPath $meta -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($current.custodianSid -cne $Settings.custodianSid -or $current.custodianMode -cne $Settings.custodianMode -or
        $current.requestGeneration -cne $Settings.requestGeneration -or $current.requestAuthority -cne $Settings.requestAuthority) {
        throw 'Ответственный изменился. Откройте архивы заново и подтвердите операцию.'
    }
}
function Wait-Response([string]$Id,$JobTask,$Settings) {
    $until = [DateTime]::UtcNow.AddMinutes(2)
    $nextRun = [DateTime]::MinValue
    do {
        try { $reply = Read-Tolerant $responseFile } catch [IO.IOException] { $reply = $null }
        if ($reply -and $reply.id -ceq $Id) { return $reply }
        # Планировщик может проигнорировать запуск, пока заканчивается прежний запрос.
        if ([DateTime]::UtcNow -ge $nextRun) {
            Assert-CurrentAssignment $Settings
            if ($JobTask.State -eq 3) { [void]$JobTask.Run($null) }
            $nextRun = [DateTime]::UtcNow.AddSeconds(5)
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $until)
    throw 'Время ожидания истекло. Проверьте журнал «Приложение», источник LocalUsbAuditMaintenance.'
}
function Submit-ArchiveRequest($Settings) {
    $submit = Enter-FileLock $submitFile 120
    try {
        Assert-CurrentAssignment $Settings
        # Очередь доступна SYSTEM и повышенным администраторам. Планировщик получает
        # команду от повышенного процесса; пароль ответственного к этому моменту освобождён.
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $jobTask = $service.GetFolder('\').GetTask($controlTask)
        # Сначала дожидаемся ответа на запрос, оставшийся после перезапуска АРМ.
        $prior = Read-Tolerant $requestFile
        $reply = Read-Tolerant $responseFile
        if ($prior -and (!$reply -or $prior.id -cne $reply.id)) {
            [void](Wait-Response ([string]$prior.id) $jobTask $Settings)
        }
        $id = $operationId
        if ($Action -eq 'Rotate') { $Archive = 'usb-' + [DateTime]::UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'") + "-$id.jsonl" }
        Save-Message $requestFile @{id=$id;action=$Action;archive=$Archive;actorSid=$Settings.custodianSid;generation=$Settings.requestGeneration}
        $response = Wait-Response $id $jobTask $Settings
        if ($response.status -ne 'ok') { throw $response.message }
        Write-Host $response.message
    } finally { $submit.Dispose() }
}
function Invoke-ArchiveOperation($Settings) {
    $account = Get-CustodianAccount $Settings
    if ($Settings.custodianMode -ceq 'ExistingAdmin') { [void](Get-SelectedLocalAdmin ([string]$Settings.custodianSid)) }
    $name = $account.Substring($account.IndexOf('\') + 1)
    Write-Host "Учётная запись: $account. Операция: $Action $Archive"
    $password = Read-Host "Введите пароль $account" -AsSecureString
    try {
        if (!$password -or !$password.Length) { throw 'Для этой операции требуется пароль.' }
        try { $token = Open-CustodianToken $name $password }
        catch { throw "Windows отклонила вход $account. Проверьте пароль и состояние учётной записи. $($_.Exception.GetBaseException().Message)" }
        try {
            # Сравнение SID защищает и от пересоздания УЗ с таким же именем.
            $verified = [Security.Principal.WindowsIdentity]::new($token.DangerousGetHandle())
            try {
                if ($verified.User.Value -cne [string]$Settings.custodianSid) { throw 'SID учётной записи не совпадает с назначенным.' }
            } finally { $verified.Dispose() }
        } finally { $token.Dispose() }
    } catch {
        Write-ArchiveOperationRecord $operationName $Archive 'Проверка учётной записи отклонена' $operationId 'auth'
        throw
    } finally { if ($password) { $password.Dispose() } }
    Submit-ArchiveRequest $Settings
}
# Rotate и Delete проходят одну и ту же проверку, включая запуск от имени ответственного.
$operationId = [guid]::NewGuid().ToString('N')
$operationName = if ($Action -eq 'Delete') { 'Удаление архива' } else { 'Закрытие журнала' }
# Сохраняем запрос до проверки пароля: даже закрытое на этапе ввода окно оставляет след.
Write-ArchiveOperationRecord $operationName $Archive 'Запрошено в программе' $operationId 'requested'
Invoke-ArchiveOperation $config
} finally {
    foreach ($key in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($key,$savedEnvironment[$key])
    }
}
