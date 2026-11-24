#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string[]]$ReaderUser = @(),
    [Alias('AdministratorSid')][string]$AdminSid,
    [string[]]$DestinationFolders,
    [switch]$EnableHotPlugSecureOpen
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {
    throw 'Запустите 64-разрядную Windows PowerShell 5.1 с правами администратора.'
}
. (Join-Path $PSScriptRoot 'Access.ps1')
. (Join-Path $PSScriptRoot 'ArchiveAudit.ps1')
. (Join-Path $PSScriptRoot 'DestinationAudit.ps1')
$sourceFiles = 'ArchiveAudit.ps1','DestinationAudit.ps1','TransferAudit.ps1','Access.ps1','Collector.ps1','Report.ps1','viewer.html','Maintenance.ps1','Check.ps1','Install.ps1','KernelFileTrace.cs','KernelTransferMatcher.cs'
foreach ($name in $sourceFiles) {
    $inputFile = Join-Path $PSScriptRoot $name
    if (!(Test-Path -LiteralPath $inputFile -PathType Leaf)) { throw "В комплекте отсутствует $name" }
    Assert-RegularPath $inputFile
}
if (([IO.DriveInfo]::new([IO.Path]::GetPathRoot($store))).DriveFormat -ne 'NTFS') { throw 'Для защищённого журнала требуется локальный том NTFS.' }
$readerSids = foreach ($reader in $ReaderUser) {
    if ($reader -match '^S-1-') {
        $sid = [Security.Principal.SecurityIdentifier]::new($reader)
        [void]$sid.Translate([Security.Principal.NTAccount])
        $sid
    } else {
        ([Security.Principal.NTAccount]::new($reader)).Translate([Security.Principal.SecurityIdentifier])
    }
}
$fresh = !(Test-Path -LiteralPath $meta)
function Get-CollectorTaskSid {
    $sidLine = & "$env:SystemRoot\System32\schtasks.exe" /showsid /tn "\$collectorTask"
    if ($LASTEXITCODE -ne 0 -or ($sidLine -join ' ') -notmatch '(S-1-5-87-(?:\d+-){4}\d+)') {
        throw 'Планировщик не вернул уникальный SID задания.'
    }
    return $Matches[1]
}
function Assert-RetainedAcl([string]$Path,[string]$Rules) {
    Assert-RegularPath $Path
    $actual=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $kind=if ([IO.Directory]::Exists($Path)) {[Security.AccessControl.DirectorySecurity]} else {[Security.AccessControl.FileSecurity]}
    $expected=$kind::new()
    $expected.SetSecurityDescriptorSddlForm($Rules)
    if (!$actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin 'S-1-5-18','S-1-5-32-544') {
        throw "Недоверенный владелец или права сохранённой установки: $Path"
    }
    # Порядок независимых разрешающих ACE может меняться при сохранении Windows.
    $sets=foreach($acl in $actual,$expected) {
        $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
        (@(foreach($ace in $raw.DiscretionaryAcl) {
            $bytes=[byte[]]::new($ace.BinaryLength)
            $ace.GetBinaryForm($bytes,0)
            [Convert]::ToBase64String($bytes)
        }) | Sort-Object) -join '|'
    }
    if ($sets[0] -cne $sets[1]) { throw "Права отличаются от сохранённой установки USB-Audit: $Path" }
}
function Assert-RetainedStore($Group,[string]$TaskSid) {
    # При удалении 1.1.2 installation.json удалялся, но история и её группа оставались.
    # Признаём только исходную структуру с правом дописывания у уникального SID сборщика.
    foreach ($pair in @(
        @{path=$store;names=@('Data','Maintenance','State')},
        @{path=$data;names=@('Active','Archive')},
        @{path=(Split-Path $active);names=@('events.jsonl')}
    )) {
        Assert-RegularPath $pair.path
        $names=@(Get-ChildItem -LiteralPath $pair.path -Force | Select-Object -ExpandProperty Name)
        if ($names.Count -ne $pair.names.Count -or @(Compare-Object $pair.names $names).Count) {
            throw "В каталоге нет ожидаемой структуры USB-Audit: $($pair.path)"
        }
    }
    Assert-RegularPath $active
    $readersId=$Group.SID.Value
    $custodians=@((Get-Acl -LiteralPath $active).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
        ForEach-Object { $_.IdentityReference.Value } | Where-Object { $_ -match '^S-1-5-21-' -and $_ -ne $readersId } | Sort-Object -Unique)
    if ($custodians.Count -ne 1) { throw 'Не удалось распознать права владельца сохранённой истории USB-Audit.' }
    $prior=@{readersSid=$readersId;custodianSid=$custodians[0];taskSid=$TaskSid}
    $browse="(A;;0x1200a9;;;$readersId)(A;;0x1200a9;;;$($prior.custodianSid))(A;;0x1200a9;;;$TaskSid)"
    foreach ($dir in $store,$data,(Split-Path $active),$archives) { Assert-RetainedAcl $dir "$baseAcl$browse" }
    Assert-RetainedAcl $active (Get-FileRules $prior -WritableLog)
    Assert-RetainedAcl $stage $baseAcl
    Assert-RetainedAcl (Join-Path $store 'State') "$baseAcl(A;;0x1200ab;;;$TaskSid)(A;OIIO;0x1301bf;;;$TaskSid)"
    foreach ($archive in @(Get-ChildItem -LiteralPath $archives -Force)) {
        if ($archive.PSIsContainer -or $archive.Name -cnotmatch '\Ausb-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.jsonl\z') { throw "Неизвестный объект в сохранённом архиве: $($archive.Name)" }
        Assert-RetainedAcl $archive.FullName (Get-FileRules $prior)
    }
}
$resumeHistory=$false
# При чистой установке выбор обязателен. Пароль администратора установщику не передаётся.
if ($AdminSid) { [void](Get-SelectedLocalAdmin $AdminSid) }
elseif ($fresh) { throw 'При первой установке выберите администратора в окне программы или укажите -AdminSid.' }
if ($fresh) {
    $retainedGroup=Get-LocalGroup -Name $readersName -ErrorAction SilentlyContinue
    if ($retainedGroup -and [IO.File]::Exists($active)) {
        Assert-RetainedStore $retainedGroup (Get-CollectorTaskSid)
        $resumeHistory=$true
    }
    foreach ($path in @($app,$store)) {
        if ($path -eq $store -and $resumeHistory) { continue }
        Assert-RegularPath $path
        if (Test-Path -LiteralPath $path) {
            $owner = [IO.Directory]::GetAccessControl($path).GetOwner([Security.Principal.SecurityIdentifier]).Value
            $unexpected = @(Get-ChildItem -LiteralPath $path -Force | Where-Object {
                $path -ne $app -or $_.Name -notin 'installation.json.tmp','setup.lock'
            })
            if ($owner -notin 'S-1-5-18','S-1-5-32-544' -or $unexpected.Count) {
                throw "Уже существует каталог без метки установки: $path"
            }
        }
    }
    foreach ($task in $collectorTask,$controlTask) {
        if (Get-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction SilentlyContinue) { throw "Уже существует задание $task" }
    }
    if ($retainedGroup -and !$resumeHistory) {
        throw "Группа $readersName уже существует без метки установки. Установка остановлена."
    }
}
$sourceId = 'local-usb-audit-v1'
$adminPath = "$baseAcl(A;OICI;0x1200a9;;;AU)"
Set-GuardedDirectory $app $adminPath
Set-GuardedFile (Join-Path $app 'setup.lock') $baseFile
$setupLock = Enter-FileLock (Join-Path $app 'setup.lock')
function Save-Config($NewConfig) {
    $temp = "$meta.tmp"
    Set-GuardedFile $temp "$baseFile(A;;FR;;;AU)"
    [IO.File]::WriteAllText($temp,($NewConfig | ConvertTo-Json),$utf8)
    if ([IO.File]::Exists($meta)) {
        [IO.File]::Replace($temp,$meta,[Management.Automation.Language.NullString]::Value,$false)
    } else { [IO.File]::Move($temp,$meta) }
}
try {
  if (![IO.File]::Exists($meta)) {
    Save-Config @{format=$sourceId}
  } else {
    Assert-RegularPath $meta
    $metaOwner = [IO.File]::GetAccessControl($meta).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($metaOwner -notin 'S-1-5-18','S-1-5-32-544') { throw 'Недоверенный владелец метки установки.' }
    foreach ($rule in ([IO.File]::GetAccessControl($meta).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin 'S-1-5-18','S-1-5-32-544' -and
            ([long]$rule.FileSystemRights -band 0xD0116)) { throw 'Посторонняя учётная запись может изменять метку установки.' }
    }
    $previous = Get-Content -LiteralPath $meta -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($previous.format -ne $sourceId) { throw 'Каталог используется другой установкой.' }
  }
    if (!$AdminSid) {
        if ($previous.custodianMode -ne 'ExistingAdmin') { throw 'Для перехода со старой версии выберите существующую УЗ администратора или укажите -AdminSid.' }
        $AdminSid = [string]$previous.custodianSid
    }
    $custodian = Get-SelectedLocalAdmin $AdminSid
    $c = $custodian.SID.Value
    $account = $custodian.SID.Translate([Security.Principal.NTAccount]).Value
    # Прежние версии давали выбранному SID прямую запись. Для них тоже создаём
    # новую очередь: ACL уже открытого старого дескриптора действует до его закрытия.
    $roleChanged = $previous.custodianMode -ne 'ExistingAdmin' -or $previous.custodianSid -ne $c -or
        $previous.requestAuthority -cne 'ElevatedAdministrators'
    # Отдельная очередь при каждом новом назначении. Открытый ранее файл запроса
    # относится к прежней очереди даже после смены NTFS-разрешений.
    Set-RequestPaths $previous
    $oldQueue = if ($roleChanged -and $previous.custodianSid) { @($requestFile,$responseFile,$intentFile,$submitFile) }
    $generation = if ($roleChanged) { [guid]::NewGuid().ToString('N') } else { $previous.requestGeneration }
    $restartPriorCollector = $false
    $oldSubmitPath = $submitFile
    if ($previous.custodianSid -and [IO.File]::Exists($oldSubmitPath)) {
        # Берём замки в порядке клиента: сначала отправка, затем обработчик.
        # Пока предыдущая команда выполняется, Планировщик продолжает её обслуживать.
        Assert-RegularPath $oldSubmitPath
        try { $lockedSubmit = Enter-FileLock $oldSubmitPath 12 }
        catch [IO.IOException] { throw 'Пользователь выполняет обслуживание архива. После завершения команды повторите установку.' }
    }
    $priorMaintenance = Get-ScheduledTask -TaskPath '\' -TaskName $controlTask -ErrorAction SilentlyContinue
    if ($priorMaintenance -and $priorMaintenance.State -eq 'Running') { throw 'Дождитесь окончания обслуживания архива.' }
    if ($priorMaintenance) {
        # На старой версии worker читает настройку при старте. Сначала запрещаем
        # новые запуски, затем проверяем уже запущенные экземпляры Планировщика.
        [void](Disable-ScheduledTask -InputObject $priorMaintenance)
        $scheduler = New-Object -ComObject 'Schedule.Service'
        $scheduler.Connect()
        $inFlight = @($scheduler.GetRunningTasks(1) | Where-Object { $_.Path -ieq ("\$controlTask") })
        if ($inFlight.Count) {
            if ($priorMaintenance.State -ne 'Disabled') { [void](Enable-ScheduledTask -InputObject $priorMaintenance) }
            throw 'Обслуживание архива уже выполняется. Дождитесь его завершения и повторите установку.'
        }
    }
    $workerLock = Join-Path $stage 'worker.lock'
    if (Test-Path -LiteralPath $workerLock) {
        Assert-RegularPath $workerLock
        $lockedWorker = Enter-FileLock $workerLock
    }
    $priorCollector = Get-ScheduledTask -TaskPath '\' -TaskName $collectorTask -ErrorAction SilentlyContinue
    if ($priorCollector -and $priorCollector.State -eq 'Running') {
        $restartPriorCollector = $true
        Stop-ScheduledTask -InputObject $priorCollector
        $stopUntil = [DateTime]::UtcNow.AddSeconds(30)
        while ((Get-ScheduledTask -TaskPath '\' -TaskName $collectorTask).State -eq 'Running') {
            if ([DateTime]::UtcNow -ge $stopUntil) { throw 'Не удалось остановить старый сборщик.' }
            Start-Sleep -Milliseconds 200
        }
    }
    if ($priorCollector -and [IO.File]::Exists((Join-Path $app 'KernelFileTrace.cs'))) {
        # Планировщик мог завершить старый процесс до его finally. Используем
        # реализацию из устанавливаемого комплекта, проверяющую GUID ETW-сеанса.
        if (!('UsbAuditKernelTrace' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'KernelFileTrace.cs') }
        [UsbAuditKernelTrace]::StopOrphaned('LocalUsbAuditFileTrace')
    }
    $readers = Get-LocalGroup -Name $readersName -ErrorAction SilentlyContinue
    if (!$readers -and $previous.readersSid) { throw 'Исходная группа читателей отсутствует. Проверьте её SID до обновления.' }
    if (!$readers) { $readers = New-LocalGroup -Name $readersName -Description 'Local USB Audit read and export' }
    $r = $readers.SID.Value
    if ($previous.readersSid -and $r -ne $previous.readersSid) { throw 'SID группы читателей изменился.' }
    $w = Get-CollectorTaskSid
    # Задание читает сценарии с собственным SID, в том числе при ограниченном токене службы.
    Set-GuardedDirectory $app "$adminPath(A;OICI;0x1200a9;;;$w)"
    $config = [ordered]@{format=$sourceId; custodianMode='ExistingAdmin'; custodianAccount=$account;
        custodianSid=$c; requestGeneration=$generation; requestAuthority='ElevatedAdministrators'; readersSid=$r; taskSid=$w}
    Set-RequestPaths $config
    $memberSids = [LocalUsbAudit.LocalAdminGroup]::DirectMemberSids($readers.Name)
    foreach ($readerSid in $readerSids) {
        if (!$memberSids.Contains($readerSid.Value)) {
            Add-LocalGroupMember -SID $readers.SID -Member $readerSid.Value
            [void]$memberSids.Add($readerSid.Value)
        }
    }
    $browse = "(A;;0x1200a9;;;$r)(A;;0x1200a9;;;$c)(A;;0x1200a9;;;$w)"
    foreach ($dir in $store,$data,(Split-Path $active),$archives) { Set-GuardedDirectory $dir "$baseAcl$browse" }
    # Сборщик заменяет свои контрольные точки и дописывает активный журнал.
    $stateRule = "(A;;0x1200ab;;;$w)(A;OIIO;0x1301bf;;;$w)"
    Set-GuardedDirectory (Join-Path $store 'State') "$baseAcl$stateRule"
    Set-GuardedFile $lockFile "$baseFile(A;;0x12019f;;;$w)"
    Set-GuardedFile $active (Get-FileRules $config -WritableLog)
    # Наследуемый SACL защищает каталог; существующие и перемещаемые архивы
    # также проверяем отдельно, поскольку NTFS может сохранить прежний SACL при перемещении.
    Set-ArchiveAuditRule -Path $archives -Directory
    foreach ($archive in @(Get-ChildItem -LiteralPath $archives -File -Filter 'usb-*.jsonl')) {
        if ($archive.Name -cmatch '\Ausb-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.jsonl\z') {
            if ($oldQueue -or $resumeHistory) { Set-GuardedFile $archive.FullName (Get-FileRules $config) }
            Set-ArchiveAuditRule -Path $archive.FullName
        }
    }
    if ($oldQueue) {
        # Отзываем у прежней УЗ прямые права на служебные файлы старого назначения.
        foreach ($oldPath in $oldQueue) {
            if ($lockedSubmit -and $oldPath -eq $oldSubmitPath) { continue }
            if ([IO.File]::Exists($oldPath)) { Set-GuardedFile $oldPath $baseFile }
        }
    }
    # Файл запроса, замок и результат доступны SYSTEM и повышенному администратору.
    # Обычный сеанс выбранной УЗ сохраняет право чтения журналов, но не записи команд.
    Set-GuardedDirectory $stage $baseAcl
    Set-GuardedFile $requestFile $baseFile
    if (!$lockedSubmit -or $oldSubmitPath -ne $submitFile) {
        Set-GuardedFile $submitFile $baseFile
    }
    Set-GuardedFile $responseFile $baseFile
    Set-GuardedFile $intentFile $baseFile
    if (!$lockedWorker) {
        Set-GuardedFile $workerLock $baseFile
        $lockedWorker = Enter-FileLock $workerLock
    }
    foreach ($file in $sourceFiles) {
        $source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $file))
        $dest = Join-Path $app $file
        Assert-RegularPath $dest
        if ($source -ine $dest) {
            $temp = $dest + '.setup.tmp'
            Assert-RegularPath $temp
            [IO.File]::Copy($source,$temp,$true)
            if ([IO.File]::Exists($dest)) { [IO.File]::Replace($temp,$dest,[Management.Automation.Language.NullString]::Value,$false) }
            else { [IO.File]::Move($temp,$dest) }
        }
    }
    # Добавляем к разрешениям журнала Security чтение для SID сборщика.
    $eventLog = [Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security')
    try {
        $security = [Security.AccessControl.CommonSecurityDescriptor]::new($false,$false,$eventLog.SecurityDescriptor)
        $sid = [Security.Principal.SecurityIdentifier]::new($w)
        $exists = $security.DiscretionaryAcl | Where-Object {
            $_.SecurityIdentifier -eq $sid -and $_.AceQualifier -eq 'AccessAllowed' -and ($_.AccessMask -band 1)
        }
        if (!$exists) {
            $security.DiscretionaryAcl.AddAccess([Security.AccessControl.AccessControlType]::Allow,$sid,1,
                [Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None)
            $eventLog.SecurityDescriptor = $security.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
            $eventLog.SaveChanges()
        }
    } finally { $eventLog.Dispose() }
    foreach ($id in '0CCE9245','0CCE9248') {
        & "$env:SystemRoot\System32\auditpol.exe" /set "/subcategory:{$id-69AE-11D9-BED3-505054503030}" /success:enable | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Не удалось включить аудит $id." }
    }
    # Файловый аудит действует на объекты с подходящими SACL. Отказы нужны для 4656
    # при попытках записи или удаления, успешный доступ также даёт события 4663.
    & "$env:SystemRoot\System32\auditpol.exe" /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось включить аудит доступа к файлам.' }
    # При отказе Windows 10/11 в открытии архива журнал 4656 требует также
    # отказов в подкатегории «Операции с дескрипторами». Её аудиты успеха сохраняем.
    & "$env:SystemRoot\System32\auditpol.exe" /set '/subcategory:{0CCE9223-69AE-11D9-BED3-505054503030}' /failure:enable | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось включить регистрацию отказов при открытии архива.' }
    Set-UsbDestinationAudit -AppDirectory $app -Paths $DestinationFolders
    if (![Diagnostics.EventLog]::SourceExists($opsSource)) { New-EventLog -LogName Application -Source $opsSource }
    if ([Diagnostics.EventLog]::LogNameFromSourceName($opsSource,'.') -ne 'Application') { throw 'Источник журнала Windows занят.' }
    $pwshFlags = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '
    $action = New-ScheduledTaskAction -Execute $psExe -Argument ($pwshFlags + '"' + (Join-Path $app 'Collector.ps1') + '"') -WorkingDirectory $app
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount -RunLevel Limited -ProcessTokenSidType Unrestricted
    $options = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    $boot = New-ScheduledTaskTrigger -AtStartup
    [void](Register-ScheduledTask -TaskName $collectorTask -Action $action -Trigger $boot -Principal $taskPrincipal -Settings $options -Force)
    $adminPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $worker = New-ScheduledTaskAction -Execute $psExe -Argument ($pwshFlags + '"' + (Join-Path $app 'Maintenance.ps1') + '" -Action Worker') -WorkingDirectory $app
    $workerOptions = New-ScheduledTaskSettingsSet -Disable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    [void](Register-ScheduledTask -TaskName $controlTask -Action $worker -Principal $adminPrincipal -Trigger $boot -Settings $workerOptions -Force)
    $sched = New-Object -ComObject 'Schedule.Service'
    $sched.Connect()
    $registered = $sched.GetFolder('\').GetTask($controlTask)
    # Задачу может вызвать только защищённый повышенный процесс или SYSTEM.
    $registered.SetSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)",0)
    # Задача начинает принимать запросы только после публикации новой конфигурации.
    [void](Get-SelectedLocalAdmin $c)
    Save-Config $config
    if ($lockedSubmit) {
        $lockedSubmit.Dispose()
        $lockedSubmit = $null
        Set-GuardedFile $oldSubmitPath $baseFile
    }
    [void](Enable-ScheduledTask -TaskPath '\' -TaskName $controlTask)
    $lockedWorker.Dispose()
    $lockedWorker = $null
    $start = [DateTime]::UtcNow
    Start-ScheduledTask -TaskName $collectorTask
    $restartPriorCollector = $false
    $ready = $false
    $deadline = $start.AddSeconds(60)
    do {
        Start-Sleep -Seconds 1
        # Свежая метка подтверждает чтение Security и запись именно процессом сборщика.
        try {
            $rows = Get-Content -LiteralPath $active -Encoding UTF8 -Tail 80 -ErrorAction Stop
            foreach ($line in $rows) {
                if ($line -notmatch '"key"\s*:\s*"ready"') { continue }
                $row = $line | ConvertFrom-Json -ErrorAction Stop
                if ($row.type -eq 'status' -and $row.key -eq 'ready' -and [DateTimeOffset]::Parse($row.time).UtcDateTime -ge $start) {
                    $ready = $true; break
                }
            }
        } catch [IO.IOException] {}
    } until ($ready -or [DateTime]::UtcNow -ge $deadline)
    if (!$ready) {
        throw "Сборщик не подтвердил чтение Security и запись журнала за 60 секунд. Проверьте $app\Check.ps1, состояние задания $collectorTask и последние сообщения в $active. После исправления повторите установку."
    }
    if ($EnableHotPlugSecureOpen) {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Storage'
        if (!(Test-Path -LiteralPath $key)) { [void](New-Item -Path $key -Force) }
        $confirmed = $false
        for ($attempt = 1; $attempt -le 3 -and !$confirmed; $attempt++) {
            [void](New-ItemProperty -LiteralPath $key -Name HotPlugSecureOpen -PropertyType DWord -Value 1 -Force)
            foreach ($delay in 1,2) {
                Start-Sleep -Seconds $delay
                $storage = Get-Item -LiteralPath $key
                $confirmed = $storage.GetValue('HotPlugSecureOpen') -eq 1 -and $storage.GetValueKind('HotPlugSecureOpen') -eq 'DWord'
                if (!$confirmed) { break }
            }
        }
        if (!$confirmed) {
            throw 'Сборщик запущен, но после трёх попыток Windows не сохранила DWORD HotPlugSecureOpen = 1. Проверьте применяемую политику аудита и настройки АРМ. Регистрация операций с файлами требует контрольной проверки.'
        }
    }
    # Отдельный процесс читателя формирует HTML только в его профиле и с его правами.
    $reportFlags = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File '
    $reportFile = Join-Path $app 'Report.ps1'
    $reportAction = New-ScheduledTaskAction -Execute $psExe -Argument ($reportFlags + '"' + $reportFile + '" -Watch') -WorkingDirectory $app
    $reportSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    $reportReaders = @($readerSids | ForEach-Object { if ($_) { $_.Value } })
    # На обновлении сохраняем автообновление и для прежних локальных читателей.
    $reportReaders += @(Get-LocalUser | Where-Object { $memberSids.Contains($_.SID.Value) } | ForEach-Object { $_.SID.Value })
    foreach ($readerId in ($reportReaders | Sort-Object -Unique)) {
        $reportName = 'LocalUsbAuditReport-' + $readerId
        $reportPrincipal = New-ScheduledTaskPrincipal -UserId $readerId -LogonType Interactive -RunLevel Limited
        $logon = New-ScheduledTaskTrigger -AtLogOn -User $readerId
        $existing = Get-ScheduledTask -TaskPath '\' -TaskName $reportName -ErrorAction SilentlyContinue
        if ($existing) {
            $existingActions = @($existing.Actions)
            if ($existingActions.Count -ne 1 -or $existingActions[0].Execute -ine $psExe -or
                $existingActions[0].Arguments -cne $reportAction.Arguments) { throw "Имя задания $reportName занято другим действием." }
            if ($existing.State -eq 'Running') { Stop-ScheduledTask -InputObject $existing }
        }
        [void](Register-ScheduledTask -TaskName $reportName -TaskPath '\' -Action $reportAction -Trigger $logon -Principal $reportPrincipal -Settings $reportSettings -Force)
        $sched.GetFolder('\').GetTask($reportName).SetSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;$readerId)",0)
        try { Start-ScheduledTask -TaskPath '\' -TaskName $reportName -ErrorAction Stop }
        catch { Write-Warning "Задание $reportName создано и запустится при входе читателя. Немедленный запуск не выполнен: $_" }
    }
    Write-Host "Проверено: сборщик читает Security и записывает журнал. Группа для просмотра: $readersName. Проверка: $app\Check.ps1"
    Write-Host "За обслуживание архивов отвечает $account."
    Write-Host 'После добавления в группу читателей выйдите из Windows и войдите снова. Переподключите тестовый СНИ и проверьте запись и чтение файла по имени.'
} finally {
    if ($lockedWorker) { $lockedWorker.Dispose() }
    if ($lockedSubmit) { $lockedSubmit.Dispose() }
    $setupLock.Dispose()
    if ($restartPriorCollector) {
        try { Start-ScheduledTask -TaskName $collectorTask }
        catch { Write-Warning "Не удалось возобновить работу сборщика: $_" }
    }
}
