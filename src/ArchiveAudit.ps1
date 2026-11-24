# Преобразуем только события изменения в каталоге архивов. Эти функции используют установщик,
# служба и программа обслуживания; чтение отчёта не создаёт новых строк аудита архива.
function Get-ArchiveAuditRoots([string]$ArchiveDirectory) {
    $full = [IO.Path]::GetFullPath($ArchiveDirectory).TrimEnd('\')
    $roots = @($full)
    if ('UsbAuditNative' -as [type]) {
        # Security может записать букву, имя тома с GUID либо собственное имя устройства NT.
        $mount = [IO.DirectoryInfo]::new($full)
        while ($mount) {
            $prefix = $mount.FullName.TrimEnd('\') + '\'
            $volume = [UsbAuditNative]::VolumeName($prefix)
            if ($volume) {
                $suffix = $full.Substring($prefix.Length - 1)
                $volumeName = $volume.Substring(4).TrimEnd('\')
                $nt = [UsbAuditNative]::NtName($volumeName)
                $roots += $volume.TrimEnd('\') + $suffix
                if ($nt) { $roots += $nt.TrimEnd('\') + $suffix }
                break
            }
            $mount = $mount.Parent
        }
    }
    return $roots
}

function ConvertFrom-ArchiveSecurityEvent([int]$EventId,$Fields,[bool]$Denied,[string]$ArchiveDirectory) {
    if ($EventId -notin 4656,4663 -or $Fields.ObjectType -ne 'File') { return }
    $path = [string]$Fields.ObjectName
    if (!$path) { return }
    if ($path.StartsWith('\??\')) { $path = '\\?\' + $path.Substring(4) }
    if ($path -match '^\\\\\?\\[a-zA-Z]:\\') { $path = $path.Substring(4) }
    if ($script:archiveScopePath -ne $ArchiveDirectory -or !$script:archiveScopeRoots) {
        $script:archiveScopeRoots = @(Get-ArchiveAuditRoots $ArchiveDirectory)
        $script:archiveScopePath = $ArchiveDirectory
    }
    $relative = $null
    foreach ($prefix in $script:archiveScopeRoots) {
        if ($path.TrimEnd('\') -ieq $prefix) { $relative = ''; break }
        if ($path.StartsWith(($prefix+'\'),[StringComparison]::OrdinalIgnoreCase)) {
            $relative = $path.Substring($prefix.Length+1)
            break
        }
    }
    if ($null -eq $relative -or $relative -match '(^|\\)\.\.?($|\\)') { return }
    if ([string]$Fields.AccessMask -notmatch '\A0x([0-9a-fA-F]{1,8})\z') { return }
    $mask = [convert]::ToUInt32($Matches[1],16)
    $actions = @(
        if ($mask -band 0x10000) { 'Удаление или переименование' }
        if ($mask -band 0x40) { 'Удаление из каталога' }
        if ($mask -band 6) { if ($relative) { 'Запись данных' } else { 'Создание в каталоге' } }
        if ($mask -band 0x110) { 'Изменение атрибутов' }
        if ($mask -band 0xc0000) { 'Изменение разрешений или владельца' }
    )
    if (!$actions.Count) { return }
    # 4656 описывает запрос дескриптора, 4663 — использование права; завершение удаления
    # по одному праву DELETE не доказано (оно нужно и при переименовании).
    $result = if ($Denied) { 'Отказано в доступе' }
              elseif ($EventId -eq 4656) { 'Доступ запрошен и разрешён' }
              else { 'Право доступа использовано' }
    $account = [string]$Fields.SubjectUserName
    if ($Fields.SubjectDomainName) { $account = $Fields.SubjectDomainName + '\' + $account }
    $name = if ($relative) { $relative } else { '(каталог архивов)' }
    return @{archive=$name; path=$path; action=($actions -join ', '); result=$result; account=$account
        actorSid=[string]$Fields.SubjectUserSid; process=[string]$Fields.ProcessName; source='Windows Security'
        eventId=$EventId; accessMask=[string]$Fields.AccessMask}
}

function Test-ArchiveAuditRule($Security,[bool]$Directory) {
    $rules = $Security.GetAuditRules($true,$true,[Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -ne 'S-1-1-0' -or
            ($rule.AuditFlags -band 3) -ne 3 -or ([long]$rule.FileSystemRights -band 0xd0156) -ne 0xd0156 -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { continue }
        if ($Directory -and ($rule.InheritanceFlags -band 3) -ne 3) { continue }
        return $true
    }
    return $false
}

function Set-ArchiveAuditRule([string]$Path,[switch]$Directory) {
    Assert-RegularPath $Path
    $sections = [Security.AccessControl.AccessControlSections]::Audit
    $security = if ($Directory) { [IO.Directory]::GetAccessControl($Path,$sections) }
                else { [IO.File]::GetAccessControl($Path,$sections) }
    if (Test-ArchiveAuditRule $security $Directory.IsPresent) { return }
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ObjectInherit,ContainerInherit' }
               else { [Security.AccessControl.InheritanceFlags]::None }
    # Редактируется только SACL. Существующие правила аудита и разрешения DACL сохраняются.
    $ace = [Security.AccessControl.FileSystemAuditRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]0xd0156,
        $inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AuditFlags]'Success,Failure')
    $security.AddAuditRule($ace)
    if ($Directory) { [IO.Directory]::SetAccessControl($Path,$security) } else { [IO.File]::SetAccessControl($Path,$security) }
}

function Write-ArchiveOperationRecord([string]$Operation,[string]$Name,[string]$Result,[string]$Id,[string]$Phase,
    [string]$Account,[string]$ActorSid) {
    # Рабочий процесс и повышенный клиент используют тот же замок, что и сборщик с ротацией.
    # Постоянный UID этапа исключает повтор результата при восстановлении запроса после сбоя.
    $caller = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if (!$Account) { $Account = $caller.Name; $ActorSid = $caller.User.Value }
        $entry = [ordered]@{type='archiveAudit';time=[DateTime]::UtcNow.ToString('o');uid="archive-$Id-$Phase"
            archive=$Name; path=''; action=$Operation; result=$Result; account=$Account; actorSid=$ActorSid
            process=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName; source='USB-Audit';requestId=$Id;executor=$caller.Name}
        if ($Name) { $entry.path = Join-Path $archives $Name }
    } finally { $caller.Dispose() }
    $bytes = $utf8.GetBytes("`n" + ($entry | ConvertTo-Json -Compress) + "`n")
    $journalGuard = Enter-FileLock $lockFile
    try {
        Assert-RegularPath $active
        $handle = [IO.File]::Open($active,'Open','Write',([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            [void]$handle.Seek(0,[IO.SeekOrigin]::End)
            $handle.Write($bytes,0,$bytes.Length)
            $handle.Flush($true)
        } finally { $handle.Dispose() }
    } finally { $journalGuard.Dispose() }
}

function Read-UsbArchiveInterfaceEvents {
    # Курсор Application независим от Security. При повторной доставке UID сохраняется.
    if (!$state.PSObject.Properties['archiveUiCursor']) {
        $state | Add-Member NoteProperty archiveUiCursor ([long]0)
    }
    $latestQuery=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Application','LogName','*')
    $latestQuery.ReverseDirection=$true
    $tail=[Diagnostics.Eventing.Reader.EventLogReader]::new($latestQuery)
    try {
        $last=$tail.ReadEvent()
        if (!$last) { return $false }
        try { $end=[long]$last.RecordId } finally { $last.Dispose() }
    } finally { $tail.Dispose() }
    $cursor=[long]$state.archiveUiCursor
    if ($cursor -eq $end) { return $false }
    if ($cursor -gt $end) { $cursor=0; Add-Notice 'archive-ui-reset' 'Нумерация журнала Windows «Приложение» началась заново.' }
    $since=([datetimeoffset]::Parse($state.baselineSince)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $xpath="*[System[Provider[@Name='LocalUsbAuditMaintenance'] and (EventID=4101 or EventID=4102 or EventID=4103) and EventRecordID > $cursor and EventRecordID <= $end and TimeCreated[@SystemTime >= '$since']]]"
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new([Diagnostics.Eventing.Reader.EventLogQuery]::new('Application','LogName',$xpath))
    $count=0
    try {
        while ($count -lt 64) {
            $record=$reader.ReadEvent()
            if (!$record) { $state.archiveUiCursor=$end; break }
            try {
                $count++
                # Classic Event Log может добавить Binary после строки ReportEventW.
                $name=if ($record.Properties.Count -ge 1 -and $record.Properties[0].Value -is [string]) { $record.Properties[0].Value }
                if ($name -cmatch '\Ausb-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.jsonl\z') {
                    $sid=if ($record.UserId) { $record.UserId.Value } else { '' }
                    $account=$sid
                    if ($sid) { try { $account=$record.UserId.Translate([Security.Principal.NTAccount]).Value } catch [Security.Principal.IdentityNotMappedException] {} }
                    $result=switch ($record.Id) { 4101 { 'Выбрано удаление в интерфейсе' } 4102 { 'Отменено в окне подтверждения' } 4103 { 'Отменено в окне UAC' } }
                    $date=$record.TimeCreated.ToUniversalTime()
                    New-Entry 'archiveAudit' $date @{archive=$name;path=(Join-Path (Join-Path $root 'Data\Archive') $name)
                        action='Удаление архива';result=$result;account=$account;actorSid=$sid;source='Интерфейс USB-Audit'
                        eventId=$record.Id;recordId=$record.RecordId;uid=('ui-'+$date.Ticks+'-'+$record.RecordId)}
                }
                $state.archiveUiCursor=[long]$record.RecordId
            } finally { $record.Dispose() }
        }
    } finally { $reader.Dispose() }
    return $true
}
