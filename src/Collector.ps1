#requires -version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'LocalUsbAudit'
$journal = Join-Path $root 'Data\Active\events.jsonl'
$journalLock = Join-Path $root 'State\journal.lock'
$checkpoint = Join-Path $root 'State\collector.json'
$utf8 = New-Object Text.UTF8Encoding($false)
. (Join-Path $PSScriptRoot 'TransferAudit.ps1')
. (Join-Path $PSScriptRoot 'ArchiveAudit.ps1')

# Сборщик открывает существующий файл журнала с правом добавления строк.
# Обычная запись через FileStream может потребовать также право менять прежнее содержимое.
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class UsbAuditNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint mode, uint options, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteFile(SafeFileHandle file, byte[] bytes, int count,
        out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool MoveFileEx(string oldName, string newName, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint QueryDosDevice(string device, StringBuilder value, int size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool GetVolumeNameForVolumeMountPoint(string path, StringBuilder name, int size);
    [DllImport("cfgmgr32.dll", CharSet=CharSet.Unicode)]
    static extern int CM_Locate_DevNodeW(out uint node, string id, uint flags);
    [DllImport("cfgmgr32.dll")]
    static extern int CM_Get_Parent(out uint parent, uint node, uint flags);
    [DllImport("cfgmgr32.dll", CharSet=CharSet.Unicode)]
    static extern int CM_Get_Device_IDW(uint node, StringBuilder id, int size, uint flags);

    public static void Append(string path, byte[] data) {
        using(var h = CreateFile(path, 4, 7, IntPtr.Zero, 3, 0x80000000, IntPtr.Zero)) {
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            int written;
            if (!WriteFile(h, data, data.Length, out written, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (written != data.Length) throw new System.IO.IOException("Incomplete journal write");
        }
    }
    public static void ReplaceState(string temporary, string destination) {
        if (!MoveFileEx(temporary,destination,1|8))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public static string NtName(string alias) {
        var value = new StringBuilder(32768);
        return QueryDosDevice(alias, value, value.Capacity) == 0 ? null : value.ToString();
    }
    public static string VolumeName(string root) {
        var value = new StringBuilder(1024);
        return GetVolumeNameForVolumeMountPoint(root, value, value.Capacity) ? value.ToString() : null;
    }
    public static bool IsUsb(string id) {
        uint node, parent;
        if (String.IsNullOrEmpty(id) || CM_Locate_DevNodeW(out node, id, 0) != 0) return false;
        for (int depth=0; depth<32; depth++) {
            var name = new StringBuilder(1024);
            if (CM_Get_Device_IDW(node, name, name.Capacity, 0) != 0) break;
            if (name.ToString().StartsWith(@"USB\",StringComparison.OrdinalIgnoreCase)) return true;
            if (CM_Get_Parent(out parent,node,0)!=0) break;
            node=parent;
        }
        return false;
    }
}
'@

function Get-UtcText([datetime]$Date) { $Date.ToUniversalTime().ToString('o') }
function Get-Instant([string]$Value) {
    [datetime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}
function New-Entry([string]$Type, [datetime]$Date, [hashtable]$Fields) {
    $entry = [ordered]@{ type = $Type; time = Get-UtcText $Date; uid = [guid]::NewGuid().ToString() }
    foreach ($key in $Fields.Keys) { $entry[$key] = $Fields[$key] }
    $script:pending.Add([pscustomobject]$entry)
}
function Add-Notice([string]$Key, [string]$Message) {
    $now = [datetime]::UtcNow
    if ($script:lastNotice.ContainsKey($Key) -and ($now - $script:lastNotice[$Key]).TotalMinutes -lt 10) { return }
    $script:lastNotice[$Key] = $now
    New-Entry 'status' $now @{message=$Message}
}

function Save-Checkpoint {
    $temp = $checkpoint + '.tmp'
    $json = $state | ConvertTo-Json -Compress -Depth 14
    $bytes = $utf8.GetBytes($json)
    $stream = [IO.File]::Open($temp,'Create','Write','None')
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    [UsbAuditNative]::ReplaceState($temp,$checkpoint)
}
function Publish-Pending {
    if (@($state.pending).Count -eq 0) { return }
    $lines = foreach ($record in $state.pending) { $record | ConvertTo-Json -Compress -Depth 12 }
    # Перевод строки отделяет новую запись от возможного незавершённого хвоста журнала.
    $bytes = $utf8.GetBytes("`n" + ($lines -join "`n") + "`n")
    $published=$false
    for ($n = 0; $n -lt 60; $n++) {
        $lock=$null
        try {
            $lock=[IO.File]::Open($journalLock,'Open','ReadWrite','None')
            [UsbAuditNative]::Append($journal,$bytes)
            $published=$true
            break
        } catch {
            $cause=$_.Exception.GetBaseException()
            $sharing=($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -in 32,33) -or
                ($cause -is [IO.IOException] -and ($cause.HResult -band 0xFFFF) -in 32,33)
            if (!$sharing) { throw }
        } finally { if ($lock) { $lock.Dispose() } }
        Start-Sleep -Milliseconds 200
    }
    if (!$published) { throw 'Journal is busy. The batch is saved in the checkpoint for retry.' }
    $state.pending = @()
    Save-Checkpoint
}
function Commit-State {
    # После аварии порция записей может попасть в журнал повторно. Постоянные идентификаторы
    # позволяют отличить повторную доставку от нового действия того же пользователя.
    $state.pending = $script:pending.ToArray()
    Save-Checkpoint
    Publish-Pending
    $script:pending.Clear()
}

# У одного физического СНИ может быть несколько томов. Сохраняем их буквы, GUID и имена Windows для поиска пути из события.
function Get-DiskVolumes($Disk) {
    $number = [int]$Disk.Index
    try {
        $parts = @(Get-CimInstance -Namespace 'root/Microsoft/Windows/Storage' -ClassName MSFT_Partition -Filter "DiskNumber=$number")
        $partPaths = foreach ($part in $parts) {
            [pscustomobject]@{ paths = @($part.AccessPaths | Where-Object { $_ }) }
        }
    } catch {
        # Если службе недоступен класс Storage, узнаём буквы томов через связи Win32.
        $parts = @(Get-CimInstance Win32_DiskPartition -Filter "DiskIndex=$number")
        $partPaths = foreach ($part in $parts) {
            $logical = @(Get-CimAssociatedInstance -InputObject $part -Association Win32_LogicalDiskToPartition)
            [pscustomobject]@{ paths = @($logical | ForEach-Object { $_.DeviceID + '\' }) }
        }
    }
    foreach ($part in $partPaths) {
        $paths = @($part.paths)
        $letter = $null
        foreach ($path in $part.paths) {
            if ($path -match '^[A-Za-z]:\\?$') { $letter = $path.Substring(0,2) }
            if ($path -match '^\\\\\?\\Volume\{') {
                $paths += [UsbAuditNative]::NtName($path.Substring(4).TrimEnd('\'))
            } elseif ($path.EndsWith('\')) {
                $guid = [UsbAuditNative]::VolumeName($path)
                if ($guid) {
                    $paths += $guid
                    $paths += [UsbAuditNative]::NtName($guid.Substring(4).TrimEnd('\'))
                }
            }
        }
        if ($letter) { $paths += [UsbAuditNative]::NtName($letter) }
        $paths = @($paths | Where-Object { $_ } | Sort-Object -Unique)
        if ($paths.Count) { [pscustomobject]@{letter=$letter; paths=$paths} }
    }
}

# PnP-идентификатор и серийный номер берём из разных свойств диска. Поле серийного номера может быть пустым.
function Get-UsbSnapshot {
    $result = @{}
    foreach ($disk in (Get-CimInstance Win32_DiskDrive -Property Index,InterfaceType,PNPDeviceID,SerialNumber,Model)) {
        $id = [string]$disk.PNPDeviceID
        if (!$id) { continue }
        # По родительским устройствам PnP распознаём и USB-корпуса, зарегистрированные как SCSI.
        if ($disk.InterfaceType -ne 'USB' -and $id -notlike 'USBSTOR\*' -and ![UsbAuditNative]::IsUsb($id)) { continue }
        $serial = ([string]$disk.SerialNumber).Trim()
        if (!$serial) { $serial = $null }
        $result[$id] = [pscustomobject]@{
            deviceId=$id; serial=$serial; model=[string]$disk.Model
            volumes=@(Get-DiskVolumes $disk)
        }
    }
    return $result
}
function Get-Paths($Volumes) {
    foreach ($volume in $Volumes) { foreach ($path in $volume.paths) { $path.TrimEnd('\') } }
}
function Add-SessionRecord([string]$Type, [datetime]$Time, $Item, [string]$EndSource) {
    $fields=@{session=$Item.session; deviceId=$Item.deviceId; serial=$Item.serial
        model=$Item.model; volumes=$Item.volumes; observedOnly=$Item.observedOnly}
    if ($EndSource) {
        $fields.endSource=$EndSource
        $fields.lastSeen=$Item.lastSeen
    }
    New-Entry $Type $Time $fields
}
function Close-Session($Item, [datetime]$Time, [string]$EndSource) {
    $Item.end = Get-UtcText $Time
    foreach ($binding in $Item.bindings) {
        if ($binding.end) { continue }
        $binding.end=$Item.end
        # Между опросами буква или папка монтирования могла перейти другому тому.
        # Системное имя тома позволяет привязать запись даже непосредственно перед извлечением.
        if ($EndSource -eq 'inventory' -and $binding.path -match '^[a-z]:') { $binding.end=$Item.lastSeen }
    }
    $type=if ($EndSource -in 'volumeEvent','inventory') { 'disconnect' } else { 'end_unknown' }
    Add-SessionRecord $type $Time $Item $EndSource
}
function Refresh-Inventory($Snapshot, $Signals, [datetime]$Now) {
    $open = @{}
    foreach ($s in $state.sessions) { if (!$s.end) { $open[$s.deviceId]=$s } }
    foreach ($id in $open.Keys) {
        $s=$open[$id]
        $letters=@($s.volumes | ForEach-Object { $_.letter } | Where-Object { $_ })
        $removals=@($Signals | Where-Object { $_.kind -eq 3 -and $_.letter -in $letters -and $_.time -ge (Get-Instant $s.start) -and $_.time -le $Now })
        $removed=$null
        if ($letters.Count -and $letters.Count -eq @($s.volumes).Count) {
            $firstByLetter=@($removals | Group-Object letter | ForEach-Object { $_.Group | Sort-Object time | Select-Object -First 1 })
            if ($firstByLetter.Count -eq $letters.Count) {
                $removed=$firstByLetter | Sort-Object time -Descending | Select-Object -First 1
            }
        }
        # Уведомление об извлечении тома может прийти раньше, чем исчезнет сам диск.
        # Сохраняем его за этим сеансом, даже если буквы томов пропадут при следующем опросе.
        if ($removed) { $s.removalSignal=[pscustomobject]@{time=Get-UtcText $removed.time;letters=$letters} }
        elseif ($s.removalSignal -and ($Now-(Get-Instant $s.removalSignal.time)).TotalSeconds -gt 15) { $s.removalSignal=$null }
        $removalTime=$null
        $insertedAgain=$false
        if ($s.removalSignal) {
            $removalTime=Get-Instant $s.removalSignal.time
            $insertedAgain=@($Signals | Where-Object { $_.kind -eq 2 -and $_.letter -in $s.removalSignal.letters -and $_.time -ge $removalTime -and $_.time -le $Now }).Count -gt 0
        }
        $present=$Snapshot.ContainsKey($id)
        if ($removalTime -and (!$present -or $insertedAgain)) {
            if ($s.firstAbsent -and $removalTime -gt (Get-Instant $s.firstAbsent)) {
                Close-Session $s (Get-Instant $s.firstAbsent) 'inventory'
            } else { Close-Session $s $removalTime 'volumeEvent' }
        } elseif (!$present) {
            # Один снимок может пропустить устройство. Повторное отсутствие подтверждает
            # отключение; время первого отсутствия является верхней границей интервала.
            if ($s.firstAbsent) { Close-Session $s (Get-Instant $s.firstAbsent) 'inventory' }
            else { $s.firstAbsent=Get-UtcText $Now }
        } elseif ($s.firstAbsent) {
            $absent=Get-Instant $s.firstAbsent
            $newLetters=@($Snapshot[$id].volumes | ForEach-Object { $_.letter } | Where-Object { $_ })
            $arrivalAfterAbsence=$Signals | Where-Object {
                $_.kind -eq 2 -and $_.letter -in $newLetters -and $_.time -ge $absent -and $_.time -le $Now
            } | Select-Object -First 1
            if ($arrivalAfterAbsence) { Close-Session $s $absent 'inventory' }
            else { $s.firstAbsent=$null }
        }
    }
    foreach ($device in $Snapshot.Values) {
        $id = $device.deviceId
        $paths = @(Get-Paths $device.volumes)
        $letters = @($device.volumes | ForEach-Object { $_.letter } | Where-Object { $_ })
        $s = $open[$id]
        if (!$s -or $s.end) {
            $arrival = $Signals | Where-Object { $_.kind -eq 2 -and $_.letter -in $letters } | Sort-Object time -Descending | Select-Object -First 1
            $start=$Now
            if ($arrival -and $arrival.time -le $Now -and (!$s -or $arrival.time -ge (Get-Instant $s.end))) { $start=$arrival.time }
            $s=[pscustomobject]@{session=[guid]::NewGuid().ToString(); deviceId=$id; serial=$device.serial; model=$device.model
                start=Get-UtcText $start; end=$null; lastSeen=Get-UtcText $Now; firstAbsent=$null; removalSignal=$null
                observedOnly=($start -eq $Now); volumes=$device.volumes; bindings=@()}
            foreach ($path in $paths) { $s.bindings+= [pscustomobject]@{path=$path;start=$s.start;end=$null} }
            $state.sessions+= $s
            Add-SessionRecord 'connect' $start $s
        } else {
            $formerly=@($s.bindings | Where-Object { !$_.end } | ForEach-Object { $_.path })
            $changed=$false
            $unmounted=$s.lastSeen
            if ($s.removalSignal -and (Get-Instant $s.removalSignal.time) -ge (Get-Instant $s.lastSeen)) {
                $unmounted=$s.removalSignal.time
            }
            foreach ($b in $s.bindings) {
                if (!$b.end -and $b.path -notin $paths) { $b.end=$unmounted; $changed=$true }
            }
            foreach ($path in $paths) {
                if ($path -notin $formerly) {
                    $since=$Now
                    $mount=$device.volumes | Where-Object { $path -in @($_.paths | ForEach-Object { $_.TrimEnd('\') }) } | Select-Object -First 1
                    $arrival = $Signals | Where-Object { $_.kind -eq 2 -and $_.letter -eq $mount.letter } | Sort-Object time -Descending | Select-Object -First 1
                    if ($arrival -and $arrival.time -ge (Get-Instant $s.start) -and $arrival.time -le $Now) { $since=$arrival.time }
                    $s.bindings+= [pscustomobject]@{path=$path;start=Get-UtcText $since;end=$null}
                    $changed=$true
                }
            }
            $s.volumes=$device.volumes
            $s.lastSeen=Get-UtcText $Now
            if ($changed) { New-Entry 'status' $Now @{kind='volumes';session=$s.session;volumes=$s.volumes;message='Изменились точки подключения тома.'} }
        }
    }
}

function New-SecurityReader([string]$XPath, [bool]$Reverse) {
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security','LogName',$XPath)
    $query.ReverseDirection = $Reverse
    return New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
}
function Get-LogAnchor([string]$XPath, [bool]$Reverse) {
    $reader=New-SecurityReader $XPath $Reverse
    try {
        $record=$reader.ReadEvent()
        if ($record) {
            try { return [pscustomobject]@{id=[long]$record.RecordId;time=Get-UtcText ($record.TimeCreated)} }
            finally { $record.Dispose() }
        }
    } finally { $reader.Dispose() }
}
function Get-AccessDescription([uint32]$Mask) {
    $words=@()
    # Младшие биты маски имеют разные значения для файла и для каталога.
    if ($Mask -band 1) { $words+='Чтение данных / списка каталога' }
    if ($Mask -band 2) { $words+='Запись данных / создание файла' }
    if ($Mask -band 4) { $words+='Добавление данных / создание каталога' }
    if ($Mask -band 32) { $words+='Выполнение / проход по каталогу' }
    if ($Mask -band 65536 -or $Mask -band 64) { $words+='Использование права удаления' }
    if ($Mask -band 136) { $words+='Чтение атрибутов' }
    if ($Mask -band 272) { $words+='Запись атрибутов' }
    if (!$words.Count) { return ('Доступ 0x{0:X}' -f $Mask) }
    $words -join ', '
}
# Для файлового события учитываем путь и время подключения: после извлечения букву диска может получить другой СНИ.
function Find-Session([string]$Path, [datetime]$Date) {
    $normalized=$Path
    if ($normalized.StartsWith('\??\')) { $normalized='\\?\' + $normalized.Substring(4) }
    if ($normalized -match '^\\\\\?\\[A-Z]:') { $normalized=$normalized.Substring(4) }
    $best=$null
    $length=-1
    foreach ($s in $state.sessions) {
        if ($Date -lt (Get-Instant $s.start) -or ($s.end -and $Date -ge (Get-Instant $s.end))) { continue }
        foreach ($b in $s.bindings) {
            $name=$b.path
            if ($name.Length -lt $length -or ($normalized -ne $name -and
                !$normalized.StartsWith($name+'\',[StringComparison]::OrdinalIgnoreCase))) { continue }
            if ($Date -lt (Get-Instant $b.start) -or ($b.end -and $Date -ge (Get-Instant $b.end))) { continue }
            if ($name.Length -eq $length -and (!$best -or $best.session -ne $s.session)) { $best=$null }
            else { $best=$s; $length=$name.Length }
        }
    }
    return $best
}
# Читаем события Windows после сохранённой позиции. В запись файла переносим процесс, пользователя и использованные права.
function Import-SecurityEvents([datetime]$Through) {
    $script:backlog=$false
    $bound=Get-UtcText $Through
    if ($state.cursor -lt 0) {
        # Если при запуске журнал был пуст или временно недоступен, учитываем и его первое событие.
        $baseline=$bound
        if ($state.baselineSince -and (Get-Instant $state.baselineSince) -lt $Through) { $baseline=$state.baselineSince }
        $initial=Get-LogAnchor "*[System[TimeCreated[@SystemTime < '$baseline']]]" $true
        $state.cursor=0L
        $state.cursorTime=$null
        if ($initial) { $state.cursor=$initial.id; $state.cursorTime=$initial.time }
    }
    $latest=Get-LogAnchor "*[System[TimeCreated[@SystemTime <= '$bound']]]" $true
    if (!$latest) { return }
    # После очистки Security номер записи может повториться. Сверяем также сохранённое время.
    $anchor=$null
    if ($state.cursor -gt 0) { $anchor=Get-LogAnchor "*[System[EventRecordID=$($state.cursor)]]" $false }
    if ($state.cursor -gt 0 -and (!$anchor -or $anchor.time -ne $state.cursorTime)) {
        $oldest=Get-LogAnchor '*' $false
        if (!$oldest) { return }
        if ($oldest.id -gt $latest.id) { return }
        $state.cursor=[long]$oldest.id-1
        $state.logEpoch=[guid]::NewGuid().ToString()
        $script:transferEvents.Clear()
        $state.transferGapUntil=''
        Add-Notice 'retention' 'Изменился или был перезаписан журнал «Безопасность». Сбор продолжен с доступных записей.'
    }
    if ($state.cursor -ge $latest.id) { Complete-TransferObservations $Through; return }
    $range="(EventRecordID > $($state.cursor)) and (EventRecordID <= $($latest.id))"
    $query="*[System[((EventID=4663 and Task=12812) or ((EventID=4656 or EventID=4663) and Task=12800) or EventID=6416) and $range]]"
    $reader=New-SecurityReader $query $false
    $unmapped=0
    try {
        for ($i=0; $i -lt 256; $i++) {
            $record=$reader.ReadEvent()
            if (!$record) {
                $state.cursor=$latest.id
                $state.cursorTime=$latest.time
                break
            }
            try {
                $xml=[xml]$record.ToXml()
                $fields=@{}
                foreach ($node in $xml.Event.EventData.Data) { $fields[$node.Name]=[string]$node.'#text' }
                $date=$record.TimeCreated.ToUniversalTime()
                if ($record.Id -eq 6416) {
                    # Если носитель извлекли до обнаружения его томов, фиксируем распознавание Windows.
                    # Серийный номер и связь с файловыми операциями указываем только по данным СНИ.
                    $id=[string]$fields.DeviceId
                    if ($id -like 'USBSTOR\*' -or ([string]$fields.ClassId -eq '{4d36e967-e325-11ce-bfc1-08002be10318}' -and [UsbAuditNative]::IsUsb($id))) {
                        $known=@($state.sessions | Where-Object { $_.deviceId -eq $id -and
                            (Get-Instant $_.start) -le $date.AddSeconds(15) -and
                            (!$_.end -or (Get-Instant $_.end) -ge $date) })
                        if (!$known.Count) {
                            New-Entry 'status' $date @{kind='recognition';deviceId=$id;serial=$null;model=$fields.DeviceDescription
                                message="Windows распознала USB-диск $id. Достоверный сеанс и серийный номер на момент события не установлены."
                                recordId=[long]$record.RecordId;logEpoch=$state.logEpoch}
                        }
                    }
                } elseif ([int]$record.Task -eq 12800) {
                    $denied=([long]$record.Keywords -band 0x0010000000000000L) -ne 0
                    $archive=ConvertFrom-ArchiveSecurityEvent -EventId $record.Id -Fields $fields -Denied $denied -ArchiveDirectory (Join-Path $root 'Data\Archive')
                    if ($archive) {
                        $archive.recordId=[long]$record.RecordId
                        $archive.logEpoch=$state.logEpoch
                        New-Entry 'archiveAudit' $date $archive
                    } elseif (!$denied -and $record.Id -eq 4663 -and $fields.ObjectType -eq 'File' -and
                              $script:transferFolders.Count -and ([convert]::ToUInt32($fields.AccessMask,16) -band 6)) {
                        $destination=ConvertTo-TransferDestination $fields.ObjectName
                        if ($destination -and (Test-TransferSessionNear $date) -and !(Find-Session $destination $date)) {
                            Add-TransferObservation 'write' $destination $fields $null $date $record.RecordId
                        }
                    }
                } else {
                    $match=Find-Session $fields.ObjectName $date
                    if ($match) {
                        $mask=[convert]::ToUInt32($fields.AccessMask,16)
                        $account=$fields.SubjectUserName
                        if ($fields.SubjectDomainName) { $account=$fields.SubjectDomainName+'\'+$account }
                        # При сверке содержимого сам сборщик читает исходник. Это его техническое обращение.
                        $ownRead=$fields.SubjectUserSid -eq 'S-1-5-19' -and $fields.ProcessId -and
                            [convert]::ToUInt32($fields.ProcessId,16) -eq $PID
                        if (!$ownRead) {
                            New-Entry 'file' $date @{session=$match.session;deviceId=$match.deviceId;serial=$match.serial;model=$match.model
                                account=$account;path=$fields.ObjectName;process=$fields.ProcessName;action=Get-AccessDescription $mask
                                accessMask=$fields.AccessMask;recordId=[long]$record.RecordId;logEpoch=$state.logEpoch}
                            if ($script:transferFolders.Count -and ($mask -band 1) -and $fields.ObjectType -eq 'File') {
                                $sourcePath=ConvertTo-TransferSource $fields.ObjectName $match $date
                                if ($sourcePath -notin @($match.bindings | ForEach-Object { $_.path })) {
                                    Add-TransferObservation 'read' $sourcePath $fields $match $date $record.RecordId
                                }
                            }
                        }
                    } else { $unmapped++ }
                }
                $state.cursor=[long]$record.RecordId
                $state.cursorTime=Get-UtcText $date
            } finally { $record.Dispose() }
        }
    } finally { $reader.Dispose() }
    if ($state.cursor -lt $latest.id) {
        $script:backlog=$true
        if ($state.cursorTime) { Complete-TransferObservations (Get-Instant $state.cursorTime) }
        if ($state.cursorTime -and ($Through-(Get-Instant $state.cursorTime)).TotalMinutes -gt 2) {
            Add-Notice 'backlog' 'Сборщик обрабатывает накопленные события. Последние операции появятся с задержкой.'
        }
    } else { Complete-TransferObservations $Through }
    if ($unmapped) {
        Add-Notice 'unmapped' "Обнаружены операции со съёмными носителями без достоверной связи с сеансом. За этот опрос: $unmapped."
    }
}

# Блокировка защищает журнал и сохранённую позицию чтения событий от одновременного запуска двух сборщиков.
$instanceFile=Join-Path $root 'State\collector.instance'
$instance=[IO.File]::Open($instanceFile,'OpenOrCreate','ReadWrite','None')
$source='LocalUsbAudit.Volumes'
$subscription=$null
try {
    $script:lastNotice=@{}
    $script:pending=New-Object 'Collections.Generic.List[object]'
    $state=[pscustomobject]@{version=1;sessions=@();cursor=[long]-1;cursorTime=$null;baselineSince=Get-UtcText ([datetime]::UtcNow)
        logEpoch=[guid]::NewGuid().ToString();pending=@()}
    if ([IO.File]::Exists($checkpoint)) {
        $state=[IO.File]::ReadAllText($checkpoint,$utf8) | ConvertFrom-Json
        if ($state.version -ne 1) { throw 'Unsupported collector state version.' }
        Publish-Pending
    }
    Initialize-TransferQueue
    $script:transferFolders=@()
    try { $script:transferFolders=@(Get-TransferFolders (Join-Path $PSScriptRoot 'destinations.json')) }
    catch { Add-Notice 'destination-config' ('Ошибка настроек папок назначения: '+$_.Exception.Message) }
    foreach ($s in $state.sessions) {
        if (!$s.end) { Close-Session $s (Get-Instant $s.lastSeen) 'collectorRestart' }
    }
    New-Entry 'status' ([datetime]::UtcNow) @{message='Сборщик запущен. Для ранее подключённых носителей отмечается время обнаружения.'}
    try {
        $null=Register-WmiEvent -Query 'SELECT * FROM Win32_VolumeChangeEvent WHERE EventType=2 OR EventType=3' -SourceIdentifier $source
        $subscription=$true
    } catch {
        Add-Notice 'wmi' 'Уведомления об изменении томов недоступны. Работает периодическая проверка.'
    }
    Commit-State
    $lastScan=[datetime]::MinValue
    $lastRead=[datetime]::MinValue
    $lastCommit=[datetime]::MinValue
    $watchConnected=$false
    $lastAttempt=[datetime]::MinValue
    $retryScan=[datetime]::MinValue
    $script:backlog=$false
    $ready=$false
    $signals=@()
    while ($true) {
        $now=[datetime]::UtcNow
        if ($subscription) {
            foreach ($item in @(Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue)) {
                try {
                    $volumeEvent=$item.SourceEventArgs.NewEvent
                    $timestamp=[datetime]::FromFileTimeUtc([long]$volumeEvent.TIME_CREATED)
                    if (!$volumeEvent.TIME_CREATED) { $timestamp=$item.TimeGenerated.ToUniversalTime() }
                    $signals+= [pscustomobject]@{kind=[int]$volumeEvent.EventType;letter=([string]$volumeEvent.DriveName).TrimEnd('\');time=$timestamp}
                    if ($signals.Count -gt 128) {
                        $signals=@()
                        foreach ($s in $state.sessions) { if (!$s.end) { Close-Session $s (Get-Instant $s.lastSeen) 'queueOverflow' } }
                        Add-Notice 'queue-limit' 'Слишком много уведомлений о томах. Границы незавершённых сеансов помечены как неизвестные.'
                    }
                } finally { Remove-Event -EventIdentifier $item.EventIdentifier }
            }
        }
        $dirty=$false
        $scanAge=($now-$lastAttempt).TotalSeconds
        if ($now -ge $retryScan -and (($signals.Count -and $scanAge -ge 0.7) -or $scanAge -ge 4)) {
            try {
                $lastAttempt=$now
                $snapshot=Get-UsbSnapshot
                $scanTime=[datetime]::UtcNow
                if ($lastScan -gt [datetime]::MinValue -and ($scanTime-$lastScan).TotalSeconds -gt 30) {
                    foreach ($s in $state.sessions) {
                        if (!$s.end) { Close-Session $s (Get-Instant $s.lastSeen) 'observationGap' }
                    }
                    $signals=@()
                    Add-Notice 'gap' 'Был перерыв в наблюдении. Для подключённых устройств открыты новые сеансы.'
                }
                Refresh-Inventory $snapshot $signals $scanTime
                $watchConnected=$snapshot.Count -gt 0
                $lastScan=$scanTime
                # Уведомление может опередить перечисление томов. На короткое время
                # сохраняем его вместе с исходной отметкой времени подключения.
                $mounted=@(foreach ($disk in $snapshot.Values) { foreach ($v in $disk.volumes) { $v.letter } })
                $latestSignals=@($signals | Sort-Object time -Descending | Group-Object letter | ForEach-Object { $_.Group[0] })
                $signals=@($latestSignals | Where-Object { $_.kind -eq 2 -and $_.letter -notin $mounted -and ($lastScan-$_.time).TotalSeconds -lt 15 })
                $dirty=$true
            } catch {
                $retryScan=[datetime]::UtcNow.AddSeconds(4)
                if ($lastScan -gt [datetime]::MinValue -and ([datetime]::UtcNow-$lastScan).TotalSeconds -gt 30) {
                    $watchConnected=$false
                    foreach ($s in $state.sessions) { if (!$s.end) { Close-Session $s (Get-Instant $s.lastSeen) 'observationGap' } }
                    $signals=@()
                }
                Add-Notice 'inventory-error' ('Ошибка опроса USB-устройств: '+$_.Exception.Message)
            }
        }
        if ($script:transferFolders.Count) { Update-TransferWatchers $watchConnected $now }
        if ($lastScan -gt [datetime]::MinValue -and ($script:backlog -or ($now-$lastRead).TotalSeconds -ge 1)) {
            try {
                $before=$state.cursor
                if (!$lastArchiveUiRead -or ($now-$lastArchiveUiRead).TotalSeconds -ge 3) {
                    try { if (Read-UsbArchiveInterfaceEvents) { $dirty=$true } }
                    catch { Add-Notice 'archive-ui-error' ('Ошибка чтения уведомлений об архивах: '+$_.Exception.Message) }
                    $lastArchiveUiRead=$now
                }
                # Обрабатываем события до момента последнего успешного сопоставления томов.
                $through=$lastScan
                foreach ($signal in $signals) { if ($signal.time -lt $through) { $through=$signal.time } }
                # Пока ждём подтверждения отсутствия, не двигаем курсор Security за последнее
                # наблюдение носителя. Поздние записи разберём, когда граница сеанса уточнится.
                foreach ($s in $state.sessions) {
                    if (!$s.end -and $s.removalSignal) {
                        $notified=Get-Instant $s.removalSignal.time
                        if ($notified -lt $through) { $through=$notified }
                    }
                    if (!$s.end -and $s.firstAbsent) {
                        $lastSeen=Get-Instant $s.lastSeen
                        if ($lastSeen -lt $through) { $through=$lastSeen }
                    }
                }
                Import-SecurityEvents ($through.AddSeconds(-2))
                if (!$ready) {
                    New-Entry 'status' ([datetime]::UtcNow) @{key='ready';message='Сборщик готов. Опрос устройств и чтение журнала «Безопасность» доступны.'}
                    $ready=$true
                }
                if ($state.cursor -ne $before) { $dirty=$true }
            } catch {
                Add-Notice 'security-error' ('Чтение журнала «Безопасность» недоступно: '+$_.Exception.Message)
            }
            $lastRead=$now
        }
        if ($script:pending.Count -or $script:transferWatchDirty -or ($dirty -and ($now-$lastCommit).TotalSeconds -ge 30)) {
            # Закрытый сеанс нужен для привязки запоздавших событий Security.
            # Его удаление из рабочего списка сохраняет историю в журнале.
            $cutoff=$now.AddHours(-1)
            if ($state.cursorTime) {
                $readTime=Get-Instant $state.cursorTime
                if ($readTime -lt $cutoff) { $cutoff=$readTime }
            }
            $state.sessions=@($state.sessions | Where-Object { !$_.end -or (Get-Instant $_.end) -ge $cutoff })
            Commit-State
            $script:transferWatchDirty=$false
            $lastCommit=$now
        }
        if ($script:backlog) { Start-Sleep -Milliseconds 50 } else { Start-Sleep -Milliseconds 700 }
    }
} finally {
    if ($script:folderWatches) { foreach ($watch in $script:folderWatches.Values) { $watch.Dispose() } }
    if ($subscription) { Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue }
    $instance.Dispose()
}
