# Проверяем рабочие функции чтения Security и сопоставления на изолированных файлах.
[CmdletBinding()]
param([switch]$ToUsbOnly)
$ErrorActionPreference='Stop'
if (!$ToUsbOnly) {
    # Отдельный процесс даёт независимый лимит чтений для сверки SHA-256.
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -ToUsbOnly
    if ($LASTEXITCODE -ne 0) { throw 'Проверка переноса с компьютера на USB завершилась с ошибкой.' }
}
$src=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\src')).Path
$body=[IO.File]::ReadAllText((Join-Path $src 'Collector.ps1'))
$body=$body.Substring(0,$body.IndexOf('$instanceFile=Join-Path',[StringComparison]::Ordinal))
. ([scriptblock]::Create($body.Replace('$PSScriptRoot',("'"+$src.Replace("'","''")+"'"))))
$scratch=[IO.Directory]::CreateDirectory((Join-Path ([IO.Path]::GetTempPath()) ('usb-transfer-'+[guid]::NewGuid()))).FullName
$origin=[IO.Directory]::CreateDirectory((Join-Path $scratch 'source')).FullName
$target=[IO.Directory]::CreateDirectory((Join-Path $scratch 'target')).FullName
$instant=[datetime]::UtcNow.AddSeconds(-15)
$sourceFile=Join-Path $origin 'sample.txt'
$targetFile=Join-Path $target 'sample.txt'
$content=[Text.Encoding]::UTF8.GetBytes('Контрольная строка для сверки двух файлов.')
$script:transferFolders=@([pscustomobject]@{dos=$target;nt='\Device\UnitTarget\out'})
$driveLetter=$origin.Substring(0,2)
$volumeGuid=[UsbAuditNative]::VolumeName($driveLetter+'\')
if (!$volumeGuid) {throw 'Fixture requires a local volume GUID'}
$usb=[pscustomobject]@{session='session-42';deviceId='USBSTOR\UNIT';serial='TEST';model='USB unit'
    firstAbsent=$null;removalSignal=$null;start=Get-UtcText $instant.AddMinutes(-2);end=$null;
    bindings=@([pscustomobject]@{path=$origin;start=Get-UtcText $instant.AddMinutes(-2);end=$null});
    volumes=@([pscustomobject]@{letter=$driveLetter;paths=@(($driveLetter+'\'),$volumeGuid)})}
function Reset-Case {
    $script:state=[pscustomobject]@{sessions=@($usb);logEpoch='test-epoch';cursor=0L;cursorTime=$null}
    $script:pending=[Collections.Generic.List[object]]::new()
    $script:lastNotice=@{}
    $script:records=[Collections.Generic.Queue[object]]::new()
    $script:lastId=0L
    Initialize-TransferQueue
}
function Add-FixtureRecord([string]$Path,[int]$Task,[int]$Mask,[int]$Seconds,[string]$ProcessId='0x987',[string]$Login='0x1234',[int]$EventId=4663,[long]$Keywords=0) {
    $script:lastId++
    $fields=[ordered]@{ObjectName=$Path;AccessMask=('0x{0:x}' -f $Mask);ProcessName='C:\Windows\explorer.exe';ProcessId=$ProcessId;
        SubjectUserSid='S-1-5-21-123-456-789-1001';SubjectLogonId=$Login;SubjectUserName='operator';SubjectDomainName='TEST';ObjectType='File'}
    $part=foreach ($pair in $fields.GetEnumerator()) {
        '<Data Name="'+$pair.Key+'">'+[Security.SecurityElement]::Escape([string]$pair.Value)+'</Data>'
    }
    $item=[pscustomobject]@{RecordId=$script:lastId;Id=$EventId;Task=$Task;Keywords=$Keywords;TimeCreated=$instant.AddSeconds($Seconds);
        xml=('<Event><EventData>'+($part -join '')+'</EventData></Event>')}
    $item | Add-Member ScriptMethod ToXml { return $this.xml }
    $item | Add-Member ScriptMethod Dispose {}
    $script:records.Enqueue($item)
}
function New-SecurityReader($XPath,$Reverse) {
    if ($XPath -notmatch '12800' -or $XPath -notmatch '12812') { throw 'Missing audit task in Windows query' }
    $r=[pscustomobject]@{}
    $r | Add-Member ScriptMethod ReadEvent {if ($script:records.Count) {return $script:records.Dequeue()}}
    $r | Add-Member ScriptMethod Dispose {}
    return $r
}
function Get-LogAnchor($XPath,$Reverse) {
    if ($XPath -match '^\*\[System\[EventRecordID=') {return [pscustomobject]@{id=$state.cursor;time=$state.cursorTime}}
    [pscustomobject]@{id=$script:lastId;time=Get-UtcText $instant.AddSeconds(5)}
}
function Assert-Transfers([int]$Count,[string]$Evidence) {
    $rows=@($script:pending | Where-Object type -eq 'transfer')
    if ($rows.Count -ne $Count) {throw "Expected $Count transfer(s), observed $($rows.Count)"}
    if ($Count -and ($rows[0].evidence -ne $Evidence -or $rows[0].destination -ne $targetFile -or
            $rows[0].path -ne $sourceFile -or $rows[0].session -ne 'session-42')) {throw "Unexpected transfer: $($rows[0] | ConvertTo-Json -Compress)"}
}
try {
    [IO.File]::WriteAllBytes($sourceFile,$content)
    [IO.File]::Copy($sourceFile,$targetFile)
    if ($ToUsbOnly) {
        # Фикстура помечает origin как том USB, а target как выбранную папку компьютера.
        function Get-ToUsb($Expected) {
            $all=@($script:pending | Where-Object type -eq 'transfer')
            if (!$Expected) { if ($all.Count) { throw 'Ложный перенос на USB' }; return }
            if ($all.Count -ne 1 -or $all[0].direction -ne 'toUsb' -or $all[0].evidence -ne $Expected -or
                $all[0].localPath -ne $targetFile -or $all[0].destination -ne $sourceFile -or $all[0].session -ne $usb.session) {
                throw "Неверная запись ПК → USB: $($all | ConvertTo-Json -Compress)"
            }
            return $all[0]
        }
        Reset-Case
        Add-FixtureRecord $sourceFile 12812 2 1
        Add-FixtureRecord $sourceFile 12812 4 1
        Add-FixtureRecord '\Device\UnitTarget\out\sample.txt' 12800 1 0
        Import-SecurityEvents $instant.AddSeconds(5)
        Get-ToUsb $null
        $state=$state | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        Initialize-TransferQueue
        Import-SecurityEvents $instant.AddSeconds(12)
        $row=Get-ToUsb 'matchingContent'
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$expected=[BitConverter]::ToString($sha.ComputeHash($content)).Replace('-','')} finally {$sha.Dispose()}
        if ($row.sourceRecordId -ne 3 -or $row.destinationRecordId -ne 1 -or $row.account -ne 'TEST\operator' -or
            $row.sha256 -ne $expected) {throw 'Неверное основание пары 4663'}

        foreach ($invalid in 'different-actor','different-source','network','expired','unbound','different-bytes') {
            Reset-Case
            Add-FixtureRecord $sourceFile 12812 2 1
            switch ($invalid) {
                'different-actor' { Add-FixtureRecord $targetFile 12800 1 0 '0x888' }
                'different-source' { Add-FixtureRecord $targetFile 12800 1 0; Add-FixtureRecord (Join-Path $target 'other\sample.txt') 12800 1 0 }
                'network' { Add-FixtureRecord '\\unmonitored\share\sample.txt' 12800 1 0 }
                'expired' { Add-FixtureRecord $targetFile 12800 1 -18 }
                'unbound' { $state.sessions=@(); Add-FixtureRecord $targetFile 12800 1 0 }
                'different-bytes' { [IO.File]::WriteAllBytes($targetFile,(New-Object byte[] $content.Length)); Add-FixtureRecord $targetFile 12800 1 0 }
            }
            Import-SecurityEvents $instant.AddSeconds(15)
            Get-ToUsb $null
        }
        Reset-Case
        [IO.File]::Delete($targetFile)
        Add-FixtureRecord $targetFile 12800 1 0
        Add-FixtureRecord $sourceFile 12800 2 1
        Import-SecurityEvents $instant.AddSeconds(12)
        $row=Get-ToUsb 'pairedAccess'
        if ($row.sha256) { throw 'Пропавшему исходнику присвоена контрольная сумма' }

        [IO.File]::WriteAllBytes($targetFile,$content)
        foreach ($case in 'watch','both','overwrite','edit-only','only-watch','ambiguous','no-bytes') {
            Reset-Case
            $change=if($case -in 'overwrite','edit-only'){'changed'}else{'created'}
            Add-UsbDestinationNotice $sourceFile $usb $instant $change 'volume-test-uid'
            Add-UsbDestinationNotice $sourceFile $usb $instant.AddMilliseconds(50) 'changed' 'volume-repeat-uid'
            if (@($script:transferEvents | Where-Object kind -eq 'watch').Count -ne 1) {throw 'Одна запись данных оставила несколько кандидатов'}
            if ($case -notin 'only-watch','edit-only') {Add-FixtureRecord $targetFile 12800 1 0}
            if ($case -eq 'both') {Add-FixtureRecord $sourceFile 12812 2 1}
            if ($case -eq 'ambiguous') {Add-FixtureRecord (Join-Path $target 'other\sample.txt') 12800 1 0}
            if ($case -eq 'no-bytes') {[IO.File]::Delete($targetFile)}
            Import-SecurityEvents $instant.AddSeconds(18)
            if ($case -in 'watch','overwrite') {
                $row=Get-ToUsb 'observedMatchingContent'
                if ($row.destinationEventUid -ne 'volume-test-uid' -or $row.destinationRecordId -or $row.destinationChange -ine $change) {throw 'Неверная привязка уведомления СНИ'}
            } elseif ($case -eq 'both') {
                $row=Get-ToUsb 'matchingContent'
            } else {Get-ToUsb $null}
        }
        # Путь источника вне всех настроенных каталогов: реальная таблица NT-имён томов,
        # та же функция импорта результатов ETW, что и в цикле сборщика.
        [IO.File]::WriteAllBytes($targetFile,$content)
        $nativeRoots=[UsbAuditNative]::LocalRoots()
        $nt=[UsbAuditNative]::NtName($driveLetter)
        if (!$nativeRoots.ContainsKey($nt)) {throw 'Фикстуре требуется локальный физический диск с системным именем'}
        foreach ($case in 'kernel','kernel-security','kernel-write-watch','hybrid','hybrid-bad-id','security-anywhere','wrong-session','different-bytes','cleanup-removed','cleanup-missing','created-and-removed','written-and-removed') {
            Reset-Case
            [IO.File]::WriteAllBytes($sourceFile,$content)
            $script:transferFolders=@()
            $script:localRoots=$nativeRoots
            $script:localAliases=@($nativeRoots.Keys | Sort-Object Length -Descending)
            $pair=[pscustomobject]@{SourceNt=$nt+$targetFile.Substring(2);DestinationNt=$sourceFile;
                ProcessId=0x987;ReadTicks=$instant.Ticks;WriteTicks=$instant.AddSeconds(1).Ticks;HasKernelWrite=$true;SecurityWriteId=0L}
            if ($case -like 'hybrid*') {
                $pair.HasKernelWrite=$false
                $pair.SecurityWriteId=if($case -eq 'hybrid'){1L}else{7L}
                $script:seenWrite=@()
                $script:kernelObserver=[pscustomobject]@{}
                $script:kernelObserver | Add-Member ScriptMethod RecordAuditedUsbWrite {
                    param($native,$processId,$ticks,$recordId)
                    $script:seenWrite=@($native,$processId,$ticks,$recordId)
                }
                $usb.volumes[0].paths=@(($driveLetter+'\'),$volumeGuid,$nt)
            }
            if ($case -eq 'wrong-session') {$pair.ReadTicks=$instant.AddMinutes(-5).Ticks}
            if ($case -ne 'security-anywhere') {Add-KernelTransfer $pair}
            if ($case -in 'kernel-security','security-anywhere') {Add-FixtureRecord $pair.SourceNt 12800 1 0}
            if ($case -in 'kernel-security','kernel-write-watch','hybrid','hybrid-bad-id','security-anywhere') {Add-FixtureRecord $sourceFile 12812 2 1}
            if ($case -eq 'kernel-write-watch') {Add-UsbDestinationNotice $sourceFile $usb $instant 'created' 'kernel-volume-uid'}
            if ($case -in 'cleanup-removed','cleanup-missing','created-and-removed','written-and-removed') {
                $first=if ($case -eq 'created-and-removed') {'created'} else {'changed'}
                Add-UsbDestinationNotice $sourceFile $usb $instant.AddSeconds(1) $first 'change-before-delete'
                if ($case -eq 'written-and-removed') {Add-FixtureRecord $sourceFile 12812 2 1}
                if ($case -ne 'cleanup-missing') {Add-UsbDestinationNotice $sourceFile $usb $instant.AddSeconds(2) 'deleted' 'remove-notice'}
                [IO.File]::Delete($sourceFile)
            }
            # Здесь проверяем маршрутизацию и отрицательный результат сравнения.
            # Реальное хеширование по привязанному дескриптору проверено выше.
            & {
                function Get-TransferDigest {param($Usb,$LocalPath,$When)
                    if ($Usb.path -ne $sourceFile -or $LocalPath -ne $targetFile) {throw 'Перепутаны стороны сверки'}
                    if ($case -eq 'different-bytes') {return 'different'}
                    if ($case -in 'hybrid','cleanup-removed','cleanup-missing','created-and-removed','written-and-removed') {return}
                    return $expected
                }
                # Пустой диапазон Security допустим: ETW независимо получил обе операции.
                if ($script:lastId -gt 0) { Import-SecurityEvents $instant.AddSeconds(18) }
                else { Complete-TransferObservations $instant.AddSeconds(18) }
            }
            switch ($case) {
                'kernel' {
                    $row=Get-ToUsb 'kernelMatchingContent'
                    if ($row.processId -ne 0x987 -or $row.account -or $row.destinationRecordId -or $row.sourceRecordId) {throw 'ETW получил вымышленную идентификацию'}
                }
                'kernel-write-watch' {
                    $row=Get-ToUsb 'kernelMatchingContent'
                    if ($row.destinationRecordId -ne 1 -or $row.destinationEventUid -ne 'kernel-volume-uid' -or $row.account -ne 'TEST\operator') {throw 'Не связаны идентификаторы событий'}
                }
                'hybrid' {
                    $row=Get-ToUsb 'pairedKernelAccess'
                    if ($row.source -cne 'kernelReadSecurityWrite' -or $row.destinationRecordId -ne 1 -or
                        $row.sourceRecordId -or $row.logEpoch -ne 'test-epoch' -or $row.account -ne 'TEST\operator' -or
                        ($script:seenWrite -join '|') -ne ((@($nt+$sourceFile.Substring(2))+@(0x987,$instant.AddSeconds(1).Ticks,1)) -join '|')) {
                        throw 'Не подтверждена передача NT-пути или привязка к точной записи 4663'
                    }
                }
                'kernel-security' {$null=Get-ToUsb 'matchingContent'}
                'security-anywhere' {$null=Get-ToUsb 'matchingContent'}
                'created-and-removed' {$null=Get-ToUsb 'pairedKernelAccess'}
                'written-and-removed' {$null=Get-ToUsb 'pairedKernelAccess'}
                default {Get-ToUsb $null}
            }
        }
        # Один каталог фикстуры представляет СНИ, другой — произвольную папку ПК.
        # InspectTarget открывает реальный файл по проверенному NT-имени и читает размер.
        $usb.bindings+=@([pscustomobject]@{path=$nt+$origin.Substring(2);start=$usb.start;end=$null})
        $usb.volumes[0].paths=@(($driveLetter+'\'),$volumeGuid,$nt)
        [IO.File]::WriteAllBytes($sourceFile,[byte[]]@())
        [IO.File]::WriteAllBytes($targetFile,[byte[]]@())
        $renamed=Join-Path $target 'different-name.txt'
        try {
            [IO.File]::WriteAllBytes($renamed,[byte[]]@())
            foreach ($case in 'copy-zero','move-zero','skip','old-notice','wrong-size','ambiguous','other-pid','unbound','from-usb','from-usb-no-change','private-command','local-change-verified','local-watched-overwrite') {
                Reset-Case
                $script:localRoots=$nativeRoots
                $script:localAliases=@($nativeRoots.Keys | Sort-Object Length -Descending)
                $script:transferFolders=@([pscustomobject]@{dos=$target;nt=$nt+$target.Substring(2)})
                $fromUsb=$case -in 'from-usb','from-usb-no-change','private-command','local-change-verified','local-watched-overwrite'
                if ($case -in 'private-command','local-change-verified') { $script:transferFolders=@() }
                $sourceNt=$nt+$(if ($fromUsb) {$sourceFile.Substring(2)} else {$renamed.Substring(2)})
                $destinationNt=$nt+$(if ($fromUsb) {$renamed.Substring(2)} else {$sourceFile.Substring(2)})
                $ticks=$instant.Ticks
                if ($case -eq 'local-change-verified') {
                    $fileInfo=[UsbAuditFileComparison]::InspectTarget($renamed,$destinationNt)
                    if (!$fileInfo -or !$fileInfo.ChangeTicks) {throw 'Fixture requires local NTFS change time'}
                    $ticks=$fileInfo.ChangeTicks-1
                }
                if ($case -eq 'local-watched-overwrite') {
                    Update-TransferWatchers $true ([datetime]::UtcNow)
                    $ticks=[datetime]::UtcNow.Ticks
                    [IO.File]::WriteAllBytes($renamed,[byte[]]@())
                    [IO.File]::SetLastWriteTimeUtc($renamed,[datetime]::UtcNow.AddMinutes(-5))
                    Start-Sleep -Milliseconds 150
                }
                $command=[pscustomobject]@{SourceNt=$sourceNt;DestinationNt=$destinationNt;ProcessId=0x987;
                    Operation=if ($case -eq 'move-zero') {'move'} else {'copy'};FileSize=0;Ticks=$ticks}
                if ($case -eq 'wrong-size') {$command.FileSize=1}
                if ($case -eq 'unbound') {$state.sessions=@()}
                Add-ShellTransfer $command
                if ($case -eq 'ambiguous') {
                    $command.SourceNt=$nt+$targetFile.Substring(2)
                    Add-ShellTransfer $command
                }
                if ($case -eq 'from-usb') {Add-FixtureRecord $renamed 12800 2 1}
                if ($case -in 'copy-zero','move-zero','wrong-size','ambiguous','other-pid','old-notice','unbound') {
                    $at=if ($case -eq 'old-notice') {$instant.AddSeconds(-5)} else {$instant}
                    Add-UsbDestinationNotice $sourceFile $usb $at 'changed' 'shell-watch'
                    Add-UsbDestinationNotice $sourceFile $usb $at.AddMilliseconds(20) 'changed' 'duplicate'
                }
                if ($case -eq 'other-pid') {Add-FixtureRecord $sourceFile 12812 2 0 '0x999'}
                if ($case -eq 'copy-zero') {
                    Add-FixtureRecord $sourceFile 12812 2 0
                    Add-KernelTransfer ([pscustomobject]@{SourceNt=$sourceNt;DestinationNt=$destinationNt;ProcessId=0x987;
                        ReadTicks=$ticks;WriteTicks=$ticks;HasKernelWrite=$true;SecurityWriteId=0L})
                }
                if ($case -eq 'move-zero') {[IO.File]::Delete($renamed)}
                try {
                    if ($lastId) {Import-SecurityEvents $instant.AddSeconds(19)}
                    else {
                        # Изолируем лимит хеширования предыдущих сценариев только для ветки ChangeTime.
                        if ($case -eq 'local-change-verified') {
                            & {
                                function Get-TransferDigest {param($Usb,$LocalPath,$When) 'sizes:0:0'}
                                Complete-TransferObservations ([datetime]::new($ticks,[datetimekind]::Utc).AddSeconds(19))
                            }
                        } else {Complete-TransferObservations ([datetime]::new($ticks,[datetimekind]::Utc).AddSeconds(19))}
                    }
                    $shellRows=@($pending | Where-Object type -eq 'transfer')
                    $commands=@($pending | Where-Object type -eq 'shellCommand')
                    if ($case -eq 'private-command') {
                        if ($commands.Count -ne 1 -or $commands[0].evidence -ne 'shellOutcomeUnknown' -or
                            $commands[0].sourcePath -ne $sourceFile -or $commands[0].destination -ne $renamed) {throw 'Missing independent unconfirmed command'}
                    } elseif ($commands.Count) {throw "Unexpected unconfirmed command $case"}
                    if ($case -in 'copy-zero','move-zero','from-usb','local-change-verified','local-watched-overwrite') {
                        $expectedTarget=if($fromUsb){$renamed}else{$sourceFile}
                        $expectedSource=if($fromUsb){$sourceFile}else{$renamed}
                        if ($shellRows.Count -ne 1 -or $shellRows[0].source -ne 'shellFileOperation' -or
                            $shellRows[0].evidence -ne 'shellDestinationObserved' -or $shellRows[0].operation -ne $command.Operation -or
                            $shellRows[0].sourcePath -ne $expectedSource -or $shellRows[0].destination -ne $expectedTarget -or
                            $shellRows[0].destinationBytes -ne 0 -or $shellRows[0].processId -ne 0x987) {throw "Shell $case : $($shellRows | ConvertTo-Json -Compress)"}
                        if ($case -eq 'local-change-verified' -and $shellRows[0].destinationChange -ne 'ChangeTime') {throw 'Missing NTFS evidence'}
                        if ($case -eq 'local-watched-overwrite' -and $shellRows[0].destinationChange -ne 'Changed') {throw 'Missing local overwrite notification'}
                    } elseif ($shellRows.Count) {throw "False Shell transfer: $case"}
                } finally {
                    if ($case -eq 'local-watched-overwrite') {Update-TransferWatchers $false ([datetime]::UtcNow)}
                    if ($case -eq 'move-zero') {[IO.File]::WriteAllBytes($renamed,[byte[]]@())}
                }
            }
        } finally {[IO.File]::Delete($renamed)}
        'Passed Shell zero-byte copy and move, different destination name, both directions, NTFS metadata, exact size, cancelled/skipped intent, unrelated writer, stale changes and integrated de-duplication.'
        'Passed PC to USB: ETW and Security outside configured folders, cross-source de-duplication, digest/missing source, record linkage, restart and ambiguity rejection.'
        return
    }
    Reset-Case
    Add-FixtureRecord $targetFile 12800 2 0
    Add-FixtureRecord $targetFile 12800 4 0
    Add-FixtureRecord $sourceFile 12812 1 1
    Import-SecurityEvents $instant.AddSeconds(5)
    Assert-Transfers 0
    # Даже после перезапуска курсора неоднозначность проверяется до конца окна.
    $state=$state | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    Initialize-TransferQueue
    Import-SecurityEvents $instant.AddSeconds(10)
    Assert-Transfers 1 'matchingContent'
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $expectedHash=[BitConverter]::ToString($sha.ComputeHash($content)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $transfer=@($script:pending | Where-Object type -eq 'transfer')[0]
    if ($transfer.sha256 -ne $expectedHash -or $transfer.sourceRecordId -ne 3 -or $transfer.destinationRecordId -ne 1) {throw 'Missing event or SHA evidence'}
    if ((ConvertTo-TransferDestination '\Device\UnitTarget\out\sample.txt') -ne $targetFile -or
        (ConvertTo-TransferDestination '\Device\UnitTarget\outside\sample.txt')) {throw 'Incorrect destination folder boundary'}
    # Некоторые драйверы отдают по USB-файлу только категорию File System.
    $instant=$instant.AddSeconds(-60)
    Reset-Case
    Add-FixtureRecord $sourceFile 12800 1 0
    Add-FixtureRecord $sourceFile 12800 2 0
    Add-FixtureRecord $targetFile 12800 2 1
    Add-FixtureRecord (Join-Path $scratch 'unrelated.txt') 12800 2 1
    Add-FixtureRecord $sourceFile 12800 2 1 -EventId 4656 -Keywords 0x0010000000000000L
    Add-FixtureRecord $sourceFile 12800 1 1 -EventId 4656
    Add-FixtureRecord $sourceFile 12800 1 1 -Keywords 0x0010000000000000L
    Import-SecurityEvents $instant.AddSeconds(10)
    $rawFiles=@($script:pending | Where-Object type -eq 'file')
    if ($rawFiles.Count -ne 2 -or $rawFiles[0].accessMask -ne '0x1' -or
        $rawFiles[1].accessMask -ne '0x2' -or @($rawFiles | Where-Object path -ne $sourceFile).Count) {
        throw 'USB File System records did not preserve only the two actual source accesses'
    }
    if (@($script:pending | Where-Object type -eq 'status').Count) {throw 'Unrelated local paths must stay quiet'}
    Assert-Transfers 1 'pairedAccess'
    # Два разных события Windows — два исходных обращения и один перенос.
    Reset-Case
    Add-FixtureRecord $sourceFile 12800 1 0
    Add-FixtureRecord $sourceFile 12812 1 0
    Add-FixtureRecord $targetFile 12800 2 1
    Add-FixtureRecord $targetFile 12800 4 1
    Add-FixtureRecord $targetFile 12812 2 1
    Import-SecurityEvents $instant.AddSeconds(10)
    Assert-Transfers 1 'pairedAccess'
    $rawIds=@($script:pending | Where-Object type -eq 'file' | ForEach-Object { $_.recordId })
    if ($rawIds.Count -ne 2 -or $rawIds[0] -ne 1 -or $rawIds[1] -ne 2) {throw 'Source record IDs lost'}
    # Неопознанное обращение Removable Storage порождает предупреждение; оно не получает чужой сеанс.
    if (!$script:lastNotice.ContainsKey('unmapped')) {throw 'Missing notice for an unbound removable event'}

    # В журнале Windows тип File получают и каталоги. Они остаются в исходном аудите.
    Reset-Case
    $subdirectory=[IO.Directory]::CreateDirectory((Join-Path $origin 'folder.txt')).FullName
    try {
        Add-FixtureRecord $origin 12800 1 0
        Add-FixtureRecord $subdirectory 12800 1 0
        Add-FixtureRecord (Join-Path $target 'folder.txt') 12800 2 1
        Import-SecurityEvents $instant.AddSeconds(10)
        Assert-Transfers 0
        if (@($script:pending | Where-Object type -eq 'file').Count -ne 2) {throw 'Missing raw directory accesses'}
    } finally { [IO.Directory]::Delete($subdirectory) }

    # Архив контролируется резидентным аудитом даже при пересечении с привязкой тома.
    Reset-Case
    $archivePath=Join-Path $root 'Data\Archive\fixture.jsonl'
    $state.sessions=@([pscustomobject]@{session='overlap';start=$usb.start;end=$null
        bindings=@([pscustomobject]@{path=(Split-Path $archivePath);start=$usb.start;end=$null});volumes=@()})
    Add-FixtureRecord $archivePath 12800 0x10000 0 -EventId 4656 -Keywords 0x0010000000000000L
    Add-FixtureRecord $archivePath 12800 2 1
    Import-SecurityEvents $instant.AddSeconds(10)
    $audit=@($script:pending | Where-Object type -eq 'archiveAudit')
    if ($audit.Count -ne 2 -or $audit[0].result -ne 'Отказано в доступе' -or
        $audit[1].eventId -ne 4663 -or @($script:pending | Where-Object type -eq 'file').Count) {throw 'Archive routing lost'}
    $instant=$instant.AddSeconds(60)
    $wrongVolume='\\?\Volume{00000000-0000-0000-0000-000000000000}'+$sourceFile.Substring(2)
    if ([UsbAuditFileComparison]::TryCompare($sourceFile,$targetFile,$wrongVolume)) {throw 'Drive letter reuse was accepted'}

    Reset-Case
    Add-FixtureRecord $sourceFile 12812 1 0
    Add-FixtureRecord $targetFile 12800 2 0 '0x999'
    Add-FixtureRecord $targetFile 12800 2 0 '0x987' '0x9999'
    Add-FixtureRecord (Join-Path $scratch 'sample.txt') 12800 2 0
    Add-FixtureRecord $targetFile 12800 2 14
    Import-SecurityEvents $instant.AddSeconds(25)
    Assert-Transfers 0

    Reset-Case
    Add-FixtureRecord $sourceFile 12812 1 0
    Add-FixtureRecord (Join-Path $origin 'nested\sample.txt') 12812 1 1
    Add-FixtureRecord $targetFile 12800 2 0
    Import-SecurityEvents $instant.AddSeconds(10)
    Assert-Transfers 0

    Reset-Case
    [IO.File]::WriteAllText($targetFile,'Different contents')
    Add-FixtureRecord $sourceFile 12812 1 0
    Add-FixtureRecord $targetFile 12800 2 1
    Import-SecurityEvents $instant.AddSeconds(10)
    Assert-Transfers 0

    Reset-Case
    [IO.File]::Delete($sourceFile)
    Add-FixtureRecord $sourceFile 12812 1 0
    Add-FixtureRecord $targetFile 12800 2 1
    Import-SecurityEvents $instant.AddSeconds(10)
    Assert-Transfers 1 'pairedAccess'

    # Реальные уведомления локальной NTFS-папки при отсутствии события 4663 назначения.
    function Watch-Copy([string]$Scenario,[int]$Length) {
        $script:instant=[datetime]::UtcNow
        Reset-Case
        $bytes=[byte[]]::new($Length)
        $bytes[0]=1
        [IO.File]::WriteAllBytes($sourceFile,$bytes)
        [IO.File]::Delete($targetFile)
        if ($Scenario -in 'overwrite','overwrite-audit') { [IO.File]::WriteAllBytes($targetFile,$bytes) }
        Update-TransferWatchers $true $instant
        if ($Scenario -eq 'different') { $bytes[0]=2 }
        [IO.File]::WriteAllBytes($targetFile,$bytes)
        Start-Sleep -Milliseconds 200
        Update-TransferWatchers $false ([datetime]::UtcNow)
        Add-FixtureRecord $sourceFile 12812 1 0
        if ($Scenario -in 'both','overwrite-audit') {Add-FixtureRecord $targetFile 12800 2 1}
        if ($Scenario -eq 'ambiguous') {Add-FixtureRecord (Join-Path $origin 'other\sample.txt') 12812 1 1}
        if ($Scenario -eq 'two-processes') {Add-FixtureRecord $sourceFile 12812 1 1 '0x444'}
        Import-SecurityEvents $instant.AddSeconds(18)
    }
    Watch-Copy 'created' 190
    Assert-Transfers 1 'observedMatchingContent'
    $notice=@($script:pending | Where-Object type -eq 'transfer')[0]
    if ($notice.destinationChange -ne 'Created' -or $notice.PSObject.Properties['destinationRecordId'] -or !$notice.sha256) {throw 'Invalid watcher evidence'}
    Watch-Copy 'large' (4MB+1)
    Assert-Transfers 1 'observedCreation'
    $notice=@($script:pending | Where-Object type -eq 'transfer')[0]
    if ($notice.sourceBytes -ne (4MB+1) -or $notice.destinationBytes -ne $notice.sourceBytes -or $notice.sha256) {throw 'Missing large-file size evidence'}
    Watch-Copy 'different' 190
    Assert-Transfers 0
    Watch-Copy 'overwrite' 190
    Assert-Transfers 0
    Watch-Copy 'ambiguous' 190
    Assert-Transfers 0
    Watch-Copy 'both' 190
    Assert-Transfers 1 'matchingContent'
    Watch-Copy 'overwrite-audit' 190
    $overwrite=@($script:pending | Where-Object type -eq 'transfer')
    if ($overwrite.Count -ne 1 -or !$overwrite[0].destinationRecordId -or
        $overwrite[0].evidence -notin 'pairedAccess','matchingContent') {throw 'Audited overwrite was lost'}
    # Уведомление назначения не содержит автора. Два процесса читали один путь:
    # сохраняем оба события и допускаем такой перенос только при совпадении SHA-256.
    & {
        function Get-TransferDigest { param($Read,$Destination,$When) return $testDigest }
        foreach ($testDigest in @($expectedHash,'sizes:190:190','different',$null)) {
            Watch-Copy 'two-processes' 190
            if ($testDigest -eq $expectedHash) {
                Assert-Transfers 1 'observedMatchingContent'
                $multi=@($script:pending | Where-Object type -eq 'transfer')[0]
                if ($multi.account -or $multi.process -or $multi.sourceRecordId -or $multi.sha256 -ne $expectedHash -or
                    ($multi.sourceRecordIds -join ',') -ne '1,2') {throw 'Ambiguous actor was attributed or read evidence was lost'}
            } else { Assert-Transfers 0 }
        }
    }
    'Passed outbound file audit, reverse order, source account/process/session, duplicate rights, checkpoint replay, ambiguous source, unmatched read, differing contents and SHA-256.'
    'Passed actual NTFS directory notifications, same-size mismatch, existing-file modification, priority for Security evidence, and >4 MiB transfer.'
} finally {
    # Удаляем только созданные этим тестом два файла и три уже пустых каталога.
    [IO.File]::Delete($sourceFile)
    [IO.File]::Delete($targetFile)
    [IO.Directory]::Delete($origin)
    [IO.Directory]::Delete($target)
    [IO.Directory]::Delete($scratch)
}
