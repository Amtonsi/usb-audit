# Проверяем рабочие функции чтения Security и сопоставления на изолированных файлах.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
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
function Add-FixtureRecord([string]$Path,[int]$Task,[int]$Mask,[int]$Seconds,[string]$ProcessId='0x987',[string]$Login='0x1234') {
    $script:lastId++
    $fields=[ordered]@{ObjectName=$Path;AccessMask=('0x{0:x}' -f $Mask);ProcessName='C:\Windows\explorer.exe';ProcessId=$ProcessId;
        SubjectUserSid='S-1-5-21-123-456-789-1001';SubjectLogonId=$Login;SubjectUserName='operator';SubjectDomainName='TEST';ObjectType='File'}
    $part=foreach ($pair in $fields.GetEnumerator()) {
        '<Data Name="'+$pair.Key+'">'+[Security.SecurityElement]::Escape([string]$pair.Value)+'</Data>'
    }
    $item=[pscustomobject]@{RecordId=$script:lastId;Id=4663;Task=$Task;Keywords=0L;TimeCreated=$instant.AddSeconds($Seconds);
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
