$ErrorActionPreference = 'Stop'
$src = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
Add-Type -Path @((Join-Path $src 'KernelFileTrace.cs'),(Join-Path $src 'KernelTransferMatcher.cs'))
$pc = '\Device\HarddiskVolume1'
$usb = '\Device\HarddiskVolume2'
$t = [DateTime]::UtcNow.Ticks
$second = [TimeSpan]::TicksPerSecond
function New-Matcher {
    [UsbAuditTransferMatcher]::new([string[]]@($usb),[string[]]@($pc),999)
}
function Open-File($m,$obj,$path) { $m.OnFile(12,100,$t,$obj,0,$path,0) }
function Read-File($m,$obj,$who=100) { $m.OnFile(15,$who,$t,$obj,0,$null,8192) }
function Write-Usb($m,$obj,$who=100) { $m.OnFile(16,$who,$t+$second,$obj,0,$null,8192) }
foreach ($case in 'copy','sameName','otherProcess','noRead','reusedHandle','network','loss','ownProcess','keyOnly') {
    $m = New-Matcher
    $from = "$pc\Произвольная папка\Вложенная\план.txt"
    $to = "$usb\Передача\план.txt"
    Open-File $m 10 $from
    Open-File $m 11 $to
    switch ($case) {
        'copy' {Read-File $m 10; Write-Usb $m 11}
        'sameName' {Read-File $m 10; Write-Usb $m 11; Open-File $m 22 "$pc\другая\план.txt"; Read-File $m 22}
        'otherProcess' {Read-File $m 10; Write-Usb $m 11 121}
        'noRead' {Write-Usb $m 11}
        'reusedHandle' {$m.OnFile(14,100,$t,10,0,$null,0); Read-File $m 10; Write-Usb $m 11}
        'network' {Open-File $m 10 '\Device\Mup\srv\share\план.txt'; Read-File $m 10; Write-Usb $m 11}
        'loss' {Read-File $m 10; Write-Usb $m 11; $m.OnLoss()}
        'ownProcess' {Read-File $m 10 999; Write-Usb $m 11 999}
        'keyOnly' {$m.OnFile(10,100,$t,0,73,$from,0); $m.OnFile(15,100,$t,0,73,$null,8192); Write-Usb $m 11}
    }
    if ($m.Drain($t+2*$second).Length) {throw "Early attribution: $case"}
    $pairs = $m.Drain($t+20*$second)
    if ($case -in 'copy','keyOnly') {
        if ($pairs.Length -ne 1 -or $pairs[0].SourceNt -cne $from -or $pairs[0].DestinationNt -cne $to) {throw "Source or destination missing: $case"}
    } elseif ($pairs.Length) {throw "False attribution: $case"}
    if ($m.Drain($t+25*$second).Length) {throw "Duplicate: $case"}
}
# Частые обращения к одноимённым файлам другого приложения не должны
# лишать Проводник информации о каталоге его собственного файла.
$m = New-Matcher
for ($i=1; $i -le 40; $i++) {
    Open-File $m 50 "$pc\lib$i\index.js"
    Read-File $m 50 201
}
Open-File $m 10 "$pc\проекты\план.txt"
Open-File $m 11 "$usb\план.txt"
Read-File $m 10
Write-Usb $m 11
if (!$m.TakeLoss() -or $m.Drain($t+20*$second).Length -ne 1) {throw 'Unrelated saturation hid the copy'}
Write-Output 'ETW matcher: 10 source-path, ambiguity, timing, saturation, loss and identity cases passed.'
foreach ($case in 'overwrite','late','duplicate','both','ambiguous','wrongPid','gap','early','noRead','nonUsb','zeroId') {
    $m=New-Matcher
    $t=[DateTime]::UtcNow.Ticks
    $from="$pc\Документы\тест.exe"
    $to="$usb\ранее существующий\тест.exe"
    Open-File $m 20 $from
    Open-File $m 21 $to
    if ($case -ne 'noRead') {Read-File $m 20}
    if ($case -eq 'ambiguous') {Open-File $m 22 "$pc\Вторая\тест.exe";Read-File $m 22}
    if ($case -in 'both','duplicate') {Write-Usb $m 21}
    if ($case -eq 'late') {
        # Один опрос уже прошел; ядро позже ещё раз прочитало тот же источник.
        [void]$m.Drain($t+12*$second)
        $m.OnFile(15,100,$t+14*$second,20,0,$null,4096)
    }
    if ($case -eq 'duplicate') {
        $pairs=$m.Drain($t+12*$second)
        if ($pairs.Length -ne 1 -or !$pairs[0].HasKernelWrite) { throw 'Missing original ETW pair' }
    }
    if ($case -eq 'gap') {$m.OnLoss()}
    $pidOfWriter=if ($case -eq 'wrongPid') {115} else {100}
    $dest=if ($case -eq 'nonUsb') {$from} else {$to}
    $ticks=if ($case -eq 'early') {$t-2*$second} else {$t+$second}
    $id=if ($case -eq 'zeroId') {0} else {4123}
    $m.RecordAuditedUsbWrite($dest,$pidOfWriter,$ticks,$id)
    $pairs=$m.Drain($t+22*$second)
    if ($case -in 'overwrite','late','both') {
        if ($pairs.Length -ne 1 -or $pairs[0].SourceNt -cne $from -or $pairs[0].DestinationNt -cne $to -or
            $pairs[0].SecurityWriteId -ne 4123 -or $pairs[0].HasKernelWrite -ne ($case -eq 'both') -or
            $pairs[0].ReadTicks -ne $t) {throw "Invalid Security write pairing: $case"}
    } elseif ($pairs.Length) {throw "False Security write pairing: $case"}
}
Write-Output 'Named audited writes: overwrite, delayed delivery, read history, provenance, gaps, duplicates and ambiguity passed.'
# При заполнении лимита имён запись и её подтверждённый источник должны
# пережить посторонний поток. Дополнительные чтения идут от отдельного PID.
$m=New-Matcher
$t=[datetime]::UtcNow.Ticks
$from="$pc\A\test.bin"; $to="$usb\test.bin"
Open-File $m 1 $from
Read-File $m 1
for ($i=0;$i -lt 16500;$i++) {
    Open-File $m 2 "$pc\library\f$i.bin"
    Read-File $m 2 201
}
$m.RecordAuditedUsbWrite($to,100,$t+$second,6001)
$pairs=$m.Drain($t+20*$second)
if(!$m.TakeLoss() -or $pairs.Length -ne 1 -or $pairs[0].SecurityWriteId -ne 6001) {throw 'Unrelated name limit erased an observed source'}
Write-Output 'Unrelated capacity pressure preserved the pending transfer.'
