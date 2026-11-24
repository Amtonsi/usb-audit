$ErrorActionPreference='Stop'
$src=Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
# Тот же файл отдельно компилируется при уборке оставшегося после сбоя сеанса.
Add-Type -Path (Join-Path $src 'KernelFileTrace.cs')
$kind=[UsbAuditKernelTrace].Assembly.GetType('UsbAuditShellQueue',$true)
$flags=[Reflection.BindingFlags]'Instance,NonPublic'
$queue=[Activator]::CreateInstance($kind,$true)
$pc='\Device\HarddiskVolume8001'
$usb='\Device\HarddiskVolume8002'
$roots=[object[]]::new(2)
$roots[0]=[string[]]@($usb)
$roots[1]=[string[]]@($pc)
$null=$kind.GetMethod('UpdateRoots',$flags).Invoke($queue,$roots)
$ticks=[DateTime]::UtcNow.Ticks
function Assert-True([bool]$Value,[string]$Message) { if(!$Value){throw $Message} }
function New-Payload([string]$From,[string]$To,[uint32]$Operation,[uint64]$Size) {
    $stream=[IO.MemoryStream]::new()
    $writer=[IO.BinaryWriter]::new($stream)
    try {
        $encoding=[Text.Encoding]::Unicode
        $writer.Write($encoding.GetBytes($From+[char]0+$To+[char]0))
        $writer.Write([uint32]0)
        $writer.Write([uint32]0)
        $writer.Write($Operation)
        $writer.Write($Size)
        $writer.Flush()
        return ,$stream.ToArray()
    } finally {$writer.Dispose()}
}
function Add-Payload([byte[]]$Payload,[long]$At=$ticks,[int]$ProcessId=888) {
    $buffer=[Runtime.InteropServices.Marshal]::AllocHGlobal($Payload.Length)
    try {
        [Runtime.InteropServices.Marshal]::Copy($Payload,0,$buffer,$Payload.Length)
        $kind.GetMethod('Receive',$flags).Invoke($queue,@($buffer,$Payload.Length,$ProcessId,$At))
    } finally {[Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)}
}
function Read-Queue {return ,($kind.GetMethod('Drain',$flags).Invoke($queue,@()))}
function Test-Loss { $kind.GetMethod('TakeLoss',$flags).Invoke($queue,@()) }
$from="$pc\deep\source.txt"
$to="$usb\elsewhere\renamed.txt"
$copy=New-Payload $from $to 2 0
Assert-True (Add-Payload $copy) 'valid shell record'
Assert-True (Add-Payload $copy) 'duplicate shell record'
$rows=Read-Queue
Assert-True ($rows.Count -eq 1 -and $rows[0].Operation -eq 'copy' -and $rows[0].SourceNt -ceq $from -and
    $rows[0].DestinationNt -ceq $to -and $rows[0].FileSize -eq 0 -and $rows[0].Ticks -eq $ticks -and $rows[0].ProcessId -eq 888) 'empty renamed copy'
Assert-True (Add-Payload (New-Payload $to $from 1 5000000012)) 'valid outbound move'
$rows=Read-Queue
Assert-True ($rows.Count -eq 1 -and $rows[0].Operation -eq 'move' -and $rows[0].FileSize -eq 5000000012 -and
    $rows[0].SourceNt -ceq $to -and $rows[0].DestinationNt -ceq $from) 'outbound 64-bit size'
foreach($case in @(@($from,$from,2),@($to,$to,2),@($from,$to,3),@($from,'\\server\share\file',2),
    @($from,"$usb\..\elsewhere\x",2),@($from,"$usb\File:stream",2),@($from,"$usb\dir\",2))) {
    Assert-True (Add-Payload (New-Payload @case 1234)) 'irrelevant well-formed event'
}
Assert-True ((Read-Queue).Count -eq 0) 'no unrelated or unsupported events'
Assert-True (!(Add-Payload ($copy[0..($copy.Length-3)]))) 'truncated scalars'
Assert-True (!(Add-Payload ([byte[]](65)*40))) 'missing string terminator'
Assert-True (!(Add-Payload ($copy[0..($copy.Length-2)]))) 'odd byte count'
# Проводник обычно отдаёт DOS-путь. Используем фактическое отображение системного
# тома, не открывая ни исходный, ни целевой файл и не требуя подключённой флешки.
$drive=$env:SystemDrive+'\'
$mount=@($kind.GetField('roots',$flags).GetValue($queue) | Where-Object {
    $_.GetType().GetField('Alias',$flags).GetValue($_) -eq $drive
})
Assert-True ($mount.Count -eq 1) 'system drive resolved through actual mounted-volume aliases'
$nt=$mount[0].GetType().GetField('Native',$flags).GetValue($mount[0]).TrimEnd('\')
$roots[1]=[string[]]@($pc,$nt)
$null=$kind.GetMethod('UpdateRoots',$flags).Invoke($queue,$roots)
$ticks=[DateTime]::UtcNow.Ticks
Assert-True (Add-Payload (New-Payload ("\\?\"+$drive+'folder\file.txt') $to 2 0)) 'DOS extended path'
$rows=Read-Queue
Assert-True ($rows.Count -eq 1 -and $rows[0].SourceNt -ceq "$nt\folder\file.txt") 'DOS path conversion'
for($i=0;$i -lt 1030;$i++){[void](Add-Payload $copy ($ticks+$i))}
Assert-True ((Read-Queue).Count -eq 1024 -and (Test-Loss) -and !(Test-Loss)) 'bounded queue and one loss indication'
Assert-True (Add-Payload $copy) 'queue restored after drain'
$null=$kind.GetMethod('OnLoss',$flags).Invoke($queue,@())
Assert-True ((Read-Queue).Count -eq 0 -and (Test-Loss)) 'OS event loss clears pending records'
try {
    [UsbAuditKernelTrace]::StopOrphaned('ForeignTraceName')
    throw 'unexpectedly accepted foreign name'
} catch {
    Assert-True ($_.Exception.GetBaseException() -is [ArgumentException]) 'reject foreign session before creating a controller'
}
'Shell-Core: copies, moves, zero bytes, changed names, out-of-scope records, malformed payloads, bounds and private logger guard passed.'
