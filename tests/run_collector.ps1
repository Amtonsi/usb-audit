param([Parameter(Mandatory)][string]$Source,
      [Parameter(Mandatory)][string]$Scenario,
      [Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference='Stop'

# The production loop, native append/checkpoint code and reconciliation functions run
# normally. Only the machine inputs, wait and clock are replaced for deterministic tests.
$env:ProgramData = [IO.Path]::GetFullPath($FixtureRoot)
$sandboxRoot = Join-Path $env:ProgramData 'LocalUsbAudit'
foreach ($part in 'State','Data\Active','Data\Archive') {
    [void][IO.Directory]::CreateDirectory((Join-Path $sandboxRoot $part))
}
foreach ($file in 'State\journal.lock','Data\Active\events.jsonl') {
    $p = Join-Path $sandboxRoot $file
    if (![IO.File]::Exists($p)) {[IO.File]::WriteAllText($p,'')}
}
$script:frames = (Get-Content -Encoding UTF8 -LiteralPath $Scenario -Raw | ConvertFrom-Json)
$script:frame = 0
$script:baseTime = [datetime]::Parse('2026-11-22T06:30:00Z').ToUniversalTime()
function Get-FixtureNow { $script:baseTime.AddSeconds($script:frames[$script:frame].at) }
$mock = @'
function Get-UsbSnapshot {
    $f=$script:frames[$script:frame]
    if ($f.inventory -eq 'error') {throw 'simulated WMI failure'}
    $devices=@{}
    if ($f.inventory -in 'present','unmounted') {
        $device=[pscustomobject]@{deviceId='USBSTOR\QA\ONE';serial='QA-001';model='Fixture USB'
            volumes=@([pscustomobject]@{letter='E:';paths=@('E:\','\Device\HarddiskVolume88')})}
        if ($f.inventory -eq 'unmounted') { $device.volumes=@() }
        $devices[$device.deviceId]=$device
    }
    return $devices
}
function Register-WmiEvent {param($Query,$SourceIdentifier)}
function Read-UsbArchiveInterfaceEvents {}
function Unregister-Event {param($SourceIdentifier)}
function Remove-Event {param($EventIdentifier)}
function Get-Event {
    param($SourceIdentifier,$ErrorAction)
    foreach($v in @($script:frames[$script:frame].events | Where-Object {$_})){
        $when=$script:baseTime.AddSeconds($v.at)
        [pscustomobject]@{EventIdentifier=1;TimeGenerated=$when;SourceEventArgs=[pscustomobject]@{
            NewEvent=[pscustomobject]@{TIME_CREATED=$when.ToFileTimeUtc();EventType=$v.kind;DriveName='E:'}}}
    }
}
function Import-SecurityEvents {
    param([datetime]$Through)
    $f=$script:frames[$script:frame]
    if ($null -ne $f.probe) {
        $when=$script:baseTime.AddSeconds($f.probe)
        if ($when -gt $Through) { $value='deferred' }
        else {
            $onLetter=Find-Session 'E:\fixture.txt' $when
            $onNt=Find-Session '\Device\HarddiskVolume88\fixture.txt' $when
            $value="$([bool]$onLetter) $([bool]$onNt)"
        }
        [IO.File]::AppendAllText((Join-Path $env:ProgramData 'probes.txt'),"$($f.at) $value`n")
    }
}
function Start-Sleep {
    param($Milliseconds)
    $script:frame++
    if ($script:frame -ge $script:frames.Count) {throw 'END_OF_FIXTURE'}
}
'@
$code = [IO.File]::ReadAllText([IO.Path]::GetFullPath($Source))
# Dynamically created script blocks have no installation directory for the shared helpers.
$sourceDir=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Source)).Replace("'","''")
$code=$code.Replace('$PSScriptRoot',("'"+$sourceDir+"'"))
$mark = '$instanceFile=Join-Path'
$split = $code.IndexOf($mark,[StringComparison]::Ordinal)
if ($split -lt 0) {throw 'Collector entry point changed'}
$code = $code.Insert($split, $mock + [Environment]::NewLine)
$code = $code.Replace('[datetime]::UtcNow','(Get-FixtureNow)')
try { & ([scriptblock]::Create($code)) }
catch { if ($_.Exception.Message -ne 'END_OF_FIXTURE') {throw} }
