[CmdletBinding(DefaultParameterSetName='All')]
param(
    [string]$DataRoot = (Join-Path $env:ProgramData 'LocalUsbAudit\Data'),
    [string]$OutputPath = (Join-Path $env:LOCALAPPDATA 'LocalUsbAudit\Reports\USB-Audit.html'),
    [string]$ViewerTemplate,
    [switch]$NoOpen,
    [switch]$Demo,
    [Parameter(ParameterSetName='All')][switch]$RequireComplete,
    [Parameter(ParameterSetName='Watch',Mandatory)][switch]$Watch,
    [Parameter(ParameterSetName='Active',Mandatory)][switch]$ActiveOnly,
    [Parameter(ParameterSetName='Archive',Mandatory)][ValidateNotNullOrEmpty()][string]$ArchiveName
)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$defaultReport = Join-Path $env:LOCALAPPDATA 'LocalUsbAudit\Reports\USB-Audit.html'
if (!$PSBoundParameters.ContainsKey('OutputPath') -and $ArchiveName) {
    $OutputPath = Join-Path ([IO.Path]::GetDirectoryName($defaultReport)) ('Archive-' + [IO.Path]::GetFileNameWithoutExtension($ArchiveName) + '.html')
}
if (!$PSBoundParameters.ContainsKey('OutputPath') -and $ActiveOnly) {
    $OutputPath = Join-Path ([IO.Path]::GetDirectoryName($defaultReport)) 'Active.html'
}
# Планировщик запускает обновление только в обычном интерактивном сеансе читателя.
# В профиле остаются самостоятельный HTML и метка без путей, имён и событий аудита.
if ($Watch) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Обновление отчёта должно работать в обычном сеансе читателя.'
    }
    $root = [IO.Path]::GetFullPath($DataRoot)
    $target = [IO.Path]::GetFullPath($OutputPath)
    if (!$target.Equals($defaultReport,[StringComparison]::OrdinalIgnoreCase)) { throw 'Допускается только основной HTML-отчёт читателя.' }
    $folder = [IO.Path]::GetDirectoryName($target)
    [void][IO.Directory]::CreateDirectory($folder)
    $signal = Join-Path $folder 'USB-Audit-status.css'
    $tempSignal = Join-Path $folder ('.usb-status-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $scriptPath = $PSCommandPath
    $prior = $null
    $lastSignal = ''
    $lastWrite = [datetime]::MinValue
    try {
        while ([IO.File]::Exists($scriptPath)) {
            $phase = 'ok'
            try {
                $active = Get-Item -LiteralPath (Join-Path $root 'Active\events.jsonl') -ErrorAction Stop
                $archives = @(Get-ChildItem -LiteralPath (Join-Path $root 'Archive') -File -Filter '*.jsonl' -ErrorAction Stop | Sort-Object Name)
                $signature = (@($active) + $archives | ForEach-Object { '{0}:{1}:{2}' -f $_.Name,$_.Length,$_.LastWriteTimeUtc.Ticks }) -join '|'
                if ($signature -cne $prior -or ![IO.File]::Exists($target)) {
                    & $scriptPath -DataRoot $root -OutputPath $target -RequireComplete -NoOpen | Out-Null
                    $prior = $signature
                }
            } catch { $phase = 'unavailable' }
            $now = [datetime]::UtcNow
            $generation = [IO.File]::GetLastWriteTimeUtc($target).ToFileTimeUtc().ToString()
            $stateKey = $generation + ':' + $phase
            if ($lastSignal -cne $stateKey -or ($now-$lastWrite).TotalSeconds -ge 15) {
                $unix = [datetimeoffset]::UtcNow.ToUnixTimeSeconds()
                $css = ":root{--usb-generation:$generation;--usb-heartbeat:$unix;--usb-state:$phase}"
                [IO.File]::WriteAllText($tempSignal,$css,$utf8)
                if ([IO.File]::Exists($signal)) { [IO.File]::Replace($tempSignal,$signal,[Management.Automation.Language.NullString]::Value) }
                else { [IO.File]::Move($tempSignal,$signal) }
                $lastSignal=$stateKey
                $lastWrite=$now
            }
            Start-Sleep -Seconds 5
        }
    } finally {
        if ([IO.File]::Exists($tempSignal)) { [IO.File]::Delete($tempSignal) }
    }
    return
}
# При запуске из EXE шаблон той же сборки приходит из встроенного ресурса.
# Самостоятельно запущенный сценарий читает файл рядом с собой.
$templatePath = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'viewer.html' }
$template = if ($PSBoundParameters.ContainsKey('ViewerTemplate')) { $ViewerTemplate }
            else { [IO.File]::ReadAllText($templatePath, $utf8) }
$marker = '<!-- USB-AUDIT-DATA -->'
$offset = $template.IndexOf($marker, [StringComparison]::Ordinal)
if ($offset -lt 0) { throw 'Report template is incomplete.' }
if ($ArchiveName -and (
    $ArchiveName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
    $ArchiveName -ne [IO.Path]::GetFileName($ArchiveName) -or
    [IO.Path]::GetExtension($ArchiveName) -ine '.jsonl' -or
    $ArchiveName -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])\.'
)) {
    throw 'ArchiveName must be a single JSONL file name within the archive directory.'
}

# Отчёт сохраняется за пределами каталога аудита, чтобы экспорт не мог перезаписать исходный журнал.
$rootPath = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\') + '\'
$destination = [IO.Path]::GetFullPath($OutputPath)
if ([IO.Path]::GetExtension($destination) -notin @('.html', '.htm')) {
    throw 'Use an HTML file as the report destination.'
}
if ($destination.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Save the report outside the audit data directory.'
}
if ($templatePath -and $destination.Equals($templatePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Choose a destination other than the application template.'
}
$dir = [IO.Path]::GetDirectoryName($destination)
[void][IO.Directory]::CreateDirectory($dir)
$scratch = Join-Path $dir ('.usb-report-' + [guid]::NewGuid().ToString('N') + '.tmp')
$problems = New-Object 'System.Collections.Generic.List[string]'
$handles = New-Object 'System.Collections.Generic.List[object]'
$sharing = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
$localData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'LocalUsbAudit\Data\'
$useEvidence = !$Demo -and $rootPath.Equals($localData, [StringComparison]::OrdinalIgnoreCase)
$primaryData = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'LocalUsbAudit\Data')).TrimEnd('\') + '\'
$live = !$Demo -and !$ArchiveName -and !$ActiveOnly -and $rootPath.Equals($primaryData,[StringComparison]::OrdinalIgnoreCase) -and $destination.Equals($defaultReport,[StringComparison]::OrdinalIgnoreCase)
if ($live) {
    # Только основная страница может загрузить локальную таблицу стилей с меткой.
    $template = $template.Replace("style-src 'unsafe-inline'; base-uri","style-src 'unsafe-inline' file:; base-uri")
    $offset = $template.IndexOf($marker,[StringComparison]::Ordinal)
}
$legacySessions = @{}

# Разбираем только записи прежнего формата о конце сеанса. Они не указывают причину завершения.
function Read-LegacyEnds([string]$Text, $Sessions) {
    if ($Text.IndexOf('end_unknown',[StringComparison]::Ordinal) -lt 0) { return }
    foreach ($line in $Text.Split([char]10)) {
        if ($line -notmatch '"type"\s*:\s*"end_unknown"') { continue }
        try {
            $row = $line.TrimStart([char]0xfeff) | ConvertFrom-Json -ErrorAction Stop
            if ($row.type -cne 'end_unknown' -or $row.PSObject.Properties['endSource'] -or
                !$row.session -or !$row.deviceId -or !$row.time) { continue }
            $when = if ($row.time -is [datetime]) { $row.time.ToUniversalTime() } else {
                [datetimeoffset]::Parse($row.time,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime
            }
            if ($Sessions.ContainsKey($row.session)) {
                $old = $Sessions[$row.session]
                if ($old -and ($old.lastSeen -ne $when -or $old.deviceId -ine $row.deviceId)) {
                    $Sessions[$row.session] = $null
                }
            } else {
                $Sessions[$row.session] = [pscustomobject]@{session=$row.session; deviceId=$row.deviceId; lastSeen=$when}
            }
        } catch { continue }
    }
}

# Находим события за короткий интервал в отсортированных отметках одного экземпляра устройства.
function Get-TimesInRange($Times, [datetime]$From, [datetime]$To) {
    if ($null -eq $Times) { return }
    $i = $Times.BinarySearch($From)
    if ($i -lt 0) { $i = -bnot $i }
    else { while ($i -gt 0 -and $Times[$i-1] -eq $From) { $i-- } }
    while ($i -lt $Times.Count -and $Times[$i] -le $To) { $Times[$i]; $i++ }
}

function Get-RemovalEvidence($Sessions, [datetime]$AsOf) {
    $ends = @($Sessions.Values | Where-Object { $_ -and $_.lastSeen -le $AsOf } | Sort-Object lastSeen)
    if (!$ends.Count) { return }
    $times = @{}; $volumes = @{}; $parents = @{}
    foreach ($e in $ends) {
        $disk = $e.deviceId
        if (!$times.ContainsKey($disk)) {
            $times[$disk] = [Collections.Generic.List[datetime]]::new()
            $volume = 'STORAGE\Volume\_??_' + $disk.Replace('\','#')
            $volumes[$volume] = $true
            $times[$volume] = [Collections.Generic.List[datetime]]::new()
        }
    }
    # Для дисков USBSTOR Windows нередко записывает отдельно физический USB-родитель и том диска.
    # Связываем их по полному InstanceId из PnP, затем проверяем время обеих записей.
    try {
        $disks = @($ends.deviceId | Sort-Object -Unique)
        foreach ($p in @(Get-PnpDeviceProperty -InstanceId $disks -KeyName DEVPKEY_Device_Parent -ErrorAction SilentlyContinue)) {
            if (!$p -or !$times.ContainsKey([string]$p.InstanceId) -or $p.Data -notmatch '^USB\\VID_[^\\]+\\[^\\]+$') { continue }
            $parents[$p.InstanceId] = $p.Data
            if (!$times.ContainsKey($p.Data)) { $times[$p.Data] = [Collections.Generic.List[datetime]]::new() }
        }
    } catch { } # При недоступной связи PnP по-прежнему учитываем прямое событие диска.
    $upper = $ends[-1].lastSeen.AddSeconds(8)
    if ($upper -gt $AsOf) { $upper = $AsOf }
    $filter = @{LogName='Microsoft-Windows-Kernel-PnP/Device Management'; ProviderName='Microsoft-Windows-Kernel-PnP'
        Id=1010; StartTime=$ends[0].lastSeen.ToLocalTime(); EndTime=$upper.ToLocalTime()}
    $guid = '[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
    Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object {
        $event = $_
        try {
            $xml = [xml]$event.ToXml()
            $field = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DeviceInstanceId' } | Select-Object -First 1
            $id = if ($field) { [string]$field.'#text' }
            if ($id -and $id -match "^(.+)#\{($guid)\}$" -and $volumes.ContainsKey($Matches[1])) {
                $id = $Matches[1]
            } elseif ($id -and $volumes.ContainsKey($id)) {
                $id = $null
            }
            if ($id -and $times.ContainsKey($id)) {
                $times[$id].Add($event.TimeCreated.ToUniversalTime())
            }
        } finally { $event.Dispose() }
    }
    foreach ($list in $times.Values) { $list.Sort() }
    foreach ($e in $ends) {
        $from = $e.lastSeen; $to = $from.AddSeconds(8)
        $disk = $e.deviceId
        $direct = @(Get-TimesInRange $times[$disk] $from $to)
        $paired = @()
        if ($parents.ContainsKey($disk)) {
            $volume = 'STORAGE\Volume\_??_' + $disk.Replace('\','#')
            $volumeTimes = @(Get-TimesInRange $times[$volume] $from $to)
            $paired = @(foreach ($t in (Get-TimesInRange $times[$parents[$disk]] $from $to)) {
                if (@($volumeTimes | Where-Object { [Math]::Abs(($_-$t).TotalSeconds) -le 2 }).Count) { $t }
            })
        }
        if ($direct.Count -gt 1 -or $paired.Count -gt 1 -or
            ($direct.Count -eq 1 -and $paired.Count -eq 1 -and [Math]::Abs(($direct[0]-$paired[0]).TotalSeconds) -gt 2)) { continue }
        $time = if ($direct.Count) { $direct[0] } elseif ($paired.Count) { $paired[0] }
        if ($time) {
            [pscustomobject]@{session=$e.session; deviceId=$disk; lastSeen=$from.ToString('o'); time=$time.ToString('o')}
        }
    }
}

$writer = $null
try {
    # Открытый поток сохраняет доступ к файлу при его переносе в архив. Повторные события исключает средство просмотра.
    $activePath = Join-Path $rootPath 'Active\events.jsonl'
    if (-not $ArchiveName) {
        try {
            $active = [IO.File]::Open($activePath, 'Open', 'Read', $sharing)
            $handles.Add([pscustomobject]@{ Name='Active/events.jsonl'; Stream=$active; Length=$active.Length })
        } catch {
            $problems.Add(('Не удалось прочитать активный журнал: ' + $_.Exception.Message))
        }
    }
    $archivePath = Join-Path $rootPath 'Archive'
    try {
        $archives = if ($ArchiveName) {
            Join-Path $archivePath $ArchiveName
        } elseif (-not $ActiveOnly) {
            [IO.Directory]::GetFiles($archivePath, '*.jsonl') | Sort-Object
        }
        foreach ($file in $archives) {
            try {
                $stream = [IO.File]::Open($file, 'Open', 'Read', $sharing)
                $handles.Add([pscustomobject]@{ Name=('Archive/' + [IO.Path]::GetFileName($file)); Stream=$stream; Length=$stream.Length })
            } catch {
                $problems.Add(('Не удалось прочитать архив {0}: {1}' -f [IO.Path]::GetFileName($file), $_.Exception.Message))
            }
        }
    } catch {
        $problems.Add(('Не удалось прочитать каталог архивов: ' + $_.Exception.Message))
    }
    if (!$handles.Count) {
        throw ('Не удалось открыть ни одного журнала. После добавления в группу читателей выйдите из Windows и войдите снова. ' + ($problems -join ' '))
    }
    if ($RequireComplete -and $problems.Count) { throw ($problems -join ' ') }
    $writer = [IO.StreamWriter]::new($scratch, $false, $utf8)
    $writer.Write($template.Substring(0, $offset))
    $computerName = if ($Demo) { 'ARM-DEMO' } else { $env:COMPUTERNAME }
    $scope = if ($ActiveOnly) { 'active' } elseif ($ArchiveName) { 'archive' } else { 'all' }
    $meta = @{time=[DateTimeOffset]::UtcNow.ToString('o'); host=$computerName; demo=[bool]$Demo; scope=$scope; archive=$ArchiveName; problems=$problems.ToArray()}
    if ($live) {
        $stamp = [DateTime]::UtcNow
        $meta.liveUri = ([Uri]::new($destination)).AbsoluteUri
        $meta.generation = $stamp.ToFileTimeUtc().ToString()
    }
    # Встраиваем снимок журналов в HTML. Его можно открыть и скопировать без обращения к исходному АРМ.
    foreach ($source in $handles) {
        $encodedName = [Convert]::ToBase64String($utf8.GetBytes($source.Name))
        $writer.Write(('<script type="application/octet-stream" class="log-source" data-name="{0}">' -f $encodedName))
        $reader = [IO.BinaryReader]::new($source.Stream, $utf8, $true)
        try {
            $left = $source.Length
            if ($useEvidence) {
                $decoder = $utf8.GetDecoder()
                $chars = [char[]]::new($utf8.GetMaxCharCount(196608))
                $tail = ''
            }
            while ($left -gt 0) {
                # Размер полного блока кратен трём, поэтому знак заполнения Base64 появится только в конце.
                $requested = [int][Math]::Min([long]196608, $left)
                $block = $reader.ReadBytes($requested)
                if ($block.Length -ne $requested) {throw ('Журнал изменился при чтении: ' + $source.Name)}
                $writer.Write([Convert]::ToBase64String($block))
                $left -= $block.Length
                if ($useEvidence) {
                    # Декодер сохраняет незавершённый символ, хвост — незавершённую строку между блоками.
                    $n = $decoder.GetChars($block,0,$block.Length,$chars,0,($left -eq 0))
                    $text = $tail + [string]::new($chars,0,$n)
                    $split = $text.LastIndexOf([char]10) + 1
                    if ($split) { Read-LegacyEnds $text.Substring(0,$split) $legacySessions }
                    $tail = $text.Substring($split)
                }
            }
            if ($useEvidence -and $tail) { Read-LegacyEnds $tail $legacySessions }
        } finally { $reader.Dispose() }
        $writer.WriteLine('</script>')
    }
    if ($useEvidence -and $legacySessions.Count) {
        try { $meta.removalEvidence = @(Get-RemovalEvidence $legacySessions ([datetimeoffset]::Parse($meta.time).UtcDateTime)) }
        catch { $meta.removalEvidence = @() } # Недоступный журнал PnP оставляет прежнюю степень достоверности.
    }
    $writer.Write('<script type="application/octet-stream" id="report-meta">')
    $writer.Write([Convert]::ToBase64String($utf8.GetBytes(($meta | ConvertTo-Json -Depth 4 -Compress))))
    $writer.WriteLine('</script>')
    $writer.Write($template.Substring($offset + $marker.Length))
    $writer.Dispose()
    $writer = $null
    if ($live) { [IO.File]::SetLastWriteTimeUtc($scratch,$stamp) }
    if ([IO.File]::Exists($destination)) {
        [IO.File]::Replace($scratch, $destination, [Management.Automation.Language.NullString]::Value)
    } else {
        [IO.File]::Move($scratch, $destination)
    }
} finally {
    if ($writer) { $writer.Dispose() }
    foreach ($source in $handles) { $source.Stream.Dispose() }
    if ([IO.File]::Exists($scratch)) { [IO.File]::Delete($scratch) }
}
if (-not $NoOpen) { Start-Process -FilePath $destination }
Write-Output $destination
