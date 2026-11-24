#requires -Version 5.1
[CmdletBinding()]
param([string]$TestFileName)

# Диагностика читает настройки АРМ и журнал. При недостаточных данных выводится отметка «ПРОВЕРИТЬ».
$ErrorActionPreference = 'Stop'
$data = Join-Path $env:ProgramData 'LocalUsbAudit\Data'
$program = Join-Path $env:ProgramFiles 'LocalUsbAudit'
$script:problems = 0

function Show-Check([string]$Name, [bool]$Ok, [string]$Details) {
    if ($Ok) { $label = 'OK' } else { $label = 'ПРОВЕРИТЬ'; $script:problems++ }
    Write-Output ("[{0}] {1} — {2}" -f $label, $Name, $Details)
}

# Для контрольного файла объединяем права доступа только внутри одного сеанса и одного полного пути.
function Test-FileEvidence($Lines, [string]$Name, [datetime]$Since) {
    $rights = @{}
    foreach ($line in $Lines) {
        try {
            $row = $line | ConvertFrom-Json -ErrorAction Stop
            if ($row.type -ne 'file' -or !$row.session -or !$row.deviceId) { continue }
            $instant = if ($row.time -is [datetime]) { $row.time.ToUniversalTime() }
                       else { [DateTimeOffset]::Parse($row.time,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
            if ($instant -lt $Since) { continue }
            $path = [string]$row.path
            if ($path -notmatch '\\' -or $path.EndsWith('\') -or [IO.Path]::GetFileName($path) -ne $Name) { continue }
            if ($path -match '^\\Device\\HarddiskVolume\d+$' -or $path -match '^\\\\\?\\Volume\{[^}]+\}$') { continue }
            if ($row.accessMask -notmatch '^0x([A-Fa-f0-9]{1,8})$') { continue }
            $mask = [Convert]::ToUInt32($Matches[1],16)
            $key = $row.session + '|' + $path
            $rights[$key] = [long]$rights[$key] -bor [long]$mask
            if (($rights[$key] -band 1) -and ($rights[$key] -band 6)) { return $true }
        } catch { continue }
    }
    return $false
}

if (-not ('LocalUsbAudit.CheckPolicy' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace LocalUsbAudit {
    public static class CheckPolicy {
        [StructLayout(LayoutKind.Sequential)]
        private struct Policy { public Guid subcategory; public uint flags; public Guid category; }
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr result);
        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr result);
        public static uint Flags(Guid id) {
            IntPtr p;
            if (!AuditQuerySystemPolicy(new Guid[] {id}, 1, out p))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try { return ((Policy)Marshal.PtrToStructure(p, typeof(Policy))).flags; }
            finally { AuditFree(p); }
        }
    }
}
'@
}

foreach ($policy in @(
    @{Name='Аудит съёмных носителей'; Id='0cce9245-69ae-11d9-bed3-505054503030'},
    @{Name='Аудит Plug and Play'; Id='0cce9248-69ae-11d9-bed3-505054503030'},
    @{Name='Аудит файловой системы'; Id='0cce921d-69ae-11d9-bed3-505054503030'; Required=3},
    @{Name='Аудит отказов операций с дескрипторами'; Id='0cce9223-69ae-11d9-bed3-505054503030'; Required=2}
)) {
    try {
        try {
            $flags = [LocalUsbAudit.CheckPolicy]::Flags([guid]$policy.Id)
        } catch {
            # Если системный вызов недоступен, штатная auditpol запрашивает право на чтение политики.
            $csv = & "$env:SystemRoot\System32\auditpol.exe" /get "/subcategory:{$($policy.Id)}" /r
            if ($LASTEXITCODE -ne 0) { throw 'Для чтения политики запустите проверку от имени администратора.' }
            $rows = @($csv | Where-Object { $_ -match [regex]::Escape($policy.Id) } |
                ConvertFrom-Csv -Header Machine,PolicyTarget,Subcategory,Guid,Include,Exclude,Value)
            if ($rows.Count -ne 1) { throw 'Не удалось разобрать ответ auditpol.' }
            $flags = 0
            if (![int]::TryParse($rows[0].Value,[ref]$flags)) { throw 'В ответе auditpol отсутствует числовая настройка.' }
        }
        $success = ($flags -band 1) -ne 0
        $details = if ($success) { 'регистрация успешных операций включена' } else { 'регистрация успешных операций выключена' }
        if ($policy.Required -eq 2) {
            $success = ($flags -band 2) -ne 0
            $details = if ($success) { 'отказы в доступе регистрируются' } else { 'регистрация отказов выключена' }
        } elseif ($policy.Required -eq 3) {
            $failure = ($flags -band 2) -ne 0
            $details += if ($failure) { ', регистрация отказов включена' } else { ', регистрация отказов выключена' }
            $success = $success -and $failure
        }
        Show-Check $policy.Name $success $details
    } catch { Show-Check $policy.Name $false $_.Exception.GetBaseException().Message }
}

try {
    $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Storage'
    $hotPlug = $key.GetValue('HotPlugSecureOpen')
    $activeSetting = $null -ne $hotPlug -and $key.GetValueKind('HotPlugSecureOpen') -eq 'DWord' -and $hotPlug -eq 1
    $detail = if ($activeSetting) { 'DWORD = 1' } else { 'ожидается DWORD = 1, проверьте настройку и переподключите СНИ' }
    Show-Check 'HotPlugSecureOpen' $activeSetting $detail
} catch { Show-Check 'HotPlugSecureOpen' $false $_.Exception.Message }

# Назначение хранится по SID: после переименования показываем актуальное имя из Windows.
# Проверяем также, что УЗ включена и всё ещё входит в группу администраторов.
try {
    $assignment = & {
        . (Join-Path $PSScriptRoot 'Access.ps1')
        $settings = Get-Content -Raw -Encoding UTF8 -LiteralPath $meta | ConvertFrom-Json
        if ($settings.custodianMode -ne 'ExistingAdmin') { throw 'Для этой версии установки требуется выбрать администратора через «Обновить».' }
        $admin = Get-SelectedLocalAdmin $settings.custodianSid
        '{0}  ·  SID {1}' -f $admin.SID.Translate([Security.Principal.NTAccount]).Value,$admin.SID.Value
    }
    Show-Check 'Ответственный за архивы' $true $assignment
} catch { Show-Check 'Ответственный за архивы' $false $_.Exception.Message }

foreach ($name in 'LocalUsbAuditCollector','LocalUsbAuditMaintenance') {
    try {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\'
        $want = if ($name -eq 'LocalUsbAuditCollector') { @('Running') } else { @('Ready', 'Running') }
        Show-Check $name ($task.State.ToString() -in $want) $task.State.ToString()
    } catch { Show-Check $name $false $_.Exception.Message }
}
foreach ($fileName in 'Collector.ps1','Report.ps1','viewer.html','Maintenance.ps1','ArchiveAudit.ps1','TransferAudit.ps1','DestinationAudit.ps1','KernelFileTrace.cs','KernelTransferMatcher.cs','destinations.json') {
    $path = Join-Path $program $fileName
    Show-Check $fileName (Test-Path -LiteralPath $path -PathType Leaf) $path
}
try {
    $current = Get-Item -LiteralPath (Join-Path $data 'Active\events.jsonl') -ErrorAction Stop
    $stream = [IO.File]::Open($current.FullName,'Open','Read',([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { $size = $stream.Length } finally { $stream.Dispose() }
    if ($size -gt 0) {
        Show-Check 'Текущий журнал' $true ("{0:N0} байт, последнее изменение {1:g}" -f $size,$current.LastWriteTime)
    } else {
        # После закрытия архива новый активный файл остаётся пустым до следующего события.
        Write-Output '[СВЕДЕНИЯ] Текущий журнал доступен для чтения и пока пуст. Для проверки сбора подключите СНИ и сформируйте отчёт заново.'
    }
} catch { Show-Check 'Текущий журнал' $false $_.Exception.Message }
if ($TestFileName) {
    try {
        if ($TestFileName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw 'Укажите только имя контрольного файла, без пути.' }
        $lines = Get-Content -LiteralPath (Join-Path $data 'Active\events.jsonl') -Encoding UTF8 -Tail 2000
        $found = Test-FileEvidence $lines $TestFileName ([datetime]::UtcNow.AddMinutes(-15))
        $note = if ($found) { 'подтверждены чтение и запись по одному пути в одном сеансе' } else { 'подтверждения чтения и записи по одному пути в одном сеансе недостаточно' }
        Show-Check "Контрольный файл $TestFileName" $found "$note (последние 15 минут, до 2000 строк активного журнала)"
    } catch { Show-Check 'Контрольный файл' $false $_.Exception.Message }
} else {
    Write-Output '[СВЕДЕНИЯ] Проверены настройки. Для проверки файловых операций переподключите тестовый СНИ, запишите и прочтите файл с уникальным именем, затем сверьте его путь в отчёте или передайте имя в Check.ps1 -TestFileName.'
}
if ($script:problems) { exit 2 }
exit 0
