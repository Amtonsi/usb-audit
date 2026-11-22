# Общие пути, проверки учётных записей и правила NTFS для установки и обслуживания.
$app = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'LocalUsbAudit'
$store = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'LocalUsbAudit'
$data = Join-Path $store 'Data'
$active = Join-Path $data 'Active\events.jsonl'
$archives = Join-Path $data 'Archive'
$stage = Join-Path $store 'Maintenance'
$requestFile = Join-Path $stage 'request.json'
$responseFile = Join-Path $stage 'result.json'
$intentFile = Join-Path $stage 'intent.json'
$submitFile = Join-Path $stage 'submit.lock'
$lockFile = Join-Path $store 'State\journal.lock'
$meta = Join-Path $app 'installation.json'
$collectorTask = 'LocalUsbAuditCollector'
$controlTask = 'LocalUsbAuditMaintenance'
$opsSource = 'LocalUsbAuditMaintenance'
$readersName = 'LocalUsbAuditReaders'
$psExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$utf8 = [Text.UTF8Encoding]::new($false)
$baseAcl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$baseFile = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'

function Get-UsbLocalAdministrators {
    # SID встроенной группы одинаков во всех языковых версиях Windows.
    # Уровень 0 возвращает SID участников без разрешения удалённых и доменных имён.
    if (!('LocalUsbAudit.LocalAdminGroup' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace LocalUsbAudit {
    public static class LocalAdminGroup {
        [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
        static extern int NetLocalGroupGetMembers(string server, string group, int level,
            out IntPtr buffer, int maxBytes, out int count, out int total, ref UIntPtr resume);
        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buffer);
        public static HashSet<string> DirectMemberSids(string group) {
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            UIntPtr resume = UIntPtr.Zero;
            int status;
            do {
                IntPtr buffer; int count, total;
                status = NetLocalGroupGetMembers(null, group, 0, out buffer, -1, out count, out total, ref resume);
                try {
                    if (status != 0 && status != 234) throw new Win32Exception(status);
                    for (int i = 0; i < count; i++) {
                        var sid = new SecurityIdentifier(Marshal.ReadIntPtr(buffer, i * IntPtr.Size));
                        result.Add(sid.Value);
                    }
                } finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
            } while (status == 234);
            return result;
        }
    }
}
'@
    }
    $group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    $members = [LocalUsbAudit.LocalAdminGroup]::DirectMemberSids($group.Name)
    Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $members.Contains($_.SID.Value) } | Sort-Object Name
}

function Get-SelectedLocalAdmin([string]$Sid) {
    # Снова проверяем SID при применении: УЗ могли отключить после выбора в окне.
    $selected = @(Get-UsbLocalAdministrators | Where-Object { $_.SID.Value -ceq $Sid })
    if ($selected.Count -ne 1) {
        throw 'Выберите включённую учётную запись этого компьютера, входящую непосредственно в локальную группу администраторов.'
    }
    return $selected[0]
}

function Set-RequestPaths($Config) {
    # Своя очередь для каждого назначения отделяет новые команды от старых запросов.
    # Старая установка хранит request.json и result.json без суффикса.
    $suffix = ''
    if ($Config.requestGeneration) {
        if ([string]$Config.requestGeneration -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Некорректный идентификатор очереди обслуживания.' }
        $suffix = '-' + $Config.requestGeneration
    } elseif ($Config.custodianMode -eq 'ExistingAdmin') { throw 'В конфигурации отсутствует идентификатор очереди обслуживания.' }
    $script:requestFile = Join-Path $stage ("request$suffix.json")
    $script:responseFile = Join-Path $stage ("result$suffix.json")
    $script:intentFile = Join-Path $stage ("intent$suffix.json")
    $script:submitFile = Join-Path $stage ("submit$suffix.lock")
}

function Assert-RegularPath([string]$Path) {
    # Проверяем всех предков, чтобы ссылка не перенаправила запись в другой каталог.
    $full = [IO.Path]::GetFullPath($Path)
    while ($full) {
        try {
            $attributes = [IO.File]::GetAttributes($full)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Точка повторного анализа в защищённом пути: $full"
            }
        } catch [IO.FileNotFoundException] {
        } catch [IO.DirectoryNotFoundException] {
        }
        $parent = [IO.Directory]::GetParent($full)
        if (!$parent) { break }
        $full = $parent.FullName
    }
}

function Set-GuardedDirectory([string]$Path, [string]$Sddl) {
    Assert-RegularPath $Path
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Sddl)
    if ([IO.Directory]::Exists($Path)) {
        $owner = [IO.Directory]::GetAccessControl($Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin 'S-1-5-18','S-1-5-32-544') { throw "Недоверенный владелец каталога: $Path" }
        [IO.Directory]::SetAccessControl($Path,$security)
    } else {
        [void][IO.Directory]::CreateDirectory($Path,$security)
    }
}

function Set-GuardedFile([string]$Path, [string]$Sddl) {
    Assert-RegularPath $Path
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Sddl)
    if ([IO.File]::Exists($Path)) {
        $owner = [IO.File]::GetAccessControl($Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin 'S-1-5-18','S-1-5-32-544') { throw "Недоверенный владелец файла: $Path" }
        [IO.File]::SetAccessControl($Path,$security)
    } else {
        $handle = [IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,
            [Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::ReadWrite,
            4096,[IO.FileOptions]::None,$security)
        $handle.Dispose()
    }
}

function Get-FileRules($Config, [switch]$WritableLog) {
    $sddl = $baseFile + "(A;;FR;;;$($Config.readersSid))(A;;FR;;;$($Config.custodianSid))"
    # Сборщик может читать активный журнал и только дописывать в его конец.
    if ($WritableLog) { $sddl += "(A;;0x12008d;;;$($Config.taskSid))" }
    return $sddl
}

function Enter-FileLock([string]$Path, [int]$Seconds = 30) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try { return [IO.File]::Open($Path,'Open','ReadWrite','None') }
        catch [IO.IOException] { if ([DateTime]::UtcNow -ge $until) { throw }; Start-Sleep -Milliseconds 150 }
    } while ($true)
}
