# Настраиваем аудит записи только для выбранных локальных папок. Содержимое и права чтения файлов сохраняются.
function Get-UsbInboxPath {
    return [IO.Path]::Combine([Environment]::GetFolderPath('CommonDocuments'), 'USB-Audit-Inbox')
}
function Get-UsbDestinationPath([string]$Path) {
    if ($Path -notmatch '^[a-zA-Z]:\\' -or $Path.Substring(2).Contains(':')) { throw "Требуется локальный путь к папке NTFS: $Path" }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [IO.Path]::GetPathRoot($full + '\')
    $drive = [IO.DriveInfo]::new($root)
    if ($full.Length -le 3 -or $drive.DriveType -ne 'Fixed' -or $drive.DriveFormat -ne 'NTFS') { throw "Выберите папку на локальном томе NTFS: $full" }
    foreach ($folder in 'Windows','ProgramFiles','ProgramFilesX86','CommonApplicationData') {
        $reserved = [Environment]::GetFolderPath($folder)
        if ($reserved -and ($full -ieq $reserved -or $full.StartsWith($reserved+'\',[StringComparison]::OrdinalIgnoreCase) -or $reserved.StartsWith($full+'\',[StringComparison]::OrdinalIgnoreCase))) {
            throw "Выберите папку для документов вне системных каталогов: $full"
        }
    }
    Assert-RegularPath $full
    return $full
}
function Read-UsbDestinationSettings([string]$AppDirectory) {
    $file = Join-Path $AppDirectory 'destinations.json'
    Assert-RegularPath $file
    if (![IO.File]::Exists($file)) { return @{format='usb-destinations-v1'; folders=@()} }
    $config = [IO.File]::ReadAllText($file) | ConvertFrom-Json
    if ($config.format -ne 'usb-destinations-v1' -or $null -eq $config.folders) { throw "Не удалось прочитать список контролируемых папок: $file" }
    return $config
}
function Save-UsbDestinationSettings([string]$AppDirectory,$Config) {
    $file = Join-Path $AppDirectory 'destinations.json'
    $temp = Join-Path $AppDirectory ('destinations-'+[guid]::NewGuid().ToString('N')+'.tmp')
    try {
        # Метаданные доступны для чтения сборщику, изменять их могут только SYSTEM и администраторы.
        Set-GuardedFile $temp 'O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;AU)'
        [IO.File]::WriteAllText($temp,($Config | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
        if ([IO.File]::Exists($file)) { [IO.File]::Replace($temp,$file,[Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temp,$file) }
    } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}
function Get-UsbAuditDescriptor($Security) {
    $sddl = $Security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
    if (!$sddl) { return 'S:' }
    return $sddl
}
function Set-UsbDestinationAudit([string]$AppDirectory,[string[]]$Paths) {
    $config = Read-UsbDestinationSettings $AppDirectory
    $inbox = Get-UsbInboxPath
    if (!$Paths -and !@($config.folders).Count) { $Paths = @($inbox) }
    $requested = @(@($config.folders | ForEach-Object { $_.path }) + @($Paths) | Where-Object { $_ } | ForEach-Object { Get-UsbDestinationPath $_ } | Sort-Object -Unique)
    $checkedDrives = @{}
    foreach ($path in $requested) {
        $letter = $path.Substring(0,1)
        if (!$checkedDrives.ContainsKey($letter)) {
            # Внешний USB SSD иногда сообщает тип Fixed. Проверяем также шину физического диска.
            $disks = @(Get-Partition -DriveLetter $letter -ErrorAction Stop | Get-Disk -ErrorAction Stop)
            if (!$disks.Count -or @($disks | Where-Object { $_.BusType -eq 'USB' }).Count) {
                throw "Для папки назначения требуется локальный диск компьютера: $path"
            }
            $checkedDrives[$letter] = $true
        }
        foreach ($ancestor in $requested) {
            if ($path.StartsWith($ancestor+'\',[StringComparison]::OrdinalIgnoreCase)) { throw "Папка $path уже входит в $ancestor. Укажите только родительскую папку." }
        }
        if (![IO.Directory]::Exists($path) -and $path -ine $inbox) { throw "Папка назначения отсутствует: $path" }
    }
    foreach ($path in $requested) {
        if (![IO.Directory]::Exists($path)) { [void][IO.Directory]::CreateDirectory($path) }
        Assert-RegularPath $path
        $sec = [IO.Directory]::GetAccessControl($path,[Security.AccessControl.AccessControlSections]::Audit)
        $before = Get-UsbAuditDescriptor $sec
        $entry = $config.folders | Where-Object { $_.path -ieq $path } | Select-Object -First 1
        if ($entry -and $entry.after -eq $before) { continue }
        if ($entry -and $entry.before -ne $before) { throw "Параметры аудита папки изменились после установки: $path. Сверьте её SACL перед обновлением." }
        $rule = [Security.AccessControl.FileSystemAuditRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]6,'ContainerInherit, ObjectInherit','InheritOnly','Success')
        $sec.AddAuditRule($rule)
        $after = Get-UsbAuditDescriptor $sec
        if (!$entry) {
            $entry = [pscustomobject]@{path=$path; before=$before; after=$after}
            $config.folders = @($config.folders) + @($entry)
        }
        # Сохраняем исходное состояние до записи SACL, чтобы прерванную установку можно было повторить.
        Save-UsbDestinationSettings $AppDirectory $config
        if ($after -ne $before) {
            [IO.Directory]::SetAccessControl($path,$sec)
            $actual = Get-UsbAuditDescriptor ([IO.Directory]::GetAccessControl($path,[Security.AccessControl.AccessControlSections]::Audit))
            $entry.after = $actual
            Save-UsbDestinationSettings $AppDirectory $config
        }
    }
}
function Remove-UsbDestinationAudit([string]$AppDirectory) {
    $file = Join-Path $AppDirectory 'destinations.json'
    if (![IO.File]::Exists($file)) { return }
    $config = Read-UsbDestinationSettings $AppDirectory
    foreach ($entry in @($config.folders)) {
        $path = Get-UsbDestinationPath $entry.path
        if ([IO.Directory]::Exists($path) -and $entry.before -ne $entry.after) {
            $sec = [IO.Directory]::GetAccessControl($path,[Security.AccessControl.AccessControlSections]::Audit)
            $current = Get-UsbAuditDescriptor $sec
            if ($current -eq $entry.after) {
                $sec.SetSecurityDescriptorSddlForm($entry.before,[Security.AccessControl.AccessControlSections]::Audit)
                [IO.Directory]::SetAccessControl($path,$sec)
            } elseif ($current -ne $entry.before) { throw "В папке изменился аудит: $path. Сверьте текущую SACL с destinations.json." }
        }
        $config.folders = @($config.folders | Where-Object { $_.path -ine $path })
        Save-UsbDestinationSettings $AppDirectory $config
    }
    [IO.File]::Delete($file)
}
