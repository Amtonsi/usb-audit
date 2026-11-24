# Синтетические события и локальные временные файлы. Прав администратора не требуется.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot) 'src\Access.ps1')
. (Join-Path (Split-Path $PSScriptRoot) 'src\ArchiveAudit.ps1')
$archives = 'C:\example\Archive'
$name = 'usb-20261124T195542Z-0123456789abcdef0123456789abcdef.jsonl'
$path = Join-Path $archives $name
function Get-Record([int]$EventId,[string]$Object,[string]$Mask,[bool]$Failure) {
    $values = @{ObjectType='File';ObjectName=$Object;AccessMask=$Mask;SubjectUserSid='S-1-5-18'
        SubjectUserName='demo';SubjectDomainName='EXAMPLE';ProcessName='test.exe'}
    ConvertFrom-ArchiveSecurityEvent $EventId $values $Failure $archives
}
function Assert-True([bool]$Ok,[string]$Case) { if (!$Ok) { throw "Не прошла проверка: $Case" } }
$write = Get-Record 4663 $path '0x2' $false
Assert-True ($write.action -eq 'Запись данных' -and $write.archive -eq $name -and
    $write.account -eq 'EXAMPLE\demo' -and $write.result -eq 'Право доступа использовано') 'запись данных'
$deny = Get-Record 4656 $path '0x10000' $true
Assert-True ($deny.action -match 'Удаление' -and $deny.result -eq 'Отказано в доступе') 'отказ при удалении'
$opened = Get-Record 4656 $path '0x10000' $false
Assert-True ($opened.result -eq 'Доступ запрошен и разрешён') 'выданное разрешение не означает удаление'
$parent = Get-Record 4663 $archives '0x40' $false
Assert-True ($parent.archive -eq '(каталог архивов)' -and $parent.action -match 'Удаление') 'удаление через родителя'
$writeAcl = Get-Record 4663 $path '0xc0000' $false
Assert-True ($writeAcl.action -match 'разрешений') 'изменение прав'
Assert-True ($null -eq (Get-Record 4663 $path '0x120089' $false)) 'чтение исключено'
Assert-True ($null -eq (Get-Record 4663 ($archives+'-copy\other.jsonl') '0x2' $false)) 'соседний каталог'
Assert-True ($null -eq (Get-Record 4663 ($archives+'\..\other.jsonl') '0x2' $false)) 'выход из каталога'
Assert-True ($null -eq (Get-Record 4663 $path 'bogus' $false)) 'недействительная маска'
Assert-True ($null -eq (Get-Record 4660 $path '0x10000' $false)) 'неподдерживаемое событие'
Assert-True ((Get-Record 4656 ('\??\'+$path) '0x2' $true).archive -eq $name) 'NT префикс буквы'
$script:archiveScopeRoots += '\Device\HarddiskVolume99\example\Archive','\\?\Volume{deadbeef}\example\Archive'
Assert-True ((Get-Record 4656 ('\Device\HarddiskVolume99\example\Archive\'+$name) '0x2' $true).archive -eq $name) 'NT имя тома'
Assert-True ((Get-Record 4656 ('\??\Volume{deadbeef}\example\Archive\'+$name) '0x2' $true).archive -eq $name) 'GUID тома'
# Пустое или неполное правило не проходит проверку. Полный наследуемый SACL
# проверяем на дескрипторе в памяти без изменения разрешений тестового компьютера.
$descriptor = [Security.AccessControl.DirectorySecurity]::new()
Assert-True (!(Test-ArchiveAuditRule $descriptor $true)) 'пустой SACL'
$everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$rule = [Security.AccessControl.FileSystemAuditRule]::new($everyone,[Security.AccessControl.FileSystemRights]0xd0156,
    [Security.AccessControl.InheritanceFlags]'ObjectInherit,ContainerInherit',[Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AuditFlags]'Success,Failure')
$descriptor.AddAuditRule($rule)
Assert-True (Test-ArchiveAuditRule $descriptor $true) 'успех и отказ унаследованы всеми архивами'
# Проверяем запись и корреляцию этапов, сохраняя уже существующие данные.
$base = [IO.Directory]::CreateDirectory((Join-Path ([IO.Path]::GetTempPath()) ('usb-audit-test-'+[guid]::NewGuid().ToString('N'))))
$active = Join-Path $base.FullName 'test.jsonl'
$lockFile = Join-Path $base.FullName 'lock'
try {
    [IO.File]::WriteAllText($active,'{"prior":true}',$utf8)
    [IO.File]::WriteAllText($lockFile,'',$utf8)
    Write-ArchiveOperationRecord 'Удаление архива' $name 'Запрошено в программе' 'abc' 'requested'
    Write-ArchiveOperationRecord 'Удаление архива' $name 'Проверка учётной записи отклонена' 'abc' 'auth'
    $rows = @(Get-Content -Encoding UTF8 -LiteralPath $active | Where-Object { $_ } | ForEach-Object {$_ | ConvertFrom-Json})
    Assert-True ($rows.Count -eq 3 -and $rows[0].prior -and $rows[1].requestId -eq $rows[2].requestId -and
        $rows[1].uid -ne $rows[2].uid -and $rows[1].type -eq 'archiveAudit' -and $rows[1].actorSid -and
        $rows[2].path -eq $path) 'журнал этапов'
} finally {
    [IO.File]::Delete($active)
    [IO.File]::Delete($lockFile)
    $base.Delete()
}
Write-Output 'Проверки аудита архивов пройдены.'
