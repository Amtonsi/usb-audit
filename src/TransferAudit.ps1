# Сопоставление наблюдаемого чтения СНИ и записи в выбранную локальную папку.
# События с одинаковым именем сами по себе не доказывают совпадение содержимого.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

// Обработчик .NET принимает уведомления Windows независимо от цикла чтения Security.
// На СНИ читаем относительные имена от дескриптора конкретного тома.
public sealed class UsbAuditDestinationWatcher : IDisposable {
    public sealed class Notice {
        public string Path, Change, OldPath;
        public long Ticks;
    }
    readonly FileSystemWatcher watcher;
    readonly Queue<Notice> queue=new Queue<Notice>();
    readonly Queue<Notice> localChanges=new Queue<Notice>();
    string failure;
    public UsbAuditDestinationWatcher(string path) : this(path,false) {}
    public UsbAuditDestinationWatcher(string path,bool sourceVolume) {
        watcher=new FileSystemWatcher(path);
        try {
            watcher.IncludeSubdirectories=true;
            watcher.NotifyFilter=NotifyFilters.FileName;
            watcher.InternalBufferSize=32*1024;
            if (sourceVolume) {
                watcher.NotifyFilter|=NotifyFilters.DirectoryName|NotifyFilters.LastWrite|NotifyFilters.Size;
                watcher.Created+=(s,e)=>Add(e.Name,"created",null);
                watcher.Changed+=(s,e)=>Add(e.Name,"changed",null);
                watcher.Deleted+=(s,e)=>Add(e.Name,"deleted",null);
                watcher.Renamed+=(s,e)=>Add(e.Name,"renamed",e.OldName);
            } else {
                watcher.NotifyFilter|=NotifyFilters.LastWrite|NotifyFilters.Size;
                watcher.Created+=(s,e)=>Add(e.FullPath,"Created",null);
                watcher.Renamed+=(s,e)=>Add(e.FullPath,"Renamed",null);
                watcher.Changed+=(s,e)=>RememberChange(e.FullPath);
            }
            watcher.Error+=(s,e)=>{lock(queue) { failure=e.GetException().Message; queue.Clear(); localChanges.Clear(); }};
            watcher.EnableRaisingEvents=true;
        } catch { watcher.Dispose(); throw; }
    }
    void Add(string path,string change,string oldPath) {
        lock(queue) {
            if(failure!=null) return;
            if(queue.Count>=512) {failure="Переполнение очереди наблюдения"; queue.Clear(); return;}
            queue.Enqueue(new Notice {Path=path,Change=change,OldPath=oldPath,Ticks=DateTime.UtcNow.Ticks});
        }
    }
    // Изменения в выбранной локальной папке помогают подтвердить только точное
    // назначение команды Проводника. Не сохраняем их в журнал или в контрольную точку.
    void TrimChanges(long now) {
        while(localChanges.Count>0 && now-localChanges.Peek().Ticks>30*TimeSpan.TicksPerSecond) localChanges.Dequeue();
    }
    void RememberChange(string path) {
        lock(queue) {
            if(failure!=null) return;
            long now=DateTime.UtcNow.Ticks;
            TrimChanges(now);
            if(localChanges.Count>=256) localChanges.Dequeue();
            localChanges.Enqueue(new Notice {Path=path,Ticks=now});
        }
    }
    public bool ChangedNear(string path,long ticks,long distance) {
        lock(queue) {
            if(failure!=null) return false;
            foreach(var item in localChanges)
                if(Math.Abs(item.Ticks-ticks)<=distance && String.Equals(path,item.Path,StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
    public Notice[] Drain() {lock(queue) {TrimChanges(DateTime.UtcNow.Ticks);var events=queue.ToArray();queue.Clear();return events;}}
    public string Error {get {lock(queue) {return failure;}}}
    public void Dispose() {watcher.Dispose();}
}

public static class UsbAuditFileComparison {
    const int MaxBytes = 4 * 1024 * 1024;
    static readonly Queue<long> attempts = new Queue<long>();
    static Task<string> worker;
    [StructLayout(LayoutKind.Sequential)]
    struct FileInfo {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfo value);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder name, uint size, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint mode,uint flags,IntPtr template);
    [StructLayout(LayoutKind.Sequential)]
    struct BasicInfo { public long Created,Accessed,Written,Changed; public uint Attributes; }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int kind,out BasicInfo value,uint size);
    public sealed class TargetInfo { public long Length,ChangeTicks; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFileAttributesW(string fileName);

    // Проверяем отсутствие по привязанному имени самого тома. Отказ в доступе,
    // извлечение диска и сетевой путь не являются подтверждением удаления файла.
    public static bool IsAbsentOnMountedVolume(string expected) {
        if(String.IsNullOrEmpty(expected)) return false;
        string path;
        int start;
        if(expected.StartsWith(@"\\?\Volume{",StringComparison.OrdinalIgnoreCase)) { path=expected; start=4; }
        else if(expected.StartsWith(@"\Device\HarddiskVolume",StringComparison.OrdinalIgnoreCase)) {
            path=@"\\?\GLOBALROOT"+expected; start=@"\\?\GLOBALROOT\Device\".Length;
        } else return false;
        int split=path.IndexOf('\\',start);
        if(split<0 || split==path.Length-1 || GetFileAttributesW(path)!=UInt32.MaxValue) return false;
        int err=Marshal.GetLastWin32Error();
        if(err!=2 && err!=3) return false;
        uint root=GetFileAttributesW(path.Substring(0,split+1));
        return root!=UInt32.MaxValue && (root & 16)!=0;
    }

    // Проверяем тот самый файл по имени тома, даже если буква уже перешла другому диску.
    // FILE_READ_ATTRIBUTES не читает данные и не создаёт обращений к содержимому файла.
    public static TargetInfo InspectTarget(string path,string expectedVolumePath) {
        try {
            if(String.IsNullOrEmpty(expectedVolumePath) || !OrdinaryPath(path)) return null;
            using(var h=CreateFile(path,0x80,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
                FileInfo info;
                if(h.IsInvalid || !GetFileInformationByHandle(h,out info) || (info.Attributes & 0x410)!=0) return null;
                var actual=new StringBuilder(32768);
                uint format=expectedVolumePath.StartsWith(@"\\?\Volume{",StringComparison.OrdinalIgnoreCase) ? 1u : 2u;
                uint n=GetFinalPathNameByHandle(h,actual,(uint)actual.Capacity,format);
                if(n==0 || n>=actual.Capacity || !String.Equals(actual.ToString(),expectedVolumePath,StringComparison.OrdinalIgnoreCase)) return null;
                BasicInfo basic;
                long changed=0;
                if(GetFileInformationByHandleEx(h,0,out basic,(uint)Marshal.SizeOf(typeof(BasicInfo))) && basic.Changed>0)
                    changed=DateTime.FromFileTimeUtc(basic.Changed).Ticks;
                return new TargetInfo {Length=((long)info.SizeHigh<<32) | info.SizeLow,ChangeTicks=changed};
            }
        } catch(Exception) { return null; }
    }

    // Не хешируем объекты за точками повторной обработки, временные облачные файлы и тома по UNC.
    static bool OrdinaryPath(string path) {
        if (String.IsNullOrEmpty(path) || path.Length < 4 || path[1]!=':' || path[2]!='\\'
            || path.IndexOf(':',2)>=0 || !String.Equals(Path.GetFullPath(path),path,StringComparison.OrdinalIgnoreCase)) return false;
        for (string item=path; item!=null; item=Path.GetDirectoryName(item)) {
            if (((uint)File.GetAttributes(item) & (0x400u | 0x1000u | 0x40000u | 0x400000u)) != 0) return false;
        }
        return true;
    }
    static bool Inspect(FileStream stream, string expected, out FileInfo info) {
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out info) || (info.Attributes & 0x410u)!=0) return false;
        var name=new StringBuilder(32768);
        uint count=GetFinalPathNameByHandle(stream.SafeFileHandle,name,(uint)name.Capacity,0);
        return count>0 && count<name.Capacity && String.Equals(name.ToString(),@"\\?\"+expected,StringComparison.OrdinalIgnoreCase);
    }
    static bool Stable(FileStream stream, FileInfo before) {
        FileInfo after;
        return GetFileInformationByHandle(stream.SafeFileHandle,out after) && before.SizeHigh==after.SizeHigh
            && before.SizeLow==after.SizeLow && before.Written.dwHighDateTime==after.Written.dwHighDateTime
            && before.Written.dwLowDateTime==after.Written.dwLowDateTime;
    }
    static string Digest(FileStream stream, uint size, Stopwatch clock) {
        var buffer=new byte[64*1024];
        using (var hash=SHA256.Create()) {
            uint total=0;
            while(total<size) {
                if(clock.ElapsedMilliseconds>700) return null;
                int n=stream.Read(buffer,0,(int)Math.Min((uint)buffer.Length,size-total));
                if(n==0) return null;
                hash.TransformBlock(buffer,0,n,buffer,0);
                total+=(uint)n;
            }
            hash.TransformFinalBlock(buffer,0,0);
            return BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
        }
    }
    static bool SourceVolumeMatches(FileStream stream,string expected) {
        if(String.IsNullOrEmpty(expected)) return false;
        var actual=new StringBuilder(32768);
        uint flags=expected.StartsWith(@"\\?\Volume{",StringComparison.OrdinalIgnoreCase) ? 1u : 2u;
        uint n=GetFinalPathNameByHandle(stream.SafeFileHandle,actual,(uint)actual.Capacity,flags);
        return n>0 && n<actual.Capacity && String.Equals(actual.ToString(),expected,StringComparison.OrdinalIgnoreCase);
    }
    static string Compare(string from,string to,string expected,Stopwatch clock) {
        try {
            if (clock.ElapsedMilliseconds>150 || !OrdinaryPath(from) || !OrdinaryPath(to)) return null;
            const FileShare share=FileShare.ReadWrite|FileShare.Delete;
            using(var a=new FileStream(from,FileMode.Open,FileAccess.Read,share))
            using(var b=new FileStream(to,FileMode.Open,FileAccess.Read,share)) {
                FileInfo left,right;
                // Буква может перейти другому диску между опросом и открытием файла.
                if(!SourceVolumeMatches(a,expected) || !Inspect(a,from,out left) || !Inspect(b,to,out right)) return null;
                if(left.Volume==right.Volume && left.IndexHigh==right.IndexHigh && left.IndexLow==right.IndexLow) return null;
                long length=((long)left.SizeHigh<<32) | left.SizeLow;
                long targetLength=((long)right.SizeHigh<<32) | right.SizeLow;
                if(length!=targetLength || length==0 || length>MaxBytes)
                    return String.Format(System.Globalization.CultureInfo.InvariantCulture,"sizes:{0}:{1}",length,targetLength);
                var h1=Digest(a,left.SizeLow,clock);
                var h2=h1==null ? null : Digest(b,right.SizeLow,clock);
                if(h2==null || !Stable(a,left) || !Stable(b,right)) return null;
                return h1==h2 ? h1 : "different";
            }
        } catch (Exception) { return null; }
    }
    // Если носитель занят, быстрый сбор событий продолжается. Одновременно работает не более одной проверки.
    public static string TryCompare(string from,string to,string expected) {
        lock (attempts) {
            long now=Stopwatch.GetTimestamp(), minute=60*Stopwatch.Frequency;
            while(attempts.Count>0 && now-attempts.Peek()>minute) attempts.Dequeue();
            if ((worker!=null && !worker.IsCompleted) || attempts.Count>=8) return null;
            attempts.Enqueue(now);
            var clock=Stopwatch.StartNew();
            worker=Task.Factory.StartNew(() => Compare(from,to,expected,clock), System.Threading.CancellationToken.None,
                                        TaskCreationOptions.None, TaskScheduler.Default);
            return worker.Wait(150) ? worker.Result : null;
        }
    }
}
'@

function Get-TransferFolders([string]$Config) {
    if (![IO.File]::Exists($Config)) { return }
    $settings=[IO.File]::ReadAllText($Config) | ConvertFrom-Json
    if ($settings.format -ne 'usb-destinations-v1') { throw 'Неизвестный формат настроек папок назначения.' }
    foreach ($item in $settings.folders) {
        $folder=[string]$item.path
        if ($folder -notmatch '^[A-Z]:\\' -or $folder.Substring(2).Contains(':')) { continue }
        $folder=[IO.Path]::GetFullPath($folder).TrimEnd('\')
        $device=[UsbAuditNative]::NtName($folder.Substring(0,2))
        [pscustomobject]@{dos=$folder;nt=if ($device) { $device+$folder.Substring(2) }}
    }
}

function ConvertTo-TransferDestination([string]$Path) {
    if ($Path.StartsWith('\??\') -or $Path.StartsWith('\\?\')) { $Path=$Path.Substring(4) }
    foreach ($folder in $script:transferFolders) {
        foreach ($prefix in @($folder.dos,$folder.nt)) {
            if ($prefix -and $Path.StartsWith($prefix+'\',[StringComparison]::OrdinalIgnoreCase)) {
                $rest=$Path.Substring($prefix.Length)
                if ($rest.EndsWith('\') -or $rest.Contains(':') -or $rest -match '(^|\\)\.{1,2}(\\|$)') { return }
                return $folder.dos+$rest
            }
        }
    }
}

function ConvertTo-LocalReadPath([string]$Path,[datetime]$When) {
    if ($Path.StartsWith('\??\')) { $Path='\\?\'+$Path.Substring(4) }
    if ($Path -match '^\\\\\?\\[A-Z]:\\') { $Path=$Path.Substring(4) }
    foreach ($prefix in $script:localAliases) {
        if (!$Path.StartsWith($prefix+'\',[StringComparison]::OrdinalIgnoreCase)) { continue }
        $relative=$Path.Substring($prefix.Length+1)
        if (!$relative -or $relative.EndsWith('\') -or $relative.Contains(':') -or $relative -match '(^|\\)\.{1,2}(\\|$)') { return }
        $result=$script:localRoots[$prefix]+'\'+$relative
        if (!(Find-Session $result $When)) { return $result }
        return
    }
}

function ConvertTo-TransferSource([string]$Path,$Session,[datetime]$When) {
    if ($Path.StartsWith('\??\') -or $Path.StartsWith('\\?\')) {
        $trimmed=$Path.Substring(4)
        if ($trimmed -match '^[A-Z]:\\') { $Path=$trimmed }
    }
    foreach ($volume in $Session.volumes) {
        if (!$volume.letter) { continue }
        foreach ($alias in $volume.paths) {
            $prefix=$alias.TrimEnd('\')+'\'
            if ($Path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
                $dos=$volume.letter+'\'+$Path.Substring($prefix.Length)
                $owner=Find-Session $dos $When
                if ($owner -and $owner.session -eq $Session.session) { return $dos }
            }
        }
    }
    return $Path
}

function Get-TransferVolumePath([string]$Path,$Session) {
    if ($Path -notmatch '^[A-Z]:\\') { return }
    foreach ($volume in $Session.volumes) {
        if ($volume.letter -ne $Path.Substring(0,2)) { continue }
        $nt=$null
        foreach ($alias in $volume.paths) {
            if ($alias.StartsWith('\\?\Volume{',[StringComparison]::OrdinalIgnoreCase)) { return $alias.TrimEnd('\')+$Path.Substring(2) }
            if ($alias.StartsWith('\Device\HarddiskVolume',[StringComparison]::OrdinalIgnoreCase)) { $nt=$alias }
        }
        if ($nt) { return $nt.TrimEnd('\')+$Path.Substring(2) }
    }
}

function Test-TransferSessionNear([datetime]$When) {
    foreach ($session in $state.sessions) {
        if ((Get-Instant $session.start) -le $When.AddSeconds($script:transferWindow) -and
            (!$session.end -or (Get-Instant $session.end) -ge $When.AddSeconds(-$script:transferWindow))) { return $true }
    }
    return $false
}

function Initialize-TransferQueue {
    if (!$state.PSObject.Properties['transferEvents']) { $state | Add-Member NoteProperty transferEvents @() }
    if (!$state.PSObject.Properties['transferGapUntil']) { $state | Add-Member NoteProperty transferGapUntil '' }
    $script:transferWindow=8
    $script:folderWatches=@{}
    $script:usbNoticeStarts=@{}
    $script:watchRetry=@{}
    $script:transferWatchDirty=$false
    $script:localRoots=@{}
    $script:localAliases=@()
    $script:kernelObserver=$null
    $script:traceRootKey=''
    $script:traceLastMounted=[datetime]::MinValue
    $script:lastLocalScan=[datetime]::MinValue
    $script:traceRetry=[datetime]::MinValue
    $script:transferEvents=[Collections.Generic.List[object]]::new()
    foreach ($row in $state.transferEvents) { if ($row) { $script:transferEvents.Add($row) } }
    $state.transferEvents=$script:transferEvents
}

function Update-TransferWatchers([bool]$Connected,[datetime]$Now) {
    foreach ($folder in $script:transferFolders) {
        $path=$folder.dos
        $watch=$script:folderWatches[$path]
        if (!$watch -and $Connected -and (!$script:watchRetry[$path] -or $script:watchRetry[$path] -le $Now)) {
            try {
                $watch=[UsbAuditDestinationWatcher]::new($path)
                $script:folderWatches[$path]=$watch
            } catch {
                Add-Notice ('watch-open-'+$path) ("Наблюдение папки «"+$path+"» недоступно: "+$_.Exception.GetBaseException().Message)
                $script:watchRetry[$path]=$Now.AddSeconds(30)
            }
        }
        if (!$watch) { continue }
        if ($watch.Error) {
            Add-Notice ('watch-loss-'+$path) ("Перерыв наблюдения за папкой «"+$path+"»: "+$watch.Error)
            $script:watchRetry[$path]=$Now.AddSeconds(5)
        } else {
            foreach ($notice in $watch.Drain()) {
                $destination=ConvertTo-TransferDestination $notice.Path
                if (!$destination) { continue }
                $when=[datetime]::new($notice.Ticks,[DateTimeKind]::Utc)
                if (Test-TransferSessionNear $when) {
                    Test-TransferCapacity $when
                    $script:transferEvents.Add([pscustomobject]@{kind='watch';path=$destination;folder=$path;change=$notice.Change;
                        key='watch|'+[IO.Path]::GetFileName($destination);ticks=$notice.Ticks;rid=('watch-'+[guid]::NewGuid())})
                    $script:transferWatchDirty=$true
                }
            }
        }
        if (!$Connected -or $watch.Error) {
            $watch.Dispose()
            $script:folderWatches.Remove($path)
        }
    }
}

function Test-TransferCapacity([datetime]$When) {
    if ($script:transferEvents.Count -lt 1024) { return }
    $script:transferEvents.Clear()
    $script:usbNoticeStarts.Clear()
    $state.transferGapUntil=Get-UtcText $When.AddSeconds($script:transferWindow)
    Add-Notice 'transfer-capacity' 'Превышен буфер сопоставления файлов. Часть переносов между компьютером и СНИ могла остаться без привязки.'
}

function Add-TransferObservation([string]$Kind,[string]$Path,$Fields,$Session,[datetime]$When,[long]$RecordId,[switch]$ToUsb) {
    $leaf=[IO.Path]::GetFileName($Path)
    if (!$leaf -or $leaf.Contains(':') -or !$Fields.ProcessName -or !$Fields.SubjectUserSid -or
        !$Fields.SubjectLogonId -or !$Fields.ProcessId -or $Fields.ProcessId -in '0','0x0') { return }
    $key=@($Fields.SubjectUserSid,$Fields.SubjectLogonId,$Fields.ProcessId,$Fields.ProcessName,$leaf) -join '|'
    $ticks=$When.Ticks
    Test-TransferCapacity $When
    $row=[pscustomobject]@{kind=$Kind;path=$Path;key=$key;ticks=$ticks;rid=$RecordId}
    # Направление в ключе исключает сопоставление встречных операций.
    $row | Add-Member NoteProperty pidValue ([Convert]::ToUInt32($Fields.ProcessId,16))
    if ($ToUsb) {
        $row.key='toUsb|'+$key
        $row | Add-Member NoteProperty direction 'toUsb'
    }
    if ($Session) { $row | Add-Member NoteProperty volumePath (Get-TransferVolumePath $Path $Session) }
    if ($Kind -eq 'read' -or $Session) {
        $account=$Fields.SubjectUserName
        if ($Fields.SubjectDomainName) { $account=$Fields.SubjectDomainName+'\'+$account }
        $row | Add-Member NoteProperty identity ([pscustomobject]@{account=$account;process=$Fields.ProcessName;
            session=$Session.session;deviceId=$Session.deviceId;serial=$Session.serial;model=$Session.model})
    }
    $script:transferEvents.Add($row)
}

function Add-UsbDestinationNotice([string]$Path,$Session,[datetime]$When,[string]$Change,[string]$Uid,[string]$OldPath) {
    $noticeKey=$Session.session+'|'+$Path
    if ($OldPath) {$script:usbNoticeStarts.Remove($Session.session+'|'+$OldPath)}
    if ($Change -eq 'deleted') {
        $script:usbNoticeStarts.Remove($noticeKey)
        $usbPath=ConvertTo-TransferSource $Path $Session $When
        Test-TransferCapacity $When
        $script:transferEvents.Add([pscustomobject]@{kind='removed';direction='toUsb';path=$usbPath;key='removed|'+$usbPath;ticks=$When.Ticks;
            identity=[pscustomobject]@{session=$Session.session}})
        $script:transferWatchDirty=$true
        return
    }
    if ($Change -notin 'created','renamed','changed') {return}
    # Одна запись, включая перезапись существующего файла, может породить серию
    # Changed. Исходные уведомления сохраняются; для сопоставления достаточно первого.
    if ($Change -eq 'changed' -and $script:usbNoticeStarts.ContainsKey($noticeKey)) {
        $delta=$When.Ticks-[long]$script:usbNoticeStarts[$noticeKey]
        if ($delta -ge 0 -and $delta -le 2*[timespan]::TicksPerSecond) {return}
    }
    $usbPath=ConvertTo-TransferSource $Path $Session $When
    $leaf=[IO.Path]::GetFileName($usbPath)
    if (!$leaf -or $leaf.Contains(':')) { return }
    Test-TransferCapacity $When
    if ($script:usbNoticeStarts.Count -ge 1024) {$script:usbNoticeStarts.Clear()}
    $script:usbNoticeStarts[$noticeKey]=$When.Ticks
    $name=@{created='Created';renamed='Renamed';changed='Changed'}[$Change]
    $identity=[pscustomobject]@{session=$Session.session;deviceId=$Session.deviceId;serial=$Session.serial;model=$Session.model}
    $script:transferEvents.Add([pscustomobject]@{kind='watch';direction='toUsb';path=$usbPath;change=$name;
        key='toUsb|watch|'+$leaf;ticks=$When.Ticks;rid=$Uid;identity=$identity;volumePath=Get-TransferVolumePath $usbPath $Session})
    $script:transferWatchDirty=$true
}

# Привязка системного имени использует точку монтирования из данного сеанса.
# Та же буква после повторного подключения может относиться к другому устройству.
function Add-AuditedUsbWrite([string]$ObjectName,[string]$UsbPath,$Session,$Fields,[datetime]$When,[long]$RecordId) {
    if (!$script:kernelObserver -or !$Fields.ProcessId -or !$Session) {return}
    $processId=[convert]::ToUInt32($Fields.ProcessId,16)
    if ($processId -le 4 -or $processId -gt [int]::MaxValue) {return}
    $native=$ObjectName
    if ($native -notmatch '^\\Device\\HarddiskVolume\d+\\.') {
        if ($UsbPath -notmatch '^[A-Z]:\\.') {return}
        $v=@($Session.volumes | Where-Object {$_.letter -eq $UsbPath.Substring(0,2)})
        if ($v.Count -ne 1) { return }
        $root=@($v[0].paths | Where-Object {$_ -match '^\\Device\\HarddiskVolume\d+\\?$'})
        if ($root.Count -ne 1) {return}
        $native=$root[0].TrimEnd('\')+$UsbPath.Substring(2)
    }
    try {$null=$script:kernelObserver.RecordAuditedUsbWrite($native,[int]$processId,$When.Ticks,$RecordId)}
    catch {Add-Notice 'kernel-audited-write' ('Не удалось передать событие записи СНИ для сопоставления: '+$_.Exception.GetBaseException().Message)}
}

function Get-TransferDigest($Usb,$LocalPath,[datetime]$When) {
    $now=[datetime]::UtcNow
    $current=Find-Session $Usb.path $now
    $sameVolume=$current -and $current.session -eq $Usb.identity.session -and !$current.firstAbsent -and !$current.removalSignal
    # Бит чтения файла в событии 4663 совпадает с битом перечисления каталога.
    # Проверяем тип только у кандидатов на перенос; извлечённый том по старой букве не открываем.
    if ([IO.Directory]::Exists($LocalPath) -or ($sameVolume -and $Usb.path -match '^[A-Z]:\\' -and [IO.Directory]::Exists($Usb.path))) {
        return 'directory'
    }
    if ($Usb.volumePath -and $sameVolume -and ($now-$When).TotalSeconds -le 45) {
        # Первый дескриптор всегда принадлежит USB и проверяется по системному имени тома.
        return [UsbAuditFileComparison]::TryCompare($Usb.path,$LocalPath,$Usb.volumePath)
    }
}

function New-TransferFields($Read,$Edge,[string]$Evidence) {
    $usb=if ($Edge.direction -eq 'toUsb') {$Edge} else {$Read}
    $identity=$usb.identity
    $fields=@{session=$identity.session;deviceId=$identity.deviceId;serial=$identity.serial;model=$identity.model
        account=$Read.identity.account;process=$Read.identity.process;path=$usb.path;destination=$Edge.path;evidence=$Evidence
        sourceRecordId=$Read.rid;logEpoch=$state.logEpoch}
    if ($Edge.direction -eq 'toUsb') {
        $fields.direction='toUsb'
        $fields.localPath=$Read.path
        $fields.sourcePath=$Read.path
    }
    return $fields
}

function Test-TransferReadInSession($Read,$Edge) {
    if ($Edge.direction -ne 'toUsb') { return $true }
    $when=[datetime]::new([long]$Read.ticks,[DateTimeKind]::Utc)
    $owner=Find-Session $Edge.path $when
    return ($null -ne $owner -and $owner.session -eq $Edge.identity.session)
}

# Ядро сообщает пары чтение/запись. Коллектор привязывает их к физическому СНИ по
# системному пути и обеим отметкам времени, включая уже завершённые сеансы.
function Add-KernelTransfer($Pair) {
    $when=[datetime]::new([long]$Pair.WriteTicks,[datetimekind]::Utc)
    $readAt=[datetime]::new([long]$Pair.ReadTicks,[datetimekind]::Utc)
    $owner=Find-Session $Pair.DestinationNt $when
    if (!$owner -or (Find-Session $Pair.DestinationNt $readAt).session -ne $owner.session) {return}
    $local=ConvertTo-LocalReadPath $Pair.SourceNt $readAt
    if (!$local -or (Find-Session $Pair.SourceNt $readAt)) {return}
    $usb=ConvertTo-TransferSource $Pair.DestinationNt $owner $when
    Test-TransferCapacity $when
    $identity=[pscustomobject]@{session=$owner.session;deviceId=$owner.deviceId;serial=$owner.serial;model=$owner.model}
    $script:transferEvents.Add([pscustomobject]@{kind='kernel';direction='toUsb';path=$usb;localPath=$local;usbNtPath=$Pair.DestinationNt;
        key='kernel|'+[IO.Path]::GetFileName($usb);ticks=$Pair.WriteTicks;readTicks=$Pair.ReadTicks;
        pidValue=$Pair.ProcessId;rid=[guid]::NewGuid().ToString();identity=$identity;volumePath=Get-TransferVolumePath $usb $owner
        securityWriteId=[long]$Pair.SecurityWriteId;auditedOnly=([long]$Pair.SecurityWriteId -gt 0 -and !$Pair.HasKernelWrite)})
    $script:transferWatchDirty=$true
}

# 18905 содержит оба имени (включая новое имя назначения), вид команды и размер.
# Запись Проводника сама по себе не доказывает изменения файла.
function Add-ShellTransfer($Operation) {
    $when=[datetime]::new([long]$Operation.Ticks,[datetimekind]::Utc)
    $srcUsb=Find-Session $Operation.SourceNt $when
    $dstUsb=Find-Session $Operation.DestinationNt $when
    if ((!$srcUsb -and !$dstUsb) -or ($srcUsb -and $dstUsb) -or $Operation.Operation -notin 'copy','move' -or $Operation.FileSize -lt 0) {return}
    if ($dstUsb) {
        $owner=$dstUsb
        $direction='toUsb'
        $usb=ConvertTo-TransferSource $Operation.DestinationNt $owner $when
        $local=ConvertTo-LocalReadPath $Operation.SourceNt $when
        $destination=$usb
    } else {
        $owner=$srcUsb
        $direction='fromUsb'
        $usb=ConvertTo-TransferSource $Operation.SourceNt $owner $when
        $local=ConvertTo-LocalReadPath $Operation.DestinationNt $when
        $destination=$local
    }
    if (!$local -or !$usb -or $usb -notmatch '^[A-Z]:\\.' -or ![IO.Path]::GetFileName($usb)) {return}
    Test-TransferCapacity $when
    $identity=[pscustomobject]@{session=$owner.session;deviceId=$owner.deviceId;serial=$owner.serial;model=$owner.model}
    $script:transferEvents.Add([pscustomobject]@{kind='shell';key='shell|'+$destination;ticks=$Operation.Ticks;path=$destination;
        usbPath=$usb;localPath=$local;destinationNt=$Operation.DestinationNt;identity=$identity;direction=$direction;
        pidValue=$Operation.ProcessId;operation=$Operation.Operation;fileSize=$Operation.FileSize})
    $script:transferWatchDirty=$true
}

# Связываем точное назначение с изменением на диске. Существующий файл с таким
# именем, в том числе пустой, не считается самостоятельным подтверждением.
function Complete-ShellTransfers($ByDestination,[long]$WatermarkTicks,[long]$Gap) {
    $distance=2*[timespan]::TicksPerSecond
    foreach ($shell in $script:transferEvents) {
        if ($shell.kind -ne 'shell' -or $shell.ticks -gt $WatermarkTicks-$distance) {continue}
        $shell.kind='shellDone'
        if ($shell.ticks -le $Gap) {continue}
        $peers=@($ByDestination[$shell.path] | Where-Object {$_ -ne $shell -and
            [math]::Abs([long]$_.ticks-[long]$shell.ticks) -le $distance})
        # Два запроса к одному назначению нельзя подтверждать одним уведомлением.
        if (@($peers | Where-Object {$_.kind -in 'shell','shellDone' -or $_.published}).Count) {continue}
        $when=[datetime]::new([long]$shell.ticks,[datetimekind]::Utc)
        $now=[datetime]::UtcNow
        $current=Find-Session $shell.usbPath $now
        if (!$current -or $current.firstAbsent -or $current.removalSignal -or $current.session -ne $shell.identity.session) {continue}
        $toUsb=$shell.direction -eq 'toUsb'
        $target=[UsbAuditFileComparison]::InspectTarget($shell.path,$shell.destinationNt)
        if (!$target -or $target.Length -ne $shell.fileSize) {continue}
        $observations=@($peers | Where-Object {($_.direction -eq 'toUsb') -eq $toUsb -and
            (!$toUsb -or $_.identity.session -eq $current.session)})
        $writes=@($observations | Where-Object {$_.kind -in 'write','done'})
        if (@($writes | Where-Object {$_.pidValue -ne $shell.pidValue}).Count) {continue}
        $watch=@($observations | Where-Object {$_.kind -in 'watch','watchDone' -and $_.change -in 'Created','Changed','Renamed'})
        $localChanged=$false
        if (!$toUsb -and !$watch.Count) {
            foreach ($folderWatch in $script:folderWatches.Values) {
                if ($folderWatch.ChangedNear($shell.path,$shell.ticks,$distance)) {$localChanged=$true;break}
            }
        }
        # Для произвольной локальной папки проверяем ChangeTime NTFS по дескриптору
        # назначения. Засчитываем только изменение ПОСЛЕ события в двухсекундном окне.
        $recentLocal=(!$toUsb -and $target.ChangeTicks -gt $shell.ticks -and $target.ChangeTicks-$shell.ticks -le $distance)
        if (!$writes.Count -and !$watch.Count -and !$localChanged -and !$recentLocal) {continue}
        $usbEdge=[pscustomobject]@{path=$shell.usbPath;identity=$shell.identity;volumePath=Get-TransferVolumePath $shell.usbPath $current}
        $digest=Get-TransferDigest $usbEdge $shell.localPath $when
        if ($digest -in 'directory','different') {continue}
        if ($digest -match '^sizes:(\d+):(\d+)$' -and ($Matches[1] -ne $Matches[2] -or [long]$Matches[1] -ne $target.Length)) {continue}
        if (!$writes.Count -and !$watch.Count -and !$localChanged) {
            # Смена одних атрибутов без подтверждения второй стороны недостаточна.
            if ($shell.operation -eq 'copy' -and $digest -notmatch '^[0-9a-f]{64}$|^sizes:0:0$') {continue}
            if ($shell.operation -eq 'move') {
                try { $null=[IO.File]::GetAttributes($shell.usbPath);continue }
                catch [IO.FileNotFoundException] {}
                catch {continue}
            }
        }
        $fields=@{direction=$shell.direction;source='shellFileOperation';evidence='shellDestinationObserved';shellEventId=18905;
            operation=$shell.operation;sourcePath=if ($toUsb) {$shell.localPath} else {$shell.usbPath};
            destination=$shell.path;localPath=$shell.localPath;path=$shell.usbPath;processId=$shell.pidValue;
            sourceBytes=$shell.fileSize;destinationBytes=$target.Length;
            session=$current.session;deviceId=$current.deviceId;serial=$current.serial;model=$current.model}
        if ($digest -match '^[0-9a-f]{64}$') {$fields.sha256=$digest}
        if ($writes.Count) {
            $writer=$writes[0]
            $fields.destinationRecordId=$writer.rid
            $fields.logEpoch=$state.logEpoch
            if ($writer.identity.account) {$fields.account=$writer.identity.account;$fields.process=$writer.identity.process}
        }
        if ($watch.Count) {
            $fields.destinationChange=$watch[0].change
            if ($toUsb) {$fields.destinationEventUid=$watch[0].rid}
        } elseif ($localChanged) {$fields.destinationChange='Changed'}
        elseif (!$writes.Count) {$fields.destinationChange='ChangeTime'}
        New-Entry 'transfer' $when $fields
        $shell | Add-Member NoteProperty published $true
    }
}

function Test-ShellCoveredDestination($ByDestination,$Edge) {
    foreach ($item in $ByDestination[$Edge.path]) {
        if ($item.kind -eq 'shellDone' -and $item.published -and ($item.direction -eq 'toUsb') -eq ($Edge.direction -eq 'toUsb') -and
            (!$Edge.identity.session -or $Edge.identity.session -eq $item.identity.session) -and
            [math]::Abs([long]$item.ticks-[long]$Edge.ticks) -le 2*[timespan]::TicksPerSecond) {return $true}
    }
    return $false
}

function Update-KernelTransferObserver([datetime]$Now) {
    $usbRoots=@(foreach ($s in $state.sessions) {
        if (!$s.end -and !$s.firstAbsent -and !$s.removalSignal) {
            Get-Paths $s.volumes | Where-Object {$_ -match '^\\Device\\HarddiskVolume\d+$'}
        }
    })
    # Drain до смены перечня: прежний том мог исчезнуть между опросами.
    try {
        if ($script:kernelObserver) {
            foreach ($pair in $script:kernelObserver.Drain()) {Add-KernelTransfer $pair}
            if ($script:kernelObserver.TakeShellLoss()) {
                Add-Notice 'shell-loss' 'Windows сообщила о пропуске команд Проводника. Часть переносов могла остаться без привязки.'
            }
            foreach ($operation in $script:kernelObserver.DrainShell()) {Add-ShellTransfer $operation}
            if ($script:kernelObserver.TakeLoss()) {Add-Notice 'kernel-loss' 'Windows сообщила о пропуске файловых событий ядра. Часть источников переноса на СНИ могла остаться неизвестной.'}
            if ($usbRoots.Count -and !$script:kernelObserver.IsRunning) {throw 'Сеанс наблюдения завершился.'}
            # После быстрого извлечения ещё могут прибыть уже произошедшие операции
            # и их имена из буферов ETW. Принимаются только времена действительного сеанса.
            if (!$usbRoots.Count -and ($Now-$script:traceLastMounted).TotalSeconds -ge 15) {
                $script:kernelObserver.Dispose();$script:kernelObserver=$null
            }
        }
        if (!$usbRoots.Count) { $script:traceRootKey='';return }
        $script:traceLastMounted=$Now
        if ($Now -lt $script:traceRetry) {return}
        $key=($usbRoots | Sort-Object -Unique) -join '|'
        if ($key -ne $script:traceRootKey -or ($Now-$script:lastLocalScan).TotalSeconds -ge 30) {
            $script:localRoots=[UsbAuditNative]::LocalRoots()
            $script:localAliases=@($script:localRoots.Keys | Sort-Object Length -Descending)
            $fixedRoots=@($script:localAliases | Where-Object {$_ -match '^\\Device\\HarddiskVolume\d+$' -and $_ -notin $usbRoots})
            if (!$fixedRoots.Count) {throw 'Не найдены доступные локальные тома с подтверждённой шиной.'}
            $script:traceFixedRoots=[string[]]$fixedRoots
            if ($script:kernelObserver) {$script:kernelObserver.UpdateRoots([string[]]$usbRoots,$script:traceFixedRoots)}
            $script:traceRootKey=$key
            $script:lastLocalScan=$Now
        }
        if (!$script:kernelObserver) {
            if (!('UsbAuditTransferObserver' -as [type])) {
                Add-Type -Path @((Join-Path $PSScriptRoot 'KernelFileTrace.cs'),(Join-Path $PSScriptRoot 'KernelTransferMatcher.cs'))
            }
            $script:kernelObserver=[UsbAuditTransferObserver]::new([string[]]$usbRoots,$script:traceFixedRoots,$PID)
            if ($script:kernelObserver.ShellStatus) {Add-Notice 'shell-start' ('Наблюдение команд Проводника недоступно: '+$script:kernelObserver.ShellStatus)}
        }
    } catch {
        if ($script:kernelObserver) {
            try {$script:kernelObserver.Dispose()} catch {}
            $script:kernelObserver=$null
        }
        Add-Notice 'kernel-start' ('Сопоставление путей через события ядра временно недоступно: '+$_.Exception.GetBaseException().Message)
        $script:traceRetry=$Now.AddSeconds(15)
    }
}

function Complete-TransferObservations([datetime]$Watermark,[switch]$KernelOnly) {
    if (!$script:transferEvents.Count) { return }
    $window=[timespan]::FromSeconds($script:transferWindow).Ticks
    $cutoff=$Watermark.Ticks-$window
    $gap=0L
    if ($state.transferGapUntil) { $gap=(Get-Instant $state.transferGapUntil).Ticks }
    # Обе стороны могут появиться в Security в любом порядке. Решение принимаем после всего окна.
    $groups=@{}
    $publishedKernel=@{}
    $byDestination=@{}
    foreach ($edge in $script:transferEvents) {
        if ($edge.kind -ne 'read') {
            if (!$byDestination.ContainsKey($edge.path)) {$byDestination[$edge.path]=[Collections.Generic.List[object]]::new()}
            $byDestination[$edge.path].Add($edge)
        }
        if (!$groups.ContainsKey($edge.key)) { $groups[$edge.key]=[Collections.Generic.List[object]]::new() }
        $groups[$edge.key].Add($edge)
        if ($edge.kind -eq 'kernelDone' -and $edge.published) {
            $k=$edge.identity.session+'|'+$edge.path+'|'+$edge.localPath+'|'+$edge.pidValue
            if (!$publishedKernel.ContainsKey($k)) {$publishedKernel[$k]=[Collections.Generic.List[long]]::new()}
            $publishedKernel[$k].Add([long]$edge.ticks)
        }
    }
    Complete-ShellTransfers $byDestination $Watermark.Ticks $gap
    foreach ($edge in $script:transferEvents) {
        if ($KernelOnly -or $edge.kind -ne 'write' -or $edge.ticks -gt $cutoff) { continue }
        $edge.kind='done'
        if ($edge.ticks -le $gap -or (Test-ShellCoveredDestination $byDestination $edge)) { continue }
        $candidates=@{}
        $repeat=$false
        foreach ($other in $groups[$edge.key]) {
            if ($other.rid -eq $edge.rid -or [math]::Abs([long]$other.ticks-[long]$edge.ticks) -gt $window) { continue }
            if ($other.kind -eq 'done' -and $other.path -eq $edge.path -and $other.identity.session -eq $edge.identity.session -and
                [math]::Abs([long]$other.ticks-[long]$edge.ticks) -le [timespan]::TicksPerSecond*2) { $repeat=$true }
            if ($other.kind -eq 'read' -and (Test-TransferReadInSession $other $edge)) { $candidates[$other.identity.session+'|'+$other.path]=$other }
        }
        if ($repeat -or $candidates.Count -ne 1) { continue }
        $read=@($candidates.Values)[0]
        if ($edge.direction -eq 'toUsb') {
            $k=$edge.identity.session+'|'+$edge.path+'|'+$read.path+'|'+$edge.pidValue
            if ($publishedKernel.ContainsKey($k) -and @($publishedKernel[$k] | Where-Object {[Math]::Abs($_-[long]$edge.ticks) -le $window}).Count) {continue}
        }
        $when=[datetime]::new([long]$edge.ticks,[DateTimeKind]::Utc)
        $fields=New-TransferFields $read $edge 'pairedAccess'
        $fields.destinationRecordId=$edge.rid
        $digest=if ($edge.direction -eq 'toUsb') { Get-TransferDigest $edge $read.path $when } else { Get-TransferDigest $read $edge.path $when }
        if ($digest -in 'different','directory') { continue }
        if ($digest -match '^sizes:(\d+):(\d+)$') {
            if ($Matches[1] -ne $Matches[2]) { continue }
            $fields.sourceBytes=[long]$Matches[1]; $fields.destinationBytes=[long]$Matches[2]
        } elseif ($digest) { $fields.evidence='matchingContent'; $fields.sha256=$digest }
        New-Entry 'transfer' $when $fields
        $edge | Add-Member NoteProperty published $true
        if ($edge.direction -eq 'toUsb') { $edge | Add-Member NoteProperty localPath $read.path }
    }
    # Для уведомления о новом имени Windows не сообщает процесс записи. Даём парам 4663 приоритет.
    $byName=@{}
    foreach ($item in $script:transferEvents) {
        $name=[string]$item.direction+'|'+[IO.Path]::GetFileName($item.path)
        if (!$byName.ContainsKey($name)) { $byName[$name]=[Collections.Generic.List[object]]::new() }
        $byName[$name].Add($item)
    }
    foreach ($edge in $script:transferEvents) {
        if ($edge.kind -ne 'kernel' -or $edge.ticks -gt $cutoff) { continue }
        $edge.kind='kernelDone'
        if ($edge.ticks -le $gap -or (Test-ShellCoveredDestination $byDestination $edge)) { continue }
        $peers=$byName[('toUsb|'+[IO.Path]::GetFileName($edge.path))]
        $near=@($peers | Where-Object {$_ -ne $edge -and $_.path -eq $edge.path -and $_.identity.session -eq $edge.identity.session -and
            [Math]::Abs([long]$_.ticks-[long]$edge.ticks) -le $window})
        $writer=@($near | Where-Object {$_.kind -in 'write','done' -and $_.pidValue -eq $edge.pidValue} | Sort-Object ticks)
        $observed=@($near | Where-Object {$_.kind -in 'watch','watchDone'})
        # Проверка и удаление двух одноимённых файлов тоже могут породить пару
        # Kernel-File и Changed. Ищем отдельное подтверждение записи или создания.
        $created=@($observed | Where-Object {$_.change -in 'Created','Renamed'})
        if (!$writer.Count -and !$created.Count) {
            if (@($near | Where-Object {$_.kind -eq 'removed'}).Count -or
                [UsbAuditFileComparison]::IsAbsentOnMountedVolume($edge.volumePath)) {continue}
        }
        # Пара 4663 сохраняет исходные номера Security. Второе основание не дублирует перенос.
        if (@($near | Where-Object {$_.published -and ($_.localPath -eq $edge.localPath -or $_.pidValue -eq $edge.pidValue)}).Count) {continue}
        $when=[datetime]::new([long]$edge.ticks,[datetimekind]::Utc)
        $digest=Get-TransferDigest $edge $edge.localPath $when
        if ($digest -in 'different','directory') {continue}
        if ($digest -match '^sizes:(\d+):(\d+)$' -and $Matches[1] -ne $Matches[2]) {continue}
        if ($edge.auditedOnly) {
            $writer=@($writer | Where-Object {$_.rid -eq $edge.securityWriteId})
            if (!$writer.Count) {continue}
        }
        $basis=if($edge.auditedOnly){'kernelReadSecurityWrite'}else{'kernelFileIO'}
        $fields=@{direction='toUsb';source=$basis;evidence='pairedKernelAccess';processId=$edge.pidValue;
            sourcePath=$edge.localPath;localPath=$edge.localPath;destination=$edge.path;path=$edge.path;usbNtPath=$edge.usbNtPath;
            kernelReadTime=Get-UtcText ([datetime]::new([long]$edge.readTicks,[datetimekind]::Utc));
            session=$edge.identity.session;deviceId=$edge.identity.deviceId;serial=$edge.identity.serial;model=$edge.identity.model}
        if ($digest -match '^[a-fA-F0-9]{64}$') {$fields.sha256=$digest;$fields.evidence='kernelMatchingContent'}
        if ($writer.Count -and @($writer | ForEach-Object {$_.key} | Sort-Object -Unique).Count -eq 1) {
            $fields.destinationRecordId=$writer[0].rid
            $fields.logEpoch=$state.logEpoch
            $fields.account=$writer[0].identity.account
            $fields.process=$writer[0].identity.process
        }
        if ($observed.Count -eq 1) {$fields.destinationEventUid=$observed[0].rid;$fields.destinationChange=$observed[0].change}
        New-Entry 'transfer' $when $fields
        $edge | Add-Member NoteProperty published $true
    }
    foreach ($edge in $script:transferEvents) {
        if ($KernelOnly -or $edge.kind -ne 'watch' -or $edge.ticks -gt $cutoff-$window) { continue }
        $peers=$byName[([string]$edge.direction+'|'+[IO.Path]::GetFileName($edge.path))]
        $edge.kind='watchDone'
        if ($edge.ticks -le $gap -or (Test-ShellCoveredDestination $byDestination $edge)) { continue }
        $candidates=@{}
        $actors=@{}
        $readIds=[Collections.Generic.HashSet[long]]::new()
        $otherWrite=$false
        foreach ($item in $peers) {
            if ([math]::Abs([long]$item.ticks-[long]$edge.ticks) -gt $window) {continue}
            if ($item.path -eq $edge.path -and $item.published -and $item.identity.session -eq $edge.identity.session) {$otherWrite=$true}
            if ($item.kind -eq 'read' -and (Test-TransferReadInSession $item $edge)) {
                $candidates[$item.identity.session+'|'+$item.path]=$item
                $actors[$item.key]=$true
                [void]$readIds.Add([long]$item.rid)
            }
        }
        if ($otherWrite -or $candidates.Count -ne 1) {continue}
        $read=@($candidates.Values)[0]
        $when=[datetime]::new([long]$edge.ticks,[DateTimeKind]::Utc)
        $digest=if ($edge.direction -eq 'toUsb') { Get-TransferDigest $edge $read.path $when } else { Get-TransferDigest $read $edge.path $when }
        if ($digest -in 'different','directory') {continue}
        # SHA-256 связывает два файла, но не определяет, какой процесс выполнил перенос.
        if (($actors.Count -gt 1 -or $edge.direction -eq 'toUsb') -and $digest -notmatch '^[a-fA-F0-9]{64}$') {continue}
        $fields=New-TransferFields $read $edge 'observedCreation'
        if ($actors.Count -gt 1) {
            $fields.account=$null
            $fields.process=$null
            $fields.Remove('sourceRecordId')
            $fields.sourceRecordIds=@($readIds | Sort-Object)
        }
        if ($digest -match '^sizes:(\d+):(\d+)$') {
            $fields.sourceBytes=[long]$Matches[1]; $fields.destinationBytes=[long]$Matches[2]
        } elseif ($digest) {
            $fields.evidence='observedMatchingContent'
            $fields.sha256=$digest
        } else {
            Add-Notice ('watch-verify-'+$edge.folder) ("Содержимое файла для папки «"+$edge.folder+"» проверить не удалось. Возможны ограничения доступа, размера, времени сверки или отключение СНИ.")
        }
        $fields.destinationChange=$edge.change
        if ($edge.direction -eq 'toUsb') { $fields.destinationEventUid=$edge.rid }
        New-Entry 'transfer' $when $fields
        $edge | Add-Member NoteProperty published $true
        if ($edge.direction -eq 'toUsb') {$edge | Add-Member NoteProperty localPath $read.path}
    }
    # В личной папке Windows может запретить сборщику проверку результата. После
    # обычного окна сопоставления сохраняем ровно то, что сообщил Проводник.
    foreach ($edge in $script:transferEvents) {
        if ($edge.kind -ne 'shellDone' -or $edge.direction -ne 'fromUsb' -or $edge.published -or
            $edge.ticks -le $gap -or $edge.ticks -gt $cutoff-$window) {continue}
        if (ConvertTo-TransferDestination $edge.path) {continue}
        $edge.kind='shellReported'
        $same=@($byDestination[$edge.path] | Where-Object {$_.published -and
            [Math]::Abs([long]$_.ticks-[long]$edge.ticks) -le 2*[timespan]::TicksPerSecond})
        if ($same.Count) {continue}
        $when=[datetime]::new([long]$edge.ticks,[datetimekind]::Utc)
        New-Entry 'shellCommand' $when @{
            direction=$edge.direction;source='shellFileOperation';evidence='shellOutcomeUnknown';shellEventId=18905
            operation=$edge.operation;sourcePath=$edge.usbPath;path=$edge.usbPath;localPath=$edge.localPath;destination=$edge.path
            processId=$edge.pidValue;session=$edge.identity.session;deviceId=$edge.identity.deviceId;serial=$edge.identity.serial;model=$edge.identity.model
        }
    }
    # Чтение должно пережить ещё одно окно для записей, ожидающих уточнения.
    $keepAfter=$cutoff-2*$window
    $script:transferEvents.RemoveAll([Predicate[object]]{param($edge)
        $edge.ticks -lt $keepAfter -and (!$KernelOnly -or $edge.kind -in 'kernelDone','shellDone','shellReported')}) | Out-Null
}
