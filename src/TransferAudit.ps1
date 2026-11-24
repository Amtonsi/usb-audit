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

// Очередь создаётся только для выбранной папки во время сеанса USB.
// Обработчик .NET принимает уведомления Windows независимо от цикла чтения Security.
public sealed class UsbAuditDestinationWatcher : IDisposable {
    public sealed class Notice {
        public string Path, Change;
        public long Ticks;
    }
    readonly FileSystemWatcher watcher;
    readonly Queue<Notice> queue=new Queue<Notice>();
    string failure;
    public UsbAuditDestinationWatcher(string path) {
        watcher=new FileSystemWatcher(path);
        try {
            watcher.IncludeSubdirectories=true;
            watcher.NotifyFilter=NotifyFilters.FileName;
            watcher.InternalBufferSize=32*1024;
            watcher.Created+=(s,e)=>Add(e.FullPath,"Created");
            watcher.Renamed+=(s,e)=>Add(e.FullPath,"Renamed");
            watcher.Error+=(s,e)=>{lock(queue) { failure=e.GetException().Message; queue.Clear(); }};
            watcher.EnableRaisingEvents=true;
        } catch { watcher.Dispose(); throw; }
    }
    void Add(string path,string change) {
        lock(queue) {
            if(failure!=null) return;
            if(queue.Count>=512) {failure="Переполнение очереди наблюдения"; queue.Clear(); return;}
            queue.Enqueue(new Notice {Path=path,Change=change,Ticks=DateTime.UtcNow.Ticks});
        }
    }
    public Notice[] Drain() {lock(queue) {var events=queue.ToArray();queue.Clear();return events;}}
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
    $script:watchRetry=@{}
    $script:transferWatchDirty=$false
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
    $state.transferGapUntil=Get-UtcText $When.AddSeconds($script:transferWindow)
    Add-Notice 'transfer-capacity' 'Превышен буфер сопоставления файлов. Часть переносов со СНИ могла остаться без привязки.'
}

function Add-TransferObservation([string]$Kind,[string]$Path,$Fields,$Session,[datetime]$When,[long]$RecordId) {
    $leaf=[IO.Path]::GetFileName($Path)
    if (!$leaf -or $leaf.Contains(':') -or !$Fields.ProcessName -or !$Fields.SubjectUserSid -or
        !$Fields.SubjectLogonId -or !$Fields.ProcessId -or $Fields.ProcessId -in '0','0x0') { return }
    $key=@($Fields.SubjectUserSid,$Fields.SubjectLogonId,$Fields.ProcessId,$Fields.ProcessName,$leaf) -join '|'
    $ticks=$When.Ticks
    Test-TransferCapacity $When
    $row=[pscustomobject]@{kind=$Kind;path=$Path;key=$key;ticks=$ticks;rid=$RecordId}
    if ($Kind -eq 'read') {
        $row | Add-Member NoteProperty volumePath (Get-TransferVolumePath $Path $Session)
        $account=$Fields.SubjectUserName
        if ($Fields.SubjectDomainName) { $account=$Fields.SubjectDomainName+'\'+$account }
        $row | Add-Member NoteProperty identity ([pscustomobject]@{account=$account;process=$Fields.ProcessName;
            session=$Session.session;deviceId=$Session.deviceId;serial=$Session.serial;model=$Session.model})
    }
    $script:transferEvents.Add($row)
}

function Get-TransferDigest($Read,$Destination,[datetime]$When) {
    $now=[datetime]::UtcNow
    $current=Find-Session $Read.path $now
    if ($Read.volumePath -and $current -and $current.session -eq $Read.identity.session -and
        !$current.firstAbsent -and !$current.removalSignal -and ($now-$When).TotalSeconds -le 45) {
        return [UsbAuditFileComparison]::TryCompare($Read.path,$Destination,$Read.volumePath)
    }
}

function New-TransferFields($Read,$Edge,[string]$Evidence) {
    $identity=$Read.identity
    return @{session=$identity.session;deviceId=$identity.deviceId;serial=$identity.serial;model=$identity.model
        account=$identity.account;process=$identity.process;path=$Read.path;destination=$Edge.path;evidence=$Evidence
        sourceRecordId=$Read.rid;logEpoch=$state.logEpoch}
}

function Complete-TransferObservations([datetime]$Watermark) {
    if (!$script:transferEvents.Count) { return }
    $window=[timespan]::FromSeconds($script:transferWindow).Ticks
    $cutoff=$Watermark.Ticks-$window
    $gap=0L
    if ($state.transferGapUntil) { $gap=(Get-Instant $state.transferGapUntil).Ticks }
    # Обе стороны могут появиться в Security в любом порядке. Решение принимаем после всего окна.
    $groups=@{}
    foreach ($edge in $script:transferEvents) {
        if (!$groups.ContainsKey($edge.key)) { $groups[$edge.key]=[Collections.Generic.List[object]]::new() }
        $groups[$edge.key].Add($edge)
    }
    foreach ($edge in $script:transferEvents) {
        if ($edge.kind -ne 'write' -or $edge.ticks -gt $cutoff) { continue }
        $edge.kind='done'
        if ($edge.ticks -le $gap) { continue }
        $candidates=@{}
        $repeat=$false
        foreach ($other in $groups[$edge.key]) {
            if ($other.rid -eq $edge.rid -or [math]::Abs([long]$other.ticks-[long]$edge.ticks) -gt $window) { continue }
            if ($other.kind -eq 'done' -and $other.path -eq $edge.path -and
                [math]::Abs([long]$other.ticks-[long]$edge.ticks) -le [timespan]::TicksPerSecond*2) { $repeat=$true }
            if ($other.kind -eq 'read') { $candidates[$other.identity.session+'|'+$other.path]=$other }
        }
        if ($repeat -or $candidates.Count -ne 1) { continue }
        $read=@($candidates.Values)[0]
        $when=[datetime]::new([long]$edge.ticks,[DateTimeKind]::Utc)
        $fields=New-TransferFields $read $edge 'pairedAccess'
        $fields.destinationRecordId=$edge.rid
        $digest=Get-TransferDigest $read $edge.path $when
        if ($digest -eq 'different') { continue }
        if ($digest -match '^sizes:(\d+):(\d+)$') {
            if ($Matches[1] -ne $Matches[2]) { continue }
            $fields.sourceBytes=[long]$Matches[1]; $fields.destinationBytes=[long]$Matches[2]
        } elseif ($digest) { $fields.evidence='matchingContent'; $fields.sha256=$digest }
        New-Entry 'transfer' $when $fields
        $edge | Add-Member NoteProperty published $true
    }
    # Для уведомления о новом имени Windows не сообщает процесс записи. Даём парам 4663 приоритет.
    $byName=@{}
    foreach ($item in $script:transferEvents) {
        $name=[IO.Path]::GetFileName($item.path)
        if (!$byName.ContainsKey($name)) { $byName[$name]=[Collections.Generic.List[object]]::new() }
        $byName[$name].Add($item)
    }
    foreach ($edge in $script:transferEvents) {
        if ($edge.kind -ne 'watch' -or $edge.ticks -gt $cutoff-$window) { continue }
        $peers=$byName[[IO.Path]::GetFileName($edge.path)]
        $edge.kind='watchDone'
        if ($edge.ticks -le $gap) { continue }
        $candidates=@{}
        $otherWrite=$false
        foreach ($item in $peers) {
            if ([math]::Abs([long]$item.ticks-[long]$edge.ticks) -gt $window) {continue}
            if ($item.path -eq $edge.path -and $item.published) {$otherWrite=$true}
            if ($item.kind -eq 'read') {$candidates[$item.identity.session+'|'+$item.key+'|'+$item.path]=$item}
        }
        if ($otherWrite -or $candidates.Count -ne 1) {continue}
        $read=@($candidates.Values)[0]
        $when=[datetime]::new([long]$edge.ticks,[DateTimeKind]::Utc)
        $digest=Get-TransferDigest $read $edge.path $when
        if ($digest -eq 'different') {continue}
        $fields=New-TransferFields $read $edge 'observedCreation'
        if ($digest -match '^sizes:(\d+):(\d+)$') {
            $fields.sourceBytes=[long]$Matches[1]; $fields.destinationBytes=[long]$Matches[2]
        } elseif ($digest) {
            $fields.evidence='observedMatchingContent'
            $fields.sha256=$digest
        } else {
            Add-Notice ('watch-verify-'+$edge.folder) ("Содержимое файла для папки «"+$edge.folder+"» проверить не удалось. Возможны ограничения доступа, размера, времени сверки или отключение СНИ.")
        }
        $fields.destinationChange=$edge.change
        New-Entry 'transfer' $when $fields
        $edge | Add-Member NoteProperty published $true
    }
    # Чтение должно пережить ещё одно окно для записей, ожидающих уточнения.
    $keepAfter=$cutoff-2*$window
    $script:transferEvents.RemoveAll([Predicate[object]]{param($edge) $edge.ticks -lt $keepAfter}) | Out-Null
}
