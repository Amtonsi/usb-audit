using System;
using System.Collections.Generic;
using System.Linq;

// ETW передаёт пути при открытии файла, а при чтении и записи — ключи
// открытых объектов. За пределы этого буфера выходят только пары ПК -> USB.
public sealed class UsbAuditTransferMatcher
{
    public sealed class Pair
    {
        public string SourceNt, DestinationNt;
        public int ProcessId;
        public long ReadTicks, WriteTicks, SecurityWriteId;
        public bool HasKernelWrite;
    }
    sealed class FileName
    {
        public string Path, Leaf;
        public bool Usb;
    }
    sealed class Write
    {
        public string Destination, Source;
        public int Pid;
        public long First, Last, Read, SecurityId;
        public bool Ambiguous, KernelWrite;
        public void Consider(string source, long ticks)
        {
            if (Source != null && !Same(Source, source)) { Ambiguous = true; return; }
            if (Source == null || Math.Abs(ticks - First) < Math.Abs(Read - First)) Read = ticks;
            Source = source;
        }
    }
    // Оставляем фактические метки чтения на время доставки Security. При
    // повторном чтении новый доступ не должен затереть прежнее окно копирования.
    sealed class ReadHistory
    {
        readonly List<long> samples = new List<long>(1);
        public bool Empty { get { return samples.Count==0; } }
        public void Observe(long ticks)
        {
            int pos=samples.BinarySearch(ticks);
            if (pos>=0) return;
            pos=~pos;
            long sec=ticks/TimeSpan.TicksPerSecond;
            bool previous=pos>0 && samples[pos-1]/TimeSpan.TicksPerSecond==sec;
            bool next=pos<samples.Count && samples[pos]/TimeSpan.TicksPerSecond==sec;
            // Достаточно первого и последнего фактического чтения за секунду.
            if (previous && next) return;
            if(previous && pos>1 && samples[pos-2]/TimeSpan.TicksPerSecond==sec) {samples[pos-1]=ticks;return;}
            if(next && pos+1<samples.Count && samples[pos+1]/TimeSpan.TicksPerSecond==sec) {samples[pos]=ticks;return;}
            samples.Insert(pos,ticks);
            if (samples.Count>96) samples.RemoveAt(0);
        }
        public void Prune(long cutoff)
        {
            int n=0; while(n<samples.Count && samples[n]<cutoff) n++;
            if(n>0) samples.RemoveRange(0,n);
        }
        public void Match(Write w,long ticks,string path)
        {
            for(int i=samples.Count-1;i>=0;i--) {
                long sample=samples[i];
                if(sample<ticks-Window) break;
                if(sample<=ticks+Window) w.Consider(path,sample);
            }
        }
    }
    sealed class Bucket
    {
        public readonly Dictionary<string,ReadHistory> Reads = new Dictionary<string,ReadHistory>(StringComparer.OrdinalIgnoreCase);
        public readonly List<Write> Writes = new List<Write>();
        public readonly List<Write> Sent = new List<Write>();
        public long Last, SuppressUntil;
    }
    const long Window = 8 * TimeSpan.TicksPerSecond;
    const long AuditLag = 30 * TimeSpan.TicksPerSecond;
    readonly object gate = new object();
    readonly Dictionary<ulong,FileName> objects = new Dictionary<ulong,FileName>();
    readonly Dictionary<ulong,FileName> fileKeys = new Dictionary<ulong,FileName>();
    readonly Dictionary<int,Dictionary<string,Bucket>> processes = new Dictionary<int,Dictionary<string,Bucket>>();
    readonly Queue<Pair> ready = new Queue<Pair>();
    readonly long[] admission = new long[32768];
    readonly int ignorePid;
    string[] usb = new string[0], local = new string[0];
    int bucketCount;
    bool lost;
    long epoch, quietUntil, reads, writes, auditedWrites, matched, ambiguous, conflicts, nameLimits, globalLimits, traceGaps, rootChanges;
    static bool Same(string a, string b) { return String.Equals(a,b,StringComparison.OrdinalIgnoreCase); }
    static string[] Roots(string[] roots)
    {
        return (roots ?? new string[0]).Where(s => !String.IsNullOrWhiteSpace(s))
            .Select(s => s.TrimEnd('\\') + "\\").Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s,StringComparer.OrdinalIgnoreCase).ToArray();
    }
    public UsbAuditTransferMatcher(string[] usbRoots, string[] fixedRoots, int excludedProcess)
    {
        ignorePid = excludedProcess;
        UpdateRoots(usbRoots,fixedRoots);
    }
    public void UpdateRoots(string[] usbRoots, string[] fixedRoots)
    {
        var u = Roots(usbRoots);
        var f = Roots(fixedRoots);
        lock(gate) {
            if (usb.SequenceEqual(u,StringComparer.OrdinalIgnoreCase) && local.SequenceEqual(f,StringComparer.OrdinalIgnoreCase)) return;
            if (processes.Values.Any(n => n.Values.Any(b => b.Writes.Count != 0))) { lost = true;rootChanges++; }
            Clear();
            usb = u; local = f; epoch=DateTime.UtcNow.Ticks;
        }
    }
    void Clear()
    {
        objects.Clear(); fileKeys.Clear(); processes.Clear(); ready.Clear(); bucketCount = 0;
        Array.Clear(admission,0,admission.Length);
    }
    void Gap(long ticks)
    {
        Clear(); lost = true; quietUntil = ticks + Window;
    }
    public void OnLoss() { lock(gate) { traceGaps++;Gap(DateTime.UtcNow.Ticks); } }
    public bool TakeLoss() { lock(gate) { bool before = lost; lost = false; return before; } }
    public string Statistics()
    {
        lock (gate) return String.Format("reads={0} writes={1} pairs={2} ambiguous={3} conflicts={4} nameLimits={5} globalLimits={6} traceGaps={7} rootChanges={8} names={9} objects={10} auditedWrites={11}",
            reads,writes,matched,ambiguous,conflicts,nameLimits,globalLimits,traceGaps,rootChanges,bucketCount,objects.Count+fileKeys.Count,auditedWrites);
    }
    FileName ResolveName(string path)
    {
        if (String.IsNullOrEmpty(path) || path.Length > 32767 || path.IndexOf(':') >= 0) return null;
        int sep = path.LastIndexOf('\\');
        if (sep < 0 || sep == path.Length - 1) return null;
        bool onUsb = false, known = false;
        foreach (string root in usb) if (path.StartsWith(root,StringComparison.OrdinalIgnoreCase)) { onUsb = known = true; break; }
        if (!known) foreach (string root in local) if (path.StartsWith(root,StringComparison.OrdinalIgnoreCase)) { known = true; break; }
        return known ? new FileName {Path=path, Leaf=path.Substring(sep+1), Usb=onUsb} : null;
    }
    void Bind(Dictionary<ulong,FileName> table, ulong key, string path)
    {
        if (key == 0) return;
        var name = ResolveName(path);
        if (name == null) table.Remove(key);
        else table[key] = name;
    }
    // Объекты и ключи ядра — два отдельных пространства идентификаторов.
    public void OnFile(int id, int pid, long ticks, ulong obj, ulong key, string path, uint size)
    {
        lock(gate) {
            if (objects.Count + fileKeys.Count >= 131072) { globalLimits++;Gap(ticks); }
            if (id == 10) { Bind(fileKeys,key,path); return; }
            if (id == 11) { fileKeys.Remove(key); return; }
            if (id == 12) { Bind(objects,obj,path); return; }
            if (id == 14) { objects.Remove(obj); return; }
            if ((id != 15 && id != 16) || size == 0 || pid <= 4 || pid == ignorePid || ticks < quietUntil) return;
            FileName file, namedKey;
            if (!objects.TryGetValue(obj,out file)) {
                if (!fileKeys.TryGetValue(key,out file)) return;
            } else if (fileKeys.TryGetValue(key,out namedKey) && !Same(file.Path,namedKey.Path)) {
                // Противоречивое имя (например, после переименования) не используем.
                conflicts++;return;
            }
            if ((id == 16) != file.Usb) return;
            if (id == 15) reads++; else writes++;
            Observe(file,pid,ticks,id==15,0);
        }
    }
    public void RecordAuditedUsbWrite(string path, int pid, long ticks, long recordId)
    {
        if (pid<=4 || pid==ignorePid || recordId<=0) return;
        long now=DateTime.UtcNow.Ticks;
        lock(gate) {
            if(ticks<epoch || ticks<quietUntil || now-ticks>AuditLag || ticks>now+2*TimeSpan.TicksPerSecond) return;
            var file=ResolveName(path);
            if(file==null || !file.Usb) return;
            auditedWrites++;
            Observe(file,pid,ticks,false,recordId);
        }
    }
    void Observe(FileName file,int pid,long ticks,bool read,long securityId)
    {
        Dictionary<string,Bucket> names;
        Bucket bucket=null;
        if (processes.TryGetValue(pid,out names)) names.TryGetValue(file.Leaf,out bucket);
        if (bucket==null) {
            // Переполнение по посторонним именам не должно отменять уже
            // наблюдавшуюся запись. Пропущенное имя остаётся исключённым
            // до истечения окна, в том числе для запоздавшего события 4663.
            int slot=(StringComparer.OrdinalIgnoreCase.GetHashCode(file.Leaf)^pid)&(admission.Length-1);
            if(ticks<admission[slot] || bucketCount>=16384) {
                if(ticks>=admission[slot]) {globalLimits++;lost=true;}
                admission[slot]=Math.Max(admission[slot],ticks+AuditLag+Window); return;
            }
            if(names==null) processes.Add(pid,names = new Dictionary<string,Bucket>(StringComparer.OrdinalIgnoreCase));
            names.Add(file.Leaf,bucket=new Bucket());bucketCount++;
        }
        bucket.Last = Math.Max(bucket.Last,ticks);
        // Популярные имена (например index.js в разных каталогах) могут быть
        // неоднозначны для одного процесса. Изолируем только это имя и PID.
        if (ticks < bucket.SuppressUntil) { bucket.SuppressUntil = Math.Max(bucket.SuppressUntil,ticks+Window); return; }
        if ((bucket.Reads.Count>=32 && read && !bucket.Reads.ContainsKey(file.Path)) || bucket.Writes.Count+bucket.Sent.Count>64) {
            nameLimits++;lost=true;bucket.Reads.Clear();bucket.Writes.Clear();bucket.Sent.Clear();bucket.SuppressUntil=ticks+Window;return;
        }
        if (read) {
            ReadHistory history;
            if(!bucket.Reads.TryGetValue(file.Path,out history)) bucket.Reads[file.Path]=history=new ReadHistory();
            history.Observe(ticks);
            foreach (var w in bucket.Writes)
                if (ticks >= w.First-Window && ticks <= w.Last+Window) w.Consider(file.Path,ticks);
        } else {
            if(securityId>0 && bucket.Sent.Any(s=>Same(s.Destination,file.Path) && ticks>=s.First-Window && ticks<=s.Last+Window))return;
            Write w = null;
            foreach (var prev in bucket.Writes)
                if (Same(prev.Destination,file.Path) && Math.Abs(ticks-prev.Last) <= Window) { w=prev; break; }
            if (w == null) {
                w = new Write { First=ticks, Last=ticks, Destination=file.Path, Pid=pid };
                bucket.Writes.Add(w);
            } else {
                w.Last = Math.Max(ticks,w.Last);
                w.First = Math.Min(ticks,w.First);
            }
            if(securityId==0)w.KernelWrite=true;
            else if(w.SecurityId==0)w.SecurityId=securityId;
            foreach (var r in bucket.Reads) r.Value.Match(w,ticks,r.Key);
        }
    }
    // Ждём завершения окна неоднозначности и доставки буферов ETW. Долгая
    // запись остаётся кандидатом, пока в неё поступают новые блоки данных.
    public Pair[] Drain(long now)
    {
        lock(gate) {
            // В реальном сеансе FlushTimer=1 с. При простое может больше не прийти
            // ни одного файлового события, поэтому окно замыкаем также по часам.
            long cutoff = now - 2*TimeSpan.TicksPerSecond - Window;
            long retained = now - AuditLag - Window - 2*TimeSpan.TicksPerSecond;
            foreach (var names in processes.Values) {
                foreach (var bucket in names.Values) {
                    for (int i=bucket.Writes.Count-1; i>=0; i--) {
                        var w=bucket.Writes[i];
                        if (w.Last>=cutoff) continue;
                        bucket.Writes.RemoveAt(i);
                        if (!w.Ambiguous && w.Source!=null) {
                            if (ready.Count>=2048) { globalLimits++;Gap(now); return new Pair[0]; }
                            matched++;
                            ready.Enqueue(new Pair { SourceNt=w.Source,DestinationNt=w.Destination,
                                ProcessId=w.Pid,ReadTicks=w.Read,WriteTicks=w.First,
                                HasKernelWrite=w.KernelWrite,SecurityWriteId=w.SecurityId });
                            bucket.Sent.Add(w);
                        } else if(w.Ambiguous) ambiguous++;
                    }
                    foreach(var h in bucket.Reads.Values) h.Prune(retained);
                    foreach (var r in bucket.Reads.Where(x=>x.Value.Empty).Select(x=>x.Key).ToArray()) bucket.Reads.Remove(r);
                    bucket.Sent.RemoveAll(w=>w.Last<retained);
                }
                foreach (var name in names.Where(n=>n.Value.Last < retained && n.Value.Writes.Count==0).Select(n=>n.Key).ToArray()) {
                    names.Remove(name);bucketCount--;
                }
            }
            foreach (int pid in processes.Where(p=>p.Value.Count==0).Select(p=>p.Key).ToArray()) processes.Remove(pid);
            var result=ready.ToArray();ready.Clear();return result;
        }
    }
}

public sealed class UsbAuditTransferObserver : IDisposable
{
    readonly UsbAuditTransferMatcher matcher;
    readonly UsbAuditKernelTrace trace;
    readonly UsbAuditShellQueue shell = new UsbAuditShellQueue();
    public UsbAuditTransferObserver(string[] usbNtRoots, string[] fixedNtRoots, int ignorePid)
    {
        matcher = new UsbAuditTransferMatcher(usbNtRoots,fixedNtRoots,ignorePid);
        shell.UpdateRoots(usbNtRoots,fixedNtRoots);
        trace = new UsbAuditKernelTrace("LocalUsbAuditFileTrace",matcher.OnFile,matcher.OnLoss,shell);
    }
    public bool IsRunning { get { return trace.IsRunning; } }
    public string ShellStatus { get { return trace.ShellStatus; } }
    public UsbAuditShellOperation[] DrainShell() { return shell.Drain(); }
    public bool TakeShellLoss() { return shell.TakeLoss(); }
    public void RecordAuditedUsbWrite(string ntPath,int pid,long ticks,long recordId) {matcher.RecordAuditedUsbWrite(ntPath,pid,ticks,recordId);}
    public void UpdateRoots(string[] usbNtRoots,string[] fixedNtRoots) {
        matcher.UpdateRoots(usbNtRoots,fixedNtRoots);shell.UpdateRoots(usbNtRoots,fixedNtRoots);
    }
    public UsbAuditTransferMatcher.Pair[] Drain() { return matcher.Drain(DateTime.UtcNow.Ticks); }
    public bool TakeLoss() { return matcher.TakeLoss(); }
    public string Statistics() { return matcher.Statistics()+" "+trace.Statistics(); }
    public void Dispose() { trace.Dispose(); }
}
