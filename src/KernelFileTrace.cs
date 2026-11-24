using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// 18905 описывает намерение оболочки. Коллектор отдельно проверяет признаки записи.
public sealed class UsbAuditShellOperation {
    public string SourceNt, DestinationNt, Operation;
    public int ProcessId;
    public long Ticks, FileSize;
}

internal sealed class UsbAuditShellQueue {
    const int MaxItems=1024, MaxChars=1024*1024;
    sealed class Root {
        internal string Alias, Native;
        internal int Kind; // 1 = USB, 2 = подтверждённый локальный том, 0 = прочее.
    }
    readonly object gate=new object();
    readonly List<UsbAuditShellOperation> pending=new List<UsbAuditShellOperation>();
    Root[] roots=new Root[0];
    long epoch;
    int queuedChars;
    bool lost;
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern IntPtr FindFirstVolumeW(StringBuilder name,uint capacity);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern bool FindNextVolumeW(IntPtr handle,StringBuilder name,uint capacity);
    [DllImport("kernel32.dll")] static extern bool FindVolumeClose(IntPtr handle);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern uint QueryDosDeviceW(string name,StringBuilder mappings,int capacity);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern bool GetVolumePathNamesForVolumeNameW(string volume,[Out] char[] paths,uint size,out uint needed);
    static bool Same(string a,string b) { return String.Equals(a,b,StringComparison.OrdinalIgnoreCase); }
    static void AddRoot(Dictionary<string,Root> all,string alias,string native,int kind) {
        string prefix=alias.TrimEnd('\\')+"\\";
        all[prefix]=new Root {Alias=prefix,Native=native.TrimEnd('\\')+"\\",Kind=kind};
    }
    internal void UpdateRoots(string[] usb,string[] fixedVolumes) {
        var all=new Dictionary<string,Root>(StringComparer.OrdinalIgnoreCase);
        foreach(string nt in fixedVolumes)AddRoot(all,nt,nt,2);
        foreach(string nt in usb)AddRoot(all,nt,nt,1);
        // Разрешаем DOS-пути из Shell по точкам монтирования. Вложенный том имеет
        // приоритет над корневой буквой, даже если он не входит в область наблюдения.
        var name=new StringBuilder(128);
        IntPtr h=FindFirstVolumeW(name,(uint)name.Capacity);
        if(h!=new IntPtr(-1)) {
            try {
                do {
                    string volume=name.ToString();
                    if(!volume.StartsWith(@"\\?\Volume{",StringComparison.OrdinalIgnoreCase))continue;
                    var target=new StringBuilder(1024);
                    if(QueryDosDeviceW(volume.Substring(4).TrimEnd('\\'),target,target.Capacity)==0)continue;
                    string nt=target.ToString();
                    Root known;
                    int kind=all.TryGetValue(nt+"\\",out known)?known.Kind:0;
                    AddRoot(all,volume,nt,kind);
                    uint size;
                    GetVolumePathNamesForVolumeNameW(volume,null,0,out size);
                    if(size<2 || size>65536)continue;
                    var paths=new char[size];
                    if(!GetVolumePathNamesForVolumeNameW(volume,paths,size,out size))continue;
                    foreach(string path in new string(paths).Split(new[]{'\0'},StringSplitOptions.RemoveEmptyEntries)) {
                        if(path.Length>=3 && path[1]==':' && path[2]=='\\')AddRoot(all,path,nt,kind);
                    }
                } while(FindNextVolumeW(h,name,(uint)name.Capacity));
            } finally {FindVolumeClose(h);}
        }
        var updated=new List<Root>(all.Values);
        updated.Sort(delegate(Root x,Root y) {
            int length=y.Alias.Length.CompareTo(x.Alias.Length);
            return length!=0?length:StringComparer.OrdinalIgnoreCase.Compare(x.Alias,y.Alias);
        });
        lock(gate) {
            bool changed=updated.Count!=roots.Length;
            for(int i=0;!changed && i<updated.Count;i++)
                changed=updated[i].Kind!=roots[i].Kind || !Same(updated[i].Alias,roots[i].Alias) || !Same(updated[i].Native,roots[i].Native);
            if(!changed)return;
            if(pending.Count!=0)lost=true;
            Clear();roots=updated.ToArray();epoch=DateTime.UtcNow.Ticks;
        }
    }
    int Resolve(string path,out string native) {
        native=null;
        if(path.StartsWith(@"\??\",StringComparison.Ordinal))path=@"\\?\"+path.Substring(4);
        if(path.StartsWith(@"\\?\",StringComparison.Ordinal) && path.Length>6 && path[5]==':')path=path.Substring(4);
        foreach(var root in roots) {
            if(!path.StartsWith(root.Alias,StringComparison.OrdinalIgnoreCase))continue;
            if(root.Kind==0 || path.Length<=root.Alias.Length || path.EndsWith("\\",StringComparison.Ordinal))return 0;
            string tail=path.Substring(root.Alias.Length);
            string bounded="\\"+tail+"\\";
            if(tail.IndexOf(':')>=0 || tail.IndexOf('/')>=0 || bounded.Contains("\\.\\") || bounded.Contains("\\..\\") || bounded.Contains("\\\\"))return 0;
            native=root.Native+tail;return root.Kind;
        }
        return 0;
    }
    static string ReadPath(IntPtr data,int bytes,ref int offset) {
        int start=offset;
        while(offset+2<=bytes) {
            offset+=2;
            if(Marshal.ReadInt16(data,offset-2)==0)
                return Marshal.PtrToStringUni(IntPtr.Add(data,start),(offset-start)/2-1);
        }
        return null;
    }
    // Схема v0: две UTF-16Z строки, два типа объектов, FileOp и UInt64 FileSize.
    internal bool Receive(IntPtr data,int bytes,int pid,long ticks) {
        if(data==IntPtr.Zero || bytes<24 || (bytes&1)!=0)return false;
        int offset=0;
        string from=ReadPath(data,bytes,ref offset);
        string to=ReadPath(data,bytes,ref offset);
        if(from==null || to==null || offset+20>bytes)return false;
        int op=Marshal.ReadInt32(data,offset+8);
        if((op!=1 && op!=2) || pid<=4 || from.Length==0 || to.Length==0)return true;
        long size=Marshal.ReadInt64(data,offset+12);
        lock(gate) {
            if(ticks<epoch)return true;
            string source,destination;
            int a=Resolve(from,out source),b=Resolve(to,out destination);
            if(a+b!=3 || a==0 || b==0)return true;
            var operation=op==1?"move":"copy";
            // Повтор идентичного уведомления не означает повтор пользовательской операции.
            if(pending.Count!=0) {
                var last=pending[pending.Count-1];
                if(last.Ticks==ticks && last.ProcessId==pid && last.Operation==operation &&
                    Same(last.SourceNt,source) && Same(last.DestinationNt,destination) && last.FileSize==size)return true;
            }
            int chars=source.Length+destination.Length;
            if(pending.Count>=MaxItems || queuedChars+chars>MaxChars){lost=true;return true;}
            pending.Add(new UsbAuditShellOperation {SourceNt=source,DestinationNt=destination,ProcessId=pid,
                Ticks=ticks,Operation=operation,FileSize=size<0?-1:size});
            queuedChars+=chars;
        }
        return true;
    }
    void Clear() {pending.Clear();queuedChars=0;}
    internal void OnLoss() {lock(gate){lost=true;Clear();}}
    internal bool TakeLoss() {lock(gate){bool before=lost;lost=false;return before;}}
    internal UsbAuditShellOperation[] Drain() {lock(gate){var rows=pending.ToArray();Clear();return rows;}}
}

// Чтение манифестных событий Microsoft-Windows-Kernel-File. Сеанс работает
// только в реальном времени. Содержимое файлов в событиях отсутствует.
public sealed class UsbAuditKernelTrace : IDisposable
{
    private static readonly Guid Provider = new Guid("edd08927-9cc4-4e65-b970-c2560fb5c289");
    private static readonly Guid ShellProvider = new Guid("30336ed4-e327-447c-9de0-51b652c86108");
    private static readonly Guid SessionGuid = new Guid("5ecda003-832f-4ea6-8bac-93747995ed7a");
    private static readonly Guid LossProvider = new Guid("6a399ae0-4bc6-4de9-870b-3657f8947e7e");
    private const uint RealTime = 0x100, NotFound = 4201;
    private const ulong InvalidHandle = ulong.MaxValue;
    private const int NamesBuffer = 8192;
    private readonly string name;
    private readonly Action<int,int,long,ulong,ulong,string,uint> onFile;
    private readonly Action onLoss;
    private readonly UsbAuditShellQueue shell;
    private readonly RecordCallback recordCallback;
    private readonly BufferCallback bufferCallback;
    private readonly object shutdown = new object();
    private Mutex ownership;
    private ulong controller, consumer = InvalidHandle;
    private Thread reader;
    private volatile bool stopping, finished, faulted;
    private readonly long[] eventCounts=new long[7];
    private long osLossSignals, malformed, userReads, userWrites;
    private volatile string lastIssue="";
    private volatile string shellStatus="";
    public string ShellStatus { get { return shellStatus; } }
    public bool IsRunning { get { return !stopping && !finished && !faulted; } }
    // Счётчики не содержат путей и остаются малы при длительном наблюдении.
    public string Statistics() {
        return String.Format("events 10..16={0}; userReads={1}; userWrites={2}; lossSignals={3}; malformed={4}; issue={5}",
            String.Join(",",eventCounts),userReads,userWrites,osLossSignals,malformed,lastIssue);
    }

    // Раскладки Win64 из evntrace.h и evntcons.h. Вложенные выходные поля
    // CurrentEvent и LogfileHeader OpenTrace заполняет сама; мы их не читаем.
    [StructLayout(LayoutKind.Explicit, Size=448)]
    private struct LogFile {
        [FieldOffset(8)] public IntPtr LoggerName;
        [FieldOffset(28)] public uint ProcessTraceMode;
        [FieldOffset(400)] public IntPtr BufferCallback;
        [FieldOffset(424)] public IntPtr EventRecordCallback;
    }
    [StructLayout(LayoutKind.Explicit, Size=112)]
    private struct Record {
        [FieldOffset(4)] public ushort Flags;
        [FieldOffset(12)] public int Pid;
        [FieldOffset(16)] public long TimeStamp;
        [FieldOffset(24)] public Guid ProviderId;
        [FieldOffset(40)] public ushort Id;
        [FieldOffset(42)] public byte Version;
        [FieldOffset(86)] public ushort Length;
        [FieldOffset(96)] public IntPtr Data;
    }
    [StructLayout(LayoutKind.Explicit, Size=120)]
    private struct Properties {
        [FieldOffset(0)] public uint Size;
        [FieldOffset(24)] public Guid Guid;
        [FieldOffset(40)] public uint Clock;
        [FieldOffset(44)] public uint Flags;
        [FieldOffset(48)] public uint BufferKB;
        [FieldOffset(52)] public uint MinBuffers;
        [FieldOffset(56)] public uint MaxBuffers;
        [FieldOffset(64)] public uint LogFileMode;
        [FieldOffset(68)] public uint FlushSeconds;
        [FieldOffset(112)] public uint LogFileNameOffset;
        [FieldOffset(116)] public uint LoggerNameOffset;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct EnableParameters {
        public uint Version, EnableProperty, ControlFlags;
        public Guid SourceId;
        public IntPtr Filters;
        public uint FilterCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FilterDescriptor {
        public ulong Pointer;
        public uint Size, Type;
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void RecordCallback(ref Record e);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint BufferCallback(IntPtr log);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    private static extern uint StartTraceW(out ulong id, string name, IntPtr properties);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    private static extern uint ControlTraceW(ulong id, string name, IntPtr properties, uint control);
    [DllImport("advapi32.dll", ExactSpelling=true)]
    private static extern uint EnableTraceEx2(ulong id, ref Guid provider, uint control, byte level,
        ulong anyKeywords, ulong allKeywords, uint timeout, ref EnableParameters parameters);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
    private static extern ulong OpenTraceW(ref LogFile log);
    [DllImport("advapi32.dll", ExactSpelling=true)]
    private static extern uint ProcessTrace([In] ulong[] handles, uint count, IntPtr start, IntPtr end);
    [DllImport("advapi32.dll", ExactSpelling=true)]
    private static extern uint CloseTrace(ulong handle);

    private static void Check(uint status, string step) {
        if (status != 0) throw new Win32Exception((int)status, step + ": " + new Win32Exception((int)status).Message);
    }
    private static Mutex Claim(string name) {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("Windows x64 required");
        if (String.IsNullOrEmpty(name) || !name.StartsWith("LocalUsbAudit", StringComparison.OrdinalIgnoreCase) ||
            name.Length > 100 || name.IndexOf('\0') >= 0 || name.IndexOf('\\') >= 0)
            throw new ArgumentException("Invalid USB-Audit trace name", "name");
        bool fresh;
        // Существование объекта, а не привязка mutex к потоку, служит признаком живого владельца.
        var gate = new Mutex(false, @"Global\UsbAuditKernelTrace-" + SessionGuid.ToString("N"), out fresh);
        if (!fresh) { gate.Dispose(); throw new InvalidOperationException("USB-Audit trace controller is active"); }
        return gate;
    }
    private static IntPtr NewProperties(bool query) {
        int size = Marshal.SizeOf(typeof(Properties)) + NamesBuffer;
        var memory = Marshal.AllocHGlobal(size);
        Marshal.Copy(new byte[size],0,memory,size);
        var p = new Properties {Size=(uint)size, Guid=SessionGuid, Flags=0x20000, Clock=1,
            BufferKB=128, MinBuffers=32, MaxBuffers=256, LogFileMode=RealTime, FlushSeconds=1,
            LoggerNameOffset=(uint)Marshal.SizeOf(typeof(Properties))};
        if(query) {
            p.Guid=Guid.Empty;
            p.LogFileMode=0;
            p.LogFileNameOffset=p.LoggerNameOffset+NamesBuffer/2;
        }
        Marshal.StructureToPtr(p,memory,false);
        return memory;
    }
    private static void StopByHandle(ulong id) {
        IntPtr p=NewProperties(true);
        try { uint err=ControlTraceW(id,null,p,1); if(err!=NotFound) Check(err,"ControlTraceW(STOP)"); }
        finally { Marshal.FreeHGlobal(p); }
    }
    private static void Reclaim(string name) {
        IntPtr p=NewProperties(true);
        try {
            uint err=ControlTraceW(0,name,p,0);
            if(err==NotFound)return;
            Check(err,"ControlTraceW(QUERY)");
            var actual=(Properties)Marshal.PtrToStructure(p,typeof(Properties));
            // Windows может вернуть дополнительный EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN.
            // Все прочие режимы и посторонние GUID остаются защищены от остановки.
            if(actual.Guid!=SessionGuid || (actual.LogFileMode & ~0x00800000u)!=RealTime)
                throw new InvalidOperationException("ETW session name belongs to another controller: "+name);
            err=ControlTraceW(0,name,p,1);
            if(err!=NotFound)Check(err,"ControlTraceW(STOP orphan)");
        } finally { Marshal.FreeHGlobal(p); }
    }
    public static void StopOrphaned(string name) {
        using(Claim(name)) Reclaim(name);
    }
    public UsbAuditKernelTrace(string sessionName, Action<int,int,long,ulong,ulong,string,uint> onFile, Action onLoss)
        : this(sessionName,onFile,onLoss,null) { }
    internal UsbAuditKernelTrace(string sessionName, Action<int,int,long,ulong,ulong,string,uint> onFile, Action onLoss, UsbAuditShellQueue shell) {
        if(onFile==null || onLoss==null)throw new ArgumentNullException();
        name=sessionName;this.onFile=onFile;this.onLoss=onLoss;this.shell=shell;
        recordCallback=ProcessRecord;bufferCallback=ContinueBuffer;
        ownership=Claim(name);
        try {
            IntPtr p=NewProperties(false);
            try {
                ulong id;
                uint err=StartTraceW(out id,name,p);
                if(err==183) { Reclaim(name); err=StartTraceW(out id,name,p); }
                Check(err,"StartTraceW"); controller=id;
            } finally { Marshal.FreeHGlobal(p); }
            IntPtr logger=Marshal.StringToHGlobalUni(name);
            try {
                var log=new LogFile {LoggerName=logger, ProcessTraceMode=0x10000100,
                    EventRecordCallback=Marshal.GetFunctionPointerForDelegate(recordCallback),
                    BufferCallback=Marshal.GetFunctionPointerForDelegate(bufferCallback)};
                consumer=OpenTraceW(ref log);
                if(consumer==InvalidHandle)throw new Win32Exception(Marshal.GetLastWin32Error());
            } finally { Marshal.FreeHGlobal(logger); }
            Check(EnableEvents(Provider,5,0x3b0,10,11,12,13,14,15,16),"EnableTraceEx2(Kernel-File)");
            if(shell!=null) {
                // Второй поставщик использует тот же принадлежащий сборщику сеанс.
                uint status=EnableEvents(ShellProvider,4,0x10000,18905);
                if(status!=0)shellStatus=new Win32Exception((int)status).Message+" ("+status+")";
            }
            reader=new Thread(Read);
            reader.IsBackground=true;reader.Name="USB-Audit Kernel-File";
            reader.Start();
        } catch { Dispose();throw; }
    }
    private uint EnableEvents(Guid provider,byte level,ulong keywords,params ushort[] eventIds) {
        // EVENT_FILTER_EVENT_ID (FilterIn, Reserved, Count, Events[]).
        byte[] ids=new byte[4+2*eventIds.Length];
        ids[0]=1;ids[2]=checked((byte)eventIds.Length);
        Buffer.BlockCopy(eventIds,0,ids,4,2*eventIds.Length);
        GCHandle pin=GCHandle.Alloc(ids,GCHandleType.Pinned);
        IntPtr filter=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FilterDescriptor)));
        try {
            var descriptor=new FilterDescriptor {Type=0x80000200, Size=(uint)ids.Length,
                Pointer=unchecked((ulong)pin.AddrOfPinnedObject().ToInt64())};
            Marshal.StructureToPtr(descriptor,filter,false);
            var parameters=new EnableParameters {Version=2, SourceId=SessionGuid, Filters=filter, FilterCount=1};
            return EnableTraceEx2(controller,ref provider,1,level,keywords,0,5000,ref parameters);
        } finally { Marshal.FreeHGlobal(filter);pin.Free(); }
    }
    private void Read() {
        try {
            uint status=ProcessTrace(new[]{consumer},1,IntPtr.Zero,IntPtr.Zero);
            if(!stopping && !faulted)lastIssue="ProcessTrace ended: "+status;
        }
        finally { finished=true; if(!stopping)Lost(); }
    }
    private uint ContinueBuffer(IntPtr unused) { return stopping || faulted ? 0u : 1u; }
    private void Lost() {
        if(shell!=null)shell.OnLoss();
        try { onLoss(); } catch { faulted=true; }
    }
    private void Bad(ref Record e, bool missingIdentity) {
        malformed++;
        if((malformed & (malformed-1))==0)
            lastIssue="Malformed event "+e.Id+"/"+e.Version+", bytes="+e.Length+", flags="+e.Flags;
        if(missingIdentity)Lost();
    }
    private static ulong Ptr(IntPtr data, int offset, int width) {
        return width==8 ? unchecked((ulong)Marshal.ReadInt64(data,offset)) : unchecked((uint)Marshal.ReadInt32(data,offset));
    }
    private static string PathAt(ref Record e,int offset) {
        int bytes=e.Length-offset;
        if(bytes<2 || (bytes&1)!=0 || Marshal.ReadInt16(e.Data,e.Length-2)!=0)return null;
        return Marshal.PtrToStringUni(IntPtr.Add(e.Data,offset),bytes/2-1);
    }
    private void ProcessRecord(ref Record e) {
        if(stopping || faulted)return;
        if(e.ProviderId==ShellProvider) {
            if(shell!=null && e.Id==18905) {
                try {
                    if(e.Version!=0)shellStatus="Неизвестная версия события 18905: "+e.Version;
                    else if(!shell.Receive(e.Data,e.Length,e.Pid,DateTime.FromFileTimeUtc(e.TimeStamp).Ticks))
                        shellStatus="Неполные данные события Shell-Core 18905.";
                } catch(Exception ex) { shellStatus=ex.GetType().Name;shell.OnLoss(); }
            }
            return;
        }
        try {
            if(e.ProviderId==LossProvider) { osLossSignals++;Lost();return; }
            if(e.ProviderId!=Provider || e.Id<10 || e.Id>16)return;
            eventCounts[e.Id-10]++;
            // Схемы v0/v1 взяты из ProviderMetadata Microsoft-Windows-Kernel-File.
            // Нельзя читать смещения от другой версии: это даёт чужие имена и дескрипторы.
            if(e.Version>1 || (e.Id<=11 && e.Version!=0)) {
                lastIssue="Unknown event version "+e.Id+"/"+e.Version;faulted=true;Lost();return;
            }
            int w=(e.Flags & 0x20)!=0?4:8;
            bool old=e.Version==0;
            ulong obj=0,key=0;uint bytes=0;string path=null;
            if(e.Id<=11) {
                if(e.Length<w) {Bad(ref e,true);return;}
                key=Ptr(e.Data,0,w);
                // Для снятия привязки достаточно FileKey, имя не понадобится.
                if(e.Id==10)path=PathAt(ref e,w);
            } else if(e.Id==12) {
                int at=old?3*w+12:2*w+16;
                if(e.Length<(old?3*w:2*w)){Bad(ref e,true);return;}
                obj=Ptr(e.Data,old?2*w:w,w); path=PathAt(ref e,at);
            } else {
                bool io=e.Id>=15;
                int at=(io?8:0)+(old?2*w:w);
                int sizeAt=at+2*w+(old?0:4);
                if(e.Length<(io?sizeAt+4:at+2*w)){Bad(ref e,true);return;}
                obj=Ptr(e.Data,at,w);key=Ptr(e.Data,at+w,w);
                if(io)bytes=unchecked((uint)Marshal.ReadInt32(e.Data,sizeAt));
            }
            // Пустое имя в корректном событии снимает одну прежнюю привязку.
            // Нулевой результат PathAt означает повреждённое поле целиком.
            if((e.Id==10 || e.Id==12) && path==null) {
                // Известен ключ этого повреждённого имени. Нулевая привязка снимет
                // только его старое значение, без потери истории других файлов.
                Bad(ref e,false);
            }
            if(e.Id==15 && e.Pid>4)userReads++;
            if(e.Id==16 && e.Pid>4)userWrites++;
            onFile(e.Id,e.Pid,DateTime.FromFileTimeUtc(e.TimeStamp).Ticks,obj,key,path,bytes);
        } catch(Exception ex) { lastIssue=ex.GetType().Name; faulted=true;Lost(); }
    }
    public void Dispose() {
        lock(shutdown) {
            if(ownership==null)return;
            stopping=true;
            try { if(controller!=0)StopByHandle(controller); }
            finally {
                controller=0;
                if(consumer!=InvalidHandle){CloseTrace(consumer);consumer=InvalidHandle;}
                if(reader!=null && reader.IsAlive && reader!=Thread.CurrentThread)reader.Join(5000);
                ownership.Dispose();ownership=null;
            }
        }
    }
}
