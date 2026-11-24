// Оболочка для Windows x64. Build.ps1 встраивает в EXE сценарии и шаблон отчёта.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;

[assembly: AssemblyVersion("1.1.1.0")]
[assembly: AssemblyFileVersion("1.1.1.0")]

internal static class UsbAudit
{
    internal static readonly string[] Files = {
        "Access.ps1", "Collector.ps1", "Install.ps1", "Report.ps1",
        "viewer.html", "Maintenance.ps1", "Check.ps1",
        "ArchiveAudit.ps1", "TransferAudit.ps1", "DestinationAudit.ps1"
    };
    internal static readonly string ProgramRoot = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    internal static readonly string Installed = Path.Combine(ProgramRoot, "LocalUsbAudit");
    internal static readonly string Data = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LocalUsbAudit", "Data");
    internal static readonly string ArchiveDirectory = Path.Combine(Data, "Archive");
    private static readonly string SystemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string NativePowerShell = Path.Combine(
        Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
    internal static readonly Regex ArchivePattern = new Regex(
        @"\Ausb-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.jsonl\z", RegexOptions.CultureInvariant);
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly string Executable = Assembly.GetExecutingAssembly().Location;
    internal const string Title = "Журнал USB";

    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll")] private static extern IntPtr GetStdHandle(int number);
    [DllImport("kernel32.dll")] private static extern uint GetFileType(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(uint pid);

    [STAThread]
    private static int Main(string[] args)
    {
        bool guiInstaller = args.Length == 2 && args[0] == "--install-ui";
        try
        {
            if (args.Length == 0)
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new Dashboard());
                return 0;
            }
            // У оконного EXE нет собственной консоли. В файлы и каналы выводим текст в UTF-8.
            if (!IsFileOrPipe(-11) && GetConsoleWindow() == IntPtr.Zero)
                AttachConsole(0xffffffff);
            if (IsFileOrPipe(-11))
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
            if (IsFileOrPipe(-12))
                Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
            if (args.Length == 1 && args[0] == "--help")
            {
                Console.WriteLine("USB-Audit.exe — окно журнала USB.\n" +
                    "--self-test    проверить ресурсы и синтаксис PowerShell\n" +
                    "--extract ПАПКА    извлечь исходные компоненты в пустую папку\n" +
                    "--list-admins    показать доступных локальных администраторов и их SID\n" +
                    "--install SID_ЧИТАТЕЛЯ [SID_АДМИНИСТРАТОРА [--watch-folder ПАПКА]...]    установить с повышенными правами;\n" +
                    "    если второй SID пропущен, откроется окно выбора ответственного за архивы.");
                return 0;
            }
            if (!Environment.Is64BitOperatingSystem || !Environment.Is64BitProcess)
                throw new PlatformNotSupportedException("Требуется 64-разрядная Windows.");
            if (args.Length == 1 && args[0] == "--self-test") { SelfTest(); return 0; }
            if (args.Length == 1 && args[0] == "--list-admins")
            {
                var accounts = LoadAdministrators(false).Accounts;
                if (accounts.Count == 0) Console.WriteLine("Подходящих локальных администраторов нет.");
                foreach (var account in accounts) Console.WriteLine(account.Name + "\t" + account.Sid);
                return 0;
            }
            if (args.Length == 2 && args[0] == "--extract")
            {
                ExtractPublic(args[1]);
                Console.WriteLine("Извлечено компонентов: " + Files.Length);
                return 0;
            }
            if ((args.Length >= 2 && args[0] == "--install") || guiInstaller)
            {
                if (!Role.Admin()) throw new UnauthorizedAccessException("Установка требует прав администратора.");
                string adminSid;
                string[] folders = new string[0];
                if (args.Length >= 3)
                {
                    adminSid = ValidateAccountSid(args[2]);
                    var paths = new List<string>();
                    for (int i=3; i<args.Length; i+=2)
                    {
                        if (args[i] != "--watch-folder" || i+1 >= args.Length)
                            throw new ArgumentException("Укажите --watch-folder и полный путь к папке.");
                        paths.Add(args[i+1]);
                    }
                    folders = paths.ToArray();
                }
                else
                {
                    // В окне после UAC доступны локальные УЗ, даже если оператору запрещено их перечислять.
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    using (var chooser = new AdministratorPicker(LoadAdministrators(true)))
                    {
                        if (chooser.ShowDialog() != DialogResult.OK) { Console.WriteLine("Выбор отменён."); return 3; }
                        adminSid = chooser.SelectedSid;
                        folders = chooser.SelectedFolders;
                    }
                }
                Install(ValidateAccountSid(args[1]), adminSid, folders);
                Console.WriteLine("Установка завершена.");
                return 0;
            }
            Console.Error.WriteLine("Неизвестная команда. Выполните USB-Audit.exe --help.");
            return 2;
        }
        catch (Exception error)
        {
            if (args.Length == 0 || guiInstaller)
                MessageBox.Show(error.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static bool IsFileOrPipe(int number)
    {
        uint kind = GetFileType(GetStdHandle(number));
        return kind == 1 || kind == 3;
    }

    private static byte[] Resource(string name)
    {
        using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
        {
            if (resource == null || resource.Length == 0) throw new InvalidDataException("Отсутствует компонент " + name);
            using (MemoryStream buffer = new MemoryStream())
            {
                resource.CopyTo(buffer);
                return buffer.ToArray();
            }
        }
    }

    // Сверяем состав ресурсов, печатаем их SHA-256 и разбираем сценарии штатным парсером PowerShell.
    private static void SelfTest()
    {
        if (!new HashSet<string>(Files).SetEquals(Assembly.GetExecutingAssembly().GetManifestResourceNames()))
            throw new InvalidDataException("Состав ресурсов отличается от ожидаемого.");
        StringBuilder source = new StringBuilder();
        using (SHA256 sha = SHA256.Create())
        foreach (string file in Files)
        {
            byte[] contents = Resource(file);
            string text = Utf8.GetString(contents).TrimStart('\ufeff');
            if (file == "viewer.html")
            {
                if (!text.Contains("<!-- USB-AUDIT-DATA -->")) throw new InvalidDataException("Повреждён шаблон отчёта.");
            }
            else
                source.AppendLine(file + " " + Convert.ToBase64String(Utf8.GetBytes(text)));
            Console.WriteLine(BitConverter.ToString(sha.ComputeHash(contents)).Replace("-", "") + "  " + file);
        }
        string parser =
            "while ($null -ne ($s=[Console]::ReadLine())) {" +
            "$i=$s.IndexOf(' ');$name=$s.Substring(0,$i);$data=[Convert]::FromBase64String($s.Substring($i+1));" +
            "$tok=$null;$err=$null;$null=[Management.Automation.Language.Parser]::ParseInput(" +
            "[Text.Encoding]::UTF8.GetString($data),[ref]$tok,[ref]$err);" +
            "if($err.Count){throw ($name+' '+$err[0].Message)}}; exit 0";
        PsResult result = PowerShell(parser, Environment.SystemDirectory, source.ToString(), null);
        result.RequireSuccess();
        Console.WriteLine("OK: {0} ресурсов, {1} сценариев PowerShell, шаблон HTML.", Files.Length, Files.Length-1);
    }

    private static void CheckNoLinks(string path)
    {
        for (DirectoryInfo dir = new DirectoryInfo(path); dir != null; dir = dir.Parent)
            if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Путь содержит перенаправление: " + dir.FullName);
    }

    private static void WriteResources(string directory)
    {
        List<string> created = new List<string>();
        try
        {
            foreach (string name in Files)
            {
                byte[] data = Resource(name);
                string path = Path.Combine(directory, name);
                using (FileStream stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    created.Add(path);
                    stream.Write(data, 0, data.Length);
                }
            }
        }
        catch
        {
            foreach (string path in created) File.Delete(path);
            throw;
        }
    }

    // Выгрузка исходников разрешена только в новую или пустую папку, без перезаписи существующих файлов.
    private static void ExtractPublic(string destination)
    {
        if (String.IsNullOrWhiteSpace(destination)) throw new ArgumentException("Укажите каталог назначения.");
        string path = Path.GetFullPath(destination);
        CheckNoLinks(path);
        if (Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any())
            throw new IOException("Каталог назначения должен быть пустым.");
        Directory.CreateDirectory(path);
        WriteResources(path);
    }

    internal static class Role
    {
        internal static string CurrentSid()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) return identity.User.Value;
        }
        internal static bool Admin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    // Фильтрация по членству и состоянию УЗ общая у окна выбора и установщика.
    // Валидируем SID отдельно от отображаемого имени, которое пользователь Windows может изменить.
    private static string ValidateAccountSid(string value)
    {
        SecurityIdentifier sid;
        try { sid = new SecurityIdentifier(value); }
        catch (ArgumentException) { throw new ArgumentException("Укажите SID учётной записи Windows."); }
        if (sid.Value != value || !sid.IsAccountSid()) throw new ArgumentException("Укажите SID учётной записи Windows.");
        return sid.Value;
    }

    internal sealed class AdminAccount
    {
        internal string Name, Sid;
        public override string ToString() { return Name; }
    }

    internal sealed class AdminCatalog
    {
        internal readonly List<AdminAccount> Accounts = new List<AdminAccount>();
        internal string ConfiguredSid, ConfiguredName;
        internal bool PreviousInstallation;
        internal readonly List<string> Folders = new List<string>();
    }

    internal static AdminCatalog LoadAdministrators(bool includeRegistration)
    {
        // Access.ps1 читаем из собственного ресурса. Пути и команды от пользователя в код не подставляются.
        const string source =
            "$code=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())).TrimStart([char]0xfeff);" +
            ". ([scriptblock]::Create($code));" +
            "function ToText64([string]$value){[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))};";
        const string registration =
            "Assert-RegularPath $meta;" +
            "if(Test-Path -LiteralPath $meta -PathType Leaf){" +
            "$cfg=Get-Content -LiteralPath $meta -Raw -Encoding UTF8|ConvertFrom-Json;" +
            "if($cfg.format -ne 'local-usb-audit-v1'){throw 'Неизвестный формат существующей установки.'};" +
            "[Console]::WriteLine('existing');" +
            "if($cfg.custodianMode -ceq 'ExistingAdmin' -and $cfg.custodianSid){" +
            "[Console]::WriteLine(('saved'+[char]9+$cfg.custodianSid+[char]9+(ToText64 $cfg.custodianAccount)))}};";
        const string destinations =
            "$dest=Join-Path (Split-Path -LiteralPath $meta) 'destinations.json';Assert-RegularPath $dest;" +
            "if([IO.File]::Exists($dest)){$conf=[IO.File]::ReadAllText($dest)|ConvertFrom-Json;" +
            "foreach($f in $conf.folders){[Console]::WriteLine(('folder'+[char]9+(ToText64 $f.path)))}};";
        const string candidates =
            "foreach($u in @(Get-UsbLocalAdministrators | Sort-Object Name)){" +
            "$name=[Environment]::MachineName+[char]92+$u.Name;" +
            "[Console]::WriteLine(('user'+[char]9+$u.SID.Value+[char]9+(ToText64 $name)))}";
        string command = source + (includeRegistration ? registration + destinations : "") + candidates;
        // Windows PowerShell компилирует встроенный вызов NetAPI во временной папке.
        // При высоких правах используем закрытый каталог с ACL SYSTEM/Администраторы.
        string stage = Role.Admin() ? NewStage() : null;
        PsResult result;
        try
        {
            var environment = stage == null ? null : new Dictionary<string,string>{{"TEMP",stage},{"TMP",stage}};
            result = PowerShell(command, Environment.SystemDirectory,
                Convert.ToBase64String(Resource("Access.ps1")), environment);
        }
        finally { if (stage != null) RemoveDirectoryTree(new DirectoryInfo(stage)); }
        result.RequireSuccess();
        var catalog = new AdminCatalog();
        foreach (string line in result.Output.Split(new[]{'\r','\n'}, StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("folder\t",StringComparison.Ordinal))
            {
                catalog.Folders.Add(Utf8.GetString(Convert.FromBase64String(line.Substring(7))));
                continue;
            }
            if (line == "existing") { catalog.PreviousInstallation = true; continue; }
            string[] values = line.Split('\t');
            if (values.Length != 3 || (values[0] != "saved" && values[0] != "user"))
                throw new InvalidDataException("Не удалось прочитать список администраторов.");
            string sid = ValidateAccountSid(values[1]);
            string name = Utf8.GetString(Convert.FromBase64String(values[2]));
            if (values[0] == "saved") { catalog.ConfiguredSid=sid; catalog.ConfiguredName=name; }
            else catalog.Accounts.Add(new AdminAccount {Name=name, Sid=sid});
        }
        return catalog;
    }

    private static string NewStage()
    {
        CheckNoLinks(ProgramRoot);
        string path = Path.Combine(ProgramRoot, "LocalUsbAudit-Setup-" + Guid.NewGuid().ToString("N"));
        DirectorySecurity security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)");
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("Временный каталог уже занят.");
        Directory.CreateDirectory(path, security);
        return path;
    }

    // Удаляем только временное дерево этой установки, не переходим по ссылкам на другие каталоги.
    private static void RemoveDirectoryTree(DirectoryInfo directory)
    {
        foreach (FileSystemInfo entry in directory.GetFileSystemInfos())
        {
            DirectoryInfo child = entry as DirectoryInfo;
            if (child != null && (child.Attributes & FileAttributes.ReparsePoint) == 0)
                RemoveDirectoryTree(child);
            else
                entry.Delete();
        }
        directory.Delete();
    }

    private static void Install(string readerSid, string adminSid, string[] folders)
    {
        string stage = NewStage();
        try
        {
            WriteResources(stage);
            Dictionary<string, string> env = new Dictionary<string, string>();
            // SID читателя получен до повышения прав. SID ответственного повторно проверит Install.ps1.
            env["LOCALUSBAUDIT_READER"] = readerSid;
            env["LOCALUSBAUDIT_ADMIN_SID"] = adminSid;
            // Имена папок передаются как данные, включая пробелы, кавычки PowerShell и кириллицу.
            env["LOCALUSBAUDIT_FOLDERS"] = String.Join(",", folders.Select(p => Convert.ToBase64String(Utf8.GetBytes(p))));
            env["TEMP"] = env["TMP"] = Directory.CreateDirectory(Path.Combine(stage, "Temp")).FullName;
            string body = "Write-Host 'Установка журнала USB';" +
                "$paths=@($env:LOCALUSBAUDIT_FOLDERS -split ',' | Where-Object {$_} | ForEach-Object {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))});" +
                "& .\\Install.ps1 -DestinationFolders $paths -ReaderUser $env:LOCALUSBAUDIT_READER -AdminSid $env:LOCALUSBAUDIT_ADMIN_SID -EnableHotPlugSecureOpen";
            PowerShell(body, stage, null, env).RequireSuccess();
        }
        finally { RemoveDirectoryTree(new DirectoryInfo(stage)); }
    }

    internal static int StartInstall()
    {
        ProcessStartInfo start = new ProcessStartInfo(Executable, "--install-ui " + Role.CurrentSid());
        start.UseShellExecute = true;
        start.Verb = "runas";
        start.WorkingDirectory = Environment.SystemDirectory;
        using (Process child = Process.Start(start))
        {
            child.WaitForExit();
            return child.ExitCode;
        }
    }

    internal sealed class PsResult
    {
        internal int Code;
        internal string Output, Errors;
        internal void RequireSuccess()
        {
            if (Code != 0) throw new InvalidOperationException(
                !String.IsNullOrWhiteSpace(Errors) ? Errors.Trim() :
                "Windows PowerShell завершила операцию с кодом " + Code + ".");
        }
    }

    // PowerShell передаёт часть ошибок в CLIXML. В диалоге показываем текст ошибки.
    private static string ReadErrors(string raw)
    {
        string messages = Regex.Replace(raw, @"<Objs\b[^>]*>[\s\S]*?</Objs>", delegate(Match block)
        {
            var xml = new XmlDocument { XmlResolver = null };
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            try
            {
                using (XmlReader reader = XmlReader.Create(new StringReader(block.Value), settings)) xml.Load(reader);
                var lines = new List<string>();
                foreach (XmlNode item in xml.DocumentElement.ChildNodes)
                {
                    var record = item as XmlElement;
                    if (record == null || !String.Equals(record.GetAttribute("S"), "Error", StringComparison.OrdinalIgnoreCase)) continue;
                    XmlNode message = record.LocalName == "S" ? record :
                        record.SelectSingleNode("./*[local-name()='ToString']");
                    if (message != null) lines.Add(XmlConvert.DecodeName(message.InnerText).Trim());
                }
                return String.Join(Environment.NewLine, lines);
            }
            catch (XmlException) { return "Windows PowerShell вернула повреждённое сообщение об ошибке."; }
        });
        return Regex.Replace(messages, @"(?m)^\s*#< CLIXML[ \t]*\r?$", "").Trim();
    }

    // Параметры передаются как значения; текст команд постоянен. Пароль не входит в командную строку.
    private static PsResult PowerShell(string body, string directory,
        string input, Dictionary<string, string> environment)
    {
        string script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" +
            "try{" + body + "}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}";
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        ProcessStartInfo start = new ProcessStartInfo(NativePowerShell,
            "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
            "-EncodedCommand " + encoded);
        start.UseShellExecute = false;
        start.WorkingDirectory = directory;
        start.CreateNoWindow = true;
        start.RedirectStandardError = true;
        start.StandardErrorEncoding = Encoding.UTF8;
        start.RedirectStandardOutput = true;
        start.StandardOutputEncoding = Encoding.UTF8;
        start.RedirectStandardInput = input != null;
        if (environment != null)
            foreach (KeyValuePair<string,string> item in environment) start.EnvironmentVariables[item.Key] = item.Value;
        // Загружаем модули и системные утилиты из каталогов, доступных для записи администраторам.
        start.EnvironmentVariables["PSModulePath"] =
            Path.Combine(ProgramRoot, @"WindowsPowerShell\Modules") + ";" +
            Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\Modules");
        start.EnvironmentVariables["Path"] = Environment.SystemDirectory + ";" + SystemRoot + ";" +
            Path.Combine(Environment.SystemDirectory, "Wbem") + ";" +
            Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0");
        // Системные пути получаем от Windows и не наследуем их значения от вызывающего процесса.
        start.EnvironmentVariables["SystemRoot"] = start.EnvironmentVariables["windir"] = SystemRoot;
        start.EnvironmentVariables["ProgramFiles"] = ProgramRoot;
        start.EnvironmentVariables["ProgramData"] = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        start.EnvironmentVariables["ComSpec"] = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        using (Process process = Process.Start(start))
        {
            Task<string> errors = process.StandardError.ReadToEndAsync();
            Task<string> output = process.StandardOutput.ReadToEndAsync();
            if (input != null)
            {
                process.StandardInput.Write(input);
                process.StandardInput.Close();
            }
            process.WaitForExit();
            return new PsResult {Code=process.ExitCode, Errors=ReadErrors(errors.Result), Output=output.Result};
        }
    }

    // В UAC передаём только штатную Windows PowerShell, путь к установленному сценарию и фиксированные параметры.
    // Строка архива проверяется целиком. Пароль вводится уже в отдельном повышенном процессе.
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr RegisterEventSource(string server, string source);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool ReportEvent(IntPtr handle, ushort type, ushort category, uint id,
        byte[] userSid, ushort count, uint size,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType=UnmanagedType.LPWStr, SizeParamIndex=5)] string[] strings,
        IntPtr data);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool DeregisterEventSource(IntPtr handle);

    // Читатель сообщает о выборе в Windows Application. Права записи в защищённый журнал ему не выдаются.
    internal static void NoteArchiveChoice(string archive, int id)
    {
        if (archive==null || !ArchivePattern.IsMatch(archive) || id<4101 || id>4103)
            throw new ArgumentException("Некорректное событие интерфейса.");
        using (var identity=WindowsIdentity.GetCurrent())
        {
            var sid=new byte[identity.User.BinaryLength];
            identity.User.GetBinaryForm(sid,0);
            IntPtr handle=RegisterEventSource(null,"LocalUsbAuditMaintenance");
            if (handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                if (!ReportEvent(handle,4,0,(uint)id,sid,1,0,new[]{archive},IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            } finally { DeregisterEventSource(handle); }
        }
    }

    internal static ProcessStartInfo MaintenanceStart(string action, string archive)
    {
        string arguments = "-NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File \"" +
            Path.Combine(Installed,"Maintenance.ps1") + "\" -InteractiveWindow -Action ";
        if (action == "rotate" && archive == null) arguments += "Rotate";
        else if (action == "delete" && archive != null && ArchivePattern.IsMatch(archive))
            arguments += "Delete -Archive " + archive;
        else throw new ArgumentException("Некорректное действие или имя архива.");
        return new ProcessStartInfo(NativePowerShell, arguments) {
            WorkingDirectory=Environment.SystemDirectory, UseShellExecute=true, Verb="runas", WindowStyle=ProcessWindowStyle.Normal
        };
    }

    // Перед вызовом UAC проверяем возможность подмены системного исполняемого файла и рабочего каталога.
    private static void CheckProtectedAcl(FileSystemSecurity security, bool systemFile)
    {
        const string installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        Func<string,bool> trusted = sid => sid=="S-1-5-18" || sid=="S-1-5-32-544" || (systemFile && sid==installer);
        var descriptor=new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(),0);
        if (descriptor.DiscretionaryAcl==null || !trusted(descriptor.Owner.Value))
            throw new IOException("У защищённого пути неподходящий владелец или отсутствует список разрешений.");
        const FileSystemRights writes = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType!=AccessControlType.Allow || trusted(rule.IdentityReference.Value) ||
                (rule.PropagationFlags & PropagationFlags.InheritOnly)!=0) continue;
            if ((((uint)rule.FileSystemRights) & (0x50000000u | (uint)writes))!=0)
                throw new IOException("Права доступа допускают подмену рабочего компонента. Обратитесь к администратору.");
        }
    }

    private static FileStream OpenVerifiedResource(string name)
    {
        string path=Path.Combine(Installed,name);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Рабочий компонент является ссылкой: " + name);
        var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        try
        {
            using (SHA256 sha=SHA256.Create())
                if (!sha.ComputeHash(stream).SequenceEqual(sha.ComputeHash(Resource(name))))
                    throw new InvalidDataException("Контрольная сумма " + name +
                        " отличается. Откройте EXE установленной версии или выполните согласованное обновление.");
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    private static PsResult Maintain(string action, string archive)
    {
        ProcessStartInfo start = MaintenanceStart(action, archive);
        CheckNoLinks(Path.GetDirectoryName(start.FileName));
        if ((File.GetAttributes(start.FileName) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Путь к системной Windows PowerShell перенаправлен.");
        CheckProtectedAcl(File.GetAccessControl(start.FileName),true);
        CheckNoLinks(Installed);
        CheckProtectedAcl(Directory.GetAccessControl(Installed),false);
        // Обслуживание требует установленных файлов той же версии, что и открытый EXE.
        // До завершения операции удерживаем эти файлы открытыми с запретом записи и удаления.
        using (OpenVerifiedResource("ArchiveAudit.ps1"))
        using (OpenVerifiedResource("Maintenance.ps1"))
        using (OpenVerifiedResource("Access.ps1"))
        try
        {
            using (Process child=Process.Start(start))
            {
                child.WaitForExit();
                return new PsResult {Code=child.ExitCode, Output="", Errors=child.ExitCode==0 ? "" :
                    "Обслуживание не подтвердило успех. Подробности приведены в окне Windows PowerShell. Код " + child.ExitCode + "."};
            }
        }
        catch (Win32Exception error)
        {
            if (error.NativeErrorCode!=1223) throw;
            if (action=="delete") NoteArchiveChoice(archive,4103);
            return new PsResult {Code=1223, Output="", Errors="Запрос UAC отменён. Операция с архивом не запущена."};
        }
    }

    // Шаблон и сценарий берём из открытого EXE, чтобы уже собранные журналы
    // можно было просмотреть новой версией без перезапуска или обновления сборщика.
    private static PsResult GenerateReport(string archive)
    {
        const string command =
            "$code=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::ReadLine())).TrimStart([char]0xfeff);" +
            "$viewer=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()));" +
            "$options=@{ViewerTemplate=$viewer;NoOpen=$true};" +
            "if($env:LOCALUSBAUDIT_ARCHIVE){$options.ArchiveName=$env:LOCALUSBAUDIT_ARCHIVE};" +
            "& ([scriptblock]::Create($code)) @options";
        string input = Convert.ToBase64String(Resource("Report.ps1")) + "\n" +
            Convert.ToBase64String(Resource("viewer.html"));
        var environment = new Dictionary<string,string>{{"LOCALUSBAUDIT_ARCHIVE", archive ?? ""}};
        return PowerShell(command, Environment.SystemDirectory, input, environment);
    }

    // Отчёт открывается с правами текущего читателя. Диагностика относится к установленному сборщику.
    internal static PsResult Script(string action, string archive)
    {
        CheckNoLinks(Installed);
        if (archive != null && !ArchivePattern.IsMatch(archive))
            throw new ArgumentException("Недопустимое имя закрытого архива.");
        PsResult result;
        switch (action)
        {
            case "report":
                result = GenerateReport(archive);
                break;
            case "check":
                result = PowerShell("& .\\Check.ps1;exit $LASTEXITCODE", Installed, null, null);
                break;
            case "rotate":
            case "delete": return Maintain(action, archive);
            default: throw new ArgumentException("Неизвестная операция.");
        }
        if (action == "report" && result.Code == 0)
        {
            string report = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"LocalUsbAudit\Reports\USB-Audit.html");
            if (!File.Exists(report)) throw new FileNotFoundException("Отчёт не найден после формирования.", report);
            Process.Start(new ProcessStartInfo(report) {UseShellExecute=true});
        }
        return result;
    }
}

// Пользователь подтверждает конкретную УЗ. Для старой установки прежний служебный SID автоматически не выбирается.
internal sealed class AdministratorPicker : Form
{
    private readonly ComboBox accounts = new ComboBox { DropDownStyle=ComboBoxStyle.DropDownList, Dock=DockStyle.Fill };
    private readonly TextBox sid = new TextBox { ReadOnly=true, Dock=DockStyle.Fill };
    private readonly Button confirm = Dashboard.Button("Продолжить");
    internal string SelectedSid { get { return ((UsbAudit.AdminAccount)accounts.SelectedItem).Sid; } }

    private readonly ListBox folders = new ListBox { Dock=DockStyle.Fill, Height=68, HorizontalScrollbar=true };
    internal string[] SelectedFolders { get { return folders.Items.Cast<string>().ToArray(); } }
    internal AdministratorPicker(UsbAudit.AdminCatalog catalog)
    {
        Text = "Ответственный за архивы";
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = MaximizeBox = false;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        var layout = new TableLayoutPanel {
            Dock=DockStyle.Fill, Padding=new Padding(16), ColumnCount=1, AutoSize=true, AutoSizeMode=AutoSizeMode.GrowAndShrink
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 520));
        int row=0;
        AddLabel(layout, row++, "Выберите локального администратора. Его пароль потребуется для закрытия журнала и удаления архивов.");
        if (catalog.ConfiguredSid != null)
            AddLabel(layout, row++, "Сейчас назначен: " +
                (String.IsNullOrEmpty(catalog.ConfiguredName) ? catalog.ConfiguredSid : catalog.ConfiguredName) + ".");
        else if (catalog.PreviousInstallation)
            AddLabel(layout, row++, "Для обновления назначьте ответственного из списка.");
        accounts.Name = "Administrators";
        accounts.AccessibleName = "Учётная запись администратора";
        layout.Controls.Add(accounts, 0, row++);
        AddLabel(layout, row++, "SID выбранной учётной записи");
        sid.AccessibleName = "SID выбранной учётной записи";
        layout.Controls.Add(sid, 0, row++);
        AddLabel(layout, row++, "Папки, в которых отслеживается запись файлов с USB");
        folders.AccessibleName = "Контролируемые папки назначения";
        folders.Items.AddRange(catalog.Folders.Count == 0
            ? new[]{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments),"USB-Audit-Inbox")}
            : catalog.Folders.ToArray());
        layout.Controls.Add(folders, 0, row++);
        var addFolder = Dashboard.Button("Добавить папку…");
        addFolder.AutoSize = true;
        addFolder.Click += delegate {
            using (var dialog = new FolderBrowserDialog {Description="Выберите локальную папку NTFS. Для рабочего стола откройте папку того пользователя, который будет копировать файлы.", ShowNewFolderButton=false})
                if (dialog.ShowDialog(this)==DialogResult.OK && !SelectedFolders.Contains(dialog.SelectedPath,StringComparer.OrdinalIgnoreCase))
                    folders.Items.Add(dialog.SelectedPath);
        };
        layout.Controls.Add(addFolder, 0, row++);
        var current = catalog.Accounts.Find(a=>a.Sid==catalog.ConfiguredSid);
        if (catalog.Accounts.Count == 0)
            AddLabel(layout, row++, "На этом компьютере нет включённых локальных пользователей, напрямую входящих в группу администраторов.");
        else if (catalog.ConfiguredSid != null && current == null)
            AddLabel(layout, row++, "Ранее выбранная УЗ недоступна. Для продолжения выберите действующего администратора.");
        var buttons = new FlowLayoutPanel {AutoSize=true, Dock=DockStyle.Fill, FlowDirection=FlowDirection.RightToLeft,
            Padding=new Padding(0, 12, 0, 0)};
        var cancel = Dashboard.Button("Отмена");
        cancel.DialogResult = DialogResult.Cancel;
        confirm.DialogResult = DialogResult.OK;
        confirm.Enabled = false;
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(confirm);
        layout.Controls.Add(buttons, 0, row);
        Controls.Add(layout);
        AcceptButton = confirm;
        CancelButton = cancel;
        accounts.SelectedIndexChanged += delegate {
            var selected = accounts.SelectedItem as UsbAudit.AdminAccount;
            sid.Text = selected == null ? "" : selected.Sid;
            confirm.Enabled = selected != null;
        };
        accounts.Items.AddRange(catalog.Accounts.ToArray());
        if (current != null) accounts.SelectedItem = current;
    }

    private static void AddLabel(TableLayoutPanel panel, int row, string text)
    {
        panel.Controls.Add(new Label {Text=text, AutoSize=true, MaximumSize=new Size(500,0),
            Margin=new Padding(0,6,0,6)}, 0, row);
    }
}

// Главное окно и отчёт работают с правами читателя. Установка и обслуживание запускаются отдельно через UAC.
internal sealed class Dashboard : Form
{
    private readonly Label state = new Label();
    private readonly Button report = Button("Открыть журнал");
    private readonly Button check = Button("Проверить");
    private readonly Button archives = Button("Архивы…");
    private readonly Button install = Button("Установить");
    private bool busy;

    internal static Button Button(string text)
    {
        Button b = new Button();
        b.Text = text; b.AutoSize = true; b.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        b.Padding = new Padding(8, 3, 8, 3); b.Margin = new Padding(0, 0, 8, 8);
        return b;
    }
    internal Dashboard()
    {
        Text = UsbAudit.Title; Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi; StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(545, 180); MinimumSize = new Size(500, 208);
        var panel = new TableLayoutPanel {Dock=DockStyle.Fill, Padding=new Padding(18), RowCount=3, ColumnCount=1};
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.Controls.Add(new Label {Text="Журнал съёмных носителей", AutoSize=true,
            Font=new Font(Font, FontStyle.Bold)}, 0, 0);
        state.Dock = DockStyle.Fill; state.TextAlign = ContentAlignment.MiddleLeft; panel.Controls.Add(state, 0, 1);
        var buttons = new FlowLayoutPanel {AutoSize=true, Dock=DockStyle.Fill};
        buttons.Controls.AddRange(new Control[]{report, check, archives, install}); panel.Controls.Add(buttons, 0, 2);
        Controls.Add(panel);
        report.Click += async delegate { await Run("report"); };
        check.Click += async delegate { await Run("check"); };
        install.Click += async delegate { await Run("install"); };
        archives.Click += delegate { using (var form = new Archives()) form.ShowDialog(this); };
        FormClosing += delegate(object sender, FormClosingEventArgs e) { if (busy) e.Cancel = true; };
        RefreshState();
    }
    private void RefreshState()
    {
        bool present = UsbAudit.Files.All(n=>File.Exists(Path.Combine(UsbAudit.Installed,n)));
        bool partial = Directory.Exists(UsbAudit.Installed);
        report.Enabled = check.Enabled = archives.Enabled = present && !busy;
        install.Enabled = !busy; install.Text = partial ? "Обновить" : "Установить";
        if (!busy) state.Text = present ? "Компоненты установлены. Состояние сбора доступно по кнопке «Проверить»." :
            partial ? "Установка неполна. Обновите компоненты." :
            "Для начала сбора установите компоненты на этом компьютере.";
    }
    private async Task Run(string action)
    {
        if (busy) return;
        busy=true; RefreshState();
        state.Text = action == "install" ? "Подтвердите запрос Windows и выберите ответственного за архивы в окне установки." :
            action == "report" ? "Формируется отчёт…" : "Выполняется проверка…";
        try
        {
            if (action == "install")
            {
                int code = await Task.Run(()=>UsbAudit.StartInstall());
                if (code == 0) MessageBox.Show(this,
                    "Сборщик запущен. Выйдите из учётной записи и войдите снова, чтобы применились новые права чтения. Подключите тестовый СНИ после входа.",
                    UsbAudit.Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                UsbAudit.PsResult r = await Task.Run(()=>UsbAudit.Script(action, null));
                if (action == "check" && !String.IsNullOrWhiteSpace(r.Output))
                    ShowText(this, "Результаты проверки", r.Output + (r.Code != 0 && r.Errors.Length > 0 ? "\r\n"+r.Errors : ""));
                else r.RequireSuccess();
            }
        }
        catch (Win32Exception e) { MessageBox.Show(this, e.NativeErrorCode == 1223 ?
            "Windows отменила запрос повышения прав." : e.Message, UsbAudit.Title); }
        catch (Exception e) { MessageBox.Show(this,e.Message,UsbAudit.Title,MessageBoxButtons.OK,MessageBoxIcon.Error); }
        finally {busy=false;RefreshState();}
    }
    internal static void ShowText(Form owner, string title, string value)
    {
        using (var form = new Form {Text=title,Font=owner.Font,Size=new Size(750,440),
            StartPosition=FormStartPosition.CenterParent})
        {
            var view = new TextBox {Dock=DockStyle.Fill, ReadOnly=true, Multiline=true,
                ScrollBars=ScrollBars.Vertical, Text=value.Trim(), WordWrap=true};
            form.Controls.Add(view); form.ShowDialog(owner);
        }
    }
}

// Выбор архива относится только к закрытым файлам. Запрос пароля и его проверку выполняет Maintenance.ps1.
internal sealed class Archives : Form
{
    private readonly ListBox list = new ListBox {Dock=DockStyle.Fill,HorizontalScrollbar=true};
    private readonly Label status = new Label {AutoSize=true,Dock=DockStyle.Fill};
    private readonly Button open = Dashboard.Button("Открыть архив");
    private readonly Button rotate = Dashboard.Button("Закрыть текущий журнал");
    private readonly Button delete = Dashboard.Button("Удалить архив");
    private bool busy;
    internal Archives()
    {
        Text="Архивы журнала USB"; Font=new Font("Segoe UI",10); Size=new Size(730,395);
        MinimumSize=new Size(555,290); StartPosition=FormStartPosition.CenterParent;
        var panel=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(14),ColumnCount=1,RowCount=3};
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); panel.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); panel.Controls.Add(status,0,0); panel.Controls.Add(list,0,1);
        var tools = new FlowLayoutPanel {Dock=DockStyle.Fill,AutoSize=true,Padding=new Padding(0,8,0,0)};
        tools.Controls.AddRange(new Control[]{open,rotate,delete});panel.Controls.Add(tools,0,2);Controls.Add(panel);
        list.SelectedIndexChanged+=delegate{EnableButtons();};
        open.Click += async delegate {await Run("report");}; rotate.Click += async delegate {await Run("rotate");};
        delete.Click += async delegate {await Run("delete");};
        FormClosing += delegate(object sender,FormClosingEventArgs e){if(busy)e.Cancel=true;};
        LoadList();
    }
    private void LoadList()
    {
        list.Items.Clear();
        try
        {
            var names=Directory.EnumerateFiles(UsbAudit.ArchiveDirectory,"usb-*.jsonl")
                .Select(Path.GetFileName).Where(n=>UsbAudit.ArchivePattern.IsMatch(n)).OrderByDescending(n=>n).ToArray();
            list.Items.AddRange(names);
            status.Text=names.Length == 0 ? "Закрытых архивов пока нет." : "Закрытые архивы";
        }
        catch(Exception e){ status.Text="Чтение списка архивов: "+e.Message; }
        EnableButtons();
    }
    private void EnableButtons()
    {
        open.Enabled=delete.Enabled=!busy && list.SelectedIndex>=0; rotate.Enabled=!busy;list.Enabled=!busy;
    }
    private async Task Run(string action)
    {
        if(busy)return;
        string archive = action=="rotate" ? null : list.SelectedItem as string;
        if(action!="rotate" && archive==null)return;
        busy=true;EnableButtons();
        try
        {
            if(action=="delete")
            {
                UsbAudit.NoteArchiveChoice(archive,4101);
                if(MessageBox.Show(this,"Удалить закрытый архив?\n\n"+archive,
                    UsbAudit.Title,MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)
                {
                    UsbAudit.NoteArchiveChoice(archive,4102);
                    return;
                }
            }
            UsbAudit.PsResult r=await Task.Run(()=>UsbAudit.Script(action,archive));
            r.RequireSuccess();
            if(action!="report") MessageBox.Show(this,action=="rotate" ? "Текущий журнал закрыт. Создан архив." :
                "Выбранный архив удалён.",UsbAudit.Title);
        }
        catch(Exception e){MessageBox.Show(this,e.Message,UsbAudit.Title,MessageBoxButtons.OK,MessageBoxIcon.Error);}
        finally{busy=false;LoadList();}
    }
}
