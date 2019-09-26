using Common.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

// added for mutex support
using System.Threading;

// added for http request
using System.Net;
using System.IO;

// added for named pipes
using System.IO.Pipes;

// added for regkey work
using Microsoft.Win32;

// JSON
//using System.Json;
using Newtonsoft.Json;

// enable using the resource of this executable
using System.Reflection;
using System.Resources;
using System.Globalization;

// mailslots
//using System.Text;
using System.Runtime.InteropServices;
using System.Security;
using System.Runtime.ConstrainedExecution;
using Microsoft.Win32.SafeHandles;
using System.Security.Permissions;
using System.ComponentModel;

using System.Threading.Tasks;
using Topshelf;

namespace Innoculate.Service
{
    public class BooleanJsonConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(bool) || objectType == typeof(PipeDirection) || objectType == typeof(RegistryValueKind);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            Console.WriteLine(objectType.ToString());
            if (objectType == typeof(bool))
            {
                switch (reader.Value.ToString().ToLower().Trim())
                {
                    case "true":
                    case "yes":
                    case "y":
                    case "1":
                        return true;
                    case "false":
                    case "no":
                    case "n":
                    case "0":
                        return false;
                }
            }
            else if (objectType == typeof(PipeDirection))
            {
                switch (reader.Value.ToString().ToLower().Trim())
                {
                    case "in":
                        return PipeDirection.In;
                    case "out":
                        return PipeDirection.Out;
                    case "inout":
                        return PipeDirection.InOut;
                }
            }
            else if (objectType == typeof(RegistryValueKind))
            {
                switch (reader.Value.ToString().ToLower().Trim())
                {
                    case "binary":
                        return RegistryValueKind.Binary;
                    case "dword":
                        return RegistryValueKind.DWord;
                    case "expandstring":
                        return RegistryValueKind.ExpandString;
                    case "multistring":
                        return RegistryValueKind.MultiString;
                    case "none":
                        return RegistryValueKind.None;
                    case "qword":
                        return RegistryValueKind.QWord;
                    case "string":
                        return RegistryValueKind.String;
                    case "unknown":
                        return RegistryValueKind.Unknown;
                }
            }
            // If we reach here, we're pretty much going to throw an error so let's let Json.NET throw it's pretty-fied error message.
            return new JsonSerializer().Deserialize(reader, objectType);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
        }

    }
    public class JsonFilepath : IEquatable<JsonFilepath>
    {
        public string path { get; set; }
        public int size { get; set; }
        public bool directory { get; set; }
        public string GetDirPath()
        {
            if (directory == true)
                return path;
            else
            {
                return Path.GetDirectoryName(path);
            }
        }
        public override bool Equals(object obj)
        {
            return this.Equals(obj as JsonFilepath);
        }
        public bool Equals(JsonFilepath other)
        {
            if (other.path != path)
                return false;
            if (other.directory != directory)
                return false;
            if (other.size != size)
                return false;
            return true;
        }
        public override int GetHashCode()
        {
            return path.GetHashCode() ^ size ^ directory.GetHashCode();
        }
    }

    public class JsonMutex : IEquatable<JsonMutex>
    {
        public string name { get; set; }
        public bool used { get; set; }
        public override bool Equals(object obj)
        {
            return this.Equals(obj as JsonFilepath);
        }
        public bool Equals(JsonMutex other)
        {
            if (other.name != name)
                return false;
            if (other.used != used)
                return false;
            return true;
        }
        public override int GetHashCode()
        {
            return name.GetHashCode() ^ used.GetHashCode();
        }
    }

    public class JsonNamedpipe : IEquatable<JsonNamedpipe>
    {
        //public string direction { get; set; }
        public PipeDirection direction { get; set; }
        public string path { get; set; }
        public override bool Equals(object obj)
        {
            return this.Equals(obj as JsonFilepath);
        }
        public bool Equals(JsonNamedpipe other)
        {
            if (other.path != path)
                return false;
            if (other.direction != direction)
                return false;
            return true;
        }
        public override int GetHashCode()
        {
            return path.GetHashCode() ^ direction.GetHashCode();
        }
    }

    public class JsonMailslot : IEquatable<JsonMailslot>
    {
        public string path { get; set; }
        public override bool Equals(object obj)
        {
            return this.Equals(obj as JsonMailslot);
        }
        public bool Equals(JsonMailslot other)
        {
            if (other.path != path)
                return false;
            return true;
        }
        public override int GetHashCode()
        {
            return path.GetHashCode();
        }
    }

    public class JsonProcess : IEquatable<JsonProcess>
    {
        public string name { get; set; }
        public string type { get; set; }
        public override bool Equals(object obj)
        {
            return this.Equals(obj as JsonFilepath);
        }
        public bool Equals(JsonProcess other)
        {
            if (other.name != name)
                return false;
            if (other.type != type)
                return false;
            return true;
        }
        public override int GetHashCode()
        {
            return name.GetHashCode() ^ type.GetHashCode();
        }
    }

    public class JsonRegkey : IEquatable<JsonRegkey>
    {
        public string path { get; set; }
        public RegistryValueKind type { get; set; }
        public string value { get; set; }
        public string valuename { get; set; }
        public bool Equals(JsonRegkey other)
        {
            if (other.path != path)
                return false;
            if (other.type != type)
                return false;
            if (other.value != value)
                return false;
            if (other.valuename != valuename)
                return false;
            return true;
        }
        public override int GetHashCode()
        {
            return path.GetHashCode() ^ type.GetHashCode() ^ value.GetHashCode() ^ valuename.GetHashCode();
        }
        public object GetCastValue()
        {
            switch (type)
            {
                case RegistryValueKind.Binary:
                    return Convert.FromBase64String(value);
                case RegistryValueKind.DWord:
                    return Convert.ToInt32(value);
                case RegistryValueKind.ExpandString:
                    return value;
                case RegistryValueKind.MultiString:
                    string[] strings = value.Split(',');
                    List<string> tmpList = new List<string>();
                    foreach (string s in strings)
                    {
                        tmpList.Add(Encoding.UTF8.GetString(Convert.FromBase64String(s)));
                    }
                    return tmpList.ToArray();
                case RegistryValueKind.None:
                    return null;
                case RegistryValueKind.QWord:
                    return Convert.ToInt64(value);
                case RegistryValueKind.String:
                    return value;
                case RegistryValueKind.Unknown:
                    return null;
            }
            return null;
        }
        public RegistryKey getRegistryKey()
        {
            string cmpath = path.ToLower();
            string[] hkcr = new string[] { "classesroot", "hkcr", "hkey_classes_root" };
            string[] hkcc = new string[] { "currentconfig", "hkcc", "hkey_current_config" };
            string[] hkcu = new string[] { "currentuser", "hkcu", "hkey_current_user" };
            //string[] hkdd = new string[] { "dyndata", "hkdd" };
            string[] hklm = new string[] { "localmachine", "hklm", "hkey_local_machine" };
            string[] hkpd = new string[] { "performancedata", "hkpd", "hkey_performance_data" };
            string[] hku = new string[] { "user", "hku", "hkey_users" };
            if (hkcr.Any(cmpath.Contains))
            {
                return Registry.ClassesRoot;
            }
            else if (hkcc.Any(cmpath.Contains))
            {
                return Registry.CurrentConfig;

            }
            else if (hkcu.Any(cmpath.Contains))
            {
                return Registry.CurrentUser;

            }
            //else if (hkdd.Any(cmpath.Contains))
            //{
            //    return Registry.DynData;

            //}
            else if (hklm.Any(cmpath.StartsWith))
            {
                return Registry.LocalMachine;
            }
            else if (hkpd.Any(cmpath.Contains))
            {
                return Registry.PerformanceData;
            }
            else if (hku.Any(cmpath.StartsWith))
            {
                return Registry.Users;
            }
            return null;
        }
    }

    public class JsonListener : IEquatable<JsonListener>
    {
        public string protocol { get; set; }
        public uint port { get; set; }
        public string response { get; set; }
        public bool immediateresponse { get; set; }

        public override bool Equals(object obj)
        {
            return this.Equals(obj as JsonListener);
        }
        public bool Equals(JsonListener other)
        {
            if (other.protocol != protocol)
                return false;
            if (other.port != port)
                return false;

            return true;
        }
        public override int GetHashCode()
        {
            return protocol.GetHashCode() ^ port.GetHashCode() ^ response.GetHashCode() ^ immediateresponse.GetHashCode();
        }
    }

    public class JsonDefinitionDocument
    {
        public List<JsonFilepath> filepaths { get; set; }
        public List<JsonMutex> mutex { get; set; }
        public List<JsonNamedpipe> namedpipes { get; set; }
        public List<JsonMailslot> mailslots { get; set; }
        public List<JsonProcess> processes { get; set; }
        public List<JsonRegkey> regkeys { get; set; }
    }
    class WinService
    {
        private Thread innocThread;
        //private List<Thread> pipeThreads;
        private static List<JsonMutex> mutexList;
        private static List<JsonNamedpipe> pipeList;
        private static List<JsonRegkey> regkeyList;
        private static List<JsonFilepath> filepathList;
        private static List<JsonMailslot> mailslotList;

        public ILog Log { get; private set; }

        public WinService(ILog logger)
        {
            // IocModule.cs needs to be updated in case new paramteres are added to this constructor

            if (logger == null)
                throw new ArgumentNullException(nameof(logger));

            Log = logger;

            mutexList = new List<JsonMutex>();
            pipeList = new List<JsonNamedpipe>();
            regkeyList = new List<JsonRegkey>();
            filepathList = new List<JsonFilepath>();
            mailslotList = new List<JsonMailslot>();

        }

        private static void SyncFromJSON(string html)
        {
            JsonDefinitionDocument json = JsonConvert.DeserializeObject<JsonDefinitionDocument>(html, new BooleanJsonConverter());

            // MUTEX section
            Console.WriteLine("Mutices:");
            if (json.mutex != null)
            {
                Console.WriteLine(" * Entries found:");
                foreach (JsonMutex jmutex in json.mutex)
                {
                    if (mutexList.Contains(jmutex) == false)
                    {
                        Mutex mut = new Mutex(jmutex.used, jmutex.name);
                        Console.WriteLine("  * " + jmutex.name);
                        mutexList.Add(jmutex);
                    }


                }

            }

            // NAMED PIPE section
            Console.WriteLine("Named Pipes:");
            if (json.namedpipes != null)
            {
                Console.WriteLine(" * Entries found:");
                foreach (JsonNamedpipe jpipe in json.namedpipes)
                {
                    if (pipeList.Contains(jpipe) == false)
                    {
                        InnoculatePipeThread(jpipe);
                        Console.WriteLine("  * " + jpipe.path);
                        pipeList.Add(jpipe);
                    }
                }

            }


            // MAILSLOTS section
            Console.WriteLine("Mailslots:");
            if (json.mailslots != null)
            {
                Console.WriteLine(" * Entries found:");
                foreach (JsonMailslot jmail in json.mailslots)
                {
                    if (mailslotList.Contains(jmail) == false)
                    {
                        InnoculateMailThread(jmail);
                        Console.WriteLine("  * " + jmail.path);
                        mailslotList.Add(jmail);
                    }
                }

            }

            // REGKEYS section
            Console.WriteLine("Registry Keys:");
            if (json.regkeys != null)
            {
                Console.WriteLine(" * Entries found:");
                foreach (JsonRegkey jkey in json.regkeys)
                {
                    if (regkeyList.Contains(jkey) == false)
                    {
                        string[] arrpath = jkey.path.Split(new string[] { @"\" }, StringSplitOptions.None);
                        string path = String.Join(@"\", jkey.path.Split(new string[] { @"\" }, StringSplitOptions.None).Skip(1));
                        //Microsoft.Win32.Registry.open
                        RegistryKey baseregkey = jkey.getRegistryKey();
                        try
                        {
                            var key = baseregkey.CreateSubKey(path);
                            if (jkey.type != RegistryValueKind.None)
                            {
                                key.SetValue(jkey.valuename, jkey.value, jkey.type);
                            }
                        }
                        catch (System.IO.IOException e)
                        {
                            Console.WriteLine("IOException: " + e.Message);
                            continue;
                        }
                        catch (System.FormatException e)
                        {
                            Console.WriteLine("FormatException: " + e.Message);
                            continue;
                        }
                        catch (System.ArgumentException e)
                        {
                            Console.WriteLine("ArgumentException: " + e.Message);
                            continue;
                        }
                        catch (System.UnauthorizedAccessException e)
                        {
                            Console.WriteLine("UnauthorizedAccessException: " + e.Message);
                            continue;
                        }
                        Console.WriteLine("  * " + jkey.path);
                        regkeyList.Add(jkey);
                    }
                }

            }

            // FILE/DIR CREATION section
            Console.WriteLine("File Paths:");
            if (json.filepaths != null)
            {
                Console.WriteLine(" * Entries found:");
                foreach (JsonFilepath jfile in json.filepaths)
                {
                    try
                    {
                        Directory.CreateDirectory(jfile.GetDirPath());
                        if (jfile.directory == false)
                        {
                            FileStream fs = new FileStream(jfile.path, FileMode.CreateNew);
                            fs.Seek(jfile.size, SeekOrigin.Begin);
                            fs.WriteByte(0);
                            fs.Close();
                        }
                        Console.WriteLine(jfile.path);
                    }
                    catch (System.IO.IOException e)
                    {
                        Console.WriteLine("IOException: " + e.Message);
                        continue;
                    }
                    filepathList.Add(jfile);
                    Console.WriteLine("  * " + jfile.path);
                }
            }

            // PROCESSES section
            Console.WriteLine("Processes:");
            if (json.processes != null)
            {
                Console.WriteLine(" * Entries found:");
                //    JsonArray procstrings = (JsonArray)json["processes"];
                //    foreach (string procstring in procstrings)
                //    {
                //        Console.WriteLine(procstring);
                //    }

            }
        }

        private static void InnoculatePipeThread(JsonNamedpipe jpipe)
        {
            NamedPipeServerStream pipe = new NamedPipeServerStream(jpipe.path, jpipe.direction);
            pipe.WaitForConnectionAsync();
        }

        // https://code.msdn.microsoft.com/windowsapps/CSMailslotServer-1ca18b47/sourcecode?fileId=21681&pathId=621891947
        private static void InnoculateMailThread(JsonMailslot jpipe)
        {
            SECURITY_ATTRIBUTES sa = CreateMailslotSecurity();
            SafeMailslotHandle hMailslot = NativeMethod.CreateMailslot(
                    jpipe.path,               // The name of the mailslot 
                    0,                          // No maximum message size 
                    MAILSLOT_WAIT_FOREVER,      // Waits forever for a message 
                    sa                          // Mailslot security attributes 
                    );

            if (hMailslot.IsInvalid)
            {
                throw new Win32Exception();
            }

            Console.WriteLine("The mailslot ({0}) is created.", jpipe.path);

            // Check messages in the mailslot. 
            ReadMailslot(hMailslot);
        }

        private static void InnocProc()
        {
            string html = string.Empty;

            ResourceManager rm = new ResourceManager("Innoculate.ConfigurationResources", Assembly.GetExecutingAssembly());
            string url = rm.GetString("SourceURL");

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                html = reader.ReadToEnd();
            }

            Console.WriteLine(html);

            SyncFromJSON(html);
        }


        public bool Start(HostControl hostControl)
        {

            Log.Info($"{nameof(Service.WinService)} Start command received.");
            innocThread = new Thread(new ThreadStart(InnocProc));
            innocThread.Start();
            //TODO: Implement your service start routine.
            return true;

        }

        public bool Stop(HostControl hostControl)
        {

            Log.Trace($"{nameof(Service.WinService)} Stop command received.");

            //TODO: Implement your service stop routine.
            return true;

        }

        public bool Pause(HostControl hostControl)
        {

            Log.Trace($"{nameof(Service.WinService)} Pause command received.");

            //TODO: Implement your service start routine.
            return true;

        }

        public bool Continue(HostControl hostControl)
        {

            Log.Trace($"{nameof(Service.WinService)} Continue command received.");

            //TODO: Implement your service stop routine.
            return true;

        }

        public bool Shutdown(HostControl hostControl)
        {

            Log.Trace($"{nameof(Service.WinService)} Shutdown command received.");

            //TODO: Implement your service stop routine.
            return true;

        }

        /// <summary> 
        /// The CreateMailslotSecurity function creates and initializes a new  
        /// SECURITY_ATTRIBUTES object to allow Authenticated Users read and  
        /// write access to a mailslot, and to allow the Administrators group full  
        /// access to the mailslot. 
        /// </summary> 
        /// <returns> 
        /// A SECURITY_ATTRIBUTES object that allows Authenticated Users read and  
        /// write access to a mailslot, and allows the Administrators group full  
        /// access to the mailslot. 
        /// </returns> 
        /// <see cref="http://msdn.microsoft.com/en-us/library/aa365600.aspx"/> 
        static SECURITY_ATTRIBUTES CreateMailslotSecurity()
        {
            // Define the SDDL for the security descriptor. 
            string sddl = "D:" +        // Discretionary ACL 
                "(A;OICI;GRGW;;;AU)" +  // Allow read/write to authenticated users 
                "(A;OICI;GA;;;BA)";     // Allow full control to administrators 

            SafeLocalMemHandle pSecurityDescriptor = null;
            if (!NativeMethod.ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl, 1, out pSecurityDescriptor, IntPtr.Zero))
            {
                throw new Win32Exception();
            }

            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = pSecurityDescriptor;
            sa.bInheritHandle = false;
            return sa;
        }


        /// <summary> 
        /// Read the messages from a mailslot by using the mailslot handle in a call  
        /// to the ReadFile function.  
        /// </summary> 
        /// <param name="hMailslot">The handle of the mailslot</param> 
        /// <returns>  
        /// If the function succeeds, the return value is true. 
        /// </returns> 
        static bool ReadMailslot(SafeMailslotHandle hMailslot)
        {
            int cbMessageBytes = 0;         // Size of the message in bytes 
            int cbBytesRead = 0;            // Number of bytes read from the mailslot 
            int cMessages = 0;              // Number of messages in the slot 
            int nMessageId = 0;             // Message ID 

            bool succeeded = false;

            // Check for the number of messages in the mailslot. 
            succeeded = NativeMethod.GetMailslotInfo(
                hMailslot,                  // Handle of the mailslot 
                IntPtr.Zero,                // No maximum message size  
                out cbMessageBytes,         // Size of next message  
                out cMessages,              // Number of messages  
                IntPtr.Zero                 // No read time-out 
                );
            if (!succeeded)
            {
                Console.WriteLine("GetMailslotInfo failed w/err 0x{0:X}",
                    Marshal.GetLastWin32Error());
                return succeeded;
            }

            if (cbMessageBytes == MAILSLOT_NO_MESSAGE)
            {
                // There are no new messages in the mailslot at present 
                Console.WriteLine("No new messages.");
                return succeeded;
            }

            // Retrieve the messages one by one from the mailslot. 
            while (cMessages != 0)
            {
                nMessageId++;

                // Declare a byte array to fetch the data 
                byte[] bBuffer = new byte[cbMessageBytes];
                succeeded = NativeMethod.ReadFile(
                    hMailslot,              // Handle of mailslot 
                    bBuffer,                // Buffer to receive data 
                    cbMessageBytes,         // Size of buffer in bytes 
                    out cbBytesRead,        // Number of bytes read from mailslot 
                    IntPtr.Zero             // Not overlapped I/O 
                    );
                if (!succeeded)
                {
                    Console.WriteLine("ReadFile failed w/err 0x{0:X}",
                        Marshal.GetLastWin32Error());
                    break;
                }

                // Display the message.  
                Console.WriteLine("Message #{0}: {1}", nMessageId,
                    Encoding.Unicode.GetString(bBuffer));

                // Get the current number of un-read messages in the slot. The number 
                // may not equal the initial message number because new messages may  
                // arrive while we are reading the items in the slot. 
                succeeded = NativeMethod.GetMailslotInfo(
                    hMailslot,              // Handle of the mailslot 
                    IntPtr.Zero,            // No maximum message size  
                    out cbMessageBytes,     // Size of next message  
                    out cMessages,          // Number of messages  
                    IntPtr.Zero             // No read time-out  
                    );
                if (!succeeded)
                {
                    Console.WriteLine("GetMailslotInfo failed w/err 0x{0:X}",
                        Marshal.GetLastWin32Error());
                    break;
                }
            }

            return succeeded;
        }


        #region Native API Signatures and Types 

        /// <summary> 
        /// Mailslot waits forever for a message  
        /// </summary> 
        internal const int MAILSLOT_WAIT_FOREVER = -1;

        /// <summary> 
        /// There is no next message 
        /// </summary> 
        internal const int MAILSLOT_NO_MESSAGE = -1;


        /// <summary> 
        /// Represents a wrapper class for a mailslot handle.  
        /// </summary> 
        [SecurityCritical(SecurityCriticalScope.Everything),
        HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true),
        SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        internal sealed class SafeMailslotHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeMailslotHandle()
                : base(true)
            {
            }

            public SafeMailslotHandle(IntPtr preexistingHandle, bool ownsHandle)
                : base(ownsHandle)
            {
                base.SetHandle(preexistingHandle);
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success),
            DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                return CloseHandle(base.handle);
            }
        }


        /// <summary> 
        /// The SECURITY_ATTRIBUTES structure contains the security descriptor for  
        /// an object and specifies whether the handle retrieved by specifying  
        /// this structure is inheritable. This structure provides security  
        /// settings for objects created by various functions, such as CreateFile,  
        /// CreateNamedPipe, CreateProcess, RegCreateKeyEx, or RegSaveKeyEx. 
        /// </summary> 
        [StructLayout(LayoutKind.Sequential)]
        internal class SECURITY_ATTRIBUTES
        {
            public int nLength;
            public SafeLocalMemHandle lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        /// <summary> 
        /// Represents a wrapper class for a local memory pointer.  
        /// </summary> 
        [SuppressUnmanagedCodeSecurity,
        HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
        internal sealed class SafeLocalMemHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeLocalMemHandle()
                : base(true)
            {
            }

            public SafeLocalMemHandle(IntPtr preexistingHandle, bool ownsHandle)
                : base(ownsHandle)
            {
                base.SetHandle(preexistingHandle);
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success),
            DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern IntPtr LocalFree(IntPtr hMem);

            protected override bool ReleaseHandle()
            {
                return (LocalFree(base.handle) == IntPtr.Zero);
            }
        }


        /// <summary> 
        /// The class exposes Windows APIs to be used in this code sample. 
        /// </summary> 
        [SuppressUnmanagedCodeSecurity]
        internal class NativeMethod
        {
            /// <summary> 
            /// Creates an instance of a mailslot and returns a handle for subsequent  
            /// operations. 
            /// </summary> 
            /// <param name="mailslotName">Mailslot name</param> 
            /// <param name="nMaxMessageSize"> 
            /// The maximum size of a single message 
            /// </param> 
            /// <param name="lReadTimeout"> 
            /// The time a read operation can wait for a message. 
            /// </param> 
            /// <param name="securityAttributes">Security attributes</param> 
            /// <returns> 
            /// If the function succeeds, the return value is a handle to the server  
            /// end of a mailslot instance. 
            /// </returns> 
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern SafeMailslotHandle CreateMailslot(string mailslotName,
                uint nMaxMessageSize, int lReadTimeout,
                SECURITY_ATTRIBUTES securityAttributes);


            /// <summary> 
            /// Retrieves information about the specified mailslot. 
            /// </summary> 
            /// <param name="hMailslot">A handle to a mailslot</param> 
            /// <param name="lpMaxMessageSize"> 
            /// The maximum message size, in bytes, allowed for this mailslot. 
            /// </param> 
            /// <param name="lpNextSize"> 
            /// The size of the next message in bytes. 
            /// </param> 
            /// <param name="lpMessageCount"> 
            /// The total number of messages waiting to be read. 
            /// </param> 
            /// <param name="lpReadTimeout"> 
            /// The amount of time, in milliseconds, a read operation can wait for a  
            /// message to be written to the mailslot before a time-out occurs.  
            /// </param> 
            /// <returns></returns> 
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetMailslotInfo(SafeMailslotHandle hMailslot,
                IntPtr lpMaxMessageSize, out int lpNextSize, out int lpMessageCount,
                IntPtr lpReadTimeout);


            /// <summary> 
            /// Reads data from the specified file or input/output (I/O) device. 
            /// </summary> 
            /// <param name="handle"> 
            /// A handle to the device (for example, a file, file stream, physical  
            /// disk, volume, console buffer, tape drive, socket, communications  
            /// resource, mailslot, or pipe). 
            /// </param> 
            /// <param name="bytes"> 
            /// A buffer that receives the data read from a file or device. 
            /// </param> 
            /// <param name="numBytesToRead"> 
            /// The maximum number of bytes to be read. 
            /// </param> 
            /// <param name="numBytesRead"> 
            /// The number of bytes read when using a synchronous IO. 
            /// </param> 
            /// <param name="overlapped"> 
            /// A pointer to an OVERLAPPED structure if the file was opened with  
            /// FILE_FLAG_OVERLAPPED. 
            /// </param>  
            /// <returns> 
            /// If the function succeeds, the return value is true. If the function  
            /// fails, or is completing asynchronously, the return value is false. 
            /// </returns> 
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool ReadFile(SafeMailslotHandle handle,
                byte[] bytes, int numBytesToRead, out int numBytesRead,
                IntPtr overlapped);


            /// <summary> 
            /// The ConvertStringSecurityDescriptorToSecurityDescriptor function  
            /// converts a string-format security descriptor into a valid,  
            /// functional security descriptor. 
            /// </summary> 
            /// <param name="sddlSecurityDescriptor"> 
            /// A string containing the string-format security descriptor (SDDL)  
            /// to convert. 
            /// </param> 
            /// <param name="sddlRevision"> 
            /// The revision level of the sddlSecurityDescriptor string.  
            /// Currently this value must be 1. 
            /// </param> 
            /// <param name="pSecurityDescriptor"> 
            /// A pointer to a variable that receives a pointer to the converted  
            /// security descriptor. 
            /// </param> 
            /// <param name="securityDescriptorSize"> 
            /// A pointer to a variable that receives the size, in bytes, of the  
            /// converted security descriptor. This parameter can be IntPtr.Zero. 
            /// </param> 
            /// <returns> 
            /// If the function succeeds, the return value is true. 
            /// </returns> 
            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
                string sddlSecurityDescriptor, int sddlRevision,
                out SafeLocalMemHandle pSecurityDescriptor,
                IntPtr securityDescriptorSize);
        }

        #endregion
    }
}
