using System;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text;

namespace NoMoreCookiesInstaller
{
    internal class Program
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr OpenServiceA(IntPtr SCManager, string ServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hService);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool MoveFileExA(string FileName, string NewFileName, uint Flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr OpenSCManagerA(string MachineName, string DatabaseName, uint DesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName, uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword);

        public static bool IsSecureBootEnabled()
        {
            try
            {
                RegistryKey SecureBoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", true);
                if (SecureBoot != null)
                {
                    object SecureBootState = SecureBoot.GetValue("UEFISecureBootEnabled");
                    if ((int)SecureBootState == 1)
                        return true;
                }
            }
            catch (Exception ex)
            {
                Console.Write("Error Determining SecureBoot Status: " + ex.Message);
                Console.ReadLine();
                return false;
            }
            return false;
        }

        public static string NMCType(bool SecureBoot)
        {
            if (SecureBoot)
            {
                return "NoMoreCookies Service";
            }
            return "AppInit_DLLs";
        }

        public static void PrintAvailableBrowsers()
        {
            Console.Clear();
            ConsoleColor Default = ConsoleColor.White;
            const string RegisteredApps = @"SOFTWARE\RegisteredApplications";
            using (RegistryKey InstalledApps = Registry.LocalMachine.OpenSubKey(RegisteredApps))
            {
                if (InstalledApps != null)
                {
                    foreach (string ValueName in InstalledApps.GetValueNames())
                    {
                        if (!string.IsNullOrEmpty(ValueName))
                        {
                            string value = ValueName.ToLower();
                            if (value.Contains("firefox"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Firefox has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }

                            if (value.Contains("waterfox"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Waterfox has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }

                            if (value.Contains("brave"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Brave has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }

                            if (value.Contains("chrome"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Chrome has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }

                            if (value.Contains("microsoft edge"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Edge has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }

                            if (value.Contains("opera"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Opera has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }

                            if (value.Contains("librewolf"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("LibreWolf has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.Write("Not Supported.\n");
                            }

                            if (value.Contains("yandex"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Yandex has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }

                            if (value.Contains("chromium"))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write("Chromium has been detected, support status: ");
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("Supported.\n");
                            }
                        }
                    }
                }
            }
            Console.ForegroundColor = Default;
        }

        static void ProcessArgs(string[] args)
        {
            try
            {
                foreach (string arg in args)
                {
                    switch (arg)
                    {
                        case "--ignore-updates":
                            Settings.CheckUpdates = false;
                            break;
                        case "--ignore-warnings":
                            Settings.ShowWarnings = false;
                            break;
                        //this setting is turned off by default for security reasons, you can enable it by editing the code
                        /*
                        case "--direct-uninstall":
                            if (!Settings.DirectInstall)
                                Settings.DirectUninstall = true;
                            break;
                        */
                        case "--show-browsers":
                            Settings.ShowBrowsers = true;
                            break;
                        case "--no-output":
                            Settings.ShowOutput = false;
                            break;
                    }
                    if (arg.StartsWith("--direct-install=") && !Settings.DirectUninstall)
                    {
                        string InstallationOption = arg.Replace("--direct-install=", null).ToLower();
                        switch (InstallationOption)
                        {
                            case "minimode":
                                Settings.DirectInstall = true;
                                Settings.Option = Settings.InstallationOptions.MiniMode;
                                break;
                            case "normalmode":
                                Settings.DirectInstall = true;
                                Settings.Option = Settings.InstallationOptions.NormalMode;
                                break;
                            case "xmode":
                                Settings.DirectInstall = true;
                                Settings.Option = Settings.InstallationOptions.XMode;
                                break;
                        }
                    }
                }
            }
            catch
            {

            }
        }

        public static bool IsComponentsAvailable(string Option)
        {
            if (Option != "1" && Option != "2" && Option != "3")
                return true;
            string MiniNoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\MiniNoMoreCookies_x64.dll";
            string MiniNoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\MiniNoMoreCookies.dll";
            string NoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\NoMoreCookies_x64.dll";
            string NoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\NoMoreCookies.dll";
            string XNoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\XNoMoreCookies_x64.dll";
            string XNoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\XNoMoreCookies.dll";
            if (File.Exists(MiniNoMoreCookiesx86) && File.Exists(MiniNoMoreCookiesx64) && File.Exists(NoMoreCookiesx64) && File.Exists(NoMoreCookiesx86) && File.Exists(XNoMoreCookiesx64) && File.Exists(XNoMoreCookiesx86) && File.Exists(Environment.CurrentDirectory + "\\Components\\NoMoreCookiesService.exe") && File.Exists(Environment.CurrentDirectory + "\\Components\\NoMoreCookiesService_x64.exe"))
            {
                return true;
            }
            return false;
        }

        public static void Install(string Option, bool SecureBoot)
        {
            try
            {
                string MiniNoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\MiniNoMoreCookies_x64.dll";
                string MiniNoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\MiniNoMoreCookies.dll";
                string NoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\NoMoreCookies_x64.dll";
                string NoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\NoMoreCookies.dll";
                string XNoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\XNoMoreCookies_x64.dll";
                string XNoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\XNoMoreCookies.dll";
                if (IsComponentsAvailable(Option))
                {
                    if (!SecureBoot)
                    {
                        switch (Option)
                        {
                            case "1":
                                if (!Environment.Is64BitOperatingSystem)
                                {
                                    RegistryKey Local = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local != null)
                                    {
                                        Local.SetValue("AppInit_DLLs", "C:\\NoMoreCookies.dll", RegistryValueKind.String);
                                        Local.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        if (File.Exists(@"C:\MiniNoMoreCookies.dll"))
                                        {
                                            try
                                            {
                                                File.Delete(@"C:\MiniNoMoreCookies.dll");
                                            }
                                            catch
                                            {
                                                Console.Write("Couldn't delete the existing NoMoreCookies.dll in the File Path: C:\\NoMoreCookies.dll, this maybe because NoMoreCookies.dll are already running in another process.");
                                            }
                                        }
                                        File.Copy(MiniNoMoreCookiesx86, "C:\\MiniNoMoreCookies.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully installed MiniNoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                else
                                {
                                    RegistryKey Local = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local != null)
                                    {
                                        Local.SetValue("AppInit_DLLs", "C:\\MiniNoMoreCookies_x64.dll", RegistryValueKind.String);
                                        Local.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        if (File.Exists(@"C:\MiniNoMoreCookies_x64.dll"))
                                        {
                                            try
                                            {
                                                File.Delete(@"C:\MiniNoMoreCookies_x64.dll");
                                            }
                                            catch
                                            {
                                                Console.Write("Couldn't delete the existing MiniNoMoreCookies_x64.dll in the File Path: C:\\MiniNoMoreCookies_x64.dll, this maybe because MiniNoMoreCookies_x64.dll are already running in another process.");
                                            }
                                        }
                                        File.Copy(MiniNoMoreCookiesx64, "C:\\MiniNoMoreCookies_x64.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls of x64 registry key for writing.");
                                    RegistryKey Local2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                                    RegistryKey Local3 = Local2.OpenSubKey("SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local3 != null)
                                    {
                                        Local3.SetValue("AppInit_DLLs", "C:\\MiniNoMoreCookies.dll", RegistryValueKind.String);
                                        Local3.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        if (File.Exists(@"C:\MiniNoMoreCookies.dll"))
                                        {
                                            try
                                            {
                                                File.Delete(@"C:\MiniNoMoreCookies.dll");
                                            }
                                            catch
                                            {
                                                Console.Write("Couldn't delete the existing MiniNoMoreCookies.dll in the File Path: C:\\MiniNoMoreCookies.dll, this maybe because MiniNoMoreCookies.dll are already running in another process.");
                                            }
                                        }
                                        File.Copy(MiniNoMoreCookiesx86, "C:\\MiniNoMoreCookies.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls of x86 registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully installed MiniNoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                break;
                            case "2":
                                if (!Environment.Is64BitOperatingSystem)
                                {
                                    RegistryKey Local = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local != null)
                                    {
                                        Local.SetValue("AppInit_DLLs", "C:\\NoMoreCookies.dll", RegistryValueKind.String);
                                        Local.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        if (File.Exists(@"C:\NoMoreCookies.dll"))
                                        {
                                            try
                                            {
                                                File.Delete(@"C:\NoMoreCookies.dll");
                                            }
                                            catch
                                            {
                                                Console.Write("Couldn't delete the existing NoMoreCookies.dll in the File Path: C:\\NoMoreCookies.dll, this maybe because NoMoreCookies.dll are already running in another process.");
                                            }
                                        }
                                        File.Copy(NoMoreCookiesx86, "C:\\NoMoreCookies.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully installed NoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                else
                                {
                                    RegistryKey Local = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local != null)
                                    {
                                        Local.SetValue("AppInit_DLLs", "C:\\NoMoreCookies_x64.dll", RegistryValueKind.String);
                                        Local.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        if (File.Exists(@"C:\NoMoreCookies_x64.dll"))
                                        {
                                            try
                                            {
                                                File.Delete(@"C:\NoMoreCookies_x64.dll");
                                            }
                                            catch
                                            {
                                                Console.Write("Couldn't delete the existing NoMoreCookies_x64.dll in the File Path: C:\\NoMoreCookies_x64.dll, this maybe because NoMoreCookies_x64.dll are already running in another process.");
                                            }
                                        }
                                        File.Copy(NoMoreCookiesx64, "C:\\NoMoreCookies_x64.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls of x64 registry key for writing.");
                                    RegistryKey Local2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                                    RegistryKey Local3 = Local2.OpenSubKey("SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local3 != null)
                                    {
                                        Local3.SetValue("AppInit_DLLs", "C:\\NoMoreCookies.dll", RegistryValueKind.String);
                                        Local3.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        if (File.Exists(@"C:\NoMoreCookies.dll"))
                                        {
                                            try
                                            {
                                                File.Delete(@"C:\NoMoreCookies.dll");
                                            }
                                            catch
                                            {
                                                Console.Write("Couldn't delete the existing NoMoreCookies.dll in the File Path: C:\\NoMoreCookies.dll, this maybe because NoMoreCookies.dll are already running in another process.");
                                            }
                                        }
                                        File.Copy(NoMoreCookiesx86, "C:\\NoMoreCookies.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls of x86 registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully installed NoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                break;
                            case "3":
                                if (!Environment.Is64BitOperatingSystem)
                                {
                                    RegistryKey Local = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local != null)
                                    {
                                        Local.SetValue("AppInit_DLLs", "C:\\XNoMoreCookies.dll", RegistryValueKind.String);
                                        Local.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        if (File.Exists(@"C:\XNoMoreCookies.dll"))
                                        {
                                            try
                                            {
                                                File.Delete(@"C:\XNoMoreCookies.dll");
                                            }
                                            catch
                                            {
                                                Console.Write("Couldn't delete the existing XNoMoreCookies.dll in the File Path: C:\\XNoMoreCookies.dll, this maybe because XNoMoreCookies.dll are already running in another process.");
                                            }
                                        }
                                        File.Copy(XNoMoreCookiesx86, "C:\\XNoMoreCookies.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully installed XNoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                else
                                {
                                    RegistryKey Local = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local != null)
                                    {
                                        Local.SetValue("AppInit_DLLs", "C:\\XNoMoreCookies_x64.dll", RegistryValueKind.String);
                                        Local.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        File.Copy(XNoMoreCookiesx64, "C:\\XNoMoreCookies_x64.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls of x64 registry key for writing.");
                                    RegistryKey Local2 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                                    RegistryKey Local3 = Local2.OpenSubKey("SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local3 != null)
                                    {
                                        Local3.SetValue("AppInit_DLLs", "C:\\XNoMoreCookies.dll", RegistryValueKind.String);
                                        Local3.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
                                        File.Copy(XNoMoreCookiesx86, "C:\\XNoMoreCookies.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls of x86 registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully installed XNoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                break;
                            case "4":
                                PrintAvailableBrowsers();
                                Console.Write("\n\n");
                                Main(null);
                                break;
                            case "5":
                                if (!Environment.Is64BitOperatingSystem)
                                {
                                    RegistryKey Local3 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local3 != null)
                                    {
                                        Local3.SetValue("AppInit_DLLs", "", RegistryValueKind.String);
                                        Local3.SetValue("LoadAppInit_DLLs", 0, RegistryValueKind.DWord);
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully uninstalled NoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                else
                                {
                                    RegistryKey Local3 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local3 != null)
                                    {
                                        Local3.SetValue("AppInit_DLLs", "", RegistryValueKind.String);
                                        Local3.SetValue("LoadAppInit_DLLs", 0, RegistryValueKind.DWord);
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls x64 registry key for writing.");
                                    RegistryKey Local4 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                                    RegistryKey Local5 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local5 != null)
                                    {
                                        Local5.SetValue("AppInit_DLLs", "", RegistryValueKind.String);
                                        Local5.SetValue("LoadAppInit_DLLs", 0, RegistryValueKind.DWord);
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls x86 registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully uninstalled NoMoreCookies, please restart your system to apply changes.");
                                    Console.Read();
                                    Environment.Exit(0);
                                }
                                break;
                            default:
                                Console.Write("\n\nInvalid Option Selected.");
                                Console.Read();
                                Environment.Exit(0);
                                break;
                        }
                    }
                    else
                    {
                        string NoMoreCookiesServicex86Machine = "C:\\Windows\\System32\\NoMoreCookiesService.exe";
                        string NoMoreCookiesService = "C:\\Windows\\SysWOW64\\NoMoreCookiesService.exe";
                        string NoMoreCookiesService64 = "C:\\Windows\\System32\\NoMoreCookiesService_x64.exe";
                        if (Option == "5")
                        {
                            if (Environment.Is64BitOperatingSystem && File.Exists(NoMoreCookiesService) && File.Exists(NoMoreCookiesService64) || !Environment.Is64BitOperatingSystem && File.Exists(NoMoreCookiesServicex86Machine))
                            {
                                uint SC_MANAGER_CONNECT = 0x0001;
                                uint DELETE = 0x10000;
                                IntPtr hSCM = OpenSCManagerA(null, null, SC_MANAGER_CONNECT);
                                if (hSCM != IntPtr.Zero)
                                {
                                    if (Environment.Is64BitOperatingSystem)
                                    {
                                        IntPtr NoMoreCookies = OpenServiceA(hSCM, "NoMoreCookies", DELETE);
                                        IntPtr NoMoreCookies_x64 = OpenServiceA(hSCM, "NoMoreCookies_x64", DELETE);
                                        if (NoMoreCookies != IntPtr.Zero && NoMoreCookies_x64 != IntPtr.Zero)
                                        {
                                            bool Operation1 = DeleteService(NoMoreCookies);
                                            bool Operation2 = DeleteService(NoMoreCookies_x64);
                                            if (Operation1 && Operation2)
                                            {
                                                bool RemoveOp = MoveFileExA(NoMoreCookiesService, null, 4);
                                                bool RemoveOp2 = MoveFileExA(NoMoreCookiesService64, null, 4);
                                                if (RemoveOp && RemoveOp2)
                                                {
                                                    Console.Clear();
                                                    Console.Write("Successfully Uninstalled NoMoreCookies, please restart your system.");
                                                    Console.ReadLine();
                                                    Environment.Exit(0);
                                                }
                                                else
                                                {
                                                    Console.Clear();
                                                    Console.Write("Unable to Mark NoMoreCookies Services for deletion, Error Code: " + Marshal.GetLastWin32Error());
                                                    Console.ReadLine();
                                                    Environment.Exit(0);
                                                }
                                            }
                                            else
                                            {
                                                Console.Clear();
                                                Console.Write("Unable to delete NoMoreCookies Services, Error Code: " + Marshal.GetLastWin32Error());
                                                Console.ReadLine();
                                                Environment.Exit(0);
                                            }
                                        }
                                        else
                                        {
                                            if (Marshal.GetLastWin32Error() == 1060L)
                                            {
                                                Console.Clear();
                                                Console.Write("NoMoreCookies are not installed in the first place...");
                                                Console.ReadLine();
                                                Environment.Exit(0);
                                            }
                                            else
                                            {
                                                Console.Clear();
                                                Console.Write("Failed to Open a Handle to NoMoreCookies Services, Error Code: " + Marshal.GetLastWin32Error());
                                                Console.ReadLine();
                                                Environment.Exit(0);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        IntPtr NoMoreCookies = OpenServiceA(hSCM, "NoMoreCookies", DELETE);
                                        if (NoMoreCookies != IntPtr.Zero)
                                        {
                                            bool Operation1 = DeleteService(NoMoreCookies);
                                            if (Operation1)
                                            {
                                                bool RemoveOp = MoveFileExA(NoMoreCookiesService, null, 4);
                                                if (RemoveOp)
                                                {
                                                    Console.Clear();
                                                    Console.Write("Successfully Uninstalled NoMoreCookies, please restart your system.");
                                                    Console.ReadLine();
                                                    Environment.Exit(0);
                                                }
                                                else
                                                {
                                                    Console.Clear();
                                                    Console.Write("Unable to Mark NoMoreCookies Service for deletion, Error Code: " + Marshal.GetLastWin32Error());
                                                    Console.ReadLine();
                                                    Environment.Exit(0);
                                                }
                                            }
                                            else
                                            {
                                                Console.Clear();
                                                Console.Write("Unable to delete NoMoreCookies Service, Error Code: " + Marshal.GetLastWin32Error());
                                                Console.ReadLine();
                                                Environment.Exit(0);
                                            }
                                        }
                                        else
                                        {
                                            if (Marshal.GetLastWin32Error() == 1060L)
                                            {
                                                Console.Clear();
                                                Console.Write("NoMoreCookies are not installed in the first place...");
                                                Console.ReadLine();
                                                Environment.Exit(0);
                                            }
                                            else
                                            {
                                                Console.Clear();
                                                Console.Write("Failed to Open a Handle to NoMoreCookies Service, Error Code: " + Marshal.GetLastWin32Error());
                                                Console.ReadLine();
                                                Environment.Exit(0);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    Console.Clear();
                                    Console.Write("Failed to Open a Service Manager Handle, Error Code: " + Marshal.GetLastWin32Error());
                                    Console.ReadLine();
                                    Environment.Exit(0);
                                }
                            }
                            else
                            {
                                Console.Clear();
                                Console.Write("Looks like NoMoreCookies aren't even installed...");
                                Console.ReadLine();
                                Environment.Exit(0);
                            }
                        }
                        else if (Option == "4")
                        {
                            PrintAvailableBrowsers();
                            Console.Write("\n\n");
                            Main(null);
                        }
                        else
                        {
                            if (Option != "1" && Option != "2" && Option != "3")
                            {
                                Console.Clear();
                                Console.Write("Invalid Option Selected.");
                                Console.ReadLine();
                                Environment.Exit(0);
                            }
                            else
                            {
                                try
                                {
                                    if (Option == "1")
                                    {
                                        File.Copy(MiniNoMoreCookiesx86, "C:\\MiniNoMoreCookies.dll");
                                        if (Environment.Is64BitOperatingSystem)
                                            File.Copy(MiniNoMoreCookiesx64, "C:\\MiniNoMoreCookies_x64.dll");
                                    }
                                    else if (Option == "2")
                                    {
                                        File.Copy(NoMoreCookiesx86, "C:\\NoMoreCookies.dll");
                                        if (Environment.Is64BitOperatingSystem)
                                            File.Copy(NoMoreCookiesx64, "C:\\NoMoreCookies_x64.dll");
                                    }
                                    else if (Option == "3")
                                    {
                                        File.Copy(XNoMoreCookiesx86, "C:\\XNoMoreCookies.dll");
                                        if (Environment.Is64BitOperatingSystem)
                                            File.Copy(XNoMoreCookiesx64, "C:\\XNoMoreCookies_x64.dll");
                                    }
                                    if (Environment.Is64BitOperatingSystem)
                                    {
                                        File.Copy(Environment.CurrentDirectory + "\\Components\\NoMoreCookiesService_x64.exe", NoMoreCookiesService64);
                                        File.Copy(Environment.CurrentDirectory + "\\Components\\NoMoreCookiesService.exe", NoMoreCookiesService);
                                        if (Option == "1")
                                        {
                                            File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Mini");
                                            File.WriteAllText("C:\\Windows\\SysWOW64\\NoMoreConfig.txt", "XMode: Mini");
                                        }
                                        else if (Option == "2")
                                        {
                                            File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Disabled");
                                            File.WriteAllText("C:\\Windows\\SysWOW64\\NoMoreConfig.txt", "XMode: Disabled");
                                        }
                                        else if (Option == "3")
                                        {
                                            File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Enabled");
                                            File.WriteAllText("C:\\Windows\\SysWOW64\\NoMoreConfig.txt", "XMode: Enabled");
                                        }
                                    }
                                    else
                                    {
                                        File.Copy(Environment.CurrentDirectory + "\\Components\\NoMoreCookiesService.exe", NoMoreCookiesServicex86Machine);
                                        if (Option == "1")
                                        {
                                            File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Mini");
                                        }
                                        else if (Option == "2")
                                        {
                                            File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Disabled");
                                        }
                                        else if (Option == "3")
                                        {
                                            File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Enabled");
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.Clear();
                                    Console.Write("Error Moving Necessarry Files: " + ex.Message);
                                    Console.ReadLine();
                                    Environment.Exit(0);
                                }

                                uint SC_MANAGER_CREATE_SERVICE = 0x0002;
                                IntPtr hSCM2 = OpenSCManagerA(null, null, SC_MANAGER_CREATE_SERVICE);
                                if (hSCM2 != IntPtr.Zero)
                                {
                                    uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
                                    uint SERVICE_AUTO_START = 0x00000002;
                                    uint SERVICE_ERROR_NORMAL = 0x00000001;
                                    uint SERVICE_ALL_ACCESS = 0xF01FF;
                                    if (Environment.Is64BitOperatingSystem)
                                    {
                                        IntPtr hService = CreateService(hSCM2, "NoMoreCookies", "NoMoreCookies Injection Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, NoMoreCookiesService, null, IntPtr.Zero, null, "NT AUTHORITY\\SYSTEM", null);
                                        IntPtr hService2 = CreateService(hSCM2, "NoMoreCookies_x64", "NoMoreCookies Injection Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, NoMoreCookiesService64, null, IntPtr.Zero, null, "NT AUTHORITY\\SYSTEM", null);
                                        if (hService != IntPtr.Zero && hService2 != IntPtr.Zero)
                                        {
                                            Console.Clear();
                                            Console.Write("NoMoreCookies have been successfully installed, please your restart your system.");
                                            Console.ReadLine();
                                            Environment.Exit(0);
                                        }
                                        else
                                        {
                                            Console.Clear();
                                            Console.Write("Failed to Create NoMoreCookies Services, Error Code: " + Marshal.GetLastWin32Error());
                                            Console.ReadLine();
                                            Environment.Exit(0);
                                        }
                                    }
                                    else
                                    {
                                        IntPtr hService = CreateService(hSCM2, "NoMoreCookies", "NoMoreCookies Injection Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, NoMoreCookiesService, null, IntPtr.Zero, null, "NT AUTHORITY\\SYSTEM", null);
                                        if (hService != IntPtr.Zero)
                                        {
                                            Console.Clear();
                                            Console.Write("NoMoreCookies have been successfully installed, please your restart your system.");
                                            Console.ReadLine();
                                            Environment.Exit(0);
                                        }
                                        else
                                        {
                                            Console.Clear();
                                            Console.Write("Failed to Create NoMoreCookies Service, Error Code: " + Marshal.GetLastWin32Error());
                                            Console.ReadLine();
                                            Environment.Exit(0);
                                        }
                                    }
                                }
                                else
                                {
                                    Console.Clear();
                                    Console.Write("Failed to Open a Service Manager Handle, Error Code: " + Marshal.GetLastWin32Error());
                                    Console.ReadLine();
                                    Environment.Exit(0);
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("One or more of the Components of NoMoreCookies are not found...");
                    Console.Read();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n\nError while doing an operation: " + ex.Message);
                Console.Read();
            }
        }

        static double Version = 2.3;

        static void Main(string[] args)
        {
            ProcessArgs(args);
            bool SecureBoot = IsSecureBootEnabled();
            if (!Settings.ShowOutput)
            {
                Type consoleType = typeof(Console);
                FieldInfo outField = consoleType.GetField("_out", BindingFlags.Static | BindingFlags.NonPublic);
                FieldInfo inField = consoleType.GetField("_in", BindingFlags.Static | BindingFlags.NonPublic);
                CustomTextWriter customWriter = new CustomTextWriter();
                CustomTextReader customReader = new CustomTextReader();
                outField.SetValue(null, customWriter);
                inField.SetValue(null, customReader);
            }
            if (Settings.ShowBrowsers)
            {
                PrintAvailableBrowsers();
            }
            if (Settings.DirectInstall)
            {
                int Option = (int)Settings.Option;
                Install(Option.ToString(), SecureBoot);
            }
            /* turned off by default for security reasons
            else if(Settings.DirectUninstall)
            {
                Install("5", SecureBoot);
            }*/
            else
            {
                if (Settings.CheckUpdates)
                {
                    Console.Write("Checking for updates... ");
                    VersionChecker.CheckVersion(Version);
                }
                if (Settings.ShowWarnings)
                {
                    ConsoleColor Color = Console.BackgroundColor;
                    if (!Environment.Is64BitOperatingSystem)
                    {
                        Console.BackgroundColor = ConsoleColor.DarkYellow;
                        Console.Write("Please Notice that NoMoreCookies are not tested on x86 systems and may cause bugs.\n\n");
                        Console.BackgroundColor = Color;
                    }
                    if (SecureBoot)
                    {
                        Console.BackgroundColor = ConsoleColor.DarkRed;
                        Console.Write("NoMoreCookies Noticed that you have SecureBoot Enabled, you can still install NoMoreCookies but bugs in the installer may occur and the protection will be much less effective as it doesn't fully Support SecureBoot yet, it's recommended to disable SecureBoot to use NoMoreCookies.\n\n");
                        Console.BackgroundColor = Color;
                    }
                }
                Console.Title = "NoMoreCookies Installer";
                Console.Write("Welcome to NoMoreCookies Installer!\n\n");
                string InstallationType = NMCType(SecureBoot);
                Console.Write($"1. Install MiniNoMoreCookies (The Most compatible version that support nearly all programs, games, and software but provides the most minimal protection but works for most automated stealers)\n\n2. Install NoMoreCookies (Compatible with most programs and games, only hooks Non-Signed Programs and Non-Services Processes and provides additional anti-unhooking and anti-tamper protection and automatically injects NoMoreCookies into programs and the child processes of those programs without relying much on {InstallationType})\n\n3. Install XNoMoreCookies (Hooks all programs except services, also provides anti-unhooking but with a better anti-tamper and a better browser protection that also protects the browser memory from stealers, and automatically injects NoMoreCookies into programs and the child processes of those programs without relying much on {InstallationType}, recommended for maximum security but will break some programs)\n\n4. Browsers Detection and Support View\n\n5. Uninstall NoMoreCookies\n\nOption: ");
                string Option = Console.ReadLine();
                Install(Option, SecureBoot);
            }
        }
    }
}

class CustomTextWriter : TextWriter
{
    public override void Write(string value)
    {
        
    }

    public override void WriteLine(string value)
    {
        
    }

    public override Encoding Encoding => Encoding.Default;
}

class CustomTextReader : TextReader
{
    public override int Read(char[] buffer, int index, int count)
    {
        return 0;
    }

    public override string ReadLine()
    {
        return null;
    }
}