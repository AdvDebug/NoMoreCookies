using System;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Data;
using System.Security.Policy;

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
                Console.Write("Error: " + ex.Message);
                Console.ReadLine();
                return false;
            }
            return false;
        }

        static void Main(string[] args)
        {
            string VERSION = "1.8";
            Console.Title = "NoMoreCookies Installer";
            Console.WriteLine("Checking for updates");
            VersionChecker versionChecker = new VersionChecker();
            versionChecker.CheckVersion(VERSION);
            Console.Write("Welcome to NoMoreCookies Installer!\n\n1. Install NoMoreCookies (Compatible with programs and games, only hooks Non-Signed Programs and Non-Services Processes)\n2. Install XNoMoreCookies (Hooks all programs except services, also compatible with most games and software but may cause some delays, recommended for maximum security)\n\n3. Uninstall NoMoreCookies\n\nOption: ");
            string Option = Console.ReadLine();
            try
            {
                string NoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\NoMoreCookies_x64.dll";
                string NoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\NoMoreCookies.dll";
                string XNoMoreCookiesx64 = Environment.CurrentDirectory + "\\Components\\XNoMoreCookies_x64.dll";
                string XNoMoreCookiesx86 = Environment.CurrentDirectory + "\\Components\\XNoMoreCookies.dll";
                if (File.Exists(Environment.CurrentDirectory + "\\Components\\NoMoreCookies_x64.dll") && File.Exists(Environment.CurrentDirectory + "\\Components\\NoMoreCookies.dll") && File.Exists(Environment.CurrentDirectory + "\\Components\\XNoMoreCookies_x64.dll") && File.Exists(Environment.CurrentDirectory + "\\Components\\XNoMoreCookies.dll") && File.Exists(Environment.CurrentDirectory + "\\Components\\NoMoreCookiesService.exe") && File.Exists(Environment.CurrentDirectory + "\\Components\\NoMoreCookiesService_x64.exe"))
                {
                    if (!IsSecureBootEnabled())
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
                                        File.Copy(NoMoreCookiesx86, "C:\\NoMoreCookies.dll");
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls of x86 registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully installed NoMoreCookies, please restart your system to apply changes.");
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
                                        Local.SetValue("AppInit_DLLs", "C:\\XNoMoreCookies.dll", RegistryValueKind.String);
                                        Local.SetValue("LoadAppInit_DLLs", 1, RegistryValueKind.DWord);
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
                            case "3":
                                if (!Environment.Is64BitOperatingSystem)
                                {
                                    RegistryKey Local3 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true);
                                    if (Local3 != null)
                                    {
                                        Local3.SetValue("AppInit_DLLs", null, RegistryValueKind.String);
                                        Local3.SetValue("LoadAppInit_DLLs", 0, RegistryValueKind.DWord);
                                    }
                                    else
                                        Console.WriteLine("\n\nCouldn't open the AppInit_Dlls registry key for writing.");
                                    Console.WriteLine("\n\nSuccessfully uninstalled NoMoreCookies, please restart your system to apply changes.");
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
                        if (Option == "3")
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

                        if (Option != "1" && Option != "2")
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
                                    File.Copy(NoMoreCookiesx86, "C:\\NoMoreCookies.dll");
                                    if (Environment.Is64BitOperatingSystem)
                                        File.Copy(NoMoreCookiesx64, "C:\\NoMoreCookies_x64.dll");
                                }
                                else if (Option == "2")
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
                                        File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Disabled");
                                        File.WriteAllText("C:\\Windows\\SysWOW64\\NoMoreConfig.txt", "XMode: Disabled");
                                        
                                    }
                                    else if(Option == "2")
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
                                        File.WriteAllText("C:\\Windows\\System32\\NoMoreConfig.txt", "XMode: Disabled");

                                    }
                                    else if (Option == "2")
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
                else
                {
                    Console.WriteLine("\n\nUnable to find NoMoreCookies Libraries in the current directory.");
                    Console.Read();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n\nError while doing an operation: " + ex.Message);
                Console.Read();
            }
        }
    }
}