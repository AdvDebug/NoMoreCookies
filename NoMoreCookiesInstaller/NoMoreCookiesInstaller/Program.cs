using System;
using System.IO;
using Microsoft.Win32;

namespace NoMoreCookiesInstaller
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Welcome to NoMoreCookies Installer!\n\n1. Install NoMoreCookies\n2. Uninstall NoMoreCookies\n\nOption: ");
            string Option = Console.ReadLine();
            try
            {
                string NoMoreCookiesx64 = Environment.CurrentDirectory + "\\NoMoreCookies_x64.dll";
                string NoMoreCookiesx86 = Environment.CurrentDirectory + "\\NoMoreCookies.dll";
                if (File.Exists(Environment.CurrentDirectory + "\\NoMoreCookies_x64.dll") && File.Exists(Environment.CurrentDirectory + "\\NoMoreCookies.dll"))
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
                    Console.WriteLine("\n\nUnable to find NoMoreCookies Libraries in the current directory.");
                    Console.Read();
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("\n\nError while doing an operation: " + ex.Message);
                Console.Read();
            }
        }
    }
}
