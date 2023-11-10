using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;

namespace NoMoreCookiesService
{
    public partial class MainService : ServiceBase
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr Handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr Module, string Function);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr ProcHandle, IntPtr BaseAddress, string Buffer, int size, int NumOfBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr ProcessHandle, IntPtr Address, int Size, uint AllocationType, uint Protection);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr ProcessHandle, IntPtr ThreadAttributes, uint StackSize, IntPtr StartAddress, IntPtr Parameter, uint CreationFlags, [Out] uint ThreadID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr Handle, uint TimeInMilli);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr ProcessHandle, IntPtr Address, int Size, uint FreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, ref bool IsWow64);

        public MainService()
        {
            InitializeComponent();
        }

        public static unsafe int strlen(string s)
        {
            int length = 0;
            fixed (char* pStr = s)
            {
                length = *(((int*)pStr) - 1);
            }
            return length;
        }

        bool IsSameArch(Process process)
        {
            bool Remote = false;
            bool Current = false;
            IntPtr CurrentProcess = Process.GetCurrentProcess().Handle;
            if (IsWow64Process(process.Handle, ref Remote))
            {
                if (IsWow64Process(CurrentProcess, ref Current))
                {
                    CloseHandle(CurrentProcess);
                    if (Current == Remote)
                        return true;
                }
            }
            return false;
        }

        protected override void OnStart(string[] args)
        {
            Thread.Sleep(10000);
            string DllPath = null;
            if (File.Exists(Environment.CurrentDirectory + "\\NoMoreConfig.txt"))
            {
                string Config = File.ReadAllText(Environment.CurrentDirectory + "\\NoMoreConfig.txt");
                if (Config == "XMode: Mini")
                {
                    if (Environment.Is64BitProcess)
                    {
                        DllPath = @"C:\MiniNoMoreCookies_x64.dll";
                    }
                    else
                    {
                        DllPath = @"C:\MiniNoMoreCookies.dll";
                    }
                }
                else if (Config == "XMode: Disabled")
                {
                    if (Environment.Is64BitProcess)
                    {
                        DllPath = @"C:\NoMoreCookies_x64.dll";
                    }
                    else
                    {
                        DllPath = @"C:\NoMoreCookies.dll";
                    }
                }
                else if (Config == "XMode: Enabled")
                {
                    if (Environment.Is64BitProcess)
                    {
                        DllPath = @"C:\XNoMoreCookies.dll";
                    }
                    else
                    {
                        DllPath = @"C:\XNoMoreCookies_x64.dll";
                    }
                }
            }
            if (DllPath != null)
            {
                while (true)
                {
                    Thread.Sleep(500);
                    foreach (Process ProcessInject in Process.GetProcesses())
                    {
                        try
                        {
                            if (ProcessInject.Id != Process.GetCurrentProcess().Id)
                            {
                                if (IsSameArch(ProcessInject))
                                {
                                    IntPtr LoadLibraryA = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                                    IntPtr Allocation = VirtualAllocEx(ProcessInject.Handle, IntPtr.Zero, strlen(DllPath), 0x00001000 | 0x00002000, 0x04);
                                    WriteProcessMemory(ProcessInject.Handle, Allocation, DllPath, strlen(DllPath), 0);
                                    IntPtr RemoteThread = CreateRemoteThread(ProcessInject.Handle, IntPtr.Zero, 0, LoadLibraryA, Allocation, 0, 0);
                                    WaitForSingleObject(RemoteThread, 4000);
                                    VirtualFreeEx(ProcessInject.Handle, Allocation, strlen(DllPath), 0x00008000);
                                    CloseHandle(RemoteThread);
                                    CloseHandle(ProcessInject.Handle);
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                }
            }
        }

        protected override void OnStop()
        {

        }
    }
}