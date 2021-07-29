using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace _2Simple_Dll_Injector
{
    class Program
    {
        static void Main(string[] args)
        {
            if(args[0] == null || args[1] == null)
            {
                Console.WriteLine("2Simple Dll Injector.exe <Process Name> <Path To DLL>");
                return;
            }
            Injector.Inject(args[0],args[1]);
        }
    }

    class Injector
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        public static void Inject(string procname, string path)
        {
            string dll = path;
            Process targetProcess = null;
            bool found = false;

            do
            {
                try
                {
                    targetProcess = Process.GetProcessesByName(procname)[0];
                    found = true;
                }
                catch (Exception)
                {
                    Console.WriteLine("Could not find process!");
                    Thread.Sleep(1000);
                    continue;
                }
            }
            while (found == false);

            Console.WriteLine("Process found. ID: " + targetProcess.Id);

            IntPtr handle = OpenProcess(0x001F0FFF, false, targetProcess.Id); //0x001F0FFF: Access - All

            IntPtr LibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            IntPtr AllocatedMemory = VirtualAllocEx(handle, IntPtr.Zero, (uint)((dll.Length + 1) * Marshal.SizeOf(typeof(char))), 0x00001000, 4); //0x00001000: Memory - commit, 4: Page - Read and Write
            Console.WriteLine("DLL allocated at: " + AllocatedMemory.ToString());

            UIntPtr bytesWritten;
            WriteProcessMemory(handle, AllocatedMemory, Encoding.Default.GetBytes(dll), (uint)((dll.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            CreateRemoteThread(handle, IntPtr.Zero, 0, LibraryAddress, AllocatedMemory, 0, IntPtr.Zero);

            Console.WriteLine("Injected! Press enter to continue...");
            Console.ReadLine();
        }
    }
}
