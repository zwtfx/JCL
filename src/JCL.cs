using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace JCL
{
    public class JCL
    {
        private readonly Process _process;
        private readonly IntPtr _handle;
        private readonly bool _is64Bit;

        public JCL(string processName, bool is64Bit)
        {
            _is64Bit = is64Bit;
            _process = Process.GetProcessesByName(processName)[0];
            _handle = OpenProcess(0x1F0FFF, false, _process.Id);
        }

        // --- MODULE BASE ---
        public IntPtr GetModuleBase(string moduleName)
        {
            foreach (ProcessModule mod in _process.Modules)
            {
                if (mod.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    return mod.BaseAddress;
            }
            return IntPtr.Zero;
        }

        // --- READ FUNCTIONS ---
        public byte[] ReadBytes(IntPtr address, int size)
        {
            byte[] buffer = new byte[size];
            ReadProcessMemory(_handle, address, buffer, size, out _);
            return buffer;
        }

        public int ReadInt(IntPtr address)
            => BitConverter.ToInt32(ReadBytes(address, 4), 0);

        public float ReadFloat(IntPtr address)
            => BitConverter.ToSingle(ReadBytes(address, 4), 0);

        public long ReadLong(IntPtr address)
            => BitConverter.ToInt64(ReadBytes(address, 8), 0);

        public IntPtr ReadPointer(IntPtr address, long offset = 0)
        {
            var bytes = ReadBytes(address + (int)offset, _is64Bit ? 8 : 4);
            return _is64Bit
                ? (IntPtr)BitConverter.ToInt64(bytes, 0)
                : (IntPtr)BitConverter.ToInt32(bytes, 0);
        }

        // --- WRITE FUNCTIONS ---
        public void WriteBytes(IntPtr address, byte[] data)
            => WriteProcessMemory(_handle, address, data, data.Length, out _);

        public void WriteInt(IntPtr address, int value)
            => WriteBytes(address, BitConverter.GetBytes(value));

        public void WriteFloat(IntPtr address, float value)
            => WriteBytes(address, BitConverter.GetBytes(value));

        public void WriteLong(IntPtr address, long value)
            => WriteBytes(address, BitConverter.GetBytes(value));

        // --- VECTOR (float[3]) ---
        public float[] ReadVec3(IntPtr address)
        {
            byte[] data = ReadBytes(address, 12);
            return new float[]
            {
                BitConverter.ToSingle(data, 0),
                BitConverter.ToSingle(data, 4),
                BitConverter.ToSingle(data, 8)
            };
        }

        // --- CLEANUP ---
        public void Close() => CloseHandle(_handle);

        // --- P/INVOKE ---
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
