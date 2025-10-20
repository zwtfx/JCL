using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace JCL
{
    /// <summary>
    /// Primary memory-access class. Attach to an external process and perform reads/writes.
    /// Implements IDisposable to ensure handles are released.
    /// </summary>
    public sealed class JCLM : IDisposable
    {
        private IntPtr _processHandle = IntPtr.Zero;
        private readonly Process _process;
        private readonly bool _is64BitProcess;
        private bool _disposed;

        public JCLM(string processNameOrPid)
        {
            if (int.TryParse(processNameOrPid, out int pid))
                _process = Process.GetProcessById(pid);
            else
            {
                var procs = Process.GetProcessesByName(processNameOrPid);
                if (procs == null || procs.Length == 0)
                    throw new ArgumentException($"Process '{processNameOrPid}' not found.");
                _process = procs[0];
            }

            _processHandle = OpenProcess(ProcessAccessFlags.VirtualMemoryRead |
                                         ProcessAccessFlags.VirtualMemoryWrite |
                                         ProcessAccessFlags.VirtualMemoryOperation |
                                         ProcessAccessFlags.QueryInformation,
                                         false, _process.Id);

            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Failed to open process {_process.ProcessName} (pid {_process.Id}).");

            _is64BitProcess = DetermineIf64Bit(_processHandle);
        }

        public JCLM(Process process)
        {
            _process = process ?? throw new ArgumentNullException(nameof(process));
            _processHandle = OpenProcess(ProcessAccessFlags.VirtualMemoryRead |
                                         ProcessAccessFlags.VirtualMemoryWrite |
                                         ProcessAccessFlags.VirtualMemoryOperation |
                                         ProcessAccessFlags.QueryInformation,
                                         false, _process.Id);

            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Failed to open process {_process.ProcessName} (pid {_process.Id}).");

            _is64BitProcess = DetermineIf64Bit(_processHandle);
        }

        public bool Is64Bit => _is64BitProcess;

        public IntPtr GetModuleBase(string moduleName)
        {
            foreach (ProcessModule m in _process.Modules)
            {
                if (string.Equals(m.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(m.ModuleName, moduleName + ".dll", StringComparison.OrdinalIgnoreCase))
                    return m.BaseAddress;
            }
            return IntPtr.Zero;
        }

        public byte[] ReadBytes(IntPtr address, int length)
        {
            if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
            var buffer = new byte[length];
            if (!ReadProcessMemory(_processHandle, address, buffer, length, out int bytesRead) || bytesRead != length)
                throw new InvalidOperationException($"Failed to read memory at 0x{address.ToInt64():X} (read {bytesRead} of {length}).");
            return buffer;
        }

        public void WriteBytes(IntPtr address, byte[] data)
        {
            if (data == null || data.Length == 0) throw new ArgumentNullException(nameof(data));
            if (!WriteProcessMemory(_processHandle, address, data, data.Length, out int written) || written != data.Length)
                throw new InvalidOperationException($"Failed to write memory at 0x{address.ToInt64():X} (wrote {written} of {data.Length}).");
        }

        public T ReadStruct<T>(IntPtr address) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            var bytes = ReadBytes(address, size);
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try { return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject()); }
            finally { handle.Free(); }
        }

        public void WriteStruct<T>(IntPtr address, T value) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            var buffer = new byte[size];
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try { Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false); }
            finally { handle.Free(); }
            WriteBytes(address, buffer);
        }

        public IntPtr ReadPointer(IntPtr address)
        {
            var bytes = ReadBytes(address, _is64BitProcess ? 8 : 4);
            return _is64BitProcess ? (IntPtr)BitConverter.ToInt64(bytes, 0)
                                   : (IntPtr)BitConverter.ToInt32(bytes, 0);
        }

        public IntPtr ReadPointerChain(IntPtr baseAddress, params int[] offsets)
        {
            IntPtr cur = baseAddress;
            foreach (int offset in offsets)
            {
                cur = ReadPointer(cur + offset);
                if (cur == IntPtr.Zero) return IntPtr.Zero;
            }
            return cur;
        }

        public int ReadInt32(IntPtr address) => BitConverter.ToInt32(ReadBytes(address, 4), 0);
        public float ReadFloat(IntPtr address) => BitConverter.ToSingle(ReadBytes(address, 4), 0);
        public long ReadInt64(IntPtr address) => BitConverter.ToInt64(ReadBytes(address, 8), 0);

        public void WriteInt32(IntPtr address, int v) => WriteBytes(address, BitConverter.GetBytes(v));
        public void WriteFloat(IntPtr address, float v) => WriteBytes(address, BitConverter.GetBytes(v));
        public void WriteInt64(IntPtr address, long v) => WriteBytes(address, BitConverter.GetBytes(v));

        private static bool DetermineIf64Bit(IntPtr processHandle)
        {
            if (!IsWow64Process(processHandle, out bool isWow64))
                throw new InvalidOperationException("Failed to determine process bitness.");
            return Environment.Is64BitOperatingSystem && !isWow64;
        }

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x0400,
            VirtualMemoryRead = 0x0010,
            VirtualMemoryOperation = 0x0008,
            VirtualMemoryWrite = 0x0020,
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags access, bool inherit, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_processHandle != IntPtr.Zero)
            {
                CloseHandle(_processHandle);
                _processHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~JCLM() => Dispose();
    }
}
