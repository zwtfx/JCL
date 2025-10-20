using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace JCL
{
    /// <summary>
    /// Primary memory-access class. Attach to an external process and perform reads/writes.
    /// Implements IDisposable to ensure handles are released.
    /// </summary>
    public sealed class JCL : IDisposable
    {
        private IntPtr _processHandle = IntPtr.Zero;
        private readonly Process _process;
        private readonly bool _is64BitProcess;
        private bool _disposed;

        /// <summary>
        /// Create and attach to a process by name (without extension) or PID.
        /// If multiple processes with the same name exist, the first is used.
        /// </summary>
        /// <param name="processNameOrPid">Process name (e.g. "notepad") or PID string (e.g. "12345").</param>
        public JCL(string processNameOrPid)
        {
            if (int.TryParse(processNameOrPid, out int pid))
            {
                _process = Process.GetProcessById(pid);
            }
            else
            {
                var procs = Process.GetProcessesByName(processNameOrPid);
                if (procs == null || procs.Length == 0)
                    throw new ArgumentException($"Process '{processNameOrPid}' not found.");
                _process = procs[0];
            }

            // Open process with all access rights we need
            _processHandle = OpenProcess(ProcessAccessFlags.VirtualMemoryRead | ProcessAccessFlags.VirtualMemoryWrite | ProcessAccessFlags.VirtualMemoryOperation | ProcessAccessFlags.QueryInformation, false, _process.Id);
            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Failed to open process {_process.ProcessName} (pid {_process.Id}). Make sure you have sufficient privileges.");

            // Determine process bitness using IsWow64Process
            _is64BitProcess = DetermineIf64Bit(_processHandle);
        }

        /// <summary>
        /// Create and attach by Process instance (advanced)
        /// </summary>
        public JCL(Process process)
        {
            _process = process ?? throw new ArgumentNullException(nameof(process));
            _processHandle = OpenProcess(ProcessAccessFlags.VirtualMemoryRead | ProcessAccessFlags.VirtualMemoryWrite | ProcessAccessFlags.VirtualMemoryOperation | ProcessAccessFlags.QueryInformation, false, _process.Id);
            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Failed to open process {_process.ProcessName} (pid {_process.Id}).");
            _is64BitProcess = DetermineIf64Bit(_processHandle);
        }

        /// <summary>
        /// True if the target process is 64-bit.
        /// </summary>
        public bool Is64Bit => _is64BitProcess;

        /// <summary>
        /// Get base address of a loaded module by name (case-insensitive).
        /// Returns IntPtr.Zero if module not found.
        /// </summary>
        public IntPtr GetModuleBase(string moduleName)
        {
            foreach (ProcessModule m in _process.Modules)
            {
                if (string.Equals(m.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase) || string.Equals(m.ModuleName, moduleName + ".dll", StringComparison.OrdinalIgnoreCase))
                    return m.BaseAddress;
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Read raw bytes from the target process.
        /// </summary>
        public byte[] ReadBytes(IntPtr address, int length)
        {
            if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
            var buffer = new byte[length];
            if (!ReadProcessMemory(_processHandle, address, buffer, length, out int bytesRead) || bytesRead != length)
                throw new InvalidOperationException($"Failed to read memory at 0x{address.ToInt64():X} (read {bytesRead} of {length}).");
            return buffer;
        }

        /// <summary>
        /// Write raw bytes to the target process.
        /// </summary>
        public void WriteBytes(IntPtr address, byte[] data)
        {
            if (data == null || data.Length == 0) throw new ArgumentNullException(nameof(data));
            if (!WriteProcessMemory(_processHandle, address, data, data.Length, out int written) || written != data.Length)
                throw new InvalidOperationException($"Failed to write memory at 0x{address.ToInt64():X} (wrote {written} of {data.Length}).");
        }

        /// <summary>
        /// Generic read; supports primitive types and structs with Marshal.SizeOf.
        /// </summary>
        public T ReadStruct<T>(IntPtr address) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            var bytes = ReadBytes(address, size);
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            }
            finally { handle.Free(); }
        }

        /// <summary>
        /// Generic write; supports primitive types and structs.
        /// </summary>
        public void WriteStruct<T>(IntPtr address, T value) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            var buffer = new byte[size];
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
            }
            finally { handle.Free(); }
            WriteBytes(address, buffer);
        }

        /// <summary>
        /// Read an IntPtr value (pointer) from an address.
        /// </summary>
        public IntPtr ReadPointer(IntPtr address)
        {
            var bytes = ReadBytes(address, _is64BitProcess ? 8 : 4);
            return _is64BitProcess ? (IntPtr)BitConverter.ToInt64(bytes, 0) : (IntPtr)BitConverter.ToInt32(bytes, 0);
        }

        /// <summary>
        /// Read a chain of pointers: start at base, then apply offsets in order (classic multilevel pointer).
        /// Returns IntPtr.Zero if any read fails.
        /// </summary>
        public IntPtr ReadPointerChain(IntPtr baseAddress, params int[] offsets)
        {
            IntPtr cur = baseAddress;
            for (int i = 0; i < offsets.Length; i++)
            {
                cur = ReadPointer(cur + offsets[i]);
                if (cur == IntPtr.Zero) return IntPtr.Zero;
            }
            return cur;
        }

        /// <summary>
        /// Simple AoB (pattern) scan within a module. Pattern expressed as bytes and mask string where 'x' = match, '?' = wildcard.
        /// Returns first match address or IntPtr.Zero.
        /// </summary>
        public IntPtr PatternScan(ProcessModule module, byte[] pattern, string mask)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));
            if (pattern == null) throw new ArgumentNullException(nameof(pattern));
            if (pattern.Length != mask.Length) throw new ArgumentException("Pattern and mask lengths must match.");

            int size = module.ModuleMemorySize;
            IntPtr region = module.BaseAddress;
            var data = ReadBytes(region, size);

            for (int i = 0; i < size - pattern.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (mask[j] == 'x' && data[i + j] != pattern[j]) { ok = false; break; }
                }
                if (ok) return region + i;
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Convenience helpers for reading common primitives.
        /// </summary>
        public int ReadInt32(IntPtr address) => BitConverter.ToInt32(ReadBytes(address, 4), 0);
        public float ReadFloat(IntPtr address) => BitConverter.ToSingle(ReadBytes(address, 4), 0);
        public long ReadInt64(IntPtr address) => BitConverter.ToInt64(ReadBytes(address, 8), 0);

        public void WriteInt32(IntPtr address, int v) => WriteBytes(address, BitConverter.GetBytes(v));
        public void WriteFloat(IntPtr address, float v) => WriteBytes(address, BitConverter.GetBytes(v));
        public void WriteInt64(IntPtr address, long v) => WriteBytes(address, BitConverter.GetBytes(v));

        // --- Private helpers ---
        private static bool DetermineIf64Bit(IntPtr processHandle)
        {
            if (!IsWow64Process(processHandle, out bool isWow64))
                throw new InvalidOperationException("Failed to determine process bitness.");

            // If process is running under WOW64, it's 32-bit. If not and OS is 64-bit, process is 64-bit.
            bool os64 = Environment.Is64BitOperatingSystem;
            return os64 && !isWow64;
        }

        #region PInvoke
        [Flags]
        private enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x0400,
            VirtualMemoryRead = 0x0010,
            VirtualMemoryOperation = 0x0008,
            VirtualMemoryWrite = 0x0020,
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);
        #endregion

        #region IDisposable
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

        ~JCL() { Dispose(); }
        #endregion
    }
}
