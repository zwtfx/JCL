# 🧠 JCLM — Lightweight External Memory Library

**JCLM** is a simple and lightweight C# library for external process memory reading and writing — similar to Swed32/Swed64 — built for .NET 8.0

---

## ✨ Features

- Attach to 32-bit or 64-bit processes by name or PID  
- Read and write primitive types, structs, and byte arrays  
- Read pointer chains  
- Scan for AoB (Array of Bytes) patterns  
- Safe resource cleanup with `IDisposable`  
- Easy to use and fully managed C#

---

## 🚀 Installation

You can install **JCLM** via NuGet:

```bash
dotnet add package JCL.Memory
```

# Usage
```csharp
using JCLM;
// Attach to process (by name or PID)
JCLM jcl = new JCLM("game.exe", true); // true = 64bit | false = 32bit

// Get module base
IntPtr client = jcl.GetModuleBase("client.dll");

// Read values
int health = jcl.ReadInt32(client + 0x123456);
float posX = jcl.ReadFloat(client + 0x654321);

// Write values
jcl.WriteInt32(client + 0x123456, 1337);

// Read pointer chain
IntPtr localPlayer = jcl.ReadPointerChain(client + 0x123456, 0x10, 0x20, 0x30);

// Scan for an AoB pattern
IntPtr patternAddress = jcl.PatternScan(
    module: Process.GetProcessesByName("game")[0].Modules[0],
    pattern: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
    mask: "xxxx"
);

// Dispose safely when done
jcl.Dispose();
```
