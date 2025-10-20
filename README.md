# JCL.Memory

Lightweight external process memory helper for 32/64-bit processes.

```csharp
using JCL;

var jcl = new JCL("game.exe", true); // true defines that it is a 64bit process / false defines that it is a 32bit process
IntPtr baseAddress = jcl.GetModuleBase("client.dll");
int health = jcl.ReadInt(baseAddress + 0x123456);
```
