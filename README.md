# JCL — Starter


## Usage


```csharp
using (var jcl = new JCL.JCL("notepad"))
{
var baseAddr = jcl.GetModuleBase("notepad.exe");
Console.WriteLine($"Base: 0x{baseAddr.ToInt64():X}");


// read int
int x = jcl.ReadInt32(baseAddr + 0x1234);


// pointer chain
IntPtr final = jcl.ReadPointerChain(baseAddr + 0x1000, 0x10, 0x20, 0x8);
var v = jcl.ReadInt32(final);
}
```
