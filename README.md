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
```


---


## Packaging & Publishing


1. Build and pack locally:


```bash
cd src/JCL
dotnet build -c Release
dotnet pack -c Release
# Will create JCL.0.1.0.nupkg in bin/Release
```


2. Publish to nuget.org:


```bash
dotnet nuget push bin/Release/JCL.0.1.0.nupkg -k <API_KEY> -s https://api.nuget.org/v3/index.json
```


(For CI, set NUGET_API_KEY as a secret.)


---


## .github/workflows/ci.yml (example)
