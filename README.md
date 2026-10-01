# CsS7CommPlus

A C# library for **S7comm-plus** communication with Siemens **S7-1200 / S7-1500**
PLCs — a straight port of the Python [pyS7commplus](../pyS7CommPlus) library,
in the same spirit that [cslogix](../../AppendAutomation/cslogix) ports pylogix.
The public interface mirrors pyS7commplus / pylogix: every operation returns a
`Response` with `TagName`, `Value` and `Status`.

```csharp
using CsS7CommPlus;

using var comm = new PLC("192.168.2.50");
var ident = comm.GetDeviceProperties();   // CPU identity (clear-text V1)
Console.WriteLine(ident.Value);

var r = comm.Read("SPDL BLU Winder DB.driveKp");   // V3 (needs a backend; see below)
Console.WriteLine(r);                               // "SPDL BLU Winder DB.driveKp 85.5 Success"
```

## Layout (mirrors cslogix)

```
src/CsS7CommPlus/            class library (netstandard2.0; net6.0; net8.0)
  Constants/S7PlusConstants.cs   transport + framing + function codes (port of s7p_const.py)
  Codec/S7PlusTypes.cs           value codecs incl. the DInt base-128 varint (s7p_types.py)
  Models/{Response,Tag,Device}.cs
  Helpers/ExploreParser.cs       Explore name-block parsers (s7p_tag.py)
  Connection.cs                  TPKT + COTP + S7comm-plus v1/v2/v3 framing (s7p_comm.py)
  IntegrityProvider.cs           integrity hook (s7p_comm.IntegrityProvider)
  Backend/IV3Backend.cs          the V3 session seam (s7p_v3.py)
  PLC.cs                         the facade (s7p.py)
tests/CsS7CommPlus.Tests/     xUnit tests (codecs/framing/parser/models)
examples/BasicExample/
```

## Mapping from the Python library

| Python (`pyS7commplus`)        | C# (`CsS7CommPlus`)                      |
|--------------------------------|------------------------------------------|
| `s7p_const.py`                 | `Constants/S7PlusConstants.cs`           |
| `s7p_types.py`                 | `Codec/S7PlusTypes.cs` (`S7Type` enum)   |
| `s7p_response.py` / `s7p_tag.py` | `Models/Response.cs`, `Models/Tag.cs`, `Models/Device.cs`, `Helpers/ExploreParser.cs` |
| `s7p_comm.py`                  | `Connection.cs`, `IntegrityProvider.cs`  |
| `s7p_v3.py` (backend seam)     | `Backend/IV3Backend.cs`                  |
| `s7p.py` (`PLC`, `Device`)     | `PLC.cs`                                  |

`PLC` methods match: `Connect`, `Close`/`Dispose`, `GetDeviceProperties`,
`ConnectionTest`, `GetTagList`, `Read`, `ReadList` (batched), `Write`, plus the
static `BuildWriteRequest` / `BuildReadSingleRequest` builders.

## What works out of the box

- TCP + TPKT + COTP connect, the S7comm-plus v1/v2/v3 envelope, and the
  clear-text **v1 CreateObject identity** read.
- All **value codecs** (Bool, (U)SInt, (U)Int, (U)DInt, Word, DWord, Real,
  LReal, incl. the base-128 two's-complement DInt varint) — every worked
  example in spec §12.1 is reproduced byte-for-byte by the tests.
- The **Explore** name parsers and the read/write PDU builders.

## Protocol version 3 (Explore / Read / Write) — the backend seam

On S7-1200 FW4+ the V3 traffic is wrapped in SIMATIC integrity protection.
Exactly as in the Python library — where that crypto is an **external MIT
dependency** (gijzelaerr/s7commplus), not part of the library's own code — the
C# port delegates the V3 session to a pluggable `IV3Backend`.  Per the wire-spec
Appendix C, the C# backend is **HarpoS7 / the S7CommPlusDriver**.

Provide it by implementing `IV3Backend` (Browse / Read / Write over the
integrity-protected session) and setting the factory:

```csharp
comm.V3BackendFactory = plc => new S7CommPlusDriverBackend(plc);  // your adapter
comm.GetTagList();                                   // now browses live
comm.Read("SPDL BLU Winder DB.driveKp");             // now reads live
```

Without a backend, `GetTagList` / `Read` / `ReadList` / `Write` return a clear
`Status` explaining that the V3 backend must be wired — the direct analog of
pyS7commplus when its `s7commplus` dependency is absent.  The adapter over the
local `S7CommPlusDriver` (Connect/Browse/ReadValues/WriteValues, with
SymbolCRC = 0 for optimized DBs, as the Python side learned) is the remaining
integration to light up live V3.

## Build & test

```
dotnet build  CsS7CommPlus.sln -c Release
dotnet test   tests/CsS7CommPlus.Tests
```

## Licence

Apache-2.0 (same as pyS7commplus).  The V3 integrity backend (HarpoS7 /
S7CommPlusDriver) is MIT — see `THIRD-PARTY-NOTICES.md`.
