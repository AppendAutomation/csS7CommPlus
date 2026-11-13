# CsS7CommPlus

A C# library for **S7comm-plus** communication with Siemens **S7-1200 / S7-1500**
PLCs — a straight port of the Python pyS7commplus library,
in the same spirit that [cslogix](https://github.com/AppendAutomation/cslogix) ports pylogix.
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
src/CsS7CommPlus.V3/         the protocol-version-3 backend (net8.0)
  Protocol/                      VLQ, constants, wire codecs
  Session/                       TLS session, requests, subscriptions
  Symbols/                       type-info parsing, symbol tree, catalog
  Values/                        value decoding and formatting
  S7CommPlusClient.cs            browse / read / write / subscribe
  V3Backend.cs                   IV3Backend + IV3SubscriptionBackend
tests/CsS7CommPlus.Tests/     xUnit tests (codecs/framing/parser/models/V3)
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

## Protocol version 3 (Explore / Read / Write) — `CsS7CommPlus.V3`

Everything that reads *data* travels over the integrity-protected
protocol-version-3 session, which the core library delegates to a pluggable
`IV3Backend`.  **`src/CsS7CommPlus.V3/` is that backend**, a port of the
MIT-licensed `s7commplus` Python implementation's protocol layer, with the
session authentication taken from HarpoS7 (MIT, via NuGet).

Wire it in and the facade works against a live PLC:

```csharp
using CsS7CommPlus;
using CsS7CommPlus.V3;

using var comm = new PLC("192.168.2.50");
comm.V3BackendFactory = plc => new V3Backend(plc);

var tags = comm.GetTagList();                        // browse the symbol tree
var r = comm.Read("SPDL BLU Winder DB.driveKp");     // 85.5
comm.Write("SPDL BLU Winder DB.typeOfWinder", 3);

comm.Subscribe(new[] { "HBTimer" }, cycleMs: 500);   // the PLC pushes changes
var changes = comm.WaitForChanges(2000);
```

It handles **both session variants** and picks one automatically: the TLS
session a TIA-Portal-V17+ CPU uses, and the challenge scheme of V16 and earlier.
Verified live against an S7-1212C FW V4.6 — 2290 symbols browsed in 1.56 s, a
site-sized 152-tag read in 209 ms.

See **[docs/V3-BACKEND.md](docs/V3-BACKEND.md)** for the session sequence, why
symbolic access is needed for optimized blocks, the batching limits, the
process-area quirks, and what the port deliberately leaves out.

Without any backend, `GetTagList` / `Read` / `ReadList` / `Write` still return a
clear `Status` saying the V3 backend must be wired — the direct analog of
pyS7commplus when its `s7commplus` dependency is absent.

## Build & test

```
dotnet build  CsS7CommPlus.sln -c Release
dotnet test   tests/CsS7CommPlus.Tests
```

The V3 tests check the port against vectors produced by the Python
implementation for the same inputs, so a divergence fails a test rather than
producing a request a PLC quietly rejects.

## Licence

Apache-2.0 (same as pyS7commplus).  `CsS7CommPlus.V3` is a port of the
MIT-licensed `s7commplus` and depends on HarpoS7 (MIT) — see
`THIRD-PARTY-NOTICES.md`.
