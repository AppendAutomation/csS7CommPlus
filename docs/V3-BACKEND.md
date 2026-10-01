# CsS7CommPlus.V3 — the protocol-version-3 backend

`CsS7CommPlus` on its own speaks the clear-text protocol-version-1 path: it
connects, negotiates a session and reads the CPU identity. Everything that
reads *data* — Explore, symbolic read, symbolic write — travels over the
integrity-protected version-3 session, which the core library delegates to an
`IV3Backend`.

`CsS7CommPlus.V3` is that backend. With it wired in, the pylogix-style facade
works against a live PLC:

```csharp
using var comm = new PLC("192.168.2.50");
comm.V3BackendFactory = plc => new V3Backend(plc);

var tags = comm.GetTagList();                        // browse the symbol tree
var r = comm.Read("SPDL BLU Winder DB.driveKp");     // 85.5
comm.Write("SPDL BLU Winder DB.typeOfWinder", 3);
```

or drive it directly when you want the subscription and catalog APIs:

```csharp
using var client = new S7CommPlusClient("192.168.2.50");
client.Connect();

foreach (var tag in client.TagCatalog)
    Console.WriteLine($"{tag.Name} : {tag.SoftDataType}");

var raw = client.ReadSymbolic(0x8A0E0005, new uint[] { 2 });
```

## Why symbolic access

With "Optimized block access" ticked — the TIA Portal default — the PLC is free
to relocate variables inside a data block on each download, and the block
export carries no offsets. A classic S7comm driver addresses `DB5.DBD12` and
cannot read such a block at all.

A symbolic request instead names an **access area** (a DB area id, or a process
area's RID) and a **LID path** through the PLC's own symbol tree. The PLC walks
that tree itself, so the request stays correct across downloads. This is how TIA
Portal, Siemens HMI panels and the AVEVA OI Server read these blocks.

## What the session looks like

```
TCP 102
  └── COTP connection request / confirm      (TSAP "SIMATIC-ROOT-HMI")
        └── InitSSL request / response       (clear text)
              └── TLS 1.2/1.3 handshake      (records inside COTP data frames)
                    └── CreateObject         (NullServerSession → session id)
                          └── SetMultiVariables  (echo ServerSessionVersion)
                                └── Explore / GetMultiVariables / SetMultiVariables
```

Two details matter and are easy to get wrong:

- **TLS records are the payload of COTP data frames.** The TPKT and COTP headers
  stay in clear text. Wrapping the socket in TLS encrypts them too, and the PLC
  drops the connection. HarpoS7's `CotpStream` provides that framing, and
  `SslStream` sits on top of it.
- **Inside TLS there is no keyed frame digest.** TLS itself protects the
  session, so the V2 framing that follows carries only the IntegrityId counters.
  The 32-byte keyed digest belongs to the pre-V17 challenge path, which this
  backend does not implement.

## Requirements on the PLC

- A CPU and firmware with secure communication: **S7-1200 FW V4.3 or later**, or
  **S7-1500 FW V2.9 or later**, configured with **TIA Portal V17 or later**.
  Verified on an S7-1212C FW V4.6.
- Each tag's **"Accessible from HMI/OPC UA"** ticked. It is on by default for DB
  members and PLC tags.
- No access-level password. The password (legitimation) exchange is not ported;
  a protected PLC reports its protection level and then refuses the operations
  that level forbids.
- The PLC is addressed by IP or host name. PROFINET DCP discovery is not used.

A PLC configured with TIA Portal V16 or earlier uses the legacy challenge
scheme, where frames carry a keyed digest instead of travelling inside TLS.
HarpoS7 implements that scheme's crypto (`LegacyAuthenticationScheme`), so the
path could be added, but it is not implemented here and such a PLC fails to
connect rather than falling back.

## Reads are issued with SymbolCRC 0

Every symbolic request carries a symbol CRC that asks the PLC to verify the
block layout the client believes in. The browsed catalog CRC does not match
every firmware, and a mismatched value is rejected with error `0x..9A0013`, so
this backend sends 0 and skips the check. The address path is resolved from the
PLC's live symbol tree on each connect, which is what the check would have been
guarding against.

## Batching

`ReadMany` reads up to `chunk` tags per round-trip (40 by default) with a single
`GetMultiVariables`. The PLC rejects an over-large response and resets the
session; the measured ceiling on an S7-1212C is about 50 tags, so 40 leaves
margin across tag mixes. If a batch fails for any other reason it is retried one
tag at a time, so a single unreadable tag never costs the rest of the batch.

## Subscriptions

`V3Backend` also implements `IV3SubscriptionBackend`, so the PLC can push
changed values instead of being re-read each cycle:

```csharp
comm.Subscribe(new[] { "HBTimer", "IEC_Timer_0_DB.ET" }, cycleMs: 500);
while (true)
{
    var changes = comm.WaitForChanges(2000);
    if (changes == null) break;              // nothing arrived: treat as lost
    foreach (var c in changes) Console.WriteLine(c);
}
```

The PLC's first notification carries every value, so it doubles as the initial
read. It then sends one notification per cycle, **empty when nothing changed** —
an empty list is a healthy result, and a run of timeouts is the signal that the
connection is gone.

## Known behaviour of the process areas

Observed on S7-1200 firmware, and inherited from the implementation this was
ported from:

- Reading a physical output byte LID while every output is off returns an error
  rather than a zero. Treat the error as zero.
- Some firmware sends a TCP reset after the first I/Q/M `GetMultiVariables` of a
  connection. Data-block reads are unaffected.
- A symbolic BOOL written through `SetMultiVariables` may not be reflected by a
  later read of the physical byte. For output state, read the byte LID.

## Omissions from the port

Deliberate, with the reason:

| Not ported | Why |
|---|---|
| Legacy challenge (`SessionKey`) auth | Needs TIA Portal V16 or earlier; the target band is V17+ |
| Password legitimation | Requires the TLS exporter secret, which `SslStream` does not expose |
| Alarms | Not needed for data collection |
| Async client, server | The synchronous client is what a driver needs |
| Block upload/download | Not a data-collection concern |
| zlib preset-dictionary blobs | Only the XML tag-browser path uses them; the symbol browse here reads the binary type-info container instead |

That last row is worth noting: the preset dictionaries in the Python
implementation are documented there as extracted from an LGPL-3.0 project. The
browse path used here does not need them, so none of that data is present in
this library.

## Tests

`tests/CsS7CommPlus.Tests/V3CodecTests.cs` and `V3SymbolTests.cs` check the port
against vectors produced by the Python implementation for the same inputs — the
VLQ forms, the object qualifier, item addresses, PValue encode and decode, the
vartype and name lists, the symbol-tree flattening and the notification parser.
A divergence in the port fails a test instead of producing a request the PLC
quietly rejects.
