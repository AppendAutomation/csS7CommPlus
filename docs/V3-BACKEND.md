# CsS7CommPlus.V3 — the protocol-version-3 backend

`CsS7CommPlus` on its own speaks the clear-text protocol-version-1 path: it
connects, negotiates a session and reads the CPU identity. Everything that
reads *data* — Explore, symbolic read, symbolic write — travels over the
protocol-version-3 session, which the core library delegates to an
`IV3Backend`.

`CsS7CommPlus.V3` is that backend. With it wired in, the pylogix-style facade
works against a live PLC:

```csharp
using var comm = new PLC("192.168.2.50");
comm.V3BackendFactory = plc => new V3Backend(plc);

comm.OpenSession();                                  // establish it now
var tags = comm.GetTagList();                        // browse the symbol tree
var r = comm.Read("SPDL BLU Winder DB.driveKp");     // 85.5
comm.Write("SPDL BLU Winder DB.typeOfWinder", 3);
```

or drive it directly when you want the catalog and subscription APIs:

```csharp
using var client = new S7CommPlusClient("192.168.2.50");
client.Connect();

foreach (var tag in client.TagCatalog)
    Console.WriteLine($"{tag.Name} : {tag.SoftDataType}");
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

## Two session variants, chosen automatically

A CPU supports exactly one of these, decided by the TIA Portal version its
project was made with:

| | **TLS** | **SessionKey** |
|---|---|---|
| CPU configured with | TIA Portal V17+ | V16 and earlier |
| Handshake | InitSSL, then a TLS handshake whose records travel inside COTP data frames | CreateObject in clear text; the CPU returns a 20-byte challenge and a public-key fingerprint, and the client's solution goes back in the session-setup write |
| Per-frame protection | none needed — TLS already protects the session; the framing inside it is V2 | every frame carries a 32-byte HMAC-SHA256 over its own data, and responses carry an IntegrityId |

There is no field that announces which one a CPU wants: its InitSSL reply is all
zeros either way. So `SessionMode.Automatic`, the default, **offers the TLS
handshake and sees whether it is taken**; a CPU that wants the older scheme
refuses it, and the connection then restarts on the SessionKey path. Set
`Mode` to `Tls` or `SessionKey` to skip the probe when the site is known.

Beware a misleading signal here: the bench S7-1212C FW V4.6 answers the
clear-text CreateObject with a challenge *and* a fingerprint, as though it
wanted the SessionKey scheme, but it then rejects the session-setup write that
carries the solution — and it completes a TLS 1.3 handshake happily. The
Python implementation this was ported from fails on that CPU in exactly the same
way, byte-for-byte, so the challenge it offers appears to be vestigial. That is
why the probe tries TLS *first* rather than trusting the challenge.

## The TLS handshake does not use SslStream

A SIMATIC CPU is particular about the client hello, and answers one it dislikes
with a **TCP reset rather than a TLS alert**. .NET's own `SslStream` cannot be
told what to send per connection — on Windows it is SChannel, which

- advertises the `session_ticket` and `extended_master_secret` extensions, and
- cannot speak TLS 1.3 before Windows 11 / Server 2022.

The bench CPU resets on SChannel's hello on Windows 10 for both reasons, while
it negotiates TLS 1.3 with `TLS_AES_128_GCM_SHA256` over x25519 when the hello
is right. So the handshake is driven by **BouncyCastle** (MIT), a managed stack
whose hello `Transport/SiemensTls.cs` controls exactly: TLS 1.3 then 1.2,
x25519 then secp256r1, and none of the three extensions above. That also makes
the behaviour identical on every Windows version and on Linux.

The session sequence is then:

```
TCP 102
  └── COTP connection request / confirm      (TSAP "SIMATIC-ROOT-HMI")
        └── InitSSL request / response       (clear text)
              └── TLS 1.3 handshake          (records inside COTP data frames)
                    └── CreateObject         (NullServerSession → session id)
                          └── SetMultiVariables  (echo ServerSessionVersion)
                                └── Explore / GetMultiVariables / SetMultiVariables
```

TLS records are the payload of COTP data frames, so the TPKT and COTP headers
stay in clear text. Wrapping the socket in TLS encrypts them too, and the PLC
drops the connection.

## Requirements on the PLC

- An S7-1200 or S7-1500. Verified on an S7-1212C FW V4.6
  (`OMSP_12.00.02.11`, order number `6ES7 212-1HE40-0XB0`).
- Each tag's **"Accessible from HMI/OPC UA"** ticked. It is on by default for DB
  members and PLC tags.
- No access-level password. The password (legitimation) exchange is not ported;
  a protected PLC still connects and reports its protection level, then serves
  only what that level allows.
- The PLC is addressed by IP or host name. PROFINET DCP discovery is not used.

## Symbol names

A data block's subtree is rooted at the block's own name, so its members come
out as TIA spells them: `HMI_Tags.Core_Size`,
`SPDL BLU Winder DB.InstTPID.Kp1`.

The I, Q and M areas have no such name, so the browse invents `IArea`, `QArea`
and `MArea` to root them. TIA Portal shows those symbols as plain PLC tags, and
a site tag list spells them that way, so the **catalog drops the invented
prefix**: `Tension Raw`, not `IArea.Tension Raw`. The qualified spelling stays
resolvable as an alternative, and `Browse()` still returns the qualified name so
the browse itself remains faithful to the wire.

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
session; the measured ceiling on an S7-1212C is about 50, so 40 leaves margin.
If a batch fails for any other reason it is retried one tag at a time, so a
single unreadable tag never costs the rest of the batch.

## Subscriptions

`V3Backend` also implements `IV3SubscriptionBackend`, so the PLC can push
changed values instead of being re-read each cycle:

```csharp
comm.Subscribe(new[] { "CommsHeartbeat", "IEC_Timer_0_DB.ET" }, cycleMs: 500);
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

`cycleMs` is **a sampling rate, not a change filter**. The PLC compares the
symbols once per cycle and reports whatever differs from last time, so a value
that moves several times within one cycle is reported once, at its latest value.
Measured on the bench CPU against a millisecond counter:

| Cycle | Notification interval | Counter advance per notification |
|---|---|---|
| 200 ms | 191–201 ms | +195 to +203 ms |
| 500 ms | 494–501 ms | +495 to +503 ms |
| 1000 ms | 998–1001 ms | +997 to +1001 ms |

At a 1000 ms cycle that counter changed about a thousand times between
notifications and one value arrived. To catch a short pulse — an alarm bit set
for 50 ms, say — the cycle has to be shorter than the pulse, or the subscription
will step over it entirely.

The protocol also has a per-reference trigger mode (attribute 1005) that this
backend does not set, so the PLC's default applies. Whether it offers a true
unsampled on-change mode is untested.

## Measured on the bench S7-1212C

Over the LAN from this repository, 2026-10-01:

| Operation | Time |
|---|---|
| Connect: COTP, InitSSL, TLS 1.3, CreateObject, session setup | ~0.4 s |
| Browse the whole symbol tree (2290 symbols) | ~1.56 s |
| Read 9 tags, batched | 31 ms |
| Read 152 tags (a site-sized set), batched | 209 ms |
| Subscription notification interval, 500 ms cycle | 500 ms |

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
| Password legitimation | Needs the TLS exporter secret (RFC 5705), which neither `SslStream` nor this handshake exposes |
| Alarms | Not needed for data collection |
| Async client, server role | The synchronous client is what a driver needs |
| Block upload/download | Not a data-collection concern |
| zlib preset-dictionary blobs | Only the XML tag-browser path uses them; the symbol browse here reads the binary type-info container instead |

That last row is worth noting: the preset dictionaries in the Python
implementation are documented there as extracted from an LGPL-3.0 project. The
browse path used here does not need them, so none of that data is present in
this library.

## Diagnosing a refused request

Siemens does not document this protocol, so when a CPU refuses something the
frame bytes are usually the only way to see why. Set `TraceFrames` and every
frame sent and received is logged as hex through `OnDiagnostic`:

```csharp
var conn = new S7CommPlusConnection("192.168.2.50") { TraceFrames = true };
conn.OnDiagnostic += Console.WriteLine;
```

Leave it off in production — it logs every byte of every PDU.

## Tests

`tests/CsS7CommPlus.Tests/V3CodecTests.cs` and `V3SymbolTests.cs` check the port
against vectors produced by the Python implementation for the same inputs — the
VLQ forms, the object qualifier, item addresses, PValue encode and decode, the
vartype and name lists, the symbol-tree flattening, the notification parser and
the value decoder. A divergence in the port fails a test instead of producing a
request the PLC quietly rejects.
