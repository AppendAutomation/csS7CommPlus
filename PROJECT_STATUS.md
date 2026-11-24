# Project status — CsS7CommPlus

A C# S7comm-plus driver for S7-1200/1500: the core library is a port of the
Python pyS7commplus, and `CsS7CommPlus.V3` is a port of the MIT-licensed
`s7commplus` protocol-version-3 implementation.

## Done — core library (`CsS7CommPlus`)
- Builds for netstandard2.0, net6.0 and net8.0 with no warnings.
- Value codecs including the DInt base-128 varint — byte-exact to spec §12.1.
- TPKT / COTP / S7comm-plus v1/v2/v3 framing with round-trip tests.
- Explore name parsers; `Response` / `Tag` / `Device` models; read/write PDU builders.
- Clear-text v1 CreateObject identity path (`GetDeviceProperties`).
- The pluggable V3 seam (`IV3Backend`) wired through `PLC`, plus the optional
  push half (`IV3SubscriptionBackend`) surfaced as `Subscribe` /
  `WaitForChanges` / `Unsubscribe`.

## Done — V3 backend (`CsS7CommPlus.V3`, net8.0)
- Both session variants, chosen automatically by offering the TLS handshake and
  falling back when a CPU refuses it, and each tried with two CreateObject
  variants — the full TIA-Portal-style identification first, then the minimal
  ClientRID-only request on a fresh transport when the CPU answers the fuller
  one with a non-zero return value and no ServerSessionVersion:
  - **TLS** (TIA Portal V17+): COTP, InitSSL, a TLS 1.3 handshake whose records
    travel inside COTP data frames, CreateObject, and the V2 session-setup echo
    with the device identity string blanked. The handshake is BouncyCastle's,
    not `SslStream`'s, because a SIMATIC CPU resets the connection on the hello
    SChannel sends and `SslStream` cannot be configured per connection.
  - **SessionKey** (TIA Portal V16 and earlier): the CPU's challenge solved with
    HarpoS7, encoded into the SecurityKey structure, and then a 32-byte
    HMAC-SHA256 on every frame with cumulative digests across the fragments of
    one response, plus the session activation TIA Portal performs.
- V2 IntegrityId tracking, with the read and write counters spliced into each
  request at the position the protocol expects per function.
- Multi-fragment response reassembly, system-event handling, stale-response
  rejection and notification queueing.
- Symbol browse: enumerate the data blocks, resolve each block's type-info
  relation id, explore the OMS type-info container, rebuild the symbol tree and
  flatten it into named tags with their address paths.
- Symbolic read (batched `GetMultiVariables`, 40 per round-trip, with per-tag
  retry on a batch failure) and symbolic write.
- Data-change subscriptions: create, receive and delete.
- Value decoding and historian-style formatting for every scalar type, the time
  and date types, DTL, STRING and WSTRING.
- CPU operating state.
- Session authentication from HarpoS7 (MIT, NuGet) rather than reimplemented.

## Tests
182 passing. The V3 tests assert against vectors produced by the Python
implementation for the same inputs: the VLQ forms, the object qualifier, item
addresses, PValue encode/decode, the vartype and name lists, the symbol-tree
flattening, the notification parser and the value decoder.

## Not implemented
- Password legitimation: it needs the TLS exporter secret (RFC 5705), which
  .NET's `SslStream` does not expose. A password-protected PLC connects and
  reports its protection level, then refuses what that level forbids.
- Alarms, the async client, the server role, and block upload/download.
- zlib preset-dictionary blob decoding. Only the XML tag-browser path needs it,
  and the symbol browse here reads the binary type-info container instead.

## Verified live
Against the bench S7-1212C FW V4.6 (`OMSP_12.00.02.11`) at 192.168.2.50 on
2026-10-01, over TLS 1.3 with `TLS_AES_128_GCM_SHA256` on x25519:

- connect in about 0.4 s; the CPU reports protection level 1;
- the whole symbol tree browsed: 2290 symbols in 1.56 s;
- optimized-DB reads (`HMI_Tags.Core_Size`, `SPDL BLU Winder DB.InstTPID.Kp1`,
  `IEC_Timer_0_DB.ET`) and process-area reads (`Core OD Offset`, `Tension Raw`,
  `CommsHeartbeat`) all correct; an unknown tag errors per item;
- 9 tags in 31 ms, and 152 tags — a site-sized set — in 209 ms;
- a subscription whose first notification carries every value and which then
  delivers only what changed, on a 500 ms cycle.

Note on the bench CPU: it answers the clear-text CreateObject with a challenge
and a public-key fingerprint, as though it wanted the SessionKey scheme, but it
rejects the session-setup write that carries the solution. The Python
implementation this was ported from fails there identically, byte-for-byte, so
that challenge appears to be vestigial on this firmware. The automatic probe
tries TLS first for exactly this reason.

## Re-verified live, 2026-11-24 — the CPU's session response changed

The same CPU at 192.168.2.50 no longer accepts the full TIA-Portal-style
identification that the 2026-10-01 connect above used. It now answers that
CreateObject with return value `0xE022BD00019FFF7A` and omits
`ServerSessionVersion` entirely, so the 2026-10-01 result does not reproduce as
recorded: a connect fails at session setup in every mode until the driver falls
back to the minimal ClientRID-only request (the port of
`pyS7CommPlus_cli` `b30edf7`). The socket is not reusable after the refusal, so
the retry reconnects.

With the fallback in place, against the same CPU:

- `Automatic` and `Tls` both connect — the full request is refused, the minimal
  one yields `ServerSessionVersion` 83 bytes, fingerprint
  `01:BD426B091F08731A` and a 20-byte challenge, session setup completes, the
  CPU reports protection level 1 — and `HMI_Tags.Core_Size` reads 7, matching
  the value on the PLC.
- `SessionKey` now reaches the setup write (the retry fires and the key blob is
  built) and is then refused there, which is the same vestigial-challenge wall
  described above, not the identification problem.

## Fixed 2026-11-24 — the subscription ran out of credit every two minutes

`SubscriptionCodec.DefaultCreditLimit` was 1000, a finite credit, and nothing in
this library replenishes credit. Worse, the bench CPU honors a positive limit to
its **low byte only**: 1000 (`0x03E8`) buys 232 notifications, 300 (`0x012C`)
buys 44, and a multiple of 256 buys none at all. The CPU then simply goes quiet,
which a client with a watchdog reads as a lost connection — FlynnProbe
reconnected every 125–128 s, to the second, on its 500 ms cycle.

The default is now `-1`, unlimited, which is what the attribute is for. Measured
against the same CPU: 1,192 notifications over 120 s on a 100 ms cycle with no
silence and `CreditTick` constant at 0, where the old default stopped at 232
after 28 s. The encoding was never wrong — two raw big-endian bytes under a
`DataType.Int` scalar, byte-identical to the Python reference — so the value was
the whole defect. `V3SubscriptionCreditTests` now pins both the encoding and the
unlimited default; nothing covered this attribute before, which is how it
shipped.
