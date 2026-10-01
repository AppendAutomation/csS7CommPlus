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
- The full session for PLCs configured with TIA Portal V17 or later: COTP,
  InitSSL, the TLS handshake over COTP data frames, CreateObject, and the V2
  session-setup echo with the device identity string blanked.
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
170 passing. The V3 tests assert against vectors produced by the Python
implementation for the same inputs: the VLQ forms, the object qualifier, item
addresses, PValue encode/decode, the vartype and name lists, the symbol-tree
flattening, the notification parser and the value decoder.

## Not implemented
- The pre-TIA-V17 legacy challenge (`SessionKey`) authentication path. HarpoS7
  supplies that crypto, so it could be added; today such a PLC fails to connect
  rather than falling back.
- Password legitimation: it needs the TLS exporter secret (RFC 5705), which
  .NET's `SslStream` does not expose. A password-protected PLC connects and
  reports its protection level, then refuses what that level forbids.
- Alarms, the async client, the server role, and block upload/download.
- zlib preset-dictionary blob decoding. Only the XML tag-browser path needs it,
  and the symbol browse here reads the binary type-info container instead.

## Not yet verified
The V3 backend has not been run against a live PLC from this repository. The
bench CPU is an S7-1212C FW V4.6 at 192.168.2.50. Until that run happens, treat
the protocol layer as "tested against the reference implementation's vectors",
not as "proven on the wire".
