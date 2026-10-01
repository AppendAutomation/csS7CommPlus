# Project status — CsS7CommPlus

A straight C# port of the Python pyS7commplus library.

## Done
- Core library builds for netstandard2.0, net6.0, net8.0 (0 warnings).
- Value codecs (incl. DInt base-128 varint) — byte-exact to spec §12.1,
  verified by xUnit tests (28 tests passing).
- TPKT/COTP/S7comm-plus v1/v2/v3 framing with round-trip tests.
- Explore name parsers; Response/Tag/Device models; read/write PDU builders.
- Clear-text v1 CreateObject identity path (GetDeviceProperties).
- Pluggable V3 seam (IV3Backend) wired through PLC: GetTagList/Read/ReadList/Write.

## Remaining (the V3 backend, an external dependency)
- Live Explore/Read/Write need an IV3Backend adapter over HarpoS7 /
  S7CommPlusDriver (the C# analog of the Python library's s7commplus pip
  dependency). The adapter maps Browse -> V3TagInfo and ReadValues/WriteValues
  with SymbolCRC = 0 for optimized DBs. This is the one piece not portable from
  the Python source because the Python side delegated it to gijzelaerr/s7commplus.
