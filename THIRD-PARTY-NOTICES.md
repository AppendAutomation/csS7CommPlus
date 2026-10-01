# Third-party notices

`CsS7CommPlus` (the core library) implements the S7comm-plus protocol itself —
framing, codecs, Explore parsing and the clear-text V1 identity path — directly
from the VM106 / S7-1200 specification, and has no third-party dependencies.

`CsS7CommPlus.V3` (the protocol-version-3 backend) is a C# port of the
MIT-licensed `s7commplus` Python implementation. It takes the pre-TIA-V17
session authentication from the MIT-licensed HarpoS7 rather than reimplementing
it, and drives the TLS handshake with the MIT-licensed BouncyCastle. All three
licences are MIT, which permits use in any software including closed-source and
commercial products, provided the copyright and permission notices below are
retained.

## s7commplus (gijzelaerr/s7commplus) — MIT

    Copyright (c) 2013 Gijs Molenaar, Stephan Preeker

`CsS7CommPlus.V3` is a port of this implementation's protocol layer. The ported
parts and the files they came from:

| `CsS7CommPlus.V3`                       | `s7commplus`             |
|-----------------------------------------|--------------------------|
| `Protocol/Vlq.cs`                       | `vlq.py`                 |
| `Protocol/S7Protocol.cs`                | `protocol.py`            |
| `Protocol/S7Codec.cs`                   | `codec.py`               |
| `Protocol/Exceptions.cs`                | `error.py`               |
| `Session/S7CommPlusConnection.cs`       | `connection.py`          |
| `Session/SessionKeyAuth.cs`             | `connection.py` (SecurityKey struct) |
| `Transport/IsoTcpConnection.cs`         | `transport.py`           |
| `Session/SubscriptionCodec.cs`          | `subscription.py`        |
| `Symbols/TypeInfo.cs`, `Symbols/SymbolTree.cs` | `typeinfo.py`     |
| `Symbols/SymbolCatalog.cs`              | `catalog.py`             |
| `S7CommPlusClient.cs`                   | `client.py`              |

Not ported: the password legitimation path, alarms, the async client, the
server role, block upload/download, and the zlib preset-dictionary blob
decoding. See `docs/V3-BACKEND.md` for what each omission means in practice.

`Transport/SiemensTls.cs` is not a port: the Python implementation reaches TLS
through OpenSSL, which has no .NET equivalent, so the client hello a SIMATIC CPU
accepts is configured directly on BouncyCastle there.

## HarpoS7 (bonk-dev/HarpoS7) and HarpoS7.PublicKeys — MIT

    Copyright (c) 2024 bonk

Consumed as NuGet packages (`HarpoS7`, `HarpoS7.PublicKeys`). They provide the
pre-TIA-V17 session authentication — `LegacyAuthenticationScheme` for solving
the CPU's challenge, `KeyExtensions.DeriveKeyId`, the key-flag constants, and
the bundled Siemens public-key set. The `s7commplus` session-authentication code
is itself a port of HarpoS7.

## BouncyCastle.NET (BouncyCastle.Cryptography) — MIT

    Copyright (c) 2000-2024 The Legion of the Bouncy Castle Inc.

Consumed as a NuGet package. It provides the TLS 1.3 client used for the
TIA-Portal-V17+ session. .NET's own `SslStream` cannot be told what to put in
its client hello per connection, and a SIMATIC CPU resets the connection on the
hello SChannel sends; BouncyCastle's managed stack can be configured exactly.

## Siemens

S7, S7-1200, S7-1500, SIMATIC and TIA Portal are trademarks of Siemens AG.
Neither this library nor its authors are affiliated with or endorsed by Siemens.
The S7comm-plus protocol is not publicly documented by Siemens; this
implementation follows the VM106 / S7-1200 wire-format specification and the
public descriptions cited by the projects above.
