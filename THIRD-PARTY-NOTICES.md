# Third-party notices

`CsS7CommPlus` (the core library) implements the S7comm-plus protocol itself —
framing, codecs, Explore parsing and the clear-text V1 identity path — directly
from the VM106 / S7-1200 specification, and has no third-party dependencies.

`CsS7CommPlus.V3` (the protocol-version-3 backend) is a C# port of the
MIT-licensed `s7commplus` Python implementation, and it takes the session
authentication from the MIT-licensed HarpoS7 rather than reimplementing it.
Both licences are MIT, which permits use in any software including closed-source
and commercial products, provided the copyright and permission notice below are
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
| `Session/S7CommPlusConnection.cs`       | `connection.py`, `transport.py` |
| `Session/SubscriptionCodec.cs`          | `subscription.py`        |
| `Symbols/TypeInfo.cs`, `Symbols/SymbolTree.cs` | `typeinfo.py`     |
| `Symbols/SymbolCatalog.cs`              | `catalog.py`             |
| `S7CommPlusClient.cs`                   | `client.py`              |

Not ported: the legacy challenge (`SessionKey`) authentication path, the
password legitimation path, alarms, the async client, the server, block
upload/download, and the zlib preset-dictionary blob decoding. See
`docs/V3-BACKEND.md` for what each omission means in practice.

## HarpoS7 (bonk-dev/HarpoS7) and HarpoS7.PublicKeys — MIT

    Copyright (c) 2024 bonk

Consumed as NuGet packages (`HarpoS7`, `HarpoS7.PublicKeys`). They provide the
S7comm-plus session authentication — `HarpoTlsAuth` for the TIA Portal V17+ TLS
handshake, `CotpStream` for the COTP framing it runs over, and the Siemens
public-key set. The `s7commplus` session-authentication code is itself a port of
HarpoS7.

## Siemens

S7, S7-1200, S7-1500, SIMATIC and TIA Portal are trademarks of Siemens AG.
Neither this library nor its authors are affiliated with or endorsed by Siemens.
The S7comm-plus protocol is not publicly documented by Siemens; this
implementation follows the VM106 / S7-1200 wire-format specification and the
public descriptions cited by the projects above.
