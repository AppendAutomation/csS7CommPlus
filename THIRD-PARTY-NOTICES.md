# Third-party notices

CsS7CommPlus implements the S7comm-plus protocol itself (framing, codecs,
Explore parsing, the V1 identity path) directly from the VM106 / S7-1200
specification.  The protocol-version-3 integrity key-exchange and per-frame
digest are not implemented here; per Appendix C of that specification a C#
client takes them from the MIT-licensed HarpoS7 (and its public-key set), via
an IV3Backend adapter.  When such a backend is wired in, include its notice:

## HarpoS7 (bonk-dev/HarpoS7) and HarpoS7.PublicKeys — MIT
    Copyright (c) 2024 bonk

## S7CommPlusDriver (Thomas Wiens) — used as a reference/adapter backend
    See its repository for its licence and copyright.

The MIT License permits use in any software, including closed-source and
commercial products, provided the copyright and permission notice are retained.
