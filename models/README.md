# Hub Network models

This package is the Go representation of the version 1 Hub Network wire models.
JSON field names, strings, timestamps, and optional-field behavior match the
TypeScript definitions in `hub-pro/src/network/wire.ts`.

Files under `testdata/v1` are shared cross-language contract fixtures. Consumers
must decode them, re-encode them with the same field semantics, and reject
unsupported major versions. Timestamps remain RFC 3339 strings on the wire;
signatures and keys remain padded base64 strings.

