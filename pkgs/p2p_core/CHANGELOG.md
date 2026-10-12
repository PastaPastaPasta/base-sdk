# Changelog

All notable changes to `dash-p2p-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `limits`, Dash Core's P2P protocol limits, and `ProtocolVersion` constants for every `version.h` boundary, with
  `V23_1`, `V24_0`, `INIT` and `MIN_MASTERNODE` (`MIN_MASTERNODE_PROTO_VERSION`).
- V1 framing: `V1Header`, `encode_v1` and `checksum`, with Core's header checks (magic, then the 3 MiB length) and
  payload checks (checksum, then the command bytes) as `V1FrameError`, which says whether Core disconnects.
- `ShortId::for_send` and `ShortId::min_version`, Core's V2 send gate: short IDs from common version 70235, 70240 for
  `platformban`, the long form before the peer's `version`.
- `Headers2::reply` and `Headers2::announce`, Core's two `headers2` encoders, and `Headers2::decode_with_hasher`.
- `decode_v2_payload`, which decodes a V2 payload kept apart from its type under V2 rules (the contents limit after the
  shortest type that carries the command, 0x7f in a long-form type).
- `CommandString::EMPTY`, the all-zero type.

### Changed

- `headers2` decodes the headers Core's `Compress` builds, restoring their fields as Core's `Uncompress` does, and
  computes a previous block hash only where Core computes it. A first header with a field left off, or a version
  offset past the list, fails with `DecodeError::InvalidValue`, where Core's `Uncompress` leaves the fields zero.
  `Headers2` keeps each header's wire form as a `CompressedHeader`, replacing `CompressionState`; a caller that needs
  Core's reconstruction parses each `CompressedHeader` and restores the fields itself. The fields of both are private,
  read through accessors (`Headers2::headers`, `CompressedHeader::flags`, `header` and `time_offset`), so a header's
  restored fields always agree with what it encodes; deserializing a `Headers2` checks it.
- The `headers2` encoders compress as Core's `Compress`: the previous block hash always, and a time delta only when
  the time does not step backwards.
- `encode_v2` takes the peer's common version.
- `P2pDecodeError::Consensus` carries the `DecodeError` instead of its text.
- A V2 short ID with no message, including the slots Core reserves (5, 29 to 32), fails with `UnknownShortId`: drop
  the message and keep the peer. Core types those slots as the empty command and ignores them.

### Removed

- `ProtocolVersion::CURRENT`; use `V24_0`, or a version the caller defines.
