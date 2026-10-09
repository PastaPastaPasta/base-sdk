# Changelog

All notable changes to `dash-p2p-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `limits`, Dash Core's P2P protocol limits, and `ProtocolVersion` constants for every `version.h` boundary, with
  `V23_1`, `V24_0` and `INIT`.
- V1 framing: `V1Header`, `encode_v1` and `checksum`, with Core's header checks (magic, then the 3 MiB length) and
  payload checks (checksum, then the command bytes) as `V1FrameError`, which says whether Core disconnects.
- `ShortId::for_send` and `ShortId::min_version`, Core's V2 send gate: short IDs from common version 70235, 70240 for
  `platformban`, the long form before the peer's `version`.
- Typed `block`, `tx`, `getblocks`, `sendtxrcncl`, `ssc`, BIP37 (`filterload`, `filteradd`, `merkleblock`), BIP152
  (`sendcmpct`, `cmpctblock`, `getblocktxn`, `blocktxn`, with `CmpctBlock::short_id`) and BIP157 messages.
- `P2pMsg::Unread` for the commands Core knows but has no handler for (`merkleblock`, `cfilter`, `cfheaders`,
  `cfcheckpt`); their typed variants are for sending.
- `InvType` names every type Core knows, with Core's `command`, `is_known`, `is_gen_tx`, `is_gen_blk` and
  `request_interval`; `AssetUnlockInv` selects whether type 34 is known (v24.0) or not (v23.1.8).
- `Headers2::reply` and `Headers2::announce`, Core's two `headers2` encoders, and `Headers2::decode_with_hasher`.
- `GetBlockTxn::new`, which refuses indexes that do not strictly increase, as Core's serializer does, with the
  `block_hash` and `indexes` accessors.
- `decode_v2_payload`, which decodes a V2 payload kept apart from its type under V2 rules (the contents limit after the
  shortest type that carries the command, 0x7f in a long-form type).
- `CommandString::EMPTY`, the all-zero type.

### Changed

- `headers2` decodes as Core's `Uncompress`: the first header restores no compressed field, a version offset past the
  list leaves version 0, and a previous block hash is computed only where Core computes it. `Headers2` keeps each
  header's wire form as a `CompressedHeader`, replacing `CompressionState`.
- The `headers2` encoders compress as Core's `Compress`: the previous block hash always, and a time delta only when
  the time does not step backwards.
- `encode_v2` takes the peer's common version.
- `filterclear`, `mempool` and `qwatch` are no longer stubs.
- `P2pDecodeError::Consensus` carries the `DecodeError` instead of its text.
- `GetBlockTxn`'s fields are private and deserialization checks their order; `getblocktxn` reads every declared index
  until one is missing or overflows, so a failure leaves the cursor where Core's does.
- A `cmpctblock` listing more than 65,535 transactions fails with `DecodeError::BadLen`.
- `ProtocolVersion::CURRENT` is deprecated in favour of `V23_1` and `V24_0`.

### Not provided

- A Core-style `CmpctBlock` constructor from a block (coinbase prefilled, random nonce, txid or instance hash by
  release); P3 builds it from `short_id_keys` and `short_id_with_keys`.
