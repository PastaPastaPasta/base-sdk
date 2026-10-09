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
- Typed `block`, `tx`, `getblocks`, `sendtxrcncl`, `ssc`, BIP37 (`filterload`, `filteradd`, `merkleblock`), BIP152
  (`sendcmpct`, `cmpctblock`, `getblocktxn`, `blocktxn`, with `CmpctBlock::short_id`) and BIP157 messages.
- `merkleblock`, `cfilter`, `cfheaders` and `cfcheckpt` decode to their typed variants. Core has no handler for them
  and ignores them; a node that follows Core ignores them before decoding.
- `InvType` names every type Core knows, with Core's `command`, `is_known`, `is_gen_tx`, `is_gen_blk` and
  `request_interval`; type 34, `MSG_ASSET_UNLOCK`, is known and carried in a `tx`, as at v24.0.
- `Headers2::reply` and `Headers2::announce`, Core's two `headers2` encoders, and `Headers2::decode_with_hasher`.
- `GetBlockTxn::new`, which refuses indexes that do not strictly increase, as Core's serializer does, with the
  `block_hash` and `indexes` accessors.
- `decode_v2_payload`, which decodes a V2 payload kept apart from its type under V2 rules (the contents limit after the
  shortest type that carries the command, 0x7f in a long-form type).
- `CommandString::EMPTY`, the all-zero type.
- Typed overlay messages: `clsig` (`ClSig`), `isdlock` (`IsdLock`), `qsigrec` (`RecoveredSig`), `qfcommit` (the
  final commitment, versions 1 to 4), `mnauth` (`MnAuth`), `spork` (`Spork`), `platformban` (`PlatformBan`, with
  `signed_hash`), `qgetdata` (`QuorumDataRequest`), `qdata` (`QData`), `getqrinfo` (`GetQrInfo`) and `qrinfo`
  (`QrInfo`, with `QuorumSnapshot` and `CycleInfo`). BLS keys and signatures are bytes, except a commitment's, which
  go through the BLS wire-form classifier as before.
- `MnListFormat`, the `mnlistdiff` layouts by protocol version (no version, version after the cbTx, versioned
  entries, version first, ChainLock signatures), with `MnListDiff::decode_as`; `qrinfo` and `mnlistdiff` decode in the
  layout of the context's version.
- `QData::read_data`, which reads the verification vector and the contributions against the quorum's threshold and
  valid member count, as Core's `UnserializeVectorWithMaxSize` does, failing with `TooManyEntries` before the entries.
- `MAX_SPORK_SIG_LEN` and `MAX_QRINFO_BASE_HASHES`, the read limits of `spork` and `getqrinfo`. Core checks them only
  when reading, so both encode any length.

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
- `filterclear`, `mempool` and `qwatch` are no longer stubs.
- A `qgetdata` over 67 bytes fails with `PayloadTooLarge`, as Core's handler refuses it before reading.
- `P2pDecodeError::Consensus` carries the `DecodeError` instead of its text.
- `GetBlockTxn`'s fields are private and deserialization checks their order; an index past 65,535 fails, as in Core.
- `SendCmpct::high_bandwidth` is a `bool` read as 0 or 1, the bytes Core writes; another byte, which Core reads as
  `true`, is an error.
- A `cmpctblock` listing more than 65,535 transactions fails with `DecodeError::BadLen`.
- A V2 short ID with no message, including the slots Core reserves (5, 29 to 32), fails with `UnknownShortId`: drop
  the message and keep the peer. Core types those slots as the empty command and ignores them.
- `spork`, `qfcommit`, `qsigrec`, `qgetdata`, `qdata`, `clsig`, `isdlock`, `mnauth`, `getqrinfo`, `qrinfo` and
  `platformban` are no longer stubs. `P2pMsg::QfCommit` and `P2pMsg::QrInfo` box their message.
- `MnListDiff` holds its fields directly, replacing `MnListDiffPayload`, and records its `format`: the cbTx's
  `PartialMerkleTree`, the cbTx, and `quorum_cl_sigs` in wire order. Core reads the ChainLock signatures into a map
  keyed by the signature, keeping the first of equal keys; a caller that needs that map builds it.
- `QuorumClSig::index_set` is a `BTreeSet<u16>`: Core reads the indexes into a set, dropping repeats.
- `SimplifiedMnListEntry` carries its `version` and the entry's `NetInfo` (the address list from version 3, as
  `protx` payloads read it), replacing `service`; `decode_as` and `encode_as` read and write it with or without the
  version.
- `SimplifiedMnListEntry::is_valid` and `GetQrInfo::extra_share`, like the `qrinfo` extra share flag, are a `bool` read
  as 0 or 1, the bytes Core writes; another byte, which Core reads as `true`, is an error.

### Removed

- `ProtocolVersion::CURRENT`; use `V24_0`, or a version the caller defines.

### Not provided

- A Core-style `CmpctBlock` constructor from a block (coinbase prefilled, random nonce, txid or instance hash by
  release); a caller builds it from `short_id_keys` and `short_id_with_keys`.
