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
- `P2pDecodeError::HandlerPayloadTooLarge`, a payload over its handler's own length limit.
- Typed overlay messages: `clsig` (`ClSig`), `isdlock` (`IsdLock`), `qsigrec` (`RecoveredSig`), `qfcommit` (the
  final commitment, versions 1 to 4), `mnauth` (`MnAuth`), `spork` (`Spork`), `platformban` (`PlatformBan`, whose
  hash is Core's `GetHash()`, without the signature), `qgetdata` (`QuorumDataRequest`), `qdata` (`QData`),
  `getqrinfo` (`GetQrInfo`) and `qrinfo` (`QrInfo`, with `QuorumSnapshot` and `CycleInfo`). BLS keys and signatures
  are bytes, except a commitment's, which go through the BLS wire-form classifier as before.
- `MnListFormat`, the `mnlistdiff` layouts by protocol version (no version, version after the cbTx, versioned
  entries, version first, ChainLock signatures), with `MnListDiff::decode_as`; `qrinfo` and `mnlistdiff` decode in the
  layout of the context's version.
- `QData::read_data`, which reads the verification vector and the contributions against the quorum's threshold and
  valid member count, as Core's `UnserializeVectorWithMaxSize` does, failing with `TooManyEntries` before the entries;
  `QData::read_vvec` and `QData::read_contributions` read the two apart, as Core's handler does, with
  `VerificationVector`.
- Typed DKG messages: `qcontrib` (`DkgContribution`), `qcomplaint` (`DkgComplaint`), `qjustify`
  (`DkgJustification`, with `DkgRevealedShare`) and `qpcommit` (`DkgPrematureCommitment`), read whole as Core's DKG worker
  reads them, with Core's `GetSignHash()` as `sign_hash`. `DkgMessage::check_payload` runs Core's handler checks
  before the read: `MaxDKGMessageSize` (`HandlerPayloadTooLarge`) and the framing walk against the quorum's
  `LlmqParams` (`P2pDecodeError::DkgFraming`), and `DkgMessage::decode_checked` runs them then the read;
  `dkg_quorum` peeks the type and quorum the parameters come from. `P2pMsg::decode_with_policy` refuses a DKG payload
  over 1 MiB (`HandlerPayloadTooLarge`) before reading it, as Core's size cap does whatever the quorum once the
  handler's gates have passed.
- `DkgMessage::eager`, Core's eager read of a DKG message's BLS fields under the process-wide scheme (the message Core
  writes back and signs), and `dkg_inventory_hash`, Core's inventory hash of the payload as received. `DkgMessage`
  documents the order of Core's handler and worker: gates, checks, inventory hash, GETDATA-response gate, queue, read.
- Typed signature share messages: `qsigsesann` (`SigSesAnnMsg`), `qsigsinv` and `qgetsigs` (`SigSharesInvMsg`),
  `qbsigs` (`BatchedSigSharesMsg`) and `qsigshare` (`SigShareMsg`), each refusing more entries than Core's limits
  before reading them (`MAX_SIG_SES_ANNS`, `MAX_SIG_SHARES_INVS`, `MAX_SIG_SHARES`, and `MAX_BATCHED_SIGS` for the
  batches and their shares together). Session ids are Core's `VARINT`s, and a share inventory's bits its
  `AUTOBITSET`, written in Core's shorter form. `SigSesAnn::sign_hash` and `SigShare::sign_hash` are Core's
  `SignHash`.
- Typed CoinJoin messages: `dsa` (`DsAccept`, its flags read from `ProtocolVersion::COINJOIN_REBALANCE`, written for the
  connection's negotiated version by `DsAccept::for_version`), `dsi` (`DsEntry`, the collateral between its lists),
  `dsf` (`DsFinalTx`), `dss` (`DsSignedInputs`), `dsc` (`DsComplete`), `dssu` (`DsStatusUpdate`), `dstx` (`DsTx`) and
  `dsq` (`DsQueue`). `DsQueue`'s `ready` is a `bool` read as Core reads it, so its hash (`GetHash`) and
  `DsQueue::signature_hash` are of the queue as Core writes it back; `DsTx::signature_hash` signs the time and not the
  signature. `max_pool_entries` is Core's pool bound: `DsEntry::fits_pool` on a read `dsi`, and
  `DsSignedInputs::check_payload` on a `dss` count before the read (`TooManyEntries`, Core's `ERR_MAXIMUM`).
- `VOTE_ECDSA_SIG_LEN` and `VOTE_BLS_SIG_LEN`, Core's vote signature sizes.
- `FilterLoad::is_within_size_constraints`, Core's `CBloomFilter::IsWithinSizeConstraints()`.
- `MAX_SPORK_SIG_LEN` and `MAX_QRINFO_BASE_HASHES`, the read limits of `spork` and `getqrinfo`. Core checks them only
  when reading, so both encode any length.

### Changed

- `GovSync::bloom_filter` is a `FilterLoad`, Core's whole `CBloomFilter` (its data limited to 36,000 bytes, then the
  hash function count, tweak and flags); it was the data alone. Its serde form names fields in camelCase
  (`bloomFilter`).
- `govobjvote` is read as Core's network read: a signature of at most 96 bytes, then exactly 65 or 96, else
  `P2pDecodeError::InvalidValue`; any other length was read.
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
- A `qgetdata` over 67 bytes fails with `HandlerPayloadTooLarge`, as Core's handler refuses it before reading; Core
  disconnects and discourages the peer, where for `PayloadTooLarge` it disconnects without discouraging.
- `SimplifiedMnListEntry`'s hash is Core's `CalcHash()`, its leaf in `merkleRootMNList`: the entry without its
  version.
- `P2pDecodeError::Consensus` carries the `DecodeError` instead of its text.
- `GetBlockTxn`'s fields are private and deserialization checks their order; an index past 65,535 fails, as in Core.
- `SendCmpct::high_bandwidth` is a `bool` read as 0 or 1, the bytes Core writes; another byte, which Core reads as
  `true`, fails with `DecodeError::NonCanonicalBool`.
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
  as 0 or 1, the bytes Core writes; another byte, which Core reads as `true`, fails with
  `DecodeError::NonCanonicalBool`. Core serves a `getqrinfo` with such a byte.

### Removed

- `ProtocolVersion::CURRENT`; use `V24_0`, or a version the caller defines.

### Not provided

- A Core-style `CmpctBlock` constructor from a block (coinbase prefilled, random nonce, txid or instance hash by
  release); a caller builds it from `short_id_keys` and `short_id_with_keys`.
