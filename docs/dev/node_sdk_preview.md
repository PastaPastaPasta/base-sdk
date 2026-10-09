# Node SDK preview

This branch is a preview, not a pull request. It collects the base-sdk changes we made while building a Dash full node
in Rust, so that you can diff them against your own v24 alignment work in one place. It is based on `develop` at
`33fcc59`. Nothing here is meant to be merged as is: the plan is to send small, reshaped pull requests (section 5),
paced after your v24 series lands.

The branch has five area commits and this document:

| Commit | Area |
|---|---|
| `1068cfa` | `dash-types`: `CoreBool`, `DecodeError::MalleableBls`, Core's length-prefix and allocation rules |
| `c9cf17d` | `dash-pkc`: BLS fields decoded as Dash Core's BLS wrappers read them, with Core-judged vectors |
| `140425b` | `dash-primitives`: v24 special payloads and Core's decode domain, with Core-judged vectors |
| `961841b` | `dash-params`: chain params built per network and release, checked against Core's own values |
| `96992b8` | `dash-p2p-core`: framing, typed messages and headers2 as Core's handlers read them |

Each commit builds and passes the workspace tests, clippy (`-D warnings`, minimal and full features) and the repository
lints. A few hunks and tests from our fork are withheld from this branch; they follow later.

## 1. What is on the branch

Throughout, "Core" means Dash Core v24.0.0-rc.3, with v23.1.8 checked wherever the two differ.

### 1.1 `dash-types` (`1068cfa`)

- `CoreBool`: a wire boolean that reads any non-zero byte as `true`, as Core's `bool` deserializer does, and writes
  `0x00` or `0x01`. The old 0/1-only `bool` codec is removed in the p2p commit, where the last user switches over.
- `CompactSize::decode_size`, and length prefixes of vectors, strings and scripts range-checked against `MAX_SER_SIZE`
  even when enough bytes remain, as Core's `ReadCompactSize` does.
- `Vec<T>` reserves each allocation batch exactly, as Core's `reserve(allocated)` does, instead of growing past it.
- `DecodeError::MalleableBls`, Core's "malleable BLS object".
- `serialize::opt_str_u64`.

Why: every one of these is a place where a strict decoder gave a different verdict from Core on bytes a peer can send.

### 1.2 `dash-pkc` BLS (`c9cf17d`)

- `BlsSchemeKind`, `BlsCtx` and `BlsSchemeSource` select the legacy or basic scheme at run time. Core picks the scheme
  per field: from the payload version, always basic, or from its process-wide flag.
- `BlsEager`, `BlsLazy` and `BlsGlobal` model Core's `CBLSWrapper`, `CBLSLazyWrapper` and the flag-scheme fields. An
  eager read gives a valid object, the invalid object (serialized as zeros) or Core's malleability error. The legacy
  scheme's decode rule follows Core's.
- `contrib/vectors/bls_wrapper/`: a seeded input generator and a small C++ program linked against Core's own BLS code.
  `pkgs/pkc/corpus/bls_wrapper.json5` records Core's outcome for every input class at both releases.

Why: payload BLS fields decide transaction and block verdicts, and Core's rules for them are not the IETF rules.

### 1.3 `dash-primitives` (`140425b`)

- v24 payloads: CbTx v4 with `merkleRootAssetUnlocks`, AssetLock and AssetUnlock v2, the ProRegTx and ProUpRegTx v3
  payout and share lists, and the new types 10 to 12 (`ProDisTx`, `ProUpShareTx`, `ProUpSharedRegTx`).
- BLS fields typed with the scheme source Core uses for each, and written back under Core's write-time scheme.
- NetInfo read as Core reads it: one group per purpose (the first wins), unknown or invalid entries kept as `Invalid`,
  the 253-byte domain cap, and an empty NetInfo reported as Core reports it.
- `TxOut` value decoded as Core's signed `CAmount`; special payloads bounded by `MAX_SER_SIZE`; the serialized size
  checked before the payload size, as in Core's `CheckTransaction`; `decode_payload` reports how much it read.
- LLMQ types 103 and 105 named (all 14 Core knows), and `dash-params` reuses `LlmqType`.
- `contrib/vectors/payloads/` and two corpora: `payload_core.json5` (crafted payloads judged by
  `decoderawtransaction` on both releases, under both BLS flags) and `v24.json5` (special transactions from regtest
  chains built by Core's functional tests and two testnet blocks, with Core's JSON for each).

Why: section 2.1. Without these, `develop` cannot decode or check a post-v24 block.

### 1.4 `dash-params` (`961841b`)

- Chain params built per network kind (main, test, regtest, devnet) and release, including Core's command-line
  overrides (`-testactivationheight`, `-vbparams`, LLMQ overrides, devnet options, spork addresses).
- v24 data: deployments, checkpoints, chain work, assumevalid, LLMQ tables, devnet genesis, the BRR payment table.
- `pkgs/params/corpus/` holds Core's own values for 178 cases per release, produced by Core and not written by hand.

Why: the node needs the exact params Core selects, including regtest and devnet setups used by Core's functional tests.

### 1.5 `dash-p2p-core` (`96992b8`)

- Core's protocol versions and message limits; V1 framing with Core's header and payload checks; the V2 short-ID send
  gate; every inventory type Core knows.
- Typed `block`, `tx`, `getblocks`, `sendtxrcncl`, `ssc`, BIP37, BIP152 (with v24 short-ID keys) and BIP157 messages.
- headers2 decoded and encoded as Core's `Compress` does, with each header's wire form kept.
- `senddsq` and `qsendrecsigs` carry their flag; `version`'s optional fields read as Core reads them; header counts
  bounded by the payload; every command bounded by 3 MiB.
- Corpora of messages two Core nodes sent each other, Core's replies to a raw peer, and Core's verdict on each crafted
  payload (kept, disconnected, or the exception it logged).

Why: section 2.2, and the node needs every message a Core peer sends.

## 2. Conformance findings

We decoded the first ~650,000 blocks of mainnet and of testnet (testnet's range includes DIP3 special transactions),
and the regtest chains Core's own v24 functional tests build, with `develop` and with Core side by side. Every block
checked before v24 agreed. Every failure was on a v24 format.

### 2.1 Six v24 gaps in `develop`

1. **CbTx v4 is not supported.** `decode_payload()` fails with "trailing bytes: 32 remaining", and
   `CoinbaseCommitment::check()` rejects version 4. Fixed in `140425b`.
2. **Types 10, 11 and 12 have no decoder.** They decode as `SpecialPayload::Unknown` and `Transaction::check()` reports
   `bad-txns-type`. Fixed in `140425b`.
3. **Every ProRegTx v3 fails to decode**, including a plain ExtAddr registration with one payout and no shares.
   `develop` models v3 as v2 plus ExtAddr NetInfo, the layout before the payout and share lists. Fixed in `140425b`.
4. **ProUpRegTx v3 fails to decode** (payout lists). Fixed in `140425b`.
5. **The AssetUnlock v2 stable-txid rule is missing**, so `Transaction::hash()` is wrong for v2 unlocks,
   `Block::merkle()` does not match the header, and `Block::check()` rejects the valid block with `bad-merkle-root`.
   Not on this branch; in progress (section 8).
6. **`Block::check()` rejects every valid post-v24 block**: at the coinbase (gap 1) or earlier (gap 5). Gap 1 is fixed
   here; the rest follows with gap 5.

Repro: the transactions are in `pkgs/primitives/corpus/v24.json5`, each with its source chain and height. Decode any of
them on `develop` with `Transaction::decode` and `decode_payload`. To rebuild the chains, run Core v24.0.0-rc.3's
`feature_asset_locks.py`, `feature_masternode_payout_shares.py`, `feature_masternode_shares.py` and
`feature_protx_version.py` with `--nocleanup` and save `getblock <hash> 2` for each block;
`contrib/vectors/payloads/gen.py v24` turns those into the corpus.

### 2.2 Four strict-decoder bugs on honest traffic

These reject messages that honest Core peers or wallets send. None of them is a leniency: each is a wrong message
definition, and each fix stays strict.

1. **`senddsq` and `qsendrecsigs` carry one flag byte.** `develop` expects an empty payload, so it rejects the message
   from every Core peer. Repro: `senddsq 01` and `qsendrecsigs 01` in `pkgs/p2p_core/corpus/decode_domain.json5`
   ("captured" is exactly what each release sent).
2. **The `version` tail.** Core reads the optional trailing fields one by one and accepts a message that stops between
   them. SPV wallets send such a message (`cut_104_through_relay` in the same corpus is exactly that shape), and
   `develop` rejects all six cuts Core accepts.
3. **The headers2 cap.** `develop` caps `headers2` at 2000 headers; Core sends up to 8000 when the common version is at
   least 70235. Repro: `pkgs/p2p_core/corpus/core_headers2.json5`.
4. **The `govsync` tail.** Core's own `govsync` carries a bloom filter after the hash (42 bytes in total), which
   `develop` rejects as trailing bytes. The branch tolerates the tail in its handler-level decoder; the real fix is a
   complete `GovSync` message, which is planned.

## 3. How we triaged our own changes

Our fork accepts some bytes Core accepts and a strict design would reject. We sorted every such change into one of
three classes:

- **(a) consensus-required:** a strict decoder would change a block or transaction verdict, hash or stored form. Keep
  it, as a named Core-compatibility rule, ideally outside the generic decoders.
- **(i) interoperability-required:** needed to exchange messages with honest peers, with no direct consensus effect.
  Keep it as the strict, correct definition of the message (section 2.2).
- **(c) unnecessary:** only error classes, reject reasons or fingerprints differ, and only on crafted input. Remove it
  from base-sdk; where our node needs Core's exact behaviour, the node does it itself.

Changes with no leniency (strictness fixes, Core-exact limits, v24 data, new types) get no class. Where Core's behaviour
looks like a bug, it gets a flag (section 7).

## 4. Per area: what stays, what goes, what moves to the node

The (c) items are still on this branch, as they are on our fork. They are listed here so you can skip them.

**`dash-types`.** Stays: the `MAX_SER_SIZE` checks and exact reservation. Goes: `CoreBool` reads; upstream keeps a
strict 0/1 `bool`, and `senddsq`, `qsendrecsigs` and `sendcmpct` use it. `MalleableBls` gives way to the BLS
classifier's error if that proposal goes ahead (section 6).

**`dash-pkc`.** Stays: run-time scheme naming. Moves to the node: `BlsEager`, `BlsLazy`, `BlsGlobal`, `BlsCtx` and
`BlsSchemeSource`. Goes: lazy decoding, the flag-scheme deferral and `BlsValue::from_set_bytes_basic`, and the CodeQL
`Eq`/`Hash` exemptions for lazy fields. What we would like upstream is one classifier (section 6).

**`dash-primitives`.** Stays: the v24 payloads, LLMQ type names, the size checks and the domain cap. Upstream, payload
BLS fields stay byte bags, with methods saying which scheme each field's bytes are in. Goes: `TxOut`'s unchecked
signed value (the node maps out-of-range values itself), the raised payload bound, `PayloadDecode` unless you like it,
the special-payload reject-reason mapping, and ExtNetInfo reading nothing more after a version Core does not know.
Needs your view: the Core-view NetInfo reader (section 6).

**`dash-params`.** Stays, reshaped: v24 data, new chain-param members, LLMQ tables, devnet with a derived genesis, typed
regtest and devnet overrides (stricter than Core where Core does not range-check), the BRR table. Goes: the release
axis and the v23 data. Moves to the node: Core's command-line occurrence model, its integer-parsing replicas, Core's
error texts, spork-address resolution and the hard-coded network pins.

**`dash-p2p-core`.** Stays: limits and versions, V1 framing, the V2 send gate, inventory names, headers2 encoders and
the strict wire image, the message definitions of section 2.2, `P2pDecodeError` carrying the `DecodeError`. Goes: the
short `pong`, empty-payload and trailing-byte tolerances, `headers` with a non-zero transaction count, header counts
read past the data, and `V23_1`/`V24_0`/`CURRENT`. Moves to the node: `ProtoCtx`, `decode_with_policy`, the version
head-first checks, handler count limits, `disconnects()`, `request_interval()` and Core's headers2 reconstruction with
its penalties.

## 5. Proposed pull-request series

Units are rebuilt on `develop` in your shapes; the fork commits are a source, not history. Sizes are estimates for the
rebuilt unit. "After" means the unit is cut from that unit's branch.

**Tier 1: no leniency.**

| Branch | Title | After | Size | Status |
|---|---|---|---|---|
| `codec_size` | `types%fix`: range-check length prefixes, reserve vector batches exactly | | ~+90/−5 | open, #57 |
| `llmq_types` | `primitives%feat!`: name LLMQ types 103 and 105, reuse `LlmqType` in `dash-params` | | ~+55/−35 | open, #58 |
| `p2p_frame` | `p2p_core%fix!`: signed `ProtocolVersion`, command and V2 bounds, command validity | | ~+300/−60 | open, #59 |
| `tx_check` | `primitives%fix`: size before payload size; lengths through `decode_size` | `codec_size` | ~+150/−40 | built, held |
| `p2p_ctrl` | `p2p_core%fix!`: `senddsq`/`qsendrecsigs` flags; `ssc`, `sendtxrcncl`, `getblocks` | `p2p_frame` | ~+150/−20 | built, held |
| `hdr_limits` | `p2p_core%fix!`: header counts bounded by the payload; Core's header limits | `p2p_frame` | ~+120/−40 | planned |
| `params_v24` | `params%feat!`: v24 chain params | | ~+450/−250 + fixture | planned |
| `llmq_params` | `params%feat`: LLMQ parameters and per-network quorum sets | `llmq_types`, `params_v24` | ~+350 | planned |
| `params_devnet` | `params%feat!`: devnet with a derived genesis, static path kept | `llmq_params` | ~+300/−100 | planned |
| `params_ovr` | `params%feat`: typed regtest and devnet overrides | `params_devnet` | ~+450/−50 | planned |
| `v24_cbtx_assetlock` | `primitives%feat!`: CbTx v4, AssetLock and AssetUnlock v2 | `llmq_types`, `tx_check` | ~+300/−60 | planned |
| `cql_share` | `sdk%lint(codeql)`: payout-share types and the secret-name rule | | tiny | needs your call |
| `v24_protx` | `primitives%feat!`: types 10 to 12, v3 payout and share lists | `v24_cbtx_assetlock`, `cql_share` | ~+800/−120 | planned |
| `netinfo_strict` | `primitives%fix`: 253-byte domains, empty NetInfo as Core reports it | `tx_check` | ~+100/−60 | planned |
| `p2p_limits` | `p2p_core%feat`: Core's protocol versions and message limits | `p2p_frame` | ~+110 | planned |
| `p2p_v1` | `p2p_core%feat`: V1 framing with Core's checks | `p2p_limits` | ~+200 | planned |
| `p2p_v2` | `p2p_core%refac!`: V2 typing apart from payloads; short-ID send gate | `p2p_limits` | ~+400/−100 | planned |
| `p2p_inv` | `p2p_core%feat`: every inventory type Core knows | `p2p_limits` | ~+90 | planned |
| `headers2` | `p2p_core%fix!`: headers2 as Core encodes it, strict decode, one hash per header | `hdr_limits`, `p2p_limits` | ~+470/−260 | planned |

**Tier 2: a strict reshape of an interoperability rule.**

| Branch | Title | After | Size | Status |
|---|---|---|---|---|
| `version_tail` | `p2p_core%fix!`: `version`'s optional fields as one nested tail | `p2p_frame`, `codec_size` | ~+250/−60 | planned |
| `p2p_unknown` | `p2p_core%feat!`: unknown commands as `P2pMsg::Unknown` (optional) | `p2p_frame` | ~+60/−30 | planned |

**Tier 3: needs your answer or an issue first.**

| Branch | Title | After | Size | Status |
|---|---|---|---|---|
| `p2p_bip37` | `p2p_core%feat`: BIP37 messages | `p2p_limits` | ~+130 | ask first (#40) |
| `p2p_bip152` | `p2p_core%feat!`: BIP152 messages, v24 short-ID keys | `codec_size`, `p2p_limits` | ~+420 | ask first (#40) |
| `p2p_bip157` | `p2p_core%feat`: BIP157 messages both ways | `p2p_limits` | ~+125 | ask first (#40) |
| `p2p_blocktx` | `p2p_core%feat`: `block` and `tx` messages | `p2p_limits` | ~+60 | ask first (#40) |
| `bls_wire` | `pkc%feat(bls)`: run-time schemes, a Core wire-form classifier | `v24_protx` | ~+400/−20 | issue first |
| `netinfo_core` | `primitives%fix!`: NetInfo read as Core reads it, wire form kept | `netinfo_strict` | ~+300/−100 | issue first |
| `govsync` | `p2p_core%fix`: `govsync`'s whole bloom filter | `p2p_frame` | small | not started |
| `params_brr` | `params%feat`: the BRR payment table | `params_v24` | ~+80 | planned |

If you prefer fewer, larger pull requests, `codec_size` + `tx_check`, the p2p framing units, and `params_v24` +
`llmq_params` merge naturally. We will not open more until your v24 series lands, and #57 to #59 stay open for review.

## 6. Two proposals we would rather discuss in an issue first

**A BLS wire-form classifier in `dash-pkc`.** Core reads BLS bytes by rules that differ from the IETF codec: the legacy
scheme's decode rule follows Core's, bytes canonical only in the other scheme become an invalid object, and bytes
canonical in neither are a decode error. We propose one explicitly named, pure function in `dash-pkc` that classifies
wire bytes as Core reads them (null, canonical point, other scheme only, or canonical in neither), with one error type,
reusing the existing codec, and documented as Core compatibility. Payload types keep byte-bag fields, and callers that
need Core's view apply the classifier. It belongs in `dash-pkc` because the `blst` code lives there. It is needed for
Core compatibility: Core's decoder accepts legacy-scheme bytes that a strict codec rejects.

**NetInfo decoding with a Core view.** Core reads NetInfo lossily: the first group per purpose wins, unknown or invalid
entries become invalid markers, a failed service read is caught and parsing resumes, and an invalid legacy address
becomes empty. A strict decoder therefore fails to decode some ProTx transactions Core accepts in blocks, so an SPV
client or wallet on base-sdk cannot parse every valid v24 block. We propose that the ProTx decoders read NetInfo as Core
does and keep both the wire form and the Core view (for example `core_groups()` and `core_effective()`), with `check()`
reporting what Core's `Validate` would. If you prefer not to, we keep it as a documented fork patch.

## 7. Core-bug candidates

These are minor validation and robustness quirks we found in Core while matching it. We plan to report the first two.

- **Non-canonical `ExtNetInfo` map.** Core reads the purpose map with the first entry per key winning and checks neither
  count nor order; the sign string hashes the re-serialized map. Dropped or reordered bytes are covered by the
  creator's input signatures but not by the operator or owner signature. Low; worth fixing before v24 activates.
- **Second null BLS encoding.** Opposite-scheme bytes become an invalid object, which counts as null in a final
  commitment and in the CbTx ChainLock signature: arbitrary non-zero bytes act as null. Low.
- **Caught service reads.** A failed service read inside `ExtNetInfo` is swallowed and parsing resumes mid-field, so the
  wire bytes and Core's re-serialization disagree. Low.
- **Invalid legacy address.** A non-zero but invalid legacy address becomes an empty NetInfo, which ProRegTx accepts,
  silently. Low.
- **headers2 uncompress.** A version offset past the list leaves version 0, and a first header with omitted fields
  leaves them zero. Honest `Compress` never produces either. Low.
- **Local configuration only:** `-nodevnet` selects devnet "devnet-0"; `-nosporkaddr` fails instead of meaning the
  default; integer arguments are narrowed to `int` silently; negative `-dip3params`, `-budgetparams` and `-vbparams`
  heights are accepted; the devnet subsidy factor, LLMQ size/threshold overrides and `-powtargetspacing` are not
  range-checked (the last one can divide by zero in difficulty code).

## 8. Work in flight on our fork

- Special-payload signature hashes, and the AssetUnlock v2 stable txid (gap 5 in section 2.1).
- Overlay wire types: ChainLocks, InstantSend, recovered signatures, final commitments, quorum snapshots, QRInfo,
  simplified masternode list entries and diffs, MNAUTH, sporks, platform bans and `qgetdata`/`qdata`.
- Later: the remaining LLMQ messages and signature shares, and CoinJoin and governance messages (including the full
  `govsync`).
- Outside base-sdk, in our node: X11 block hashing and a network-type mapping.

## 9. Questions for you

1. Which v24 pieces are you doing yourself, and which would you like from us? Section 2.1 lists what `develop` needs.
2. Do you want the BLS classifier (section 6) in `dash-pkc`, and is a scheme-neutral byte bag acceptable for
   version-dependent BLS fields? `BlsPkBytes<BlsScIetf>` mislabels a version-1 key.
3. NetInfo with a Core view (section 6): yes, no, or something else?
4. BIP37, BIP152 and BIP157 (and `block`/`tx`): should we type them, or wait for `bitcoin-p2p-messages` (#40)?
5. The payout-share types and the CodeQL secret-name rule: rename, or amend the rule? It is your policy.
6. Fixtures: generate them from v24.0.0-rc.3 now and regenerate at the final tag, or wait?
7. Pull-request size: the small units of section 5, or the merged groups?
8. `MIN_MASTERNODE_PROTO_VERSION` (70242) upstream, and drop `ProtocolVersion::CURRENT` rather than move it?
