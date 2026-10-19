//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P message types and dispatch.

mod addr;
mod gov;
mod headers;
mod headers2;
mod inv;
mod mn_list;
mod ping;
mod version;

use crate::command::CommandString;
use crate::prelude::*;
use crate::short_id::ShortId;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::{GovObject, GovVote};
use dash_types::type_id::Unencodable;

pub use addr::{Addr, AddrV2Entry, AddrV2Msg, TimestampedAddr};
pub use gov::GovSync;
pub use headers::{GetHeaders, Headers};
pub use headers2::{CompressionState, GetHeaders2, Headers2};
pub use inv::{GetData, Inv, InvType, Inventory, NotFound};
pub use mn_list::{DeletedQuorum, GetMnListDiff, MnListDiff, MnListDiffPayload, QuorumClSig, SimplifiedMnListEntry};
pub use ping::{Ping, Pong};
pub use version::{ServiceFlags, UserAgent, UserAgentTooLong, Version, VersionAddr};

define_p2p! {
  parsed {
    /// Protocol version exchange.
    Version(Version) => VERSION "version",
    /// Keepalive request.
    Ping(Ping) => PING "ping" @ 18,
    /// Keepalive response.
    Pong(Pong) => PONG "pong" @ 19,
    /// V1 address list.
    Addr(Addr) => ADDR "addr" @ 1,
    /// BIP155 V2 address list.
    AddrV2(AddrV2Msg) => ADDRV2 "addrv2" @ 28,
    /// Inventory announcement.
    Inv(Inv) => INV "inv" @ 14,
    /// Request specific inventory.
    GetData(GetData) => GETDATA "getdata" @ 11,
    /// Inventory not found.
    NotFound(NotFound) => NOTFOUND "notfound" @ 17,
    /// Request block headers.
    GetHeaders(GetHeaders) => GETHEADERS "getheaders" @ 12,
    /// Block headers.
    Headers(Headers) => HEADERS "headers" @ 13,
    /// Request compressed block headers.
    GetHeaders2(GetHeaders2) => GETHEADERS2 "getheaders2" @ 163,
    /// Compressed block headers.
    Headers2(Headers2) => HEADERS2 "headers2" @ 165,
    /// Governance sync request.
    GovSync(GovSync) => GOVSYNC "govsync" @ 140,
    /// Governance object.
    GovObj(GovObject) => GOVOBJ "govobj" @ 141,
    /// Governance vote.
    GovObjVote(GovVote) => GOVOBJVOTE "govobjvote" @ 142,
    /// Request MN list diff.
    GetMnListDiff(GetMnListDiff) => GETMNLISTD "getmnlistd" @ 143,
    /// MN list diff.
    MnListDiff(MnListDiff) => MNLISTDIFF "mnlistdiff" @ 144,
  }

  parsed_empty {
    /// Version acknowledgement.
    Verack => VERACK "verack",
    /// Request peer addresses.
    GetAddr => GETADDR "getaddr",
    /// Signal addrv2 support.
    SendAddrV2 => SENDADDRV2 "sendaddrv2",
    /// Prefer unsolicited header announcements.
    SendHeaders => SENDHEADERS "sendheaders",
    /// Prefer compressed header announcements.
    SendHeaders2 => SENDHEADERS2 "sendheaders2" @ 164,
  }

  stub {
    /// Block data.
    Block => BLOCK "block" @ 2,
    /// BIP152: compact block transactions.
    BlockTxn => BLOCKTXN "blocktxn" @ 3,
    /// BIP152: compact block.
    CmpctBlock => CMPCTBLOCK "cmpctblock" @ 4,
    /// BIP37: add data to bloom filter.
    FilterAdd => FILTERADD "filteradd" @ 6,
    /// BIP37: load bloom filter.
    FilterLoad => FILTERLOAD "filterload" @ 8,
    /// Request block hashes.
    GetBlocks => GETBLOCKS "getblocks" @ 9,
    /// BIP152: request compact block transactions.
    GetBlockTxn => GETBLOCKTXN "getblocktxn" @ 10,
    /// BIP37: filtered block.
    MerkleBlock => MERKLEBLOCK "merkleblock" @ 16,
    /// BIP152: signal compact block support.
    SendCmpct => SENDCMPCT "sendcmpct" @ 20,
    /// Transaction.
    Tx => TX "tx" @ 21,
    /// Request compact filters.
    GetCFilters => GETCFILTERS "getcfilters" @ 22,
    /// Compact block filter.
    CFilter => CFILTER "cfilter" @ 23,
    /// Request compact filter headers.
    GetCFHeaders => GETCFHEADERS "getcfheaders" @ 24,
    /// Compact filter headers.
    CFHeaders => CFHEADERS "cfheaders" @ 25,
    /// Request compact filter checkpoints.
    GetCFCheckpt => GETCFCHECKPT "getcfcheckpt" @ 26,
    /// Compact filter checkpoints.
    CFCheckpt => CFCHECKPT "cfcheckpt" @ 27,
    /// BIP330: transaction reconciliation.
    SendTxRcncl => SENDTXRCNCL "sendtxrcncl",
    /// Spork broadcast/request.
    Spork => SPORK "spork" @ 128,
    /// CoinJoin: accept denomination.
    Dsa => DSA "dsa" @ 131,
    /// CoinJoin: submit inputs.
    Dsi => DSI "dsi" @ 132,
    /// CoinJoin: final transaction.
    Dsf => DSF "dsf" @ 133,
    /// CoinJoin: sign final transaction.
    Dss => DSS "dss" @ 134,
    /// CoinJoin: complete.
    Dsc => DSC "dsc" @ 135,
    /// CoinJoin: status update.
    Dssu => DSSU "dssu" @ 136,
    /// CoinJoin: broadcast transaction.
    Dstx => DSTX "dstx" @ 137,
    /// CoinJoin: queue entry.
    Dsq => DSQ "dsq" @ 138,
    /// Sync status count.
    Ssc => SSC "ssc" @ 139,
    /// LLMQ: final commitment.
    QfCommit => QFCOMMIT "qfcommit" @ 146,
    /// LLMQ: contribution.
    QContrib => QCONTRIB "qcontrib" @ 147,
    /// LLMQ: complaint.
    QComplaint => QCOMPLAINT "qcomplaint" @ 148,
    /// LLMQ: justification.
    QJustify => QJUSTIFY "qjustify" @ 149,
    /// LLMQ: premature commitment.
    QpCommit => QPCOMMIT "qpcommit" @ 150,
    /// LLMQ: signing session announcement.
    QSigSesAnn => QSIGSESANN "qsigsesann" @ 152,
    /// LLMQ: signature shares inventory.
    QSigsInv => QSIGSINV "qsigsinv" @ 153,
    /// LLMQ: request signature shares.
    QGetSigs => QGETSIGS "qgetsigs" @ 154,
    /// LLMQ: batched signature shares.
    QbSigs => QBSIGS "qbsigs" @ 155,
    /// LLMQ: recovered signature.
    QSigRec => QSIGREC "qsigrec" @ 156,
    /// LLMQ: single signature share.
    QSigShare => QSIGSHARE "qsigshare" @ 157,
    /// LLMQ: request quorum data.
    QGetData => QGETDATA "qgetdata" @ 158,
    /// LLMQ: quorum data.
    QData => QDATA "qdata" @ 159,
    /// ChainLock signature.
    ClSig => CLSIG "clsig" @ 160,
    /// InstantSend deterministic lock.
    IsdLock => ISDLOCK "isdlock" @ 161,
    /// Masternode authentication.
    MnAuth => MNAUTH "mnauth" @ 162,
    /// Request quorum rotation info.
    GetQrInfo => GETQRINFO "getqrinfo" @ 166,
    /// Quorum rotation info.
    QrInfo => QRINFO "qrinfo" @ 167,
    /// DIP-0031: platform ban.
    PlatformBan => PLATFORMBAN "platformban" @ 168,
  }

  stub_empty {
    /// BIP37: clear bloom filter.
    FilterClear => FILTERCLEAR "filterclear" @ 7,
    /// Request mempool contents.
    Mempool => MEMPOOL "mempool" @ 15,
    /// Request active sporks.
    GetSporks => GETSPORKS "getsporks" @ 129,
    /// Signal CoinJoin queue relay.
    SendDsq => SENDDSQ "senddsq" @ 130,
    /// LLMQ: send recovered signatures.
    QSendRecSigs => QSENDRECSIGS "qsendrecsigs" @ 145,
    /// LLMQ: watch quorums.
    QWatch => QWATCH "qwatch" @ 151,
  }
}
