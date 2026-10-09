//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P message types and dispatch.

mod addr;
mod bloom;
mod cfilter;
mod compact;
mod control;
mod gov;
mod headers;
mod headers2;
mod inv;
mod mn_list;
mod ping;
mod version;

use crate::codec::MsgDecode;
use crate::command::CommandString;
use crate::prelude::*;
use crate::short_id::ShortId;

use dash_primitives::{Block, GovObject, GovVote, Transaction};
use dash_types::type_id::Unencodable;

pub use addr::{Addr, AddrV2Entry, AddrV2Msg, TimestampedAddr};
pub use bloom::{FilterAdd, FilterLoad, MerkleBlock, PartialMerkleTree};
pub use cfilter::{CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters};
pub use compact::{short_id_with_keys, BlockTxn, CmpctBlock, GetBlockTxn, PrefilledTx, SendCmpct, ShortTxId};
pub use control::{QSendRecSigs, SendDsq, SendTxRcncl, Ssc};
pub use gov::GovSync;
pub use headers::{GetBlocks, GetHeaders, Headers};
pub use headers2::{CompressedHeader, GetHeaders2, Headers2};
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
    /// Signal CoinJoin queue relay.
    SendDsq(SendDsq) => SENDDSQ "senddsq" @ 130,
    /// LLMQ: send recovered signatures.
    QSendRecSigs(QSendRecSigs) => QSENDRECSIGS "qsendrecsigs" @ 145,
    /// Block data.
    Block(Block) => BLOCK "block" @ 2,
    /// Transaction.
    Tx(Transaction) => TX "tx" @ 21,
    /// Request block hashes.
    GetBlocks(GetBlocks) => GETBLOCKS "getblocks" @ 9,
    /// BIP37: load bloom filter.
    FilterLoad(FilterLoad) => FILTERLOAD "filterload" @ 8,
    /// BIP37: add data to bloom filter.
    FilterAdd(FilterAdd) => FILTERADD "filteradd" @ 6,
    /// BIP152: signal compact block support.
    SendCmpct(SendCmpct) => SENDCMPCT "sendcmpct" @ 20,
    /// BIP152: compact block.
    CmpctBlock(CmpctBlock) => CMPCTBLOCK "cmpctblock" @ 4,
    /// BIP152: request compact block transactions.
    GetBlockTxn(GetBlockTxn) => GETBLOCKTXN "getblocktxn" @ 10,
    /// BIP152: compact block transactions.
    BlockTxn(BlockTxn) => BLOCKTXN "blocktxn" @ 3,
    /// BIP157: request compact filters.
    GetCFilters(GetCFilters) => GETCFILTERS "getcfilters" @ 22,
    /// BIP157: request compact filter headers.
    GetCFHeaders(GetCFHeaders) => GETCFHEADERS "getcfheaders" @ 24,
    /// BIP157: request compact filter checkpoints.
    GetCFCheckpt(GetCFCheckpt) => GETCFCHECKPT "getcfcheckpt" @ 26,
    /// BIP37: filtered block. Core has no handler for it and ignores it.
    MerkleBlock(MerkleBlock) => MERKLEBLOCK "merkleblock" @ 16,
    /// BIP157: compact block filter. Core has no handler for it and ignores it.
    CFilter(CFilter) => CFILTER "cfilter" @ 23,
    /// BIP157: compact filter headers. Core has no handler for it and ignores it.
    CFHeaders(CFHeaders) => CFHEADERS "cfheaders" @ 25,
    /// BIP157: compact filter checkpoints. Core has no handler for it and
    /// ignores it.
    CFCheckpt(CFCheckpt) => CFCHECKPT "cfcheckpt" @ 27,
    /// BIP330: transaction reconciliation.
    SendTxRcncl(SendTxRcncl) => SENDTXRCNCL "sendtxrcncl",
    /// Masternode sync status count.
    Ssc(Ssc) => SSC "ssc" @ 139,
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
    /// BIP37: clear bloom filter.
    FilterClear => FILTERCLEAR "filterclear" @ 7,
    /// Request mempool contents.
    Mempool => MEMPOOL "mempool" @ 15,
    /// LLMQ: watch quorums.
    QWatch => QWATCH "qwatch" @ 151,
  }

  stub {
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
    /// Request active sporks.
    GetSporks => GETSPORKS "getsporks" @ 129,
  }
}

impl MsgDecode for Ping {}
impl MsgDecode for Pong {}
impl MsgDecode for Addr {}
impl MsgDecode for AddrV2Msg {}
impl MsgDecode for Inv {}
impl MsgDecode for GetData {}
impl MsgDecode for NotFound {}
impl MsgDecode for GetHeaders {}
impl MsgDecode for GetHeaders2 {}
impl MsgDecode for GovSync {}
impl MsgDecode for GovObject {}
impl MsgDecode for GovVote {}
impl MsgDecode for GetMnListDiff {}
impl MsgDecode for MnListDiff {}
impl MsgDecode for SendDsq {}
impl MsgDecode for QSendRecSigs {}
impl MsgDecode for Block {}
impl MsgDecode for Transaction {}
impl MsgDecode for GetBlocks {}
impl MsgDecode for FilterLoad {}
impl MsgDecode for FilterAdd {}
impl MsgDecode for SendCmpct {}
impl MsgDecode for CmpctBlock {}
impl MsgDecode for GetBlockTxn {}
impl MsgDecode for BlockTxn {}
impl MsgDecode for GetCFilters {}
impl MsgDecode for GetCFHeaders {}
impl MsgDecode for GetCFCheckpt {}
impl MsgDecode for MerkleBlock {}
impl MsgDecode for CFilter {}
impl MsgDecode for CFHeaders {}
impl MsgDecode for CFCheckpt {}
impl MsgDecode for SendTxRcncl {}
impl MsgDecode for Ssc {}
