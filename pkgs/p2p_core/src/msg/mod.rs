//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P message types and dispatch.

mod addr;
mod blocks;
mod bloom;
mod cfilter;
mod chainlock;
mod coinjoin;
mod gov;
mod headers;
mod headers2;
mod inv;
mod masternode;
mod mn_list;
mod ping;
mod quorum_sigs;
mod tx_reconcile;
mod version;

use crate::command::CommandString;
use crate::prelude::*;
use crate::short_id::ShortId;
use crate::version::ProtocolVersion;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::{Block, GovObject, GovVote, Transaction};
use dash_types::type_id::Unencodable;

pub use addr::{Addr, AddrV2Entry, AddrV2Msg, TimestampedAddr};
pub use blocks::{GetBlocks, SendCmpct};
pub use bloom::{BloomFlags, FilterAdd, FilterLoad, MerkleBlock, PartialMerkleTree, TxMerkleNode};
pub use cfilter::{CFCheckpt, CFHeaders, CFilter, FilterHash, FilterHeader, GetCFCheckpt, GetCFHeaders, GetCFilters};
pub use chainlock::{ClSig, IsdLock};
pub use coinjoin::SendDsq;
pub use gov::{GovSync, GovSyncStatusCount};
pub use headers::{GetHeaders, Headers};
pub use headers2::{CompressedHeader, GetHeaders2, Headers2};
pub use inv::{GetData, Inv, InvType, Inventory, NotFound};
pub use masternode::{MnAuth, PlatformBan, Spork};
pub use mn_list::{DeletedQuorum, GetMnListDiff, MnListDiff, MnListDiffPayload, QuorumClSig, SimplifiedMnListEntry};
pub use ping::{Ping, Pong};
pub use quorum_sigs::QSendRecSigs;
pub use tx_reconcile::SendTxRcncl;
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
    /// Request block hashes.
    GetBlocks(GetBlocks) => GETBLOCKS "getblocks" @ 9,
    /// Block data.
    Block(Block) => BLOCK "block" @ 2,
    /// Transaction.
    Tx(Transaction) => TX "tx" @ 21,
    /// Block headers.
    Headers(Headers) => HEADERS "headers" @ 13,
    /// Request compressed block headers.
    GetHeaders2(GetHeaders2) => GETHEADERS2 "getheaders2" @ 163,
    /// Compressed block headers.
    Headers2(Headers2) => HEADERS2 "headers2" @ 165,
    /// Governance sync request.
    GovSync(GovSync) => GOVSYNC "govsync" @ 140,
    /// Sync status count.
    Ssc(GovSyncStatusCount) => SSC "ssc" @ 139,
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
    /// BIP152: signal compact block support.
    SendCmpct(SendCmpct) => SENDCMPCT "sendcmpct" @ 20,
    /// BIP330: transaction reconciliation.
    SendTxRcncl(SendTxRcncl) => SENDTXRCNCL "sendtxrcncl",
    /// BIP37: load bloom filter.
    FilterLoad(FilterLoad) => FILTERLOAD "filterload" @ 8,
    /// BIP37: add data to bloom filter.
    FilterAdd(FilterAdd) => FILTERADD "filteradd" @ 6,
    /// BIP37: filtered block.
    MerkleBlock(MerkleBlock) => MERKLEBLOCK "merkleblock" @ 16,
    /// BIP157: request compact filters.
    GetCFilters(GetCFilters) => GETCFILTERS "getcfilters" @ 22,
    /// BIP157: compact block filter.
    CFilter(CFilter) => CFILTER "cfilter" @ 23,
    /// BIP157: request compact filter headers.
    GetCFHeaders(GetCFHeaders) => GETCFHEADERS "getcfheaders" @ 24,
    /// BIP157: compact filter headers.
    CFHeaders(CFHeaders) => CFHEADERS "cfheaders" @ 25,
    /// BIP157: request compact filter checkpoints.
    GetCFCheckpt(GetCFCheckpt) => GETCFCHECKPT "getcfcheckpt" @ 26,
    /// BIP157: compact filter checkpoints.
    CFCheckpt(CFCheckpt) => CFCHECKPT "cfcheckpt" @ 27,
    /// ChainLock signature.
    ClSig(ClSig) => CLSIG "clsig" @ 160,
    /// InstantSend deterministic lock.
    IsdLock(IsdLock) => ISDLOCK "isdlock" @ 161,
    /// Spork value.
    Spork(Spork) => SPORK "spork" @ 128,
    /// Masternode authentication.
    MnAuth(MnAuth) => MNAUTH "mnauth" @ 162,
    /// DIP-0031: platform ban.
    PlatformBan(PlatformBan) => PLATFORMBAN "platformban" @ 168,
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
  }

  stub {
    /// BIP152: compact block transactions.
    BlockTxn => BLOCKTXN "blocktxn" @ 3,
    /// BIP152: compact block.
    CmpctBlock => CMPCTBLOCK "cmpctblock" @ 4,
    /// BIP152: request compact block transactions.
    GetBlockTxn => GETBLOCKTXN "getblocktxn" @ 10,
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
    /// Request quorum rotation info.
    GetQrInfo => GETQRINFO "getqrinfo" @ 166,
    /// Quorum rotation info.
    QrInfo => QRINFO "qrinfo" @ 167,
  }

  stub_empty {
    /// Request mempool contents.
    Mempool => MEMPOOL "mempool" @ 15,
    /// Request active sporks.
    GetSporks => GETSPORKS "getsporks" @ 129,
    /// LLMQ: watch quorums.
    QWatch => QWATCH "qwatch" @ 151,
  }

  unassigned {
    // `feefilter`, which Dash does not implement.
    5,
    // Assigned in BIP324, not implemented.
    29, 30, 31, 32,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use dash_types::codec::{BaseCodec, DecodeError};
  use dash_types::CompactSize;
  use rstest::rstest;

  use core::fmt::Debug;

  /// A version before a locator.
  const VERSION: [u8; 4] = 70_240i32.to_le_bytes();

  /// A stop hash after a locator.
  const HASH: [u8; 32] = [0; 32];

  /// A `tx` entry of an inventory message.
  const INVENTORY: [u8; 36] = {
    let mut entry = [0; 36];
    entry[0] = 1;
    entry
  };

  /// An entry of an `addr`.
  const ADDR: [u8; 30] = [0; 30];

  /// An entry of an `addrv2`, an IPv4 address.
  const ADDRV2: [u8; 13] = [0, 0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0x27, 0x0f];

  /// `prefix`, a count of `count`, that many `entry` and then `suffix`.
  fn payload(prefix: &[u8], count: usize, entry: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut size = Vec::new();
    CompactSize::from(count).encode(&mut size);
    [prefix, &size, &entry.repeat(count), suffix].concat()
  }

  /// Checks that `T` reads a list of `limit` entries back to the same bytes,
  /// and fails on a count of one more before reading any entry.
  fn check_count<T: BaseCodec + Debug + PartialEq>(prefix: &[u8], entry: &[u8], suffix: &[u8], limit: usize) {
    let full = payload(prefix, limit, entry, suffix);
    let mut cursor = &full[..];
    let encoded = T::decode(&mut cursor).map(|msg| {
      let mut buf = Vec::new();
      msg.encode(&mut buf);
      buf
    });
    assert_eq!((encoded, cursor.len()), (Ok(full.clone()), 0));

    let past = Err(DecodeError::CompactSizeExceedsLimit {
      limit,
      value: limit as u64 + 1,
    });
    let over = payload(prefix, limit + 1, entry, suffix);
    assert_eq!(T::decode(&mut &over[..]), past);
    let bare = payload(prefix, limit + 1, &[], &[]);
    assert_eq!(T::decode(&mut &bare[..]), past);
  }

  #[rstest]
  #[case::inv(|| check_count::<Inv>(&[], &INVENTORY, &[], 50_000))]
  #[case::getdata(|| check_count::<GetData>(&[], &INVENTORY, &[], 50_000))]
  #[case::notfound(|| check_count::<NotFound>(&[], &INVENTORY, &[], 50_000))]
  #[case::getblocks(|| check_count::<GetBlocks>(&VERSION, &HASH, &HASH, 101))]
  #[case::getheaders(|| check_count::<GetHeaders>(&VERSION, &HASH, &HASH, 101))]
  #[case::getheaders2(|| check_count::<GetHeaders2>(&VERSION, &HASH, &HASH, 101))]
  #[case::addr(|| check_count::<Addr>(&[], &ADDR, &[], 1_000))]
  #[case::addrv2(|| check_count::<AddrV2Msg>(&[], &ADDRV2, &[], 1_000))]
  fn counts_stop_at_the_limit(#[case] check: fn()) {
    check();
  }

  #[rstest]
  #[case::inv(CommandString::INV, &[], 50_000)]
  #[case::getdata(CommandString::GETDATA, &[], 50_000)]
  #[case::notfound(CommandString::NOTFOUND, &[], 50_000)]
  #[case::getblocks(CommandString::GETBLOCKS, &VERSION, 101)]
  #[case::getheaders(CommandString::GETHEADERS, &VERSION, 101)]
  #[case::getheaders2(CommandString::GETHEADERS2, &VERSION, 101)]
  #[case::addr(CommandString::ADDR, &[], 1_000)]
  #[case::addrv2(CommandString::ADDRV2, &[], 1_000)]
  fn dispatch_keeps_the_limit(#[case] cmd: CommandString, #[case] prefix: &[u8], #[case] limit: usize) {
    let bare = payload(prefix, limit + 1, &[], &[]);
    assert_eq!(
      P2pMsg::decode_payload(&cmd, &bare),
      Err(crate::P2pDecodeError::Consensus(DecodeError::CompactSizeExceedsLimit {
        limit,
        value: limit as u64 + 1,
      }))
    );
  }
}
