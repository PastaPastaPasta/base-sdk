//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P message types and dispatch.

mod addr;
mod bloom;
mod cfilter;
mod chainlock;
mod coinjoin;
mod compact;
mod control;
mod dkg;
mod gov;
mod headers;
mod headers2;
mod inv;
mod llmq;
mod masternode;
mod mn_list;
mod ping;
mod rotation;
mod sigshare;
mod version;

use crate::codec::MsgDecode;
use crate::command::CommandString;
use crate::prelude::*;
use crate::short_id::ShortId;
use crate::version::ProtocolVersion;

use dash_primitives::{Block, Commitment, GovObject, GovVote, Transaction};
use dash_types::type_id::Unencodable;

pub use addr::{Addr, AddrV2Entry, AddrV2Msg, TimestampedAddr};
pub use bloom::{FilterAdd, FilterLoad, MerkleBlock, PartialMerkleTree};
pub use cfilter::{CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters};
pub use chainlock::{ClSig, IsdLock};
pub use coinjoin::{
  max_pool_entries, DsAccept, DsComplete, DsEntry, DsFinalTx, DsQueue, DsSignedInputs, DsStatusUpdate, DsTx,
  COINJOIN_ENTRY_MAX_SIZE,
};
pub use compact::{short_id_with_keys, BlockTxn, CmpctBlock, GetBlockTxn, PrefilledTx, SendCmpct, ShortTxId};
pub use control::{QSendRecSigs, SendDsq, SendTxRcncl, Ssc};
pub use dkg::{
  dkg_inventory_hash, dkg_quorum, DkgComplaint, DkgContribution, DkgJustification, DkgMessage, DkgPrematureCommitment,
  DkgRevealedShare,
};
pub use gov::{GovSync, VOTE_BLS_SIG_LEN, VOTE_ECDSA_SIG_LEN};
pub use headers::{GetBlocks, GetHeaders, Headers};
pub use headers2::{CompressedHeader, GetHeaders2, Headers2};
pub use inv::{GetData, Inv, InvType, Inventory, NotFound};
pub use llmq::{
  QData, QuorumData, QuorumDataError, QuorumDataRequest, RecoveredSig, VerificationVector, QUORUM_DATA_CONTRIBUTIONS,
  QUORUM_DATA_VVEC,
};
pub use masternode::{MnAuth, PlatformBan, Spork, MAX_SPORK_SIG_LEN};
pub use mn_list::{DeletedQuorum, GetMnListDiff, MnListDiff, MnListFormat, QuorumClSig, SimplifiedMnListEntry};
pub use ping::{Ping, Pong};
pub use rotation::{CycleInfo, GetQrInfo, QrInfo, QuorumSnapshot, SnapshotSkipMode, MAX_QRINFO_BASE_HASHES};
pub use sigshare::{
  BatchedSigShare, BatchedSigShares, BatchedSigSharesMsg, SigSesAnn, SigSesAnnMsg, SigShare, SigShareMsg, SigSharesInv,
  SigSharesInvMsg, MAX_BATCHED_SIGS, MAX_SIG_SES_ANNS, MAX_SIG_SHARES, MAX_SIG_SHARES_INVS,
};
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
    /// Governance sync request. Core ignores it before governance is synced,
    /// unread; the node checks that first.
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
    /// Spork broadcast.
    Spork(Spork) => SPORK "spork" @ 128,
    /// LLMQ: final commitment.
    QfCommit(Box<Commitment>) => QFCOMMIT "qfcommit" @ 146,
    /// LLMQ: recovered signature.
    QSigRec(RecoveredSig) => QSIGREC "qsigrec" @ 156,
    /// LLMQ: request quorum data.
    QGetData(QuorumDataRequest) => QGETDATA "qgetdata" @ 158,
    /// LLMQ: quorum data.
    QData(QData) => QDATA "qdata" @ 159,
    /// ChainLock signature.
    ClSig(ClSig) => CLSIG "clsig" @ 160,
    /// InstantSend deterministic lock.
    IsdLock(IsdLock) => ISDLOCK "isdlock" @ 161,
    /// Masternode authentication.
    MnAuth(MnAuth) => MNAUTH "mnauth" @ 162,
    /// Request quorum rotation info.
    GetQrInfo(GetQrInfo) => GETQRINFO "getqrinfo" @ 166,
    /// Quorum rotation info.
    QrInfo(Box<QrInfo>) => QRINFO "qrinfo" @ 167,
    /// DIP-0031: platform ban.
    PlatformBan(PlatformBan) => PLATFORMBAN "platformban" @ 168,
    /// LLMQ: DKG contribution. The handler gates, checks and queues it
    /// before this read, in the order [`DkgMessage`] gives.
    QContrib(Box<DkgContribution>) => QCONTRIB "qcontrib" @ 147,
    /// LLMQ: DKG complaint. The handler gates, checks and queues it
    /// before this read, in the order [`DkgMessage`] gives.
    QComplaint(DkgComplaint) => QCOMPLAINT "qcomplaint" @ 148,
    /// LLMQ: DKG justification. The handler gates, checks and queues it
    /// before this read, in the order [`DkgMessage`] gives.
    QJustify(DkgJustification) => QJUSTIFY "qjustify" @ 149,
    /// LLMQ: DKG premature commitment. The handler gates, checks and queues it
    /// before this read, in the order [`DkgMessage`] gives.
    QpCommit(DkgPrematureCommitment) => QPCOMMIT "qpcommit" @ 150,
    /// LLMQ: signing session announcements.
    QSigSesAnn(SigSesAnnMsg) => QSIGSESANN "qsigsesann" @ 152,
    /// LLMQ: signature share inventories.
    QSigsInv(SigSharesInvMsg) => QSIGSINV "qsigsinv" @ 153,
    /// LLMQ: signature share requests.
    QGetSigs(SigSharesInvMsg) => QGETSIGS "qgetsigs" @ 154,
    /// LLMQ: batched signature shares.
    QbSigs(BatchedSigSharesMsg) => QBSIGS "qbsigs" @ 155,
    /// LLMQ: signature shares.
    QSigShare(SigShareMsg) => QSIGSHARE "qsigshare" @ 157,
    /// CoinJoin: join a session, its flags read at the negotiated version.
    ///
    /// Like the other CoinJoin messages a masternode serves (`dsi`, `dss`),
    /// Core answers some requests before reading them (a full queue, no
    /// session, the wrong state or sender), with a status update rather
    /// than a failed read: the node gates on the command before
    /// [`P2pMsg::decode_with_policy`].
    Dsa(DsAccept) => DSA "dsa" @ 131,
    /// CoinJoin: a participant's inputs and outputs, gated as `dsa` is. The
    /// node checks [`DsEntry::fits_pool`].
    Dsi(DsEntry) => DSI "dsi" @ 132,
    /// CoinJoin: the transaction to sign.
    Dsf(DsFinalTx) => DSF "dsf" @ 133,
    /// CoinJoin: signed inputs of the final transaction, gated as `dsa` is.
    /// The node runs [`DsSignedInputs::check_payload`] before the read.
    Dss(DsSignedInputs) => DSS "dss" @ 134,
    /// CoinJoin: the session's end.
    Dsc(DsComplete) => DSC "dsc" @ 135,
    /// CoinJoin: a session's status.
    Dssu(DsStatusUpdate) => DSSU "dssu" @ 136,
    /// CoinJoin: a masternode-signed mixed transaction.
    Dstx(Box<DsTx>) => DSTX "dstx" @ 137,
    /// CoinJoin: a masternode's queue.
    Dsq(DsQueue) => DSQ "dsq" @ 138,
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
  }

  stub_empty {
    /// Request active sporks.
    GetSporks => GETSPORKS "getsporks" @ 129,
  }
}

/// Reads each listed type field by field, every list whole.
///
/// Core's handlers for these commands read the whole list and check its size
/// after the read. `BaseCodec` refuses a count above the type's limit before
/// any entry, so the handler read takes each list with `Vec`'s own codec.
macro_rules! read_lists_whole {
  ($($ty:ident { $($field:ident),+ })+) => {$(
    impl MsgDecode for $ty {
      fn decode_msg(data: &mut &[u8], _: &crate::ctx::ProtoCtx) -> Result<Self, crate::P2pDecodeError> {
        $(let $field = dash_types::codec::BaseCodec::decode(data)?;)+
        Ok(Self::new($($field),+))
      }
    }
  )+};
}

read_lists_whole! {
  Addr { addrs }
  AddrV2Msg { addrs }
  Inv { inventory }
  GetData { inventory }
  NotFound { inventory }
  GetHeaders { version, locator_hashes, hash_stop }
  GetHeaders2 { version, locator_hashes, hash_stop }
  GetBlocks { version, locator_hashes, hash_stop }
}

impl MsgDecode for Ping {}
impl MsgDecode for Pong {}
impl MsgDecode for GovSync {}
impl MsgDecode for GovObject {}
impl MsgDecode for GetMnListDiff {}
impl MsgDecode for SendDsq {}
impl MsgDecode for QSendRecSigs {}
impl MsgDecode for Block {}
impl MsgDecode for Transaction {}
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
impl MsgDecode for Spork {}
impl MsgDecode for Commitment {}
impl MsgDecode for RecoveredSig {}
impl MsgDecode for ClSig {}
impl MsgDecode for IsdLock {}
impl MsgDecode for MnAuth {}
impl MsgDecode for PlatformBan {}
impl MsgDecode for QData {}
impl MsgDecode for GetQrInfo {}

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

  /// The handler read takes a list past the `BaseCodec` limit whole.
  #[rstest]
  #[case::inv(CommandString::INV, &[], &INVENTORY, &[], 50_000)]
  #[case::getdata(CommandString::GETDATA, &[], &INVENTORY, &[], 50_000)]
  #[case::notfound(CommandString::NOTFOUND, &[], &INVENTORY, &[], 50_000)]
  #[case::getblocks(CommandString::GETBLOCKS, &VERSION, &HASH, &HASH, 101)]
  #[case::getheaders(CommandString::GETHEADERS, &VERSION, &HASH, &HASH, 101)]
  #[case::getheaders2(CommandString::GETHEADERS2, &VERSION, &HASH, &HASH, 101)]
  #[case::addr(CommandString::ADDR, &[], &ADDR, &[], 1_000)]
  #[case::addrv2(CommandString::ADDRV2, &[], &ADDRV2, &[], 1_000)]
  fn dispatch_reads_lists_whole(
    #[case] cmd: CommandString,
    #[case] prefix: &[u8],
    #[case] entry: &[u8],
    #[case] suffix: &[u8],
    #[case] limit: usize,
  ) {
    let ctx = crate::ctx::ProtoCtx::new(ProtocolVersion::V24_0, dash_pkc::bls::BlsCtx::BASIC);
    let over = payload(prefix, limit + 1, entry, suffix);
    let read = P2pMsg::decode_with_policy(&cmd, &over, &ctx)
      .map(|decoded| (decoded.msg.command(), decoded.msg.is_unknown(), decoded.consumed));
    assert_eq!(read, Ok((cmd, false, over.len())));
  }
}
