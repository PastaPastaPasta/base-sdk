//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The CoinJoin and governance messages' reads that depend on more than
//! their fields: the negotiated version, the pool size, Core's wire
//! booleans and a vote's signature size. Core's reads of the same bytes are
//! in `core_overlay_iii.json5`.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_p2p_core::{
  max_pool_entries, CommandString, DsAccept, DsSignedInputs, GovSync, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion,
};
use dash_params::{ChainParamsBuilder, NetworkKind, Release};
use dash_pkc::bls::BlsCtx;
use dash_primitives::GovVote;
use dash_types::codec::BaseCodec;
use dash_types::{CoreBool, Hashable, Numeric};
use rstest::rstest;

fn decode_at(cmd: &'static str, payload: &[u8], version: i32) -> Result<(P2pMsg, usize), P2pDecodeError> {
  let ctx = ProtoCtx::new(ProtocolVersion::from_base(version), BlsCtx::BASIC);
  P2pMsg::decode_with_policy(&CommandString::from_static(cmd), payload, &ctx).map(|d| (d.msg, d.consumed))
}

fn decode(cmd: &'static str, payload: &[u8]) -> Result<P2pMsg, P2pDecodeError> {
  decode_at(cmd, payload, 70242).map(|(m, _)| m)
}

fn encode(msg: &P2pMsg) -> Vec<u8> {
  let mut out = Vec::new();
  msg.encode_payload(&mut out);
  out
}

fn dsha256(bytes: &[u8]) -> Hash256 {
  Hash256::from_lendian(sha256d::Hash::hash(bytes).to_byte_array())
}

/// A transaction with no inputs or outputs: version 2, or version 3 of
/// type 1 with a one-byte payload.
fn tx(special: bool) -> Vec<u8> {
  if special {
    vec![0x03, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0x01, 0xaa]
  } else {
    vec![0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  }
}

/// An input spending output 1 of 0x11.., with a one-byte script.
fn txin() -> Vec<u8> {
  [vec![0x11; 32], vec![1, 0, 0, 0], vec![1, 0x51], vec![0xff; 4]].concat()
}

fn list(n: usize, item: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  dash_types::CompactSize::from(n).encode(&mut out);
  for _ in 0..n {
    out.extend(item);
  }
  out
}

#[rstest]
fn dsa_reads_the_flags_from_the_rebalance_version() {
  let body = [&[0x04, 0, 0, 0][..], &tx(false)].concat();
  // At 70241 and later the flags byte follows the collateral.
  let with = [&body[..], &[0x03]].concat();
  let (msg, consumed) = decode_at("dsa", &with, 70241).unwrap();
  let P2pMsg::Dsa(DsAccept { flags, .. }) = &msg else {
    panic!("{msg:?}")
  };
  assert_eq!((*flags, consumed), (Some(3), with.len()));
  assert_eq!(encode(&msg), with);
  assert!(decode_at("dsa", &body, 70241).is_err(), "the flags byte is read");
  // Before it, there is none: a byte after the collateral is not read.
  let (msg, consumed) = decode_at("dsa", &with, 70240).unwrap();
  let P2pMsg::Dsa(DsAccept { flags, .. }) = &msg else {
    panic!("{msg:?}")
  };
  assert_eq!((*flags, consumed), (None, body.len()));
  assert_eq!(encode(&msg), body);
}

#[rstest]
fn special_transactions_keep_their_payload() {
  let raw = [&[0, 0, 0, 0][..], &tx(true)].concat();
  let msg = decode("dsf", &raw).unwrap();
  assert_eq!(encode(&msg), raw);
}

#[rstest]
fn dsi_and_dss_counts_are_the_pools() {
  let params = &ChainParamsBuilder::new(NetworkKind::Mainnet, Release::V24_0)
    .build()
    .unwrap();
  let max = max_pool_entries(params);
  assert_eq!(max, 180);
  let entry = |n: usize| [list(n, &txin()), tx(false), list(0, &[])].concat();
  let P2pMsg::Dsi(at) = decode("dsi", &entry(max)).unwrap() else {
    panic!("dsi")
  };
  assert!(at.fits_pool(params));
  let P2pMsg::Dsi(over) = decode("dsi", &entry(max + 1)).unwrap() else {
    panic!("dsi")
  };
  assert!(!over.fits_pool(params));
  // The collateral sits between the lists.
  assert_eq!((at.inputs.len(), at.outputs.len()), (max, 0));

  // dss: the count, before any input is read (Core answers ERR_MAXIMUM).
  assert!(DsSignedInputs::check_payload(&list(max, &txin()), params).is_ok());
  let over = DsSignedInputs::check_payload(&list(max + 1, &[]), params);
  assert!(
    matches!(
      over,
      Err(P2pDecodeError::TooManyEntries {
        count: 181,
        max: 180,
        ..
      })
    ),
    "{over:?}"
  );
  // A count within the bound that the inputs don't fill fails in the read.
  assert!(DsSignedInputs::check_payload(&[5], params).is_ok());
  assert!(
    DsSignedInputs::check_payload(&[0xfd, 1, 0], params).is_err(),
    "non-canonical"
  );
}

fn dsq(ready: u8) -> Vec<u8> {
  [
    &[0x02, 0, 0, 0][..],
    &[0x22; 32],
    &1_700_000_000i64.to_le_bytes(),
    &[ready],
    &list(96, &[0x33]),
  ]
  .concat()
}

#[rstest]
fn dsq_hashes_its_ready_flag_as_core_writes_it() {
  let canonical = dsq(1);
  let P2pMsg::Dsq(q) = decode("dsq", &dsq(2)).unwrap() else {
    panic!("dsq")
  };
  assert_eq!(q.ready, CoreBool(true));
  // Core writes any non-zero byte back as 0x01 and hashes that.
  assert_eq!(encode(&P2pMsg::Dsq(q.clone())), canonical);
  assert_eq!(q.hash(), dsha256(&canonical));
  // The sign hash leaves out the signature.
  let unsigned = &canonical[..canonical.len() - 97];
  assert_eq!(q.signature_hash(), dsha256(unsigned));
  let P2pMsg::Dsq(q0) = decode("dsq", &dsq(0)).unwrap() else {
    panic!("dsq")
  };
  assert_ne!(q0.signature_hash(), q.signature_hash());
}

#[rstest]
fn dstx_signs_its_time_and_not_its_signature() {
  let sig_time = 1_700_000_000i64.to_le_bytes();
  let raw = [&tx(false)[..], &[0x44; 32], &list(96, &[0x55]), &sig_time].concat();
  let P2pMsg::Dstx(d) = decode("dstx", &raw).unwrap() else {
    panic!("dstx")
  };
  assert_eq!(encode(&P2pMsg::Dstx(d.clone())), raw);
  let unsigned = [&tx(false)[..], &[0x44; 32], &sig_time].concat();
  assert_eq!(d.signature_hash(), dsha256(&unsigned));
}

fn vote(sig: &[u8]) -> Vec<u8> {
  [
    &[0x66; 32][..],
    &[2, 0, 0, 0],
    &[0x77; 32],
    &[2, 0, 0, 0],
    &[1, 0, 0, 0],
    &1_700_000_000i64.to_le_bytes(),
    sig,
  ]
  .concat()
}

#[rstest]
#[case(0, false)]
#[case(64, false)]
#[case(65, true)]
#[case(66, false)]
#[case(95, false)]
#[case(96, true)]
#[case(97, false)]
fn a_vote_signature_is_65_or_96_bytes(#[case] len: usize, #[case] read: bool) {
  let raw = vote(&list(len, &[0x88]));
  let got = decode("govobjvote", &raw);
  assert_eq!(got.is_ok(), read, "{len}: {got:?}");
  // Any length is a vote off the network (disk, hashing).
  assert!(GovVote::decode(&mut &raw[..]).is_ok());
}

#[rstest]
fn a_vote_signature_over_96_fails_before_its_bytes() {
  // The count alone, no bytes: refused for the count, not for the end.
  let raw = vote(&[0xfd, 0x10, 0x27]);
  let err = decode("govobjvote", &raw).unwrap_err();
  assert!(!matches!(err, P2pDecodeError::InvalidValue { .. }), "{err:?}");
}

#[rstest]
fn a_vote_signs_its_wire_order_and_hashes_cores_identity() {
  let raw = vote(&list(96, &[0x88]));
  let P2pMsg::GovObjVote(v) = decode("govobjvote", &raw).unwrap() else {
    panic!("govobjvote")
  };
  assert_eq!(v.signature_hash(), dsha256(&raw[..raw.len() - 97]));
  // The identity hash: the outpoint with Core's legacy padding, the
  // parent, then the signal before the outcome, and the time.
  let identity = [
    &raw[..36],
    &[0][..],
    &[0xff; 4],
    &raw[36..68],
    &raw[72..76],
    &raw[68..72],
    &raw[76..84],
  ]
  .concat();
  assert_eq!(v.hash(), dsha256(&identity));
}

#[rstest]
fn an_object_signs_everything_but_its_signature() {
  let unsigned = [
    &[0u8; 32][..],
    &[1, 0, 0, 0],
    &1_700_000_000i64.to_le_bytes(),
    &[0x99; 32],
    &list(3, &[0x7b]),
    &[1, 0, 0, 0],
    &[0; 32],
    &[0xff; 4],
  ]
  .concat();
  let raw = [&unsigned[..], &list(65, &[0xab])].concat();
  let P2pMsg::GovObj(o) = decode("govobj", &raw).unwrap() else {
    panic!("govobj")
  };
  assert_eq!(o.signature_hash(), dsha256(&unsigned));
}

#[rstest]
fn govsync_reads_the_whole_bloom_filter() {
  let filter = [&list(3, &[0x01])[..], &[5, 0, 0, 0], &[7, 0, 0, 0], &[1]].concat();
  let raw = [&[0u8; 32][..], &filter].concat();
  let (msg, consumed) = decode_at("govsync", &raw, 70242).unwrap();
  let P2pMsg::GovSync(GovSync { bloom_filter, .. }) = &msg else {
    panic!("{msg:?}")
  };
  assert_eq!(
    (bloom_filter.hash_funcs, bloom_filter.tweak, bloom_filter.flags),
    (5, 7, 1)
  );
  assert_eq!((consumed, encode(&msg)), (raw.len(), raw.clone()));
  // Core's LIMITED_VECTOR(36000) on the data.
  let over = [&[0u8; 32][..], &list(36_001, &[0]), &[0; 9]].concat();
  assert!(decode("govsync", &over).is_err());
  let at = [&[0u8; 32][..], &list(36_000, &[0]), &[0; 9]].concat();
  assert!(decode("govsync", &at).is_ok());
}
