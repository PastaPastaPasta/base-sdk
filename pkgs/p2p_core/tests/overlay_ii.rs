//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The DKG and signature share messages' reads that depend on more than
//! their fields: a quorum's parameters, a handler's limits, `VARINT`s and
//! `AUTOBITSET`s. Core's reads of the same bytes are in
//! `core_overlay_ii.json5`.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_p2p_core::{
  BatchedSigShare, BatchedSigShares, BatchedSigSharesMsg, CommandString, DkgComplaint, DkgContribution,
  DkgJustification, DkgMessage, DkgPrematureCommitment, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion, SigSesAnn,
  SigSesAnnMsg, SigSharesInv, MAX_BATCHED_SIGS,
};
use dash_params::LlmqParams;
use dash_pkc::bls::{BlsCtx, BlsSigBytes};
use dash_primitives::{DynBitset, LlmqType};
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::{CompactSize, Numeric};
use rstest::rstest;

fn decode(cmd: &'static str, payload: &[u8]) -> Result<P2pMsg, P2pDecodeError> {
  let ctx = ProtoCtx::new(ProtocolVersion::from_base(70242), BlsCtx::BASIC);
  P2pMsg::decode_with_policy(&CommandString::from_static(cmd), payload, &ctx).map(|d| d.msg)
}

fn encode(msg: &P2pMsg) -> Vec<u8> {
  let mut out = Vec::new();
  msg.encode_payload(&mut out);
  out
}

fn wire<T: BaseCodec>(value: &T) -> Vec<u8> {
  let mut out = Vec::new();
  value.encode(&mut out);
  out
}

fn count(n: usize) -> Vec<u8> {
  wire(&CompactSize::from(n))
}

fn params(llmq_type: LlmqType) -> LlmqParams {
  *LlmqParams::available(llmq_type).unwrap()
}

/// `llmqType`, `quorumHash`, `proTxHash`.
fn prefix() -> Vec<u8> {
  let mut out = vec![LlmqType::Llmq50_60.to_base()];
  out.extend([0x11; 32]);
  out.extend([0x22; 32]);
  out
}

fn bitset(bits: usize, byte: u8) -> Vec<u8> {
  let mut out = count(bits);
  out.extend(vec![byte; bits.div_ceil(8)]);
  out
}

fn complaint(bad: &[u8], complain_for: &[u8]) -> Vec<u8> {
  [prefix(), bad.to_vec(), complain_for.to_vec(), vec![0; 96]].concat()
}

fn contribution(vvec: usize, blobs: usize) -> Vec<u8> {
  let mut out = prefix();
  out.extend(count(vvec));
  out.extend(vec![0; vvec * 48]);
  out.extend([0; 48]); // ephemeral key
  out.extend([0x33; 32]); // IV seed
  out.extend(count(blobs));
  for _ in 0..blobs {
    out.extend(count(3));
    out.extend([0x44; 3]);
  }
  out.extend([0; 96]);
  out
}

fn justification(shares: usize) -> Vec<u8> {
  let mut out = prefix();
  out.extend(count(shares));
  for i in 0..shares {
    out.extend((i as u32).to_le_bytes());
    out.extend([0x05; 32]);
  }
  out.extend([0; 96]);
  out
}

fn premature(valid: &[u8]) -> Vec<u8> {
  [prefix(), valid.to_vec(), vec![0; 48], vec![0x55; 32], vec![0; 192]].concat()
}

/// Core's `MaxDKGMessageSize`, worked by hand from its terms for the two
/// mainnet sizes.
#[rstest]
#[case(LlmqType::Llmq50_60, [9365, 1209, 2990, 1373])]
#[case(LlmqType::Llmq400_60, [65995, 1295, 15590, 1416])]
fn dkg_size_caps_are_cores(#[case] llmq_type: LlmqType, #[case] caps: [usize; 4]) {
  let p = params(llmq_type);
  assert_eq!(
    [
      DkgContribution::max_size(&p),
      DkgComplaint::max_size(&p),
      DkgJustification::max_size(&p),
      DkgPrematureCommitment::max_size(&p),
    ],
    caps
  );
}

#[rstest]
fn dkg_sizes_cap_at_one_mebibyte() {
  let mut p = params(LlmqType::Llmq400_60);
  p.size = i32::MAX;
  p.threshold = -1;
  assert_eq!(DkgContribution::max_size(&p), 1 << 20);
  assert_eq!(DkgJustification::max_size(&p), 1 << 20);
}

/// The stateless read refuses a DKG payload over 1 MiB before reading it,
/// as Core's size cap does for any quorum: three million empty blobs would
/// otherwise each allocate.
#[rstest]
fn dkg_reads_cap_at_one_mebibyte() {
  let ceiling = 1 << 20;
  let blobs = (3 << 20) - 512;
  let mut big = prefix();
  big.extend(count(0));
  big.extend([0; 48 + 32]);
  big.extend(count(blobs));
  big.extend(vec![0; blobs]);
  big.extend([0; 96]);
  for cmd in ["qcontrib", "qcomplaint", "qjustify", "qpcommit"] {
    assert_eq!(
      decode(cmd, &big),
      Err(P2pDecodeError::HandlerPayloadTooLarge {
        command: cmd,
        size: big.len(),
        max: ceiling,
      }),
      "{cmd}"
    );
  }
  // At the ceiling the read runs, and fails on these bytes as Core's would.
  assert!(!matches!(
    decode("qcontrib", &big[..ceiling]),
    Err(P2pDecodeError::HandlerPayloadTooLarge { .. })
  ));
  let ok = contribution(30, 40);
  assert!(matches!(decode("qcontrib", &ok), Ok(P2pMsg::QContrib(_))));
}

#[rstest]
fn dkg_walk_bounds_counts_by_the_quorum() {
  let p = params(LlmqType::Llmq50_60);
  let ok = contribution(30, 40);
  assert_eq!(DkgContribution::check_payload(&ok, &p), Ok(()));
  assert!(matches!(decode("qcontrib", &ok), Ok(P2pMsg::QContrib(_))));
  let framing = Err(P2pDecodeError::DkgFraming { command: "qcontrib" });
  // The vector is the threshold's size; the blobs are min..=size.
  assert_eq!(DkgContribution::check_payload(&contribution(29, 40), &p), framing);
  assert_eq!(DkgContribution::check_payload(&contribution(30, 39), &p), framing);
  assert_eq!(DkgContribution::check_payload(&contribution(30, 50), &p), Ok(()));
  assert_eq!(DkgContribution::check_payload(&contribution(30, 51), &p), framing);
  // A byte past the message, or one short.
  assert_eq!(DkgContribution::check_payload(&[&ok[..], &[0]].concat(), &p), framing);
  assert_eq!(DkgContribution::check_payload(&ok[..ok.len() - 1], &p), framing);
  // Over the cap, whatever the framing.
  let big = vec![0; DkgContribution::max_size(&p) + 1];
  assert!(matches!(
    DkgContribution::check_payload(&big, &p),
    Err(P2pDecodeError::HandlerPayloadTooLarge { max: 9365, .. })
  ));
  // Checked then read: the checks refuse first.
  let P2pMsg::QContrib(read) = decode("qcontrib", &ok).unwrap() else {
    panic!("qcontrib")
  };
  assert_eq!(DkgContribution::decode_checked(&ok, &p), Ok(*read));
  assert!(matches!(
    DkgContribution::decode_checked(&contribution(29, 40), &p),
    Err(P2pDecodeError::DkgFraming { .. })
  ));
  assert!(matches!(
    DkgContribution::decode_checked(&big, &p),
    Err(P2pDecodeError::HandlerPayloadTooLarge { .. })
  ));

  let framing = Err(P2pDecodeError::DkgFraming { command: "qcomplaint" });
  assert_eq!(
    DkgComplaint::check_payload(&complaint(&bitset(50, 0), &bitset(50, 0)), &p),
    Ok(())
  );
  assert_eq!(
    DkgComplaint::check_payload(&complaint(&bitset(49, 0), &bitset(50, 0)), &p),
    framing
  );
  assert_eq!(
    DkgComplaint::check_payload(&complaint(&bitset(51, 0), &bitset(51, 0)), &p),
    framing
  );

  let framing = Err(P2pDecodeError::DkgFraming { command: "qjustify" });
  assert_eq!(DkgJustification::check_payload(&justification(50), &p), Ok(()));
  assert_eq!(DkgJustification::check_payload(&justification(51), &p), framing);

  let framing = Err(P2pDecodeError::DkgFraming { command: "qpcommit" });
  assert_eq!(
    DkgPrematureCommitment::check_payload(&premature(&bitset(48, 0xff)), &p),
    Ok(())
  );
  assert_eq!(
    DkgPrematureCommitment::check_payload(&premature(&bitset(51, 0)), &p),
    framing
  );
  // Fewer than the type and the quorum hash.
  assert_eq!(DkgPrematureCommitment::check_payload(&[1; 32], &p), framing);
}

/// `DYNBITSET`'s padding bits: set ones fail the walk and the read.
#[rstest]
fn dkg_bitset_padding_bits_are_refused() {
  let p = params(LlmqType::Llmq50_60);
  // 50 bits: the last byte holds 2, the other 6 are padding.
  let mut padded = bitset(50, 0);
  *padded.last_mut().unwrap() = 0x04;
  let ok = premature(&bitset(50, 0));
  let bad = premature(&padded);
  assert_eq!(DkgPrematureCommitment::check_payload(&ok, &p), Ok(()));
  assert!(DkgPrematureCommitment::check_payload(&bad, &p).is_err());
  assert!(decode("qpcommit", &bad).is_err());
  let bad = complaint(&bitset(50, 0), &padded);
  assert!(DkgComplaint::check_payload(&bad, &p).is_err());
  assert!(decode("qcomplaint", &bad).is_err());
}

/// The worker reads the whole payload: a byte after the message fails.
#[rstest]
#[case("qcontrib", contribution(30, 40))]
#[case("qcomplaint", complaint(&bitset(50, 1), &bitset(50, 0)))]
#[case("qjustify", justification(2))]
#[case("qpcommit", premature(&bitset(50, 0)))]
fn dkg_reads_are_whole(#[case] cmd: &'static str, #[case] payload: Vec<u8>) {
  let msg = decode(cmd, &payload).unwrap();
  assert_eq!(encode(&msg), payload);
  assert!(matches!(
    decode(cmd, &[&payload[..], &[0]].concat()),
    Err(P2pDecodeError::Consensus(DecodeError::TrailingBytes { remaining: 1 }))
  ));
}

#[rstest]
fn dkg_sign_hashes_zero_the_signature() {
  let mut payload = complaint(&bitset(3, 1), &bitset(3, 0));
  let n = payload.len();
  payload[n - 96..].fill(0x77);
  let Ok(P2pMsg::QComplaint(signed)) = decode("qcomplaint", &payload) else {
    panic!()
  };
  let unsigned = DkgComplaint {
    sig: BlsSigBytes::from_bytes([0; 96]),
    ..signed.clone()
  };
  use dash_types::Hashable;
  assert_eq!(signed.sign_hash(), unsigned.hash());
  assert_ne!(signed.sign_hash(), signed.hash());
}

/// Core's `VARINT` bit patterns (`serialize_tests.cpp` `varints_bitpatterns`).
#[rstest]
#[case(0, "00")]
#[case(0x7f, "7f")]
#[case(0x80, "8000")]
#[case(0x1234, "a334")]
#[case(0xffff, "82fe7f")]
#[case(0x12_3456, "c7e756")]
#[case(0x8012_3456, "86ffc7e756")]
#[case(0xffff_ffff, "8efefefe7f")]
fn varints_are_cores(#[case] session_id: u32, #[case] hex: &str) {
  let ann = SigSesAnn {
    session_id,
    llmq_type: LlmqType::LlmqTest,
    quorum_hash: Default::default(),
    id: Default::default(),
    msg_hash: Default::default(),
  };
  let bytes = wire(&ann);
  let digits = hex.len() / 2;
  assert_eq!(hex_conservative::DisplayHex::to_lower_hex_string(&bytes[..digits]), hex);
  assert_eq!(SigSesAnn::decode(&mut &bytes[..]).unwrap(), ann);
}

/// A `VARINT` past `u32::MAX` fails, as Core's "size too large" does.
#[rstest]
#[case(&[0x8e, 0xfe, 0xfe, 0xff, 0x00])]
#[case(&[0x8f, 0x80, 0x80, 0x80, 0x00])]
#[case(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00])]
fn varints_past_u32_fail(#[case] digits: &[u8]) {
  let payload = [&[1][..], digits, &[100], &[0; 96]].concat();
  assert!(decode("qsigsesann", &payload).is_err());
}

fn inv(raw: &[u8]) -> Result<SigSharesInv, DecodeError> {
  SigSharesInv::decode(&mut &raw[..])
}

/// `AUTOBITSET`: a form byte, then a fixed bitset or varint offsets; Core
/// writes whichever is shorter (the varints on a tie).
#[rstest]
fn autobitsets_read_either_form_and_write_the_shorter() {
  // 16 bits, bits 0 and 9 set: fixed form `01 02`.
  let fixed = [0x07, 16, 0, 0x01, 0x02];
  let varint = [0x07, 16, 1, 0x01, 0x09, 0x00];
  let a = inv(&fixed).unwrap();
  let b = inv(&varint).unwrap();
  assert_eq!(a, b);
  assert_eq!(a.inv.iter_set_bits().collect::<Vec<_>>(), [0, 9]);
  // Fixed: 2 bytes, varints: 3 bytes.
  assert_eq!(wire(&b), fixed);
  // 8 bits, bit 2 set: fixed 1 byte, varints 2 bytes.
  assert_eq!(wire(&inv(&[0, 8, 1, 3, 0]).unwrap()), [0, 8, 0, 0x04]);
  // 16 bits, none set: fixed 2 bytes, varints 1 byte.
  assert_eq!(wire(&inv(&[0, 16, 0, 0, 0]).unwrap()), [0, 16, 1, 0]);
  // 0 bits: fixed 0 bytes, varints 1 byte.
  assert_eq!(wire(&inv(&[0, 0, 0]).unwrap()), [0, 0, 0]);
}

#[rstest]
#[case::form_byte(&[0, 8, 2, 0])]
#[case::padding_bits(&[0, 4, 0, 0x10])]
#[case::index_past_size(&[0, 4, 1, 5, 0])]
#[case::second_index_past_size(&[0, 4, 1, 1, 4, 0])]
#[case::no_stopper(&[0, 4, 1, 1])]
#[case::over_max_size(&[0, 0xfd, 0x91, 0x01, 1, 0])]
fn autobitsets_refuse_what_core_refuses(#[case] raw: &[u8]) {
  assert!(inv(raw).is_err(), "{raw:x?}");
}

#[rstest]
fn autobitset_size_is_at_most_the_largest_quorum() {
  let max = [&[0][..], &count(MAX_BATCHED_SIGS), &[1, 0]].concat();
  assert_eq!(inv(&max).unwrap().inv.num_bits, MAX_BATCHED_SIGS as u64);
}

fn share(member: u16) -> BatchedSigShare {
  BatchedSigShare {
    quorum_member: member,
    sig_share: BlsSigBytes::from_bytes([0x66; 96]),
  }
}

fn batch(n: usize) -> BatchedSigShares {
  BatchedSigShares {
    session_id: 1,
    sig_shares: (0..n as u16).map(share).collect(),
  }
}

/// `qbsigs` holds at most 400 batches and 400 shares in all; Core counts the
/// shares after each batch.
#[rstest]
fn qbsigs_bounds_its_shares_in_all() {
  let msg = |batches| wire(&BatchedSigSharesMsg { batches });
  assert!(decode("qbsigs", &msg(vec![batch(400)])).is_ok());
  assert!(decode("qbsigs", &msg(vec![batch(200), batch(200)])).is_ok());
  assert!(matches!(
    decode("qbsigs", &msg(vec![batch(200), batch(201)])),
    Err(P2pDecodeError::TooManyEntries { count: 401, .. })
  ));
  assert!(decode("qbsigs", &msg(vec![batch(401)])).is_err());
  let over = [count(401), vec![0; 401 * 2]].concat();
  assert!(matches!(
    decode("qbsigs", &over),
    Err(P2pDecodeError::TooManyEntries { count: 401, .. })
  ));
}

#[rstest]
#[case("qsigsesann", 100, 1 + 1 + 96)]
#[case("qsigsinv", 200, 3)]
#[case("qgetsigs", 200, 3)]
#[case("qsigshare", 32, 1 + 32 + 2 + 64 + 96)]
fn sig_share_vectors_are_bounded(#[case] cmd: &'static str, #[case] max: usize, #[case] entry: usize) {
  let full = [count(max), vec![0; max * entry]].concat();
  assert!(decode(cmd, &full).is_ok(), "{cmd}");
  let over = [count(max + 1), vec![0; (max + 1) * entry]].concat();
  assert!(
    matches!(decode(cmd, &over), Err(P2pDecodeError::TooManyEntries { .. })),
    "{cmd}"
  );
}

#[rstest]
fn sig_share_messages_round_trip() {
  let ann = SigSesAnnMsg {
    anns: vec![SigSesAnn {
      session_id: 300,
      llmq_type: LlmqType::Llmq50_60,
      quorum_hash: Default::default(),
      id: Default::default(),
      msg_hash: Default::default(),
    }],
  };
  let bytes = wire(&ann);
  assert_eq!(decode("qsigsesann", &bytes).unwrap(), P2pMsg::QSigSesAnn(ann));
  let inv = DynBitset {
    num_bits: 10,
    data: vec![0x01, 0x02],
  };
  let msg = [count(1), vec![0x05], count(10), vec![0, 0x01, 0x02]].concat();
  let Ok(P2pMsg::QGetSigs(m)) = decode("qgetsigs", &msg) else {
    panic!()
  };
  assert_eq!(m.invs[0].inv, inv);
  assert_eq!(m.invs[0].session_id, 5);
}
