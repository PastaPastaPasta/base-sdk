//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The overlay messages' reads that depend on more than their fields: the
//! protocol version, a handler's limits, optional bytes and Core's map
//! order. Core's reads of the same bytes are in `core_overlay.json5`.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use bitcoin_hashes::sha256d;
use dash_p2p_core::{
  CommandString, GetQrInfo, MnListDiff, MnListFormat, P2pDecodeError, P2pMsg, PlatformBan, ProtoCtx, ProtocolVersion,
  QData, QuorumClSig, QuorumDataError, QuorumDataRequest, QuorumSnapshot, SimplifiedMnListEntry, SnapshotSkipMode,
  Spork, MAX_QRINFO_BASE_HASHES, MAX_SPORK_SIG_LEN,
};
use dash_pkc::bls::BlsCtx;
use dash_primitives::MnType;
use dash_types::codec::BaseCodec;
use dash_types::{CompactSize, Numeric};
use rstest::rstest;

fn ctx(version: i32) -> ProtoCtx {
  ProtoCtx::new(ProtocolVersion::from_base(version), BlsCtx::BASIC)
}

fn decode(cmd: &'static str, payload: &[u8], version: i32) -> Result<P2pMsg, P2pDecodeError> {
  P2pMsg::decode_with_policy(&CommandString::from_static(cmd), payload, &ctx(version)).map(|d| d.msg)
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
  let mut out = Vec::new();
  CompactSize::from(n).encode(&mut out);
  out
}

/// A version 2 SML entry of `mn_type`, as Core writes it with or without
/// its version.
fn sml_entry(version: u16, mn_type: u16, with_version: bool) -> Vec<u8> {
  let mut out = Vec::new();
  if with_version {
    out.extend(version.to_le_bytes());
  }
  out.extend([0x01; 32]); // proRegTxHash
  out.extend([0x02; 32]); // confirmedHash
  out.extend([0; 10]); // service: IPv4-mapped 192.0.2.1:9999
  out.extend([0xff, 0xff, 192, 0, 2, 1, 0x27, 0x0f]);
  out.extend([0x03; 48]); // pubKeyOperator
  out.extend([0x04; 20]); // keyIDVoting
  out.push(1); // isValid
  if with_version && version >= 2 {
    out.extend(mn_type.to_le_bytes());
    if mn_type == 1 {
      out.extend(26657u16.to_le_bytes());
      out.extend([0x05; 20]);
    }
  }
  out
}

/// A list diff with `entries`, laid out for `format`.
fn mnlistdiff(format: MnListFormat, entries: &[Vec<u8>]) -> Vec<u8> {
  let mut out = Vec::new();
  if format >= MnListFormat::VersionFirst {
    out.extend(1u16.to_le_bytes());
  }
  out.extend([0x0a; 32]); // baseBlockHash
  out.extend([0x0b; 32]); // blockHash
  out.extend(1u32.to_le_bytes()); // merkle tree: one transaction,
  out.extend(count(1)); // its hash,
  out.extend([0x0c; 32]);
  out.extend([1, 1]); // and one flag byte
                      // A version 3 coinbase transaction with no inputs and no outputs.
  out.extend([3, 0, 5, 0, 0, 0, 0, 0, 0, 0]);
  out.push(0); // empty extra payload
  if matches!(format, MnListFormat::VersionAfterCbTx | MnListFormat::VersionedEntries) {
    out.extend(1u16.to_le_bytes());
  }
  out.extend(count(1)); // deletedMNs
  out.extend([0x0d; 32]);
  out.extend(count(entries.len()));
  for e in entries {
    out.extend(e);
  }
  out.extend(count(0)); // deletedQuorums
  out.extend(count(0)); // newQuorums
  if format >= MnListFormat::ClSigs {
    out.extend(count(0));
  }
  out
}

#[rstest]
#[case::unversioned(70221, MnListFormat::Unversioned)]
#[case::after_cbtx(70225, MnListFormat::VersionAfterCbTx)]
#[case::dmn_type(70227, MnListFormat::VersionAfterCbTx)]
#[case::versioned_entries(70228, MnListFormat::VersionedEntries)]
#[case::version_first(70229, MnListFormat::VersionFirst)]
#[case::clsigs(70230, MnListFormat::ClSigs)]
#[case::current(70242, MnListFormat::ClSigs)]
fn mnlistdiff_reads_and_writes_in_the_peers_band(#[case] version: i32, #[case] format: MnListFormat) {
  let versioned = format.has_entry_version();
  let entries = [sml_entry(2, 0, versioned), sml_entry(2, 1, versioned)];
  let raw = mnlistdiff(format, &entries);
  let msg = decode("mnlistdiff", &raw, version).unwrap();
  let P2pMsg::MnListDiff(diff) = &msg else {
    panic!("{msg:?}")
  };
  assert_eq!(diff.format, format);
  assert_eq!(diff.mn_list.len(), 2);
  assert_eq!(encode(&msg), raw);
  // Unversioned entries read as version 1 and carry no type.
  let evo = &diff.mn_list[1];
  if versioned {
    assert_eq!(
      (evo.version, evo.mn_type, evo.platform_http_port),
      (2, MnType::Evo, Some(26657))
    );
  } else {
    assert_eq!(
      (evo.version, evo.mn_type, evo.platform_http_port),
      (1, MnType::Regular, None)
    );
  }
}

#[rstest]
fn an_older_band_leaves_the_cl_sigs_unread() {
  let raw = mnlistdiff(MnListFormat::ClSigs, &[sml_entry(2, 0, true)]);
  // At 70229 the CL-sig count is left unread; handlers ignore trailing
  // bytes.
  let mut data = &raw[..];
  let old = MnListDiff::decode_as(&mut data, MnListFormat::VersionFirst).unwrap();
  assert_eq!(data, [0]);
  assert!(old.quorum_cl_sigs.is_empty());
}

#[rstest]
#[case::v1(1, 0, 0)]
#[case::v2_regular(2, 0, 2)]
#[case::v2_evo(2, 1, 24)]
fn sml_entry_fields_follow_its_version(#[case] version: u16, #[case] mn_type: u16, #[case] tail: usize) {
  let raw = sml_entry(version, mn_type, true);
  let entry = SimplifiedMnListEntry::decode(&mut &raw[..]).unwrap();
  assert_eq!(raw.len(), 2 + 32 + 32 + 18 + 48 + 20 + 1 + tail);
  assert_eq!(wire(&entry), raw);
  assert_eq!(entry.operator_key_scheme().is_legacy(), version == 1);
}

fn cl_sig(byte: u8, indexes: &[u16]) -> QuorumClSig {
  let mut raw = vec![byte; 96];
  raw.extend(count(indexes.len()));
  for i in indexes {
    raw.extend(i.to_le_bytes());
  }
  QuorumClSig::decode(&mut &raw[..]).unwrap()
}

#[rstest]
fn cl_sigs_are_kept_in_wire_order() {
  // Core's map order and repeated keys depend on how its BLS wrapper reads
  // each signature, which is the node's to apply.
  let sigs = [cl_sig(9, &[0]), cl_sig(1, &[1]), cl_sig(9, &[2])];
  let mut raw = count(sigs.len());
  for s in &sigs {
    raw.extend(wire(s));
  }
  let read = Vec::<QuorumClSig>::decode(&mut &raw[..]).unwrap();
  assert_eq!(read, sigs);
  assert_eq!(wire(&read), raw);
}

#[rstest]
fn cl_sig_index_sets_are_sorted_and_unique() {
  let sig = cl_sig(7, &[5, 1, 5, 3]);
  assert_eq!(sig.index_set.iter().copied().collect::<Vec<_>>(), [1, 3, 5]);
  assert_eq!(wire(&sig), wire(&cl_sig(7, &[1, 3, 5])));
}

fn qgetdata() -> Vec<u8> {
  let mut out = vec![1];
  out.extend([0x0e; 32]);
  out.extend(3u16.to_le_bytes());
  out.extend([0x0f; 32]);
  out
}

#[rstest]
fn qgetdata_is_refused_over_its_size_and_never_reads_an_error() {
  let raw = qgetdata();
  assert_eq!(raw.len(), QuorumDataRequest::SIZE);
  let msg = decode("qgetdata", &raw, 70242).unwrap();
  assert_eq!(encode(&msg), raw);
  let mut long = raw.clone();
  long.push(0);
  assert!(matches!(
    decode("qgetdata", &long, 70242),
    Err(P2pDecodeError::PayloadTooLarge { size: 68, max: 67, .. })
  ));
  assert!(decode("qgetdata", &raw[..66], 70242).is_err());
}

#[rstest]
#[case::no_error_byte(&[], QuorumDataError::Undefined, &[])]
#[case::error_ignores_the_rest(&[3, 0xaa, 0xbb], QuorumDataError::QuorumNotFound, &[3])]
#[case::undefined_byte(&[0xff], QuorumDataError::Undefined, &[])]
#[case::unknown_code(&[7], QuorumDataError::Unknown(7), &[7])]
#[case::data_follows(&[0, 0xaa, 0xbb], QuorumDataError::None, &[0, 0xaa, 0xbb])]
fn qdata_reads_the_error_as_core_does(#[case] tail: &[u8], #[case] error: QuorumDataError, #[case] written: &[u8]) {
  let mut raw = qgetdata();
  raw.extend(tail);
  let msg = decode("qdata", &raw, 70242).unwrap();
  let P2pMsg::QData(q) = &msg else { panic!("{msg:?}") };
  assert_eq!(q.error, error);
  let mut expected = qgetdata();
  expected.extend(written);
  assert_eq!(encode(&msg), expected);
}

#[rstest]
fn qdata_vectors_are_bounded_before_they_are_read() {
  let mut raw = qgetdata(); // mask 3: vector and contributions
  raw.push(0);
  raw.extend(count(2));
  raw.extend([0u8; 96]);
  raw.extend(count(0));
  let q = QData::decode(&mut &raw[..]).unwrap();
  let data = q.read_data(2, 0).unwrap();
  assert_eq!(data.vvec.unwrap().len(), 2);
  assert_eq!(data.contributions.unwrap().len(), 0);
  assert!(matches!(
    q.read_data(1, 0),
    Err(P2pDecodeError::TooManyEntries { count: 2, max: 1, .. })
  ));
}

#[rstest]
fn spork_signatures_are_limited_on_read_only() {
  let mut raw = vec![0x10, 0x27, 0, 0];
  raw.extend([0u8; 16]);
  for (len, ok) in [(MAX_SPORK_SIG_LEN, true), (MAX_SPORK_SIG_LEN + 1, false)] {
    let mut payload = raw.clone();
    payload.extend(count(len));
    payload.extend(vec![0x30; len]);
    assert_eq!(decode("spork", &payload, 70242).is_ok(), ok, "{len}");
  }
  let long = Spork {
    spork_id: 10001,
    value: 0,
    time_signed: 0,
    sig: vec![0; 70],
  };
  assert_eq!(wire(&long).len(), 20 + 1 + 70);
}

#[rstest]
fn getqrinfo_base_hashes_are_limited_on_read_only() {
  for (n, ok) in [(MAX_QRINFO_BASE_HASHES, true), (MAX_QRINFO_BASE_HASHES + 1, false)] {
    let mut payload = count(n);
    payload.extend(vec![0x11; 32 * n + 32]);
    payload.push(1);
    assert_eq!(GetQrInfo::decode(&mut &payload[..]).is_ok(), ok, "{n}");
  }
}

/// Core reads a flag byte other than 0 or 1 as `true`; base-sdk refuses it.
#[rstest]
#[case::getqrinfo_extra_share("getqrinfo", [count(0), vec![0x11; 32], vec![2]].concat())]
#[case::sml_is_valid("smlentry", sml_entry(1, 0, true).iter().rev().skip(1).rev().copied().chain([2]).collect())]
fn flags_are_read_as_0_or_1(#[case] cmd: &str, #[case] raw: Vec<u8>) {
  let mut canonical = raw.clone();
  *canonical.last_mut().unwrap() = 1;
  let read = |b: &[u8]| match cmd {
    "smlentry" => SimplifiedMnListEntry::decode(&mut &b[..]).is_ok(),
    _ => GetQrInfo::decode(&mut &b[..]).is_ok(),
  };
  assert!(read(&canonical));
  assert!(!read(&raw));
}

#[rstest]
fn platformban_hash_leaves_out_the_signature() {
  let mut raw = vec![0x21; 32];
  raw.extend(1000i32.to_le_bytes());
  raw.extend([0x22; 32]);
  let hash = sha256d::Hash::hash(&raw).to_byte_array();
  raw.extend([0x23; 96]);
  let ban = PlatformBan::decode(&mut &raw[..]).unwrap();
  assert_eq!(ban.signed_hash().to_lendian(), hash);
}

#[rstest]
#[case::known(2, SnapshotSkipMode::NoSkippingEntries)]
#[case::unknown(-5, SnapshotSkipMode::Unknown(-5))]
fn snapshot_skip_mode_reads_any_value(#[case] mode: i32, #[case] expected: SnapshotSkipMode) {
  let mut raw = mode.to_le_bytes().to_vec();
  raw.extend([10, 0xff, 0x03]); // 10 members, all active
  raw.extend(count(2));
  raw.extend(1i32.to_le_bytes());
  raw.extend((-1i32).to_le_bytes());
  let snap = QuorumSnapshot::decode(&mut &raw[..]).unwrap();
  assert_eq!(snap.skip_list_mode, expected);
  assert_eq!(snap.skip_list, [1, -1]);
  assert_eq!(wire(&snap), raw);
}

#[rstest]
fn snapshot_padding_bits_are_refused() {
  let mut raw = 0i32.to_le_bytes().to_vec();
  raw.extend([10, 0xff, 0x07]);
  raw.extend(count(0));
  assert!(QuorumSnapshot::decode(&mut &raw[..]).is_err());
}
