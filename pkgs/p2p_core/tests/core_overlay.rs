//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core's reads of the overlay messages against base-sdk's.

#![cfg(feature = "serde")]
#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_num::Hash256;
use dash_p2p_core::{
  CommandString, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion, QData, QuorumDataError, QuorumDataRequest,
  QuorumSnapshot, SimplifiedMnListEntry,
};
use dash_pkc::bls::BlsCtx;
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::{Hashable, Numeric};
use hex_conservative::decode_to_array;
use rstest::rstest;

/// Hex, or a list of hex and `{"b", "n"}` byte runs (the corpus RLE).
#[derive(::serde::Deserialize)]
#[serde(untagged)]
enum Raw {
  Hex(String),
  Runs(Vec<Run>),
}

#[derive(::serde::Deserialize)]
#[serde(untagged)]
enum Run {
  Hex(String),
  Repeat { b: String, n: usize },
}

impl Raw {
  fn bytes(&self) -> Vec<u8> {
    match self {
      Self::Hex(h) => vec_from_hex(h),
      Self::Runs(runs) => runs
        .iter()
        .flat_map(|r| match r {
          Run::Hex(h) => vec_from_hex(h),
          Run::Repeat { b, n } => vec![vec_from_hex(b)[0]; *n],
        })
        .collect(),
    }
  }
}

#[derive(::serde::Deserialize)]
struct Case {
  name: String,
  command: String,
  version: i32,
  legacy: bool,
  max: [usize; 2],
  raw: Raw,
  core: Core,
  strict: Option<String>,
}

#[derive(::serde::Deserialize)]
struct Core {
  ok: bool,
  consumed: Option<usize>,
  reenc: Option<String>,
  class: Option<String>,
  #[serde(rename = "errorCode")]
  error_code: Option<u8>,
  /// A verification vector's size, where it is not the threshold.
  #[serde(rename = "vvecSize")]
  vvec_size: Option<usize>,
  /// The hash Core keys the object by, where it hashes one.
  hash: Option<String>,
}

/// The bytes base-sdk read, what it writes back for them and its hash of
/// the object.
struct Read {
  consumed: usize,
  reenc: Vec<u8>,
  error_code: Option<u8>,
  vvec_size: Option<usize>,
  hash: Option<[u8; 32]>,
}

impl Read {
  fn plain(consumed: usize, reenc: Vec<u8>) -> Self {
    Self {
      consumed,
      reenc,
      error_code: None,
      vvec_size: None,
      hash: None,
    }
  }

  fn hashed(consumed: usize, reenc: Vec<u8>, obj: &impl Hashable<Hash = Hash256>) -> Self {
    Self {
      hash: Some(obj.hash().to_lendian()),
      ..Self::plain(consumed, reenc)
    }
  }
}

fn wire<T: BaseCodec>(value: &T) -> Vec<u8> {
  let mut out = Vec::new();
  value.encode(&mut out);
  out
}

/// `qdata` as Core reads it: the request, the error byte when there is one,
/// then the data the mask asks for when the error is `None`.
fn read_qdata(q: &QData, raw_len: usize, max: [usize; 2]) -> Result<Read, P2pDecodeError> {
  let mut reenc = wire(&q.request);
  if q.error != QuorumDataError::Undefined {
    reenc.push(q.error.to_base());
  }
  let error_code = Some(q.error.to_base());
  if q.error != QuorumDataError::None {
    return Ok(Read {
      error_code,
      ..Read::plain(raw_len.min(QuorumDataRequest::SIZE + 1), reenc)
    });
  }
  let data = q.read_data(max[0], max[1])?;
  let mut vvec_size = None;
  if let Some(vvec) = &data.vvec {
    vvec_size = Some(vvec.len()).filter(|&n| n != max[0]);
    vvec.encode(&mut reenc);
  }
  if let Some(contributions) = &data.contributions {
    contributions.encode(&mut reenc);
  }
  // Every data field has one width: the bytes read are the bytes written.
  Ok(Read {
    error_code,
    vvec_size,
    ..Read::plain(reenc.len(), reenc)
  })
}

fn read(c: &Case, raw: &[u8]) -> Result<Read, P2pDecodeError> {
  let mut data = raw;
  match c.command.as_str() {
    "smlentry" => {
      let versioned = c.version >= ProtocolVersion::SMNLE_VERSIONED.to_base();
      let e = SimplifiedMnListEntry::decode_as(&mut data, versioned)?;
      let mut reenc = Vec::new();
      e.encode_as(&mut reenc, versioned);
      return Ok(Read::hashed(raw.len() - data.len(), reenc, &e));
    }
    "qsnapshot" => {
      let s = QuorumSnapshot::decode(&mut data)?;
      return Ok(Read::plain(raw.len() - data.len(), wire(&s)));
    }
    _ => {}
  }
  let ctx = ProtoCtx::new(ProtocolVersion::from_base(c.version), BlsCtx::from_legacy(c.legacy));
  let d = P2pMsg::decode_with_policy(&CommandString::from_static(&c.command), raw, &ctx)?;
  if let P2pMsg::QData(q) = &d.msg {
    return read_qdata(q, raw.len(), c.max);
  }
  let mut reenc = Vec::new();
  d.msg.encode_payload(&mut reenc);
  Ok(match &d.msg {
    P2pMsg::ClSig(m) => Read::hashed(d.consumed, reenc, m),
    P2pMsg::IsdLock(m) => Read::hashed(d.consumed, reenc, m),
    P2pMsg::QSigRec(m) => Read::hashed(d.consumed, reenc, m),
    P2pMsg::QfCommit(m) => Read::hashed(d.consumed, reenc, m.as_ref()),
    P2pMsg::Spork(m) => Read::hashed(d.consumed, reenc, m),
    P2pMsg::PlatformBan(m) => Read::hashed(d.consumed, reenc, m),
    _ => Read::plain(d.consumed, reenc),
  })
}

fn cases() -> Vec<Case> {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_overlay").value("cases")
}

#[rstest]
fn overlay_reads_are_cores() {
  let cases = cases();
  assert!(cases.len() > 150);
  for c in &cases {
    let label = format!("{} ({} at {}, legacy {})", c.name, c.command, c.version, c.legacy);
    let raw = c.raw.bytes();
    let ours = read(c, &raw);
    match (&c.core, c.strict.as_deref()) {
      // BSX A-12: a flag is 0 or 1; Core reads any other byte as `true`.
      (Core { ok: true, .. }, Some("flag")) => {
        assert!(
          matches!(
            &ours,
            Err(P2pDecodeError::Consensus(DecodeError::NonCanonicalBool { .. }))
          ),
          "{label}: {:?}",
          ours.err()
        );
      }
      (
        Core {
          ok: true,
          consumed,
          reenc,
          error_code,
          vvec_size,
          hash,
          ..
        },
        _,
      ) => {
        let r = ours.unwrap_or_else(|e| panic!("{label}: Core read it, base-sdk: {e}"));
        assert_eq!(Some(r.consumed), *consumed, "{label}: bytes read");
        assert_eq!((r.error_code, r.vvec_size), (*error_code, *vvec_size), "{label}: qdata");
        // Core writes back an eager BLS field or the cbTx under its own
        // rules, most of which live node-side; otherwise it writes what it
        // read. A commitment's BLS fields and an entry's address list are
        // base-sdk's to write as Core does.
        let core_reenc = reenc.as_deref().map(vec_from_hex);
        match &core_reenc {
          None => assert_eq!(r.reenc, raw[..r.consumed], "{label}: write-back"),
          Some(w) if ["qfcommit", "smlentry"].contains(&c.command.as_str()) => {
            assert_eq!(&r.reenc, w, "{label}: write-back");
          }
          Some(_) => {}
        }
        // Core hashes the object as base-sdk does, except a ChainLock whose
        // signature it re-serialized, which the node normalizes first.
        if core_reenc.is_none() || c.command != "clsig" {
          let hash = hash.as_deref().map(|h| decode_to_array::<32>(h).unwrap());
          assert_eq!(r.hash, hash, "{label}: hash");
        }
      }
      (
        Core {
          ok: false,
          class: Some(class),
          ..
        },
        _,
      ) if class == "malleable" => {
        // A commitment's keys and signatures go through the BLS wire-form
        // classifier, as Core reads them; other BLS fields are bytes here,
        // classified node-side. In a diff, which field Core refused is the
        // differential's to check (rust-dashcore contrib/node/dde-probe/bs8).
        let refused = matches!(ours, Err(P2pDecodeError::Consensus(DecodeError::MalleableBls)));
        assert!(
          refused || (c.command != "qfcommit" && ours.is_ok()),
          "{label}: {:?}",
          ours.err()
        );
      }
      (Core { ok: false, class, .. }, _) => {
        assert!(ours.is_err(), "{label}: Core refused it ({class:?}), base-sdk read it");
      }
    }
  }
}

#[rstest]
fn too_long_and_too_many_are_typed() {
  let cases: Vec<Case> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_overlay").value("cases");
  let oversized = cases
    .iter()
    .find(|c| c.core.class.as_deref() == Some("oversized"))
    .unwrap();
  let ctx = ProtoCtx::new(ProtocolVersion::from_base(oversized.version), BlsCtx::BASIC);
  let r = P2pMsg::decode_with_policy(&CommandString::from_static("qgetdata"), &oversized.raw.bytes(), &ctx);
  assert!(matches!(r, Err(P2pDecodeError::HandlerPayloadTooLarge { .. })), "{r:?}");
}
