//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core's reads of the DKG and signature share messages against
//! base-sdk's.

#![cfg(feature = "serde")]
#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_num::Hash256;
use dash_p2p_core::{
  dkg_inventory_hash, dkg_quorum, CommandString, DkgComplaint, DkgContribution, DkgJustification, DkgMessage,
  DkgPrematureCommitment, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion,
};
use dash_params::LlmqParams;
use dash_pkc::bls::{BlsCtx, BlsDecodeError};
use dash_primitives::LlmqType;
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
  legacy: bool,
  /// A DKG message's quorum: size, minimum size, threshold.
  quorum: [i32; 3],
  raw: Raw,
  core: Core,
}

#[derive(::serde::Deserialize)]
struct Core {
  ok: bool,
  consumed: Option<usize>,
  reenc: Option<String>,
  class: Option<String>,
  /// A DKG message's inventory hash.
  hash: Option<String>,
  /// The sign hashes Core computes, concatenated.
  #[serde(rename = "signHash")]
  sign_hash: Option<String>,
}

/// Where base-sdk refused a payload, as Core's handlers order their checks:
/// the size checks, a DKG message's walk, then the read.
#[derive(Debug, PartialEq)]
enum Stage {
  Oversized,
  Framing,
  Read,
}

/// The bytes base-sdk read, what it writes back and its hashes.
struct Read {
  consumed: usize,
  reenc: Vec<u8>,
  hash: Option<[u8; 32]>,
  sign_hash: Option<Vec<u8>>,
}

fn le(h: Hash256) -> [u8; 32] {
  h.to_lendian()
}

fn params(quorum: [i32; 3]) -> LlmqParams {
  let mut p = *LlmqParams::available(LlmqType::LlmqTest).unwrap();
  [p.size, p.min_size, p.threshold] = quorum;
  p
}

/// Core's DKG handler checks, before the worker's read.
fn dkg_checks(c: &Case, raw: &[u8]) -> Result<(), Stage> {
  let check: fn(&[u8], &LlmqParams) -> Result<(), P2pDecodeError> = match c.command.as_str() {
    "qcontrib" => DkgContribution::check_payload,
    "qcomplaint" => DkgComplaint::check_payload,
    "qjustify" => DkgJustification::check_payload,
    "qpcommit" => DkgPrematureCommitment::check_payload,
    _ => return Ok(()),
  };
  dkg_quorum(raw).ok_or(Stage::Oversized)?;
  let checked = check(raw, &params(c.quorum));
  match checked {
    Ok(()) => Ok(()),
    Err(P2pDecodeError::HandlerPayloadTooLarge { .. }) => Err(Stage::Oversized),
    Err(P2pDecodeError::DkgFraming { .. }) => Err(Stage::Framing),
    Err(e) => panic!("{}: unexpected check error {e}", c.name),
  }
}

/// A BLS field Core cannot read eagerly fails the worker's read.
impl From<BlsDecodeError> for Stage {
  fn from(_: BlsDecodeError) -> Self {
    Self::Read
  }
}

fn read(c: &Case, raw: &[u8]) -> Result<Read, Stage> {
  dkg_checks(c, raw)?;
  let bls = BlsCtx::from_legacy(c.legacy);
  let ctx = ProtoCtx::new(ProtocolVersion::from_base(70242), bls);
  let d = P2pMsg::decode_with_policy(&CommandString::from_static(&c.command), raw, &ctx).map_err(|e| match e {
    P2pDecodeError::HandlerPayloadTooLarge { .. } => Stage::Oversized,
    _ => Stage::Read,
  })?;
  // Core keys a DKG message by the payload it received, which the read
  // writes back as is, then signs and writes back its eager read.
  let (msg, hash, sign_hash) = match &d.msg {
    P2pMsg::QContrib(m) => {
      let (hash, m) = (m.hash(), m.eager(bls)?);
      let sign_hash = le(m.sign_hash()).to_vec();
      (P2pMsg::QContrib(Box::new(m)), Some(hash), Some(sign_hash))
    }
    P2pMsg::QComplaint(m) => {
      let (hash, m) = (m.hash(), m.eager(bls)?);
      let sign_hash = le(m.sign_hash()).to_vec();
      (P2pMsg::QComplaint(m), Some(hash), Some(sign_hash))
    }
    P2pMsg::QJustify(m) => {
      let (hash, m) = (m.hash(), m.eager(bls)?);
      let sign_hash = le(m.sign_hash()).to_vec();
      (P2pMsg::QJustify(m), Some(hash), Some(sign_hash))
    }
    P2pMsg::QpCommit(m) => {
      let (hash, m) = (m.hash(), m.eager(bls)?);
      let sign_hash = le(m.sign_hash()).to_vec();
      (P2pMsg::QpCommit(m), Some(hash), Some(sign_hash))
    }
    P2pMsg::QSigSesAnn(m) => {
      let sign_hash = m.anns.iter().flat_map(|a| le(a.sign_hash())).collect();
      (d.msg.clone(), None, Some(sign_hash))
    }
    P2pMsg::QSigShare(m) => {
      let sign_hash = m.shares.iter().flat_map(|s| le(s.sign_hash())).collect();
      (d.msg.clone(), None, Some(sign_hash))
    }
    other => (other.clone(), None, None),
  };
  if let Some(hash) = hash {
    assert_eq!(hash, dkg_inventory_hash(raw), "{}: inventory hash", c.name);
  }
  let hash = hash.map(le);
  let mut reenc = Vec::new();
  msg.encode_payload(&mut reenc);
  Ok(Read {
    consumed: d.consumed,
    reenc,
    hash,
    sign_hash,
  })
}

fn cases() -> Vec<Case> {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_overlay_ii").value("cases")
}

#[rstest]
fn dkg_and_sig_share_reads_are_cores() {
  let cases = cases();
  assert!(cases.len() > 400);
  for c in &cases {
    let label = format!("{} ({}, legacy {}, quorum {:?})", c.name, c.command, c.legacy, c.quorum);
    let raw = c.raw.bytes();
    let ours = read(c, &raw);
    match &c.core {
      Core {
        ok: true,
        consumed,
        reenc,
        hash,
        sign_hash,
        ..
      } => {
        let r = ours.unwrap_or_else(|s| panic!("{label}: Core read it, base-sdk refused at {s:?}"));
        assert_eq!(Some(r.consumed), *consumed, "{label}: bytes read");
        assert_eq!(
          r.hash,
          hash.as_deref().map(|h| decode_to_array::<32>(h).unwrap()),
          "{label}: hash"
        );
        // Core writes back what it read, but for an eager BLS field
        // (canonical or zeros) and an AUTOBITSET (its shorter form).
        let written = reenc
          .as_deref()
          .map_or_else(|| raw[..r.consumed].to_vec(), vec_from_hex);
        assert_eq!(r.reenc, written, "{label}: write-back");
        assert_eq!(
          r.sign_hash,
          sign_hash.as_deref().map(vec_from_hex),
          "{label}: sign hash"
        );
      }
      Core { class, .. } => {
        // Verdicts and, for a DKG message, the stage: the handler scores a
        // refusal before the read apart from a failed read.
        let want = match class.as_deref() {
          Some("oversized") => Stage::Oversized,
          Some("framing") => Stage::Framing,
          _ => Stage::Read,
        };
        match ours {
          Err(s) => assert_eq!(s, want, "{label}: Core refused it ({class:?})"),
          Ok(_) => panic!("{label}: Core refused it ({class:?}), base-sdk read it"),
        }
      }
    }
  }
}
