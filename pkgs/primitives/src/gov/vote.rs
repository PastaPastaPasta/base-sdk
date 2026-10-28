//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance votes.

use crate::prelude::*;
use crate::sign::{message_digest, sha256d as hash256, verify_bls, verify_compact};
use crate::transaction::OutPoint;
use crate::{codec_base, hash_impl, TxHash};

use dash_num::Hash256;
use dash_pkc::bls::{BlsError, BlsPkBytes, BlsScIetf, BlsSigBytes, BLS_SIG_LEN};
use dash_pkc::ecdsa::{EcdsaError, ECDSA_REC_SIG_LEN};
use dash_script::PubKeyHash;
use dash_types::codec::BaseCodec;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, ArrayBuf, Hashable, Numeric, Signable};

enum_map! {
  /// Governance vote outcome.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum VoteOutcome, u32, Unknown {
    /// No vote cast.
    None = 0 => "none",
    /// Vote in favour.
    Yes = 1 => "yes",
    /// Vote against.
    No = 2 => "no",
    /// Abstention.
    Abstain = 3 => "abstain",
  }
}

impl_num!(VoteOutcome, u32);

hash_impl!(VoteOutcome);

enum_map! {
  /// Governance vote signal type.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum VoteSignal, u32, Unknown {
    /// No signal.
    None = 0 => "none",
    /// Fund this object.
    Funding = 1 => "funding",
    /// Object checks out.
    Valid = 2 => "valid",
    /// Object should be deleted.
    Delete = 3 => "delete",
    /// Officially endorsed.
    Endorsed = 4 => "endorsed",
  }
}

impl_num!(VoteSignal, u32);

hash_impl!(VoteSignal);

/// Message signed by ECDSA governance vote.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum GovVoteEcdsaSer {
  /// The vote hash.
  VoteHash,
  /// The signature string.
  SignatureString,
}

/// A governance vote signed with a masternode's BLS operator key.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
// TODO(kwvg): Unify common fields of GovVoteBls and GovVoteEcdsa.
pub struct GovVoteBls {
  /// Voting masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: TxHash,
  /// Vote outcome.
  pub outcome: VoteOutcome,
  /// Vote signal type.
  pub signal: VoteSignal,
  /// Vote timestamp.
  pub time: i64,
  /// Signature bytes, `None` when unsigned.
  pub sig: Option<BlsSigBytes>,
}

impl Signable for GovVoteBls {
  type Key = BlsPkBytes;
  type Context = ();
  type Error = BlsError;

  fn payload(&self, _ctx: &()) -> Vec<u8> {
    let mut buf = Vec::new();
    self.masternode_outpoint.encode(&mut buf);
    self.parent_hash.encode(&mut buf);
    self.outcome.encode(&mut buf);
    self.signal.encode(&mut buf);
    self.time.encode(&mut buf);
    hash256(&buf).to_vec()
  }

  fn set_signature(&mut self, sig: &[u8], key: &BlsPkBytes, ctx: &()) -> Result<(), BlsError> {
    let sig = <[u8; BLS_SIG_LEN]>::try_from(sig).map_err(|_| BlsError::InvalidSignature)?;
    let sig = BlsSigBytes::from_bytes(sig);
    verify_bls::<BlsScIetf>(&self.payload(ctx), &sig, key)?;
    self.sig = Some(sig);
    Ok(())
  }

  fn reset_signature(&mut self) {
    self.sig = None;
  }

  fn verify(&self, key: &BlsPkBytes, ctx: &()) -> Option<BlsError> {
    let sig = self.sig.as_ref().ok_or(BlsError::InvalidSignature);
    sig
      .and_then(|sig| verify_bls::<BlsScIetf>(&self.payload(ctx), sig, key))
      .err()
  }
}

/// A governance vote signed with a masternode's ECDSA voting key.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovVoteEcdsa {
  /// Voting masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: TxHash,
  /// Vote outcome.
  pub outcome: VoteOutcome,
  /// Vote signal type.
  pub signal: VoteSignal,
  /// Vote timestamp.
  pub time: i64,
  /// Compact recoverable signature, `None` when unsigned.
  #[cfg_attr(feature = "serde", serde(with = "crate::provider::compact_hex"))]
  pub sig: Option<[u8; ECDSA_REC_SIG_LEN]>,
}

impl Signable for GovVoteEcdsa {
  type Key = PubKeyHash;
  type Context = GovVoteEcdsaSer;
  type Error = EcdsaError;

  fn payload(&self, ctx: &GovVoteEcdsaSer) -> Vec<u8> {
    match ctx {
      // Hash of the vote without the signature.
      GovVoteEcdsaSer::VoteHash => {
        let mut buf = Vec::new();
        self.masternode_outpoint.encode(&mut buf);
        self.parent_hash.encode(&mut buf);
        self.outcome.encode(&mut buf);
        self.signal.encode(&mut buf);
        self.time.encode(&mut buf);
        hash256(&buf).to_vec()
      }
      GovVoteEcdsaSer::SignatureString => {
        let msg = format!(
          "{}-{}|{}|{}|{}|{}",
          self.masternode_outpoint.hash,
          self.masternode_outpoint.index,
          self.parent_hash,
          self.signal.to_base() as i32,
          self.outcome.to_base() as i32,
          self.time,
        );
        message_digest(msg.as_bytes()).to_vec()
      }
    }
  }

  fn set_signature(&mut self, sig: &[u8], key: &PubKeyHash, ctx: &GovVoteEcdsaSer) -> Result<(), EcdsaError> {
    let sig = <[u8; ECDSA_REC_SIG_LEN]>::try_from(sig).map_err(|_| EcdsaError::InvalidSignature)?;
    verify_compact(&self.payload(ctx), &sig, key)?;
    self.sig = Some(sig);
    Ok(())
  }

  fn reset_signature(&mut self) {
    self.sig = None;
  }

  fn verify(&self, key: &PubKeyHash, ctx: &GovVoteEcdsaSer) -> Option<EcdsaError> {
    let sig = self.sig.as_ref().ok_or(EcdsaError::InvalidSignature);
    sig.and_then(|sig| verify_compact(&self.payload(ctx), sig, key)).err()
  }
}

/// A governance vote.
///
/// ```text
/// masternode_outpoint(36) || parent_hash(32)
/// || outcome(u32) || signal(u32) || time(i64)
/// || sig(CompactSize + bytes)
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovVote {
  /// Voting masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: TxHash,
  /// Vote outcome.
  pub outcome: VoteOutcome,
  /// Vote signal type.
  pub signal: VoteSignal,
  /// Vote timestamp.
  pub time: i64,
  /// Signature bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

codec_base!(GovVote {
  masternode_outpoint,
  parent_hash,
  outcome,
  signal,
  time,
  sig,
});

impl Hashable for GovVote {
  type Hash = Hash256;

  /// Computes the canonical vote hash, including dummy padding after the
  /// outpoint for legacy compatibility.
  fn hash(&self) -> Hash256 {
    let mut buf = ArrayBuf::<89>::new();
    // outpoint + dummy padding for legacy hash compat
    self.masternode_outpoint.hash.encode(&mut buf);
    self.masternode_outpoint.index.encode(&mut buf);
    0u8.encode(&mut buf);
    0xFFFF_FFFFu32.encode(&mut buf);
    self.parent_hash.encode(&mut buf);
    self.signal.encode(&mut buf);
    self.outcome.encode(&mut buf);
    self.time.encode(&mut buf);

    Hash256::from_lendian(hash256(&buf.into_array()))
  }
}

impl GovVote {
  /// Core's `GetSignatureHash()`: the vote as written without its
  /// signature, outcome before signal. A BLS vote signature signs it, and
  /// an ECDSA one on testnet only; elsewhere Core verifies an ECDSA vote
  /// signature over its message string (`GetSignatureString()`), not this.
  pub fn signature_hash(&self) -> Hash256 {
    let mut buf = ArrayBuf::<84>::new();
    self.masternode_outpoint.encode(&mut buf);
    self.parent_hash.encode(&mut buf);
    self.outcome.encode(&mut buf);
    self.signal.encode(&mut buf);
    self.time.encode(&mut buf);
    Hash256::from_lendian(hash256(&buf.into_array()))
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::sign::tests::{bls_sign, ecdsa_sign};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use dash_pkc::bls::BlsScChia;
  use rstest::rstest;

  #[rstest]
  fn corpus_govobjvote() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobjvote");
    let items = corpus.entries::<GovVote>("govobjvote", check_wire);
    assert_serde_rt("govobjvote", &items);
  }

  #[rstest]
  fn bls_vote_signs_under_the_basic_scheme() {
    let mut vote = GovVoteBls {
      masternode_outpoint: OutPoint {
        hash: TxHash::from([0x11; 32]),
        index: 3,
      },
      parent_hash: TxHash::from([0x22; 32]),
      outcome: VoteOutcome::Yes,
      signal: VoteSignal::Funding,
      time: 1_700_000_000,
      sig: None,
    };
    let digest = <[u8; 32]>::try_from(vote.payload(&())).unwrap();
    let (legacy_key, legacy_sig) = bls_sign::<BlsScChia>(1, &digest);
    let (key, sig) = bls_sign::<BlsScIetf>(1, &digest);

    assert!(vote.set_signature(&legacy_sig, &legacy_key, &()).is_err());
    assert_eq!(vote.set_signature(&sig, &key, &()), Ok(()));

    vote.reset_signature();
    assert_eq!(vote.verify(&key, &()), Some(BlsError::InvalidSignature));
  }

  #[rstest]
  #[case::signature_string(GovVoteEcdsaSer::SignatureString)]
  #[case::vote_hash(GovVoteEcdsaSer::VoteHash)]
  fn ecdsa_vote_signs_the_payload(#[case] ctx: GovVoteEcdsaSer) {
    let mut vote = GovVoteEcdsa {
      masternode_outpoint: OutPoint {
        hash: TxHash::from([0x11; 32]),
        index: 3,
      },
      parent_hash: TxHash::from([0x22; 32]),
      outcome: VoteOutcome::Yes,
      signal: VoteSignal::Funding,
      time: 1_700_000_000,
      sig: None,
    };
    let digest = <[u8; 32]>::try_from(vote.payload(&ctx)).unwrap();
    let (key, sig) = ecdsa_sign(1, &digest);

    assert_eq!(vote.set_signature(&sig, &key, &ctx), Ok(()));
    assert_eq!(vote.verify(&key, &ctx), None);

    vote.reset_signature();
    assert_eq!(vote.verify(&key, &ctx), Some(EcdsaError::InvalidSignature));
  }
}
