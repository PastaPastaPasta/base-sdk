//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance votes.

use crate::prelude::*;
use crate::sign::{message_digest, sha256d as hash256, verify_bls, verify_compact};
use crate::transaction::OutPoint;
use crate::{hash_impl, TxHash};

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::{BlsError, BlsPkBytes, BlsScIetf, BlsSigBytes, BLS_SIG_LEN};
use dash_pkc::ecdsa::{EcdsaError, ECDSA_REC_SIG_LEN};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, impl_type, ArrayBuf, CompactSize, Hashable, Numeric, Signable};

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
          self.masternode_outpoint.txid,
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
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum GovVote {
  /// Signed with the BLS operator key.
  Bls(GovVoteBls),
  /// Signed with the ECDSA voting key.
  Ecdsa(GovVoteEcdsa),
}

impl BaseCodec for GovVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let masternode_outpoint = OutPoint::decode(data)?;
    let parent_hash = TxHash::decode(data)?;
    let outcome = VoteOutcome::decode(data)?;
    let signal = VoteSignal::decode(data)?;
    let time = i64::decode(data)?;
    match CompactSize::decode(data)?.into_len(BLS_SIG_LEN)? {
      BLS_SIG_LEN => Ok(Self::Bls(GovVoteBls {
        masternode_outpoint,
        parent_hash,
        outcome,
        signal,
        time,
        sig: Some(BlsSigBytes::decode(data)?),
      })),
      ECDSA_REC_SIG_LEN => Ok(Self::Ecdsa(GovVoteEcdsa {
        masternode_outpoint,
        parent_hash,
        outcome,
        signal,
        time,
        sig: Some(<[u8; ECDSA_REC_SIG_LEN]>::decode(data)?),
      })),
      actual => Err(DecodeError::BadLen {
        expected: vec![ECDSA_REC_SIG_LEN, BLS_SIG_LEN],
        actual,
      }),
    }
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    let (masternode_outpoint, parent_hash, outcome, signal, time) = self.parts();
    masternode_outpoint.encode(buf);
    parent_hash.encode(buf);
    outcome.encode(buf);
    signal.encode(buf);
    time.encode(buf);
    match self {
      Self::Bls(GovVoteBls { sig: Some(sig), .. }) => {
        CompactSize::from(BLS_SIG_LEN).encode(buf);
        sig.encode(buf);
      }
      Self::Ecdsa(GovVoteEcdsa { sig: Some(sig), .. }) => {
        CompactSize::from(ECDSA_REC_SIG_LEN).encode(buf);
        sig.encode(buf);
      }
      // An unsigned vote carries an empty signature.
      Self::Bls(GovVoteBls { sig: None, .. }) | Self::Ecdsa(GovVoteEcdsa { sig: None, .. }) => {
        CompactSize::from(0usize).encode(buf);
      }
    }
  }
}

impl_type!(GovVote);

impl Hashable for GovVote {
  type Hash = Hash256;

  /// Computes the canonical vote hash.
  fn hash(&self) -> Hash256 {
    let (masternode_outpoint, parent_hash, outcome, signal, time) = self.parts();
    let mut buf = ArrayBuf::<89>::new();
    masternode_outpoint.txid.encode(&mut buf);
    masternode_outpoint.index.encode(&mut buf);
    0u8.encode(&mut buf);
    0xFFFF_FFFFu32.encode(&mut buf);
    parent_hash.encode(&mut buf);
    signal.encode(&mut buf);
    outcome.encode(&mut buf);
    time.encode(&mut buf);

    Hash256::from_lendian(sha256d::Hash::hash(&buf.into_array()).to_byte_array())
  }
}

impl GovVote {
  fn parts(&self) -> (&OutPoint, &TxHash, VoteOutcome, VoteSignal, i64) {
    match self {
      Self::Bls(v) => (&v.masternode_outpoint, &v.parent_hash, v.outcome, v.signal, v.time),
      Self::Ecdsa(v) => (&v.masternode_outpoint, &v.parent_hash, v.outcome, v.signal, v.time),
    }
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::sign::tests::{bls_sign, ecdsa_sign};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use dash_pkc::bls::BlsScChia;
  use dash_pkc::ecdsa::EcdsaRecSigBytes;
  use rstest::rstest;

  #[rstest]
  fn corpus_govobjvote() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobjvote");
    let items = corpus.entries::<GovVote>("govobjvote", check_wire);
    assert_serde_rt("govobjvote", &items);
  }

  /// A vote of 84 zero bytes before the signature, then `sig_len` bytes.
  fn vote_wire(sig_len: usize) -> Vec<u8> {
    let mut wire = vec![0; 84];
    CompactSize::from(sig_len).encode(&mut wire);
    wire.resize(wire.len() + sig_len, 0xAB);
    wire
  }

  fn bad_len(actual: usize) -> Result<(), DecodeError> {
    Err(DecodeError::BadLen {
      expected: vec![65, 96],
      actual,
    })
  }

  /// The signature length is capped at 96 and checked for 65 or 96 before the
  /// bytes are read.
  #[rstest]
  #[case::empty(0, bad_len(0))]
  #[case::short_compact(64, bad_len(64))]
  #[case::compact(65, Ok(()))]
  #[case::long_compact(66, bad_len(66))]
  #[case::short_bls(95, bad_len(95))]
  #[case::bls(96, Ok(()))]
  #[case::past_bls(97, Err(DecodeError::CompactSizeExceedsLimit { limit: 96, value: 97 }))]
  fn vote_signatures_decode_at_65_or_96_bytes(#[case] len: usize, #[case] expected: Result<(), DecodeError>) {
    let wire = vote_wire(len);
    let decoded = GovVote::decode(&mut wire.as_slice());
    assert_eq!(decoded.clone().map(|_| ()), expected);
    if let Ok(vote) = decoded {
      let mut buf = Vec::new();
      vote.encode(&mut buf);
      assert_eq!(buf, wire);
    }
  }

  #[rstest]
  #[case::ecdsa(65, true)]
  #[case::bls(96, false)]
  fn vote_variant_follows_signature_length(#[case] sig_len: usize, #[case] ecdsa: bool) {
    let vote = GovVote::decode(&mut vote_wire(sig_len).as_slice()).unwrap();
    assert_eq!(matches!(vote, GovVote::Ecdsa(_)), ecdsa);
  }

  #[rstest]
  fn ecdsa_vote_masks_the_header() {
    let mut wire = vote_wire(65);
    wire[85] = 0;
    let vote = GovVote::decode(&mut wire.as_slice()).unwrap();
    let flags = match &vote {
      GovVote::Ecdsa(GovVoteEcdsa { sig: Some(sig), .. }) => {
        let rec = EcdsaRecSigBytes::from_bytes_mask(*sig);
        Some((rec.recovery_id(), rec.is_compressed()))
      }
      GovVote::Ecdsa(_) | GovVote::Bls(_) => None,
    };
    assert_eq!(flags, Some((1, true)));
  }

  #[rstest]
  fn bls_vote_signs_under_the_basic_scheme() {
    let mut vote = GovVoteBls {
      masternode_outpoint: OutPoint {
        txid: TxHash::from([0x11; 32]),
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
        txid: TxHash::from([0x11; 32]),
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
