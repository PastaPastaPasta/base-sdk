//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Masternode messages `mnauth`, `spork` and `platformban`.

use crate::codec::{codec_p2p, impl_p2p, MAX_P2P_PAYLOAD_SIZE};
use crate::prelude::*;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::BlsSigBytes;
use dash_pkc::ecdsa::ECDSA_REC_SIG_LEN;
use dash_primitives::{codec_base, hash_impl, QuorumHash, TxHash};
use dash_types::codec::{decode_vec, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_new, ArrayBuf, Hashable, Numeric};
use getset::{CopyGetters, Getters};

codec_p2p! {
/// Masternode authentication.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnAuth {
  /// Registration transaction hash of the masternode.
  #[getset(get_copy = "pub")]
  pro_reg_tx_hash: TxHash,
  /// BLS signature, as read.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

impl_new! {
/// A spork value.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Spork {
  /// Spork identifier, read as any value.
  #[getset(get_copy = "pub")]
  spork_id: i32,
  /// Spork value.
  #[getset(get_copy = "pub")]
  value: i64,
  /// Time, in seconds since the epoch.
  #[getset(get_copy = "pub")]
  time_signed: i64,
  /// Signature bytes, as read.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  sig: Vec<u8>,
}
}

impl_p2p!(Spork);

impl BaseCodec for Spork {
  /// Decodes a `spork`, reading a signature of at most
  /// [`Spork::MAX_SIG_LEN`] bytes.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      spork_id: i32::decode(data)?,
      value: i64::decode(data)?,
      time_signed: i64::decode(data)?,
      sig: decode_vec(data, Self::MAX_SIG_LEN)?,
    })
  }

  /// Encodes a `spork`, writing a signature of any length.
  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.spork_id.encode(buf);
    self.value.encode(buf);
    self.time_signed.encode(buf);
    self.sig.encode(buf);
  }
}

hash_impl!(Spork);

impl Spork {
  /// The longest signature a `spork` carries, a compact recoverable ECDSA
  /// signature.
  pub const MAX_SIG_LEN: usize = ECDSA_REC_SIG_LEN;
}

impl_new! {
/// A `platformban` message.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct PlatformBan {
  /// Registration transaction hash of the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Requested height.
  #[getset(get_copy = "pub")]
  requested_height: i32,
  /// Quorum hash.
  #[getset(get_copy = "pub")]
  quorum_hash: QuorumHash,
  /// BLS signature, as read.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

codec_base!(PlatformBan, MAX_P2P_PAYLOAD_SIZE, {
  pro_tx_hash,
  requested_height,
  quorum_hash,
  sig
});

impl Hashable for PlatformBan {
  type Hash = Hash256;

  /// The double SHA-256 of the message without its signature.
  fn hash(&self) -> Hash256 {
    let mut buf = ArrayBuf::<68>::new();
    self.pro_tx_hash.encode(&mut buf);
    self.requested_height.encode(&mut buf);
    self.quorum_hash.encode(&mut buf);
    Hash256::from_lendian(sha256d::Hash::hash(buf.as_bytes()).to_byte_array())
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, vec_from_hex, Corpus};
  use dash_types::CompactSize;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct HashVector {
    raw: String,
    hash: Hash256,
  }

  #[derive(Deserialize)]
  struct SigLenVector {
    raw: String,
    sig_len: usize,
    read: bool,
  }

  #[rstest]
  fn corpus_mnauth() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    let items = corpus.entries::<MnAuth>("mnauth", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::MNAUTH, raw);
      assert_eq!(decoded, Ok(P2pMsg::MnAuth(*details)), "{label}: dispatch");
    });
    assert_serde_rt("mnauth", &items);
  }

  #[rstest]
  fn corpus_spork() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    let items = corpus.entries::<Spork>("spork", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::SPORK, raw);
      assert_eq!(decoded, Ok(P2pMsg::Spork(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("spork", &items);
  }

  #[rstest]
  fn corpus_spork_hash() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    for v in corpus.vectors::<HashVector>("spork_hash") {
      let raw = vec_from_hex(&v.raw);
      let spork = Spork::decode(&mut &raw[..]);
      assert_eq!(spork.map(|s| s.hash()), Ok(v.hash), "{}", v.raw);
    }
  }

  #[rstest]
  fn corpus_spork_sig_len() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    for v in corpus.vectors::<SigLenVector>("spork_sig_len") {
      let raw = vec_from_hex(&v.raw);
      let decoded = Spork::decode(&mut &raw[..]);
      if v.read {
        assert_eq!(decoded.map(|s| s.sig.len()), Ok(v.sig_len), "{}", v.raw);
      } else {
        let err = DecodeError::CompactSizeExceedsLimit {
          limit: Spork::MAX_SIG_LEN,
          value: v.sig_len as u64,
        };
        assert_eq!(decoded, Err(err), "{}", v.raw);
      }
    }
  }

  #[rstest]
  #[case::at_limit(Spork::MAX_SIG_LEN, Spork::MAX_SIG_LEN, Ok(Spork::MAX_SIG_LEN))]
  #[case::past_limit(
    Spork::MAX_SIG_LEN + 1,
    Spork::MAX_SIG_LEN + 1,
    Err(DecodeError::CompactSizeExceedsLimit { limit: Spork::MAX_SIG_LEN, value: Spork::MAX_SIG_LEN as u64 + 1 })
  )]
  #[case::past_limit_bare(
    Spork::MAX_SIG_LEN + 1,
    0,
    Err(DecodeError::CompactSizeExceedsLimit { limit: Spork::MAX_SIG_LEN, value: Spork::MAX_SIG_LEN as u64 + 1 })
  )]
  fn sig_lens_are_bounded(#[case] len: usize, #[case] bytes: usize, #[case] expected: Result<usize, DecodeError>) {
    let mut head = Vec::new();
    CompactSize::from(len).encode(&mut head);
    let payload = [&[0x11; 4 + 8 + 8][..], &head, &vec![0x30; bytes]].concat();
    assert_eq!(Spork::decode(&mut &payload[..]).map(|s| s.sig.len()), expected);
  }

  #[rstest]
  fn corpus_platformban() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    let items = corpus.entries::<PlatformBan>("platformban", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::PLATFORMBAN, raw);
      assert_eq!(decoded, Ok(P2pMsg::PlatformBan(*details)), "{label}: dispatch");
    });
    assert_serde_rt("platformban", &items);
  }

  #[rstest]
  fn corpus_platformban_hash() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    for v in corpus.vectors::<HashVector>("platformban_hash") {
      let raw = vec_from_hex(&v.raw);
      let ban = PlatformBan::decode(&mut &raw[..]);
      assert_eq!(ban.map(|b| b.hash()), Ok(v.hash), "{}", v.raw);
    }
  }
}
