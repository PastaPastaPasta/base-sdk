//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! MnHardFork hard-fork signal (type 7).

use crate::codec::codec_payload;
use crate::sign::{llmq_sig_hash, request_id, tx_hash_with};
use crate::sptx::QuorumHash;
use crate::Transaction;

use dash_num::Hash256;
use dash_params::LlmqType;
use dash_pkc::bls::BlsSigBytes;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::Checkable;
use getset::CopyGetters;

use core::fmt;

/// Number of version bits available for signalling.
pub const VERSIONBITS_NUM_BITS: u8 = 29;

/// Prefix of the request id of a signal.
const REQUEST_ID_PREFIX: &str = "mnhf";

codec_payload! {
/// MnHardFork -- hard-fork signal (type 7).
#[derive(Clone, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MnHardFork {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: u8,
  /// Feature bit being activated.
  #[getset(get_copy = "pub")]
  version_bit: u8,
  /// Quorum hash.
  #[getset(get_copy = "pub")]
  quorum_hash: QuorumHash,
  /// Quorum BLS signature.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

/// MNHF signal validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum MnHardForkInvalid {
  /// `bad-mnhf-version`
  #[error("bad-mnhf-version: {version}")]
  BadVersion { version: u8 },
  /// `bad-mnhf-nbit-out-of-bounds`
  #[error("bad-mnhf-nbit-out-of-bounds: {bit}")]
  VersionBitOutOfBounds { bit: u8 },
}

impl Checkable for MnHardFork {
  type Error = MnHardForkInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 1 {
      return Some(MnHardForkInvalid::BadVersion { version: self.version });
    }

    if self.version_bit >= VERSIONBITS_NUM_BITS {
      return Some(MnHardForkInvalid::VersionBitOutOfBounds { bit: self.version_bit });
    }

    None
  }
}

impl MnHardFork {
  /// The id of the signing request, from the version bit.
  pub fn request_id(&self) -> Hash256 {
    request_id(REQUEST_ID_PREFIX, &i64::from(self.version_bit))
  }

  /// The message hash the quorum signs for this payload carried by `tx`.
  pub fn msg_hash(&self, tx: &Transaction) -> Hash256 {
    let unsigned = Self {
      sig: BlsSigBytes::default(),
      ..self.clone()
    };
    tx_hash_with(tx, &unsigned)
  }

  /// The digest the signing quorum of `llmq_type` signs for this payload
  /// carried by `tx`.
  pub fn sig_hash(&self, tx: &Transaction, llmq_type: LlmqType) -> Hash256 {
    llmq_sig_hash(llmq_type, &self.quorum_hash, &self.request_id(), &self.msg_hash(tx))
  }
}

impl fmt::Display for MnHardFork {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "MnHardFork {{ v{}, bit: {} }}", self.version, self.version_bit,)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_mnhftx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "mnhftx");
    let items = corpus.entries::<MnHardFork>("mnhftx", check_sptx);
    assert_serde_rt("mnhftx", &items);
  }
}
