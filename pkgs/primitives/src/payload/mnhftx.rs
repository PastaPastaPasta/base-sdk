//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! MnHardFork hard-fork signal (type 7).

use super::bls;
use super::sighash::{request_id, tx_bytes_unsigned};
use crate::prelude::*;
use crate::sptx::QuorumHash;
use crate::{hash_impl, Transaction};

use dash_num::Hash256;
use dash_pkc::bls::{BlsEagerSig, BlsSchemeKind, BlsSchemeSource};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable};

use core::fmt;

/// Number of version bits available for signalling.
pub const VERSIONBITS_NUM_BITS: u8 = 29;

/// Prefix of an MnHF signal's request id, Core's `MNEHF_REQUESTID_PREFIX`.
const MNHF_REQUESTID_PREFIX: &str = "mnhf";

/// MnHardFork -- hard-fork signal (type 7).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MnHardFork {
  /// Payload version.
  pub version: u8,
  /// Feature bit being activated.
  pub version_bit: u8,
  /// Quorum hash.
  pub quorum_hash: QuorumHash,
  /// Quorum BLS signature, always under the basic scheme.
  #[cfg_attr(feature = "serde", serde(with = "super::bls::serde::always_basic"))]
  pub sig: BlsEagerSig,
}

impl_type!(MnHardFork);

impl BaseCodec for MnHardFork {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      version_bit: u8::decode(data)?,
      quorum_hash: QuorumHash::decode(data)?,
      sig: bls::read_eager(data, BlsSchemeSource::AlwaysBasic)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.version_bit.encode(buf);
    self.quorum_hash.encode(buf);
    self.sig.to_bytes(BlsSchemeKind::Basic).encode(buf);
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

hash_impl!(MnHardFork);

impl MnHardFork {
  /// The bytes whose SHA256d is the message hash the quorum signs: `tx`,
  /// the transaction that carries this payload, serialized with the
  /// payload's signature zeroed, as Core's `CheckMNHFTx` hashes it.
  ///
  /// The quorum signs `SignHash(llmqTypeMnhf, quorum_hash, request_id,
  /// message hash)`.
  pub fn sig_hash_bytes(&self, tx: &Transaction) -> Vec<u8> {
    tx_bytes_unsigned(tx, self)
  }

  /// The request id of the signal, Core's `GetRequestId`.
  pub fn request_id(&self) -> Hash256 {
    request_id(MNHF_REQUESTID_PREFIX, &i64::from(self.version_bit))
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
