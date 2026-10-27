//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRevTx revocation payload (type 4).

use super::sig::verify_operator;
use super::{OperatorSig, ProTxVersion};
use crate::codec::codec_payload;
use crate::prelude::*;
use crate::sign::unsigned_digest;
use crate::sptx::{InputsHash, ProTxInvalid};
use crate::support::RevocationReason;
use crate::TxHash;

use dash_pkc::bls::{BlsError, BlsPkBytes, BlsSigBytes, BLS_SIG_LEN};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, Signable};
use getset::CopyGetters;

use core::fmt;

codec_payload! { @no_new
/// ProUpRevTx -- revoke a masternode (type 4).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpRevTx {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: ProTxVersion,
  /// ProTx hash identifying the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Revocation reason.
  #[getset(get_copy = "pub")]
  reason: RevocationReason,
  /// Hash of all inputs.
  #[getset(get_copy = "pub")]
  inputs_hash: InputsHash,
  /// Operator BLS signature.
  #[getset(get_copy = "pub")]
  sig: OperatorSig,
}
}

impl Signable for ProUpRevTx {
  type Key = BlsPkBytes;
  type Context = ();
  type Error = BlsError;

  fn payload(&self, _ctx: &()) -> Vec<u8> {
    unsigned_digest(self, &self.sig).to_vec()
  }

  fn set_signature(&mut self, sig: &[u8], key: &BlsPkBytes, _ctx: &()) -> Result<(), BlsError> {
    let sig = <[u8; BLS_SIG_LEN]>::try_from(sig).map_err(|_| BlsError::InvalidSignature)?;
    let sig = OperatorSig::new(BlsSigBytes::from_bytes(sig));
    verify_operator(self.version, &self.payload(&()), &sig, key)?;
    self.sig = sig;
    Ok(())
  }

  fn reset_signature(&mut self) {
    self.sig = OperatorSig::default();
  }

  fn verify(&self, key: &BlsPkBytes, _ctx: &()) -> Option<BlsError> {
    verify_operator(self.version, &self.payload(&()), &self.sig, key).err()
  }
}

impl Checkable for ProUpRevTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if matches!(self.reason, RevocationReason::Unknown(_)) {
      return Some(ProTxInvalid::BadReason { reason: self.reason });
    }

    None
  }
}

impl ProUpRevTx {
  /// Constructs an unsigned payload. The signature is set through
  /// [`Signable::set_signature`].
  pub fn new(version: ProTxVersion, pro_tx_hash: TxHash, reason: RevocationReason, inputs_hash: InputsHash) -> Self {
    Self {
      version,
      pro_tx_hash,
      reason,
      inputs_hash,
      sig: OperatorSig::default(),
    }
  }
}

impl fmt::Display for ProUpRevTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRevTx {{ v{} }}", self.version.to_base())
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_prouprevtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prouprevtx");
    let items = corpus.entries::<ProUpRevTx>("prouprevtx", check_sptx);
    assert_serde_rt("prouprevtx", &items);
  }
}
