//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProDisTx shared-masternode dissolution payload (type 10, v24).

use super::shares::{self, CompactSig};
use super::sighash::write_tx_header;
use crate::prelude::*;
use crate::{hash_impl, Transaction, TxHash};

use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::impl_type;
use dash_types::type_id::TypeId;

use core::fmt;

/// ProDisTx -- dissolve a shared masternode (type 10, v24).
///
/// Core reads every field whatever the version.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProDisTx {
  /// Payload version.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Index of the share that acts.
  pub actor_index: u16,
  /// One signature (unilateral) or one per share (unanimous).
  pub sigs: Vec<CompactSig>,
}

impl_type!(ProDisTx);

impl BaseCodec for ProDisTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      actor_index: u16::decode(data)?,
      sigs: shares::read_list(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.actor_index.encode(buf);
    shares::write_list(&self.sigs, buf);
  }
}

hash_impl!(ProDisTx);

impl ProDisTx {
  /// The bytes whose SHA256d every dissolution signature signs, Core's
  /// `MakeSignHash`.
  ///
  /// The digest commits to the inputs and outputs of `tx`, the transaction
  /// that carries this payload, and to `sig_count`, which selects the mode
  /// (one signature is unilateral, one per share unanimous). A signer passes
  /// the count the transaction will carry; Core verifies with `sigs.len()`.
  pub fn sig_hash_bytes(&self, tx: &Transaction, sig_count: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    String::from("DashSharedMNDissolve").encode(&mut buf);
    self.version.encode(&mut buf);
    write_tx_header(tx, &mut buf);
    for input in &tx.inputs {
      input.prevout.encode(&mut buf);
    }
    for input in &tx.inputs {
      input.sequence.encode(&mut buf);
    }
    for output in &tx.outputs {
      output.encode(&mut buf);
    }
    self.pro_tx_hash.encode(&mut buf);
    self.actor_index.encode(&mut buf);
    sig_count.encode(&mut buf);
    buf
  }
}

impl fmt::Display for ProDisTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProDisTx {{ v{}, sigs: {} }}", self.version, self.sigs.len())
  }
}
