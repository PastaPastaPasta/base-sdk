//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpSharedRegTx shared registrar-update payload (type 12, v24).

use super::bls;
use super::shares::{self, CompactSig};
use super::InputsHash;
use crate::prelude::*;
use crate::{hash_impl, TxHash};

use dash_pkc::bls::{BlsLazyPk, BlsSchemeKind, BlsSchemeSource};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::impl_type;
use dash_types::type_id::TypeId;

use core::fmt;

/// ProUpSharedRegTx -- update a shared masternode's registrar keys (type 12,
/// v24).
///
/// Core reads every field whatever the version.
#[derive(Clone, Debug, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpSharedRegTx {
  /// Payload version.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Operator BLS public key, decoded on first use, always under the basic
  /// scheme. It encodes as Core serializes a key in use, and as zeros when
  /// invalid, whether or not it was used before.
  #[cfg_attr(feature = "serde", serde(with = "super::bls::serde::lazy_always_basic"))]
  pub pub_key_operator: BlsLazyPk,
  /// Voting key id (20 bytes).
  pub key_id_voting: PubKeyHash,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// One signature per share, in share order.
  pub sigs: Vec<CompactSig>,
}

impl_type!(ProUpSharedRegTx);

impl BaseCodec for ProUpSharedRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      pub_key_operator: bls::read_lazy(data, BlsSchemeSource::AlwaysBasic)?,
      key_id_voting: PubKeyHash::decode(data)?,
      inputs_hash: InputsHash::decode(data)?,
      sigs: shares::read_list(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_unsigned(buf);
    shares::write_list(&self.sigs, buf);
  }
}

hash_impl!(ProUpSharedRegTx);

impl ProUpSharedRegTx {
  /// The payload's `SER_GETHASH` serialization, which leaves out the
  /// signatures and their count. Every share owner signs its SHA256d.
  pub fn sig_hash_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.encode_unsigned(&mut buf);
    buf
  }

  /// Every field but the signatures, as [`BaseCodec::encode`] writes them.
  fn encode_unsigned(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    bls::write_lazy(&self.pub_key_operator, BlsSchemeKind::Basic, buf);
    self.key_id_voting.encode(buf);
    self.inputs_hash.encode(buf);
  }
}

impl fmt::Display for ProUpSharedRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpSharedRegTx {{ v{}, sigs: {} }}", self.version, self.sigs.len())
  }
}
