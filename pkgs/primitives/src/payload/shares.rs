//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Owner payouts and shared collaterals of v24 provider payloads.
//!
//! Core frames these lists with a one-byte count, not a CompactSize.

use crate::prelude::*;
use crate::{codec_type, hash_impl};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::make_bytes;
use dash_types::type_id::TypeId;

/// Length of a compact recoverable ECDSA signature.
pub const COMPACT_SIG_LEN: usize = 65;

make_bytes! {
  /// A compact recoverable ECDSA signature, Core's `CompactSignature`: 65 raw
  /// bytes with no length prefix, unvalidated.
  CompactSig, COMPACT_SIG_LEN
}

hash_impl!(CompactSig);

/// An owner payout of a version-3 provider payload, Core's
/// `MasternodePayoutShare`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct PayoutShare {
  /// Payout script.
  pub script_payout: ScriptPubKeyBuf,
  /// Share of the owner reward in basis points.
  pub reward: u16,
}

codec_type!(PayoutShare { script_payout, reward });

/// One participant of a shared collateral, Core's `CCollateralShare`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CollateralShare {
  /// Collateral contributed, in duffs (Core's `CAmount`, any value decodes).
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::duffs"))]
  pub amount: i64,
  /// Script the contribution is refunded to.
  pub script_refund: ScriptPubKeyBuf,
  /// Script owner rewards are paid to; empty means the refund script.
  pub script_reward: ScriptPubKeyBuf,
  /// Owner key id of this participant.
  pub key_id_owner: PubKeyHash,
}

codec_type!(CollateralShare {
  amount,
  script_refund,
  script_reward,
  key_id_owner,
});

/// Reads `count` items, as Core resizes its vector to a one-byte count read
/// before.
///
/// # Errors
///
/// Returns a `DecodeError` when an item does not decode.
pub(crate) fn read_items<T: BaseCodec>(data: &mut &[u8], count: u8) -> Result<Vec<T>, DecodeError> {
  let mut items = Vec::with_capacity(usize::from(count));
  for _ in 0..count {
    items.push(T::decode(data)?);
  }
  Ok(items)
}

/// Reads a one-byte count and that many items.
///
/// # Errors
///
/// Returns a `DecodeError` when the count or an item does not decode.
pub(crate) fn read_list<T: BaseCodec>(data: &mut &[u8]) -> Result<Vec<T>, DecodeError> {
  let count = u8::decode(data)?;
  read_items(data, count)
}

/// Writes Core's one-byte count, the length cast to `uint8_t`.
pub(crate) fn write_count<T>(items: &[T], buf: &mut impl EncodeBuf) {
  (items.len() as u8).encode(buf);
}

/// Writes items with no count.
pub(crate) fn write_items<T: BaseCodec>(items: &[T], buf: &mut impl EncodeBuf) {
  for item in items {
    item.encode(buf);
  }
}

/// Writes a one-byte count and the items, as Core does.
///
/// Like Core, it writes every item after a count that wraps above 255.
pub(crate) fn write_list<T: BaseCodec>(items: &[T], buf: &mut impl EncodeBuf) {
  write_count(items, buf);
  write_items(items, buf);
}
