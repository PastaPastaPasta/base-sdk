//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Provider transaction version.

use crate::hash_impl;

use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_type, type_cvrt};

enum_map! {
  /// Provider transaction version.
  #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, TypeId)]
  #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
  #[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
  pub enum ProTxVersion, u16 {
    /// Legacy BLS operator keys.
    LegacyBls = 1 => "legacy_bls",
    /// Basic BLS operator keys.
    BasicBls = 2 => "basic_bls",
    /// Extended network info, owner payouts and collateral shares.
    CoreV24 = 3 => "core_v24",
  }
}

impl BaseCodec for ProTxVersion {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::try_from(u16::decode(data)?)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.to_base().encode(buf);
  }
}

impl_type!(ProTxVersion);

hash_impl!(ProTxVersion);

type_cvrt!(TryFrom<u16> for ProTxVersion, DecodeError, |version| {
  Self::try_from_base(*version).ok_or_else(|| DecodeError::InvalidValue {
    expected: Self::variants().iter().map(|v| u64::from(v.to_base())).collect(),
    actual: u64::from(*version),
  })
});

type_cvrt!(From<ProTxVersion> for u16, |version| version.to_base());
