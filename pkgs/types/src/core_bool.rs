//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Single-byte booleans read the way Dash Core reads them.

use crate::codec::{take, BaseCodec, DecodeError, EncodeBuf};
use crate::type_id::TypeId;

use core::fmt;

/// A wire boolean that decodes any non-zero byte as `true`.
///
/// Core assigns the byte to a C++ `bool`, so no byte value is rejected. The
/// encoding is always `0x00` or `0x01`, which is what Core re-serializes, so a
/// non-canonical byte does not survive a round trip.
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(::serde::Deserialize, ::serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, TypeId)]
pub struct CoreBool(pub bool);

impl BaseCodec for CoreBool {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self(take::<1>(data)?[0] != 0))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.push(u8::from(self.0));
  }
}

impl CoreBool {
  /// Returns the boolean value.
  pub const fn get(self) -> bool {
    self.0
  }
}

impl From<bool> for CoreBool {
  fn from(v: bool) -> Self {
    Self(v)
  }
}

impl From<CoreBool> for bool {
  fn from(v: CoreBool) -> Self {
    v.0
  }
}

impl fmt::Display for CoreBool {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Display::fmt(&self.0, f)
  }
}

#[cfg(test)]
mod tests {
  use super::CoreBool;
  use crate::codec::{BaseCodec, DecodeError};
  use crate::prelude::*;

  use rstest::*;

  /// Core's `Unserialize(Stream&, bool&)` assigns the byte (`serialize.h:239`
  /// in v24.0.0-rc.3, `:235` in v23.1.8), so every value decodes. Core
  /// re-serializes the `bool` as 0 or 1. Core's P2P handlers judged `02`
  /// and `ff` (p2p_core `decode_domain` corpus); `80` is from source.
  #[rstest]
  #[case::zero(0x00, false)]
  #[case::one(0x01, true)]
  #[case::two(0x02, true)]
  #[case::high(0x80, true)]
  #[case::max(0xFF, true)]
  fn every_byte_decodes(#[case] byte: u8, #[case] expected: bool) {
    let wire = [byte];
    let mut cursor = &wire[..];
    assert_eq!(CoreBool::decode(&mut cursor), Ok(CoreBool(expected)));
    assert!(cursor.is_empty());
    let mut buf = Vec::new();
    CoreBool(expected).encode(&mut buf);
    assert_eq!(buf, [u8::from(expected)]);
  }

  #[rstest]
  fn empty_input_is_eof() {
    assert_eq!(
      CoreBool::decode(&mut &[][..]),
      Err(DecodeError::Eof {
        needed: 1,
        remaining: 0
      })
    );
  }
}
