//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
//

//! SHAvite-3-512 AES rounds on plain words, for software AES.

use crate::aes::scalar::round as table_round;

use core::ops::{BitXor, BitXorAssign};

/// Four state or key words kept in general registers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Lane([u32; 4]);

impl Lane {
  /// Builds the lane from four words in order.
  #[inline(always)]
  pub(super) const fn new(words: [u32; 4]) -> Self {
    Self(words)
  }

  /// Repeats one word four times.
  #[inline(always)]
  pub(super) const fn splat(word: u32) -> Self {
    Self([word; 4])
  }

  /// Returns the words in order.
  #[inline(always)]
  pub(super) const fn to_array(self) -> [u32; 4] {
    self.0
  }
}

impl BitXor for Lane {
  type Output = Self;

  #[inline(always)]
  fn bitxor(self, rhs: Self) -> Self {
    let [a, b, c, d] = self.0;
    let [e, f, g, h] = rhs.0;
    Self([a ^ e, b ^ f, c ^ g, d ^ h])
  }
}

impl BitXorAssign for Lane {
  #[inline(always)]
  fn bitxor_assign(&mut self, rhs: Self) {
    *self = *self ^ rhs;
  }
}

/// Runs SubBytes, ShiftRows and MixColumns, then xors in `key`.
#[inline(always)]
pub(super) fn round(state: Lane, key: Lane) -> Lane {
  Lane(table_round(&state.0, &key.0))
}
