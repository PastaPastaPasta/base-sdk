//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS secret key byte bag.

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::{make_sbytes, Hashable, Numeric};

/// Raw BLS secret key length (scalar).
pub const BLS_SK_LEN: usize = 32;

make_sbytes! {
  /// BLS secret key bytes (32 bytes, zeroized on drop).
  BlsSkBytes, BLS_SK_LEN
}

impl Hashable for BlsSkBytes {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_lendian(Sha256d::hash(self.as_bytes()).to_byte_array())
  }
}
