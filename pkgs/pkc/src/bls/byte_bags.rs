//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS public and secret key byte bags.

use super::public_hash::BlsPkHash;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::{make_bytes, make_sbytes, Hashable, Numeric};

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Raw BLS secret key length (scalar).
pub const BLS_SK_LEN: usize = 32;

make_bytes! {
  /// BLS public key bytes (48 bytes, unvalidated).
  BlsPkBytes, BLS_PK_LEN
}

impl Hashable for BlsPkBytes {
  type Hash = BlsPkHash;

  fn hash(&self) -> Self::Hash {
    BlsPkHash::from_bytes(Sha256d::hash(self.as_bytes()).to_byte_array())
  }
}

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
