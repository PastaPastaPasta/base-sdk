//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hashed representation of a BLS public key.

use dash_types::make_bytes;

/// Length of a public key hash.
pub const BLS_PK_HASH_LEN: usize = 32;

make_bytes! { // nosemgrep: bytes-rev-means-hash
  /// 32-byte public key hash.
  BlsPkHash, BLS_PK_HASH_LEN, rev
}

#[cfg(all(test, feature = "bls", feature = "codec"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::tests::RSEED;
  use crate::bls::{BlsPkHash, BlsScChia, BlsScIetf, BlsSecretKey};

  use dash_types::Hashable;
  use rstest::rstest;

  #[rstest]
  fn schemes_diverge_in_pk_hash() {
    let chia = BlsSecretKey::<BlsScChia>::from_ikm(&RSEED[0]).unwrap().public_key();
    let ietf = BlsSecretKey::<BlsScIetf>::from_ikm(&RSEED[0]).unwrap().public_key();

    assert_ne!(chia.to_bytes(), ietf.to_bytes());
    assert_ne!(Hashable::hash(&chia).as_bytes(), Hashable::hash(&ietf).as_bytes());
  }

  #[rstest]
  fn slice_conversion_checks_length() {
    let bytes = [7u8; 33];

    assert_eq!(BlsPkHash::try_from(&bytes[..32]).unwrap().as_bytes(), &[7u8; 32]);
    assert!(BlsPkHash::try_from(&bytes[..]).is_err());
    assert!(BlsPkHash::try_from(&bytes[..31]).is_err());
  }
}
