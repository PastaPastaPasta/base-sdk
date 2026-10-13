//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ECDSA types for the secp256k1 curve.

mod error;
mod public_bytes;
mod public_hash;
#[cfg_attr(feature = "codec", expect(unsafe_code, reason = "buffer zeroization"))] // nosemgrep: pkc-no-unsafe-code
mod secret_bytes;
mod sig_bytes;
mod sig_rec_bytes;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

pub use error::EcdsaError;
pub use public_bytes::{EcdsaPkBytes, ECDSA_PK_LEN};
pub use public_hash::EcdsaPkHash;
pub use secret_bytes::{EcdsaSkBytes, ECDSA_SK_LEN};
pub use sig_bytes::{EcdsaSigBytes, ECDSA_SIG_LEN};
pub use sig_rec_bytes::{EcdsaRecSigBytes, ECDSA_REC_SIG_LEN};

/// Whether a key's public counterpart serializes in compressed (33-byte) or
/// uncompressed (65-byte) SEC1 form.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum Compression {
  /// The public key serializes compressed.
  Compressed,
  /// The public key serializes uncompressed.
  Uncompressed,
}

impl Compression {
  /// Whether this is the compressed form.
  pub const fn is_compressed(self) -> bool {
    matches!(self, Self::Compressed)
  }
}

impl From<bool> for Compression {
  fn from(compressed: bool) -> Self {
    if compressed {
      Self::Compressed
    } else {
      Self::Uncompressed
    }
  }
}

cfg_if::cfg_if! {
  if #[cfg(feature = "ecdsa")] {
    #[allow(dead_code, reason = "curve constants")]
    mod curve_consts;
    mod public_ops;
    mod secret_ops;
    mod sig_ops;
    mod sig_rec_ops;
    #[cfg(test)]
    #[expect(clippy::unwrap_used, reason = "test code")]
    #[allow(dead_code, reason = "usage dependent on build flags")]
    pub(crate) mod tests;

    pub use public_ops::EcdsaPublicKey;
    pub use secret_ops::EcdsaSecretKey;
    pub use sig_ops::{EcdsaDerSig, EcdsaSignature};
    pub use sig_rec_ops::EcdsaRecSignature;
  }
}
