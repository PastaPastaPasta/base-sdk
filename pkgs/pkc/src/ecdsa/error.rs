//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Error types for secp256k1 operations.

/// Errors produced by secp256k1 operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
pub enum EcdsaError {
  /// public key bytes are not a valid curve point
  #[error("public key bytes are not a valid curve point")]
  InvalidPublicKey,
  /// recovery id is out of range (must be 0..4)
  #[error("recovery id out of range (must be 0..4)")]
  InvalidRecoveryId,
  /// secret key bytes are not a valid scalar
  #[error("secret key bytes are not a valid scalar")]
  InvalidSecretKey,
  /// signature bytes are malformed
  #[error("signature bytes are malformed")]
  InvalidSignature,
  /// tweak is not below the order, or the result is zero or infinity
  #[error("tweak is not below the order, or the result is zero or infinity")]
  InvalidTweak,
  /// DER-encoded private key has invalid structure
  #[error("DER-encoded private key has invalid structure")]
  MalformedDer,
  /// recovery failed; no valid public key for this signature and message
  #[error("recovery failed; no valid public key")]
  RecoveryFailed,
  /// signature verification failed
  #[error("signature verification failed")]
  VerifyFailed,
}
