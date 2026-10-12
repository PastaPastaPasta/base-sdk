//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Error type for BLS operations.

/// Errors produced by BLS operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum BlsError {
  /// paired input counts do not match
  #[error("paired input counts differ")]
  CountMismatch,
  /// repeated message in a distinct-message aggregate
  #[error("repeated message in a distinct-message aggregate")]
  DuplicateMessage,
  /// duplicate share id in recovery set
  #[error("duplicate share id in recovery set")]
  DuplicateShareId,
  /// no items provided for aggregation
  #[error("no items provided for aggregation")]
  EmptyAggregation,
  /// recipient index past the end of the message
  #[error("recipient index past the end of the message")]
  IndexOutOfRange,
  /// recipient index above the supported maximum
  #[error("recipient index above the supported maximum")]
  IndexTooLarge,
  /// fewer than two master keys to evaluate a share
  #[error("fewer than two master keys to evaluate a share")]
  InsufficientCoefficients,
  /// not enough shares to recover
  #[error("not enough shares to recover")]
  InsufficientShares,
  /// ciphertext is empty or not a whole number of cipher blocks
  #[error("ciphertext is empty or not a whole number of cipher blocks")]
  InvalidCiphertextLength,
  /// initialisation vector seed is all zeroes
  #[error("initialisation vector seed is all zeroes")]
  InvalidIvSeed,
  /// input keying material is too short (need >= 32 bytes)
  #[error("input keying material too short")]
  InvalidKeyMaterial,
  /// plaintext is empty or not a whole number of cipher blocks
  #[error("plaintext is empty or not a whole number of cipher blocks")]
  InvalidPlaintextLength,
  /// public key bytes are not a valid G1 point
  #[error("invalid public key bytes")]
  InvalidPublicKey,
  /// secret key bytes are not a valid scalar
  #[error("invalid secret key bytes")]
  InvalidSecretKey,
  /// signature bytes are not a valid G2 point
  #[error("invalid signature bytes")]
  InvalidSignature,
  /// threshold is below 2, exceeds id count or no ids supplied
  #[error("threshold is below 2, exceeds id count or no ids supplied")]
  InvalidThreshold,
  /// tweak is not below the group order, or the result is the identity
  #[error("tweak is not below the group order, or the result is the identity")]
  InvalidTweak,
  /// signature verification failed
  #[error("signature verification failed")]
  VerifyFailed,
  /// input reduces to zero in the scalar field
  #[error("input reduces to zero in the scalar field")]
  ZeroScalar,
}
