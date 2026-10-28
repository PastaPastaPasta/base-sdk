//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Errors types for Ed25519 operations.

/// Errors produced by Ed25519 operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
pub enum EddsaError {
  /// public key bytes are not a usable curve point
  #[error("public key bytes are not a usable curve point")]
  InvalidPublicKey,
  /// signature verification failed
  #[error("signature verification failed")]
  VerifyFailed,
}
