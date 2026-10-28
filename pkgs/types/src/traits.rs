//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared trait definitions.

use crate::prelude::*;

/// Consensus types that have internal consistency checks.
pub trait Checkable {
  /// The error type returned on failure.
  type Error;

  /// Checks structural invariants, returning the first violation.
  #[must_use]
  fn check(&self) -> Option<Self::Error>;
}

/// Canonical hashed representation.
pub trait Hashable {
  /// The hash output type.
  type Hash;

  /// Computes the canonical hash of this value.
  fn hash(&self) -> Self::Hash;
}

/// Consensus types that have a signature field.
pub trait Signable {
  /// The key that verifies the signature.
  type Key;
  /// Outside input the payload depends on, `()` when there is none.
  type Context;
  /// The error type returned on failure.
  type Error;

  /// The 32-byte digest the key signs.
  fn payload(&self, ctx: &Self::Context) -> Vec<u8>;

  /// Stores `sig` if it verifies against `key` over the payload.
  ///
  /// # Errors
  ///
  /// Returns an error and keeps the stored signature when `sig` does not
  /// verify.
  fn set_signature(&mut self, sig: &[u8], key: &Self::Key, ctx: &Self::Context) -> Result<(), Self::Error>;

  /// Removes the stored signature.
  fn reset_signature(&mut self);

  /// Checks the stored signature against `key`, returning the failure.
  #[must_use]
  fn verify(&self, key: &Self::Key, ctx: &Self::Context) -> Option<Self::Error>;
}
