//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macro definitions.

/// Implements the `digest` traits that follow from `Default` and the output
/// size, leaving `Default`, `Update` and `FixedOutput` to the hash itself.
macro_rules! impl_digest {
  ($ty:ty, $size:ident) => {
    impl digest::HashMarker for $ty {}

    impl digest::OutputSizeUser for $ty {
      type OutputSize = digest::consts::$size;
    }

    impl digest::Reset for $ty {
      #[inline]
      fn reset(&mut self) {
        *self = Self::default();
      }
    }

    impl digest::FixedOutputReset for $ty {
      #[inline]
      fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        digest::FixedOutput::finalize_into(::core::mem::take(self), out);
      }
    }
  };
}
pub(crate) use impl_digest;
