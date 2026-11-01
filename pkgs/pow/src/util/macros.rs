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

/// Implements `Hash` for a core holding arrays of `wide` vectors, which lack
/// `Hash`, by hashing each vector as its lanes.
macro_rules! impl_hash {
  ($ty:ty, [$($vectors:ident),*], [$($words:ident),*]) => {
    impl ::core::hash::Hash for $ty {
      fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
        $(::core::hash::Hash::hash(&self.$vectors.map(|vector| vector.to_array()), state);)*
        $(::core::hash::Hash::hash(&self.$words, state);)*
      }
    }
  };
}
pub(crate) use impl_hash;

/// Builds an array in const context by evaluating `$element` at each index
/// `$i`. Every slot starts as `$fill` and is overwritten in index order.
macro_rules! const_array {
  ($fill:expr; $n:expr; |$i:ident| $element:expr) => {{
    let mut out = [$fill; $n];
    let mut $i = 0;
    while $i < $n {
      out[$i] = $element;
      $i += 1;
    }
    out
  }};
}
pub(crate) use const_array;

/// Invokes `$step!(i)` for each literal `i`.
macro_rules! foreach_step {
  ($step:ident; $($i:literal),* $(,)?) => {
    $($step!($i);)*
  };
}
pub(crate) use foreach_step;
