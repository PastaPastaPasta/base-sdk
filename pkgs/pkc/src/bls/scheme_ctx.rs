//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS schemes chosen at run time.

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// One of the two BLS schemes, as a value.
///
/// The scheme fixes the byte layout of a point and the rules that decode it,
/// those of [`BlsScChia`](super::BlsScChia) for the legacy scheme and of
/// [`BlsScIetf`](super::BlsScIetf) for the basic one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BlsSchemeKind {
  /// The legacy scheme.
  Legacy,
  /// The basic scheme.
  Basic,
}

impl BlsSchemeKind {
  /// The legacy scheme when `legacy` is set, otherwise the basic one.
  pub const fn from_legacy(legacy: bool) -> Self {
    if legacy {
      Self::Legacy
    } else {
      Self::Basic
    }
  }

  /// Whether this is the legacy scheme.
  pub const fn is_legacy(self) -> bool {
    matches!(self, Self::Legacy)
  }

  /// The other scheme.
  pub const fn opposite(self) -> Self {
    match self {
      Self::Legacy => Self::Basic,
      Self::Basic => Self::Legacy,
    }
  }
}

/// The scheme a caller decodes and encodes under where no version picks one.
///
/// Decoding under a context takes the scheme from a `BlsCtx` the caller
/// passes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsCtx {
  scheme: BlsSchemeKind,
}

impl BlsCtx {
  /// The context selecting the basic scheme.
  pub const BASIC: Self = Self::new(BlsSchemeKind::Basic);
  /// The context selecting the legacy scheme.
  pub const LEGACY: Self = Self::new(BlsSchemeKind::Legacy);

  /// A context selecting `scheme`.
  pub const fn new(scheme: BlsSchemeKind) -> Self {
    Self { scheme }
  }

  /// The scheme this context selects.
  pub const fn scheme(self) -> BlsSchemeKind {
    self.scheme
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  #[rstest]
  #[case::legacy(true, BlsSchemeKind::Legacy)]
  #[case::basic(false, BlsSchemeKind::Basic)]
  fn flag_maps_to_scheme(#[case] legacy: bool, #[case] scheme: BlsSchemeKind) {
    assert_eq!(BlsSchemeKind::from_legacy(legacy), scheme);
    assert_eq!(scheme.is_legacy(), legacy);
    assert_eq!(scheme.opposite().is_legacy(), !legacy);
    assert_eq!(BlsCtx::new(scheme).scheme(), scheme);
  }
}
