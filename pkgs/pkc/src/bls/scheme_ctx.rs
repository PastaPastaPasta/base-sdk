//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Runtime BLS scheme selection by scheme, call-site context and source.

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// One of Dash Core's two BLS schemes, its legacy flag as a value.
///
/// The scheme fixes the byte layout of a point and the rules that decode it.
/// Legacy decoding checks neither the curve nor the subgroup.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BlsSchemeKind {
  /// The pre-V19 scheme; Core's legacy flag set.
  Legacy,
  /// The basic (IETF) scheme; Core's legacy flag clear.
  Basic,
}

impl BlsSchemeKind {
  /// The scheme Core's legacy flag selects.
  pub const fn from_legacy(legacy: bool) -> Self {
    if legacy {
      Self::Legacy
    } else {
      Self::Basic
    }
  }

  /// Whether this is the legacy scheme, Core's flag value.
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

/// The BLS scheme Core's process-wide flag holds at one call site.
///
/// Core reads a global; callers build this per call site instead, from the
/// block being processed or the tip, and pass it down explicitly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsCtx {
  scheme: BlsSchemeKind,
}

impl BlsCtx {
  /// The context while Core's flag selects the basic scheme.
  pub const BASIC: Self = Self::new(BlsSchemeKind::Basic);
  /// The context while Core's flag selects the legacy scheme.
  pub const LEGACY: Self = Self::new(BlsSchemeKind::Legacy);

  /// A context selecting `scheme`.
  pub const fn new(scheme: BlsSchemeKind) -> Self {
    Self { scheme }
  }

  /// A context from Core's legacy flag value.
  pub const fn from_legacy(legacy: bool) -> Self {
    Self::new(BlsSchemeKind::from_legacy(legacy))
  }

  /// The scheme this context selects.
  pub const fn scheme(self) -> BlsSchemeKind {
    self.scheme
  }

  /// Whether this context selects the legacy scheme, Core's flag value.
  pub const fn is_legacy(self) -> bool {
    self.scheme.is_legacy()
  }
}

impl From<BlsSchemeKind> for BlsCtx {
  fn from(scheme: BlsSchemeKind) -> Self {
    Self::new(scheme)
  }
}

impl From<BlsCtx> for BlsSchemeKind {
  fn from(ctx: BlsCtx) -> Self {
    ctx.scheme
  }
}

/// Where a BLS field's decode scheme comes from, as Core decides it per field.
///
/// Decoding takes a source rather than a bare scheme so that every call site
/// states which of Core's rules picked the scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BlsSchemeSource {
  /// Fixed by the enclosing object's version, mapped to a scheme by its type.
  Version(BlsSchemeKind),
  /// Core's process-wide flag at the call site.
  Global(BlsCtx),
  /// The basic scheme whatever the version or context.
  AlwaysBasic,
}

impl BlsSchemeSource {
  /// The scheme this source selects.
  pub const fn kind(self) -> BlsSchemeKind {
    match self {
      Self::Version(scheme) => scheme,
      Self::Global(ctx) => ctx.scheme(),
      Self::AlwaysBasic => BlsSchemeKind::Basic,
    }
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
    assert_eq!(BlsCtx::from_legacy(legacy).scheme(), scheme);
    assert_eq!(BlsCtx::from_legacy(legacy).is_legacy(), legacy);
  }

  #[rstest]
  #[case::version_legacy(BlsSchemeSource::Version(BlsSchemeKind::Legacy), BlsSchemeKind::Legacy)]
  #[case::version_basic(BlsSchemeSource::Version(BlsSchemeKind::Basic), BlsSchemeKind::Basic)]
  #[case::global_legacy(BlsSchemeSource::Global(BlsCtx::LEGACY), BlsSchemeKind::Legacy)]
  #[case::global_basic(BlsSchemeSource::Global(BlsCtx::BASIC), BlsSchemeKind::Basic)]
  #[case::always_basic(BlsSchemeSource::AlwaysBasic, BlsSchemeKind::Basic)]
  fn source_selects_scheme(#[case] source: BlsSchemeSource, #[case] scheme: BlsSchemeKind) {
    assert_eq!(source.kind(), scheme);
  }
}
