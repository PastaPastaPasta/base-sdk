//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS fields of special payloads, read and written as Dash Core does.
//!
//! Each field takes its scheme from one of Core's rules: the payload's
//! version, Core's process-wide flag, or the basic scheme always. A field
//! under the flag keeps its wire bytes ([`BlsGlobal`]), so a payload decodes
//! without the flag. The other fields encode under the scheme their rule
//! gives when the payload is encoded, as Core's serializers do.

use crate::provider::ProTxVersion;

use dash_pkc::bls::{BlsEager, BlsGlobal, BlsSchemeKind, BlsSchemeSource, BlsWire, BlsWirePoint};
use dash_types::codec::{self, DecodeError};

/// Final commitment version: legacy BLS, not indexed.
const QC_VERSION_LEGACY_BLS: u16 = 1;

/// Final commitment version: legacy BLS, indexed.
const QC_VERSION_LEGACY_BLS_INDEXED: u16 = 2;

/// The scheme of a ProTx's BLS fields (types 1 to 4): legacy for version 1
/// only. Core reads no field of a ProTx of unknown version.
///
/// Core passes `nVersion == ProTxVersion::LegacyBLS` to the field's version
/// wrapper, when reading and when writing.
pub const fn protx_bls_scheme(version: ProTxVersion) -> BlsSchemeKind {
  BlsSchemeKind::from_legacy(matches!(version, ProTxVersion::LegacyBls))
}

/// The scheme of a final commitment's BLS fields: legacy for versions 1 and
/// 2, basic for any other version, unknown versions included.
pub const fn commitment_bls_scheme(version: u16) -> BlsSchemeKind {
  BlsSchemeKind::from_legacy(version == QC_VERSION_LEGACY_BLS || version == QC_VERSION_LEGACY_BLS_INDEXED)
}

/// The scheme source of a final commitment's BLS fields,
/// [`commitment_bls_scheme`].
pub(crate) const fn qc_source(version: u16) -> BlsSchemeSource {
  BlsSchemeSource::Version(commitment_bls_scheme(version))
}

/// Decodes an eager field from its wire bytes, Core's
/// `CBLSWrapper::Unserialize`.
///
/// # Errors
///
/// Returns [`DecodeError::MalleableBls`] when the bytes are canonical in
/// neither scheme.
pub(crate) fn eager_from<K: BlsWire<N>, const N: usize>(
  bytes: &[u8; N],
  source: BlsSchemeSource,
) -> Result<BlsEager<K, N>, DecodeError> {
  BlsEager::decode(bytes, source).map_err(|_| DecodeError::MalleableBls)
}

/// Reads an eager field.
///
/// # Errors
///
/// Returns a `DecodeError` when fewer than `N` bytes remain or the bytes are
/// canonical in neither scheme.
pub(crate) fn read_eager<K: BlsWire<N>, const N: usize>(
  data: &mut &[u8],
  source: BlsSchemeSource,
) -> Result<BlsEager<K, N>, DecodeError> {
  eager_from(&codec::take::<N>(data)?, source)
}

/// Reads a field under Core's process-wide flag, keeping its wire bytes.
///
/// # Errors
///
/// Returns a `DecodeError` when fewer than `N` bytes remain or the bytes are
/// canonical in neither scheme, which Core rejects under either flag.
pub(crate) fn read_global<K: BlsWirePoint<N>, const N: usize>(
  data: &mut &[u8],
) -> Result<BlsGlobal<K, N>, DecodeError> {
  BlsGlobal::decode(&codec::take::<N>(data)?).map_err(|_| DecodeError::MalleableBls)
}

/// Serde forms of BLS fields, the hex of the bytes the wire path writes.
///
/// A version-sourced field cannot read its scheme from its own JSON, so each
/// payload carrying one converts through a form holding the raw bytes, and
/// decodes them with [`eager_from`] or [`BlsLazy::from_bytes`] as the wire
/// path does.
#[cfg(feature = "serde")]
pub(crate) mod serde {
  use super::eager_from;

  use dash_pkc::bls::{BlsEager, BlsGlobal, BlsSchemeKind, BlsSchemeSource, BlsWire, BlsWirePoint};

  /// A field under Core's process-wide flag, as the hex of its wire bytes.
  pub(crate) mod global {
    use super::*;

    /// Serializes the wire bytes as hex.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the serializer rejects the value.
    pub(crate) fn serialize<S, K, const N: usize>(field: &BlsGlobal<K, N>, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: ::serde::Serializer,
      K: BlsWirePoint<N>,
    {
      dash_types::serialize::hex::serialize(&field.to_bytes(), serializer)
    }

    /// Deserializes hex and checks it as the wire path does.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for bad hex or a malleable object.
    pub(crate) fn deserialize<'de, D, K, const N: usize>(deserializer: D) -> Result<BlsGlobal<K, N>, D::Error>
    where
      D: ::serde::Deserializer<'de>,
      K: BlsWirePoint<N>,
    {
      let bytes: [u8; N] = dash_types::serialize::hex::deserialize(deserializer)?;
      BlsGlobal::decode(&bytes).map_err(::serde::de::Error::custom)
    }
  }

  /// An optional field under Core's process-wide flag, as [`global`] or none.
  pub(crate) mod opt_global {
    use super::*;

    /// Serializes a present field as [`super::global`] does and an absent one
    /// as none.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the serializer rejects the value.
    pub(crate) fn serialize<S, K, const N: usize>(
      field: &Option<BlsGlobal<K, N>>,
      serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
      S: ::serde::Serializer,
      K: BlsWirePoint<N>,
    {
      struct Value<'a, K: BlsWirePoint<N>, const N: usize>(&'a BlsGlobal<K, N>);

      impl<K: BlsWirePoint<N>, const N: usize> ::serde::Serialize for Value<'_, K, N> {
        fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
          super::global::serialize(self.0, serializer)
        }
      }

      match field {
        Some(field) => serializer.serialize_some(&Value(field)),
        None => serializer.serialize_none(),
      }
    }

    /// Deserializes what [`serialize`] writes.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for bad hex or a malleable object.
    pub(crate) fn deserialize<'de, D, K, const N: usize>(deserializer: D) -> Result<Option<BlsGlobal<K, N>>, D::Error>
    where
      D: ::serde::Deserializer<'de>,
      K: BlsWirePoint<N>,
    {
      struct Value<K: BlsWirePoint<N>, const N: usize>(BlsGlobal<K, N>);

      impl<'de, K: BlsWirePoint<N>, const N: usize> ::serde::Deserialize<'de> for Value<K, N> {
        fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
          super::global::deserialize(deserializer).map(Value)
        }
      }

      Ok(<Option<Value<K, N>> as ::serde::Deserialize>::deserialize(deserializer)?.map(|Value(field)| field))
    }
  }

  /// An eager field that always takes the basic scheme, as hex.
  pub(crate) mod always_basic {
    use super::*;

    /// Serializes the field under the basic scheme as hex.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the serializer rejects the value.
    pub(crate) fn serialize<S, K, const N: usize>(field: &BlsEager<K, N>, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: ::serde::Serializer,
      K: BlsWire<N>,
    {
      dash_types::serialize::hex::serialize(&field.to_bytes(BlsSchemeKind::Basic), serializer)
    }

    /// Deserializes hex and decodes it under the basic scheme.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for bad hex or a malleable object.
    pub(crate) fn deserialize<'de, D, K, const N: usize>(deserializer: D) -> Result<BlsEager<K, N>, D::Error>
    where
      D: ::serde::Deserializer<'de>,
      K: BlsWire<N>,
    {
      let bytes: [u8; N] = dash_types::serialize::hex::deserialize(deserializer)?;
      eager_from(&bytes, BlsSchemeSource::AlwaysBasic).map_err(::serde::de::Error::custom)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  /// `CProRegTx`, `CProUpServTx`, `CProUpRegTx` and `CProUpRevTx` pass
  /// `nVersion == ProTxVersion::LegacyBLS` to their version wrappers at both
  /// pins.
  #[rstest]
  #[case::legacy(ProTxVersion::LegacyBls, BlsSchemeKind::Legacy)]
  #[case::basic(ProTxVersion::BasicBls, BlsSchemeKind::Basic)]
  #[case::ext_addr(ProTxVersion::CoreV24, BlsSchemeKind::Basic)]
  fn protx_version_picks_scheme(#[case] version: ProTxVersion, #[case] scheme: BlsSchemeKind) {
    assert_eq!(protx_bls_scheme(version), scheme);
  }

  /// `CFinalCommitment` passes `nVersion` 1 or 2 as legacy at both pins.
  #[rstest]
  #[case::v0(0, BlsSchemeKind::Basic)]
  #[case::legacy(1, BlsSchemeKind::Legacy)]
  #[case::legacy_indexed(2, BlsSchemeKind::Legacy)]
  #[case::basic(3, BlsSchemeKind::Basic)]
  #[case::basic_indexed(4, BlsSchemeKind::Basic)]
  #[case::unknown(5, BlsSchemeKind::Basic)]
  #[case::max(0xffff, BlsSchemeKind::Basic)]
  fn qc_version_picks_scheme(#[case] version: u16, #[case] scheme: BlsSchemeKind) {
    assert_eq!(commitment_bls_scheme(version), scheme);
    assert_eq!(qc_source(version), BlsSchemeSource::Version(scheme));
  }
}
