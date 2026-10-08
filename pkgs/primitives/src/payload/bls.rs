//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS fields of special payloads, read and written as Dash Core does.
//!
//! Each field takes its scheme from one of Core's rules: the payload's
//! version, Core's process-wide flag, or the basic scheme always.

use super::PROTX_VERSION_LEGACY_BLS;

use dash_pkc::bls::{BlsEager, BlsLazy, BlsSchemeKind, BlsSchemeSource, BlsWire, BlsWirePoint};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};

/// Final commitment version: legacy BLS, not indexed.
const QC_VERSION_LEGACY_BLS: u16 = 1;

/// Final commitment version: legacy BLS, indexed.
const QC_VERSION_LEGACY_BLS_INDEXED: u16 = 2;

/// The scheme of a ProTx BLS field: legacy for version 1 only.
///
/// Core passes `nVersion == ProTxVersion::LegacyBLS` to the field's version
/// wrapper.
pub(crate) const fn protx_scheme(version: u16) -> BlsSchemeKind {
  BlsSchemeKind::from_legacy(version == PROTX_VERSION_LEGACY_BLS)
}

/// The scheme of a final commitment's BLS fields: legacy for versions 1 and
/// 2, basic for any other version, unknown versions included.
pub(crate) const fn qc_scheme(version: u16) -> BlsSchemeKind {
  BlsSchemeKind::from_legacy(version == QC_VERSION_LEGACY_BLS || version == QC_VERSION_LEGACY_BLS_INDEXED)
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

/// Reads a lazy field, Core's `CBLSLazyWrapper::Unserialize`; only a short
/// read fails.
///
/// # Errors
///
/// Returns a `DecodeError` when fewer than `N` bytes remain.
pub(crate) fn read_lazy<K: BlsWirePoint<N>, const N: usize>(
  data: &mut &[u8],
  source: BlsSchemeSource,
) -> Result<BlsLazy<K, N>, DecodeError> {
  Ok(BlsLazy::from_bytes(&codec::take::<N>(data)?, source))
}

/// Writes an eager field under the scheme it was decoded with; zeros when
/// invalid.
pub(crate) fn write_eager<K: BlsWire<N>, const N: usize>(field: &BlsEager<K, N>, buf: &mut impl EncodeBuf) {
  field.to_bytes(field.scheme()).encode(buf);
}

/// Writes a lazy field under its captured scheme, Core's `Serialize(s)`.
pub(crate) fn write_lazy<K: BlsWirePoint<N>, const N: usize>(field: &BlsLazy<K, N>, buf: &mut impl EncodeBuf) {
  field.to_bytes().encode(buf);
}

/// Serde forms of BLS fields, the hex of their wire bytes.
///
/// A version-sourced field cannot read its scheme from its own JSON, so each
/// payload carrying one converts through a form holding the raw bytes, and
/// decodes them with [`eager_from`] or [`BlsLazy::from_bytes`] as the wire
/// path does.
#[cfg(feature = "serde")]
pub(crate) mod serde {
  use super::eager_from;

  use dash_pkc::bls::{BlsEager, BlsLazy, BlsSchemeSource, BlsWire, BlsWirePoint};

  /// The wire bytes of an eager field, under the scheme it was decoded with.
  pub(crate) fn eager_bytes<K: BlsWire<N>, const N: usize>(field: &BlsEager<K, N>) -> [u8; N] {
    field.to_bytes(field.scheme())
  }

  /// The wire bytes of an optional field as hex, or null.
  pub(crate) mod opt_hex {
    /// Serializes present bytes as hex and absent ones as null.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the serializer rejects the value.
    pub(crate) fn serialize<S, const N: usize>(bytes: &Option<[u8; N]>, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: ::serde::Serializer,
    {
      match bytes {
        Some(bytes) => dash_types::serialize::hex::serialize(bytes, serializer),
        None => serializer.serialize_none(),
      }
    }

    /// Deserializes hex, or null for absent bytes.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for bad hex or a wrong length.
    pub(crate) fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<Option<[u8; N]>, D::Error>
    where
      D: ::serde::Deserializer<'de>,
    {
      #[derive(::serde::Deserialize)]
      struct Hex<const M: usize>(#[serde(with = "dash_types::serialize::hex")] [u8; M]);

      let hex: Option<Hex<N>> = ::serde::Deserialize::deserialize(deserializer)?;
      Ok(hex.map(|Hex(bytes)| bytes))
    }
  }

  /// An eager field that always takes the basic scheme, as hex.
  pub(crate) mod always_basic {
    use super::*;

    /// Serializes the field's wire bytes as hex.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the serializer rejects the value.
    pub(crate) fn serialize<S, K, const N: usize>(field: &BlsEager<K, N>, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: ::serde::Serializer,
      K: BlsWire<N>,
    {
      dash_types::serialize::hex::serialize(&eager_bytes(field), serializer)
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

  /// A lazy field that always takes the basic scheme, as hex.
  pub(crate) mod lazy_always_basic {
    use super::*;

    /// Serializes the field's wire bytes as hex.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the serializer rejects the value.
    pub(crate) fn serialize<S, K, const N: usize>(field: &BlsLazy<K, N>, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: ::serde::Serializer,
      K: BlsWirePoint<N>,
    {
      dash_types::serialize::hex::serialize(&field.to_bytes(), serializer)
    }

    /// Deserializes hex into a field holding the bytes under the basic scheme.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for bad hex.
    pub(crate) fn deserialize<'de, D, K, const N: usize>(deserializer: D) -> Result<BlsLazy<K, N>, D::Error>
    where
      D: ::serde::Deserializer<'de>,
      K: BlsWirePoint<N>,
    {
      let bytes: [u8; N] = dash_types::serialize::hex::deserialize(deserializer)?;
      Ok(BlsLazy::from_bytes(&bytes, BlsSchemeSource::AlwaysBasic))
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
  #[case::v0(0, BlsSchemeKind::Basic)]
  #[case::legacy(1, BlsSchemeKind::Legacy)]
  #[case::basic(2, BlsSchemeKind::Basic)]
  #[case::ext_addr(3, BlsSchemeKind::Basic)]
  #[case::unknown(0xffff, BlsSchemeKind::Basic)]
  fn protx_version_picks_scheme(#[case] version: u16, #[case] scheme: BlsSchemeKind) {
    assert_eq!(protx_scheme(version), scheme);
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
    assert_eq!(qc_scheme(version), scheme);
  }
}
