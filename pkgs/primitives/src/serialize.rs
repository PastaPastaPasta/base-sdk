//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

/// Serializes [`Amount`](bitcoin_units::Amount) as satoshis.
///
/// Integers are treated as satoshis; floats are treated as whole
/// coins and converted to satoshis.
pub mod amount {
  use crate::prelude::*;

  use bitcoin_units::Amount;

  /// Serializes as raw satoshis.
  pub fn serialize<S: serde::Serializer>(val: &Amount, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(val.to_sat())
  }

  /// Deserializes from satoshis (`u64`) or coins (`f64`).
  pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Amount, D::Error> {
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
      type Value = Amount;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("an integer (satoshis) or float (coins)")
      }

      fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Amount, E> {
        Amount::from_sat(v).map_err(E::custom)
      }

      fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Amount, E> {
        let v: u64 = v.try_into().map_err(|_| E::custom("negative amount"))?;
        Amount::from_sat(v).map_err(E::custom)
      }

      fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Amount, E> {
        if !v.is_finite() || v < 0.0 {
          return Err(E::custom("invalid amount"));
        }
        let sat = round(v * Amount::ONE_BTC.to_sat() as f64);
        if sat > u64::MAX as f64 {
          return Err(E::custom("amount overflow"));
        }
        Amount::from_sat(sat as u64).map_err(E::custom)
      }
    }

    deserializer.deserialize_any(Visitor)
  }
}

/// Serializes a signed duff value (Core's `CAmount`) as an integer.
///
/// Deserializes integers as duffs and floats as whole coins, like
/// [`amount`], without its range check.
pub mod duffs {
  use crate::prelude::*;

  use bitcoin_units::Amount;

  /// Serializes as raw duffs.
  pub fn serialize<S: serde::Serializer>(val: &i64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_i64(*val)
  }

  /// Deserializes from duffs (an integer) or coins (a float).
  pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
      type Value = i64;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("an integer (duffs) or float (coins)")
      }

      fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<i64, E> {
        Ok(v)
      }

      fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<i64, E> {
        i64::try_from(v).map_err(E::custom)
      }

      fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<i64, E> {
        let duffs = round(v * Amount::ONE_BTC.to_sat() as f64);
        if !duffs.is_finite() || duffs < i64::MIN as f64 || duffs >= i64::MAX as f64 {
          return Err(E::custom("amount overflow"));
        }
        Ok(duffs as i64)
      }
    }

    deserializer.deserialize_any(Visitor)
  }
}
