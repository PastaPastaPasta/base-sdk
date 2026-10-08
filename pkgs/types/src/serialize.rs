//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

/// Hex strings for human-readable formats and raw bytes for machine-readable
/// formats.
pub mod hex {
  use crate::prelude::*;

  use ::serde::de::Error as DeError;
  use hex_conservative::{decode_to_vec, DisplayHex};

  use core::fmt;
  use core::marker::PhantomData;

  /// Serializes bytes as a wire-order hex string, or as raw bytes when the
  /// format is machine-readable.
  ///
  /// # Errors
  ///
  /// Returns a serialization error when the serializer rejects the value.
  pub fn serialize<S: ::serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serialize_as(data, &data.as_hex(), serializer)
  }

  /// Deserializes a hex string or raw bytes into any `T` built from a byte
  /// slice, such as `Vec<u8>` or a fixed-width array.
  ///
  /// # Errors
  ///
  /// Returns a deserialization error when the input is neither form, when a
  /// string is not valid hex, or when the bytes do not convert to `T`.
  pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
  where
    D: ::serde::Deserializer<'de>,
    T: for<'a> TryFrom<&'a [u8]>,
  {
    deserialize_as(deserializer, |s: &str| {
      let bytes = decode_to_vec(s).map_err(|e| e.to_string())?;
      // For the byte arrays and bags this serves, the size of `T` is its width.
      T::try_from(bytes.as_slice()).map_err(|_| {
        format!(
          "hex decode length mismatch (expected: {}, got: {})",
          size_of::<T>(),
          bytes.len()
        )
      })
    })
  }

  /// Serializes `text` in human-readable formats and `data` as raw bytes in
  /// all others.
  ///
  /// # Errors
  ///
  /// Returns a serialization error when the serializer rejects the value.
  pub fn serialize_as<S, T>(data: &[u8], text: &T, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: ::serde::Serializer,
    T: fmt::Display + ?Sized,
  {
    if serializer.is_human_readable() {
      serializer.collect_str(text)
    } else {
      serializer.serialize_bytes(data)
    }
  }

  /// Deserializes a string through `parse` or raw bytes through `TryFrom`.
  ///
  /// Human-readable mode takes raw bytes as well, because serde replays input
  /// buffered for untagged enums and `flatten` as human-readable.
  ///
  /// # Errors
  ///
  /// Returns a deserialization error when the input is neither form, when
  /// `parse` fails, or when the raw bytes do not convert.
  pub fn deserialize_as<'de, D, T, F, E>(deserializer: D, parse: F) -> Result<T, D::Error>
  where
    D: ::serde::Deserializer<'de>,
    T: for<'a> TryFrom<&'a [u8]>,
    F: FnOnce(&str) -> Result<T, E>,
    E: fmt::Display,
  {
    struct Visitor<T, F>(F, PhantomData<fn() -> T>);

    impl<T, F, E> ::serde::de::Visitor<'_> for Visitor<T, F>
    where
      T: for<'a> TryFrom<&'a [u8]>,
      F: FnOnce(&str) -> Result<T, E>,
      E: fmt::Display,
    {
      type Value = T;

      fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a hex string or raw bytes")
      }

      fn visit_str<Er: DeError>(self, v: &str) -> Result<Self::Value, Er> {
        (self.0)(v).map_err(Er::custom)
      }

      fn visit_bytes<Er: DeError>(self, v: &[u8]) -> Result<Self::Value, Er> {
        T::try_from(v).map_err(|_| {
          let width = format!("{} raw bytes", size_of::<T>());
          Er::invalid_length(v.len(), &width.as_str())
        })
      }
    }

    if deserializer.is_human_readable() {
      deserializer.deserialize_str(Visitor(parse, PhantomData))
    } else {
      deserializer.deserialize_byte_buf(Visitor(parse, PhantomData))
    }
  }
}

/// Serializes `u64` as a decimal string in human-readable formats to avoid
/// JSON precision loss, and as a native integer in machine-readable formats.
pub mod str_u64 {
  /// Serializes a `u64` as a decimal string, or as an integer when the format
  /// is machine-readable.
  pub fn serialize<S: ::serde::Serializer>(val: &u64, s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
      s.collect_str(val)
    } else {
      s.serialize_u64(*val)
    }
  }

  /// Deserializes a `u64` from a decimal string or a number.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    struct Visitor;

    impl ::serde::de::Visitor<'_> for Visitor {
      type Value = u64;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("u64 as string or number")
      }

      fn visit_u64<E: ::serde::de::Error>(self, v: u64) -> Result<u64, E> {
        Ok(v)
      }

      fn visit_str<E: ::serde::de::Error>(self, s: &str) -> Result<u64, E> {
        s.parse().map_err(E::custom)
      }
    }

    if d.is_human_readable() {
      d.deserialize_any(Visitor)
    } else {
      d.deserialize_u64(Visitor)
    }
  }
}

/// [`str_u64`] for an optional field, `None` being null.
pub mod opt_str_u64 {
  /// Serializes `Some` as [`super::str_u64`] does and `None` as none.
  pub fn serialize<S: ::serde::Serializer>(val: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    struct Value(u64);

    impl ::serde::Serialize for Value {
      fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        super::str_u64::serialize(&self.0, s)
      }
    }

    match val {
      Some(v) => s.serialize_some(&Value(*v)),
      None => s.serialize_none(),
    }
  }

  /// Deserializes what [`serialize`] writes.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    struct Value(u64);

    impl<'de> ::serde::Deserialize<'de> for Value {
      fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        super::str_u64::deserialize(d).map(Value)
      }
    }

    Ok(<Option<Value> as ::serde::Deserialize>::deserialize(d)?.map(|Value(v)| v))
  }
}

/// UTF-8 serde for `Vec<u8>` fields that hold text.
pub mod utf8 {
  use crate::prelude::*;

  use core::str::from_utf8;

  /// Serializes bytes as a UTF-8 string.
  ///
  /// # Errors
  ///
  /// Returns a serialization error when bytes are not valid UTF-8.
  pub fn serialize<S: ::serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    let s = from_utf8(data).map_err(::serde::ser::Error::custom)?;
    serializer.serialize_str(s)
  }

  /// Deserializes a string into bytes.
  ///
  /// # Errors
  ///
  /// Returns a deserialization error when the input is not a valid string.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
    Ok(s.into_bytes())
  }
}

/// Best-effort UTF-8 serde for `Vec<u8>` fields.
///
/// Unlike [`utf8`], which rejects anything that is not valid UTF-8,
/// [`utf8_lossy`] will preserve arbitrary bytes in round-trips.
pub mod utf8_lossy {
  use crate::prelude::*;

  use ::serde::de::{Error as DeError, SeqAccess};

  use core::fmt;
  use core::str::from_utf8;

  /// Serializes bytes as raw bytes, or as a string when the format is
  /// human-readable and the bytes are valid UTF-8.
  ///
  /// # Errors
  ///
  /// Returns a serialization error when the serializer rejects the value.
  pub fn serialize<S: ::serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    match from_utf8(data) {
      Ok(text) if serializer.is_human_readable() => serializer.serialize_str(text),
      _ => serializer.serialize_bytes(data),
    }
  }

  /// Deserializes bytes from a string, a byte buffer, or a sequence of bytes.
  ///
  /// Length limits are a codec concern, so nothing is bounded here; a newtype
  /// with a maximum enforces it in its own constructor.
  ///
  /// # Errors
  ///
  /// Returns a deserialization error when the input is none of those forms.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Visitor;

    impl<'de> ::serde::de::Visitor<'de> for Visitor {
      type Value = Vec<u8>;

      fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string or byte sequence")
      }

      fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        Ok(v.as_bytes().to_vec())
      }

      fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(v.to_vec())
      }

      fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element::<u8>()? {
          bytes.push(byte);
        }
        Ok(bytes)
      }
    }

    if deserializer.is_human_readable() {
      deserializer.deserialize_any(Visitor)
    } else {
      deserializer.deserialize_byte_buf(Visitor)
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::prelude::*;

  use ::serde::{Deserialize, Serialize};
  use hex_conservative::hex;
  use rstest::rstest;

  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  struct Blob(#[serde(with = "super::hex")] Vec<u8>);

  #[rstest]
  #[case::inline(16)]
  #[case::beyond_scratch(8192)]
  fn hex_vec_roundtrips_through_cbor(#[case] len: usize) {
    let blob = Blob(vec![0xa5; len]);
    let mut wire = Vec::new();
    ciborium::into_writer(&blob, &mut wire).unwrap();
    assert_eq!(ciborium::from_reader::<Blob, _>(wire.as_slice()).unwrap(), blob);
  }

  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  #[serde(untagged)]
  enum Untagged {
    Blob(Blob),
  }

  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  struct Flattened {
    #[serde(flatten)]
    inner: Inner,
  }

  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  struct Inner {
    #[serde(with = "super::hex")]
    blob: Vec<u8>,
  }

  #[rstest]
  fn buffered_input_roundtrips_through_cbor() {
    let untagged = Untagged::Blob(Blob(vec![0xa5; 4]));
    let mut wire = Vec::new();
    ciborium::into_writer(&untagged, &mut wire).unwrap();
    assert_eq!(ciborium::from_reader::<Untagged, _>(wire.as_slice()).unwrap(), untagged);

    let flattened = Flattened {
      inner: Inner { blob: vec![0xa5; 4] },
    };
    let mut wire = Vec::new();
    ciborium::into_writer(&flattened, &mut wire).unwrap();
    assert_eq!(
      ciborium::from_reader::<Flattened, _>(wire.as_slice()).unwrap(),
      flattened
    );
  }

  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  struct Nonce(#[serde(with = "super::str_u64")] u64);

  #[rstest]
  fn str_u64_carries_integer_through_cbor() {
    let nonce = Nonce(0x0102_0304_0506_0708);
    let mut wire = Vec::new();
    ciborium::into_writer(&nonce, &mut wire).unwrap();
    assert_eq!(wire, hex!("1b0102030405060708"));
    assert_eq!(ciborium::from_reader::<Nonce, _>(wire.as_slice()).unwrap(), nonce);
  }

  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  struct Lossy(#[serde(with = "super::utf8_lossy")] Vec<u8>);

  #[rstest]
  #[case::utf8(b"abc", &hex!("43616263"))]
  #[case::non_utf8(&[0xff], &hex!("41ff"))]
  fn utf8_lossy_carries_bytes_through_cbor(#[case] data: &[u8], #[case] raw: &[u8]) {
    let lossy = Lossy(data.to_vec());
    let mut wire = Vec::new();
    ciborium::into_writer(&lossy, &mut wire).unwrap();
    assert_eq!(wire, raw);
    assert_eq!(ciborium::from_reader::<Lossy, _>(wire.as_slice()).unwrap(), lossy);
  }
}
