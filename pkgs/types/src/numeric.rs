//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-width numeric types.

/// Links a type to its underlying representation and byte image.
pub trait Numeric: Sized {
  /// The underlying representation.
  type Base: Numeric;

  /// The fixed-width byte image, always a `[u8; N]`.
  type Bytes: Copy + AsRef<[u8]>;

  /// Byte width of the image, width of [`Bytes`](Self::Bytes).
  const LEN: usize = ::core::mem::size_of::<Self::Bytes>();

  /// The zero value.
  const ZERO: Self;

  /// Constructs from the base representation.
  fn from_base(v: Self::Base) -> Self;

  /// Returns the base representation.
  fn to_base(&self) -> Self::Base;

  /// Constructs from a little-endian byte image.
  fn from_lendian(bytes: Self::Bytes) -> Self;

  /// Returns the little-endian byte image.
  fn to_lendian(&self) -> Self::Bytes;

  /// Constructs from a big-endian byte image.
  fn from_bendian(bytes: Self::Bytes) -> Self;

  /// Returns the big-endian byte image.
  fn to_bendian(&self) -> Self::Bytes;
}

/// A byte array is its own base and its own little-endian image.
impl<const N: usize> Numeric for [u8; N] {
  type Base = Self;

  type Bytes = Self;

  const ZERO: Self = [0u8; N];

  fn from_base(v: Self) -> Self {
    v
  }

  fn to_base(&self) -> Self {
    *self
  }

  fn from_lendian(bytes: Self) -> Self {
    bytes
  }

  fn to_lendian(&self) -> Self {
    *self
  }

  fn from_bendian(bytes: Self) -> Self {
    let mut out = bytes;
    out.reverse();
    out
  }

  fn to_bendian(&self) -> Self {
    Self::from_bendian(*self)
  }
}

/// Generates [`Numeric`] for a primitive integer, which is its own base.
macro_rules! numeric_prim {
  ($($ty:ty, $n:literal;)+) => {
    $(
      impl Numeric for $ty {
        type Base = Self;
        type Bytes = [u8; $n];
        const ZERO: Self = 0;

        fn from_base(v: Self) -> Self {
          v
        }

        fn to_base(&self) -> Self {
          *self
        }

        fn from_lendian(bytes: [u8; $n]) -> Self {
          Self::from_le_bytes(bytes)
        }

        fn to_lendian(&self) -> [u8; $n] {
          self.to_le_bytes()
        }

        fn from_bendian(bytes: [u8; $n]) -> Self {
          Self::from_be_bytes(bytes)
        }

        fn to_bendian(&self) -> [u8; $n] {
          self.to_be_bytes()
        }
      }
    )+
  };
}

numeric_prim! {
  i8, 1; u8, 1;
  i16, 2; u16, 2;
  i32, 4; u32, 4;
  i64, 8; u64, 8;
  i128, 16; u128, 16;
}

/// Generates `BaseCodec`, `Encode` and `Decode` with `codec`, and serde with
/// `serde`, for a type that already implements [`Numeric`] over `$uint`.
#[macro_export]
macro_rules! impl_num {
  ($name:tt, i8)  => { $crate::impl_num!(@both $name, i8, 1); };
  ($name:tt, u8)  => { $crate::impl_num!(@both $name, u8, 1); };
  ($name:tt, i16) => { $crate::impl_num!(@both $name, i16, 2); };
  ($name:tt, u16) => { $crate::impl_num!(@both $name, u16, 2); };
  ($name:tt, i32) => { $crate::impl_num!(@both $name, i32, 4); };
  ($name:tt, u32) => { $crate::impl_num!(@both $name, u32, 4); };
  ($name:tt, i64) => { $crate::impl_num!(@both $name, i64, 8); };
  ($name:tt, u64) => { $crate::impl_num!(@both $name, u64, 8); };
  ($name:tt, i128) => { $crate::impl_num!(@both $name, i128, 16); };
  ($name:tt, u128) => { $crate::impl_num!(@both $name, u128, 16); };
  (@both $name:ty, $uint:ty, $n:literal) => {
    $crate::cfg_codec! {
      $crate::impl_num!(@codec $name, $uint, $n);
    }

    $crate::cfg_serde! {
      $crate::impl_num!(@serde $name, $uint);
    }
  };
  (@codec $name:ty, $uint:ty, $n:literal) => {
    impl $crate::codec::BaseCodec for $name {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::codec::DecodeError> {
        $crate::codec::take::<$n>(data).map(|b| {
          <Self as $crate::Numeric>::from_base(
            <$uint>::from_le_bytes(b),
          )
        })
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        buf.extend_from_slice(
          &<Self as $crate::Numeric>::to_base(self)
            .to_le_bytes(),
        );
      }
    }

    $crate::impl_type!($name);
  };
  (@serde $name:ty, $uint:ty) => {
    impl $crate::__private::serde::Serialize for $name {
      fn serialize<S: $crate::__private::serde::Serializer>(
        &self, serializer: S,
      ) -> Result<S::Ok, S::Error> {
        $crate::__private::serde::Serialize::serialize(
          &<Self as $crate::Numeric>::to_base(self),
          serializer,
        )
      }
    }

    impl<'de> $crate::__private::serde::Deserialize<'de> for $name {
      fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
        deserializer: D,
      ) -> Result<Self, D::Error> {
        <$uint as $crate::__private::serde::Deserialize>::deserialize(deserializer)
          .map(<Self as $crate::Numeric>::from_base)
      }
    }
  };
}

/// Generates a fixed-size integer newtype with its base integer conversions
/// and standard trait implementations.
///
/// With `codec` the newtype also gains a `TypeId` and the consensus encoding
/// traits generated by [`impl_num!`](crate::impl_num).
#[macro_export]
macro_rules! make_num {
  (@struct {$($attr:tt)*} $(#[$derive:meta])? $name:ident, $uint:tt) => {
    $($attr)*
    #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    $(#[$derive])?
    pub struct $name($uint);
  };
  (@decl $attrs:tt $name:ident, $uint:tt) => {
    $crate::cfg_codec! {
      {
        $crate::make_num!(
          @struct $attrs #[derive($crate::type_id::TypeId)] $name, $uint
        );
      } else {
        $crate::make_num!(@struct $attrs $name, $uint);
      }
    }

    $crate::impl_num!($name, $uint);
  };
  (
    $(#[$attr:meta])*
    $name:ident, $uint:tt, $n:literal
  ) => {
    $crate::make_num!(@decl {$(#[$attr])*} $name, $uint);

    impl $crate::Numeric for $name {
      type Base = $uint;
      type Bytes = [u8; $n];
      const ZERO: Self = Self(0);

      fn from_base(v: $uint) -> Self {
        Self(v)
      }

      fn to_base(&self) -> $uint {
        self.0
      }

      fn from_lendian(bytes: [u8; $n]) -> Self {
        Self::from_base(<$uint as $crate::Numeric>::from_lendian(bytes))
      }

      fn to_lendian(&self) -> [u8; $n] {
        <$uint as $crate::Numeric>::to_lendian(&self.0)
      }

      fn from_bendian(bytes: [u8; $n]) -> Self {
        Self::from_base(<$uint as $crate::Numeric>::from_bendian(bytes))
      }

      fn to_bendian(&self) -> [u8; $n] {
        <$uint as $crate::Numeric>::to_bendian(&self.0)
      }
    }

    impl $name {
      /// Constructs from the raw integer value.
      pub const fn new(v: $uint) -> Self {
        Self(v)
      }

      /// Returns the raw integer value.
      pub const fn get(self) -> $uint {
        self.0
      }
    }

    impl From<$uint> for $name {
      fn from(v: $uint) -> Self { Self(v) }
    }

    impl From<$name> for $uint {
      fn from(v: $name) -> Self { v.0 }
    }

    impl From<[u8; $n]> for $name {
      fn from(bytes: [u8; $n]) -> Self {
        <Self as $crate::Numeric>::from_lendian(bytes)
      }
    }

    impl ::core::fmt::Debug for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "{}({})", stringify!($name), self.0)
      }
    }

    impl ::core::fmt::Display for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::fmt::Display::fmt(&self.0, f)
      }
    }
  };
}
