//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for primitives payload types.

/// Blanket `Hashable<Hash = Hash256>` via SHA256d of wire encoding.
///
/// Also asserts that the type implements `TypeId`, producing a
/// compile error if `#[derive(TypeId)]` was omitted.
#[macro_export]
macro_rules! hash_impl {
  ($($ty:ty),* $(,)?) => { $(
    impl $crate::__private::dash_types::Hashable for $ty {
      type Hash = $crate::__private::dash_num::Hash256;

      fn hash(&self) -> Self::Hash {
        use $crate::__private::dash_types::codec::BaseCodec;
        let mut buf = ::alloc::vec::Vec::new();
        self.encode(&mut buf);
        <$crate::__private::dash_num::Hash256 as $crate::__private::dash_types::Numeric>::from_lendian(
          $crate::__private::bitcoin_hashes::sha256d::Hash::hash(&buf).to_byte_array(),
        )
      }
    }

    const _: () = {
      fn _assert<T>()
      where
        T: $crate::__private::dash_types::codec::BaseCodec,
        T: $crate::__private::dash_types::type_id::TypeId,
      {
      }
      fn _check() { _assert::<$ty>(); }
    };
  )* };
}

/// Generates `BaseCodec` + `Encode` + `Decode` for flat structs
/// without `Hashable`.
#[macro_export]
macro_rules! codec_base {
  ($ty:ty { $($field:ident),+ $(,)? }) => {
    $crate::codec_base!($ty, $crate::__private::dash_types::MAX_SER_SIZE, { $($field),+ });
  };
  ($ty:ty, $max:expr, { $($field:ident),+ $(,)? }) => {
    impl $crate::__private::dash_types::codec::BaseCodec for $ty {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::__private::dash_types::codec::DecodeError> {
        Ok(Self {
          $($field: $crate::__private::dash_types::codec::BaseCodec::decode(data)?),+
        })
      }

      fn encode(&self, buf: &mut impl $crate::__private::dash_types::codec::EncodeBuf) {
        $($crate::__private::dash_types::codec::BaseCodec::encode(&self.$field, buf);)+
      }
    }

    $crate::__private::dash_types::impl_type!($ty, $max);
  };
}

/// Generates `BaseCodec` + `Encode` + `Decode` + `Hashable` for
/// flat structs.
#[macro_export]
macro_rules! codec_type {
  ($ty:ty { $($field:ident),+ $(,)? }) => {
    $crate::codec_base!($ty { $($field),+ });
    $crate::hash_impl!($ty);
  };
  ($ty:ty, $max:expr, { $($field:ident),+ $(,)? }) => {
    $crate::codec_base!($ty, $max, { $($field),+ });
    $crate::hash_impl!($ty);
  };
}
