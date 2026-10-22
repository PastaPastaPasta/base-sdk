//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for primitives payload types.

use crate::prelude::*;

use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};

/// Maximum special-transaction payload size over the wire (10 KiB).
pub const MAX_SPTX_PAYLOAD_SIZE: usize = 10_240;

/// Reads `count` values written back to back.
pub(crate) fn decode_items<T: BaseCodec>(data: &mut &[u8], count: u8) -> Result<Vec<T>, DecodeError> {
  (0..count).map(|_| T::decode(data)).collect()
}

/// Reads a list whose length is a single byte.
pub(crate) fn decode_list<T: BaseCodec>(data: &mut &[u8]) -> Result<Vec<T>, DecodeError> {
  let count = u8::decode(data)?;
  decode_items(data, count)
}

/// Writes values back to back.
pub(crate) fn encode_items<T: BaseCodec>(items: &[T], buf: &mut impl EncodeBuf) {
  for item in items {
    item.encode(buf);
  }
}

/// Writes a list whose length is a single byte, which wraps past 255 as the
/// reference implementation's does.
pub(crate) fn encode_list<T: BaseCodec>(items: &[T], buf: &mut impl EncodeBuf) {
  (items.len() as u8).encode(buf);
  encode_items(items, buf);
}

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

/// Generates `Encode` + `Decode` with payload size limit.
macro_rules! impl_payload {
  ($ty:ty) => {
    $crate::__private::dash_types::impl_type!($ty, crate::codec::MAX_SPTX_PAYLOAD_SIZE);
  };
}
pub(crate) use impl_payload;

/// Declares a flat struct with `new` and generates `BaseCodec` + `Encode` +
/// `Decode` over its fields, without `Hashable`.
///
/// The `$ty, $max, { fields }` form generates the codec alone, for
/// `codec_type!` and `codec_payload!` to build on.
#[macro_export]
macro_rules! codec_base {
  (
    $(#[$attr:meta])*
    $vis:vis struct $name:ident {
      $($(#[$fattr:meta])* $fvis:vis $field:ident: $fty:ty),+ $(,)?
    }
  ) => {
    $crate::__private::dash_types::impl_new! {
      $(#[$attr])*
      $vis struct $name {
        $($(#[$fattr])* $fvis $field: $fty),+
      }
    }

    $crate::codec_base!($name, $crate::__private::dash_types::MAX_SER_SIZE, { $($field),+ });
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

/// Declares a flat struct with `new` and generates `BaseCodec` + `Encode` +
/// `Decode` + `Hashable` over its fields.
///
/// The `$ty, $max, { fields }` form generates the codec alone, for callers
/// that declare the struct themselves.
#[macro_export]
macro_rules! codec_type {
  (
    $(#[$attr:meta])*
    $vis:vis struct $name:ident {
      $($(#[$fattr:meta])* $fvis:vis $field:ident: $fty:ty),+ $(,)?
    }
  ) => {
    $crate::codec_base! {
      $(#[$attr])*
      $vis struct $name {
        $($(#[$fattr])* $fvis $field: $fty),+
      }
    }

    $crate::hash_impl!($name);
  };
  ($ty:ty, $max:expr, { $($field:ident),+ $(,)? }) => {
    $crate::codec_base!($ty, $max, { $($field),+ });
    $crate::hash_impl!($ty);
  };
}

/// Declares a flat struct with `new` and generates `BaseCodec` + `Encode` +
/// `Decode` + `Hashable` over its fields, with payload size limit.
///
/// A leading `@no_new` leaves `new` out, for a payload whose signature is set
/// only through `Signable::set_signature`.
macro_rules! codec_payload {
  (
    @no_new
    $(#[$attr:meta])*
    $vis:vis struct $name:ident {
      $($(#[$fattr:meta])* $fvis:vis $field:ident: $fty:ty),+ $(,)?
    }
  ) => {
    $(#[$attr])*
    $vis struct $name {
      $($(#[$fattr])* $fvis $field: $fty),+
    }

    $crate::codec_base!($name, crate::codec::MAX_SPTX_PAYLOAD_SIZE, { $($field),+ });
    $crate::hash_impl!($name);
  };
  (
    $(#[$attr:meta])*
    $vis:vis struct $name:ident {
      $($(#[$fattr:meta])* $fvis:vis $field:ident: $fty:ty),+ $(,)?
    }
  ) => {
    $crate::__private::dash_types::impl_new! {
      $(#[$attr])*
      $vis struct $name {
        $($(#[$fattr])* $fvis $field: $fty),+
      }
    }

    $crate::codec_base!($name, crate::codec::MAX_SPTX_PAYLOAD_SIZE, { $($field),+ });
    $crate::hash_impl!($name);
  };
}
pub(crate) use codec_payload;
