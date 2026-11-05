//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Buffered codec implementation.

#[cfg(feature = "codec")]
use crate::codec::{BaseCodec, DecodeError, SerBound};
#[cfg(feature = "codec")]
use crate::prelude::*;

#[cfg(feature = "codec")]
use bitcoin_consensus_encoding::{Decoder, DecoderStatus, Encoder, EncoderStatus};

#[cfg(feature = "codec")]
use core::convert::Infallible;
#[cfg(feature = "codec")]
use core::fmt;

#[cfg(feature = "codec")]
/// Maximum serialized object size (32 MiB).
pub const MAX_SER_SIZE: usize = 0x0200_0000;

#[cfg(feature = "codec")]
/// An encoder that wraps a pre-built byte vector.
#[derive(Clone)]
pub struct VecEncoder {
  data: Vec<u8>,
  done: bool,
}

#[cfg(feature = "codec")]
impl VecEncoder {
  /// Creates a new encoder wrapping the given bytes.
  pub fn new(data: Vec<u8>) -> Self {
    Self { data, done: false }
  }
}

#[cfg(feature = "codec")]
impl fmt::Debug for VecEncoder {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("VecEncoder")
      .field("len", &self.data.len())
      .field("done", &self.done)
      .finish()
  }
}

#[cfg(feature = "codec")]
impl Encoder for VecEncoder {
  fn current_chunk(&self) -> &[u8] {
    if self.done {
      &[]
    } else {
      &self.data
    }
  }

  fn advance(&mut self) -> EncoderStatus {
    self.done = true;
    EncoderStatus::Finished
  }
}

#[cfg(feature = "codec")]
/// A decoder that buffers all input and decodes in `end()`.
///
/// Wraps types with complex sequential decode logic (conditional fields,
/// version branching) that cannot be expressed as a composable push-decoder
/// without excessive boilerplate.
pub struct VecDecoder<T, E = Infallible> {
  buf: Vec<u8>,
  limit: usize,
  decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>,
}

#[cfg(feature = "codec")]
impl<T, E> VecDecoder<T, E> {
  /// Creates a new decoder with the given decode function and
  /// maximum buffer size.
  pub const fn new(decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>, limit: usize) -> Self {
    Self {
      buf: Vec::new(),
      limit,
      decode_fn,
    }
  }
}

#[cfg(feature = "codec")]
impl<T, E> fmt::Debug for VecDecoder<T, E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("VecDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &self.limit)
      .finish()
  }
}

#[cfg(feature = "codec")]
impl<T, E> Clone for VecDecoder<T, E> {
  fn clone(&self) -> Self {
    Self {
      buf: self.buf.clone(),
      limit: self.limit,
      decode_fn: self.decode_fn,
    }
  }
}

#[cfg(feature = "codec")]
impl<T, E> Decoder for VecDecoder<T, E> {
  type Output = T;
  type Error = DecodeError<E>;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
    let remaining = self.limit.saturating_sub(self.buf.len());
    let take = bytes.len().min(remaining);
    self.buf.extend_from_slice(&bytes[..take]);
    *bytes = &bytes[take..];
    if self.buf.len() < self.limit {
      Ok(DecoderStatus::NeedsMore)
    } else {
      Ok(DecoderStatus::Ready)
    }
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let mut cursor = &self.buf[..];
    let result = (self.decode_fn)(&mut cursor)?;
    if !cursor.is_empty() {
      return Err(DecodeError::TrailingBytes {
        remaining: cursor.len(),
      });
    }
    Ok(result)
  }

  fn read_limit(&self) -> usize {
    self.limit.saturating_sub(self.buf.len())
  }
}

#[cfg(feature = "codec")]
impl<T: BaseCodec<E> + SerBound, E> Default for VecDecoder<T, E> {
  fn default() -> Self {
    Self::new(T::decode, T::MAX_SER_SIZE)
  }
}

/// Generates `Encode` + `Decode` for a `BaseCodec` implementor.
///
/// Stages through the growable [`VecEncoder`]/[`VecDecoder`] pair. For
/// secret material use [`impl_stype!`](crate::impl_stype) instead, which is
/// the same generator over the wiping fixed-width pair.
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! impl_type {
  (@parse [$($impl_generics:tt)*] $ty:ty, $max:expr, $err:ty) => {
    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Encode for $ty {
      type Encoder<'e> = $crate::VecEncoder;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = ::alloc::vec::Vec::new();
        $crate::codec::BaseCodec::encode(self, &mut buf);
        $crate::VecEncoder::new(buf)
      }
    }

    impl<$($impl_generics)*> $crate::codec::SerBound for $ty {
      const MAX_SER_SIZE: usize = $max;
    }

    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Decode for $ty {
      type Decoder = $crate::VecDecoder<$ty, $err>;
      fn decoder() -> Self::Decoder {
        $crate::VecDecoder::new(<$ty as $crate::codec::BaseCodec<$err>>::decode, $max)
      }
    }
  };
  (@parse [$($impl_generics:tt)*] $ty:ty, $max:expr) => {
    $crate::impl_type!(
      @parse [$($impl_generics)*] $ty,
      $max,
      ::core::convert::Infallible
    );
  };
  (@parse [$($impl_generics:tt)*] $ty:ty) => {
    $crate::impl_type!(@parse [$($impl_generics)*] $ty, $crate::MAX_SER_SIZE);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_type!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_type!(@parse [] $($args)*);
  };
}

/// Generates `BaseCodec` over the named fields of a struct, in the order
/// listed.
///
/// A field written `field: limit` is a list read with
/// [`decode_vec`](crate::codec::decode_vec), which refuses a count above
/// `limit` before any entry is read. Every other field reads with its own
/// `BaseCodec`, and every field encodes with its own `BaseCodec`.
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! impl_vec {
  (@decode $data:ident) => {
    $crate::codec::BaseCodec::decode($data)?
  };
  (@decode $data:ident $limit:expr) => {
    $crate::codec::decode_vec($data, $limit)?
  };
  ($ty:ty, { $($field:ident $(: $limit:expr)?),+ $(,)? }) => {
    impl $crate::codec::BaseCodec for $ty {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::codec::DecodeError> {
        Ok(Self {
          $($field: $crate::impl_vec!(@decode data $($limit)?)),+
        })
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        $($crate::codec::BaseCodec::encode(&self.$field, buf);)+
      }
    }
  };
}

/// Generates `BaseCodec` + `Encode` + `Decode` for a fixed-size byte newtype,
/// expressed only through `from_bytes` / `as_bytes`.
///
/// Staged through the growable [`VecEncoder`]. For a newtype whose contents
/// are secret use [`impl_sbytes!`](crate::impl_sbytes).
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! impl_bytes {
  // Shared by `impl_bytes!` and `impl_sbytes!`, only the encoder pair differs.
  (@codec [$($g:tt)*] $ty:ty, $n:expr) => {
    impl<$($g)*> $crate::codec::BaseCodec for $ty {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::codec::DecodeError> {
        $crate::codec::take::<$n>(data).map(Self::from_bytes)
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        buf.extend_from_slice(self.as_bytes());
      }
    }
  };
  (@wire [$($g:tt)*] $ty:ty, $n:expr) => {
    $crate::impl_bytes!(@codec [$($g)*] $ty, $n);

    $crate::impl_type!(@parse [$($g)*] $ty, $n);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_bytes!(@wire [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_bytes!(@wire [] $($args)*);
  };
}

/// The standard trait set for a fixed-size byte newtype, expressed only
/// through `from_bytes` / `as_bytes`.
///
/// The `serde` pair writes the `Display` hex to human-readable formats and the
/// raw storage bytes to machine-readable formats. A trailing `rev` renders and
/// parses the hex in reverse storage order, the default `fwd` in storage order.
///
/// For a newtype holding secrets use [`derive_sbytes!`](crate::derive_sbytes),
/// which withholds everything that would read or copy out the plaintext.
#[macro_export]
macro_rules! derive_bytes {
  (@parse [$($g:tt)*] $ty:ty, $n:expr, $rev:expr) => {
    impl<$($g)*> ::core::clone::Clone for $ty {
      fn clone(&self) -> Self { *self }
    }

    impl<$($g)*> ::core::marker::Copy for $ty {}

    impl<$($g)*> ::core::default::Default for $ty {
      fn default() -> Self { Self::from_bytes([0u8; $n]) }
    }

    impl<$($g)*> ::core::cmp::Eq for $ty {}

    impl<$($g)*> ::core::cmp::PartialEq for $ty {
      fn eq(&self, other: &Self) -> bool { self.as_bytes() == other.as_bytes() }
    }

    impl<$($g)*> ::core::cmp::Ord for $ty {
      fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
      }
    }

    impl<$($g)*> ::core::cmp::PartialOrd for $ty {
      fn partial_cmp(&self, other: &Self) -> ::core::option::Option<::core::cmp::Ordering> {
        ::core::option::Option::Some(::core::cmp::Ord::cmp(self, other))
      }
    }

    impl<$($g)*> ::core::hash::Hash for $ty {
      fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
        ::core::hash::Hash::hash(self.as_bytes(), state);
      }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8]> for $ty {
      fn as_ref(&self) -> &[u8] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8; $n]> for $ty {
      fn as_ref(&self) -> &[u8; $n] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::From<$ty> for [u8; $n] {
      fn from(val: $ty) -> Self { *val.as_bytes() }
    }

    $crate::type_cvrt!(for[$($g)*] From<[u8; $n]> for $ty, |bytes| Self::from_bytes(*bytes));

    impl<$($g)*> ::core::convert::TryFrom<&[u8]> for $ty {
      type Error = ::core::array::TryFromSliceError;

      fn try_from(slice: &[u8]) -> ::core::result::Result<Self, Self::Error> {
        <[u8; $n]>::try_from(slice).map(Self::from_bytes)
      }
    }

    impl<$($g)*> $ty {
      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool { self.as_bytes().iter().all(|&b| b == 0) }
    }

    impl<$($g)*> ::core::fmt::Debug for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        $crate::qtypestr(f, ::core::any::type_name::<Self>())?;
        ::core::write!(f, "({self})")
      }
    }

    $crate::derive_bytes!(@hex [$($g)*] $ty, $n, $rev);
  };
  (@order [$($g:tt)*] $ty:ty, $n:expr, fwd) => {
    $crate::derive_bytes!(@parse [$($g)*] $ty, $n, false);
  };
  (@order [$($g:tt)*] $ty:ty, $n:expr, rev) => {
    $crate::derive_bytes!(@parse [$($g)*] $ty, $n, true);
  };
  (@hex [$($g:tt)*] $ty:ty, $n:expr, $rev:expr) => {
    impl<$($g)*> ::core::fmt::Display for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // A fresh formatter drops `{:#}`, reserving the prefix for `{:#x}`.
        ::core::write!(f, "{self:x}")
      }
    }

    impl<$($g)*> ::core::fmt::LowerHex for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        $crate::__private::__write_hex(self.as_bytes(), $rev, $crate::__private::hex_conservative::Case::Lower, f)
      }
    }

    impl<$($g)*> ::core::fmt::UpperHex for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        $crate::__private::__write_hex(self.as_bytes(), $rev, $crate::__private::hex_conservative::Case::Upper, f)
      }
    }

    impl<$($g)*> ::core::str::FromStr for $ty {
      type Err = $crate::ParseHexError;

      /// Parses `2 * N` hex digits in the order `Display` writes.
      fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
        $crate::__private::__read_hex::<$n>(s, $rev).map(Self::from_bytes)
      }
    }

    $crate::cfg_serde! {
      impl<$($g)*> $crate::__private::serde::Serialize for $ty {
        fn serialize<Z>(&self, serializer: Z) -> Result<Z::Ok, Z::Error>
        where
          Z: $crate::__private::serde::Serializer,
        {
          $crate::serialize::hex::serialize_as(self.as_bytes(), self, serializer)
        }
      }

      impl<'de, $($g)*> $crate::__private::serde::Deserialize<'de> for $ty {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
          D: $crate::__private::serde::Deserializer<'de>,
        {
          $crate::serialize::hex::deserialize_as(deserializer, |s: &str| {
            $crate::__private::__read_hex::<$n>(s, $rev)
          })
          .map(Self::from_bytes)
        }
      }
    }
  };
  (for[$($generic:tt)*] $ty:ty, $n:expr, $order:tt) => {
    $crate::derive_bytes!(@order [$($generic)*] $ty, $n, $order);
  };
  (for[$($generic:tt)*] $ty:ty, $n:expr) => {
    $crate::derive_bytes!(@order [$($generic)*] $ty, $n, fwd);
  };
  ($ty:ty, $n:expr, $order:tt) => {
    $crate::derive_bytes!(@order [] $ty, $n, $order);
  };
  ($ty:ty, $n:expr) => {
    $crate::derive_bytes!(@order [] $ty, $n, fwd);
  };
}

/// Declares a fixed-size byte newtype over `[u8; N]` with the `from_bytes` /
/// `to_bytes` / `as_bytes` accessors.
///
/// A `for[..]` prefix takes type parameters, held in a `PhantomData` beside
/// the bytes, for a type that utilizes parameters for tagging without mutating
/// the inner structure.
///
/// Two optional trailing words follow the width. The first is the hex order,
/// `fwd` (the default) or `rev`. The second is whether the bag carries a wire
/// image, `codec` (the default) or `nocodec`; the second cannot be given
/// without the first.
///
/// Invokes `impl_bytes!` and [`derive_bytes!`](crate::derive_bytes). A newtype
/// that needs a validating constructor or its own trait set should define
/// itself and invoke those macros manually.
#[macro_export]
macro_rules! make_bytes {
  // `@struct`, `@decl` and `@accessors` are shared with `make_sbytes!`
  (@struct [$($g:tt)*] {$($attr:tt)*} $(#[$derive:meta])? $name:ident $(<$($param:ident),+>)?, $n:expr) => {
    $($attr)*
    $(#[$derive])?
    // A plain bag gets an empty `<>`, legal and invisible in rustdoc.
    pub struct $name<$($g)*> {
      inner: [u8; $n],
      $(_marker: ::core::marker::PhantomData<fn() -> ($($param,)+)>,)?
    }
  };
  (@decl [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr, codec, $codec:ident) => {
    $crate::cfg_codec! {
      {
        $crate::make_bytes!(
          @struct [$($g)*] $attrs #[derive($crate::type_id::TypeId)] $name $(<$($param),+>)?, $n
        );

        $crate::$codec!(@wire [$($g)*] $name $(<$($param),+>)?, $n);
      } else {
        $crate::make_bytes!(@struct [$($g)*] $attrs $name $(<$($param),+>)?, $n);
      }
    }
  };
  // `$codec` is accepted for symmetry with the arm above, nothing to stage.
  (@decl [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr, nocodec, $codec:ident) => {
    $crate::cfg_codec! {
      {
        $crate::make_bytes!(
          @struct [$($g)*] $attrs #[derive($crate::type_id::Unencodable)] $name $(<$($param),+>)?, $n
        );
      } else {
        $crate::make_bytes!(@struct [$($g)*] $attrs $name $(<$($param),+>)?, $n);
      }
    }
  };
  (@accessors [$($g:tt)*] $name:ident $(<$($param:ident),+>)?, $n:expr, {$($to_bytes:tt)*}) => {
    impl<$($g)*> $name $(<$($param),+>)? {
      /// Wraps raw bytes without validation.
      pub const fn from_bytes(bytes: [u8; $n]) -> Self {
        Self {
          inner: bytes,
          $(_marker: ::core::marker::PhantomData::<fn() -> ($($param,)+)>,)?
        }
      }

      $($to_bytes)*

      /// Borrows the inner byte array.
      pub const fn as_bytes(&self) -> &[u8; $n] {
        &self.inner
      }
    }
  };
  (@parse [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr, $rev:tt, $enc:ident) => {
    $crate::make_bytes!(@decl [$($g)*] $attrs $name $(<$($param),+>)?, $n, $enc, impl_bytes);

    $crate::derive_bytes!(@order [$($g)*] $name $(<$($param),+>)?, $n, $rev);

    $crate::make_bytes!(@accessors [$($g)*] $name $(<$($param),+>)?, $n, {
      /// Copies out the inner byte array.
      pub const fn to_bytes(&self) -> [u8; $n] {
        self.inner
      }
    });
  };
  (@parse [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr, $rev:tt) => {
    $crate::make_bytes!(@parse [$($g)*] $attrs $name $(<$($param),+>)?, $n, $rev, codec);
  };
  (@parse [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr) => {
    $crate::make_bytes!(@parse [$($g)*] $attrs $name $(<$($param),+>)?, $n, fwd);
  };
  ($(#[$attr:meta])* for[$($generic:tt)*] $name:ident<$($param:ident),+>, $($args:tt)*) => {
    $crate::make_bytes!(@parse [$($generic)*] {$(#[$attr])*} $name<$($param),+>, $($args)*);
  };
  ($(#[$attr:meta])* $name:ident, $($args:tt)*) => {
    $crate::make_bytes!(@parse [] {$(#[$attr])*} $name, $($args)*);
  };
}

/// Delegates `BaseCodec`, `Hashable`, and `impl_type!` through another type.
///
/// Decode is fallible: `$bytes` is unvalidated, so `TryFrom<$bytes>` guards
/// the operational type. Encode is not: the value is already valid, so
/// `From<&$ops> for $bytes` must exist and must be infallible, since a failing
/// encode could only emit nothing or a placeholder, corrupting the wire image.
///
/// `$max` bounds the `impl_type!` decoder buffer to the wrapped type's own
/// maximum encoded length. For a secret wire image use
/// [`dlgt_scodec!`](crate::dlgt_scodec).
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! dlgt_codec {
  // Shared by `dlgt_codec!` and `dlgt_scodec!`, only the encoder pair differs.
  (@delegate [$($impl_generics:tt)*] $ops:ty => $bytes:ty, $hash:ty, $err:ty) => {
    impl<$($impl_generics)*> $crate::codec::BaseCodec<$err> for $ops {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::codec::DecodeError<$err>> {
        let inner = <$bytes as $crate::codec::BaseCodec>::decode(data).map_err(|e| e.lift())?;
        Self::try_from(inner).map_err($crate::codec::DecodeError::DecError)
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        $crate::codec::BaseCodec::encode(&<$bytes as ::core::convert::From<&Self>>::from(self), buf);
      }
    }

    impl<$($impl_generics)*> $crate::Hashable for $ops {
      type Hash = $hash;

      fn hash(&self) -> $hash {
        $crate::Hashable::hash(&<$bytes as ::core::convert::From<&Self>>::from(self))
      }
    }
  };
  (@parse [$($impl_generics:tt)*] $ops:ty => $bytes:ty, $hash:ty, $err:ty, $max:expr) => {
    $crate::dlgt_codec!(@delegate [$($impl_generics)*] $ops => $bytes, $hash, $err);

    $crate::impl_type!(@parse [$($impl_generics)*] $ops, $max, $err);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::dlgt_codec!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::dlgt_codec!(@parse [] $($args)*);
  };
}

#[cfg(all(test, feature = "codec"))]
mod tests {
  use crate::codec::{BaseCodec, DecodeError};
  use crate::prelude::*;

  use hex_conservative::hex;
  use rstest::rstest;

  struct Paired([u8; 4]);

  impl Paired {
    const fn from_bytes(bytes: [u8; 4]) -> Self {
      Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8; 4] {
      &self.0
    }
  }

  // Pairs the two as `make_bytes!` documents for manual use.
  crate::derive_bytes!(Paired, 4);
  crate::impl_bytes!(Paired, 4);

  #[rstest]
  fn derive_and_impl_bytes_pair() {
    let paired = Paired::from(hex!("ab000001"));

    assert!(!paired.is_null());
    assert_eq!(paired.as_bytes(), &hex!("ab000001"));
  }

  #[derive(Debug, PartialEq)]
  struct Bounded {
    tag: u32,
    items: Vec<u16>,
    tail: Vec<u8>,
  }

  crate::impl_vec!(Bounded, { tag, items: 3, tail });

  #[rstest]
  fn impl_vec_reads_a_list_at_the_limit() {
    let wire = hex!("07000000030100020003000109");
    let mut cursor = &wire[..];
    assert_eq!(
      Bounded::decode(&mut cursor),
      Ok(Bounded {
        tag: 7,
        items: vec![1, 2, 3],
        tail: vec![9],
      })
    );
    assert!(cursor.is_empty());
  }

  /// The count is refused before any entry is read, so a count with no
  /// entries after it fails the same way.
  #[rstest]
  #[case::with_entries(&hex!("070000000401000200030004000109"))]
  #[case::without_entries(&hex!("0700000004"))]
  fn impl_vec_refuses_a_list_past_the_limit(#[case] wire: &[u8]) {
    assert_eq!(
      Bounded::decode(&mut &wire[..]),
      Err(DecodeError::CompactSizeExceedsLimit { limit: 3, value: 4 })
    );
  }

  #[rstest]
  fn impl_vec_reads_an_unlimited_field_with_its_own_codec() {
    let tail = hex!("050102030405");
    let wire = [&hex!("0700000000")[..], &tail].concat();
    assert_eq!(
      Bounded::decode(&mut &wire[..]).map(|value| value.tail),
      Vec::<u8>::decode(&mut &tail[..])
    );
  }

  #[rstest]
  fn impl_vec_encodes_field_for_field() {
    let value = Bounded {
      tag: 7,
      items: vec![1, 2],
      tail: vec![9],
    };
    let mut fields = Vec::new();
    value.tag.encode(&mut fields);
    value.items.encode(&mut fields);
    value.tail.encode(&mut fields);

    let mut buf = Vec::new();
    value.encode(&mut buf);
    assert_eq!(buf, fields);
    assert_eq!(buf, hex!("0700000002010002000109"));
  }
}
