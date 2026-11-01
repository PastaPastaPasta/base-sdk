//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macro definitions.

use core::fmt;

/// Emits its body only when *this* crate has the `codec` feature.
///
/// `#[cfg(feature = "codec")]` written inside an exported macro resolves
/// against the invoking crate, which doesn't need have a `codec` feature at
/// all. This marker is compiled here, so it tracks `dash-types` instead.
///
/// `{ .. } else { .. }` picks between two bodies rather than emitting one
/// conditionally, for an item that exists either way but is built differently
/// with the feature enabled.
///
/// The two arms must stay plain `#[cfg]` items. Wrapping them in `cfg_if!`
/// makes the definition macro-expanded, and a macro-expanded `#[macro_export]`
/// macro cannot be reached by `$crate::` from its own crate (rust#52234).
#[cfg(feature = "codec")]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_codec {
  ({$($with:tt)*} else {$($without:tt)*}) => { $($with)* };
  ($($item:tt)*) => { $($item)* };
}

#[cfg(not(feature = "codec"))]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_codec {
  ({$($with:tt)*} else {$($without:tt)*}) => { $($without)* };
  ($($item:tt)*) => {};
}

/// Emits its body only when *this* crate has the `serde` feature.
///
/// Identical rationale to [`cfg_codec!`](crate::cfg_codec).
#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => { $($item)* };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => {};
}

/// Writes [`type_name`](core::any::type_name) output to `f` with its module
/// qualifiers dropped.
pub fn qtypestr(f: &mut fmt::Formatter<'_>, path: &str) -> fmt::Result {
  let bytes = path.as_bytes();
  let (mut seg, mut i) = (0, 0);
  while i < bytes.len() {
    match bytes[i] {
      // A qualifier: discard everything emitted since the last segment.
      b':' if bytes.get(i + 1) == Some(&b':') => {
        i += 2;
        seg = i;
      }
      delim @ (b'<' | b'>' | b',') => {
        f.write_str(&path[seg..i])?;
        f.write_str(match delim {
          b'<' => "<",
          b'>' => ">",
          _ => ", ",
        })?;
        i += 1;
        while bytes.get(i) == Some(&b' ') {
          i += 1;
        }
        seg = i;
      }
      _ => i += 1,
    }
  }
  f.write_str(&path[seg..])
}

/// Maps enum variants to integer constants and display strings.
///
/// Generates the enum definition, the integer mapping, and `impl Display`
/// from a single table. An open enum maps through `Numeric`, a closed one
/// through an inherent fallible pair.
///
/// # Syntax
///
/// Each variant uses one of two forms:
///
/// - `Variant = VALUE` -- display string is `stringify!(Variant)`
/// - `Variant = VALUE => "label"` -- display string is `"label"`
///
/// All variants within one invocation must use the same form.
///
/// ## Infallible
///
/// Generates the enum with a catch-all variant, a [`Numeric`](crate::Numeric)
/// impl, inherent `new`, `is_canonical`, `variants`, and `impl Display`.
///
/// The catch-all displays as `unknown({v})`; build values with `new` so it
/// never shadows a named variant.
///
/// ```ignore
/// enum_map! {
///   #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
///   pub enum NIPurpose, u8, Unknown {
///     /// Core P2P port.
///     CoreP2p = 0 => "core_p2p",
///     /// Platform P2P port.
///     PlatformP2p = 1 => "platform_p2p",
///   }
/// }
/// ```
///
/// ## Fallible
///
/// Generates the enum (closed), inherent `const fn try_from_base` / `to_base`
/// methods, and `impl Display`.
///
/// ```ignore
/// enum_map! {
///   #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
///   pub enum Sec1Byte, u8 {
///     /// Compressed, even Y coordinate.
///     CompEven = 0x02,
///     /// Compressed, odd Y coordinate.
///     CompOdd  = 0x03,
///   }
/// }
/// ```
#[macro_export]
macro_rules! enum_map {
  // Infallible + manual display strings.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty, $catch_all:ident {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal => $display:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum $(#[$enum_attr])* $vis $enum, $base, $catch_all {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@infallible $enum, $base, $catch_all { $($variant = $value),+ });
    $crate::enum_map!(@display_catch_all $enum, $catch_all { $($variant = $display),+ });
  };

  // Infallible + auto-stringize.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty, $catch_all:ident {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum $(#[$enum_attr])* $vis $enum, $base, $catch_all {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@infallible $enum, $base, $catch_all { $($variant = $value),+ });
    $crate::enum_map!(@display_catch_all $enum, $catch_all { $($variant = stringify!($variant)),+ });
  };

  // Fallible + manual display strings.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal => $display:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum_closed $(#[$enum_attr])* $vis $enum {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@fallible $enum, $base { $($variant = $value),+ });
    $crate::enum_map!(@display $enum { $($variant = $display),+ });
  };

  // Fallible + auto-stringize.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:literal
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum_closed $(#[$enum_attr])* $vis $enum {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@fallible $enum, $base { $($variant = $value),+ });
    $crate::enum_map!(@display $enum { $($variant = stringify!($variant)),+ });
  };

  (@enum $(#[$enum_attr:meta])* $vis:vis $enum:ident, $base:ty, $catch_all:ident {
    $($(#[$var_attr:meta])* $variant:ident,)+
  }) => {
    $(#[$enum_attr])*
    $vis enum $enum {
      $(
        $(#[$var_attr])*
        $variant,
      )+
      /// Unrecognized value, construct through [`new`](Self::new) rather than directly
      $catch_all($base),
    }
  };

  (@enum_closed $(#[$enum_attr:meta])* $vis:vis $enum:ident {
    $($(#[$var_attr:meta])* $variant:ident,)+
  }) => {
    $(#[$enum_attr])*
    $vis enum $enum {
      $(
        $(#[$var_attr])*
        $variant,
      )+
    }
  };

  (@infallible $enum:ident, $base:ty, $catch_all:ident {
    $($variant:ident = $value:literal),+
  }) => {
    impl $enum {
      /// Canonical constructor.
      pub const fn new(val: $base) -> Self {
        match val {
          $($value => Self::$variant,)+
          other => Self::$catch_all(other),
        }
      }

      /// Whether this value is in canonical form.
      ///
      /// False only for a catch-all holding a value that a named variant
      /// already covers.
      pub fn is_canonical(&self) -> bool {
        !matches!(self, Self::$catch_all(v) if matches!(
          Self::new(*v),
          $(Self::$variant)|+
        ))
      }

      /// Named variants.
      pub const fn variants() -> &'static [Self] {
        &[$(Self::$variant),+]
      }
    }

    impl $crate::Numeric for $enum {
      type Base = $base;

      type Bytes = <$base as $crate::Numeric>::Bytes;

      const ZERO: Self = Self::new(0);

      fn from_base(val: $base) -> Self {
        Self::new(val)
      }

      fn to_base(&self) -> $base {
        match self {
          $(Self::$variant => $value,)+
          Self::$catch_all(v) => *v,
        }
      }

      fn from_lendian(bytes: Self::Bytes) -> Self {
        Self::from_base(<$base as $crate::Numeric>::from_lendian(bytes))
      }

      fn to_lendian(&self) -> Self::Bytes {
        <$base as $crate::Numeric>::to_lendian(&self.to_base())
      }

      fn from_bendian(bytes: Self::Bytes) -> Self {
        Self::from_base(<$base as $crate::Numeric>::from_bendian(bytes))
      }

      fn to_bendian(&self) -> Self::Bytes {
        <$base as $crate::Numeric>::to_bendian(&self.to_base())
      }
    }
  };

  (@fallible $enum:ident, $base:ty {
    $($variant:ident = $value:literal),+
  }) => {
    impl $enum {
      /// Constructs from the base integer value, if it names a variant.
      pub const fn try_from_base(v: $base) -> Option<Self> {
        match v {
          $($value => Some(Self::$variant),)+
          _ => None,
        }
      }

      /// Returns the base integer value.
      pub const fn to_base(self) -> $base {
        match self {
          $(Self::$variant => $value,)+
        }
      }

      /// All variants.
      pub const fn variants() -> &'static [Self] {
        &[$(Self::$variant),+]
      }
    }
  };

  (@display_catch_all $enum:ident, $catch_all:ident {
    $($variant:ident = $display:expr),+
  }) => {
    impl ::core::fmt::Display for $enum {
      fn fmt(
        &self, f: &mut ::core::fmt::Formatter<'_>,
      ) -> ::core::fmt::Result {
        match self {
          $(Self::$variant => f.write_str($display),)+
          Self::$catch_all(v) => write!(f, "unknown({v})"),
        }
      }
    }
  };

  (@display $enum:ident {
    $($variant:ident = $display:expr),+
  }) => {
    impl ::core::fmt::Display for $enum {
      fn fmt(
        &self, f: &mut ::core::fmt::Formatter<'_>,
      ) -> ::core::fmt::Result {
        match self {
          $(Self::$variant => f.write_str($display),)+
        }
      }
    }
  };
}

/// Generates `From<T>` + `From<&T>` (or `TryFrom` equivalents). The closure
/// body receives `&$src`; the owned impl delegates.
#[macro_export]
macro_rules! type_cvrt {
  (@parse [$($impl_generics:tt)*] From<$src:ty> for $dst:ty, |$v:ident| $body:expr) => {
    impl<$($impl_generics)*> ::core::convert::From<&$src> for $dst {
      fn from($v: &$src) -> Self {
        $body
      }
    }
    impl<$($impl_generics)*> ::core::convert::From<$src> for $dst {
      fn from(v: $src) -> Self {
        Self::from(&v)
      }
    }
  };
  (@parse [$($impl_generics:tt)*] TryFrom<$src:ty> for $dst:ty, $err:ty, |$v:ident| $body:expr) => {
    impl<$($impl_generics)*> ::core::convert::TryFrom<&$src> for $dst {
      type Error = $err;
      fn try_from($v: &$src) -> Result<Self, Self::Error> {
        $body
      }
    }
    impl<$($impl_generics)*> ::core::convert::TryFrom<$src> for $dst {
      type Error = $err;
      fn try_from(v: $src) -> Result<Self, Self::Error> {
        Self::try_from(&v)
      }
    }
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::type_cvrt!(@parse [$($generic)*] $($args)*);
  };
  (enum $enum:ident { $($variant:ident($inner:ty)),* $(,)? }) => { $(
    impl ::core::convert::From<$inner> for $enum {
      fn from(v: $inner) -> Self {
        Self::$variant(v)
      }
    }
    impl ::core::convert::TryFrom<$enum> for $inner {
      type Error = $enum;
      fn try_from(v: $enum) -> Result<Self, $enum> {
        match v {
          $enum::$variant(inner) => Ok(inner),
          other => Err(other),
        }
      }
    }
  )* };
  ($($args:tt)*) => {
    $crate::type_cvrt!(@parse [] $($args)*);
  };
}

/// Declares a struct with named fields and a `new` taking every field in
/// declaration order.
///
/// Attributes and field visibility pass through, so derives and `getset`
/// getters still apply. A type whose constructor validates or computes writes
/// `new` by hand instead.
///
/// ```
/// use dash_types::impl_new;
///
/// impl_new! {
/// /// Keepalive request.
/// #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// pub struct Ping {
///   /// Random nonce.
///   nonce: u64,
/// }
/// }
///
/// let ping = Ping::new(7);
/// ```
#[macro_export]
macro_rules! impl_new {
  (
    $(#[$attr:meta])*
    $vis:vis struct $name:ident {
      $($(#[$fattr:meta])* $fvis:vis $field:ident: $fty:ty),+ $(,)?
    }
  ) => {
    $(#[$attr])*
    $vis struct $name {
      $($(#[$fattr])* $fvis $field: $fty),+
    }

    impl $name {
      /// Constructs from the field values.
      pub fn new($($field: $fty),+) -> Self {
        Self { $($field),+ }
      }
    }
  };
}

#[cfg(test)]
mod tests {
  use super::qtypestr;
  use crate::prelude::*;
  use crate::Numeric;

  use rstest::*;

  use core::fmt;

  enum_map! {
    /// Open enum: unrecognized codes survive a round trip.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum Open, u8, Unknown {
      /// First.
      One = 1 => "one",
      /// Second.
      Two = 2 => "two",
    }
  }

  enum_map! {
    /// Closed enum: only the listed codes are representable.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum Closed, u16 {
      /// Low.
      Lo = 0x0100,
      /// High.
      Hi = 0x0200,
    }
  }

  enum_map! {
    /// Auto-stringized display labels.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub enum Auto, u8, Other {
      /// Alpha.
      Alpha = 7,
    }
  }

  #[rstest]
  #[case::named_low(1, Open::One)]
  #[case::named_high(2, Open::Two)]
  #[case::unknown(9, Open::Unknown(9))]
  fn open_maps_both_ways(#[case] raw: u8, #[case] expected: Open) {
    assert_eq!(Open::from_base(raw), expected);
    assert_eq!(expected.to_base(), raw);
  }

  #[rstest]
  fn new_canonicalizes_a_shadowing_catch_all() {
    let shadow = Open::Unknown(1);
    assert_eq!(shadow.to_base(), Open::One.to_base());
    assert_ne!(shadow, Open::One);
    assert!(!shadow.is_canonical());

    assert_eq!(Open::new(1), Open::One);
    assert!(Open::new(1).is_canonical());
    assert!(Open::new(9).is_canonical());
  }

  #[rstest]
  fn open_display_and_variants() {
    assert_eq!(Open::One.to_string(), "one");
    assert_eq!(Open::Unknown(9).to_string(), "unknown(9)");
    assert_eq!(Open::variants(), &[Open::One, Open::Two]);
  }

  #[rstest]
  fn auto_stringize_uses_the_variant_name() {
    assert_eq!(Auto::Alpha.to_string(), "Alpha");
    assert_eq!(Auto::Alpha.to_base(), 7);
    assert_eq!(Auto::Other(3).to_string(), "unknown(3)");
    assert_eq!(Auto::variants(), &[Auto::Alpha]);
    assert_eq!(Auto::new(7), Auto::Alpha);
    assert!(!Auto::Other(7).is_canonical());
  }

  #[rstest]
  #[case::lo(0x0100, Some(Closed::Lo))]
  #[case::hi(0x0200, Some(Closed::Hi))]
  #[case::unmapped(0x0300, None)]
  #[case::zero(0, None)]
  fn closed_rejects_unmapped(#[case] raw: u16, #[case] expected: Option<Closed>) {
    assert_eq!(Closed::try_from_base(raw), expected);
  }

  #[rstest]
  fn closed_roundtrips_every_variant() {
    for v in Closed::variants() {
      assert_eq!(Closed::try_from_base(v.to_base()), Some(*v));
    }
  }

  #[rstest]
  fn closed_display() {
    assert_eq!(Closed::Lo.to_string(), "Lo");
  }

  #[rstest]
  fn open_maps_through_the_shared_trait() {
    assert_eq!(<Open as Numeric>::from_base(1), Open::One);
    assert_eq!(Open::Two.to_base(), 2);
    assert_eq!(Open::Two.to_lendian(), [2]);
    assert_eq!(<Open as Numeric>::LEN, 1);
  }

  struct Qtype<'a>(&'a str);

  impl fmt::Display for Qtype<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      qtypestr(f, self.0)
    }
  }

  #[rstest]
  #[case::plain("a::b::Foo", "Foo")]
  #[case::unqualified("Foo", "Foo")]
  #[case::one_arg("a::Foo<b::Bar>", "Foo<Bar>")]
  #[case::two_args("a::Foo<b::Bar, c::Baz>", "Foo<Bar, Baz>")]
  #[case::nested("a::Foo<b::Bar<c::Baz>>", "Foo<Bar<Baz>>")]
  #[case::nested_pair("a::Foo<b::Bar<c::Baz>, d::Qux>", "Foo<Bar<Baz>, Qux>")]
  fn qtypestr_drops_module_paths(#[case] path: &str, #[case] expect: &str) {
    assert_eq!(Qtype(path).to_string(), expect);
  }
}
