//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Lazily decoded BLS fields, Core's `CBLSLazyWrapper`.

use super::group::{G1, G2};
use super::scheme_ctx::{BlsSchemeKind, BlsSchemeSource};
use super::wrap_codec::{is_zero, BlsWirePoint};
use super::wrap_value::BlsValue;
use super::{BLS_PK_LEN, BLS_SIG_LEN};

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use dash_types::Numeric;
use hex_conservative::DisplayHex;
use spin::Mutex;

use core::fmt::{self, Debug, Formatter};

/// A BLS field kept as raw bytes until first use, with the scheme captured
/// when it was decoded.
///
/// Decoding never fails. The object changes state as Core's does, through
/// shared references. A failed [`Self::get`] makes it serialize and hash as
/// zeros. Serializing under another scheme before a successful
/// [`Self::get`] overwrites the raw bytes with zeros.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsLazy<K: BlsWirePoint<N>, const N: usize> {
  state: Mutex<LazyState<K, N>>,
}

/// A lazily decoded public key.
pub type BlsLazyPk = BlsLazy<G1, BLS_PK_LEN>;
/// A lazily decoded signature.
pub type BlsLazySig = BlsLazy<G2, BLS_SIG_LEN>;

/// Core's lazy wrapper fields, under one lock as Core keeps them.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
struct LazyState<K: BlsWirePoint<N>, const N: usize> {
  /// Core's `vecBytes`, the raw or re-serialized bytes.
  buf: [u8; N],
  /// Core's `bufValid`, whether `buf` is current.
  buf_valid: bool,
  /// Core's `bufLegacyScheme`, the scheme of `buf`.
  scheme: BlsSchemeKind,
  /// Core's `obj`, present when `objInitialized`.
  obj: Option<BlsValue<K, N>>,
}

impl<K: BlsWirePoint<N>, const N: usize> LazyState<K, N> {
  /// Neither bytes nor an object; Core's default object.
  fn is_default(&self) -> bool {
    !self.buf_valid && self.obj.is_none()
  }

  /// `Serialize(s, scheme)`.
  fn serialize(&mut self, scheme: BlsSchemeKind) -> [u8; N] {
    if self.is_default() {
      self.buf = [0u8; N];
    } else if !self.buf_valid || self.scheme != scheme {
      // Without an object this writes zeros, Core's default object.
      self.buf = self.obj.as_ref().map_or([0u8; N], |obj| obj.to_bytes(scheme));
      self.buf_valid = true;
      self.scheme = scheme;
    }
    self.buf
  }

  /// `Get()`.
  fn get(&mut self) -> BlsValue<K, N> {
    if let Some(obj) = &self.obj {
      return obj.clone();
    }
    if !self.buf_valid {
      return BlsValue::invalid();
    }
    match BlsValue::from_canonical(&self.buf, self.scheme) {
      Some(obj) => self.obj.insert(obj).clone(),
      None => {
        self.buf_valid = false;
        BlsValue::invalid()
      }
    }
  }

  /// `GetHash()`, which refreshes the buffer exactly as serializing under
  /// the captured scheme does.
  fn serialize_hash(&mut self) -> Hash256 {
    let buf = self.serialize(self.scheme);
    Hash256::from_lendian(Sha256d::hash(&buf).to_byte_array())
  }
}

impl<K: BlsWirePoint<N>, const N: usize> BlsLazy<K, N> {
  /// Core's default object, which captures the scheme it is built under and
  /// serializes as zeros.
  pub fn new(scheme: BlsSchemeKind) -> Self {
    Self::from_state(LazyState {
      buf: [0u8; N],
      buf_valid: false,
      scheme,
      obj: None,
    })
  }

  /// Keeps raw bytes and the scheme `source` picks, Core's `Unserialize`.
  pub fn from_bytes(bytes: &[u8; N], source: BlsSchemeSource) -> Self {
    Self::from_state(LazyState {
      buf: *bytes,
      buf_valid: !is_zero(bytes),
      scheme: source.kind(),
      obj: None,
    })
  }

  /// Holds a decoded object under `scheme`, Core's `Set` on a new object.
  pub fn from_value(value: BlsValue<K, N>, scheme: BlsSchemeKind) -> Self {
    Self::from_state(LazyState {
      buf: [0u8; N],
      buf_valid: false,
      scheme,
      obj: Some(value),
    })
  }

  fn from_state(state: LazyState<K, N>) -> Self {
    Self {
      state: Mutex::new(state),
    }
  }

  /// Replaces the object, Core's `Set`.
  pub fn set(&mut self, value: BlsValue<K, N>, scheme: BlsSchemeKind) {
    let state = self.state.get_mut();
    state.buf_valid = false;
    state.scheme = scheme;
    state.obj = Some(value);
  }

  /// Decodes on first use, Core's `Get`, with no fallback to the other
  /// scheme.
  ///
  /// The object is valid only if the raw bytes are canonical under the
  /// captured scheme. Otherwise the object is invalid from then on and
  /// serializes as zeros. The first call decodes under the object's spin
  /// lock, so concurrent callers wait out one decompression.
  pub fn get(&self) -> BlsValue<K, N> {
    self.state.lock().get()
  }

  /// Serializes under the captured scheme, Core's `Serialize(s)`.
  pub fn to_bytes(&self) -> [u8; N] {
    let mut state = self.state.lock();
    let scheme = state.scheme;
    state.serialize(scheme)
  }

  /// Serializes under `scheme`, Core's `Serialize(s, scheme)`.
  ///
  /// Under a scheme other than the captured one the object adopts `scheme`.
  /// Before a successful [`Self::get`] that serializes zeros and discards the
  /// raw bytes.
  pub fn to_bytes_as(&self, scheme: BlsSchemeKind) -> [u8; N] {
    self.state.lock().serialize(scheme)
  }

  /// The hash of the serialization under the captured scheme, Core's
  /// `GetHash`. It covers the raw bytes before any [`Self::get`].
  pub fn serialize_hash(&self) -> Hash256 {
    self.state.lock().serialize_hash()
  }

  /// The captured scheme, Core's `IsLegacy`.
  pub fn scheme(&self) -> BlsSchemeKind {
    self.state.lock().scheme
  }

  /// Replaces the captured scheme and nothing else, Core's `SetLegacy`.
  pub fn set_scheme(&mut self, scheme: BlsSchemeKind) {
    self.state.get_mut().scheme = scheme;
  }
}

/// Core's copy assignment, which carries raw bytes only while current.
impl<K: BlsWirePoint<N>, const N: usize> Clone for BlsLazy<K, N> {
  fn clone(&self) -> Self {
    let state = self.state.lock();
    Self::from_state(LazyState {
      buf: if state.buf_valid { state.buf } else { [0u8; N] },
      buf_valid: state.buf_valid,
      scheme: state.scheme,
      obj: state.obj.clone(),
    })
  }
}

impl<K: BlsWirePoint<N>, const N: usize> Debug for BlsLazy<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    let state = self.state.lock();
    f.debug_struct("BlsLazy")
      .field("buf", &state.buf.as_hex())
      .field("buf_valid", &state.buf_valid)
      .field("scheme", &state.scheme)
      .field("obj", &state.obj)
      .finish()
  }
}

/// Core's `operator==`, which may call [`BlsLazy::get`] on both sides.
///
/// Default objects equal each other only. Current bytes in the same scheme
/// compare as bytes, decoded objects as objects. Anything else decodes both
/// sides and compares the results. A failed decode makes that side serialize
/// as zeros afterwards, so compare lazy fields only where Core does.
impl<K: BlsWirePoint<N>, const N: usize> PartialEq for BlsLazy<K, N> {
  fn eq(&self, other: &Self) -> bool {
    if core::ptr::eq(self, other) {
      return true;
    }
    {
      // Address order keeps two concurrent comparisons from deadlocking. The
      // checks below are symmetric, so the order does not affect them.
      let (first, second) = if (self as *const Self) < (other as *const Self) {
        (self, other)
      } else {
        (other, self)
      };
      let (a, b) = (first.state.lock(), second.state.lock());

      if a.is_default() || b.is_default() {
        return a.is_default() && b.is_default();
      }
      if a.buf_valid && b.buf_valid && a.scheme == b.scheme {
        return a.buf == b.buf;
      }
      if let (Some(x), Some(y)) = (&a.obj, &b.obj) {
        return x == y;
      }
    }
    self.get() == other.get()
  }
}
