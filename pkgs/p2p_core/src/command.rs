//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Twelve-byte null-padded command string for P2P message dispatch.

use dash_primitives::hash_impl;
use dash_types::type_id::TypeId;
use dash_types::{impl_bytes, type_cvrt};

use core::fmt;

/// A 12-byte, null-padded ASCII command identifying a P2P message type.
#[derive(Clone, Copy, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CommandString([u8; 12]);

impl_bytes!(CommandString, 12);

hash_impl!(CommandString);

impl CommandString {
  /// Builds a command string from a static `&str` at compile time.
  ///
  /// # Panics
  ///
  /// Compile-time panic if `s` is longer than 12 bytes.
  pub const fn from_static(s: &str) -> Self {
    let b = s.as_bytes();
    let len = b.len();
    assert!(len <= 12, "command string exceeds 12 bytes");
    let mut buf = [0u8; 12];
    let mut i = 0;
    while i < len {
      buf[i] = b[i];
      i += 1;
    }
    Self(buf)
  }

  /// Wraps raw bytes into a command string.
  pub const fn from_bytes(bytes: [u8; 12]) -> Self {
    Self(bytes)
  }

  /// Returns the raw 12-byte command buffer.
  pub const fn as_bytes(&self) -> &[u8; 12] {
    &self.0
  }

  /// Returns the command as a `&str` (trimmed of null padding).
  ///
  /// A command that is not UTF-8 up to its first NUL gives the empty string.
  pub fn as_str(&self) -> &str {
    let end = self.0.iter().position(|&b| b == 0).unwrap_or(12);
    core::str::from_utf8(&self.0[..end]).unwrap_or("")
  }

  /// Whether Core's V1 transport accepts the command (`IsCommandValid`).
  ///
  /// The bytes before the first NUL must be in 0x20 to 0x7e, and every byte
  /// after it NUL. Core drops any other message and keeps the peer.
  pub const fn is_valid_v1(&self) -> bool {
    self.is_valid_up_to(0x7e)
  }

  /// Whether Core's V2 transport accepts a long-form type (`GetMessageType`).
  ///
  /// As [`Self::is_valid_v1`], but 0x7f is accepted too.
  pub const fn is_valid_v2(&self) -> bool {
    self.is_valid_up_to(0x7f)
  }

  /// Printable bytes in 0x20 to `max` up to the first NUL, then only NULs.
  const fn is_valid_up_to(&self, max: u8) -> bool {
    let mut padding = false;
    let mut i = 0;
    while i < self.0.len() {
      let b = self.0[i];
      if b == 0 {
        padding = true;
      } else if padding || b < b' ' || b > max {
        return false;
      }
      i += 1;
    }
    true
  }
}

type_cvrt!(From<[u8; 12]> for CommandString, |bytes| Self(*bytes));

impl fmt::Debug for CommandString {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CommandString(\"{}\")", self.as_str())
  }
}

impl fmt::Display for CommandString {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}
