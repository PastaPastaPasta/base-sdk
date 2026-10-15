//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V2 short ID mapping for BIP324 message framing.

use crate::command::CommandString;

use dash_types::type_id::Unencodable;

/// Number of short IDs from 0 that a V2 transport takes.
const LOW_TABLE_LEN: u8 = 33;

/// Number of short IDs from 128 that a V2 transport takes.
const HIGH_TABLE_LEN: u8 = 41;

/// A resolved V2 short ID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ShortId(pub u8);

impl ShortId {
  /// Long-format sentinel (a 12-byte command follows).
  pub const LONG_FORMAT: Self = Self(0);

  /// Returns `true` if this ID maps to a known command.
  pub const fn is_valid(self) -> bool {
    self.to_command_str().is_some()
  }

  /// Whether a V2 transport takes the ID as a message type, assigned or not.
  pub const fn is_in_table(self) -> bool {
    self.0 < LOW_TABLE_LEN || (self.0 >= 128 && self.0 - 128 < HIGH_TABLE_LEN)
  }

  /// Resolves the short ID to a `CommandString`, if known.
  pub fn to_command(self) -> Option<CommandString> {
    self.to_command_str().map(CommandString::from_static)
  }
}
