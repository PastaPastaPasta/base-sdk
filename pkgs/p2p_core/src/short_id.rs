//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V2 short ID mapping for BIP324 message framing.

use crate::command::CommandString;
use crate::version::ProtocolVersion;

use dash_primitives::hash_impl;
use dash_types::make_num;

/// Number of short IDs from 0 that a V2 transport takes.
const LOW_TABLE_COUNT: u8 = table_count(0);

/// Number of short IDs from 128 that a V2 transport takes.
const HIGH_TABLE_COUNT: u8 = table_count(128);

/// Number of short IDs from `start` up to the last one in its table.
const fn table_count(start: u8) -> u8 {
  let mut count = 0;
  let mut i = 0;
  while i < ShortId::TABLE.len() {
    let id = ShortId::TABLE[i];
    if id >= start && id - start < 128 && id - start >= count {
      count = id - start + 1;
    }
    i += 1;
  }
  count
}

make_num! {
  /// A resolved V2 short ID.
  ShortId, u8, 1
}

hash_impl!(ShortId);

impl ShortId {
  /// Long-format sentinel (a 12-byte command follows).
  pub const LONG_FORMAT: Self = Self(0);

  /// Returns `true` if this ID maps to a known command.
  pub const fn is_valid(self) -> bool {
    self.to_command_str().is_some()
  }

  /// Whether a V2 transport takes the ID as a message type, assigned or not.
  pub const fn is_in_table(self) -> bool {
    self.0 < LOW_TABLE_COUNT || (self.0 >= 128 && self.0 - 128 < HIGH_TABLE_COUNT)
  }

  /// Resolves the short ID to a `CommandString`, if known.
  pub fn to_command(self) -> Option<CommandString> {
    self.to_command_str().map(CommandString::from_static)
  }

  /// Looks up the short ID to send `cmd` by, given `common`, the version both
  /// peers share.
  ///
  /// `None` means the long format. A peer older than the version that
  /// assigned the short ID would not know it, so it gets the long format too.
  pub fn for_send(cmd: &CommandString, common: ProtocolVersion) -> Option<Self> {
    let assigned = if *cmd == CommandString::PLATFORMBAN {
      ProtocolVersion::PLATFORMBAN_V2_SHORT_ID
    } else {
      ProtocolVersion::BIP324_BASELINE
    };
    Self::from_command(cmd).filter(|_| common >= assigned)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  /// The reference tables have no gaps, so every short ID up to the last one
  /// in a table is assigned or listed as unassigned, and only once.
  #[rstest]
  fn tables_are_contiguous() {
    let held = |id: u8| ShortId::TABLE.iter().filter(|&&t| t == id).count() == 1;
    assert!((1..LOW_TABLE_COUNT).all(held));
    assert!((128..128 + HIGH_TABLE_COUNT).all(held));
    assert_eq!(
      ShortId::TABLE.len(),
      usize::from(LOW_TABLE_COUNT - 1 + HIGH_TABLE_COUNT)
    );
  }
}
