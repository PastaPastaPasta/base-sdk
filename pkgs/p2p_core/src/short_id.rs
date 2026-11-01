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

make_num! {
  /// A resolved V2 short ID.
  ShortId, u8, 1
}

hash_impl!(ShortId);

impl ShortId {
  /// Long-format sentinel (a 12-byte command follows).
  pub const LONG_FORMAT: Self = Self::new(0);

  /// The first slot Core reserves without a message, which its V2 transport
  /// map assigns to the empty type (`V2MessageMap`).
  const EMPTY_TYPE: Self = Self::new(5);

  /// Returns `true` if this ID maps to a known command.
  pub const fn is_valid(self) -> bool {
    self.to_command_str().is_some()
  }

  /// Resolves the short ID to a `CommandString`, if known.
  pub fn to_command(self) -> Option<CommandString> {
    self.to_command_str().map(CommandString::from_static)
  }

  /// The common version from which Core sends `cmd` by its short ID, its
  /// `GetMessageMinVersion`.
  ///
  /// `platformban` got its ID later than the others.
  pub fn min_version(cmd: &CommandString) -> ProtocolVersion {
    if *cmd == CommandString::PLATFORMBAN {
      ProtocolVersion::PLATFORMBAN_V2_SHORT_ID
    } else {
      ProtocolVersion::BIP324_BASELINE
    }
  }

  /// Looks up the short ID to send `cmd` by, given `common`, the version both
  /// peers share.
  ///
  /// `None` means the long format. A peer older than the version that
  /// assigned the short ID would not know it, so it gets the long format too.
  pub fn for_send(cmd: &CommandString, common: ProtocolVersion) -> Option<Self> {
    Self::send_slot(cmd).filter(|_| common >= Self::min_version(cmd))
  }

  /// Core's `V2MessageMap`: the ID of every assigned slot, and the first
  /// reserved slot for the empty type.
  fn send_slot(cmd: &CommandString) -> Option<Self> {
    if *cmd == CommandString::EMPTY {
      return Some(Self::EMPTY_TYPE);
    }
    Self::from_command(cmd)
  }
}
