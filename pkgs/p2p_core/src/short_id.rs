//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V2 short ID mapping for BIP324 message framing.

use crate::command::CommandString;
use crate::version::ProtocolVersion;

use dash_types::type_id::Unencodable;

/// A resolved V2 short ID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ShortId(pub u8);

impl ShortId {
  /// Long-format sentinel (a 12-byte command follows).
  pub const LONG_FORMAT: Self = Self(0);

  /// The first slot Core reserves without a message, which its V2 transport
  /// map assigns to the empty type (`V2MessageMap`).
  const EMPTY_TYPE: Self = Self(5);

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

  /// The short ID Core's V2 transport sends `cmd` by to a peer whose common
  /// version is `peer_version`, its `SetMessageToSend`.
  ///
  /// `None` means the long format. Before the peer's `version` arrives Core
  /// uses [`ProtocolVersion::INIT`], so every message goes in the long format.
  pub fn for_send(cmd: &CommandString, peer_version: ProtocolVersion) -> Option<Self> {
    let id = Self::send_slot(cmd)?;
    (peer_version >= Self::min_version(cmd)).then_some(id)
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
