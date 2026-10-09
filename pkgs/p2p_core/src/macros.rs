//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macro definitions.

use crate::codec::MAX_P2P_PAYLOAD_SIZE;
use crate::command::CommandString;
use crate::P2pDecodeError;

use dash_types::codec::{BaseCodec, DecodeError};

/// Decodes a whole payload, failing on trailing bytes.
pub(crate) fn decode_msg<T: BaseCodec>(payload: &[u8]) -> Result<T, P2pDecodeError> {
  let mut cursor = payload;
  let msg = T::decode(&mut cursor)?;
  if !cursor.is_empty() {
    return Err(
      DecodeError::TrailingBytes {
        remaining: cursor.len(),
      }
      .into(),
    );
  }
  Ok(msg)
}

/// Reject payloads that exceed the protocol limit.
pub(crate) fn check_payload(command: &CommandString, payload: &[u8]) -> Result<(), P2pDecodeError> {
  if payload.len() > MAX_P2P_PAYLOAD_SIZE {
    return Err(P2pDecodeError::PayloadTooLarge {
      command: *command,
      size: payload.len(),
      max: MAX_P2P_PAYLOAD_SIZE,
    });
  }
  Ok(())
}

/// Reject payloads that should be empty.
pub(crate) fn check_empty(command: &'static str, payload: &[u8]) -> Result<(), P2pDecodeError> {
  if !payload.is_empty() {
    return Err(P2pDecodeError::PayloadNotEmpty {
      command,
      size: payload.len(),
    });
  }
  Ok(())
}

/// Generates `P2pMsg` definitions for every given valid message
macro_rules! define_p2p {
  (
    // Fully-parsed messages with a typed payload.
    parsed {
      $(
        $(#[$p_attr:meta])*
        $p_variant:ident ( $p_type:ty ) => $p_cmd:ident $p_wire:literal $(@ $p_sid:literal)?
      ),* $(,)?
    }
    // Fully-parsed messages with an empty payload.
    parsed_empty {
      $(
        $(#[$pe_attr:meta])*
        $pe_variant:ident => $pe_cmd:ident $pe_wire:literal $(@ $pe_sid:literal)?
      ),* $(,)?
    }
    // Recognised but not-yet-implemented (raw `Vec<u8>` payload).
    stub {
      $(
        $(#[$s_attr:meta])*
        $s_variant:ident => $s_cmd:ident $s_wire:literal $(@ $s_sid:literal)?
      ),* $(,)?
    }
    // Recognised but not-yet-implemented (empty payload).
    stub_empty {
      $(
        $(#[$se_attr:meta])*
        $se_variant:ident => $se_cmd:ident $se_wire:literal $(@ $se_sid:literal)?
      ),* $(,)?
    }
  ) => {
    impl CommandString {
      $(
        #[doc = concat!("Command string for `", $p_wire, "` messages.")]
        pub const $p_cmd: Self = Self::from_static($p_wire);
      )*
      $(
        #[doc = concat!("Command string for `", $pe_wire, "` messages.")]
        pub const $pe_cmd: Self = Self::from_static($pe_wire);
      )*
      $(
        #[doc = concat!("Command string for `", $s_wire, "` messages.")]
        pub const $s_cmd: Self = Self::from_static($s_wire);
      )*
      $(
        #[doc = concat!("Command string for `", $se_wire, "` messages.")]
        pub const $se_cmd: Self = Self::from_static($se_wire);
      )*
    }

    impl ShortId {
      /// Resolves the short ID to its command name, if one is assigned.
      pub const fn to_command_str(self) -> Option<&'static str> {
        match self.0 {
          $( $( $p_sid => Some($p_wire), )? )*
          $( $( $pe_sid => Some($pe_wire), )? )*
          $( $( $s_sid => Some($s_wire), )? )*
          $( $( $se_sid => Some($se_wire), )? )*
          _ => None,
        }
      }

      /// Looks up the short ID for a command, if one is assigned.
      ///
      /// `None` means the message has no short ID and must be sent in
      /// the long format.
      pub fn from_command(cmd: &CommandString) -> Option<Self> {
        match *cmd {
          $( $( CommandString::$p_cmd => Some(Self($p_sid)), )? )*
          $( $( CommandString::$pe_cmd => Some(Self($pe_sid)), )? )*
          $( $( CommandString::$s_cmd => Some(Self($s_sid)), )? )*
          $( $( CommandString::$se_cmd => Some(Self($se_sid)), )? )*
          _ => None,
        }
      }
    }

    /// A P2P network message.
    #[derive(Clone, Debug, Eq, PartialEq, Unencodable)]
    #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
    pub enum P2pMsg {
      $( $(#[$p_attr])* $p_variant($p_type), )*
      $( $(#[$pe_attr])* $pe_variant, )*
      $( $(#[$s_attr])* $s_variant(Vec<u8>), )*
      $( $(#[$se_attr])* $se_variant, )*
    }

    impl P2pMsg {
      /// Returns the 12-byte command string for this message.
      pub fn command(&self) -> CommandString {
        match self {
          $( Self::$p_variant(_) => CommandString::$p_cmd, )*
          $( Self::$pe_variant => CommandString::$pe_cmd, )*
          $( Self::$s_variant(_) => CommandString::$s_cmd, )*
          $( Self::$se_variant => CommandString::$se_cmd, )*
        }
      }

      /// Returns the V2 short ID for this message, if one exists.
      pub fn short_id(&self) -> Option<ShortId> {
        ShortId::from_command(&self.command())
      }

      /// Returns `true` when the message is recognised but not decoded.
      pub fn is_stub(&self) -> bool {
        match self {
          $( Self::$p_variant(_) => false, )*
          $( Self::$pe_variant => false, )*
          $( Self::$s_variant(_) => true, )*
          $( Self::$se_variant => true, )*
        }
      }

      /// Decodes a message from its command string and raw payload.
      ///
      /// Every command, known or not, is bound by Core's 3 MiB message limit
      /// first, as Core's transports refuse a larger message before reading
      /// its command.
      pub fn decode_payload(
        cmd: &CommandString,
        payload: &[u8],
      ) -> Result<Self, crate::P2pDecodeError> {
        crate::macros::check_payload(cmd, payload)?;
        let raw = || Vec::from(payload);
        let msg = match *cmd {
          $(
            CommandString::$p_cmd => Self::$p_variant(crate::macros::decode_msg(payload)?),
          )*
          $(
            CommandString::$pe_cmd => {
              crate::macros::check_empty($pe_wire, payload)?;
              Self::$pe_variant
            }
          )*
          $( CommandString::$s_cmd => Self::$s_variant(raw()), )*
          $(
            CommandString::$se_cmd => {
              crate::macros::check_empty($se_wire, payload)?;
              Self::$se_variant
            }
          )*
          _ => return Err(crate::P2pDecodeError::UnknownCommand { bytes: *cmd.as_bytes() }),
        };
        Ok(msg)
      }

      /// Encodes this message's payload (without command/short-ID framing).
      pub fn encode_payload(&self, buf: &mut Vec<u8>) {
        match self {
          $(
            Self::$p_variant(m) => {
              buf.extend_from_slice(&encoding::encode_to_vec(m));
            }
          )*
          $( Self::$pe_variant => {} )*
          $( Self::$s_variant(raw) => buf.extend_from_slice(raw), )* // nosemgrep: codec-no-raw-extend
          $( Self::$se_variant => {} )*
        }
      }
    }
  };
}
