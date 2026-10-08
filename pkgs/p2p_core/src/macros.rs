//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macro definitions.

use crate::codec::MAX_P2P_PAYLOAD_SIZE;
use crate::command::CommandString;
use crate::P2pDecodeError;

/// Rejects a V1 payload above Core's `MAX_PROTOCOL_MESSAGE_LENGTH`.
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
    // Fully-parsed messages whose handler reads no payload.
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
    // Recognised but not-yet-implemented, handler reads no payload.
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
      /// A command no handler knows, which Core logs and ignores.
      Unknown {
        /// The command as received.
        command: CommandString,
        /// The raw payload.
        payload: Vec<u8>,
      },
    }

    /// A message decoded by [`P2pMsg::decode_with_policy`].
    #[derive(Clone, Debug, Eq, PartialEq, Unencodable)]
    pub struct DecodedMsg {
      /// The decoded message.
      pub msg: P2pMsg,
      /// Payload bytes the handler reads or the message keeps raw. Core
      /// ignores the bytes after them.
      pub consumed: usize,
    }

    impl P2pMsg {
      /// Returns the 12-byte command string for this message.
      pub fn command(&self) -> CommandString {
        match self {
          $( Self::$p_variant(_) => CommandString::$p_cmd, )*
          $( Self::$pe_variant => CommandString::$pe_cmd, )*
          $( Self::$s_variant(_) => CommandString::$s_cmd, )*
          $( Self::$se_variant => CommandString::$se_cmd, )*
          Self::Unknown { command, .. } => *command,
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
          Self::Unknown { .. } => false,
        }
      }

      /// Returns `true` for a command no handler knows.
      pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
      }

      /// Decodes a V1 message as Core's handler for `cmd` reads its payload.
      ///
      /// An unknown command decodes to [`P2pMsg::Unknown`]. A command whose
      /// handler reads nothing ignores its payload, and a typed message
      /// reports the bytes its handler reads in [`DecodedMsg::consumed`].
      /// The payload is bound by the V1 transport's 3 MiB limit, then the
      /// command by its byte rules; [`crate::decode_v2`] applies the V2 rules
      /// instead. Gates that depend on connection state run before this.
      ///
      /// # Errors
      ///
      /// Returns `PayloadTooLarge`, on which Core disconnects, `InvalidCommand`,
      /// on which it drops the message, or a `P2pDecodeError` where its
      /// handler throws or stops before reading the rest.
      pub fn decode_with_policy(
        cmd: &CommandString,
        payload: &[u8],
        ctx: &crate::ctx::ProtoCtx,
      ) -> Result<DecodedMsg, crate::P2pDecodeError> {
        crate::macros::check_payload(cmd, payload)?;
        if !cmd.is_valid_v1() {
          return Err(crate::P2pDecodeError::InvalidCommand { command: *cmd });
        }
        Self::dispatch(cmd, payload, ctx)
      }

      /// Decodes as `cmd`'s handler reads, once the transport checks passed.
      pub(crate) fn dispatch(
        cmd: &CommandString,
        payload: &[u8],
        ctx: &crate::ctx::ProtoCtx,
      ) -> Result<DecodedMsg, crate::P2pDecodeError> {
        let mut cursor = payload;
        let msg = match *cmd {
          $(
            CommandString::$p_cmd => {
              Self::$p_variant(<$p_type as crate::codec::MsgDecode>::decode_msg(&mut cursor, ctx)?)
            }
          )*
          $( CommandString::$pe_cmd => Self::$pe_variant, )*
          $(
            CommandString::$s_cmd => {
              cursor = &[];
              Self::$s_variant(Vec::from(payload))
            }
          )*
          $( CommandString::$se_cmd => Self::$se_variant, )*
          _ => {
            cursor = &[];
            Self::Unknown { command: *cmd, payload: Vec::from(payload) }
          }
        };
        Ok(DecodedMsg { msg, consumed: payload.len() - cursor.len() })
      }

      /// Encodes this message's payload (without command/short-ID framing).
      pub fn encode_payload(&self, buf: &mut Vec<u8>) {
        match self {
          $(
            Self::$p_variant(m) => {
              $crate::__private::dash_types::codec::BaseCodec::encode(m, buf);
            }
          )*
          $( Self::$pe_variant => {} )*
          $( Self::$s_variant(raw) => buf.extend_from_slice(raw), )* // nosemgrep: codec-no-raw-extend
          $( Self::$se_variant => {} )*
          Self::Unknown { payload, .. } => buf.extend_from_slice(payload), // nosemgrep: codec-no-raw-extend
        }
      }
    }
  };
}
