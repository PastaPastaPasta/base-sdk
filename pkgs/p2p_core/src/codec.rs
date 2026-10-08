//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for P2P message types.

use crate::ctx::ProtoCtx;
use crate::P2pDecodeError;

use dash_types::codec::BaseCodec;

/// Maximum buffered P2P message payload.
pub(crate) const MAX_P2P_PAYLOAD_SIZE: usize = 3_145_728;

/// A message payload decoded the way Core's handler reads it.
///
/// The handler's reads, not `Unserialize` alone, define what a peer may send.
/// They can depend on the [`ProtoCtx`] and can stop before the end of the
/// payload, whose remaining bytes Core ignores.
///
/// The default reads the type's wire image, for handlers that read exactly
/// that whatever the context.
pub trait MsgDecode: BaseCodec {
  /// Decodes from the front of `data` under `ctx`, advancing past the bytes
  /// the handler reads.
  ///
  /// # Errors
  ///
  /// Returns `P2pDecodeError` where Core's handler throws or rejects the
  /// payload before acting on it.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    Ok(Self::decode(data)?)
  }
}

/// Generates `Encode` + `Decode` with P2P payload size limit.
macro_rules! impl_p2p {
  ($ty:ty) => {
    $crate::__private::dash_types::impl_type!($ty, crate::codec::MAX_P2P_PAYLOAD_SIZE);
  };
}
pub(crate) use impl_p2p;

/// Generates `BaseCodec` + `Encode` + `Decode` for flat structs
/// with P2P payload size limit.
macro_rules! codec_p2p {
  ($ty:ty { $($field:ident),+ $(,)? }) => {
    $crate::__private::dash_primitives::codec_type!($ty, crate::codec::MAX_P2P_PAYLOAD_SIZE, { $($field),+ });
  };
}
pub(crate) use codec_p2p;
