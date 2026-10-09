//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for P2P message types.

use crate::ctx::ProtoCtx;
use crate::limits;
use crate::prelude::*;
use crate::P2pDecodeError;

use dash_types::codec::{read_bytes, BaseCodec, DecodeError};
use dash_types::{CompactSize, Numeric};

/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH`, the V1 payload limit.
pub(crate) const MAX_P2P_PAYLOAD_SIZE: usize = limits::MAX_PROTOCOL_MESSAGE_LENGTH;

/// Core's V2 `MAX_CONTENTS_LEN`: the long-form type and a V1-sized payload.
///
/// Core checks it on the whole contents before reading the type, so a
/// short-ID message may carry 12 payload bytes more than the V1 limit.
pub(crate) const MAX_V2_CONTENTS_SIZE: usize = limits::MAX_V2_CONTENTS_LEN;

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
  /// Returns `P2pDecodeError` where Core's handler throws, or stops before
  /// reading the rest of the payload.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    Ok(Self::decode(data)?)
  }
}

/// Reads a flag as 0 or 1, the bytes Core writes. Core reads any other byte
/// as `true`; here it is an error.
pub(crate) fn decode_flag(data: &mut &[u8]) -> Result<bool, DecodeError> {
  match u8::decode(data)? {
    0 => Ok(false),
    1 => Ok(true),
    other => Err(DecodeError::InvalidValue {
      expected: vec![0, 1],
      actual: u64::from(other),
    }),
  }
}

impl<T: MsgDecode> MsgDecode for Box<T> {
  fn decode_msg(data: &mut &[u8], ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    T::decode_msg(data, ctx).map(Box::new)
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

/// Reads Core's `LIMITED_VECTOR(v, limit)` of bytes: a size above `limit`
/// fails before any byte is read.
pub(crate) fn read_limited_byte_vec(data: &mut &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
  let len = CompactSize::decode_size(data)?.into_len(limit)?;
  Ok(read_bytes(data, len)?.to_vec())
}

/// Reads a count, rejecting one above `max` before any entry.
///
/// Core's handlers compare the count with their limit before reading the
/// entries (`headers`' `GetHeadersLimit`, `qdata`'s
/// `UnserializeVectorWithMaxSize`). A count larger than the
/// bytes left fails here too, where Core reads up to the end of the data
/// first; a smaller count the entries cannot fill fails where they run out,
/// as in Core.
pub(crate) fn read_count_at_most(data: &mut &[u8], command: &'static str, max: usize) -> Result<usize, P2pDecodeError> {
  let count = CompactSize::decode_size(data)?;
  if count.to_base() > max as u64 {
    return Err(P2pDecodeError::TooManyEntries {
      command,
      count: count.to_base(),
      max: max as u64,
    });
  }
  Ok(count.into_len(data.len())?)
}
