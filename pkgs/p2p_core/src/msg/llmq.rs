//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ messages: recovered signatures and quorum data requests.

use crate::codec::{codec_p2p, impl_p2p, read_count_at_most, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::prelude::*;

use dash_num::Hash256;
use dash_pkc::bls::{BlsIesBlobBytes, BlsPkBytes, BlsScIetf, BlsSigBytes};
use dash_primitives::{hash_impl, LlmqType, QuorumHash, TxHash};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, Numeric};

use core::fmt;

/// A recovered threshold signature, the `qsigrec` payload (Core's
/// `CRecoveredSig`).
///
/// Core reads the signature lazily and hashes the message over its wire
/// bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RecoveredSig {
  /// Type of the signing quorum.
  pub llmq_type: LlmqType,
  /// Hash of the signing quorum.
  pub quorum_hash: QuorumHash,
  /// Signing request identifier.
  pub id: Hash256,
  /// Hash of the signed message.
  pub msg_hash: Hash256,
  /// The recovered signature.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(RecoveredSig {
  llmq_type,
  quorum_hash,
  id,
  msg_hash,
  sig
});

impl fmt::Display for RecoveredSig {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "qsigrec({}, {})", self.llmq_type, self.id)
  }
}

/// Quorum data a [`QuorumDataRequest`] asks for: the verification vector.
pub const QUORUM_DATA_VVEC: u16 = 0x0001;

/// Quorum data a [`QuorumDataRequest`] asks for: the member's encrypted
/// contributions.
pub const QUORUM_DATA_CONTRIBUTIONS: u16 = 0x0002;

/// A request for quorum data, the `qgetdata` payload (Core's
/// `CQuorumDataRequest` without its response error).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct QuorumDataRequest {
  /// Type of the quorum.
  pub llmq_type: LlmqType,
  /// Hash of the quorum.
  pub quorum_hash: QuorumHash,
  /// The data asked for, [`QUORUM_DATA_VVEC`] and
  /// [`QUORUM_DATA_CONTRIBUTIONS`] bits.
  pub data_mask: u16,
  /// The member whose encrypted contributions are asked for.
  pub pro_tx_hash: TxHash,
}

codec_p2p!(QuorumDataRequest {
  llmq_type,
  quorum_hash,
  data_mask,
  pro_tx_hash
});

impl QuorumDataRequest {
  /// Size of the request on the wire, in bytes.
  pub const SIZE: usize = 1 + 32 + 2 + 32;
}

impl MsgDecode for QuorumDataRequest {
  /// Core's `qgetdata` handler refuses a payload longer than the request
  /// before reading it, with [`P2pDecodeError::HandlerPayloadTooLarge`]; the
  /// response error byte is never read.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    if data.len() > Self::SIZE {
      return Err(P2pDecodeError::HandlerPayloadTooLarge {
        command: "qgetdata",
        size: data.len(),
        max: Self::SIZE,
      });
    }
    Ok(Self::decode(data)?)
  }
}

impl fmt::Display for QuorumDataRequest {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "qgetdata({}, {}, mask {})",
      self.llmq_type, self.quorum_hash, self.data_mask
    )
  }
}

enum_map! {
  /// Outcome of a quorum data request, Core's `CQuorumDataRequest::Errors`.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum QuorumDataError, u8, Unknown {
    /// The data follows.
    None = 0 => "none",
    /// The quorum type is not one of the chain's.
    QuorumTypeInvalid = 1 => "quorum_type_invalid",
    /// The quorum block is not on the responder's active chain.
    QuorumBlockNotFound = 2 => "quorum_block_not_found",
    /// The responder has no commitment for the quorum.
    QuorumNotFound = 3 => "quorum_not_found",
    /// The member asked about is not in the quorum.
    MasternodeIsNoMember = 4 => "masternode_is_no_member",
    /// The responder lacks the verification vector.
    QuorumVerificationVectorMissing = 5 => "quorum_verification_vector_missing",
    /// The responder lacks the encrypted contributions.
    EncryptedContributionsMissing = 6 => "encrypted_contributions_missing",
    /// No error byte: missing on the wire, or 0xff, which Core never writes.
    Undefined = 255 => "undefined",
  }
}

impl_num!(QuorumDataError, u8);

hash_impl!(QuorumDataError);

/// Quorum data, the `qdata` payload: the request it answers, the outcome and,
/// for [`QuorumDataError::None`], the data.
///
/// The data is kept raw: its vectors are sized by the quorum, which only the
/// receiver knows, and Core reads them only after checking the request.
/// [`QData::read_data`] reads them as Core does. For any other outcome Core
/// ignores the bytes after the error; the decoder does too.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QData {
  /// The request answered.
  pub request: QuorumDataRequest,
  /// The outcome. [`QuorumDataError::Undefined`] is not written.
  pub error: QuorumDataError,
  /// The data, written only when the outcome is [`QuorumDataError::None`].
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub data: Vec<u8>,
}

impl_p2p!(QData);

impl BaseCodec for QData {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let request = QuorumDataRequest::decode(data)?;
    // Core catches the failed read of a missing error byte.
    let error = match data.split_first() {
      None => QuorumDataError::Undefined,
      Some((&b, rest)) => {
        *data = rest;
        QuorumDataError::from_base(b)
      }
    };
    let body = if error == QuorumDataError::None {
      core::mem::take(data).to_vec()
    } else {
      Vec::new()
    };
    Ok(Self {
      request,
      error,
      data: body,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.request.encode(buf);
    if self.error != QuorumDataError::Undefined {
      self.error.encode(buf);
    }
    if self.error == QuorumDataError::None {
      buf.extend_from_slice(&self.data); // nosemgrep: codec-no-raw-extend
    }
  }
}

hash_impl!(QData);

/// A quorum's verification vector, as `qdata` carries it.
pub type VerificationVector = Vec<BlsPkBytes<BlsScIetf>>;

/// The data of a `qdata` message, read as Core's handler reads it.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct QuorumData {
  /// The verification vector, when asked for.
  pub vvec: Option<VerificationVector>,
  /// The member's encrypted contributions, when asked for.
  pub contributions: Option<Vec<BlsIesBlobBytes<BlsScIetf>>>,
}

impl QData {
  /// Reads the data as Core does: the verification vector, then the
  /// encrypted contributions, each when the request's mask asks for it.
  ///
  /// Core refuses a vector whose size exceeds the quorum's before reading
  /// it: `max_vvec` is the quorum's threshold and `max_contributions` its
  /// valid member count. Bytes after the data are ignored. A shorter vector
  /// reads here; Core's handler then refuses any size but those two, a check
  /// left to the caller.
  ///
  /// Core's handler checks the vector, and reads the contributions only in
  /// the node states that use them; a caller that follows it reads the two
  /// with [`QData::read_vvec`] and [`QData::read_contributions`].
  ///
  /// # Errors
  ///
  /// Returns [`P2pDecodeError::TooManyEntries`] for a size over its limit,
  /// or a decode error where Core's read throws.
  pub fn read_data(&self, max_vvec: usize, max_contributions: usize) -> Result<QuorumData, P2pDecodeError> {
    let (vvec, rest) = self.read_vvec(max_vvec)?;
    Ok(QuorumData {
      vvec,
      contributions: self.read_contributions(rest, max_contributions)?,
    })
  }

  /// Reads the verification vector, when the request's mask asks for it,
  /// and returns it with the data after it.
  ///
  /// # Errors
  ///
  /// As [`QData::read_data`], for the vector.
  pub fn read_vvec(&self, max_vvec: usize) -> Result<(Option<VerificationVector>, &[u8]), P2pDecodeError> {
    let mut data = &self.data[..];
    if self.request.data_mask & QUORUM_DATA_VVEC == 0 {
      return Ok((None, data));
    }
    let vvec = read_bounded(&mut data, max_vvec, "qdata vvec")?;
    Ok((Some(vvec), data))
  }

  /// Reads the encrypted contributions from `rest`, the data after the
  /// verification vector ([`QData::read_vvec`]), when the request's mask
  /// asks for them.
  ///
  /// # Errors
  ///
  /// As [`QData::read_data`], for the contributions.
  pub fn read_contributions(
    &self,
    mut rest: &[u8],
    max_contributions: usize,
  ) -> Result<Option<Vec<BlsIesBlobBytes<BlsScIetf>>>, P2pDecodeError> {
    if self.request.data_mask & QUORUM_DATA_CONTRIBUTIONS == 0 {
      return Ok(None);
    }
    Ok(Some(read_bounded(&mut rest, max_contributions, "qdata contributions")?))
  }
}

/// Core's `UnserializeVectorWithMaxSize`: a size above `max` fails before
/// any entry is read.
fn read_bounded<T: BaseCodec>(data: &mut &[u8], max: usize, command: &'static str) -> Result<Vec<T>, P2pDecodeError> {
  read_count_at_most(&mut &data[..], command, max)?;
  Ok(Vec::<T>::decode(data)?)
}

impl fmt::Display for QData {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "qdata({}, {})", self.request.quorum_hash, self.error)
  }
}
