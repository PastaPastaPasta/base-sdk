//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Masternode messages: authentication, sporks and platform bans.

use crate::codec::{codec_p2p, impl_p2p, read_limited_byte_vec, MAX_P2P_PAYLOAD_SIZE};
use crate::prelude::*;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_primitives::{codec_base, hash_impl, QuorumHash, TxHash};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{Hashable, Numeric};

use core::fmt;

/// Largest spork signature Core reads, `CPubKey::COMPACT_SIGNATURE_SIZE`.
pub const MAX_SPORK_SIG_LEN: usize = 65;

/// Masternode authentication, the `mnauth` payload (Core's `CMNAuth`).
///
/// Core reads the signature eagerly under its process-wide BLS scheme; the
/// field holds the wire bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MnAuth {
  /// Registration transaction hash of the authenticating masternode.
  pub pro_reg_tx_hash: TxHash,
  /// Operator signature over the connection's challenge.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(MnAuth { pro_reg_tx_hash, sig });

impl fmt::Display for MnAuth {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "mnauth({})", self.pro_reg_tx_hash)
  }
}

/// A spork value, the `spork` payload (Core's `CSporkMessage`).
///
/// Core refuses to read a signature longer than [`MAX_SPORK_SIG_LEN`] but
/// writes any length, as does the encoder.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Spork {
  /// Spork identifier; Core reads any value.
  pub spork_id: i32,
  /// Spork value.
  pub value: i64,
  /// Signing time, seconds since the epoch.
  pub time_signed: i64,
  /// Compact ECDSA signature of the spork key.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

impl_p2p!(Spork);

impl BaseCodec for Spork {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      spork_id: i32::decode(data)?,
      value: i64::decode(data)?,
      time_signed: i64::decode(data)?,
      sig: read_limited_byte_vec(data, MAX_SPORK_SIG_LEN)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.spork_id.encode(buf);
    self.value.encode(buf);
    self.time_signed.encode(buf);
    self.sig.encode(buf);
  }
}

hash_impl!(Spork);

impl fmt::Display for Spork {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "spork({} = {})", self.spork_id, self.value)
  }
}

/// A platform ban vote, the `platformban` payload (Core's
/// `PlatformBanMessage`).
///
/// Core reads the signature eagerly in the basic scheme, whatever its
/// process-wide scheme; the field holds the wire bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct PlatformBan {
  /// Registration transaction hash of the masternode to ban.
  pub pro_tx_hash: TxHash,
  /// Height the ban is requested at.
  pub requested_height: i32,
  /// Hash of the signing quorum.
  pub quorum_hash: QuorumHash,
  /// Recovered threshold signature of the signing quorum.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_base!(PlatformBan, MAX_P2P_PAYLOAD_SIZE, {
  pro_tx_hash,
  requested_height,
  quorum_hash,
  sig
});

impl Hashable for PlatformBan {
  type Hash = Hash256;

  /// Core's `GetHash()`, the message's inventory hash: the double SHA-256
  /// of the message without its signature.
  fn hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.pro_tx_hash.encode(&mut buf);
    self.requested_height.encode(&mut buf);
    self.quorum_hash.encode(&mut buf);
    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl fmt::Display for PlatformBan {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "platformban({} at {})", self.pro_tx_hash, self.requested_height)
  }
}
