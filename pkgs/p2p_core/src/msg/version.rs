//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version and capability handshake.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::version::ProtocolVersion;

use dash_num::Hash256;
use dash_primitives::{hash_impl, ServiceV1};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{make_num, CompactSize};

use core::fmt;
use core::ops::{BitAnd, BitOr, BitOrAssign};

/// Maximum user agent (subversion) length in bytes.
const MAX_USER_AGENT: usize = 256;

make_num! {
  /// Bitfield advertised in `version` messages describing node capabilities.
  ServiceFlags, u64, 8
}

hash_impl!(ServiceFlags);

impl ServiceFlags {
  /// No services.
  pub const NONE: Self = Self(0);
  /// Full blockchain data.
  pub const NODE_NETWORK: Self = Self(1 << 0);
  /// BIP37 bloom filters.
  pub const NODE_BLOOM: Self = Self(1 << 2);
  /// BIP157 compact block filters.
  pub const NODE_COMPACT_FILTERS: Self = Self(1 << 6);
  /// Last 288 blocks only.
  pub const NODE_NETWORK_LIMITED: Self = Self(1 << 10);
  /// Dash compressed headers (headers2).
  pub const NODE_HEADERS_COMPRESSED: Self = Self(1 << 11);
  /// BIP324 v2 transport.
  pub const NODE_P2P_V2: Self = Self(1 << 12);

  /// Returns `true` if all bits in `flag` are set.
  pub const fn has(self, flag: Self) -> bool {
    self.0 & flag.0 == flag.0
  }
}

impl BitAnd for ServiceFlags {
  type Output = Self;
  fn bitand(self, rhs: Self) -> Self {
    Self(self.0 & rhs.0)
  }
}

impl BitOr for ServiceFlags {
  type Output = Self;
  fn bitor(self, rhs: Self) -> Self {
    Self(self.0 | rhs.0)
  }
}

impl BitOrAssign for ServiceFlags {
  fn bitor_assign(&mut self, rhs: Self) {
    self.0 |= rhs.0;
  }
}

/// The user agent exceeds the 256-byte limit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Unencodable)]
#[error("user agent too long: {len} bytes, max {MAX_USER_AGENT}")]
pub struct UserAgentTooLong {
  /// Actual length in bytes.
  pub len: usize,
}

/// CompactSize-prefixed user agent bytestring.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
pub struct UserAgent(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::utf8_lossy"))] Vec<u8>);

impl_p2p!(UserAgent);

impl BaseCodec for UserAgent {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let len = CompactSize::decode_len(data, MAX_USER_AGENT)?;
    let raw = codec::read_bytes(data, len)?;
    Ok(Self(raw.to_vec()))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

hash_impl!(UserAgent);

impl UserAgent {
  /// Creates a new user agent from raw bytes.
  ///
  /// # Errors
  ///
  /// Returns `UserAgentTooLong` if `bytes` exceeds 256 bytes.
  pub fn new(bytes: Vec<u8>) -> Result<Self, UserAgentTooLong> {
    if bytes.len() > MAX_USER_AGENT {
      return Err(UserAgentTooLong { len: bytes.len() });
    }
    Ok(Self(bytes))
  }

  /// Returns the user agent bytes as a str, if valid UTF-8.
  pub fn as_str(&self) -> Option<&str> {
    core::str::from_utf8(&self.0).ok()
  }

  /// Returns the raw bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  /// Returns the length in bytes.
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns `true` if the user agent is empty.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl fmt::Display for UserAgent {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.as_str() {
      Some(s) => f.write_str(s),
      None => write!(f, "<{} bytes>", self.0.len()),
    }
  }
}

impl TryFrom<Vec<u8>> for UserAgent {
  type Error = UserAgentTooLong;

  fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
    Self::new(bytes)
  }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for UserAgent {
  fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let bytes = dash_types::serialize::utf8_lossy::deserialize(deserializer)?;
    Self::new(bytes).map_err(::serde::de::Error::custom)
  }
}

codec_p2p! {
/// Network address with service flags (used inside the version message).
///
/// Wire format: `u64 services` + `[u8; 16] addr` + `u16 BE port`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VersionAddr {
  /// Advertised services.
  pub services: ServiceFlags,
  /// IPv4-mapped IPv6 address + port.
  pub addr: ServiceV1,
}
}

impl fmt::Display for VersionAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?} ({})", self.addr, self.services)
  }
}

codec_p2p! {
/// The `version` message initiates the P2P handshake.
///
/// Dash extends the Bitcoin version message with two additional
/// fields for masternode authentication.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Version {
  /// Sender's protocol version.
  pub protocol_version: ProtocolVersion,
  /// Sender's advertised services.
  pub services: ServiceFlags,
  /// Unix timestamp of the sender.
  pub timestamp: i64,
  /// Receiver's address as seen by the sender.
  pub addr_recv: VersionAddr,
  /// Sender's own address.
  pub addr_send: VersionAddr,
  /// Random nonce for connection deduplication.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
  /// User agent string.
  pub user_agent: UserAgent,
  /// Sender's best block height.
  pub start_height: i32,
  /// Whether the sender wants transaction relay.
  pub relay: bool,
  /// Dash: masternode authentication challenge.
  pub mnauth_challenge: Hash256,
  /// Dash: whether the sender identifies as a masternode.
  pub mn_connection: bool,
}
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_json_rt, assert_serde_rt, check_wire, json_rejects, to_json, Corpus};
  use rstest::rstest;

  #[rstest]
  #[case::utf8(alloc::vec![b'/', b'>', b'.', b'.', b'<', b'/'])]
  #[case::non_utf8(alloc::vec![0xff, 0xfe, 0x80])]
  #[case::empty(Vec::new())]
  #[case::max(alloc::vec![0x80; MAX_USER_AGENT])]
  fn user_agent_json_round_trips(#[case] bytes: Vec<u8>) {
    assert_json_rt(&UserAgent(bytes));
  }

  #[rstest]
  fn user_agent_json_rejects_oversize() {
    let json = to_json(&UserAgent(alloc::vec![b'a'; MAX_USER_AGENT + 1]));
    assert!(json_rejects::<UserAgent>(&json));
  }

  #[rstest]
  fn corpus_version() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "version");
    let items = corpus.entries::<Version>("version", check_wire);
    assert_serde_rt("version", &items);
  }
}
