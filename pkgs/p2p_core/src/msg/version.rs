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
use dash_types::{make_num, CompactSize, CoreBool};

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
#[derive(Debug, Clone, PartialEq, Eq, Unencodable)]
pub struct UserAgentTooLong {
  /// Actual length in bytes.
  pub len: usize,
}

impl fmt::Display for UserAgentTooLong {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "user agent too long: {} bytes, max {MAX_USER_AGENT}", self.len)
  }
}

/// CompactSize-prefixed user agent bytestring.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct UserAgent(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::utf8_lossy"))] Vec<u8>);

impl_p2p!(UserAgent);

impl BaseCodec for UserAgent {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let len = CompactSize::decode_size(data)?.into_len(MAX_USER_AGENT)?;
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

codec_p2p!(VersionAddr { services, addr });

impl fmt::Display for VersionAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?} ({})", self.addr, self.services)
  }
}

/// The `version` message initiates the P2P handshake.
///
/// Dash extends the Bitcoin version message with two additional
/// fields for masternode authentication.
///
/// Core reads the fields up to `addr_recv` unconditionally, then each later
/// field only while payload bytes remain, `addr_send` and `nonce` together.
/// A field is `None` when the payload ends before it, and a field cut short
/// is a decode error. Encoding stops at the first absent field, so decode
/// from a cursor that ends with the payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Version {
  /// Sender's protocol version.
  pub protocol_version: ProtocolVersion,
  /// Sender's advertised services.
  pub services: ServiceFlags,
  /// Unix timestamp of the sender, unchecked.
  pub timestamp: i64,
  /// Receiver's address as seen by the sender.
  pub addr_recv: VersionAddr,
  /// Sender's own address, present with `nonce`.
  pub addr_send: Option<VersionAddr>,
  /// Random nonce for connection deduplication.
  #[cfg_attr(feature = "serde", serde(default, with = "opt_str_u64"))]
  pub nonce: Option<u64>,
  /// User agent string.
  pub user_agent: Option<UserAgent>,
  /// Sender's best block height.
  pub start_height: Option<i32>,
  /// Whether the sender wants transaction relay.
  pub relay: Option<CoreBool>,
  /// Dash: masternode authentication challenge.
  pub mnauth_challenge: Option<Hash256>,
  /// Dash: whether the sender identifies as a masternode.
  pub mn_connection: Option<CoreBool>,
}

impl_p2p!(Version);

/// Decodes `T` when bytes remain, as Core's `if (!vRecv.empty())`.
fn read_if_any<T: BaseCodec>(data: &mut &[u8]) -> Result<Option<T>, DecodeError> {
  if data.is_empty() {
    return Ok(None);
  }
  T::decode(data).map(Some)
}

impl BaseCodec for Version {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let protocol_version = ProtocolVersion::decode(data)?;
    let services = ServiceFlags::decode(data)?;
    let timestamp = i64::decode(data)?;
    let addr_recv = VersionAddr::decode(data)?;
    let (addr_send, nonce) = match read_if_any::<VersionAddr>(data)? {
      Some(addr) => (Some(addr), Some(u64::decode(data)?)),
      None => (None, None),
    };
    Ok(Self {
      protocol_version,
      services,
      timestamp,
      addr_recv,
      addr_send,
      nonce,
      user_agent: read_if_any(data)?,
      start_height: read_if_any(data)?,
      relay: read_if_any(data)?,
      mnauth_challenge: read_if_any(data)?,
      mn_connection: read_if_any(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.protocol_version.encode(buf);
    self.services.encode(buf);
    self.timestamp.encode(buf);
    self.addr_recv.encode(buf);
    self.encode_optional(buf);
  }
}

impl Version {
  /// Writes the optional fields up to the first absent one.
  fn encode_optional(&self, buf: &mut impl EncodeBuf) -> Option<()> {
    let (addr_send, nonce) = (self.addr_send.as_ref()?, self.nonce?);
    addr_send.encode(buf);
    nonce.encode(buf);
    self.user_agent.as_ref()?.encode(buf);
    self.start_height?.encode(buf);
    self.relay?.encode(buf);
    self.mnauth_challenge.as_ref()?.encode(buf);
    self.mn_connection?.encode(buf);
    Some(())
  }
}

hash_impl!(Version);

/// [`dash_types::serialize::str_u64`] for an optional field.
#[cfg(feature = "serde")]
mod opt_str_u64 {
  use dash_types::serialize::str_u64;

  #[derive(::serde::Deserialize, ::serde::Serialize)]
  struct Wrap(#[serde(with = "str_u64")] u64);

  /// Serializes `Some` as `str_u64` does and `None` as unit.
  pub fn serialize<S: serde::Serializer>(val: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(&val.map(Wrap), s)
  }

  /// Deserializes what [`serialize`] writes.
  pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Ok(<Option<Wrap> as serde::Deserialize>::deserialize(d)?.map(|Wrap(v)| v))
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_json_rt, assert_serde_rt, check_wire, Corpus};
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
  fn corpus_version() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "version");
    let items = corpus.entries::<Version>("version", check_wire);
    assert_serde_rt("version", &items);
  }
}
