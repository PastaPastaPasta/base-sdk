//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version and capability handshake.

use crate::codec::{codec_p2p, impl_p2p, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::prelude::*;
use crate::version::ProtocolVersion;
use crate::P2pDecodeError;

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
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
/// is a decode error, so the fields present form a prefix. Encoding stops at
/// the first absent field. Decode from a cursor that ends with the payload.
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
  #[cfg_attr(feature = "serde", serde(default, with = "dash_types::serialize::opt_str_u64"))]
  pub nonce: Option<u64>,
  /// User agent string.
  pub user_agent: Option<UserAgent>,
  /// Sender's best block height.
  pub start_height: Option<i32>,
  /// Whether the sender wants transaction relay.
  pub relay: Option<bool>,
  /// Dash: masternode authentication challenge.
  pub mnauth_challenge: Option<Hash256>,
  /// Dash: whether the sender identifies as a masternode.
  pub mn_connection: Option<bool>,
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
    let mut version = Self::decode_head(data)?;
    version.decode_optional(data)?;
    Ok(version)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.protocol_version.encode(buf);
    self.services.encode(buf);
    self.timestamp.encode(buf);
    self.addr_recv.encode(buf);
    self.encode_optional(buf);
  }
}

hash_impl!(Version);

impl Version {
  /// Decodes the fields Core reads unconditionally, leaving the rest absent.
  fn decode_head(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      protocol_version: ProtocolVersion::decode(data)?,
      services: ServiceFlags::decode(data)?,
      timestamp: i64::decode(data)?,
      addr_recv: VersionAddr::decode(data)?,
      addr_send: None,
      nonce: None,
      user_agent: None,
      start_height: None,
      relay: None,
      mnauth_challenge: None,
      mn_connection: None,
    })
  }

  /// Decodes the optional fields in Core's order while bytes remain.
  fn decode_optional(&mut self, data: &mut &[u8]) -> Result<(), DecodeError> {
    if let Some(addr_send) = read_if_any(data)? {
      self.addr_send = Some(addr_send);
      self.nonce = Some(u64::decode(data)?);
    }
    self.user_agent = read_if_any(data)?;
    self.start_height = read_if_any(data)?;
    self.relay = read_if_any(data)?;
    self.mnauth_challenge = read_if_any(data)?;
    self.mn_connection = read_if_any(data)?;
    Ok(())
  }

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

  /// Whether the optional fields present are a prefix of Core's read order.
  ///
  /// Only such a `Version` decodes from a payload; encoding another one stops
  /// at its first absent field.
  pub fn has_prefix_tail(&self) -> bool {
    let present = [
      self.addr_send.is_some(),
      self.nonce.is_some(),
      self.user_agent.is_some(),
      self.start_height.is_some(),
      self.relay.is_some(),
      self.mnauth_challenge.is_some(),
      self.mn_connection.is_some(),
    ];
    present.windows(2).all(|pair| pair[0] || !pair[1]) && present[0] == present[1]
  }

  /// This message with every optional field absent.
  fn into_head(self) -> Self {
    Self {
      addr_send: None,
      nonce: None,
      user_agent: None,
      start_height: None,
      relay: None,
      mnauth_challenge: None,
      mn_connection: None,
      ..self
    }
  }
}

/// Core checks the peer's version and services right after the fields it
/// reads unconditionally, so a failure in the optional fields keeps them.
impl MsgDecode for Version {
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    let mut version = Self::decode_head(data)?;
    match version.decode_optional(data) {
      Ok(()) => Ok(version),
      Err(e) => Err(P2pDecodeError::VersionTail {
        head: Box::new(version.into_head()),
        error: format!("{e}"),
      }),
    }
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_json_rt, assert_serde_rt, check_wire, vec_from_hex, Corpus};
  use rstest::rstest;

  #[rstest]
  #[case::utf8(alloc::vec![b'/', b'>', b'.', b'.', b'<', b'/'])]
  #[case::non_utf8(alloc::vec![0xff, 0xfe, 0x80])]
  #[case::empty(Vec::new())]
  #[case::max(alloc::vec![0x80; MAX_USER_AGENT])]
  fn user_agent_json_round_trips(#[case] bytes: Vec<u8>) {
    assert_json_rt(&UserAgent(bytes));
  }

  /// A payload ending after `addr_recv`, as Core accepts it, keeps every
  /// optional field absent through the wire and JSON, `nonce` included.
  #[rstest]
  fn head_only_version_round_trips() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "decode_domain").into_value();
    let raw = corpus["version"]
      .as_array()
      .and_then(|cases| cases.iter().find(|c| c["name"] == "cut_46_mandatory_only"))
      .and_then(|c| c["raw"].as_str())
      .map(vec_from_hex)
      .unwrap_or_default();
    let mut cursor = &raw[..];
    let decoded = Version::decode(&mut cursor);
    assert!(cursor.is_empty());
    assert!(
      matches!(&decoded, Ok(v) if v.addr_send.is_none() && v.nonce.is_none() && v.mn_connection.is_none()),
      "{decoded:?}"
    );
    if let Ok(version) = decoded {
      let mut buf = Vec::new();
      version.encode(&mut buf);
      assert_eq!(buf, raw);
      assert_json_rt(&version);
    }
  }

  #[rstest]
  fn corpus_version() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "version");
    let items = corpus.entries::<Version>("version", check_wire);
    assert_serde_rt("version", &items);
  }
}
