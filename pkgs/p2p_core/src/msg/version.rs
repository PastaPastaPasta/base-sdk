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
use dash_types::{impl_new, make_num, CompactSize};
use getset::{CopyGetters, Getters};

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

impl_new! {
/// The user agent exceeds the 256-byte limit.
#[derive(Debug, Clone, CopyGetters, PartialEq, Eq, thiserror::Error, Unencodable)]
#[error("user agent too long: {size} bytes, max {MAX_USER_AGENT}")]
pub struct UserAgentTooLong {
  /// Actual length in bytes.
  #[getset(get_copy = "pub")]
  size: usize,
}
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
      return Err(UserAgentTooLong::new(bytes.len()));
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
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VersionAddr {
  /// Advertised services.
  #[getset(get_copy = "pub")]
  services: ServiceFlags,
  /// IPv4-mapped IPv6 address + port.
  #[getset(get = "pub")]
  addr: ServiceV1,
}
}

impl fmt::Display for VersionAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?} ({})", self.addr, self.services)
  }
}

impl_new! {
/// The `version` message initiates the P2P handshake.
///
/// Dash extends the Bitcoin version message with two additional
/// fields for masternode authentication.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Version {
  /// Sender's protocol version.
  #[getset(get_copy = "pub")]
  protocol_version: ProtocolVersion,
  /// Sender's advertised services.
  #[getset(get_copy = "pub")]
  services: ServiceFlags,
  /// Unix timestamp of the sender.
  #[getset(get_copy = "pub")]
  timestamp: i64,
  /// Receiver's address as seen by the sender.
  #[getset(get = "pub")]
  addr_recv: VersionAddr,
  /// Sender's own address, present with `nonce`.
  #[getset(get = "pub")]
  addr_send: Option<VersionAddr>,
  /// Random nonce for connection deduplication, taken as 1 if absent.
  #[cfg_attr(feature = "serde", serde(default, with = "dash_types::serialize::str_u64"))]
  #[getset(get_copy = "pub")]
  nonce: Option<u64>,
  /// User agent string.
  #[getset(get = "pub")]
  user_agent: Option<UserAgent>,
  /// Sender's best block height, taken as -1 if absent.
  #[getset(get_copy = "pub")]
  start_height: Option<i32>,
  /// Whether the sender wants transaction relay, taken as true if absent.
  #[getset(get_copy = "pub")]
  relay: Option<bool>,
  /// Dash: masternode authentication challenge.
  #[getset(get_copy = "pub")]
  mnauth_challenge: Option<Hash256>,
  /// Dash: whether the sender identifies as a masternode.
  #[getset(get_copy = "pub")]
  mn_connection: Option<bool>,
}
}

impl_p2p!(Version);

impl BaseCodec for Version {
  /// Decodes a `version`, reading the fields from `addr_send` on only while
  /// payload bytes remain, `addr_send` and `nonce` together.
  ///
  /// A field cut short fails the decode, so the fields present form a prefix.
  /// Decode from a cursor that ends with the payload.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let protocol_version = ProtocolVersion::decode(data)?;
    let services = ServiceFlags::decode(data)?;
    let timestamp = i64::decode(data)?;
    let addr_recv = VersionAddr::decode(data)?;
    let (addr_send, nonce) = match decode_if_any::<VersionAddr>(data)? {
      Some(addr_send) => (Some(addr_send), Some(u64::decode(data)?)),
      None => (None, None),
    };
    let user_agent = decode_if_any(data)?;
    let start_height = decode_if_any(data)?;
    let relay = decode_if_any(data)?;
    let mnauth_challenge = decode_if_any(data)?;
    let mn_connection = decode_if_any(data)?;
    Ok(Self {
      protocol_version,
      services,
      timestamp,
      addr_recv,
      addr_send,
      nonce,
      user_agent,
      start_height,
      relay,
      mnauth_challenge,
      mn_connection,
    })
  }

  /// Encodes a `version`, stopping at the first absent field, `addr_send`
  /// and `nonce` together.
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

/// Decodes a `T` if any bytes remain, else gives `None`.
fn decode_if_any<T: BaseCodec>(data: &mut &[u8]) -> Result<Option<T>, DecodeError> {
  if data.is_empty() {
    return Ok(None);
  }
  T::decode(data).map(Some)
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::command::CommandString;
  use crate::msg::P2pMsg;

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

  /// `full` with only its first `kept` optional fields, `addr_send` and
  /// `nonce` counting as one.
  fn keep_optional(full: &Version, kept: usize) -> Version {
    let mut version = full.clone();
    if kept < 1 {
      version.addr_send = None;
      version.nonce = None;
    }
    if kept < 2 {
      version.user_agent = None;
    }
    if kept < 3 {
      version.start_height = None;
    }
    if kept < 4 {
      version.relay = None;
    }
    if kept < 5 {
      version.mnauth_challenge = None;
    }
    if kept < 6 {
      version.mn_connection = None;
    }
    version
  }

  /// A corpus payload cut where an optional field starts decodes without it
  /// and the fields after it, and encodes back to the cut. A cut anywhere
  /// else fails.
  #[rstest]
  fn corpus_version_cut_at_each_optional_field() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "version");
    for (label, full) in corpus.entries::<Version>("version", check_wire) {
      let mut raw = Vec::new();
      full.encode(&mut raw);
      let agent = full.user_agent.as_ref().map_or(0, UserAgent::len);
      let starts = [46, 80, 81 + agent, 85 + agent, 86 + agent, 118 + agent, 119 + agent];
      assert_eq!(starts[6], raw.len(), "{label}");
      for len in 0..=raw.len() {
        let decoded = P2pMsg::decode_payload(&CommandString::VERSION, &raw[..len]);
        match starts.iter().position(|&start| start == len) {
          Some(kept) => {
            let cut = keep_optional(&full, kept);
            assert_eq!(decoded, Ok(P2pMsg::Version(cut.clone())), "{label} cut at {len}");
            let mut buf = Vec::new();
            cut.encode(&mut buf);
            assert_eq!(buf, &raw[..len], "{label} cut at {len}");
            assert_json_rt(&cut);
          }
          None => assert!(decoded.is_err(), "{label} cut at {len}"),
        }
      }
    }
  }

  /// A field after an absent one is not written.
  #[rstest]
  fn encoding_stops_at_the_first_absent_field() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "version");
    for (label, full) in corpus.entries::<Version>("version", check_wire) {
      let mut gap = full.clone();
      gap.user_agent = None;
      let mut buf = Vec::new();
      gap.encode(&mut buf);
      let mut head = Vec::new();
      keep_optional(&full, 1).encode(&mut head);
      assert_eq!(buf, head, "{label}");
    }
  }
}
