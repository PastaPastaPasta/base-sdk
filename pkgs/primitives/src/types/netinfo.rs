//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network information types and trait.

use super::netaddr::{is_bad_port, NetAddr};
use super::{AddrV2, NetAddrError, ServiceV1, ServiceV2};
use crate::hash_impl;
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_new, impl_num, impl_type, Checkable, CompactSize, Numeric, MAX_SER_SIZE};
use getset::{CopyGetters, Getters};

use core::fmt;

/// Maximum entries per purpose.
const MAX_ENTRIES: usize = 4;
/// Maximum label length per RFC 1035.
const DOMAIN_LABEL_MAX: usize = 63;
/// Maximum FQDN length.
const DOMAIN_MAX: usize = 253;
/// Minimum FQDN length.
const DOMAIN_MIN: usize = 3;

/// Reserved and privacy TLDs that must be rejected.
const TLDS_BAD: &[&str] = &[
  // ICANN resolution 2018.02.04.12
  ".mail",
  // Infrastructure TLD
  ".arpa",
  // RFC 6761
  ".example",
  ".invalid",
  ".localhost",
  ".test",
  // RFC 6762
  ".local",
  // RFC 6762, appendix G
  ".corp",
  ".home",
  ".internal",
  ".intranet",
  ".lan",
  ".private",
];
/// Privacy-network TLDs that must be rejected.
const TLDS_PRIVACY: &[&str] = &[".i2p", ".onion"];

enum_map! {
  /// Purpose tag for an extended network info entry.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum NIPurpose, u8, Unknown {
    /// Core P2P port.
    CoreP2p = 0 => "core_p2p",
    /// Platform P2P port.
    PlatformP2p = 1 => "platform_p2p",
    /// Platform HTTPS port.
    PlatformHttps = 2 => "platform_https",
  }
}

impl_num!(NIPurpose, u8);

hash_impl!(NIPurpose);

enum_map! {
  /// Type tag for an extended network info entry.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum NIEntryCode, u8, Unknown {
    /// BIP155 address + port.
    Service = 0x01 => "service",
    /// Domain name + port.
    Domain = 0x02 => "domain",
  }
}

impl_num!(NIEntryCode, u8);

hash_impl!(NIEntryCode);

/// Network info validation error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
pub enum NIError {
  /// Address failed validation.
  #[error("invalid address: {error}")]
  BadAddr {
    /// The underlying address error.
    error: NetAddrError,
  },
  /// Port is zero or invalid for context.
  #[error("invalid port {port}")]
  BadPort {
    /// The invalid port value.
    port: u16,
  },
  /// Entry or address type not valid for this purpose.
  #[error("unsupported entry type {entry_type}")]
  BadType {
    /// The offending entry type byte.
    entry_type: u8,
  },
  /// Duplicate address:port within the structure.
  #[error("duplicate entry")]
  Duplicate,
  /// Too many entries or purpose groups.
  #[error("too many entries: {count} exceeds limit {max}")]
  MaxLimit {
    /// Actual count.
    count: usize,
    /// Maximum allowed.
    max: usize,
  },
  /// Structural integrity violation.
  #[error("malformed structure")]
  Malformed,
}

/// A single network info entry within a purpose group.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum NIEntry {
  /// BIP155 address + port.
  Service(ServiceV2),
  /// Domain name + port.
  Domain {
    /// The domain name as raw bytes.
    #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::utf8"))]
    name: Vec<u8>,
    /// Network port (big-endian on wire).
    port: u16,
  },
}

impl BaseCodec for NIEntry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    match NIEntryCode::from_base(u8::decode(data)?) {
      NIEntryCode::Service => Ok(Self::Service(ServiceV2::decode(data)?)),
      NIEntryCode::Domain => {
        let name_len = CompactSize::decode_len(data, DOMAIN_MAX)?;
        let name = codec::read_bytes(data, name_len)?.to_vec();
        let port = codec::read_u16_be(data)?;
        Ok(Self::Domain { name, port })
      }
      NIEntryCode::Unknown(t) => Err(DecodeError::InvalidValue {
        expected: NIEntryCode::variants().iter().map(|v| u64::from(v.to_base())).collect(),
        actual: u64::from(t),
      }),
    }
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    match self {
      Self::Service(svc) => {
        NIEntryCode::Service.to_base().encode(buf);
        svc.encode(buf);
      }
      Self::Domain { name, port } => {
        NIEntryCode::Domain.to_base().encode(buf);
        name.encode(buf);
        buf.extend_from_slice(&port.to_be_bytes());
      }
    }
  }
}

/// Validates a domain name per RFC 1035 consensus rules.
fn check_domain(name: &[u8]) -> Option<NIError> {
  let s = match core::str::from_utf8(name) {
    Ok(s) => s,
    Err(_) => return Some(NIError::Malformed),
  };
  if s.len() < DOMAIN_MIN || s.len() > DOMAIN_MAX {
    return Some(NIError::Malformed);
  }
  if s.bytes().any(|b| b.is_ascii_uppercase()) {
    return Some(NIError::Malformed);
  }
  if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
    return Some(NIError::Malformed);
  }
  if s.as_bytes()[0] == b'.' || s.as_bytes()[s.len() - 1] == b'.' {
    return Some(NIError::Malformed);
  }
  let mut label_count = 0usize;
  for label in s.split('.') {
    if label.is_empty() || label.len() > DOMAIN_LABEL_MAX {
      return Some(NIError::Malformed);
    }
    if label.as_bytes()[0] == b'-' || label.as_bytes()[label.len() - 1] == b'-' {
      return Some(NIError::Malformed);
    }
    label_count += 1;
  }
  if label_count < 2 {
    return Some(NIError::Malformed);
  }
  // Reject reserved and privacy TLDs.
  if TLDS_BAD.iter().chain(TLDS_PRIVACY.iter()).any(|tld| s.ends_with(tld)) {
    return Some(NIError::Malformed);
  }
  // TLD must be purely alphabetic (ICANN guideline).
  let last_label = s.rsplit('.').next().unwrap_or("");
  if !last_label.bytes().all(|b| b.is_ascii_lowercase()) {
    return Some(NIError::Malformed);
  }
  None
}

impl Checkable for NIEntry {
  type Error = NIError;

  fn check(&self) -> Option<Self::Error> {
    match self {
      Self::Service(svc) => {
        if let Some(error) = svc.check() {
          return Some(NIError::BadAddr { error });
        }
        if !svc.addr().is_i2p() && is_bad_port(svc.port()) {
          return Some(NIError::BadPort { port: svc.port() });
        }
        None
      }
      Self::Domain { name, port } => {
        if *port == 0 || (is_bad_port(*port) && *port != 443) {
          return Some(NIError::BadPort { port: *port });
        }
        check_domain(name)
      }
    }
  }
}

hash_impl!(NIEntry);

impl fmt::Display for NIEntry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Service(svc) => write!(f, "{svc}"),
      Self::Domain { name, port } => {
        let s = core::str::from_utf8(name).unwrap_or("<invalid utf-8>");
        write!(f, "{s}:{port}")
      }
    }
  }
}

/// Interface for network information types.
pub trait NITrait: fmt::Display {
  /// Returns entries, optionally filtered by purpose.
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_;

  /// Returns the primary service if available.
  fn primary(&self) -> Option<ServiceV2>;

  /// Returns `true` when this value carries no addresses.
  fn is_empty(&self) -> bool;

  /// Returns `true` if entries exist for the given purpose.
  fn has_entries(&self, purpose: NIPurpose) -> bool;

  /// Returns `true` when this type can carry platform addresses.
  fn stores_platform(&self) -> bool;
}

impl_new! {
/// Extended network info for v3+ ProRegTx / ProUpServTx.
///
/// Contains a versioned list of purpose-grouped network entries (core P2P,
/// platform P2P, platform HTTPS).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct NetInfoV2 {
  /// Format version.
  #[getset(get_copy = "pub")]
  version: u8,
  /// Purpose-grouped entries.
  #[cfg_attr(feature = "serde", serde(rename = "entries"))]
  #[getset(get = "pub")]
  groups: Vec<(NIPurpose, Vec<NIEntry>)>,
}
}

impl_type!(NetInfoV2);

impl BaseCodec for NetInfoV2 {
  /// Decodes an extended network info. A group purpose that is unknown, or
  /// not above the purpose before it, fails the decode.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u8::decode(data)?;
    let purpose_count = CompactSize::decode_len(data, MAX_SER_SIZE)?;
    let mut groups: Vec<(NIPurpose, Vec<NIEntry>)> = Vec::with_capacity(purpose_count);
    for _ in 0..purpose_count {
      let purpose = read_purpose(data, groups.last().map(|(last, _)| *last))?;
      let entry_count = CompactSize::decode_len(data, MAX_SER_SIZE)?;
      let mut group = Vec::with_capacity(entry_count);
      for _ in 0..entry_count {
        group.push(NIEntry::decode(data)?);
      }
      groups.push((purpose, group));
    }
    Ok(Self { version, groups })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    CompactSize::from(self.groups.len()).encode(buf);
    for (purpose, group) in &self.groups {
      purpose.to_base().encode(buf);
      CompactSize::from(group.len()).encode(buf);
      for entry in group {
        entry.encode(buf);
      }
    }
  }
}

impl Checkable for NetInfoV2 {
  type Error = NIError;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > Self::CURRENT_VERSION {
      return Some(NIError::Malformed);
    }
    if self.groups.is_empty() {
      return Some(NIError::Malformed);
    }
    if self
      .groups
      .iter()
      .any(|(purpose, _)| matches!(purpose, NIPurpose::Unknown(_)))
    {
      return Some(NIError::Malformed);
    }
    // Duplicate purpose key detection.
    for i in 0..self.groups.len() {
      for j in (i + 1)..self.groups.len() {
        if self.groups[i].0 == self.groups[j].0 {
          return Some(NIError::Duplicate);
        }
      }
    }
    if self
      .groups
      .windows(2)
      .any(|pair| pair[0].0.to_base() > pair[1].0.to_base())
    {
      return Some(NIError::Malformed);
    }
    // addr:port duplicates across all entries
    let all: Vec<&NIEntry> = self.groups.iter().flat_map(|(_, g)| g.iter()).collect();
    for i in 0..all.len() {
      for j in (i + 1)..all.len() {
        if all[i] == all[j] {
          return Some(NIError::Duplicate);
        }
      }
    }
    for (purpose, group) in &self.groups {
      if matches!(purpose, NIPurpose::Unknown(_)) {
        return Some(NIError::Malformed);
      }
      if group.is_empty() {
        return Some(NIError::Malformed);
      }
      if group.len() > MAX_ENTRIES {
        return Some(NIError::MaxLimit {
          count: group.len(),
          max: MAX_ENTRIES,
        });
      }
      // addr-only duplicates within purpose group
      for i in 0..group.len() {
        for j in (i + 1)..group.len() {
          if same_addr(&group[i], &group[j]) {
            return Some(NIError::Duplicate);
          }
        }
      }
      for entry in group {
        if let NIEntry::Service(svc) = entry {
          if matches!(svc.addr(), AddrV2::Unknown { .. }) {
            return Some(NIError::BadType {
              entry_type: svc.addr().network().to_base(),
            });
          }
        }
        if matches!(entry, NIEntry::Domain { .. }) && *purpose != NIPurpose::PlatformHttps {
          return Some(NIError::BadType { entry_type: 0x02 });
        }
        if let Some(e) = entry.check() {
          return Some(e);
        }
      }
    }
    None
  }
}

hash_impl!(NetInfoV2);

impl NetInfoV2 {
  /// Highest supported format version.
  const CURRENT_VERSION: u8 = 1;
}

impl fmt::Display for NetInfoV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.groups.is_empty() {
      return f.write_str("NetInfoV2()");
    }
    f.write_str("NetInfoV2(")?;
    for (i, (purpose, group)) in self.groups.iter().enumerate() {
      if i > 0 {
        f.write_str(", ")?;
      }
      write!(f, "{purpose}=[")?;
      for (j, entry) in group.iter().enumerate() {
        if j > 0 {
          f.write_str(", ")?;
        }
        write!(f, "{entry}")?;
      }
      f.write_str("]")?;
    }
    f.write_str(")")
  }
}

impl NITrait for NetInfoV2 {
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_ {
    self
      .groups
      .iter()
      .filter(move |(pp, _)| purpose.is_none() || purpose == Some(*pp))
      .flat_map(|(_, group)| group.iter().cloned())
  }

  fn primary(&self) -> Option<ServiceV2> {
    self
      .groups
      .iter()
      .find(|(p, e)| *p == NIPurpose::CoreP2p && !e.is_empty())
      .and_then(|(_, entries)| {
        entries.iter().find_map(|e| match e {
          NIEntry::Service(svc) => Some(svc.clone()),
          _ => None,
        })
      })
  }

  fn is_empty(&self) -> bool {
    self.groups.iter().all(|(_, group)| group.is_empty())
  }

  fn has_entries(&self, purpose: NIPurpose) -> bool {
    self.groups.iter().any(|(p, e)| *p == purpose && !e.is_empty())
  }

  fn stores_platform(&self) -> bool {
    true
  }
}

/// Reads a group purpose, which must be known and above `last`.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidValue`] for an unknown purpose or one not
/// above `last`, and the errors of reading a byte.
fn read_purpose(data: &mut &[u8], last: Option<NIPurpose>) -> Result<NIPurpose, DecodeError> {
  let value = u8::decode(data)?;
  let is_after_last = |candidate: u8| last.is_none_or(|last| candidate > last.to_base());
  let purpose = NIPurpose::from_base(value);
  if !matches!(purpose, NIPurpose::Unknown(_)) && is_after_last(value) {
    return Ok(purpose);
  }
  Err(DecodeError::InvalidValue {
    expected: NIPurpose::variants()
      .iter()
      .map(NIPurpose::to_base)
      .filter(|&candidate| is_after_last(candidate))
      .map(u64::from)
      .collect(),
    actual: u64::from(value),
  })
}

/// Returns `true` when two entries share the same address,
/// ignoring port.
fn same_addr(a: &NIEntry, b: &NIEntry) -> bool {
  match (a, b) {
    (NIEntry::Service(sa), NIEntry::Service(sb)) => sa.addr() == sb.addr(),
    (NIEntry::Domain { name: na, .. }, NIEntry::Domain { name: nb, .. }) => na == nb,
    _ => false,
  }
}

/// Legacy network information wrapper.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct NetInfoV1(ServiceV1);

impl_type!(NetInfoV1);

impl BaseCodec for NetInfoV1 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self(ServiceV1::decode(data)?))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

impl Checkable for NetInfoV1 {
  type Error = NIError;

  fn check(&self) -> Option<Self::Error> {
    if let Some(error) = self.0.check() {
      return Some(NIError::BadAddr { error });
    }
    None
  }
}

hash_impl!(NetInfoV1);

impl NetInfoV1 {
  /// Wraps a legacy service.
  pub fn new(service: ServiceV1) -> Self {
    Self(service)
  }

  /// Legacy service address.
  pub fn service(&self) -> &ServiceV1 {
    &self.0
  }
}

impl fmt::Display for NetInfoV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.0.addr().is_null() && self.0.port() == 0 {
      return f.write_str("NetInfoV1()");
    }
    write!(f, "NetInfoV1({})", self.0)
  }
}

impl NITrait for NetInfoV1 {
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_ {
    let entry = if self.is_empty() {
      None
    } else {
      match purpose {
        None | Some(NIPurpose::CoreP2p) => Some(NIEntry::Service(ServiceV2::from(&self.0))),
        Some(_) => None,
      }
    };
    entry.into_iter()
  }

  fn primary(&self) -> Option<ServiceV2> {
    if self.is_empty() {
      return None;
    }
    Some(ServiceV2::from(&self.0))
  }

  fn is_empty(&self) -> bool {
    self.0.addr().is_null() && self.0.port() == 0
  }

  fn has_entries(&self, purpose: NIPurpose) -> bool {
    purpose == NIPurpose::CoreP2p && !self.is_empty()
  }

  fn stores_platform(&self) -> bool {
    false
  }
}

/// Masternode network info: legacy ServiceV1 or structured extended format.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum NetInfo {
  /// ADDRv1 service (18 bytes).
  Legacy(NetInfoV1),
  /// Extended format (v3+) with purpose-grouped entries.
  Extended(NetInfoV2),
}

impl Checkable for NetInfo {
  type Error = NIError;

  fn check(&self) -> Option<Self::Error> {
    match self {
      Self::Legacy(v1) => v1.check(),
      Self::Extended(v2) => v2.check(),
    }
  }
}

impl fmt::Display for NetInfo {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Legacy(v1) => v1.fmt(f),
      Self::Extended(v2) => v2.fmt(f),
    }
  }
}

impl NITrait for NetInfo {
  fn entries(&self, purpose: Option<NIPurpose>) -> impl Iterator<Item = NIEntry> + '_ {
    let (a, b) = match self {
      Self::Legacy(v1) => (Some(v1.entries(purpose)), None),
      Self::Extended(v2) => (None, Some(v2.entries(purpose))),
    };
    a.into_iter().flatten().chain(b.into_iter().flatten())
  }

  fn primary(&self) -> Option<ServiceV2> {
    match self {
      Self::Legacy(v1) => v1.primary(),
      Self::Extended(v2) => v2.primary(),
    }
  }

  fn is_empty(&self) -> bool {
    match self {
      Self::Legacy(v1) => v1.is_empty(),
      Self::Extended(v2) => v2.is_empty(),
    }
  }

  fn has_entries(&self, purpose: NIPurpose) -> bool {
    match self {
      Self::Legacy(v1) => v1.has_entries(purpose),
      Self::Extended(v2) => v2.has_entries(purpose),
    }
  }

  fn stores_platform(&self) -> bool {
    match self {
      Self::Legacy(v1) => v1.stores_platform(),
      Self::Extended(v2) => v2.stores_platform(),
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::types::{AddrV1, AddrV2};

  use dash_dev::{vec_from_hex, Corpus};
  use dash_types::codec::BaseCodec;
  use dash_types::Checkable;
  use hex_conservative::{hex, DisplayHex};
  use rstest::rstest;
  use serde::Deserialize;

  #[rstest]
  #[case::ipv4(
    &hex!(concat!(
      "01",       // entry_type=Service
      "01",       // network=ipv4
      "04",       // addr_len=4
      "01020304", // addr 1.2.3.4
      "270f",     // port=9999
    )),
    NIEntry::Service(ServiceV2::new(AddrV2::Ipv4([1, 2, 3, 4]), 9999)),
  )]
  #[case::ipv6(
    &hex!(concat!(
      "01",                               // entry_type=Service
      "02",                               // network=ipv6
      "10",                               // addr_len=16
      "00000000000000000000000000000001", // addr ::1
      "270f",                             // port=9999
    )),
    NIEntry::Service(ServiceV2::new(AddrV2::Ipv6([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 9999)),
  )]
  #[case::domain(
    &hex!(concat!(
      "02",                     // entry_type=Domain
      "0b",                     // name_len=11
      "6578616d706c652e636f6d", // "example.com"
      "01bb",                   // port=443
    )),
    NIEntry::Domain { name: b"example.com".to_vec(), port: 443 },
  )]
  fn nientry_roundtrip(#[case] wire: &[u8], #[case] expected: NIEntry) {
    let decoded = NIEntry::decode(&mut &wire[..]).unwrap();
    assert_eq!(decoded, expected);
    let mut buf = Vec::new();
    decoded.encode(&mut buf);
    assert_eq!(buf, wire);
  }

  #[rstest]
  fn nientry_unknown_type_fails() {
    let wire = hex!("ff");
    assert!(NIEntry::decode(&mut &wire[..]).is_err());
  }

  #[rstest]
  #[case::single_ipv4(
    &hex!(concat!(
      "01",               // version=1
      "01",               // purpose_count=1
      "00",               // purpose=CoreP2p
      "01",               // entry_count=1
      "01",               // entry_type=Service
      "0104", "01020304", // ipv4 1.2.3.4
      "270f",             // port=9999
    )),
    NetInfoV2 {
      version: 1,
      groups: vec![(
        NIPurpose::CoreP2p,
        vec![NIEntry::Service(ServiceV2::new(AddrV2::Ipv4([1, 2, 3, 4]), 9999))],
      )],
    },
  )]
  #[case::multi_purpose(
    &hex!(concat!(
      "01",                       // version=1
      "02",                       // purpose_count=2
      "00",                       // purpose=CoreP2p
      "01",                       // entry_count=1
      "01",                       // entry_type=Service
      "0104", "c0a80001",         // ipv4 192.168.0.1
      "238e",                     // port=9102
      "02",                       // purpose=PlatformHttps
      "01",                       // entry_count=1
      "02",                       // entry_type=Domain
      "0b6578616d706c652e636f6d", // "example.com"
      "01bb",                     // port=443
    )),
    NetInfoV2 {
      version: 1,
      groups: vec![
        (
          NIPurpose::CoreP2p,
          vec![NIEntry::Service(ServiceV2::new(AddrV2::Ipv4([192, 168, 0, 1]), 9102))],
        ),
        (
          NIPurpose::PlatformHttps,
          vec![NIEntry::Domain {
            name: b"example.com".to_vec(),
            port: 443,
          }],
        ),
      ],
    },
  )]
  fn netinfov2_roundtrip(#[case] wire: &[u8], #[case] expected: NetInfoV2) {
    let decoded = NetInfoV2::decode(&mut &wire[..]).unwrap();
    assert_eq!(decoded, expected);
    let mut buf = Vec::new();
    decoded.encode(&mut buf);
    assert_eq!(buf, wire);
  }

  #[rstest]
  #[case::repeated("010200000000", 0, vec![1, 2])]
  #[case::descending("010201000000", 0, vec![2])]
  #[case::after_last_purpose("010202000100", 1, vec![])]
  #[case::unknown("01010300", 3, vec![0, 1, 2])]
  fn decode_v2_purpose_refused(#[case] wire: &str, #[case] actual: u64, #[case] expected: Vec<u64>) {
    let wire = vec_from_hex(wire);
    assert_eq!(
      NetInfoV2::decode(&mut wire.as_slice()),
      Err(DecodeError::InvalidValue { expected, actual })
    );
  }

  #[rstest]
  #[case::ipv4_valid(AddrV2::Ipv4([1, 2, 3, 4]), 9999, None)]
  #[case::ipv4_port_zero(
    AddrV2::Ipv4([1, 2, 3, 4]), 0,
    Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 0 } }),
  )]
  #[case::ipv4_port_privileged(AddrV2::Ipv4([1, 2, 3, 4]), 22, Some(NIError::BadPort { port: 22 }))]
  #[case::ipv4_port_named_bad(AddrV2::Ipv4([1, 2, 3, 4]), 8333, Some(NIError::BadPort { port: 8333 }))]
  #[case::i2p_port_zero(AddrV2::I2p([1; 32]), 0, None)]
  #[case::i2p_port_nonzero(
    AddrV2::I2p([1; 32]), 9998,
    Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 9998 } }),
  )]
  #[case::tor_port_zero(
    AddrV2::TorV3([1; 32]), 0,
    Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 0 } }),
  )]
  #[case::tor_port_valid(AddrV2::TorV3([1; 32]), 9998, None)]
  #[case::cjdns_valid(AddrV2::Cjdns(hex!("fc000000000000000000000000000001")), 9998, None)]
  fn check_entry_service(#[case] addr: AddrV2, #[case] port: u16, #[case] expected: Option<NIError>) {
    let entry = NIEntry::Service(ServiceV2::new(addr, port));
    assert_eq!(entry.check(), expected);
  }

  #[rstest]
  // Port rules
  #[case::valid(b"example.com", 443, None)]
  #[case::bad_port_zero(b"example.com", 0, Some(NIError::BadPort { port: 0 }))]
  #[case::bad_port_privileged(b"example.com", 80, Some(NIError::BadPort { port: 80 }))]
  #[case::port_443_exception(b"example.com", 443, None)]
  #[case::port_above_threshold(b"example.com", 9999, None)]
  // RFC 1035 syntax
  #[case::small_label(b"r.server-1.ab.cd", 443, None)]
  #[case::numeric_label_rfc1123(b"9998.9example7.ab", 443, None)]
  #[case::uppercase(b"Example.com", 443, Some(NIError::Malformed))]
  #[case::too_short(b"ab", 443, Some(NIError::Malformed))]
  #[case::dotless(b"localhost", 443, Some(NIError::Malformed))]
  #[case::leading_dot(b".abc.com", 443, Some(NIError::Malformed))]
  #[case::trailing_dot(b"abc.com.", 443, Some(NIError::Malformed))]
  #[case::empty_label(b"a..b.com", 443, Some(NIError::Malformed))]
  #[case::leading_hyphen(b"-example.com", 443, Some(NIError::Malformed))]
  #[case::trailing_hyphen(b"a-.bc.de", 443, Some(NIError::Malformed))]
  #[case::bad_char_apostrophe(b"it's.example.com", 443, Some(NIError::Malformed))]
  #[case::bad_char_space(b"some host.example.com", 443, Some(NIError::Malformed))]
  // TLD rules
  #[case::tld_local(b"host.local", 443, Some(NIError::Malformed))]
  #[case::tld_onion(b"hidden.onion", 443, Some(NIError::Malformed))]
  #[case::tld_test(b"host.test", 443, Some(NIError::Malformed))]
  #[case::tld_i2p(b"host.i2p", 443, Some(NIError::Malformed))]
  #[case::tld_arpa(b"host.arpa", 443, Some(NIError::Malformed))]
  #[case::tld_numeric(b"example.123", 443, Some(NIError::Malformed))]
  fn check_entry_domain(#[case] name: &[u8], #[case] port: u16, #[case] expected: Option<NIError>) {
    let entry = NIEntry::Domain {
      name: name.to_vec(),
      port,
    };
    assert_eq!(entry.check(), expected);
  }

  fn domain_wire(len: usize) -> Vec<u8> {
    let mut wire = Vec::new();
    NIEntry::Domain {
      name: vec![b'a'; len],
      port: 443,
    }
    .encode(&mut wire);
    wire
  }

  #[rstest]
  #[case::at_limit(DOMAIN_MAX, Ok(NIEntry::Domain { name: vec![b'a'; DOMAIN_MAX], port: 443 }))]
  #[case::past_limit(DOMAIN_MAX + 1, Err(DecodeError::CompactSizeExceedsLimit { limit: DOMAIN_MAX, value: 254 }))]
  fn nientry_domain_decodes_at_most_253_bytes(#[case] len: usize, #[case] expected: Result<NIEntry, DecodeError>) {
    assert_eq!(NIEntry::decode(&mut domain_wire(len).as_slice()), expected);
  }

  #[rstest]
  fn check_domain_length_limits() {
    // 63-char label is valid
    let label63 = "a".repeat(63);
    let valid_long_label = format!("{label63}.com");
    assert_eq!(check_domain(valid_long_label.as_bytes()), None,);
    // 64-char label exceeds per-label maximum
    let label64 = "a".repeat(64);
    let bad_label = format!("{label64}.com");
    assert_eq!(check_domain(bad_label.as_bytes()), Some(NIError::Malformed),);
    // 253-char FQDN is at the maximum limit
    let fqdn253 = format!(
      "{}.{}.{}.{}.ab",
      "a".repeat(63),
      "b".repeat(63),
      "c".repeat(63),
      "d".repeat(58),
    );
    assert_eq!(fqdn253.len(), 253);
    assert_eq!(check_domain(fqdn253.as_bytes()), None);
    // 254-char FQDN exceeds maximum
    let fqdn254 = format!(
      "{}.{}.{}.{}.abc",
      "a".repeat(63),
      "b".repeat(63),
      "c".repeat(63),
      "d".repeat(58),
    );
    assert_eq!(fqdn254.len(), 254);
    assert_eq!(check_domain(fqdn254.as_bytes()), Some(NIError::Malformed),);
  }

  #[rstest]
  #[case::valid("1.2.3.4", 9999, None)]
  #[case::bad_port("1.2.3.4", 0, Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 0 } }))]
  #[case::null_addr_raw("[::0]", 9999, Some(NIError::BadAddr { error: NetAddrError::BadRange { value: 0 } }))]
  #[case::ipv6_valid("[2001::1]", 9999, None)]
  fn check_v1(#[case] addr_str: &str, #[case] port: u16, #[case] expected: Option<NIError>) {
    let addr: AddrV1 = addr_str.parse().unwrap();
    let v1 = NetInfoV1(ServiceV1::new(addr, port));
    assert_eq!(v1.check(), expected);
  }

  fn svc(addr: AddrV2, port: u16) -> NIEntry {
    NIEntry::Service(ServiceV2::new(addr, port))
  }

  fn dom(name: &[u8], port: u16) -> NIEntry {
    NIEntry::Domain {
      name: name.to_vec(),
      port,
    }
  }

  fn valid_v2() -> NetInfoV2 {
    NetInfoV2 {
      version: 1,
      groups: vec![(NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 9999)])],
    }
  }

  #[rstest]
  #[case::zero(0, Some(NIError::Malformed))]
  #[case::current(1, None)]
  #[case::future(2, Some(NIError::Malformed))]
  fn check_v2_version(#[case] version: u8, #[case] expected: Option<NIError>) {
    let mut v2 = valid_v2();
    v2.version = version;
    assert_eq!(v2.check(), expected);
  }

  #[rstest]
  #[case::empty_group(
    NIPurpose::CoreP2p,
    vec![],
    Some(NIError::Malformed),
  )]
  #[case::unknown_purpose(
    NIPurpose::Unknown(99),
    vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 9999)],
    Some(NIError::Malformed),
  )]
  #[case::domain_wrong_purpose(
    NIPurpose::CoreP2p,
    vec![dom(b"example.com", 443)],
    Some(NIError::BadType { entry_type: 0x02 }),
  )]
  #[case::unknown_network(
    NIPurpose::CoreP2p,
    vec![svc(AddrV2::Unknown { network: 99, addr: vec![1, 2] }, 9999)],
    Some(NIError::BadType { entry_type: 99 }),
  )]
  #[case::delegates_entry_error(
    NIPurpose::CoreP2p,
    vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 0)],
    Some(NIError::BadAddr { error: NetAddrError::BadPort { port: 0 } }),
  )]
  #[case::duplicate_addr_same_group(
    NIPurpose::CoreP2p,
    vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 9999), svc(AddrV2::Ipv4([1, 2, 3, 4]), 8888)],
    Some(NIError::Duplicate),
  )]
  fn check_v2_group(#[case] purpose: NIPurpose, #[case] group: Vec<NIEntry>, #[case] expected: Option<NIError>) {
    let v2 = NetInfoV2 {
      version: 1,
      groups: vec![(purpose, group)],
    };
    assert_eq!(v2.check(), expected);
  }

  #[rstest]
  #[case::empty(vec![], Some(NIError::Malformed))]
  #[case::duplicate_purpose_key(
    vec![
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([10, 0, 0, 1]), 9999)]),
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([10, 0, 0, 2]), 9999)]),
    ],
    Some(NIError::Duplicate),
  )]
  #[case::ascending_purposes(
    vec![
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 9999)]),
      (NIPurpose::PlatformHttps, vec![dom(b"example.com", 443)]),
    ],
    None,
  )]
  #[case::descending_purposes(
    vec![
      (NIPurpose::PlatformHttps, vec![dom(b"example.com", 443)]),
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 9999)]),
    ],
    Some(NIError::Malformed),
  )]
  #[case::non_adjacent_repeated_purpose(
    vec![
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([10, 0, 0, 1]), 9999)]),
      (NIPurpose::PlatformP2p, vec![svc(AddrV2::Ipv4([10, 0, 0, 2]), 9999)]),
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([10, 0, 0, 3]), 9999)]),
    ],
    Some(NIError::Duplicate),
  )]
  #[case::unknown_purpose_beside_core_p2p(
    vec![
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([10, 0, 0, 1]), 9999)]),
      (NIPurpose::Unknown(0), vec![svc(AddrV2::Ipv4([10, 0, 0, 2]), 9999)]),
    ],
    Some(NIError::Malformed),
  )]
  #[case::duplicate_addr_port_cross_group(
    vec![
      (NIPurpose::CoreP2p, vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 9999)]),
      (NIPurpose::PlatformP2p, vec![svc(AddrV2::Ipv4([1, 2, 3, 4]), 9999)]),
    ],
    Some(NIError::Duplicate),
  )]
  fn check_v2_structure(#[case] entries: Vec<(NIPurpose, Vec<NIEntry>)>, #[case] expected: Option<NIError>) {
    let v2 = NetInfoV2 {
      version: 1,
      groups: entries,
    };
    assert_eq!(v2.check(), expected);
  }

  #[rstest]
  fn check_v2_too_many_entries() {
    let v2 = NetInfoV2 {
      version: 1,
      groups: vec![(
        NIPurpose::CoreP2p,
        (0..MAX_ENTRIES + 1)
          .map(|i| svc(AddrV2::Ipv4([10, 0, 0, i as u8 + 1]), 9999))
          .collect(),
      )],
    };
    assert_eq!(
      v2.check(),
      Some(NIError::MaxLimit {
        count: MAX_ENTRIES + 1,
        max: MAX_ENTRIES,
      })
    );
  }

  #[rstest]
  fn trait_v2_entries() {
    let v2 = valid_v2();
    let all: Vec<_> = v2.entries(None).collect();
    assert_eq!(all.len(), 1);
    let core: Vec<_> = v2.entries(Some(NIPurpose::CoreP2p)).collect();
    assert_eq!(core.len(), 1);
    let plat: Vec<_> = v2.entries(Some(NIPurpose::PlatformP2p)).collect();
    assert!(plat.is_empty());
  }

  #[rstest]
  fn trait_v2_primary() {
    let v2 = valid_v2();
    let primary = v2.primary().unwrap();
    assert_eq!(primary.addr(), &AddrV2::Ipv4([1, 2, 3, 4]));
    assert_eq!(primary.port(), 9999);
  }

  #[rstest]
  fn trait_v2_empty() {
    let empty = NetInfoV2 {
      version: 1,
      groups: vec![],
    };
    assert!(empty.is_empty());
    assert!(!empty.has_entries(NIPurpose::CoreP2p));
    assert!(empty.primary().is_none());
    assert!(!valid_v2().is_empty());
    assert!(valid_v2().has_entries(NIPurpose::CoreP2p));
    assert!(valid_v2().stores_platform());
  }

  #[rstest]
  fn trait_v1_entries() {
    let v1 = NetInfoV1(ServiceV1::new("1.2.3.4".parse().unwrap(), 9999));
    assert!(!v1.is_empty());
    assert!(v1.has_entries(NIPurpose::CoreP2p));
    assert!(!v1.has_entries(NIPurpose::PlatformP2p));
    assert!(!v1.stores_platform());
    let all: Vec<_> = v1.entries(None).collect();
    assert_eq!(all.len(), 1);
    let plat: Vec<_> = v1.entries(Some(NIPurpose::PlatformP2p)).collect();
    assert!(plat.is_empty());
    assert!(v1.primary().is_some());
  }

  #[rstest]
  fn trait_v1_empty() {
    let empty = NetInfoV1(ServiceV1::new(AddrV1::default(), 0));
    assert!(empty.is_empty());
    assert!(!empty.has_entries(NIPurpose::CoreP2p));
    assert!(empty.primary().is_none());
    let all: Vec<_> = empty.entries(None).collect();
    assert!(all.is_empty());
  }

  #[rstest]
  fn trait_dispatch_legacy() {
    let v1 = NetInfo::Legacy(NetInfoV1(ServiceV1::new("1.2.3.4".parse().unwrap(), 9999)));
    assert!(!v1.is_empty());
    assert!(v1.has_entries(NIPurpose::CoreP2p));
    assert!(!v1.stores_platform());
    assert!(v1.primary().is_some());
  }

  #[rstest]
  fn trait_dispatch_extended() {
    let v2 = NetInfo::Extended(valid_v2());
    assert!(!v2.is_empty());
    assert!(v2.has_entries(NIPurpose::CoreP2p));
    assert!(v2.stores_platform());
    assert!(v2.primary().is_some());
  }

  #[derive(Deserialize)]
  struct EntryVector {
    raw: String,
    read: Option<usize>,
    written: Option<String>,
    addr_port: Option<String>,
  }

  #[derive(Deserialize)]
  struct InfoVector {
    raw: String,
    read: Option<usize>,
    written: Option<String>,
    entries: Option<Vec<String>>,
    empty: Option<bool>,
  }

  /// Reads a `T` from the hex `raw`, returning the bytes read, the value
  /// written back as hex and the value, each `None` when the read fails.
  fn read<T: BaseCodec>(raw: &str) -> (Option<usize>, Option<String>, Option<T>) {
    let raw = vec_from_hex(raw);
    let mut data = raw.as_slice();
    let Ok(value) = T::decode(&mut data) else {
      return (None, None, None);
    };
    let mut written = Vec::new();
    value.encode(&mut written);
    (
      Some(raw.len() - data.len()),
      Some(written.to_lower_hex_string()),
      Some(value),
    )
  }

  type InfoRead = (Option<usize>, Option<String>, Option<Vec<String>>, Option<bool>);

  fn read_info<T: BaseCodec + NITrait>(raw: &str) -> InfoRead {
    let (len, written, info) = read::<T>(raw);
    let entries = info
      .as_ref()
      .map(|info| info.entries(None).map(|entry| entry.to_string()).collect());
    (len, written, entries, info.map(|info| info.is_empty()))
  }

  #[rstest]
  fn entry_reads_match_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "netinfo");
    for v in corpus.vectors::<EntryVector>("entry") {
      let (len, written, entry) = read::<NIEntry>(&v.raw);
      let got = (len, written, entry.map(|entry| entry.to_string()));
      assert_eq!(got, (v.read, v.written, v.addr_port), "{}", v.raw);
    }
  }

  #[rstest]
  #[case::legacy("legacy", read_info::<NetInfoV1>)]
  #[case::extended("extended", read_info::<NetInfoV2>)]
  fn info_reads_match_vectors(#[case] section: &str, #[case] read_info: fn(&str) -> InfoRead) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "netinfo");
    for v in corpus.vectors::<InfoVector>(section) {
      assert_eq!(read_info(&v.raw), (v.read, v.written, v.entries, v.empty), "{}", v.raw);
    }
  }
}
