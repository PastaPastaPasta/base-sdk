//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy ADDRv1 address and service types.

use super::addrv2::{AddrV2, ServiceV2};
use super::netaddr::{NetAddr, NetAddrError, NetworkType};
use crate::hash_impl;

use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_bytes, impl_new, impl_type, type_cvrt, Checkable};
use getset::CopyGetters;

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

/// First 12 bytes of an IPv4-mapped IPv6 address.
const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// ADDRv1 IPv4-mapped IPv6 address (16 bytes).
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct AddrV1(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))] [u8; 16]);

impl_bytes!(AddrV1, 16);

impl Checkable for AddrV1 {
  type Error = NetAddrError;

  fn check(&self) -> Option<Self::Error> {
    if self.is_null() {
      return Some(NetAddrError::BadRange { value: 0 });
    }
    // IPv4-mapped null (::ffff:0.0.0.0) has a non-zero prefix
    // so the all-zeros check above does not catch it.
    if self.is_ipv4() && self.0[12..] == [0; 4] {
      return Some(NetAddrError::BadRange { value: 0 });
    }
    if self.is_ipv4() && self.0[12..] == [255; 4] {
      return Some(NetAddrError::BadRange { value: 255 });
    }
    if NetAddr::is_rfc3849(self) {
      return Some(NetAddrError::BadRange { value: 0xb8 });
    }
    None
  }
}

hash_impl!(AddrV1);

impl AddrV1 {
  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; 16] {
    &self.0
  }

  /// Wraps raw bytes without validation.
  pub const fn from_bytes(bytes: [u8; 16]) -> Self {
    Self(bytes)
  }

  /// Returns the inner byte array.
  pub const fn to_bytes(self) -> [u8; 16] {
    self.0
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0.iter().all(|&b| b == 0)
  }

  /// Returns `true` if the address is IPv4-mapped.
  pub fn is_ipv4(&self) -> bool {
    self.0[..12] == IPV4_MAPPED_PREFIX
  }
}

impl From<[u8; 4]> for AddrV1 {
  fn from(octets: [u8; 4]) -> Self {
    let mut arr = [0u8; 16];
    arr[..12].copy_from_slice(&IPV4_MAPPED_PREFIX);
    arr[12..].copy_from_slice(&octets);
    Self(arr)
  }
}

impl From<AddrV1> for [u8; 16] {
  fn from(val: AddrV1) -> Self {
    val.0
  }
}

impl AsRef<[u8]> for AddrV1 {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl AsRef<[u8; 16]> for AddrV1 {
  fn as_ref(&self) -> &[u8; 16] {
    &self.0
  }
}

impl fmt::Debug for AddrV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AddrV1(")?;
    for byte in &self.0 {
      write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
  }
}

impl NetAddr for AddrV1 {
  fn bytes(&self) -> &[u8] {
    if self.is_ipv4() {
      &self.0[12..]
    } else {
      &self.0
    }
  }

  fn network(&self) -> NetworkType {
    if self.is_ipv4() {
      NetworkType::Ipv4
    } else {
      NetworkType::Ipv6
    }
  }

  fn is_ipv4(&self) -> bool {
    self.is_ipv4()
  }

  fn is_ipv6(&self) -> bool {
    !self.is_ipv4()
  }

  fn is_null(&self) -> bool {
    self.is_null()
  }
}

impl fmt::Display for AddrV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.is_ipv4() {
      let ip = Ipv4Addr::new(self.0[12], self.0[13], self.0[14], self.0[15]);
      write!(f, "{ip}")
    } else {
      let ip = Ipv6Addr::from(self.0);
      write!(f, "[{ip}]")
    }
  }
}

impl FromStr for AddrV1 {
  type Err = NetAddrError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
      let ip: Ipv6Addr = inner.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
      return Ok(Self(ip.octets()));
    }
    if s.ends_with(".onion") {
      return Err(NetAddrError::AddrTooNew {
        network: NetworkType::TorV3,
      });
    }
    if s.ends_with(".b32.i2p") {
      return Err(NetAddrError::AddrTooNew {
        network: NetworkType::I2p,
      });
    }
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
      let octets = ip.octets();
      let mut arr = [0u8; 16];
      arr[..12].copy_from_slice(&IPV4_MAPPED_PREFIX);
      arr[12..].copy_from_slice(&octets);
      return Ok(Self(arr));
    }
    Err(NetAddrError::BadEncode { pos: 0 })
  }
}

type_cvrt!(From<[u8; 16]> for AddrV1, |bytes| Self(*bytes));

type_cvrt!(TryFrom<AddrV2> for AddrV1, NetAddrError, |addr| {
  match addr {
    AddrV2::Ipv4(b) => {
      let mut arr = [0u8; 16];
      arr[..12].copy_from_slice(&IPV4_MAPPED_PREFIX);
      arr[12..].copy_from_slice(b);
      Ok(Self(arr))
    }
    AddrV2::Ipv6(b) => Ok(Self(*b)),
    other => Err(NetAddrError::AddrTooNew {
      network: other.network(),
    }),
  }
});

impl_new! {
/// Legacy network address (ADDRv1 format, 18 bytes).
#[derive(Clone, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ServiceV1 {
  /// 16-byte address (IPv4-mapped IPv6 or native IPv6).
  #[getset(get_copy = "pub")]
  addr: AddrV1,
  /// Network port (big-endian on the wire).
  #[getset(get_copy = "pub")]
  port: u16,
}
}

impl_type!(ServiceV1);

impl BaseCodec for ServiceV1 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      addr: AddrV1::decode(data)?,
      port: codec::read_u16_be(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl Checkable for ServiceV1 {
  type Error = NetAddrError;

  fn check(&self) -> Option<Self::Error> {
    if self.port == 0 {
      return Some(NetAddrError::BadPort { port: 0 });
    }
    self.addr.check()
  }
}

hash_impl!(ServiceV1);

impl fmt::Display for ServiceV1 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.addr, self.port)
  }
}

impl FromStr for ServiceV1 {
  type Err = NetAddrError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let (addr_str, port) = split_service_str(s)?;
    let addr = AddrV1::from_str(addr_str)?;
    Ok(Self { addr, port })
  }
}

type_cvrt!(TryFrom<ServiceV2> for ServiceV1, NetAddrError, |v2| {
  Ok(Self {
    addr: AddrV1::try_from(v2.addr())?,
    port: v2.port(),
  })
});

/// Splits a service string into `(addr, port)`.
///
/// Handles both bracketed (`[addr]:port`) and plain (`addr:port`) forms. The
/// unbracketed path uses `rfind(':')`, so callers must never pass bare IPv6
/// addresses without brackets.
///
/// # Errors
///
/// Returns `BadEncode` when the input cannot be split into a
/// valid address and port pair.
pub(super) fn split_service_str(s: &str) -> Result<(&str, u16), NetAddrError> {
  if s.starts_with('[') {
    let close = s.rfind(']').ok_or(NetAddrError::BadEncode { pos: 0 })?;
    let addr_str = &s[..=close];
    let rest = &s[close + 1..];
    let port_str = rest.strip_prefix(':').ok_or(NetAddrError::BadEncode { pos: 0 })?;
    let port: u16 = port_str.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
    return Ok((addr_str, port));
  }
  let colon = s.rfind(':').ok_or(NetAddrError::BadEncode { pos: 0 })?;
  let addr_str = &s[..colon];
  let port_str = &s[colon + 1..];
  let port: u16 = port_str.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
  Ok((addr_str, port))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::prelude::*;

  use hex_conservative::hex;
  use rstest::rstest;

  #[rstest]
  #[case::ipv4("1.2.3.4", hex!("00000000000000000000ffff01020304"))]
  #[case::loopback("127.0.0.1", hex!("00000000000000000000ffff7f000001"))]
  #[case::ipv6("[::1]", hex!("00000000000000000000000000000001"))]
  #[case::ipv6_full("[2001:db8::1]", hex!("20010db8000000000000000000000001"))]
  fn addr_roundtrip(#[case] s: &str, #[case] raw: [u8; 16]) {
    let parsed: AddrV1 = s.parse().unwrap();
    assert_eq!(parsed, AddrV1(raw));
    assert_eq!(parsed.to_string(), s);
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_carries_bytes_as_data() {
    let raw = hex!("20010db8000000000000000000000001");
    dash_dev::assert_cbor_raw(&AddrV1(raw), &raw);
  }

  #[rstest]
  #[case::ipv4("1.2.3.4:8333")]
  #[case::ipv6("[::1]:9999")]
  fn service_roundtrip(#[case] s: &str) {
    let parsed: ServiceV1 = s.parse().unwrap();
    assert_eq!(parsed.to_string(), s);
  }

  #[rstest]
  #[case::local("127.0.0.1", true)]
  #[case::rfc1918("10.0.0.1", false)]
  #[case::routable("1.2.3.4", false)]
  #[case::ipv6_local("[::1]", true)]
  fn is_local(#[case] s: &str, #[case] expected: bool) {
    let addr: AddrV1 = s.parse().unwrap();
    assert_eq!(NetAddr::is_local(&addr), expected);
  }

  #[rstest]
  #[case::routable("1.2.3.4", true)]
  #[case::local("127.0.0.1", false)]
  #[case::private("10.0.0.1", false)]
  fn is_routable(#[case] s: &str, #[case] expected: bool) {
    let addr: AddrV1 = s.parse().unwrap();
    assert_eq!(NetAddr::is_routable(&addr), expected);
  }

  #[rstest]
  #[case::yes("10.0.0.1", true)]
  #[case::no("8.8.8.8", false)]
  fn is_rfc1918(#[case] s: &str, #[case] expected: bool) {
    let addr: AddrV1 = s.parse().unwrap();
    assert_eq!(NetAddr::is_rfc1918(&addr), expected);
  }

  #[rstest]
  #[case::null([0u8; 16], Some(NetAddrError::BadRange { value: 0 }))]
  #[case::ipv4_null(
    hex!("00000000000000000000ffff00000000"),
    Some(NetAddrError::BadRange { value: 0 }),
  )]
  #[case::broadcast(
    hex!("00000000000000000000ffffffffffff"),
    Some(NetAddrError::BadRange { value: 255 }),
  )]
  #[case::rfc3849(
    hex!("20010db8000000000000000000000001"),
    Some(NetAddrError::BadRange { value: 0xb8 }),
  )]
  #[case::valid(hex!("00000000000000000000ffff08080808"), None)]
  fn check_addr(#[case] raw: [u8; 16], #[case] expected: Option<NetAddrError>) {
    assert_eq!(AddrV1(raw).check(), expected);
  }

  #[rstest]
  #[case::zero_port("8.8.8.8", 0, Some(NetAddrError::BadPort { port: 0 }))]
  #[case::null_addr([0u8; 16], 8333, Some(NetAddrError::BadRange { value: 0 }))]
  #[case::valid("8.8.8.8", 8333, None)]
  fn check_service(
    #[case] input: impl Into<CheckServiceInput>,
    #[case] port: u16,
    #[case] expected: Option<NetAddrError>,
  ) {
    let addr = input.into().0;
    assert_eq!(ServiceV1 { addr, port }.check(), expected);
  }

  /// Helper for polymorphic test inputs in `check_service`.
  struct CheckServiceInput(AddrV1);

  impl From<&str> for CheckServiceInput {
    fn from(s: &str) -> Self {
      Self(s.parse().unwrap())
    }
  }

  impl From<[u8; 16]> for CheckServiceInput {
    fn from(raw: [u8; 16]) -> Self {
      Self(AddrV1(raw))
    }
  }

  #[rstest]
  #[case::ipv4("1.2.3.4", AddrV2::Ipv4([1, 2, 3, 4]))]
  #[case::ipv6(
    "[2001:db8::1]",
    AddrV2::Ipv6(hex!("20010db8000000000000000000000001")),
  )]
  fn from_addrv1(#[case] s: &str, #[case] expected: AddrV2) {
    let v1: AddrV1 = s.parse().unwrap();
    assert_eq!(AddrV2::from(v1), expected);
  }

  #[rstest]
  #[case::ipv4(AddrV2::Ipv4([1, 2, 3, 4]), "1.2.3.4")]
  #[case::ipv6(
    AddrV2::Ipv6(hex!("20010db8000000000000000000000001")),
    "[2001:db8::1]",
  )]
  fn try_from_addrv2_ok(#[case] v2: AddrV2, #[case] s: &str) {
    let v1 = AddrV1::try_from(v2).unwrap();
    assert_eq!(v1.to_string(), s);
  }

  #[rstest]
  #[case::tor(AddrV2::TorV3([1; 32]), NetworkType::TorV3)]
  #[case::i2p(AddrV2::I2p([1; 32]), NetworkType::I2p)]
  #[case::cjdns(AddrV2::Cjdns([0xfc; 16]), NetworkType::Cjdns)]
  fn try_from_addrv2_fails(#[case] v2: AddrV2, #[case] net: NetworkType) {
    let err = AddrV1::try_from(v2).unwrap_err();
    assert_eq!(err, NetAddrError::AddrTooNew { network: net });
  }

  #[rstest]
  #[case::onion("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion", NetworkType::TorV3)]
  #[case::i2p("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p", NetworkType::I2p)]
  fn from_str_rejects(#[case] s: &str, #[case] net: NetworkType) {
    let err = s.parse::<AddrV1>().unwrap_err();
    assert_eq!(err, NetAddrError::AddrTooNew { network: net });
  }

  #[rstest]
  fn service_from_v1() {
    let v1 = ServiceV1 {
      addr: "1.2.3.4".parse().unwrap(),
      port: 8333,
    };
    let v2 = ServiceV2::from(v1);
    assert_eq!(v2.addr(), &AddrV2::Ipv4([1, 2, 3, 4]));
    assert_eq!(v2.port(), 8333);
  }

  #[rstest]
  fn service_try_from_v2() {
    let v2 = ServiceV2::new(AddrV2::Ipv4([1, 2, 3, 4]), 8333);
    let v1 = ServiceV1::try_from(v2).unwrap();
    assert_eq!(v1.to_string(), "1.2.3.4:8333");
  }

  #[rstest]
  fn service_try_from_v2_tor_fails() {
    let v2 = ServiceV2::new(AddrV2::TorV3([1; 32]), 8333);
    let err = ServiceV1::try_from(v2).unwrap_err();
    assert_eq!(
      err,
      NetAddrError::AddrTooNew {
        network: NetworkType::TorV3,
      }
    );
  }
}
