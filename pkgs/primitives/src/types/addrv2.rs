//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP155 network address types (ADDRv2).

use super::addrv1::{AddrV1, ServiceV1};
use super::netaddr::{NetAddr, NetAddrError, NetworkType};
use super::util::{base16_dec, base16_enc, base32r_dec, base32r_enc};
use crate::hash_impl;
use crate::prelude::*;

use bitcoin_hashes::sha3_256;
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::{impl_type, type_cvrt, type_id::TypeId, Checkable, CompactSize, Numeric};

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

/// Maximum raw address length for any known BIP155 network type.
pub(super) const MAX_ADDR_LEN: usize = 512;

/// BIP155 network address.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum AddrV2 {
  /// IPv4 address (4 bytes).
  Ipv4([u8; 4]),
  /// IPv6 address (16 bytes).
  Ipv6([u8; 16]),
  /// Onion hidden service (32 bytes).
  TorV3([u8; 32]),
  /// I2P address (32 bytes).
  I2p([u8; 32]),
  /// CJDNS address (16 bytes).
  Cjdns([u8; 16]),
  /// Unknown network type with raw address bytes.
  Unknown {
    /// Wire network ID.
    network: u8,
    /// Raw address bytes.
    addr: Vec<u8>,
  },
}

impl BaseCodec for AddrV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let net_byte = u8::decode(data)?;
    let network = NetworkType::from_base(net_byte);
    let len = CompactSize::decode(data)?.into_len(MAX_ADDR_LEN)?;
    if let Some(expected) = network.expected_len() {
      if len != expected {
        return Err(DecodeError::BadLen {
          expected: vec![expected],
          actual: len,
        });
      }
    }
    let raw = codec::read_bytes(data, len)?;
    match network {
      NetworkType::Ipv4 => {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(raw);
        Ok(Self::Ipv4(buf))
      }
      NetworkType::Ipv6 => {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(raw);
        // BIP155: fc00::/8 is CJDNS, not generic IPv6.
        if buf[0] == 0xfc {
          Ok(Self::Cjdns(buf))
        } else {
          Ok(Self::Ipv6(buf))
        }
      }
      NetworkType::TorV3 => {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(raw);
        Ok(Self::TorV3(buf))
      }
      NetworkType::I2p => {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(raw);
        Ok(Self::I2p(buf))
      }
      NetworkType::Cjdns => {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(raw);
        Ok(Self::Cjdns(buf))
      }
      NetworkType::Unknown(n) => Ok(Self::Unknown {
        network: n,
        addr: raw.to_vec(),
      }),
    }
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.network().to_base().encode(buf);
    let bytes = self.bytes();
    CompactSize::from(bytes.len()).encode(buf);
    buf.extend_from_slice(bytes); // nosemgrep: codec-no-raw-extend
  }
}

impl_type!(AddrV2);

impl Checkable for AddrV2 {
  type Error = NetAddrError;

  fn check(&self) -> Option<Self::Error> {
    if self.is_null() {
      return Some(NetAddrError::BadRange { value: 0 });
    }
    match self {
      Self::Ipv4(b) => {
        // broadcast address (255.255.255.255)
        if *b == [255; 4] {
          return Some(NetAddrError::BadRange { value: 255 });
        }
      }
      Self::Ipv6(b) => {
        // fc00::/8 belongs in the Cjdns variant per BIP155.
        if b[0] == 0xfc {
          return Some(NetAddrError::BadRange { value: 0xfc });
        }
      }
      Self::Cjdns(b) => {
        if b[0] != 0xfc {
          return Some(NetAddrError::BadRange { value: b[0] });
        }
      }
      Self::Unknown { network, addr } => {
        // Known network IDs must use their typed variant.
        if NetworkType::from_base(*network).expected_len().is_some() {
          return Some(NetAddrError::BadRange { value: *network });
        }
        if addr.len() > MAX_ADDR_LEN {
          return Some(NetAddrError::BadLen {
            expected: MAX_ADDR_LEN,
            actual: addr.len(),
          });
        }
      }
      _ => {}
    }
    if self.is_rfc3849() {
      return Some(NetAddrError::BadRange { value: 0xb8 });
    }
    None
  }
}

hash_impl!(AddrV2);

impl AddrV2 {
  /// Returns the BIP155 network type for this address.
  pub fn network(&self) -> NetworkType {
    match self {
      Self::Ipv4(_) => NetworkType::Ipv4,
      Self::Ipv6(_) => NetworkType::Ipv6,
      Self::TorV3(_) => NetworkType::TorV3,
      Self::I2p(_) => NetworkType::I2p,
      Self::Cjdns(_) => NetworkType::Cjdns,
      Self::Unknown { network, .. } => NetworkType::Unknown(*network),
    }
  }

  /// Raw address bytes.
  pub fn bytes(&self) -> &[u8] {
    match self {
      Self::Ipv4(b) => b,
      Self::Ipv6(b) => b,
      Self::TorV3(b) => b,
      Self::I2p(b) => b,
      Self::Cjdns(b) => b,
      Self::Unknown { addr, .. } => addr,
    }
  }
}

impl NetAddr for AddrV2 {
  fn bytes(&self) -> &[u8] {
    self.bytes()
  }

  fn network(&self) -> NetworkType {
    self.network()
  }

  fn is_ipv4(&self) -> bool {
    matches!(self, Self::Ipv4(_))
  }

  fn is_ipv6(&self) -> bool {
    matches!(self, Self::Ipv6(_))
  }

  fn is_null(&self) -> bool {
    self.bytes().iter().all(|&b| b == 0)
  }

  fn is_tor(&self) -> bool {
    matches!(self, Self::TorV3(_))
  }

  fn is_i2p(&self) -> bool {
    matches!(self, Self::I2p(_))
  }

  fn is_cjdns(&self) -> bool {
    matches!(self, Self::Cjdns(_))
  }
}

impl fmt::Display for AddrV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Ipv4(b) => {
        let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        write!(f, "{ip}")
      }
      Self::Ipv6(b) | Self::Cjdns(b) => {
        let ip = Ipv6Addr::from(*b);
        write!(f, "[{ip}]")
      }
      Self::TorV3(pubkey) => {
        const VERSION: u8 = 3;
        let mut pre = [0u8; 48];
        pre[..15].copy_from_slice(b".onion checksum");
        pre[15..47].copy_from_slice(pubkey);
        pre[47] = VERSION;
        let hash = sha3_256::Hash::hash(&pre);
        let cs = hash.to_byte_array();
        let mut buf = [0u8; 35];
        buf[..32].copy_from_slice(pubkey);
        buf[32] = cs[0];
        buf[33] = cs[1];
        buf[34] = VERSION;
        base32r_enc(&buf, f)?;
        f.write_str(".onion")
      }
      Self::I2p(b) => {
        base32r_enc(b, f)?;
        f.write_str(".b32.i2p")
      }
      Self::Unknown { network, addr } => {
        write!(f, "{}:", NetworkType::Unknown(*network))?;
        base16_enc(addr, f)
      }
    }
  }
}

type_cvrt!(From<AddrV1> for AddrV2, |v1| {
  if v1.is_ipv4() {
    let b = v1.as_bytes();
    Self::Ipv4([b[12], b[13], b[14], b[15]])
  } else {
    Self::Ipv6(*v1.as_bytes())
  }
});

impl FromStr for AddrV2 {
  type Err = NetAddrError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    if let Some(name) = s.strip_suffix(".onion") {
      let mut buf = [0u8; 35];
      base32r_dec(name, &mut buf)?;
      let version = buf[34];
      if version != 3 {
        return Err(NetAddrError::BadVersion { version });
      }
      let mut pubkey = [0u8; 32];
      pubkey.copy_from_slice(&buf[..32]);
      // Verify SHA3-256 checksum.
      let mut pre = [0u8; 48];
      pre[..15].copy_from_slice(b".onion checksum");
      pre[15..47].copy_from_slice(&pubkey);
      pre[47] = version;
      let hash = sha3_256::Hash::hash(&pre);
      let cs = hash.to_byte_array();
      if buf[32] != cs[0] || buf[33] != cs[1] {
        return Err(NetAddrError::BadChecksum {
          expected: [cs[0], cs[1]],
          actual: [buf[32], buf[33]],
        });
      }
      return Ok(Self::TorV3(pubkey));
    }
    if let Some(name) = s.strip_suffix(".b32.i2p") {
      let mut buf = [0u8; 32];
      base32r_dec(name, &mut buf)?;
      return Ok(Self::I2p(buf));
    }
    if let Some(rest) = s.strip_prefix("unknown(") {
      let close = rest.find(')').ok_or(NetAddrError::BadEncode { pos: 0 })?;
      let net_str = &rest[..close];
      let net: u8 = net_str.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
      let hex_str = rest
        .get(close + 1..)
        .and_then(|r| r.strip_prefix(':'))
        .ok_or(NetAddrError::BadEncode { pos: close + 1 })?;
      let addr = base16_dec(hex_str)?;
      if addr.len() > MAX_ADDR_LEN {
        return Err(NetAddrError::BadLen {
          expected: MAX_ADDR_LEN,
          actual: addr.len(),
        });
      }
      return Ok(Self::Unknown { network: net, addr });
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
      let ip: Ipv6Addr = inner.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
      let octets = ip.octets();
      if octets[0] == 0xfc {
        return Ok(Self::Cjdns(octets));
      }
      return Ok(Self::Ipv6(octets));
    }
    let ip: Ipv4Addr = s.parse().map_err(|_| NetAddrError::BadEncode { pos: 0 })?;
    Ok(Self::Ipv4(ip.octets()))
  }
}

/// BIP155 network service (address + port).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ServiceV2 {
  /// Typed network address.
  pub addr: AddrV2,
  /// Network port (big-endian on the wire).
  pub port: u16,
}

impl_type!(ServiceV2);

impl BaseCodec for ServiceV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let addr = AddrV2::decode(data)?;
    let port = codec::read_u16_be(data)?;
    Ok(Self { addr, port })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl Checkable for ServiceV2 {
  type Error = NetAddrError;

  fn check(&self) -> Option<Self::Error> {
    // I2P SAM 3.1 does not use ports; port must be exactly 0.
    if self.addr.is_i2p() {
      if self.port != 0 {
        return Some(NetAddrError::BadPort { port: self.port });
      }
    } else if self.port == 0 {
      return Some(NetAddrError::BadPort { port: 0 });
    }
    self.addr.check()
  }
}

hash_impl!(ServiceV2);

impl fmt::Display for ServiceV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.addr, self.port)
  }
}

type_cvrt!(From<ServiceV1> for ServiceV2, |v1| {
  Self {
    addr: AddrV2::from(&v1.addr),
    port: v1.port,
  }
});

impl FromStr for ServiceV2 {
  type Err = NetAddrError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let (addr_str, port) = super::addrv1::split_service_str(s)?;
    let addr = AddrV2::from_str(addr_str)?;
    Ok(Self { addr, port })
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use hex_conservative::hex;
  use rstest::rstest;

  #[rstest]
  #[case::torv3_vec1(
    AddrV2::TorV3(hex!("79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f")),
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
  )]
  #[case::torv3_vec2(
    AddrV2::TorV3(hex!("53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88")),
    "kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion",
  )]
  #[case::i2p(
    AddrV2::I2p(hex!("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87")),
    "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p",
  )]
  #[case::ipv4(AddrV2::Ipv4([1, 2, 3, 4]), "1.2.3.4")]
  #[case::ipv6(
    AddrV2::Ipv6(hex!("00000000000000000000000000000001")),
    "[::1]",
  )]
  #[case::cjdns(
    AddrV2::Cjdns(hex!("fc000000000000000000000000000001")),
    "[fc00::1]",
  )]
  fn display(#[case] addr: AddrV2, #[case] expected: &str) {
    assert_eq!(addr.to_string(), expected);
    assert_eq!(expected.parse::<AddrV2>().unwrap(), addr);
  }

  #[rstest]
  #[case::ipv4(AddrV2::Ipv4([1, 2, 3, 4]))]
  #[case::ipv6(AddrV2::Ipv6(hex!("20010db8000000000000000000000001")))]
  fn codec_roundtrip(#[case] addr: AddrV2) {
    let mut buf = Vec::new();
    addr.encode(&mut buf);
    let decoded = AddrV2::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(decoded, addr);
  }

  #[rstest]
  fn roundtrip_service() {
    let svc = ServiceV2 {
      addr: AddrV2::Ipv4([10, 0, 0, 1]),
      port: 9999,
    };
    let mut buf = Vec::new();
    svc.encode(&mut buf);
    let decoded = ServiceV2::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(decoded, svc);
  }

  #[rstest]
  fn netaddr_classification() {
    assert!(AddrV2::Ipv4([10, 0, 0, 1]).is_rfc1918());
    assert!(AddrV2::Ipv4([8, 8, 8, 8]).is_routable());
    assert!(!AddrV2::Ipv4([127, 0, 0, 1]).is_routable());
    assert!(AddrV2::Ipv4([127, 0, 0, 1]).is_local());
    assert!(AddrV2::Ipv4([0, 0, 0, 0]).is_null());
    assert!(AddrV2::TorV3([1; 32]).is_tor());
    assert!(AddrV2::I2p([1; 32]).is_i2p());
    assert!(AddrV2::Cjdns([0xfc; 16]).is_cjdns());
    assert!(AddrV2::TorV3([1; 32]).is_privacy_net());
    assert!(AddrV2::TorV3([1; 32]).is_routable());
  }

  #[rstest]
  fn wire_compat_with_old_format() {
    // Verify the wire encoding is identical to the old
    // AddrV2 struct format: network byte + compact-size
    // length + address bytes.
    let addr = AddrV2::Ipv4([1, 2, 3, 4]);
    let mut buf = Vec::new();
    addr.encode(&mut buf);
    // 0x01 (ipv4) + 0x04 (length) + 01020304
    assert_eq!(buf, vec![0x01, 0x04, 1, 2, 3, 4]);
  }

  #[rstest]
  #[case::ipv4_null(AddrV2::Ipv4([0; 4]), Some(NetAddrError::BadRange { value: 0 }))]
  #[case::ipv4_broadcast(AddrV2::Ipv4([255; 4]), Some(NetAddrError::BadRange { value: 255 }))]
  #[case::ipv4_valid(AddrV2::Ipv4([8, 8, 8, 8]), None)]
  #[case::ipv4_low(AddrV2::Ipv4([0, 1, 2, 3]), None)]
  #[case::ipv4_high(AddrV2::Ipv4([240, 0, 0, 1]), None)]
  #[case::ipv6_null(AddrV2::Ipv6([0; 16]), Some(NetAddrError::BadRange { value: 0 }))]
  #[case::ipv6_rfc3849(
    AddrV2::Ipv6(hex!("20010db8000000000000000000000001")),
    Some(NetAddrError::BadRange { value: 0xb8 }),
  )]
  #[case::ipv6_valid(AddrV2::Ipv6(hex!("20010000000000000000000000000001")), None)]
  #[case::cjdns_bad_prefix(
    AddrV2::Cjdns(hex!("fd000000000000000000000000000001")),
    Some(NetAddrError::BadRange { value: 0xfd }),
  )]
  #[case::cjdns_valid(AddrV2::Cjdns(hex!("fc000000000000000000000000000001")), None)]
  #[case::ipv6_cjdns_range(
    AddrV2::Ipv6(hex!("fc000000000000000000000000000001")),
    Some(NetAddrError::BadRange { value: 0xfc }),
  )]
  #[case::unknown_known_id(
    AddrV2::Unknown { network: 1, addr: vec![1, 2, 3, 4] },
    Some(NetAddrError::BadRange { value: 1 }),
  )]
  #[case::unknown_valid(
    AddrV2::Unknown { network: 99, addr: vec![1, 2] },
    None,
  )]
  #[case::tor_valid(AddrV2::TorV3([1; 32]), None)]
  #[case::i2p_valid(AddrV2::I2p([1; 32]), None)]
  fn check_addr(#[case] addr: AddrV2, #[case] expected: Option<NetAddrError>) {
    assert_eq!(addr.check(), expected);
  }

  #[rstest]
  #[case::zero_port(AddrV2::Ipv4([8, 8, 8, 8]), 0, Some(NetAddrError::BadPort { port: 0 }))]
  #[case::delegates_to_addr(
    AddrV2::Cjdns(hex!("fd000000000000000000000000000001")),
    8333,
    Some(NetAddrError::BadRange { value: 0xfd }),
  )]
  #[case::delegates_null(AddrV2::Ipv4([0; 4]), 8333, Some(NetAddrError::BadRange { value: 0 }))]
  #[case::valid(AddrV2::Ipv4([8, 8, 8, 8]), 8333, None)]
  #[case::i2p_port_zero(AddrV2::I2p([1; 32]), 0, None)]
  #[case::i2p_nonzero_port(AddrV2::I2p([1; 32]), 9999, Some(NetAddrError::BadPort { port: 9999 }))]
  fn check_service(#[case] addr: AddrV2, #[case] port: u16, #[case] expected: Option<NetAddrError>) {
    assert_eq!(ServiceV2 { addr, port }.check(), expected);
  }

  #[rstest]
  #[case::bad_ipv4("999.999.999.999")]
  #[case::bad_bracket("[not-an-ip]")]
  #[case::bad_onion("zzzz.onion")]
  fn from_str_errors(#[case] s: &str) {
    assert!(s.parse::<AddrV2>().is_err());
  }

  #[rstest]
  #[case::ipv4("1.2.3.4:8333")]
  #[case::ipv6("[::1]:9999")]
  #[case::cjdns("[fc00::1]:1234")]
  #[case::tor("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333")]
  #[case::i2p("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p:7654")]
  fn service_from_str_roundtrip(#[case] s: &str) {
    let parsed: ServiceV2 = s.parse().unwrap();
    assert_eq!(parsed.to_string(), s);
  }

  #[rstest]
  #[case::missing_separator("unknown(99)abcd")]
  #[case::unclosed_paren("unknown(99abcd")]
  fn from_str_unknown_bad_format(#[case] s: &str) {
    assert!(s.parse::<AddrV2>().is_err());
  }

  #[rstest]
  fn unknown_from_str_roundtrip() {
    let addr = AddrV2::Unknown {
      network: 99,
      addr: vec![0xab, 0xcd],
    };
    let s = addr.to_string();
    let parsed: AddrV2 = s.parse().unwrap();
    assert_eq!(parsed, addr);
  }
}
