//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network address types and classification.

use crate::hash_impl;

use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_num};

enum_map! {
  /// Network address type (BIP155).
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum NetworkType, u8, Unknown {
    /// IPv4.
    Ipv4 = 1 => "ipv4",
    /// IPv6.
    Ipv6 = 2 => "ipv6",
    /// Tor v3 hidden service.
    TorV3 = 4 => "torv3",
    /// I2P.
    I2p = 5 => "i2p",
    /// CJDNS.
    Cjdns = 6 => "cjdns",
  }
}

impl_num!(NetworkType, u8);

hash_impl!(NetworkType);

impl NetworkType {
  /// Expected byte length for a known network type, or `None`
  /// for unknown.
  pub const fn expected_len(self) -> Option<usize> {
    match self {
      Self::Ipv4 => Some(4),
      Self::Ipv6 => Some(16),
      Self::TorV3 => Some(32),
      Self::I2p => Some(32),
      Self::Cjdns => Some(16),
      Self::Unknown(_) => None,
    }
  }
}

/// Network address validation error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
pub enum NetAddrError {
  /// Numeric value outside structural bounds.
  #[error("value 0x{value:02x} out of range")]
  BadRange {
    /// The out-of-range value.
    value: u8,
  },
  /// Invalid character in encoded address.
  #[error("invalid character 0x{byte:02x}")]
  BadChar {
    /// The offending byte.
    byte: u8,
  },
  /// Checksum mismatch.
  #[error(
    "checksum mismatch: expected {:02x}{:02x}, got {:02x}{:02x}",
    .expected[0], .expected[1], .actual[0], .actual[1]
  )]
  BadChecksum {
    /// Expected checksum bytes.
    expected: [u8; 2],
    /// Actual checksum bytes.
    actual: [u8; 2],
  },
  /// Encoding error at a byte position.
  #[error("encoding error at position {pos}")]
  BadEncode {
    /// Byte offset of the error.
    pos: usize,
  },
  /// Unexpected address length.
  #[error("expected {expected} bytes, got {actual}")]
  BadLen {
    /// Expected byte count.
    expected: usize,
    /// Actual byte count.
    actual: usize,
  },
  /// Unsupported address version byte.
  #[error("unsupported version {version}")]
  BadVersion {
    /// The version byte.
    version: u8,
  },
  /// Port outside u16 range or zero.
  #[error("invalid port {port}")]
  BadPort {
    /// The invalid port value.
    port: u16,
  },
  /// Address type not representable in target format.
  #[error("{network} address type not supported")]
  AddrTooNew {
    /// The incompatible network type.
    network: NetworkType,
  },
}

/// Returns `true` when the port is on the blocklist.
pub fn is_bad_port(port: u16) -> bool {
  if (1..=1023).contains(&port) {
    return true;
  }
  matches!(
    port,
    1719  // h323gatestat
    | 1720  // h323hostcall
    | 1723  // pptp
    | 2049  // nfs
    | 3659  // apple-sasl / PasswordServer
    | 4045  // lockd
    | 5060  // sip
    | 5061  // sips
    | 6000  // X11
    | 6566  // sane-port
    | 6665  // alternate IRC
    | 6666  // alternate IRC
    | 6667  // standard IRC
    | 6668  // alternate IRC
    | 6669  // alternate IRC
    | 6697  // IRC + TLS
    | 8332  // Bitcoin JSON-RPC
    | 8333  // Bitcoin P2P
    | 10080 // Amanda
    | 18332 // Bitcoin testnet RPC
    | 18333 // Bitcoin testnet P2P
  )
}

/// Shared classification interface for network addresses.
///
/// Both legacy (`AddrV1`) and modern (`AddrV2`) address types
/// implement this trait, providing uniform RFC classification.
pub trait NetAddr {
  /// Raw address bytes (4 for IPv4, 16 for IPv6, etc.).
  fn bytes(&self) -> &[u8];

  /// BIP155 network type.
  fn network(&self) -> NetworkType;

  /// Returns `true` for IPv4 addresses.
  fn is_ipv4(&self) -> bool;

  /// Returns `true` for IPv6 addresses.
  fn is_ipv6(&self) -> bool;

  /// Returns `true` when every address byte is zero.
  fn is_null(&self) -> bool;

  /// Returns `true` for Tor v3 addresses.
  fn is_tor(&self) -> bool {
    false
  }

  /// Returns `true` for I2P addresses.
  fn is_i2p(&self) -> bool {
    false
  }

  /// Returns `true` for CJDNS addresses.
  fn is_cjdns(&self) -> bool {
    false
  }

  /// Returns `true` for privacy networks (Tor, I2P, CJDNS).
  fn is_privacy_net(&self) -> bool {
    self.is_tor() || self.is_i2p() || self.is_cjdns()
  }

  /// Returns `true` when the address fits in an ADDRv1 message.
  fn is_v1_compatible(&self) -> bool {
    self.is_ipv4() || self.is_ipv6()
  }

  /// Returns `true` for loopback and link-local addresses.
  fn is_local(&self) -> bool {
    let b = self.bytes();
    if self.is_ipv4() && b.len() == 4 {
      // 127.0.0.0/8
      if b[0] == 127 {
        return true;
      }
      // RFC 3927 link-local 169.254.0.0/16
      if b[0] == 169 && b[1] == 254 {
        return true;
      }
      return false;
    }
    if self.is_ipv6() && b.len() == 16 {
      // ::1
      if b[..15] == [0; 15] && b[15] == 1 {
        return true;
      }
      // fe80::/10 link-local
      if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 {
        return true;
      }
      return false;
    }
    false
  }

  /// RFC 1918: private IPv4 (10/8, 172.16/12, 192.168/16).
  fn is_rfc1918(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    if b.len() != 4 {
      return false;
    }
    // 10.0.0.0/8
    if b[0] == 10 {
      return true;
    }
    // 172.16.0.0/12
    if b[0] == 172 && (b[1] & 0xf0) == 16 {
      return true;
    }
    // 192.168.0.0/16
    b[0] == 192 && b[1] == 168
  }

  /// RFC 2544: benchmarking (198.18.0.0/15).
  fn is_rfc2544(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4 && b[0] == 198 && (b[1] == 18 || b[1] == 19)
  }

  /// RFC 3849: documentation IPv6 (2001:db8::/32).
  fn is_rfc3849(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8
  }

  /// RFC 3927: link-local IPv4 (169.254.0.0/16).
  fn is_rfc3927(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4 && b[0] == 169 && b[1] == 254
  }

  /// RFC 4193: unique-local IPv6 (fc00::/7).
  fn is_rfc4193(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && (b[0] & 0xfe) == 0xfc
  }

  /// RFC 4843: ORCHID IPv6 (2001:10::/28).
  fn is_rfc4843(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && (b[3] & 0xf0) == 0x10
  }

  /// RFC 6052: well-known prefix (64:ff9b::/96).
  fn is_rfc6052(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4..12] == [0; 8]
  }

  /// RFC 6145: IPv4-translated IPv6 (::ffff:0:0:0/96).
  fn is_rfc6145(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0..8] == [0; 8] && b[8] == 0xff && b[9] == 0xff && b[10] == 0x00 && b[11] == 0x00
  }

  /// RFC 6598: carrier-grade NAT (100.64.0.0/10).
  fn is_rfc6598(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4 && b[0] == 100 && (b[1] & 0xc0) == 64
  }

  /// RFC 4291: IPv4-mapped IPv6 (::ffff:0:0/96).
  fn is_rfc4291(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0..10] == [0; 10] && b[10] == 0xff && b[11] == 0xff
  }

  /// RFC 4862: IPv6 stateless address autoconfiguration (fe80::/64).
  fn is_rfc4862(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0xfe && b[1] == 0x80 && b[2..8] == [0; 6]
  }

  /// RFC 5737: documentation IPv4 (TEST-NET-1/2/3).
  fn is_rfc5737(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4
      && ((b[0] == 192 && b[1] == 0 && b[2] == 2)
        || (b[0] == 198 && b[1] == 51 && b[2] == 100)
        || (b[0] == 203 && b[1] == 0 && b[2] == 113))
  }

  /// RFC 6666: discard prefix (100::/64).
  fn is_rfc6666(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x01 && b[1] == 0x00 && b[2..8] == [0; 6]
  }

  /// RFC 6890: IETF protocol assignments (192.0.0.0/24).
  fn is_rfc6890(&self) -> bool {
    if !self.is_ipv4() {
      return false;
    }
    let b = self.bytes();
    b.len() == 4 && b[0] == 192 && b[1] == 0 && b[2] == 0
  }

  /// RFC 7343: ORCHIDv2 IPv6 (2001:20::/28).
  fn is_rfc7343(&self) -> bool {
    if !self.is_ipv6() {
      return false;
    }
    let b = self.bytes();
    b.len() == 16 && b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && (b[3] & 0xf0) == 0x20
  }

  /// Returns `true` when the address is globally routable.
  ///
  /// This classification matches the reference implementation's `IsRoutable()`
  /// and is used in consensus-adjacent paths (masternode registration and
  /// service validation).
  fn is_routable(&self) -> bool {
    if self.is_null() {
      return false;
    }
    if self.is_privacy_net() {
      return true;
    }
    if self.is_ipv4() {
      let b = self.bytes();
      // 0/8 (current-net), 127/8 (loopback), 255.255.255.255 (broadcast)
      if b.len() == 4 && (b[0] == 0 || b[0] == 127 || b == [255, 255, 255, 255]) {
        return false;
      }
      return !self.is_rfc1918()
        && !self.is_rfc2544()
        && !self.is_rfc3927()
        && !self.is_rfc5737()
        && !self.is_rfc6598();
    }
    if self.is_ipv6() {
      let b = self.bytes();
      // ::1 loopback
      if b.len() == 16 && b[..15] == [0; 15] && b[15] == 1 {
        return false;
      }
      return !self.is_rfc3849()
        && !self.is_rfc4193()
        && !self.is_rfc4843()
        && !self.is_rfc4862()
        && !self.is_rfc7343();
    }
    false
  }

  /// Returns `true` when a node can plausibly connect to this address.
  ///
  /// This is a strict superset of the ranges excluded by
  /// [`is_routable`](Self::is_routable) and additionally covers RFC ranges
  /// that the reference implementation does not yet classify. Unlike
  /// `is_routable`, this function is **not** consensus-stable and may evolve
  /// as new RFCs are published.
  fn is_reachable(&self) -> bool {
    if !self.is_routable() || self.is_local() {
      return false;
    }
    if self.is_ipv4() {
      let b = self.bytes();
      // RFC 1112: multicast (224.0.0.0/4), reserved (240.0.0.0/4)
      if b.len() == 4 && b[0] >= 224 {
        return false;
      }
      return !self.is_rfc6890();
    }
    if self.is_ipv6() {
      let b = self.bytes();
      // RFC 4291 §2.7: multicast (ff00::/8)
      if b.len() == 16 && b[0] == 0xff {
        return false;
      }
      return !self.is_rfc4291() && !self.is_rfc6052() && !self.is_rfc6145() && !self.is_rfc6666();
    }
    true
  }
}

#[expect(clippy::unwrap_used, reason = "test code")]
#[cfg(test)]
mod tests {
  use super::*;
  use crate::types::{AddrV1, AddrV2};

  use rstest::rstest;

  use core::str::FromStr;

  fn addr(s: &str) -> AddrV1 {
    AddrV1::from_str(s).unwrap()
  }

  #[rstest]
  #[case::rfc1918_10("10.0.0.1", true)]
  #[case::rfc1918_172("172.31.255.255", true)]
  #[case::rfc1918_192("192.168.1.1", true)]
  #[case::rfc1918_public("8.8.8.8", false)]
  fn rfc1918(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_rfc1918(), expected);
  }

  #[rstest]
  #[case::rfc2544_lo("198.18.0.0", true)]
  #[case::rfc2544_hi("198.19.255.255", true)]
  #[case::rfc2544_below("198.17.0.0", false)]
  fn rfc2544(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_rfc2544(), expected);
  }

  #[rstest]
  fn rfc3849() {
    assert!(addr("[2001:db8::1]").is_rfc3849());
  }

  #[rstest]
  #[case::rfc3927_yes("169.254.1.1", true)]
  #[case::rfc3927_no("169.253.1.1", false)]
  fn rfc3927(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_rfc3927(), expected);
  }

  #[rstest]
  fn rfc4193() {
    assert!(addr("[fc00::1]").is_rfc4193());
    assert!(addr("[fd00::1]").is_rfc4193());
    assert!(!addr("[fe00::1]").is_rfc4193());
  }

  #[rstest]
  fn rfc4843() {
    assert!(addr("[2001:10::1]").is_rfc4843());
    assert!(addr("[2001:1f::1]").is_rfc4843());
    assert!(!addr("[2001:20::1]").is_rfc4843());
  }

  #[rstest]
  fn rfc6052() {
    assert!(addr("[64:ff9b::1]").is_rfc6052());
    assert!(!addr("[64:ff9b:1::1]").is_rfc6052());
  }

  #[rstest]
  fn rfc6145() {
    assert!(addr("[::ffff:0:0:1]").is_rfc6145());
    assert!(!addr("[1::ffff:0:0:1]").is_rfc6145());
  }

  #[rstest]
  #[case::rfc6598_lo("100.64.0.0", true)]
  #[case::rfc6598_hi("100.127.255.255", true)]
  #[case::rfc6598_below("100.63.0.0", false)]
  fn rfc6598(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_rfc6598(), expected);
  }

  #[rstest]
  #[case::local_v4("127.0.0.1", true)]
  #[case::local_link("169.254.0.1", true)]
  #[case::local_public("8.8.8.8", false)]
  fn local_v4(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_local(), expected);
  }

  #[rstest]
  fn local_v6() {
    assert!(addr("[::1]").is_local());
    assert!(addr("[fe80::1]").is_local());
    assert!(!addr("[2001::1]").is_local());
  }

  #[rstest]
  #[case::routable_v4("8.8.8.8", true)]
  #[case::not_routable_loopback("127.0.0.1", false)]
  #[case::not_routable_private("10.0.0.1", false)]
  #[case::not_routable_null("0.0.0.0", false)]
  #[case::routable_multicast("224.0.0.1", true)]
  #[case::routable_multicast_hi("239.255.255.255", true)]
  #[case::not_routable_broadcast("255.255.255.255", false)]
  fn routable_v4(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_routable(), expected);
  }

  #[rstest]
  fn routable_v6() {
    assert!(addr("[2001::1]").is_routable());
    assert!(!addr("[2001:db8::1]").is_routable());
    assert!(!addr("[2001:10::1]").is_routable());
    assert!(!addr("[2001:20::1]").is_routable());
    assert!(!addr("[fe80::1]").is_routable());
    assert!(addr("[ff02::1]").is_routable());
  }

  #[rstest]
  #[case::test_net_1("192.0.2.1", false)]
  #[case::test_net_2("198.51.100.1", false)]
  #[case::test_net_3("203.0.113.1", false)]
  fn routable_rfc5737(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_routable(), expected);
  }

  #[rstest]
  #[case::ietf_proto("192.0.0.1", true)]
  #[case::nat64("[64:ff9b::1]", true)]
  #[case::siit("[::ffff:0:0:1]", true)]
  #[case::discard_v6("[100::1]", true)]
  fn routable_matches_upstream(#[case] s: &str, #[case] expected: bool) {
    // Routable per the reference implementation but excluded by is_reachable().
    assert_eq!(addr(s).is_routable(), expected);
  }

  #[rstest]
  fn null() {
    assert!(AddrV1::default().is_null());
    assert!(!addr("1.2.3.4").is_null());
    assert!(!addr("[::1]").is_null());
  }

  #[rstest]
  fn invariant_rfc1918_implies_ipv4() {
    let a = addr("10.0.0.1");
    if a.is_rfc1918() {
      assert!(a.is_ipv4());
    }
  }

  #[rstest]
  fn invariant_rfc3849_implies_ipv6() {
    let a = addr("[2001:db8::1]");
    if a.is_rfc3849() {
      assert!(a.is_ipv6());
    }
  }

  #[rstest]
  fn invariant_rfc4193_implies_ipv6() {
    let a = addr("[fc00::1]");
    if a.is_rfc4193() {
      assert!(a.is_ipv6());
    }
  }

  #[rstest]
  fn invariant_local_implies_not_routable() {
    let a = addr("127.0.0.1");
    if a.is_local() {
      assert!(!a.is_routable());
    }
  }

  #[rstest]
  #[case::mapped_yes("[::ffff:8.8.8.8]", true)]
  #[case::mapped_no("[2001::1]", false)]
  fn rfc4291(#[case] s: &str, #[case] expected: bool) {
    // AddrV1 treats ::ffff:x.x.x.x as IPv4, test via AddrV2.
    let a = AddrV2::from_str(s).unwrap();
    assert_eq!(a.is_rfc4291(), expected);
  }

  #[rstest]
  #[case::link_local("[fe80::1]", true)]
  #[case::link_local_boundary("[fe80:1::1]", false)]
  #[case::not_link_local("[fe81::1]", false)]
  fn rfc4862(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_rfc4862(), expected);
  }

  #[rstest]
  #[case::test_net_1("192.0.2.1", true)]
  #[case::test_net_2("198.51.100.1", true)]
  #[case::test_net_3("203.0.113.1", true)]
  #[case::not_test_net("192.0.1.1", false)]
  #[case::not_test_net_2("203.0.114.1", false)]
  fn rfc5737(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_rfc5737(), expected);
  }

  #[rstest]
  fn rfc6666() {
    assert!(addr("[100::1]").is_rfc6666());
    assert!(!addr("[100:1::1]").is_rfc6666());
  }

  #[rstest]
  #[case::ietf_yes("192.0.0.170", true)]
  #[case::ietf_no("192.0.1.1", false)]
  fn rfc6890(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_rfc6890(), expected);
  }

  #[rstest]
  fn rfc7343() {
    assert!(addr("[2001:20::1]").is_rfc7343());
    assert!(addr("[2001:2f::1]").is_rfc7343());
    assert!(!addr("[2001:30::1]").is_rfc7343());
  }

  #[rstest]
  #[case::ietf_proto("192.0.0.1", false)]
  #[case::nat64("[64:ff9b::1]", false)]
  #[case::siit("[::ffff:0:0:1]", false)]
  #[case::discard_v6("[100::1]", false)]
  #[case::multicast_v4("224.0.0.1", false)]
  #[case::multicast_v4_hi("239.255.255.255", false)]
  #[case::reserved_v4("240.0.0.1", false)]
  #[case::multicast_v6("[ff02::1]", false)]
  #[case::public_v4("8.8.8.8", true)]
  #[case::public_v6("[2001::1]", true)]
  #[case::link_local_64("[fe80::1]", false)]
  #[case::link_local_10("[fe80:40::1]", false)]
  fn reachable(#[case] s: &str, #[case] expected: bool) {
    assert_eq!(addr(s).is_reachable(), expected);
  }

  #[rstest]
  fn reachable_ipv4_mapped_v6() {
    // AddrV1 treats ::ffff:x.x.x.x as IPv4, test via AddrV2.
    let a = AddrV2::from_str("[::ffff:8.8.8.8]").unwrap();
    assert!(!a.is_reachable());
  }
}
