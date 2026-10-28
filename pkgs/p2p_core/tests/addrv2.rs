//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Wire-format round-trip tests for addr and addrv2 messages.

#![expect(clippy::panic, reason = "test code")]

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use dash_p2p_core::{Addr, AddrV2Entry, AddrV2Msg, ServiceFlags};
use dash_primitives::{AddrV2, NetworkType};
use hex_conservative::{decode_to_array, decode_to_vec};
use rstest::rstest;

fn ipv4_entry(ip: [u8; 4], port: u16, time: u32) -> AddrV2Entry {
  AddrV2Entry::new(time, ServiceFlags::new(1), AddrV2::Ipv4(ip), port)
}

/// Multi-entry addrv2 payloads must decode every entry, not just
/// the first.
#[rstest]
fn addrv2_multi_entry_roundtrip() {
  let original = AddrV2Msg::new(vec![
    ipv4_entry([10, 0, 0, 1], 9999, 1_700_000_000),
    ipv4_entry([10, 0, 0, 2], 9999, 1_700_000_001),
    ipv4_entry([10, 0, 0, 3], 9999, 1_700_000_002),
  ]);

  let encoded = encode_to_vec(&original);
  let decoded: AddrV2Msg = decode_from_slice(&encoded).unwrap_or_else(|e| panic!("decode failed: {e}"));

  assert_eq!(decoded.addrs().len(), 3);
  assert_eq!(decoded, original);
}

#[rstest]
fn addrv2_single_entry_roundtrip() {
  let original = AddrV2Msg::new(vec![ipv4_entry([192, 168, 1, 1], 19999, 1_700_000_000)]);

  let encoded = encode_to_vec(&original);
  let decoded: AddrV2Msg = decode_from_slice(&encoded).unwrap_or_else(|e| panic!("decode failed: {e}"));

  assert_eq!(decoded, original);
}

#[rstest]
fn addrv2_empty_roundtrip() {
  let original = AddrV2Msg::new(vec![]);

  let encoded = encode_to_vec(&original);
  let decoded: AddrV2Msg = decode_from_slice(&encoded).unwrap_or_else(|e| panic!("decode failed: {e}"));

  assert_eq!(decoded, original);
}

/// BIP155 wire vector: three IPv6 loopback entries exercising
/// compactsize service flags and varied timestamps/ports.
#[rstest]
fn addrv2_bip155_wire_vector() {
  let hex = concat!(
    "03",
    "61bc6649",                         // time 0x4966bc61
    "00",                               // services 0 (compactsize)
    "02",                               // network IPv6
    "10",                               // addr length 16
    "00000000000000000000000000000001", // ::1
    "0000",                             // port 0
    "79627683",                         // time 0x83766279
    "01",                               // services 1 (compactsize)
    "02",                               // network IPv6
    "10",                               // addr length 16
    "00000000000000000000000000000001", // ::1
    "00f1",                             // port 241
    "ffffffff",                         // time 0xffffffff
    "fd0004",                           // services 1024 (compactsize)
    "02",                               // network IPv6
    "10",                               // addr length 16
    "00000000000000000000000000000001", // ::1
    "f1f2",                             // port 0xf1f2
  );

  let bytes = decode_to_vec(hex).unwrap_or_else(|e| panic!("bad hex: {e}"));
  let decoded: AddrV2Msg = decode_from_slice(&bytes).unwrap_or_else(|e| panic!("decode failed: {e}"));

  assert_eq!(decoded.addrs().len(), 3);

  let loopback = {
    let mut v = [0u8; 16];
    v[15] = 1;
    v
  };

  assert_eq!(decoded.addrs()[0].time(), 0x4966bc61);
  assert_eq!(decoded.addrs()[0].services(), ServiceFlags::new(0));
  assert_eq!(decoded.addrs()[0].addr().network(), NetworkType::Ipv6);
  assert_eq!(decoded.addrs()[0].addr(), &AddrV2::Ipv6(loopback));
  assert_eq!(decoded.addrs()[0].port(), 0);

  assert_eq!(decoded.addrs()[1].time(), 0x83766279);
  assert_eq!(decoded.addrs()[1].services(), ServiceFlags::new(1));
  assert_eq!(decoded.addrs()[1].addr(), &AddrV2::Ipv6(loopback));
  assert_eq!(decoded.addrs()[1].port(), 241);

  assert_eq!(decoded.addrs()[2].time(), 0xffffffff);
  assert_eq!(decoded.addrs()[2].services(), ServiceFlags::new(1024));
  assert_eq!(decoded.addrs()[2].addr(), &AddrV2::Ipv6(loopback));
  assert_eq!(decoded.addrs()[2].port(), 0xf1f2);

  assert_eq!(encode_to_vec(&decoded), bytes);
}

/// Legacy addr wire vector: three IPv6 loopback entries with 8-byte
/// little-endian service flags.
#[rstest]
fn addr_v1_wire_vector() {
  let hex = concat!(
    "03",
    "61bc6649",                         // time
    "0000000000000000",                 // services 0 (8 bytes LE)
    "00000000000000000000000000000001", // address (16 bytes)
    "0000",                             // port
    "79627683",                         // time
    "0100000000000000",                 // services 1
    "00000000000000000000000000000001", // address
    "00f1",                             // port
    "ffffffff",                         // time
    "0004000000000000",                 // services 1024
    "00000000000000000000000000000001", // address
    "f1f2",                             // port
  );

  let bytes = decode_to_vec(hex).unwrap_or_else(|e| panic!("bad hex: {e}"));
  let decoded: Addr = decode_from_slice(&bytes).unwrap_or_else(|e| panic!("decode failed: {e}"));

  assert_eq!(decoded.addrs().len(), 3);

  assert_eq!(decoded.addrs()[0].time(), 0x4966bc61);
  assert_eq!(decoded.addrs()[0].services(), ServiceFlags::new(0));
  assert_eq!(decoded.addrs()[0].addr().port(), 0);

  assert_eq!(decoded.addrs()[1].time(), 0x83766279);
  assert_eq!(decoded.addrs()[1].services(), ServiceFlags::new(1));
  assert_eq!(decoded.addrs()[1].addr().port(), 241);

  assert_eq!(decoded.addrs()[2].time(), 0xffffffff);
  assert_eq!(decoded.addrs()[2].services(), ServiceFlags::new(1024));
  assert_eq!(decoded.addrs()[2].addr().port(), 0xf1f2);

  assert_eq!(encode_to_vec(&decoded), bytes);
}

/// All five BIP155 network types in one addrv2 payload decode and
/// round-trip correctly.
#[rstest]
fn addrv2_all_bip155_network_types() {
  let torv3_bytes: [u8; 32] = decode_to_array("79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f")
    .unwrap_or_else(|e| panic!("bad hex: {e}"));

  let i2p_bytes: [u8; 32] = decode_to_array("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87")
    .unwrap_or_else(|e| panic!("bad hex: {e}"));

  let original = AddrV2Msg::new(vec![
    AddrV2Entry::new(1_700_000_000, ServiceFlags::new(1), AddrV2::Ipv4([1, 2, 3, 4]), 9999),
    AddrV2Entry::new(
      1_700_000_001,
      ServiceFlags::new(1),
      AddrV2::Ipv6([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      ]),
      9999,
    ),
    AddrV2Entry::new(1_700_000_002, ServiceFlags::new(1), AddrV2::TorV3(torv3_bytes), 9999),
    AddrV2Entry::new(1_700_000_003, ServiceFlags::new(1), AddrV2::I2p(i2p_bytes), 9999),
    AddrV2Entry::new(
      1_700_000_004,
      ServiceFlags::new(1),
      AddrV2::Cjdns([
        0xfc, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
      ]),
      9999,
    ),
  ]);

  let encoded = encode_to_vec(&original);
  let decoded: AddrV2Msg = decode_from_slice(&encoded).unwrap_or_else(|e| panic!("decode failed: {e}"));

  assert_eq!(decoded.addrs().len(), 5);
  assert_eq!(decoded, original);
}
