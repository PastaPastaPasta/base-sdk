//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Address definitions and network parameters.

use crate::prelude::*;
use crate::{opcode::Opcode, PubKeyHash, ScriptHash};

use base58ck::decode_check;
use dash_num::Hash160;
use dash_params::AddrParams;
use dash_pkc::ecdsa::EcdsaPkBytes;
use dash_types::codec::{BaseCodec, EncodeBuf};
use dash_types::{type_cvrt, type_id::Unencodable, Hashable, Numeric};

/// Recipient parsed from address.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "data"))]
pub enum Recipient {
  /// Pay-to-public-key.
  #[cfg_attr(feature = "serde", serde(rename = "p2pk"))]
  PubKey(EcdsaPkBytes),
  /// Pay-to-public-key-hash.
  #[cfg_attr(feature = "serde", serde(rename = "p2pkh"))]
  PubKeyHash(PubKeyHash),
  /// Pay-to-script-hash.
  #[cfg_attr(feature = "serde", serde(rename = "p2sh"))]
  ScriptHash(ScriptHash),
  /// Provably unspendable `OP_RETURN`.
  #[cfg_attr(feature = "serde", serde(rename = "unspendable"))]
  Unspendable,
}

impl Recipient {
  /// Parse a scriptPubKey. Returns `None` for unrecognized patterns.
  pub fn from_script(script: &[u8]) -> Option<Self> {
    let len = script.len();

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len == 25
      && script[0] == Opcode::Dup.to_base()
      && script[1] == Opcode::Hash160.to_base()
      && script[2] == Hash160::LEN as u8
      && script[23] == Opcode::EqualVerify.to_base()
      && script[24] == Opcode::CheckSig.to_base()
    {
      let bytes: &[u8; Hash160::LEN] = script[3..23].try_into().ok()?;
      return Some(Self::PubKeyHash(PubKeyHash::from(*bytes)));
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if len == 23
      && script[0] == Opcode::Hash160.to_base()
      && script[1] == Hash160::LEN as u8
      && script[22] == Opcode::Equal.to_base()
    {
      let bytes: &[u8; Hash160::LEN] = script[2..22].try_into().ok()?;
      return Some(Self::ScriptHash(ScriptHash::from(*bytes)));
    }

    // P2PK: <33 or 65 byte pubkey> OP_CHECKSIG
    if (len == 35 || len == 67) && script[0] as usize == len - 2 && script[len - 1] == Opcode::CheckSig.to_base() {
      let pk = EcdsaPkBytes::from_bytes(&script[1..len - 1])?;
      return Some(Self::PubKey(pk));
    }

    // OP_RETURN
    if script.first() == Some(&Opcode::Return.to_base()) {
      return Some(Self::Unspendable);
    }

    None
  }

  /// Encode as a Base58Check address.
  ///
  /// Returns `None` for `Unspendable`, which has no address form.
  pub fn to_base58c(&self, params: &AddrParams) -> Option<String> {
    match self {
      Self::PubKeyHash(h) => Some(h.to_base58c(params.pubkey_addr)),
      Self::ScriptHash(h) => Some(h.to_base58c(params.script_addr)),
      Self::PubKey(pk) => Some(pk.hash().to_base58c(params.pubkey_addr)),
      Self::Unspendable => None,
    }
  }

  /// Decode a Base58Check address string.
  ///
  /// Returns `None` when the string is not a valid P2PKH or P2SH address for
  /// the given network parameters.
  pub fn from_base58c(s: &str, params: &AddrParams) -> Option<Self> {
    let data = decode_check(s).ok()?;
    if data.len() != 21 {
      return None;
    }
    let hash: [u8; Hash160::LEN] = data[1..].try_into().ok()?;
    if data[0] == params.pubkey_addr {
      Some(Self::PubKeyHash(PubKeyHash::from(hash)))
    } else if data[0] == params.script_addr {
      Some(Self::ScriptHash(ScriptHash::from(hash)))
    } else {
      None
    }
  }

  /// Encode as a scriptPubKey.
  pub fn to_script(&self, buf: &mut impl EncodeBuf) {
    match self {
      Self::PubKeyHash(h) => {
        buf.push(Opcode::Dup.to_base());
        buf.push(Opcode::Hash160.to_base());
        buf.push(Hash160::LEN as u8);
        h.encode(buf);
        buf.push(Opcode::EqualVerify.to_base());
        buf.push(Opcode::CheckSig.to_base());
      }
      Self::ScriptHash(h) => {
        buf.push(Opcode::Hash160.to_base());
        buf.push(Hash160::LEN as u8);
        h.encode(buf);
        buf.push(Opcode::Equal.to_base());
      }
      Self::PubKey(pk) => {
        let bytes = pk.as_bytes();
        buf.push(bytes.len() as u8);
        // nosemgrep: codec-no-raw-extend
        buf.extend_from_slice(bytes);
        buf.push(Opcode::CheckSig.to_base());
      }
      Self::Unspendable => {
        buf.push(Opcode::Return.to_base());
      }
    }
  }
}

type_cvrt!(
  enum Recipient {
    PubKey(EcdsaPkBytes),
    PubKeyHash(PubKeyHash),
    ScriptHash(ScriptHash),
  }
);

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_params::Network;
  use hex_conservative::hex;
  use rstest::rstest;

  // The generator point's coordinates shared across P2PK vectors
  macro_rules! gen_x {
    () => {
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    };
  }
  macro_rules! gen_y {
    () => {
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    };
  }

  // OP_DUP OP_HASH160, a zero hash160, then OP_EQUALVERIFY OP_CHECKSIG.
  const P2PKH: [u8; 25] = hex!(concat!("76a914", "0000000000000000000000000000000000000000", "88ac"));
  // OP_HASH160, the same zero hash160, then OP_EQUAL.
  const P2SH: [u8; 23] = hex!(concat!("a914", "0000000000000000000000000000000000000000", "87"));
  // The generator is used so the vectors are real keys.
  const P2PK_COMP_EVEN: [u8; 35] = hex!(concat!("21", "02", gen_x!(), "ac"));
  // Same X, 0x03 header: the other root, i.e. the negated generator, Y odd.
  const P2PK_COMP_ODD: [u8; 35] = hex!(concat!("21", "03", gen_x!(), "ac"));
  // The generator again, both coordinates spelled out.
  const P2PK_UNCOMP: [u8; 67] = hex!(concat!("41", "04", gen_x!(), gen_y!(), "ac"));
  // X = 0 has no point on the curve, but the SEC1 framing is well-formed, so
  // a structural classifier still reads it as P2PK.
  const P2PK_X_ZERO: [u8; 35] = hex!(concat!(
    "21",
    "02",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ac",
  ));
  // The generator's X with a Y that is not its square root: likewise well-formed,
  // just as unspendable.
  const P2PK_BAD_Y: [u8; 67] = hex!(concat!(
    "41",
    "04",
    gen_x!(),
    "0000000000000000000000000000000000000000000000000000000000000001",
    "ac",
  ));

  #[rstest]
  #[case::p2pkh(&P2PKH, Recipient::PubKeyHash(PubKeyHash::from([0; Hash160::LEN])))]
  #[case::p2sh(&P2SH, Recipient::ScriptHash(ScriptHash::from([0; Hash160::LEN])))]
  #[case::p2pkh_nonzero(
    &hex!("76a914010203040506070809101112131415161718192088ac"),
    Recipient::PubKeyHash(PubKeyHash::from(hex!("0102030405060708091011121314151617181920"))),
  )]
  #[case::p2sh_nonzero(
    &hex!("a914aabbccddee00112233445566778899aabbccddee87"),
    Recipient::ScriptHash(ScriptHash::from(hex!("aabbccddee00112233445566778899aabbccddee"))),
  )]
  #[case::op_return_data(&hex!("6a04deadbeef"), Recipient::Unspendable)]
  #[case::op_return_bare(&[Opcode::Return.to_base()], Recipient::Unspendable)]
  fn from_script_matches(#[case] script: &[u8], #[case] expected: Recipient) {
    assert_eq!(Recipient::from_script(script), Some(expected));
  }

  #[rstest]
  #[case::p2pk_even(&P2PK_COMP_EVEN, &P2PK_COMP_EVEN[1..34])]
  #[case::p2pk_odd(&P2PK_COMP_ODD, &P2PK_COMP_ODD[1..34])]
  #[case::p2pk_uncomp(&P2PK_UNCOMP, &P2PK_UNCOMP[1..66])]
  #[case::p2pk_x_not_on_curve(&P2PK_X_ZERO, &P2PK_X_ZERO[1..34])]
  #[case::p2pk_y_not_a_root(&P2PK_BAD_Y, &P2PK_BAD_Y[1..66])]
  fn from_script_p2pk(#[case] script: &[u8], #[case] key_bytes: &[u8]) {
    assert!(matches!(
      Recipient::from_script(script),
      Some(Recipient::PubKey(pk)) if pk.as_bytes() == key_bytes
    ));
  }

  #[rstest]
  #[case::empty(&[])]
  #[case::p2pkh_extra_byte(&hex!("76a914000000000000000000000000000000000000000088acac"))]
  #[case::p2pkh_truncated(&hex!("76a9140000000088ac"))]
  #[case::p2pkh_wrong_trailing(&hex!("76a91400000000000000000000000000000000000000001414"))]
  #[case::p2pkh_wrong_leading(&hex!("a91400000000000000000000000000000000000000008888ac6a"))]
  #[case::p2sh_pushdata1(&hex!("a94c14000000000000000000000000000000000000000087"))]
  #[case::p2sh_wrong_leading(&hex!("611400000000000000000000000000000000000000000087"))]
  #[case::p2sh_wrong_trailing(&hex!("a9140000000000000000000000000000000000000000ac"))]
  #[case::p2pk_missing_checksig(&hex!(
    "21020000000000000000000000000000000000000000000000000000000000000000"
  ))]
  #[case::p2pk_wrong_trailing(&hex!(
    "2102000000000000000000000000000000000000000000000000000000000000000088"
  ))]
  #[case::p2pk_too_short(&hex!("210200ac"))]
  #[case::arithmetic(&hex!("59935b87"))]
  #[case::p2sh_pushdata2(&hex!("4d1400000000000000000000000000000000000000000087"))]
  #[case::p2sh_pushdata4(&hex!("4e14000000000000000000000000000000000000000000000087"))]
  fn from_script_rejects(#[case] script: &[u8]) {
    assert!(Recipient::from_script(script).is_none());
  }

  #[rstest]
  #[case::p2pk(&P2PK_COMP_EVEN, Some("XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE"))]
  #[case::p2pkh(&P2PKH, Some("XagqqFetxiDb9wbartKDrXgnqLah6SqX2S"))]
  #[case::p2sh(
    &hex!("a914242424242424242424242424242424242424242487"),
    Some("7VhkNn2LJ9YE35ZGbWkfPjKisrCFT7ovqy"),
  )]
  #[case::op_return(&hex!("6a00"), None)]
  fn to_base58c_address(#[case] script: &[u8], #[case] expected: Option<&str>) {
    let addr = Recipient::from_script(script).and_then(|r| r.to_base58c(Network::Main.addr()));
    assert_eq!(addr.as_deref(), expected);
  }

  // `Unspendable` is deliberately excluded: it discards the OP_RETURN operand,
  // so it is the one variant that cannot round-trip.
  #[rstest]
  #[case::p2pkh(&P2PKH)]
  #[case::p2sh(&P2SH)]
  #[case::p2pk_even(&P2PK_COMP_EVEN)]
  #[case::p2pk_odd(&P2PK_COMP_ODD)]
  #[case::p2pk_uncomp(&P2PK_UNCOMP)]
  fn to_script_round_trips(#[case] script: &[u8]) {
    let recipient = Recipient::from_script(script).unwrap();
    let mut buf = Vec::new();
    recipient.to_script(&mut buf);
    assert_eq!(buf.as_slice(), script);
  }

  #[rstest]
  fn unspendable_to_script_drops_operand() {
    let recipient = Recipient::from_script(&hex!("6a04deadbeef")).unwrap();
    let mut buf = Vec::new();
    recipient.to_script(&mut buf);
    assert_eq!(buf.as_slice(), &[Opcode::Return.to_base()]);
  }

  #[rstest]
  #[case::p2pkh("XdywTHuctyLo75vU4gjnVFeve7erBRcpzP", Recipient::PubKeyHash(PubKeyHash::from([0x24; Hash160::LEN])))]
  #[case::p2sh("7VhkNn2LJ9YE35ZGbWkfPjKisrCFT7ovqy", Recipient::ScriptHash(ScriptHash::from([0x24; Hash160::LEN])))]
  fn from_base58c_round_trips(#[case] addr: &str, #[case] expected: Recipient) {
    let recipient = Recipient::from_base58c(addr, Network::Main.addr()).unwrap();
    assert_eq!(recipient, expected);
    assert_eq!(recipient.to_base58c(Network::Main.addr()).as_deref(), Some(addr));
  }

  #[rstest]
  // Valid Base58Check, but the testnet version byte matches no MAINNET kind.
  #[case::wrong_version("yPcYUEz4LWzsSpr1dY4BXH5GvQ9DdCV6cv")]
  #[case::bad_checksum("7VhkNn2LJ9YE35ZGbWkfPjKisrCFT7ovqz")]
  #[case::not_base58("not an address")]
  #[case::empty("")]
  fn from_base58c_rejects(#[case] addr: &str) {
    assert!(Recipient::from_base58c(addr, Network::Main.addr()).is_none());
  }
}
