//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis and devnet genesis block descriptors.

use crate::prelude::*;

use bitcoin_hashes::sha256d;
use bitcoin_units::Amount;
use dash_num::{Arith256, CompactTarget, Hash256};
use dash_pow::__deps::digest::Digest;
use dash_pow::X11;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use dash_types::Numeric;
use hex_conservative::hex;

/// Fields that define a genesis block with a single coinbase transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct GenesisParams {
  /// Block version.
  pub version: i32,
  /// Block timestamp (unix epoch seconds).
  pub time: u32,
  /// Compact difficulty target.
  pub bits: u32,
  /// Nonce used for proof-of-work.
  pub nonce: u32,
  /// Input script of the coinbase transaction.
  pub script_sig: &'static [u8],
  /// Output script of the coinbase transaction.
  pub script_pubkey: &'static [u8],
  /// Value of the coinbase output.
  pub reward: Amount,
}

impl GenesisParams {
  /// Coinbase input script shared by every network's genesis block.
  pub(crate) const COINBASE_SCRIPT_SIG: &[u8] = &hex!(concat!(
    "04ffff001d01044c5957697265642030392f4a616e2f323031342054686520",
    "4772616e64204578706572696d656e7420476f6573204c6976653a204f7665",
    "7273746f636b2e636f6d204973204e6f7720416363657074696e6720426974",
    "636f696e73"
  ));

  /// Coinbase output script shared by every network's genesis block.
  pub(crate) const COINBASE_SCRIPT_PUBKEY: &[u8] = &hex!(concat!(
    "41040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4",
    "d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070",
    "ac7b03a9ac"
  ));

  /// The genesis block's hash, the X11 hash of its header.
  pub(crate) fn block_hash(&self) -> Hash256 {
    let coinbase = coinbase(self.script_sig, self.reward, self.script_pubkey);
    let merkle_root = sha256d::Hash::hash(&coinbase).to_byte_array();
    let mut header = header(self.version, Hash256::ZERO, &merkle_root, self.time, self.bits);
    header[NONCE].copy_from_slice(&self.nonce.to_le_bytes());
    Hash256::from_lendian(X11::digest(header).into())
  }
}

/// Fields that define a devnet genesis block, the block at height 1 that
/// names its devnet in a single coinbase transaction.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct DevnetGenesisParams {
  /// The devnet's name, `devnet` or `devnet-<name>`, which the coinbase input
  /// script pushes.
  pub name: String,
  /// Hash of the genesis block it builds on.
  pub prev_hash: Hash256,
  /// Block timestamp (unix epoch seconds).
  pub time: u32,
  /// Compact difficulty target.
  pub bits: u32,
  /// Nonce used for proof-of-work.
  pub nonce: u32,
  /// Hash of the block.
  pub hash: Hash256,
}

impl DevnetGenesisParams {
  /// Block version.
  pub const VERSION: i32 = 4;

  /// Value of the coinbase output.
  pub const REWARD: Amount = Amount::from_btc_u16(50);

  /// Output script of the coinbase transaction, `OP_RETURN`.
  pub const SCRIPT_PUBKEY: &[u8] = &[0x6a];

  /// The devnet genesis block of the devnet `name` on top of `genesis`. Its
  /// nonce is the first from 0 whose X11 hash meets the genesis block's
  /// target.
  ///
  /// `None` if `name` is empty or too long for a script push, or if no
  /// nonce below `u32::MAX` qualifies.
  pub fn find(name: &str, genesis: &GenesisParams) -> Option<Self> {
    if name.is_empty() || push_prefix(name.len()).is_none() {
      return None;
    }
    let mut params = Self {
      name: String::from(name),
      prev_hash: genesis.block_hash(),
      time: genesis.time.wrapping_add(1),
      bits: genesis.bits,
      nonce: 0,
      hash: Hash256::ZERO,
    };
    let coinbase = coinbase(&params.script_sig(), Self::REWARD, Self::SCRIPT_PUBKEY);
    let merkle_root = sha256d::Hash::hash(&coinbase).to_byte_array();
    let target = CompactTarget::new(params.bits).expand().value;
    let mut header = header(Self::VERSION, params.prev_hash, &merkle_root, params.time, params.bits);
    for nonce in 0..u32::MAX {
      header[NONCE].copy_from_slice(&nonce.to_le_bytes());
      let hash = X11::digest(header);
      if Arith256::from_lendian(hash.into()) <= target {
        params.nonce = nonce;
        params.hash = Hash256::from_lendian(hash.into());
        return Some(params);
      }
    }
    None
  }

  /// Input script of the coinbase transaction, `OP_1` and then the shortest
  /// push of [`name`](Self::name).
  ///
  /// A name too long for any push, which [`find`](Self::find) refuses, gets
  /// no push opcode.
  pub fn script_sig(&self) -> Vec<u8> {
    let name = self.name.as_bytes();
    let mut script = vec![0x51];
    script.extend(push_prefix(name.len()).unwrap_or_default());
    script.extend_from_slice(name);
    script
  }
}

/// The opcode and length bytes of the shortest push of `len` bytes, or `None`
/// if no push holds that many.
fn push_prefix(len: usize) -> Option<Vec<u8>> {
  let len = u32::try_from(len).ok()?;
  let [b0, b1, ..] = len.to_le_bytes();
  Some(match len {
    0..=0x4b => vec![b0],
    0x4c..=0xff => vec![0x4c, b0],
    0x100..=0xffff => vec![0x4d, b0, b1],
    _ => [&[0x4e][..], &len.to_le_bytes()].concat(),
  })
}

/// The serialized coinbase transaction of a genesis block, whose txid is
/// the merkle root.
fn coinbase(script_sig: &[u8], reward: Amount, script_pubkey: &[u8]) -> Vec<u8> {
  let mut tx = Vec::new();
  tx.extend_from_slice(&1_i32.to_le_bytes());
  tx.push(1);
  tx.extend_from_slice(&[0; 32]);
  tx.extend_from_slice(&u32::MAX.to_le_bytes());
  compact_size(&mut tx, script_sig.len());
  tx.extend_from_slice(script_sig);
  tx.extend_from_slice(&u32::MAX.to_le_bytes());
  tx.push(1);
  tx.extend_from_slice(&reward.to_sat().to_le_bytes());
  compact_size(&mut tx, script_pubkey.len());
  tx.extend_from_slice(script_pubkey);
  tx.extend_from_slice(&0_u32.to_le_bytes());
  tx
}

/// Where a serialized block header holds its nonce, its last four bytes.
const NONCE: core::ops::Range<usize> = 76..80;

/// A serialized block header with a zero nonce, which callers write at
/// [`NONCE`].
fn header(version: i32, prev_hash: Hash256, merkle_root: &[u8; 32], time: u32, bits: u32) -> [u8; 80] {
  let mut header = [0; 80];
  header[..4].copy_from_slice(&version.to_le_bytes());
  header[4..36].copy_from_slice(&prev_hash.to_lendian());
  header[36..68].copy_from_slice(merkle_root);
  header[68..72].copy_from_slice(&time.to_le_bytes());
  header[72..76].copy_from_slice(&bits.to_le_bytes());
  header
}

/// Appends the CompactSize encoding of `n`.
fn compact_size(buf: &mut Vec<u8>, n: usize) {
  match u64::try_from(n).unwrap_or(u64::MAX) {
    n @ 0..=0xfc => buf.extend_from_slice(&n.to_le_bytes()[..1]),
    n @ 0xfd..=0xffff => {
      buf.push(0xfd);
      buf.extend_from_slice(&n.to_le_bytes()[..2]);
    }
    n @ 0x1_0000..=0xffff_ffff => {
      buf.push(0xfe);
      buf.extend_from_slice(&n.to_le_bytes()[..4]);
    }
    n => {
      buf.push(0xff);
      buf.extend_from_slice(&n.to_le_bytes());
    }
  }
}

#[cfg(test)]
mod tests {
  use super::push_prefix;
  use crate::Network;

  use rstest::rstest;

  /// Every network's genesis header hashes to its genesis block hash.
  #[rstest]
  fn genesis_header_hashes_to_the_genesis_hash(
    #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
  ) {
    let chain = network.chain();
    assert_eq!(chain.genesis.block_hash(), chain.consensus.hash_genesis_block);
  }

  #[rstest]
  #[case(0, Some(&[0x00][..]))]
  #[case(0x4b, Some(&[0x4b][..]))]
  #[case(0x4c, Some(&[0x4c, 0x4c][..]))]
  #[case(0x100, Some(&[0x4d, 0x00, 0x01][..]))]
  #[case(0x1_0000, Some(&[0x4e, 0x00, 0x00, 0x01, 0x00][..]))]
  fn push_prefixes_are_the_shortest(#[case] len: usize, #[case] want: Option<&[u8]>) {
    assert_eq!(push_prefix(len).as_deref(), want);
  }

  /// A name of 4 GiB or more has no push, so no devnet genesis block.
  #[cfg(target_pointer_width = "64")]
  #[rstest]
  fn no_push_holds_4_gib() {
    assert_eq!(push_prefix(0x1_0000_0000), None);
  }
}
