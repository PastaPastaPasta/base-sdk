//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis block descriptor.

use crate::prelude::*;

use bitcoin_hashes::sha256d;
use bitcoin_units::Amount;
use dash_num::{Arith256, CompactTarget, Hash256};
use dash_pow::__deps::digest::Digest;
use dash_pow::X11;
use dash_types::type_id::Unencodable;
use dash_types::Numeric;
use hex_conservative::hex;

/// Fields that define a genesis block with a single coinbase transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
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
}

/// Fields that define a devnet genesis block: the block at height 1 that
/// names its devnet in a single coinbase transaction.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct DevnetGenesisParams {
  /// Core's devnet name (`devnet` or `devnet-<name>`), which the coinbase
  /// input script pushes.
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

  /// Core's `FindDevNetGenesisBlock` for the devnet `name` on top of the
  /// genesis block `genesis`, whose hash is `genesis_hash`: the first nonce
  /// from 0 whose X11 hash meets the genesis block's nBits.
  ///
  /// `None` if no nonce below `u32::MAX` qualifies, where Core asserts.
  pub fn find(name: &str, genesis: &GenesisParams, genesis_hash: Hash256) -> Option<Self> {
    let mut params = Self {
      name: String::from(name),
      prev_hash: genesis_hash,
      time: genesis.time.wrapping_add(1),
      bits: genesis.bits,
      nonce: 0,
      hash: Hash256::ZERO,
    };
    let merkle_root = sha256d::Hash::hash(&params.coinbase()).to_byte_array();
    let target = CompactTarget::new(params.bits).expand().value;
    for nonce in 0..u32::MAX {
      params.nonce = nonce;
      let hash = X11::digest(params.header(&merkle_root));
      if Arith256::from_lendian(hash.into()) <= target {
        params.hash = Hash256::from_lendian(hash.into());
        return Some(params);
      }
    }
    None
  }

  /// Input script of the coinbase transaction: `OP_1`, then the shortest
  /// push of [`name`](Self::name).
  pub fn script_sig(&self) -> Vec<u8> {
    let name = self.name.as_bytes();
    let mut script = vec![0x51];
    match u32::try_from(name.len()) {
      Ok(len @ 0..=0x4b) => script.extend_from_slice(&len.to_le_bytes()[..1]),
      Ok(len @ 0x4c..=0xff) => {
        script.push(0x4c);
        script.extend_from_slice(&len.to_le_bytes()[..1]);
      }
      Ok(len @ 0x100..=0xffff) => {
        script.push(0x4d);
        script.extend_from_slice(&len.to_le_bytes()[..2]);
      }
      Ok(len) => {
        script.push(0x4e);
        script.extend_from_slice(&len.to_le_bytes());
      }
      // A name of 4 GiB or more cannot come from a command line.
      Err(_) => return script,
    }
    script.extend_from_slice(name);
    script
  }

  /// The serialized coinbase transaction, whose txid is the merkle root.
  fn coinbase(&self) -> Vec<u8> {
    let script_sig = self.script_sig();
    let mut tx = Vec::new();
    tx.extend_from_slice(&1_i32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&[0; 32]);
    tx.extend_from_slice(&u32::MAX.to_le_bytes());
    compact_size(&mut tx, script_sig.len());
    tx.extend_from_slice(&script_sig);
    tx.extend_from_slice(&u32::MAX.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&Self::REWARD.to_sat().to_le_bytes());
    compact_size(&mut tx, Self::SCRIPT_PUBKEY.len());
    tx.extend_from_slice(Self::SCRIPT_PUBKEY);
    tx.extend_from_slice(&0_u32.to_le_bytes());
    tx
  }

  /// The serialized block header over `merkle_root`.
  fn header(&self, merkle_root: &[u8; 32]) -> [u8; 80] {
    let mut header = [0; 80];
    header[..4].copy_from_slice(&Self::VERSION.to_le_bytes());
    header[4..36].copy_from_slice(&self.prev_hash.to_lendian());
    header[36..68].copy_from_slice(merkle_root);
    header[68..72].copy_from_slice(&self.time.to_le_bytes());
    header[72..76].copy_from_slice(&self.bits.to_le_bytes());
    header[76..].copy_from_slice(&self.nonce.to_le_bytes());
    header
  }
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
