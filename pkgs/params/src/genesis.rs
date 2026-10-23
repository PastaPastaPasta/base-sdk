//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis block descriptor.

use crate::prelude::*;

use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin_units::Amount;
use dash_primitives::{Block, BlockHash, BlockHeader, MerkleRoot, OutPoint, Transaction, TxHash, TxIn, TxOut, TxType};
use hex_conservative::hex;

/// Fields that define a genesis block with a single coinbase transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

impl From<&GenesisParams> for Block {
  fn from(params: &GenesisParams) -> Self {
    let coinbase = Transaction {
      version: 1,
      tx_type: TxType::Spend,
      inputs: vec![TxIn {
        prevout: OutPoint {
          hash: TxHash::default(),
          index: 0xFFFF_FFFF,
        },
        script_sig: ScriptSigBuf::from_bytes(params.script_sig.to_vec()),
        sequence: 0xFFFF_FFFF,
      }],
      outputs: vec![TxOut {
        value: params.reward,
        script_pubkey: ScriptPubKeyBuf::from_bytes(params.script_pubkey.to_vec()),
      }],
      lock_time: 0,
      extra_payload: Vec::new(),
    };

    let mut block = Block {
      header: BlockHeader {
        version: params.version,
        prev_hash: BlockHash::default(),
        merkle_root: MerkleRoot::default(),
        time: params.time,
        bits: params.bits,
        nonce: params.nonce,
      },
      transactions: vec![coinbase],
    };
    block.header.merkle_root = block.merkle().0;
    block
  }
}
