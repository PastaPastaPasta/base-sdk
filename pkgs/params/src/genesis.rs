//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis and devnet genesis blocks, as Core's `chainparams.cpp` builds them.

use crate::prelude::*;

use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin_units::Amount;
use dash_num::{Arith256, CompactTarget, Hash256};
use dash_primitives::{Block, BlockHash, BlockHeader, MerkleRoot, OutPoint, Transaction, TxHash, TxIn, TxOut, TxType};
use dash_script::Opcode;
use dash_types::{Hashable, Numeric};
use hex_conservative::hex;

/// The block reward of both genesis blocks, 50 DASH.
const GENESIS_REWARD_DASH: u16 = 50;

/// One-transaction block over `coinbase`, with the merkle root filled in.
fn block(header: BlockHeader, coinbase: Transaction) -> Block {
  let mut block = Block {
    header,
    transactions: vec![coinbase],
  };
  block.header.merkle_root = block.merkle().0;
  block
}

/// A version 1 coinbase transaction with one input and one output.
fn coinbase(script_sig: Vec<u8>, script_pubkey: Vec<u8>) -> Transaction {
  Transaction {
    version: 1,
    tx_type: TxType::Spend,
    inputs: vec![TxIn {
      prevout: OutPoint {
        hash: TxHash::default(),
        index: 0xFFFF_FFFF,
      },
      script_sig: ScriptSigBuf::from_bytes(script_sig),
      sequence: 0xFFFF_FFFF,
    }],
    outputs: vec![TxOut::new(
      Amount::from_btc_u16(GENESIS_REWARD_DASH),
      ScriptPubKeyBuf::from_bytes(script_pubkey),
    )],
    lock_time: 0,
    extra_payload: Vec::new(),
  }
}

/// Core's `CreateGenesisBlock(nTime, nNonce, nBits, 1, 50 * COIN)` with the
/// Overstock headline and Satoshi's output key; `header` gives the time,
/// bits and nonce.
pub(crate) fn genesis_block(header: BlockHeader) -> Block {
  let script_sig = hex!(concat!(
    "04ffff001d01044c5957697265642030392f4a616e2f323031342054686520",
    "4772616e64204578706572696d656e7420476f6573204c6976653a204f7665",
    "7273746f636b2e636f6d204973204e6f7720416363657074696e6720426974",
    "636f696e73"
  ));
  let script_pubkey = hex!(concat!(
    "41040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4",
    "d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070",
    "ac7b03a9ac"
  ));
  let header = BlockHeader {
    version: 1,
    prev_hash: BlockHash::default(),
    merkle_root: MerkleRoot::default(),
    ..header
  };
  block(header, coinbase(script_sig.to_vec(), script_pubkey.to_vec()))
}

/// `CScript() << data`: the shortest push of `data`.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
  match u32::try_from(data.len()) {
    Ok(len @ 0..=0x4b) => script.extend_from_slice(&len.to_le_bytes()[..1]),
    Ok(len @ 0x4c..=0xff) => {
      script.push(Opcode::PushData1.to_base());
      script.extend_from_slice(&len.to_le_bytes()[..1]);
    }
    Ok(len @ 0x100..=0xffff) => {
      script.push(Opcode::PushData2.to_base());
      script.extend_from_slice(&len.to_le_bytes()[..2]);
    }
    Ok(len) => {
      script.push(Opcode::PushData4.to_base());
      script.extend_from_slice(&len.to_le_bytes());
    }
    // A name of 4 GiB or more cannot come from a command line.
    Err(_) => return,
  }
  script.extend_from_slice(data);
}

/// Core's `FindDevNetGenesisBlock`: the first nonce from 0 whose X11 hash
/// meets `prev`'s nBits, over `CreateDevNetGenesisBlock`.
///
/// The coinbase script is `OP_1 <name>` and its output an `OP_RETURN` of
/// 50 DASH. `None` if no nonce below `u32::MAX` qualifies, where Core
/// asserts.
pub(crate) fn find_devnet_genesis(prev: &Block, devnet_name: &str) -> Option<Block> {
  let mut script_sig = vec![Opcode::Op1.to_base()];
  push_data(&mut script_sig, devnet_name.as_bytes());
  let coinbase = coinbase(script_sig, vec![Opcode::Return.to_base()]);
  let header = BlockHeader {
    version: 4,
    prev_hash: prev.header.hash(),
    merkle_root: MerkleRoot::default(),
    time: prev.header.time.wrapping_add(1),
    bits: prev.header.bits,
    nonce: 0,
  };
  let mut block = block(header, coinbase);
  let target = CompactTarget::new(block.header.bits).expand().value;
  for nonce in 0..u32::MAX {
    block.header.nonce = nonce;
    if Arith256::from(Hash256::from(block.header.hash())) <= target {
      return Some(block);
    }
  }
  None
}
