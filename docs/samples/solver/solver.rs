//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Trivial scanhash implementation.

#![no_std]

extern crate alloc;

use bitcoin_consensus_encoding::encode_to_vec;
use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin_units::Amount;
use dash_num::{Arith256, CompactTarget, Hash256};
use dash_pow::__deps::digest::Digest;
use dash_pow::X11;
use dash_primitives::{BlockHash, BlockHeader, MerkleRoot, OutPoint, Transaction, TxHash, TxIn, TxOut, TxType};
use dash_types::{Hashable, Numeric};
use hex_conservative::decode_to_vec;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
struct ScanResult {
  found: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  nonce: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  hash: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  merkle_root: Option<String>,
  hashes: u32,
}

/// Build a coinbase transaction.
fn build_coinbase(script_sig: Vec<u8>, script_pubkey: Vec<u8>, amount_duffs: &str) -> Result<Transaction, String> {
  let sat: u64 = amount_duffs.parse().map_err(|e| format!("invalid amount: {e}"))?;
  let value = Amount::from_sat(sat).map_err(|e| format!("invalid amount: {e}"))?;
  Ok(Transaction::new(
    1,
    TxType::Spend,
    vec![TxIn::new(
      OutPoint::new(TxHash::default(), 0xFFFF_FFFF),
      ScriptSigBuf::from_bytes(script_sig),
      0xFFFF_FFFF,
    )],
    vec![TxOut::new(
      value.to_signed(),
      ScriptPubKeyBuf::from_bytes(script_pubkey),
    )],
    0,
    Vec::new(),
  ))
}

/// Compute the merkle root from coinbase parameters.
#[wasm_bindgen]
pub fn merkle_root(script_sig_hex: &str, script_pubkey_hex: &str, amount_duffs: &str) -> Result<String, String> {
  let sig_bytes = decode_to_vec(script_sig_hex).map_err(|e| format!("invalid scriptSig hex: {e}"))?;
  let pk_bytes = decode_to_vec(script_pubkey_hex).map_err(|e| format!("invalid scriptPubKey hex: {e}"))?;
  let coinbase = build_coinbase(sig_bytes, pk_bytes, amount_duffs)?;
  let root = MerkleRoot::from_lendian(*coinbase.hash().as_bytes());
  Ok(format!("{root}"))
}

/// Scan a batch of nonces for a valid proof-of-work hash.
#[wasm_bindgen]
pub fn scanhash(
  version: i32,
  prev_hash_hex: &str,
  time: u32,
  bits: u32,
  script_sig_hex: &str,
  script_pubkey_hex: &str,
  amount_duffs: &str,
  nonce_start: u32,
  nonce_count: u32,
) -> Result<String, String> {
  let prev_hash = BlockHash::from_hex(prev_hash_hex).map_err(|e| format!("invalid prev_hash hex: {e}"))?;
  let sig_bytes = decode_to_vec(script_sig_hex).map_err(|e| format!("invalid scriptSig hex: {e}"))?;
  let pk_bytes = decode_to_vec(script_pubkey_hex).map_err(|e| format!("invalid scriptPubKey hex: {e}"))?;

  let coinbase = build_coinbase(sig_bytes, pk_bytes, amount_duffs)?;
  let merkle_root = MerkleRoot::from_lendian(*coinbase.hash().as_bytes());

  let header = BlockHeader::new(version, prev_hash, merkle_root, time, bits, nonce_start);
  let mut header_buf = encode_to_vec(&header);

  let decoded = CompactTarget::new(bits).expand();
  if decoded.negative || decoded.overflow {
    return Err("invalid compact target".to_string());
  }
  let target = decoded.value;

  let mut nonce = nonce_start;
  let mut hashes: u32 = 0;
  while hashes < nonce_count {
    header_buf[76..80].copy_from_slice(&nonce.to_le_bytes());
    let digest: [u8; 32] = X11::digest(&header_buf).into();
    let hash = Hash256::from(digest);
    hashes += 1;
    if Arith256::from(hash) <= target {
      let result = ScanResult {
        found: true,
        nonce: Some(nonce),
        hash: Some(format!("{hash}")),
        merkle_root: Some(format!("{merkle_root}")),
        hashes,
      };
      return serde_json::to_string(&result).map_err(|e| format!("failed to serialize: {e}"));
    }
    nonce = nonce.wrapping_add(1);
  }

  let result = ScanResult {
    found: false,
    nonce: None,
    hash: None,
    merkle_root: None,
    hashes,
  };
  serde_json::to_string(&result).map_err(|e| format!("failed to serialize: {e}"))
}
