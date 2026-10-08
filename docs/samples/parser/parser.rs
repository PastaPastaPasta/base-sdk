//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block and transaction parser.

#![no_std]

extern crate alloc;

use dash_primitives::{Block, BlockHeader, Transaction};
use dash_types::codec::BaseCodec;
use hex_conservative::decode_to_vec;
use serde_json::Value;
use wasm_bindgen::prelude::*;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};

/// Replace the hex `extra_payload` field with the decoded special payload
/// structure.
fn enrich_tx(tx: &Transaction, val: &mut Value) -> Option<String> {
  let obj = match val.as_object_mut() {
    Some(o) => o,
    None => return None,
  };
  match tx.decode_payload() {
    Some(Ok(decoded)) if !decoded.is_complete() => Some(format!(
      "{} payload: trailing bytes: {} remaining",
      tx.tx_type,
      decoded.len - decoded.consumed
    )),
    Some(Ok(decoded)) => {
      if let Ok(v) = serde_json::to_value(&decoded.payload) {
        obj.insert("extra_payload".into(), v);
      }
      None
    }
    Some(Err(e)) => Some(format!("{e}")),
    None => None,
  }
}

/// Enrich all transactions inside a serialized block value.
fn enrich_block(block: &Block, val: &mut Value) -> Vec<String> {
  let mut warnings = Vec::new();
  let txs = match val.get_mut("transactions").and_then(Value::as_array_mut) {
    Some(a) => a,
    None => return warnings,
  };
  for (i, (tx, json_tx)) in block.transactions.iter().zip(txs.iter_mut()).enumerate() {
    if let Some(msg) = enrich_tx(tx, json_tx) {
      warnings.push(format!("tx {i}: {msg}"));
    }
  }
  warnings
}

/// Build the JSON envelope
fn envelope(data: Value, warnings: Vec<String>) -> Result<String, String> {
  let w: Vec<Value> = warnings.into_iter().map(Value::String).collect();
  let mut map = serde_json::Map::new();
  map.insert("data".into(), data);
  map.insert("warnings".into(), Value::Array(w));
  serde_json::to_string_pretty(&Value::Object(map)).map_err(|e| format!("failed to serialize to JSON: {e}"))
}

/// Parses a hex-encoded raw block or block header and returns a JSON string.
/// Inputs of exactly 80 bytes are decoded as a block header; longer inputs are
/// decoded as a full block.
#[wasm_bindgen]
pub fn parse_block_hex(hex_str: &str) -> Result<String, String> {
  let bytes = decode_to_vec(hex_str).map_err(|e| format!("invalid hex: {e}"))?;

  if bytes.is_empty() {
    return Err("no data provided".to_string());
  }

  if bytes.len() == 80 {
    let header = BlockHeader::decode(&mut &bytes[..]).map_err(|e| format!("failed to decode block header: {e}"))?;
    let val = serde_json::to_value(&header).map_err(|e| format!("failed to serialize to JSON: {e}"))?;
    return envelope(val, vec![]);
  }

  let block = Block::decode(&mut &bytes[..]).map_err(|e| format!("failed to decode block: {e}"))?;
  let mut val = serde_json::to_value(&block).map_err(|e| format!("failed to serialize to JSON: {e}"))?;
  let warnings = enrich_block(&block, &mut val);

  envelope(val, warnings)
}

/// Parses a hex-encoded raw transaction and returns a JSON string.
#[wasm_bindgen]
pub fn parse_tx_hex(hex_str: &str) -> Result<String, String> {
  let bytes = decode_to_vec(hex_str).map_err(|e| format!("invalid hex: {e}"))?;

  if bytes.is_empty() {
    return Err("no data provided".to_string());
  }

  let tx = Transaction::decode(&mut &bytes[..]).map_err(|e| format!("failed to decode transaction: {e}"))?;
  let mut val = serde_json::to_value(&tx).map_err(|e| format!("failed to serialize to JSON: {e}"))?;
  let warnings = match enrich_tx(&tx, &mut val) {
    Some(msg) => vec![msg],
    None => vec![],
  };

  envelope(val, warnings)
}
