//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block (header + transactions).

use crate::prelude::*;
use crate::sptx::TxType;
use crate::transaction::{OutPoint, Transaction, TxHash, TxIn, TxInvalid, TxOut};
use crate::{codec_base, codec_type, hash_impl};

use bitcoin_hashes::sha256d;
use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use dash_num::{make_hash, Arith256, CompactTarget, Hash256};
use dash_params::{DevnetGenesisParams, GenesisParams};
use dash_pow::__deps::digest::Digest;
use dash_pow::X11;
use dash_types::codec::{self, BaseCodec};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{ArrayBuf, Checkable, Hashable, Numeric};
use getset::{CopyGetters, Getters, Setters};

use core::fmt;

/// Maximum serialized transaction size (single tx, always 1 MB).
pub const MAX_LEGACY_BLOCK_SIZE: usize = 1_000_000;

/// Post-DIP0001 maximum block size (2 MB).
pub const MAX_DIP0001_BLOCK_SIZE: usize = 2_000_000;

make_hash! {
  /// Hash of a block header.
  BlockHash, 32
}

hash_impl!(BlockHash);

make_hash! {
  /// Merkle tree root hash.
  MerkleRoot, 32
}

hash_impl!(MerkleRoot);

codec_base! {
/// A block header.
#[derive(Clone, Copy, CopyGetters, Debug, Default, Eq, Hash, PartialEq, Setters, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BlockHeader {
  /// Block version.
  #[getset(get_copy = "pub")]
  version: i32,
  /// Hash of the previous block header.
  #[getset(get_copy = "pub")]
  prev_hash: BlockHash,
  /// Merkle root of the transaction tree.
  #[getset(get_copy = "pub", set = "pub")]
  merkle_root: MerkleRoot,
  /// Block timestamp (unix epoch seconds).
  #[getset(get_copy = "pub", set = "pub")]
  time: u32,
  /// Compact difficulty target.
  #[getset(get_copy = "pub")]
  bits: u32,
  /// Nonce used for proof-of-work.
  #[getset(get_copy = "pub", set = "pub")]
  nonce: u32,
}
}

impl Hashable for BlockHeader {
  type Hash = BlockHash;

  fn hash(&self) -> BlockHash {
    let mut buf = ArrayBuf::<80>::new();
    self.encode(&mut buf);
    let digest: [u8; 32] = X11::digest(buf.into_array()).into();
    BlockHash::from(digest)
  }
}

impl fmt::Display for BlockHeader {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "BlockHeader {{ version: {}, prev_hash: {}, time: {} }}",
      self.version, self.prev_hash, self.time,
    )
  }
}

/// Block validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum BlockInvalid {
  /// Decoded target is negative, zero, overflows, or the hash exceeds it.
  #[error("bad-proof-of-work")]
  BadProofOfWork,
  /// Computed merkle root does not match the header.
  #[error("bad-merkle-root")]
  BadMerkleRoot,
  /// `bad-txns-duplicate`
  #[error("bad-txns-duplicate")]
  DuplicateTransactions,
  /// `bad-blk-length`
  #[error("bad-blk-length: {size} bytes")]
  BadBlockLength { size: usize },
  /// `bad-cb-missing`
  #[error("bad-cb-missing")]
  MissingCoinbase,
  /// `bad-cb-multiple`
  #[error("bad-cb-multiple: tx {index}")]
  MultipleCoinbases { index: usize },
  /// `bad-blk-sigops`
  #[error("bad-blk-sigops: {count} > {limit}")]
  TooManySigops { count: usize, limit: usize },
  /// A contained transaction failed validation.
  #[error("tx {index}: {error}")]
  Transaction { index: usize, error: TxInvalid },
}

codec_type! {
/// A Dash block: header followed by a vector of transactions.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Block {
  /// Block header (80 bytes).
  #[getset(get_copy = "pub")]
  header: BlockHeader,
  /// Transactions in the block.
  #[getset(get = "pub")]
  transactions: Vec<Transaction>,
}
}

impl Checkable for Block {
  type Error = BlockInvalid;

  fn check(&self) -> Option<Self::Error> {
    let pow_hash = Arith256::from(Hash256::from(self.header.hash()));
    let decoded = CompactTarget::new(self.header.bits).expand();
    if decoded.negative || decoded.value == Arith256::ZERO || decoded.overflow || pow_hash > decoded.value {
      return Some(BlockInvalid::BadProofOfWork);
    }

    let (root, mutated) = self.merkle();
    if root != self.header.merkle_root {
      return Some(BlockInvalid::BadMerkleRoot);
    }
    if mutated {
      return Some(BlockInvalid::DuplicateTransactions);
    }

    let size = codec::encoded_size(self);
    if self.transactions.is_empty() || size > MAX_DIP0001_BLOCK_SIZE {
      return Some(BlockInvalid::BadBlockLength { size });
    }

    if !self.transactions[0].is_coinbase() {
      return Some(BlockInvalid::MissingCoinbase);
    }
    for i in 1..self.transactions.len() {
      if self.transactions[i].is_coinbase() {
        return Some(BlockInvalid::MultipleCoinbases { index: i });
      }
    }

    for (i, tx) in self.transactions.iter().enumerate() {
      if let Some(e) = tx.check() {
        return Some(BlockInvalid::Transaction { index: i, error: e });
      }
    }

    let max_sigops = MAX_DIP0001_BLOCK_SIZE / 50;
    let mut total_sigops: usize = 0;
    for tx in &self.transactions {
      for input in tx.inputs() {
        total_sigops += dash_script::legacy_sigop_count(input.script_sig().as_bytes());
      }
      for output in tx.outputs() {
        total_sigops += dash_script::legacy_sigop_count(output.script_pubkey().as_bytes());
      }
    }
    if total_sigops > max_sigops {
      return Some(BlockInvalid::TooManySigops {
        count: total_sigops,
        limit: max_sigops,
      });
    }

    None
  }
}

/// Computes the merkle root from a list of transaction hashes.
///
/// Returns `(root, mutated)` where `mutated` is `true` when a
/// duplicated last-element pair was detected (CVE-2012-2459).
fn compute_merkle_root(leaves: &[TxHash]) -> (MerkleRoot, bool) {
  if leaves.is_empty() {
    return (MerkleRoot::default(), false);
  }

  let mut hashes: Vec<Hash256> = leaves.iter().map(|h| Hash256::from_lendian(*h.as_bytes())).collect();
  let mut mutated = false;

  while hashes.len() > 1 {
    let len = hashes.len();
    let half = len.div_ceil(2);
    for i in 0..half {
      let left = i * 2;
      let right = if left + 1 < len { left + 1 } else { left };
      if left != right && hashes[left] == hashes[right] {
        mutated = true;
      }
      let mut combined = [0u8; 64];
      combined[..32].copy_from_slice(hashes[left].as_bytes());
      combined[32..].copy_from_slice(hashes[right].as_bytes());
      hashes[i] = Hash256::from_lendian(sha256d::Hash::hash(&combined).to_byte_array());
    }
    hashes.truncate(half);
  }

  (MerkleRoot::from_lendian(*hashes[0].as_bytes()), mutated)
}

impl Block {
  /// Computes the merkle root from the block's transactions.
  ///
  /// Returns `(root, mutated)` where `mutated` is `true` when the
  /// tree contains a duplicated-pair anomaly (CVE-2012-2459).
  pub fn merkle(&self) -> (MerkleRoot, bool) {
    let leaves: Vec<TxHash> = self.transactions.iter().map(|tx| tx.hash()).collect();
    compute_merkle_root(&leaves)
  }
}

impl fmt::Display for Block {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Block {{ txs: {} }}", self.transactions.len())
  }
}

impl From<&GenesisParams> for Block {
  fn from(params: &GenesisParams) -> Self {
    let coinbase = Transaction::new(
      1,
      TxType::Spend,
      vec![TxIn::new(
        OutPoint::new(TxHash::default(), 0xFFFF_FFFF),
        ScriptSigBuf::from_bytes(params.script_sig.to_vec()),
        0xFFFF_FFFF,
      )],
      vec![TxOut::new(
        params.reward,
        ScriptPubKeyBuf::from_bytes(params.script_pubkey.to_vec()),
      )],
      0,
      Vec::new(),
    );

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

impl From<&DevnetGenesisParams> for Block {
  fn from(params: &DevnetGenesisParams) -> Self {
    let coinbase = Transaction::new(
      1,
      TxType::Spend,
      vec![TxIn::new(
        OutPoint::new(TxHash::default(), 0xFFFF_FFFF),
        ScriptSigBuf::from_bytes(params.script_sig()),
        0xFFFF_FFFF,
      )],
      vec![TxOut::new(
        DevnetGenesisParams::REWARD,
        ScriptPubKeyBuf::from_bytes(DevnetGenesisParams::SCRIPT_PUBKEY.to_vec()),
      )],
      0,
      Vec::new(),
    );

    let mut block = Block {
      header: BlockHeader {
        version: DevnetGenesisParams::VERSION,
        prev_hash: BlockHash::from(params.prev_hash),
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

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::panic, clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::sptx::TxType;
  use crate::transaction::{OutPoint, TxIn, TxOut};

  use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
  use bitcoin_units::Amount;
  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use dash_script::Opcode;
  use rstest::rstest;
  use serde::Deserialize;

  #[rstest]
  fn corpus_block() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "blocks");
    let items = corpus.entries::<Block>("blocks", |raw, details, label| {
      check_wire(raw, details, label);
      if let Some(e) = details.check() {
        panic!("{label}: check: {e}");
      }
      let expected = crate::BlockHash::from_hex(label).unwrap();
      assert_eq!(details.header.hash(), expected, "{label}: pow hash");
      let (root, mutated) = details.merkle();
      assert_eq!(root, details.header.merkle_root, "{label}: merkle root");
      assert!(!mutated, "{label}: merkle mutated");
    });
    assert_serde_rt("blocks", &items);
  }

  #[derive(Deserialize)]
  struct TxShape {
    inputs: Vec<u8>,
    lock_time: u32,
    sigops: usize,
    pad: usize,
  }

  impl TxShape {
    fn build(&self) -> Transaction {
      let inputs = self.inputs.iter().enumerate().map(|(i, &seed)| {
        TxIn::new(
          OutPoint::new(TxHash::from_lendian([seed; 32]), if seed == 0 { u32::MAX } else { 0 }),
          ScriptSigBuf::from_bytes(vec![0; if i == 0 { 2 } else { 0 }]),
          u32::MAX,
        )
      });
      let mut script = vec![Opcode::CheckSig.to_base(); self.sigops];
      script.resize(self.sigops + self.pad, 0);
      Transaction::new(
        3,
        TxType::Spend,
        inputs.collect(),
        vec![TxOut::new(
          Amount::from_sat(1).unwrap(),
          ScriptPubKeyBuf::from_bytes(script),
        )],
        self.lock_time,
        vec![],
      )
    }
  }

  #[derive(Deserialize)]
  struct CheckVector {
    txs: Vec<TxShape>,
    merkle_root: MerkleRoot,
    size: usize,
    reason: String,
  }

  fn reason(result: Option<BlockInvalid>) -> String {
    match result {
      None => String::new(),
      Some(BlockInvalid::Transaction { error, .. }) => crate::transaction::tests::reason(Some(error)),
      Some(error) => error.to_string().split(':').next().unwrap_or_default().into(),
    }
  }

  #[rstest]
  fn check_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "block_check");
    for (i, v) in corpus.vectors::<CheckVector>("check").into_iter().enumerate() {
      let mut block = Block {
        header: BlockHeader {
          bits: 0x207f_ffff,
          ..BlockHeader::default()
        },
        transactions: v.txs.iter().map(TxShape::build).collect(),
      };
      block.header.merkle_root = block.merkle().0;
      assert_eq!(block.header.merkle_root, v.merkle_root, "vector {i}");
      while block.check() == Some(BlockInvalid::BadProofOfWork) {
        block.header.nonce += 1;
      }
      let mut buf = Vec::new();
      block.encode(&mut buf);
      assert_eq!(buf.len(), v.size, "vector {i}");
      assert_eq!(reason(block.check()), v.reason, "vector {i}");
    }
  }
}
