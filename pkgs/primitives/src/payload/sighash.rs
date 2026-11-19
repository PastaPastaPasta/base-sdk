//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The messages that special-transaction payload signatures cover.
//!
//! Each payload's `sig_hash_bytes` gives the bytes Core hashes with SHA256d
//! into the hash the payload's signature signs (or, for quorum signatures,
//! into the message hash of the quorum's sign hash). Most are the payload's
//! `SER_GETHASH` serialization, which leaves the signature out.

use crate::prelude::*;
use crate::{QuorumHash, Transaction};

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_params::LlmqType;
use dash_pkc::bls::BLS_SIG_LEN;
use dash_types::codec::{BaseCodec, EncodeBuf};
use dash_types::Numeric;

/// SHA256d, Core's `Hash` over a serialization.
pub(crate) fn hash256(bytes: &[u8]) -> Hash256 {
  Hash256::from_lendian(sha256d::Hash::hash(bytes).to_byte_array())
}

/// Serializes `tx` with its extra payload replaced by `payload` with a
/// default signature, as Core serializes the copy it makes with
/// `SetTxPayload` to compute a quorum-signed payload's message hash.
///
/// The signature must be the last field of `payload`; Core's default
/// signature is invalid and serializes as zeros.
pub(crate) fn tx_bytes_unsigned(tx: &Transaction, payload: &impl BaseCodec) -> Vec<u8> {
  let mut extra_payload = Vec::new();
  payload.encode(&mut extra_payload);
  let len = extra_payload.len();
  extra_payload[len - BLS_SIG_LEN..].fill(0);
  let copy = Transaction::new(
    tx.version(),
    tx.tx_type(),
    tx.inputs().clone(),
    tx.outputs().clone(),
    tx.lock_time(),
    extra_payload,
  );
  let mut buf = Vec::new();
  copy.encode(&mut buf);
  buf
}

/// A quorum signing request id, `SerializeHash(std::make_pair(prefix, n))`.
pub(crate) fn request_id(prefix: &str, n: &impl BaseCodec) -> Hash256 {
  let mut buf = Vec::new();
  String::from(prefix).encode(&mut buf);
  n.encode(&mut buf);
  hash256(&buf)
}

/// Core's `llmq::BuildSignHash`: the hash a quorum of `llmq_type` signs
/// for request `id` over the message hash `msg_hash`. MnHF signals and
/// asset unlocks carry such signatures.
pub fn llmq_sign_hash(llmq_type: LlmqType, quorum_hash: &QuorumHash, id: &Hash256, msg_hash: &Hash256) -> Hash256 {
  let mut buf = Vec::new();
  llmq_type.encode(&mut buf);
  quorum_hash.encode(&mut buf);
  id.encode(&mut buf);
  msg_hash.encode(&mut buf);
  hash256(&buf)
}

/// Writes the fields of `tx` that Core's shared-masternode digests take
/// directly: the version, the type and the lock time.
pub(crate) fn write_tx_header(tx: &Transaction, buf: &mut impl EncodeBuf) {
  tx.version().encode(buf);
  tx.tx_type().to_base().encode(buf);
  tx.lock_time().encode(buf);
}
