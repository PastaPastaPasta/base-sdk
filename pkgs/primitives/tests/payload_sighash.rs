//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signatures of the reference implementation over the payload sign hashes.
//!
//! `sighash.json5` holds special transactions the reference implementation
//! signed, with the keys their signers held. A sign hash is right when the
//! signature verifies over it under the signer's key.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
use dash_params::{LlmqType, Network};
use dash_pkc::bls::{BlsPkBytes, BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSigBytes, BlsSignature};
use dash_primitives::{CollateralShare, ProTxVersion, SpecialPayload, Transaction};
use dash_script::PubKeyHash;
use dash_types::codec::BaseCodec;
use dash_types::{Numeric, Signable};

use std::collections::{BTreeMap, BTreeSet};

/// A special transaction and the keys its signers held.
#[derive(Clone, Debug, Eq, Hash, PartialEq, ::serde::Deserialize)]
struct Entry {
  /// Chain and block the transaction was read from.
  source: String,
  /// Network of the chain.
  network: String,
  /// The serialized transaction.
  raw: String,
  /// The keys the signatures verify under.
  signer: Signer,
}

/// The keys the signatures of an entry verify under.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, ::serde::Deserialize)]
#[serde(default)]
struct Signer {
  /// Key ids that own the collateral, the masternode or its shares.
  key_ids: Vec<String>,
  /// Operator BLS key of the masternode.
  operator: Option<String>,
  /// Whether the operator key is written under the legacy scheme.
  operator_legacy: Option<bool>,
  /// Whether the share owners named in the payload signed it.
  shares: bool,
  /// Whether the quorum named in the payload signed it.
  commitment: bool,
  /// LLMQ type of the signing quorum.
  llmq_type: Option<u8>,
  /// Public key of the signing quorum.
  quorum: Option<String>,
}

impl Signer {
  fn key_ids(&self) -> BTreeSet<PubKeyHash> {
    self
      .key_ids
      .iter()
      .map(|id| PubKeyHash::from_lendian(arr_from_hex(id)))
      .collect()
  }

  /// The key of the quorum of `llmq_type`.
  fn quorum(&self, llmq_type: LlmqType) -> BlsPkBytes {
    assert_eq!(self.llmq_type, Some(llmq_type.to_base()));
    BlsPkBytes::from_bytes(arr_from_hex(self.quorum.as_deref().unwrap()))
  }

  /// The operator key, and whether it is written under the legacy scheme.
  fn operator(&self) -> (BlsPkBytes, bool) {
    let key = BlsPkBytes::from_bytes(arr_from_hex(self.operator.as_deref().unwrap()));
    (key, self.operator_legacy.unwrap())
  }
}

fn corpus() -> BTreeMap<String, Entry> {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "sighash").value("sighash")
}

/// The key `bytes` hold, read under the legacy or the basic scheme and
/// carried over to scheme `V`.
fn bls_key<V: BlsScheme>(bytes: &BlsPkBytes, legacy: bool) -> Option<BlsPublicKey<V>> {
  if legacy {
    bytes.to::<BlsScChia>().ok()?.to_scheme().ok()
  } else {
    bytes.to::<BlsScIetf>().ok()?.to_scheme().ok()
  }
}

/// The signature `bytes` hold, read as [`bls_key`] reads a key.
fn bls_sig<V: BlsScheme>(bytes: &BlsSigBytes, legacy: bool) -> Option<BlsSignature<V>> {
  if legacy {
    bytes.to::<BlsScChia>().ok()?.to_scheme().ok()
  } else {
    bytes.to::<BlsScIetf>().ok()?.to_scheme().ok()
  }
}

/// Whether `sig` verifies over `digest` under `key` with scheme `V`.
fn bls_verifies<V: BlsScheme>(key: &(BlsPkBytes, bool), sig: &(BlsSigBytes, bool), digest: &[u8]) -> bool {
  let digest = <&[u8; 32]>::try_from(digest).unwrap();
  match (bls_key::<V>(&key.0, key.1), bls_sig::<V>(&sig.0, sig.1)) {
    (Some(key), Some(sig)) => key.verify_digest(digest, &sig).is_ok(),
    _ => false,
  }
}

/// Whether `sig` verifies over `digest` under `key`, each given with whether
/// it is written under the legacy scheme.
fn bls_signed(key: &(BlsPkBytes, bool), sig: &(BlsSigBytes, bool), digest: &[u8], either: bool) -> bool {
  let legacy = || bls_verifies::<BlsScChia>(key, sig, digest);
  let basic = || bls_verifies::<BlsScIetf>(key, sig, digest);
  if either {
    legacy() || basic()
  } else if sig.1 {
    legacy()
  } else {
    basic()
  }
}

/// Whether an operator's `sig` verifies over `digest` under `key`. A
/// signature in a legacy payload may have been made under either scheme,
/// which the corpus does not record.
fn operator_signed(key: &(BlsPkBytes, bool), sig: &(BlsSigBytes, bool), digest: &[u8]) -> bool {
  bls_signed(key, sig, digest, sig.1)
}

/// Whether the payload's signature verifies under one of `keys`.
fn owner_signed<T: Signable<Key = PubKeyHash>>(payload: &T, keys: &BTreeSet<PubKeyHash>, ctx: &T::Context) -> bool {
  keys.iter().any(|key| payload.verify(key, ctx).is_none())
}

/// Whether `sigs` is not empty and each verifies under one of `keys`.
fn consents_signed<T: Signable<Key = PubKeyHash>>(sigs: &[T], keys: &BTreeSet<PubKeyHash>, ctx: &T::Context) -> bool {
  !sigs.is_empty() && sigs.iter().all(|sig| owner_signed(sig, keys, ctx))
}

/// Checks the signatures of one entry over its payload's sign hash.
///
/// Returns the transaction type and the payload version, or `None` for a
/// payload this test does not cover.
fn check_signed(txid: &str, entry: &Entry) -> Option<(u16, u16)> {
  let tx = Transaction::decode(&mut vec_from_hex(&entry.raw).as_slice()).unwrap();
  let payload = tx.decode_payload().unwrap().unwrap();
  let signer = &entry.signer;
  let network = match entry.network.as_str() {
    "mainnet" => Network::Main,
    "regtest" => Network::Regtest,
    other => panic!("{txid}: unknown network {other}"),
  };

  let (version, signed) = match &payload {
    SpecialPayload::ProviderRegister(p) if signer.shares => {
      let owners = p.shares().iter().map(CollateralShare::key_id_owner).collect();
      (
        p.version().to_base(),
        consents_signed(p.join_sigs(), &owners, &(tx.clone(), p.clone())),
      )
    }
    SpecialPayload::ProviderRegister(p) => (
      p.version().to_base(),
      owner_signed(p, &signer.key_ids(), network.addr()),
    ),
    SpecialPayload::ProviderUpdateService(p) => {
      let sig = (*p.sig().as_bytes(), p.version() == ProTxVersion::LegacyBls);
      let signed = operator_signed(&signer.operator(), &sig, &p.payload(&()));
      (p.version().to_base(), signed)
    }
    SpecialPayload::ProviderUpdateRegistrar(p) => (p.version().to_base(), owner_signed(p, &signer.key_ids(), &())),
    SpecialPayload::ProviderUpdateRevoke(p) => {
      let sig = (*p.sig().as_bytes(), p.version() == ProTxVersion::LegacyBls);
      let signed = operator_signed(&signer.operator(), &sig, &p.payload(&()));
      (p.version().to_base(), signed)
    }
    SpecialPayload::ProviderDissolve(p) => {
      let signed = consents_signed(p.sigs(), &signer.key_ids(), &(tx.clone(), p.clone()));
      (p.version(), signed)
    }
    SpecialPayload::ProviderUpdateShare(p) => (p.version(), owner_signed(p, &signer.key_ids(), &())),
    SpecialPayload::ProviderUpdateSharedRegistrar(p) => (p.version(), consents_signed(p.sigs(), &signer.key_ids(), p)),
    SpecialPayload::QuorumCommitment(p) if signer.commitment => {
      let c = p.commitment();
      let legacy = c.version() <= 2;
      let signed = bls_signed(
        &(c.quorum_public_key(), legacy),
        &(c.quorum_sig(), legacy),
        &c.sig_hash().to_lendian(),
        false,
      );
      (c.version(), signed)
    }
    SpecialPayload::MnhfSignal(p) => {
      let llmq_type = network.consensus().llmq_type_mnhf;
      let digest = p.sig_hash(&tx, llmq_type).to_lendian();
      let signed = bls_signed(&(signer.quorum(llmq_type), false), &(p.sig(), false), &digest, false);
      (p.version().into(), signed)
    }
    SpecialPayload::AssetUnlock(p) => {
      let llmq_type = network.consensus().llmq_type_platform;
      let digest = p.sig_hash(&tx, llmq_type).to_lendian();
      let signed = bls_signed(
        &(signer.quorum(llmq_type), false),
        &(p.quorum_sig(), false),
        &digest,
        false,
      );
      (p.version().into(), signed)
    }
    _ => return None,
  };
  assert!(signed, "{txid} ({}): the signature does not verify", entry.source);
  Some((tx.tx_type().to_base(), version))
}

/// The signatures verify over the sign hash of every signed payload type,
/// at every version.
#[test]
fn signatures_verify_over_sighash() {
  let shapes: BTreeSet<_> = corpus()
    .iter()
    .filter_map(|(txid, entry)| check_signed(txid, entry))
    .collect();
  let protx = (1..=4).flat_map(|t| (1..=3).map(move |v| (t, v)));
  let commitments = (1..=4).map(|v| (6, v));
  let others = [(7, 1), (9, 1), (9, 2), (10, 1), (11, 1), (12, 1)];
  assert_eq!(shapes, protx.chain(commitments).chain(others).collect());
}
