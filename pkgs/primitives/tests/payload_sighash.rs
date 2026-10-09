//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signatures Dash Core made, checked over the payloads' sign hashes.
//!
//! `sighash.json5` holds special transactions from Core-built chains with
//! the keys their signers held. A sign hash is right when Core's signature
//! verifies over it: a BLS signature under the signer's key, an ECDSA one by
//! recovering a key whose id the signer owns, as Core's `CHashSigner` does.
//! The corpus also holds asset unlocks with Core's txid and instance hash.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use bitcoin_hashes::sha256d;
use dash_dev::{Corpus, Value};
use dash_num::Hash256;
use dash_pkc::bls::{
  BlsCtx, BlsEager, BlsEagerPk, BlsEagerSig, BlsPkBytes, BlsPublicKey, BlsScChia, BlsScIetf, BlsSchemeKind,
  BlsSchemeSource, BlsSigBytes, BlsSigId, BlsSignature,
};
use dash_pkc::ecdsa::{EcdsaPkBytes, EcdsaPublicKey, EcdsaRecSigBytes, EcdsaRecSignature};
use dash_primitives::{llmq_sign_hash, CompactSig, LlmqType, PayloadDecode, QuorumHash, SpecialPayload, Transaction};
use dash_script::AddrParams;
use dash_types::codec::BaseCodec;
use dash_types::{Hashable, Numeric};
use hex_conservative::DisplayHex;

use std::collections::BTreeSet;

/// Core's address encoding: `CMainParams`, and `CRegTestParams` (which
/// testnet and devnets share).
const MAINNET: AddrParams = AddrParams {
  pubkey_addr: 76,
  script_addr: 16,
  secret_key: 204,
  ext_pubkey: [0x04, 0x88, 0xB2, 0x1E],
  ext_secret: [0x04, 0x88, 0xAD, 0xE4],
  bip44_idx: 5,
};
const REGTEST: AddrParams = AddrParams {
  pubkey_addr: 140,
  script_addr: 19,
  secret_key: 239,
  ext_pubkey: [0x04, 0x35, 0x87, 0xCF],
  ext_secret: [0x04, 0x35, 0x83, 0x94],
  bip44_idx: 1,
};

fn corpus(section: &str) -> Value {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "sighash").into_value()[section].take()
}

fn decode_tx(raw: &str) -> Transaction {
  let bytes = dash_dev::vec_from_hex(raw);
  Transaction::decode(&mut &bytes[..]).unwrap()
}

/// SHA256d, as Core's `SerializeHash` and `CHashWriter::GetHash`.
fn hash(bytes: &[u8]) -> Hash256 {
  Hash256::from_lendian(sha256d::Hash::hash(bytes).to_byte_array())
}

fn unhex<const N: usize>(hex: &str) -> [u8; N] {
  dash_dev::vec_from_hex(hex).try_into().unwrap()
}

/// `CBLSSignature::VerifyInsecure` with Core's flag selecting `scheme`.
fn bls_verifies(scheme: BlsSchemeKind, pk: &BlsEagerPk, sig: &BlsEagerSig, hash: &Hash256) -> bool {
  let msg = hash.to_lendian();
  let (pk, sig) = (pk.to_bytes(scheme), sig.to_bytes(scheme));
  match scheme {
    BlsSchemeKind::Legacy => {
      let pk = BlsPublicKey::<BlsScChia>::try_from(BlsPkBytes::from(pk));
      let sig = BlsSignature::<BlsScChia>::try_from(BlsSigBytes::from(sig));
      matches!((pk, sig), (Ok(pk), Ok(sig)) if pk.verify(&msg, &sig).is_ok())
    }
    BlsSchemeKind::Basic => {
      let pk = BlsPublicKey::<BlsScIetf>::try_from(BlsPkBytes::from(pk));
      let sig = BlsSignature::<BlsScIetf>::try_from(BlsSigBytes::from(sig));
      matches!((pk, sig), (Ok(pk), Ok(sig)) if pk.verify_with(&msg, &sig, BlsSigId::Basic).is_ok())
    }
  }
}

/// Verifies under either flag: the corpus does not record which one was in
/// force where the signature does not depend on it.
fn bls_verifies_any(pk: &BlsEagerPk, sig: &BlsEagerSig, hash: &Hash256) -> bool {
  [BlsSchemeKind::Legacy, BlsSchemeKind::Basic]
    .into_iter()
    .any(|scheme| bls_verifies(scheme, pk, sig, hash))
}

/// A key as Core printed it, under `scheme`.
fn bls_pk(hex: &str, scheme: BlsSchemeKind) -> BlsEagerPk {
  BlsEager::decode(&unhex(hex), BlsSchemeSource::Version(scheme)).unwrap()
}

/// The key id of the key `CPubKey::RecoverCompact` recovers from `sig`.
fn recovered_key_id(sig: &[u8], hash: &Hash256) -> Option<String> {
  let sig = EcdsaRecSigBytes::from_raw(sig.try_into().ok()?)?;
  let sig = EcdsaRecSignature::try_from(sig).ok()?;
  let pk = EcdsaPublicKey::recover(&hash.to_lendian(), &sig).ok()?;
  Some(EcdsaPkBytes::from(pk).hash().as_bytes().to_lower_hex_string())
}

fn compact(sig: &CompactSig) -> &[u8] {
  sig.as_bytes()
}

/// Whether `sig` verifies under the signer's quorum over
/// `SignHash(llmq_type, quorum_hash, id, msg_hash)`.
fn quorum_signed(signer: &Value, quorum_hash: &QuorumHash, id: &Hash256, msg: &Hash256, sig: &BlsEagerSig) -> bool {
  let llmq_type = LlmqType::from_base(u8::try_from(signer["llmq_type"].as_u64().unwrap()).unwrap());
  let pk = bls_pk(signer["quorum"].as_str().unwrap(), BlsSchemeKind::Basic);
  bls_verifies_any(&pk, sig, &llmq_sign_hash(llmq_type, quorum_hash, id, msg))
}

/// Whether every one of `sigs` recovers to a key id in `owners`.
fn owners_signed<'a>(owners: &BTreeSet<String>, sigs: impl IntoIterator<Item = &'a [u8]>, hash: &Hash256) -> bool {
  let mut sigs = sigs.into_iter().peekable();
  sigs.peek().is_some() && sigs.all(|sig| recovered_key_id(sig, hash).is_some_and(|id| owners.contains(&id)))
}

/// Checks the signatures of one Core-signed transaction over its payload's
/// sign hash. Returns the type and the version the hash depends on: the
/// commitment's for a quorum commitment, the payload's otherwise.
fn check_signed(txid: &str, entry: &Value) -> (u16, u16) {
  let tx = decode_tx(entry["raw"].as_str().unwrap());
  let PayloadDecode { payload, .. } = tx.decode_payload().unwrap().unwrap();
  let signer = &entry["signer"];
  let addr = match entry["network"].as_str().unwrap() {
    "mainnet" => &MAINNET,
    _ => &REGTEST,
  };
  let key_ids: BTreeSet<String> = signer["key_ids"]
    .as_array()
    .map(|ids| ids.iter().map(|id| id.as_str().unwrap().to_owned()).collect())
    .unwrap_or_default();
  let operator = || {
    let legacy = signer["operator_legacy"].as_bool().unwrap();
    let scheme = if legacy {
      BlsSchemeKind::Legacy
    } else {
      BlsSchemeKind::Basic
    };
    bls_pk(signer["operator"].as_str().unwrap(), scheme)
  };
  let (version, signed) = match &payload {
    SpecialPayload::ProviderRegister(p) if signer["shares"].as_bool() == Some(true) => {
      let owners = p
        .shares
        .iter()
        .map(|s| s.key_id_owner.as_bytes().to_lower_hex_string())
        .collect();
      let hash = hash(&p.shared_consent_bytes(&tx));
      (
        p.version,
        owners_signed(&owners, p.join_sigs.iter().map(compact), &hash),
      )
    }
    SpecialPayload::ProviderRegister(p) => {
      let hash = hash(&p.sign_message_bytes(addr));
      (p.version, owners_signed(&key_ids, [&p.vch_sig[..]], &hash))
    }
    SpecialPayload::ProviderUpdateService(p) => (
      p.version,
      bls_verifies_any(&operator(), &p.sig, &hash(&p.sig_hash_bytes())),
    ),
    SpecialPayload::ProviderUpdateRegistrar(p) => (
      p.version,
      owners_signed(&key_ids, [&p.vch_sig[..]], &hash(&p.sig_hash_bytes())),
    ),
    SpecialPayload::ProviderUpdateRevoke(p) => (
      p.version,
      bls_verifies_any(&operator(), &p.sig, &hash(&p.sig_hash_bytes())),
    ),
    SpecialPayload::QuorumCommitment(p) => {
      // The key enters the hash under the flag the signature verifies under.
      let c = &p.commitment;
      let signed = [BlsSchemeKind::Legacy, BlsSchemeKind::Basic].into_iter().any(|scheme| {
        bls_verifies(
          scheme,
          &c.quorum_public_key,
          &c.quorum_sig,
          &hash(&c.sig_hash_bytes(scheme)),
        )
      });
      (c.version, signed)
    }
    SpecialPayload::MnhfSignal(p) => {
      let msg = hash(&p.sig_hash_bytes(&tx));
      (
        p.version.into(),
        quorum_signed(signer, &p.quorum_hash, &p.request_id(), &msg, &p.sig),
      )
    }
    SpecialPayload::AssetUnlock(p) => {
      let msg = hash(&p.sig_hash_bytes(&tx));
      let signed = [BlsCtx::LEGACY, BlsCtx::BASIC]
        .into_iter()
        .any(|ctx| quorum_signed(signer, &p.quorum_hash, &p.request_id(), &msg, &p.quorum_sig.get(ctx)));
      (p.version.into(), signed)
    }
    SpecialPayload::ProviderDissolve(p) => {
      let hash = hash(&p.sig_hash_bytes(&tx, u8::try_from(p.sigs.len()).unwrap()));
      (p.version, owners_signed(&key_ids, p.sigs.iter().map(compact), &hash))
    }
    SpecialPayload::ProviderUpdateShare(p) => (
      p.version,
      owners_signed(&key_ids, [&p.vch_sig[..]], &hash(&p.sig_hash_bytes())),
    ),
    SpecialPayload::ProviderUpdateSharedRegistrar(p) => (
      p.version,
      owners_signed(&key_ids, p.sigs.iter().map(compact), &hash(&p.sig_hash_bytes())),
    ),
    other => panic!("{txid}: unexpected payload {other:?}"),
  };
  assert!(signed, "{txid} ({}): Core's signature does not verify", entry["source"]);
  (tx.tx_type.to_base(), version)
}

/// Core's signatures verify over the sign hash of every signed payload
/// type, at every version Core v24 reads.
#[test]
fn core_signatures_verify_over_sighash() {
  let mut shapes = BTreeSet::new();
  for (txid, entry) in corpus("sighash").as_object().unwrap() {
    shapes.insert(check_signed(txid, entry));
  }
  let protx = (1..=4).flat_map(|t| (1..=3).map(move |v| (t, v)));
  let commitments = (1..=4).map(|v| (6, v));
  let others = [(7, 1), (9, 1), (9, 2), (10, 1), (11, 1), (12, 1)];
  assert_eq!(shapes, protx.chain(commitments).chain(others).collect());
}

/// Asset unlocks: the txid is Core's, and the instance hash is the one Core
/// printed for a version-2 unlock, the txid otherwise.
#[test]
fn asset_unlock_txids_match_core() {
  let entries = corpus("stable_txid");
  let entries = entries.as_object().unwrap();
  let mut stable = 0;
  for (txid, entry) in entries {
    let tx = decode_tx(entry["raw"].as_str().unwrap());
    let instance = entry
      .get("instance_hash")
      .map_or(txid.as_str(), |h| h.as_str().unwrap());
    assert_eq!(tx.hash().to_string(), *txid, "{txid}: txid");
    assert_eq!(tx.instance_hash().to_string(), instance, "{txid}: instance hash");
    assert_eq!(
      tx.has_stable_txid(),
      entry.get("instance_hash").is_some(),
      "{txid}: stable"
    );
    stable += usize::from(tx.has_stable_txid());
  }
  assert!(stable >= 2 && entries.len() > stable);
}
