//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signatures of the reference implementation over the payload sign hashes.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
use dash_params::Network;
use dash_pkc::bls::{BlsPkBytes, BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSigBytes, BlsSignature};
use dash_primitives::{ProTxVersion, SpecialPayload, Transaction};
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

/// A BLS scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ::serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Scheme {
  Legacy,
  Basic,
}

impl Scheme {
  /// The scheme a payload of `version` writes its operator signature under.
  fn of(version: ProTxVersion) -> Self {
    if version == ProTxVersion::LegacyBls {
      Self::Legacy
    } else {
      Self::Basic
    }
  }
}

/// The keys the signatures of an entry verify under.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, ::serde::Deserialize)]
#[serde(default)]
struct Signer {
  /// Key ids that own the collateral, the masternode or its shares, in
  /// share order.
  key_ids: Vec<String>,
  /// Operator BLS key of the masternode.
  operator: Option<String>,
  /// Scheme the operator key is written under.
  key_scheme: Option<Scheme>,
  /// Scheme the operator signed under.
  sig_scheme: Option<Scheme>,
}

impl Signer {
  fn key_ids(&self) -> Vec<PubKeyHash> {
    self
      .key_ids
      .iter()
      .map(|id| PubKeyHash::from_lendian(arr_from_hex(id)))
      .collect()
  }

  /// The only key id.
  fn key_id(&self) -> PubKeyHash {
    let [key] = self.key_ids()[..] else {
      panic!("{} key ids", self.key_ids.len());
    };
    key
  }

  /// Whether the operator's `sig`, given with the scheme it is written
  /// under, verifies over `digest` under the operator key in the scheme the
  /// operator signed under.
  fn operator_signed(&self, sig: &(BlsSigBytes, Scheme), digest: &[u8]) -> bool {
    let key = BlsPkBytes::from_bytes(arr_from_hex(self.operator.as_deref().unwrap()));
    let key = (key, self.key_scheme.unwrap());
    match self.sig_scheme.unwrap() {
      Scheme::Legacy => bls_verifies::<BlsScChia>(&key, sig, digest),
      Scheme::Basic => bls_verifies::<BlsScIetf>(&key, sig, digest),
    }
  }
}

fn corpus() -> BTreeMap<String, Entry> {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "sighash").value("sighash")
}

// TODO(pasta): replace these with testnet rows once there are some
/// Regtest transactions for payloads with no testnet transaction through
/// height 1591381, from functional tests of the reference implementation at
/// v24.0.0-rc.3, with the keys their signers held at the block before.
fn regtest() -> BTreeMap<String, Entry> {
  let owners = |ids: &[&str]| Signer {
    key_ids: ids.iter().map(ToString::to_string).collect(),
    ..Signer::default()
  };
  [
    // A version 3 registrar update.
    ("11394a49704f57a63ba119742074ce43e4fcb13d97eece242de7be94c263aad5", "feature_protx_version block 384", "03000300010bb3bcc0293303a7c33471fa9081b0f9ad87a5bfb1769f7059b1cfca08ef3ba3010000006a473044022055815478b33579ae4573755ee425f49bd09f9e9cfb07f17821810dc950597863022063e3a1b3082fd81ac040ce40058f6d56e0947f6113cab321c0bb292a4e9a1416012103090f1455503bddf1bdb7b6ae6dffafb7a66248551bfb592900ed7e8efd21d486feffffff014fdff505000000001976a9146ce2ac804158e51299b5bc017cedd10064231f8f88ac00000000e703000b641b8f63f4b8619cac88d532533ca7a64461a32e8669d90fdd4aaf0e92704f000091bea3a77f336a4c5df0c5fdbb1c5f6d33c04e2ed251d99359f0d5a80e46c4f7aa9077755d2cdae9ab5248f0c70d8f14a6ea9fa81746664db9fb2dd4996ee31622e61b15011976a9148a20a1b135db76136993a65494336ce82df8b6a988ac1027bef1be7238c10c0dfc48647a05acfe779b1323ffdd7c57641405f4a806c30c124120c13fec728c8b52c481a2d0b7e8b9556933206c7429818a4c072ced05ea1aadce365c9da7b6006a9c9278bf1da1416eb380eec900ff6e61775a162047d8193af9", owners(&["3adab6dfd8ba2e8f0023248f5b46278da6f4faef"])),
  ]
  .into_iter()
  .map(|(txid, source, raw, signer)| {
    let entry = Entry {
      source: format!("regtest {source}"),
      network: "regtest".to_string(),
      raw: raw.to_string(),
      signer,
    };
    (txid.to_string(), entry)
  })
  .collect()
}

/// The key `bytes` hold, read under the legacy or the basic scheme and
/// carried over to scheme `V`.
fn bls_key<V: BlsScheme>(bytes: &BlsPkBytes, scheme: Scheme) -> Option<BlsPublicKey<V>> {
  match scheme {
    Scheme::Legacy => bytes.to::<BlsScChia>().ok()?.to_scheme().ok(),
    Scheme::Basic => bytes.to::<BlsScIetf>().ok()?.to_scheme().ok(),
  }
}

/// The signature `bytes` hold, read as [`bls_key`] reads a key.
fn bls_sig<V: BlsScheme>(bytes: &BlsSigBytes, scheme: Scheme) -> Option<BlsSignature<V>> {
  match scheme {
    Scheme::Legacy => bytes.to::<BlsScChia>().ok()?.to_scheme().ok(),
    Scheme::Basic => bytes.to::<BlsScIetf>().ok()?.to_scheme().ok(),
  }
}

/// Whether `sig` verifies over `digest` under `key` with scheme `V`.
fn bls_verifies<V: BlsScheme>(key: &(BlsPkBytes, Scheme), sig: &(BlsSigBytes, Scheme), digest: &[u8]) -> bool {
  let digest = <&[u8; 32]>::try_from(digest).unwrap();
  match (bls_key::<V>(&key.0, key.1), bls_sig::<V>(&sig.0, sig.1)) {
    (Some(key), Some(sig)) => key.verify_digest(digest, &sig).is_ok(),
    _ => false,
  }
}

/// Checks the signatures of one entry over its payload's sign hash, and
/// returns its type and payload version, or `None` for a payload this test
/// does not cover.
fn check_signed(txid: &str, entry: &Entry) -> Option<(u16, u16)> {
  let tx = Transaction::decode(&mut vec_from_hex(&entry.raw).as_slice()).unwrap();
  let payload = tx.decode_payload().unwrap().unwrap();
  let signer = &entry.signer;
  let network = match entry.network.as_str() {
    "mainnet" => Network::Main,
    "testnet" => Network::Testnet3,
    "regtest" => Network::Regtest,
    other => panic!("{txid}: unknown network {other}"),
  };

  let (version, signed) = match &payload {
    SpecialPayload::ProviderRegister(p) => (
      p.version().to_base(),
      p.verify(&signer.key_id(), network.addr()).is_none(),
    ),
    SpecialPayload::ProviderUpdateService(p) => {
      let sig = (*p.sig().as_bytes(), Scheme::of(p.version()));
      (p.version().to_base(), signer.operator_signed(&sig, &p.payload(&())))
    }
    SpecialPayload::ProviderUpdateRegistrar(p) => (p.version().to_base(), p.verify(&signer.key_id(), &()).is_none()),
    SpecialPayload::ProviderUpdateRevoke(p) => {
      let sig = (*p.sig().as_bytes(), Scheme::of(p.version()));
      (p.version().to_base(), signer.operator_signed(&sig, &p.payload(&())))
    }
    _ => return None,
  };
  assert!(signed, "{txid} ({}): the signature does not verify", entry.source);
  Some((tx.tx_type().to_base(), version))
}

/// The signatures verify over the sign hash of every payload type that has
/// one, at every version.
#[test]
fn signatures_verify_over_sighash() {
  let shapes: BTreeSet<_> = corpus()
    .into_iter()
    .chain(regtest())
    .filter_map(|(txid, entry)| check_signed(&txid, &entry))
    .collect();
  let mut expected = BTreeSet::<(u16, u16)>::new();
  expected.extend((1..=4).flat_map(|t| (1..=3).map(move |v| (t, v))));
  assert_eq!(shapes, expected);
}
