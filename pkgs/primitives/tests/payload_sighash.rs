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

/// A BLS scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ::serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Scheme {
  Legacy,
  Basic,
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

  /// The key id of share `index`.
  fn share_key(&self, index: u16) -> PubKeyHash {
    self.key_ids()[usize::from(index)]
  }

  /// Whether the operator's `sig`, given with whether it is written under
  /// the legacy scheme, verifies over `digest` under the operator key in the
  /// scheme the operator signed under.
  fn operator_signed(&self, sig: &(BlsSigBytes, bool), digest: &[u8]) -> bool {
    let key = BlsPkBytes::from_bytes(arr_from_hex(self.operator.as_deref().unwrap()));
    let key = (key, self.key_scheme.unwrap() == Scheme::Legacy);
    match self.sig_scheme.unwrap() {
      Scheme::Legacy => bls_verifies::<BlsScChia>(&key, sig, digest),
      Scheme::Basic => bls_verifies::<BlsScIetf>(&key, sig, digest),
    }
  }
}

fn corpus() -> BTreeMap<String, Entry> {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "sighash").value("sighash")
}

// TODO(pasta): replace these with mainnet or testnet rows once these
// payloads are live there
/// Regtest transactions of payloads live on no public network, from
/// functional tests of the reference implementation at v24.0.0-rc.3, with the
/// keys their signers held at the block before.
fn regtest() -> BTreeMap<String, Entry> {
  let owners = |ids: &[&str]| Signer {
    key_ids: ids.iter().map(ToString::to_string).collect(),
    ..Signer::default()
  };
  [
    // A version 3 registrar update.
    ("11394a49704f57a63ba119742074ce43e4fcb13d97eece242de7be94c263aad5", "feature_protx_version block 384", "03000300010bb3bcc0293303a7c33471fa9081b0f9ad87a5bfb1769f7059b1cfca08ef3ba3010000006a473044022055815478b33579ae4573755ee425f49bd09f9e9cfb07f17821810dc950597863022063e3a1b3082fd81ac040ce40058f6d56e0947f6113cab321c0bb292a4e9a1416012103090f1455503bddf1bdb7b6ae6dffafb7a66248551bfb592900ed7e8efd21d486feffffff014fdff505000000001976a9146ce2ac804158e51299b5bc017cedd10064231f8f88ac00000000e703000b641b8f63f4b8619cac88d532533ca7a64461a32e8669d90fdd4aaf0e92704f000091bea3a77f336a4c5df0c5fdbb1c5f6d33c04e2ed251d99359f0d5a80e46c4f7aa9077755d2cdae9ab5248f0c70d8f14a6ea9fa81746664db9fb2dd4996ee31622e61b15011976a9148a20a1b135db76136993a65494336ce82df8b6a988ac1027bef1be7238c10c0dfc48647a05acfe779b1323ffdd7c57641405f4a806c30c124120c13fec728c8b52c481a2d0b7e8b9556933206c7429818a4c072ced05ea1aadce365c9da7b6006a9c9278bf1da1416eb380eec900ff6e61775a162047d8193af9", owners(&["3adab6dfd8ba2e8f0023248f5b46278da6f4faef"])),
    // A share update.
    ("7c71f29451b4a09756b8664eb59592514bbd43395b43b4fe6878a762ada093c7", "feature_masternode_shares block 276", "03000b0001acebb7cbf7176bdf33fae143c11f82cb97659477e73dff20ba414ea2ec011970000000006a47304402202a35e0e5a5e2239346b7a2f211f3bc2063048c4a644a650821baa181c4bb79a3022001933d1764fcf337d44f38322a2866e541f6638dcf4e57d3e6cda8895f26f3e2012102fd12b3ea269e7ffa97c6d30ac236ea269819dad98216c4ad33b3f9aabfa025cdfeffffff0196dff505000000001976a91491e4b0a9c865845fc4ab401e475059af9cd0a5db88ac00000000a00100e49e985715484b5d76b8d96b710282712a73e744683f4987bd8e2bd10743574500001976a9143e7caaa99621cd878ed371726f4e459104e23dbc88aca3b3f94d0cd5851f4e7503297ca5212488f14ab89181a1a90fd59fed9df0afb541203a324a03e47ed3cda35b2e605dacfe87fcc7121e0657ff29785dd053addf72d04e38d407bb3869f9fe1dd8cd3e12b39cce7d12f69cb2e0c3c937fb2662349bd4", owners(&["5a71973a879b5cd702e4ebad0eb96244e84e0627", "c374c77db723510a2717e27c91033e1c9431342a"])),
    // A shared registrar update.
    ("0175bb1b4df1560403ec27341eb80543c1db6a2682eab1f0e3fb576680d460c7", "feature_masternode_shares block 279", "03000c0001719a49038ccfc9a23fe2f9e66b89f8b5b0d644d5d91dd6810c6d2c3112560b9e010000006a4730440220269c10d1fd32d4fa7994c7fbb4cc6886ee1e021442584a03c0cb6db65e7c6d9c02206ea2a34de3a581b7e643ae1800b920065c1b5cbe1417bb01af0a8bbdd8c1f9ed012102fd12b3ea269e7ffa97c6d30ac236ea269819dad98216c4ad33b3f9aabfa025cdfeffffff012bdff505000000001976a91491e4b0a9c865845fc4ab401e475059af9cd0a5db88ac00000000fd09010100e49e985715484b5d76b8d96b710282712a73e744683f4987bd8e2bd10743574583d7356ed2c7bf71cdb1175e8760c2b4f1290a09757a392082185389b1ad1a875c80b62993979a9180ccf8eb4377d4e660cec402e24d9e54669a074034532f734531e201af7cfe60eee6fa746a4c0d3c130ce763f697539609afbb133421161aad6c5337021f6b11d8e5a47d662b47de9822a6fbfead736d95f30ba6fc2a7bb890c365fcc34d057dee4d1fb662cee0432f857c7cdf8a8a4b9979087b8019c250025d3c54238f20a5fa6d84ca799f76d6dcbaa80432224da803683f09bba0f3fce0d5f6b2bb2b56156c9e40f4695f96371a7252edac23f60991eb03b63c89dbc9af6fd053d84d83", owners(&["5a71973a879b5cd702e4ebad0eb96244e84e0627", "c374c77db723510a2717e27c91033e1c9431342a"])),
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

/// Whether `sigs` holds one signature per key in `keys`, each verifying under
/// its key.
fn consents_signed<T: Signable<Key = PubKeyHash>>(sigs: &[T], keys: &[PubKeyHash], ctx: &T::Context) -> bool {
  sigs.len() == keys.len() && sigs.iter().zip(keys).all(|(sig, key)| sig.verify(key, ctx).is_none())
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
    SpecialPayload::ProviderRegister(p) if !p.shares().is_empty() => {
      let owners: Vec<_> = p.shares().iter().map(CollateralShare::key_id_owner).collect();
      (
        p.version().to_base(),
        consents_signed(p.join_sigs(), &owners, &(tx.clone(), p.clone())),
      )
    }
    SpecialPayload::ProviderRegister(p) => (
      p.version().to_base(),
      p.verify(&signer.key_id(), network.addr()).is_none(),
    ),
    SpecialPayload::ProviderUpdateService(p) => {
      let sig = (*p.sig().as_bytes(), p.version() == ProTxVersion::LegacyBls);
      (p.version().to_base(), signer.operator_signed(&sig, &p.payload(&())))
    }
    SpecialPayload::ProviderUpdateRegistrar(p) => (p.version().to_base(), p.verify(&signer.key_id(), &()).is_none()),
    SpecialPayload::ProviderUpdateRevoke(p) => {
      let sig = (*p.sig().as_bytes(), p.version() == ProTxVersion::LegacyBls);
      (p.version().to_base(), signer.operator_signed(&sig, &p.payload(&())))
    }
    SpecialPayload::ProviderDissolve(p) => {
      let keys = match p.sigs().len() {
        1 => vec![signer.share_key(p.actor_index())],
        _ => signer.key_ids(),
      };
      (p.version(), consents_signed(p.sigs(), &keys, &(tx.clone(), p.clone())))
    }
    SpecialPayload::ProviderUpdateShare(p) => {
      (p.version(), p.verify(&signer.share_key(p.share_index()), &()).is_none())
    }
    SpecialPayload::ProviderUpdateSharedRegistrar(p) => (p.version(), consents_signed(p.sigs(), &signer.key_ids(), p)),
    _ => return None,
  };
  assert!(signed, "{txid} ({}): the signature does not verify", entry.source);
  Some((tx.tx_type().to_base(), version))
}

/// The signatures verify over the sign hash of every signed provider
/// payload type, at every version.
#[test]
fn signatures_verify_over_sighash() {
  let shapes: BTreeSet<_> = corpus()
    .into_iter()
    .chain(regtest())
    .filter_map(|(txid, entry)| check_signed(&txid, &entry))
    .collect();
  let protx = (1..=4).flat_map(|t| (1..=3).map(move |v| (t, v)));
  let shared = [(10, 1), (11, 1), (12, 1)];
  assert_eq!(shapes, protx.chain(shared).collect());
}
