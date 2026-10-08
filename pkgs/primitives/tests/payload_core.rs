//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Special payloads judged by Dash Core, run through the payload decoders.
//!
//! `payload_core.json5` holds crafted payloads with Core's verdict at both
//! pins under both BLS flags; `v24.json5` holds Core-built v24 transactions
//! with Core's JSON for their payloads.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_pkc::bls::{BlsCtx, BlsEager, BlsLazyPk, BlsSchemeKind, BlsWire};
use dash_primitives::{
  CoinbaseCommitment, MnType, NIEntry, NITrait, NetInfo, PayloadDecode, SpecialPayload, Transaction,
};
use dash_types::codec::BaseCodec;
use dash_types::{Checkable, Numeric};
use hex_conservative::DisplayHex;

use std::collections::BTreeSet;
use std::sync::LazyLock;

const V23: &str = "v23.1.8";
const V24: &str = "v24.0.0-rc.3";

/// Cases whose decode verdict differs between the pins. BS6a decodes as v24
/// does; each entry names the task that adds the v23.1 behaviour.
const PIN_DEPENDENT: &[(&str, &str)] = &[
  // v24-only transaction types; v23.1 rejects the type before decoding.
  ("proupsharedregtx_pk_legacy", "v24 type"),
  ("proupsharedregtx_pk_basic", "v24 type"),
  ("proupsharedregtx_pk_throw", "v24 type"),
  // O17 SIG-05: v23.1 reads a version-4 CbTx in the version-3 layout.
  ("cbtx_v4_root", "SIG-05"),
  ("cbtx_v4_no_root", "SIG-05"),
  // O17 EVO-14 (BS6c): v24 caps domains at 253 bytes and fails the payload.
  ("netinfo_domain_254", "BS6c"),
  // O17 EVO-14 (BS6c): v23.1 reads one payout script in a v3 ProRegTx.
  ("proregtx_v3_v23_layout_f137aa6f", "BS6c"),
  ("proregtx_v3_v23_layout_a5132479", "BS6c"),
  ("proregtx_v3_v23_layout_ecf23a8a", "BS6c"),
];

/// Core's outcome for one pin and flag: the payload object, or none.
fn core_object<'a>(case: &'a Value, pin: &str, flag: &str) -> Option<&'a Value> {
  let outcome = &case["core"][pin][flag];
  if outcome.is_null() {
    return None;
  }
  assert!(outcome.get("rpc-error").is_none(), "rpc error: {outcome}");
  let obj = outcome.as_object().unwrap();
  assert_eq!(obj.len(), 1, "one payload object: {outcome}");
  obj.values().next()
}

fn decode_tx(raw: &str) -> Transaction {
  let bytes = dash_dev::vec_from_hex(raw);
  Transaction::decode(&mut &bytes[..]).unwrap()
}

/// The payload, when it decodes and Core's `GetTxPayload` would accept it.
fn accepted(tx: &Transaction) -> Option<PayloadDecode> {
  tx.decode_payload()?.ok().filter(PayloadDecode::is_complete)
}

/// `payload_core.json5`, parsed once.
static CRAFTED: LazyLock<Value> =
  LazyLock::new(|| Corpus::open(env!("CARGO_MANIFEST_DIR"), "payload_core").into_value());

/// The transaction of a crafted case.
fn crafted_tx(name: &str) -> Transaction {
  decode_tx(CRAFTED[name]["raw"].as_str().unwrap())
}

/// The payload a crafted case decodes to.
fn crafted(name: &str) -> SpecialPayload {
  accepted(&crafted_tx(name)).unwrap_or_else(|| panic!("{name}")).payload
}

/// Core's address list (`GetNetInfoWithLegacyFields`), `[invalid entry]` for
/// an entry it marked invalid. An Evo node with legacy network info lists its
/// platform ports at the primary address.
fn render_net_info(net: &NetInfo, mn_type: MnType, platform: (Option<u16>, Option<u16>)) -> Value {
  let mut groups: Vec<(String, Value)> = match net {
    NetInfo::Legacy(v1) => v1
      .primary()
      .map(|svc| {
        vec![(
          String::from("core_p2p"),
          Value::from(vec![Value::from(svc.to_string())]),
        )]
      })
      .unwrap_or_default(),
    NetInfo::Extended(v2) => v2
      .entries
      .iter()
      .map(|(purpose, group)| {
        let entries: Vec<Value> = group.iter().map(|e| Value::from(render_entry(e))).collect();
        (purpose.to_string(), Value::from(entries))
      })
      .collect(),
  };
  if let (NetInfo::Legacy(v1), MnType::Evo, Some(primary)) = (net, mn_type, net.primary()) {
    let at = |port: Option<u16>| Value::from(vec![Value::from(format!("{}:{}", primary.addr, port.unwrap_or(0)))]);
    debug_assert!(!v1.is_empty());
    groups.push((String::from("platform_p2p"), at(platform.0)));
    groups.push((String::from("platform_https"), at(platform.1)));
  }
  Value::from_iter(groups)
}

fn render_entry(entry: &NIEntry) -> String {
  match entry {
    NIEntry::Invalid => String::from("[invalid entry]"),
    other => other.to_string(),
  }
}

/// Compares fields of Core's JSON with values rendered from a decode, and
/// tracks which of Core's leaves were compared.
struct Fields<'a> {
  label: String,
  core: &'a Value,
  seen: BTreeSet<String>,
}

impl<'a> Fields<'a> {
  fn new(label: &str, core: &'a Value) -> Self {
    Self {
      label: label.into(),
      core,
      seen: BTreeSet::new(),
    }
  }

  /// Asserts the leaf at `path` (`a.b[1].c`) equals `ours`.
  fn eq(&mut self, path: &str, ours: impl Into<Value>) {
    let mut node = self.core;
    for part in path.split('.') {
      let (key, index) = match part.split_once('[') {
        Some((key, rest)) => (key, Some(rest.trim_end_matches(']').parse::<usize>().unwrap())),
        None => (part, None),
      };
      node = &node[key];
      if let Some(i) = index {
        node = &node[i];
      }
    }
    let ours = ours.into();
    if node.is_f64() || ours.is_f64() {
      assert_eq!(node.as_f64(), ours.as_f64(), "{}: {path}", self.label);
    } else {
      assert_eq!(*node, ours, "{}: {path}", self.label);
    }
    collect_leaves(node, strip_indices(path), &mut self.seen);
  }

  /// Asserts every leaf Core printed was compared or is in `skip`.
  fn finish(self, skip: &[&str]) {
    let mut leaves = BTreeSet::new();
    collect_leaves(self.core, String::new(), &mut leaves);
    for leaf in leaves {
      assert!(
        self.seen.contains(&leaf) || skip.contains(&leaf.as_str()),
        "{}: Core's {leaf} not compared",
        self.label
      );
    }
  }
}

fn strip_indices(path: &str) -> String {
  path
    .split('.')
    .map(|p| p.split_once('[').map_or(p, |(k, _)| k))
    .collect::<Vec<_>>()
    .join(".")
}

fn collect_leaves(node: &Value, prefix: String, out: &mut BTreeSet<String>) {
  match node {
    Value::Object(map) => {
      for (k, v) in map {
        let path = if prefix.is_empty() {
          k.clone()
        } else {
          format!("{prefix}.{k}")
        };
        collect_leaves(v, path, out);
      }
    }
    Value::Array(items) => {
      for item in items {
        collect_leaves(item, prefix.clone(), out);
      }
    }
    _ => {
      out.insert(prefix);
    }
  }
}

/// Core's leaves this test does not render: base58 addresses and the script
/// renderings around a compared script.
const SKIP: &[&str] = &[
  "ownerAddress",
  "votingAddress",
  "payoutAddress",
  "operatorPayoutAddress",
  "rewardAddress",
  "payouts.address",
  "shares.ownerAddress",
  "shares.refundAddress",
  "shares.rewardAddress",
  "creditOutputs.address",
  "creditOutputs.scriptPubKey.asm",
  "creditOutputs.scriptPubKey.type",
  "creditOutputs.value",
  // Core prints the bitsets as hex; their counts are compared.
  "commitment.signers",
  "commitment.validMembers",
];

fn hex(bytes: &[u8]) -> String {
  bytes.to_lower_hex_string()
}

/// Core's `ValueFromAmount`, compared in duffs.
fn duffs(core: &Value) -> i64 {
  (core.as_f64().unwrap() * 1e8).round() as i64
}

/// Compares a decoded payload with the object Core printed for it under
/// `bls`. Lazy keys print through `Get()` under their own scheme; global-flag
/// signatures under the flag; commitment fields under the version's scheme.
fn compare(label: &str, payload: &SpecialPayload, core: &Value, bls: BlsCtx) {
  let mut f = Fields::new(label, core);
  match payload {
    SpecialPayload::ProviderRegister(p) => {
      f.eq("version", p.version);
      f.eq("type", p.mn_type.to_base());
      f.eq("collateralHash", p.collateral_hash.to_string());
      f.eq("collateralIndex", p.collateral_index);
      let platform = (p.platform_p2p_port, p.platform_http_port);
      f.eq("addresses", render_net_info(&p.net_info, p.mn_type, platform));
      f.eq("pubKeyOperator", lazy_hex(&p.pub_key_operator));
      // Core prints the reward in percent.
      f.eq("operatorReward", f64::from(p.operator_reward) / 100.0);
      f.eq("inputsHash", p.inputs_hash.to_string());
      for (i, payout) in p.payouts.iter().enumerate() {
        f.eq(&format!("payouts[{i}].script"), hex(payout.script_payout.as_bytes()));
        f.eq(&format!("payouts[{i}].reward"), payout.reward);
      }
      for (i, share) in p.shares.iter().enumerate() {
        f.eq(&format!("shares[{i}].amount"), share.amount);
        f.eq(
          &format!("shares[{i}].refundScript"),
          hex(share.script_refund.as_bytes()),
        );
        f.eq(&format!("shares[{i}].rewardScript"), hex(reward_script(share)));
      }
      if !p.shares.is_empty() {
        f.eq("earlyPeriodBlocks", p.early_period_blocks);
        f.eq("earlyPenalty", p.early_penalty);
      }
      if let Some(node_id) = &p.platform_node_id {
        f.eq("platformNodeID", node_id.to_string());
      }
    }
    SpecialPayload::ProviderUpdateService(p) => {
      f.eq("version", p.version);
      // Core prints its default type for v1, which carries none.
      f.eq("type", p.mn_type.to_base());
      f.eq("proTxHash", p.pro_tx_hash.to_string());
      let platform = (p.platform_p2p_port, p.platform_http_port);
      f.eq("addresses", render_net_info(&p.net_info, p.mn_type, platform));
      f.eq("inputsHash", p.inputs_hash.to_string());
    }
    SpecialPayload::ProviderUpdateRegistrar(p) => {
      f.eq("version", p.version);
      f.eq("proTxHash", p.pro_tx_hash.to_string());
      f.eq("pubKeyOperator", lazy_hex(&p.pub_key_operator));
      for (i, payout) in p.payouts.iter().enumerate() {
        f.eq(&format!("payouts[{i}].script"), hex(payout.script_payout.as_bytes()));
        f.eq(&format!("payouts[{i}].reward"), payout.reward);
      }
      f.eq("inputsHash", p.inputs_hash.to_string());
    }
    SpecialPayload::ProviderUpdateRevoke(p) => {
      f.eq("version", p.version);
      f.eq("proTxHash", p.pro_tx_hash.to_string());
      f.eq("reason", p.reason.to_base());
      f.eq("inputsHash", p.inputs_hash.to_string());
    }
    SpecialPayload::CoinbaseCommitment(p) => compare_cbtx(&mut f, p, bls),
    SpecialPayload::QuorumCommitment(p) => {
      let qc = &p.commitment;
      f.eq("version", p.version);
      f.eq("height", p.height.to_u32());
      f.eq("commitment.version", qc.version);
      f.eq("commitment.llmqType", qc.llmq_type.to_base());
      f.eq("commitment.quorumHash", qc.quorum_hash.to_string());
      f.eq("commitment.quorumIndex", qc.quorum_index.unwrap_or(0));
      f.eq("commitment.signersCount", qc.signers.count_ones());
      f.eq("commitment.validMembersCount", qc.valid_members.count_ones());
      f.eq("commitment.quorumPublicKey", eager_hex(&qc.quorum_public_key));
      f.eq("commitment.quorumVvecHash", qc.quorum_vvec_hash.to_string());
      f.eq("commitment.quorumSig", eager_hex(&qc.quorum_sig));
      f.eq("commitment.membersSig", eager_hex(&qc.members_sig));
    }
    SpecialPayload::MnhfSignal(p) => {
      f.eq("version", p.version);
      f.eq("signal.versionBit", p.version_bit);
      f.eq("signal.quorumHash", p.quorum_hash.to_string());
      // Decoded under the basic scheme, printed under the flag.
      f.eq("signal.sig", hex(&p.sig.to_bytes(bls.scheme())));
    }
    SpecialPayload::AssetLock(p) => {
      f.eq("version", p.version);
      for (i, out) in p.credit_outputs.iter().enumerate() {
        f.eq(&format!("creditOutputs[{i}].valueSat"), out.value);
        f.eq(
          &format!("creditOutputs[{i}].scriptPubKey.hex"),
          hex(out.script_pubkey.as_bytes()),
        );
      }
    }
    SpecialPayload::AssetUnlock(p) => {
      f.eq("version", p.version);
      f.eq("index", p.index);
      f.eq("fee", p.fee);
      f.eq("requestedHeight", p.requested_height);
      f.eq("quorumHash", p.quorum_hash.to_string());
      f.eq("quorumSig", hex(&p.quorum_sig.get(bls).to_bytes(bls.scheme())));
    }
    SpecialPayload::ProviderDissolve(p) => {
      f.eq("version", p.version);
      f.eq("proTxHash", p.pro_tx_hash.to_string());
      f.eq("actorIndex", p.actor_index);
      f.eq("sigCount", p.sigs.len());
    }
    SpecialPayload::ProviderUpdateShare(p) => {
      f.eq("version", p.version);
      f.eq("proTxHash", p.pro_tx_hash.to_string());
      f.eq("shareIndex", p.share_index);
      f.eq("inputsHash", p.inputs_hash.to_string());
    }
    SpecialPayload::ProviderUpdateSharedRegistrar(p) => {
      f.eq("version", p.version);
      f.eq("proTxHash", p.pro_tx_hash.to_string());
      f.eq("pubKeyOperator", lazy_hex(&p.pub_key_operator));
      f.eq("inputsHash", p.inputs_hash.to_string());
      f.eq("sigCount", p.sigs.len());
    }
    SpecialPayload::UnknownProTxVersion { version, .. } => {
      // Core read the version alone and prints its defaults for the rest.
      f.eq("version", *version);
      let mut rest = BTreeSet::new();
      collect_leaves(core, String::new(), &mut rest);
      rest.retain(|leaf| !f.seen.contains(leaf) && !SKIP.contains(&leaf.as_str()));
      for leaf in rest {
        let v = &core[leaf.as_str()];
        let zero = v.as_u64() == Some(0) || v.as_str().is_some_and(|s| s.bytes().all(|b| b == b'0'));
        assert!(zero, "{label}: {leaf} = {v}, not Core's default");
        f.seen.insert(leaf);
      }
    }
    other => panic!("{label}: no Core object expected for {other:?}"),
  }
  f.finish(SKIP);
}

fn compare_cbtx(f: &mut Fields<'_>, p: &CoinbaseCommitment, bls: BlsCtx) {
  f.eq("version", p.version);
  f.eq("height", p.height);
  f.eq("merkleRootMNList", p.merkle_root_mn_list.to_string());
  if let Some(root) = p.merkle_root_quorums {
    f.eq("merkleRootQuorums", root.to_string());
  }
  if let (Some(diff), Some(sig), Some(balance)) = (p.best_cl_height_diff, &p.best_cl_signature, p.credit_pool_balance) {
    f.eq("bestCLHeightDiff", diff);
    f.eq("bestCLSignature", hex(&sig.get(bls).to_bytes(bls.scheme())));
    assert_eq!(duffs(&f.core["creditPoolBalance"]), balance, "{}", f.label);
    f.seen.insert("creditPoolBalance".into());
  }
  if let Some(root) = p.merkle_root_asset_unlocks {
    f.eq("merkleRootAssetUnlocks", root.to_string());
  }
}

/// Core's lazy `ToString`, `Get()` printed under the captured scheme.
fn lazy_hex(key: &BlsLazyPk) -> String {
  hex(&key.get().to_bytes(key.scheme()))
}

/// A version-sourced eager field as Core prints it, under its own scheme.
fn eager_hex<K: BlsWire<N>, const N: usize>(field: &BlsEager<K, N>) -> String {
  hex(&field.to_bytes(field.scheme()))
}

/// Core's `RewardScript`: the refund script when the reward script is empty.
fn reward_script(share: &dash_primitives::CollateralShare) -> &[u8] {
  if share.script_reward.is_empty() {
    share.script_refund.as_bytes()
  } else {
    share.script_reward.as_bytes()
  }
}

/// Every crafted case: base-sdk, which decodes without the flag, accepts the
/// payload exactly when v24.0.0-rc.3 does under each flag, and renders what
/// Core printed under it. A case whose verdict differs at v23.1.8 must be
/// listed in [`PIN_DEPENDENT`].
#[test]
fn crafted_payloads_match_core() {
  let cases = CRAFTED.as_object().unwrap();
  assert!(cases.len() >= 70);
  let mut pin_dependent = BTreeSet::new();
  for (name, case) in cases {
    let ours = accepted(&decode_tx(case["raw"].as_str().unwrap()));
    for (flag, bls) in [("basic", BlsCtx::BASIC), ("legacy", BlsCtx::LEGACY)] {
      let label = format!("{name} ({flag})");
      let core = core_object(case, V24, flag);
      assert_eq!(ours.is_some(), core.is_some(), "{label}: decode verdict");
      if let (Some(ours), Some(core)) = (&ours, core) {
        compare(&label, &ours.payload, core, bls);
      }
      if core_object(case, V23, flag).is_some() != core.is_some() {
        pin_dependent.insert(name.as_str());
      }
    }
  }
  let listed: BTreeSet<&str> = PIN_DEPENDENT.iter().map(|(name, _)| *name).collect();
  assert_eq!(pin_dependent, listed, "cases whose verdict differs by pin");
}

/// Core-built v24 transactions: every payload decodes completely, re-encodes
/// to its bytes, and matches Core's JSON. The regtest chains ran past V19, so
/// Core read them under the basic flag.
#[test]
fn v24_payloads_match_core() {
  let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "v24").into_value();
  let entries = corpus["v24"].as_object().unwrap();
  let mut types = BTreeSet::new();
  for (txid, entry) in entries {
    let tx = decode_tx(entry["raw"].as_str().unwrap());
    let decoded = accepted(&tx).unwrap_or_else(|| panic!("{txid}: payload"));
    let core = entry["core"].as_object().unwrap().values().next().unwrap();
    compare(txid, &decoded.payload, core, BlsCtx::BASIC);
    // Core mined these, so base-sdk's partial checks must pass them.
    assert_eq!(decoded.payload.check(), None, "{txid}: check");
    types.insert(tx.tx_type.to_base());
    assert_eq!(reencode(&decoded.payload), tx.extra_payload, "{txid}: re-encode");
  }
  assert_eq!(types, (1..=12).filter(|t| *t != 4 && *t != 7).collect());
}

fn reencode(payload: &SpecialPayload) -> Vec<u8> {
  let mut buf = Vec::new();
  match payload {
    SpecialPayload::ProviderRegister(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateService(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateRegistrar(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateRevoke(p) => p.encode(&mut buf),
    SpecialPayload::CoinbaseCommitment(p) => p.encode(&mut buf),
    SpecialPayload::QuorumCommitment(p) => p.encode(&mut buf),
    SpecialPayload::MnhfSignal(p) => p.encode(&mut buf),
    SpecialPayload::AssetLock(p) => p.encode(&mut buf),
    SpecialPayload::AssetUnlock(p) => p.encode(&mut buf),
    SpecialPayload::ProviderDissolve(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateShare(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateSharedRegistrar(p) => p.encode(&mut buf),
    other => panic!("no encoding for {other:?}"),
  }
  buf
}

/// The scheme each BLS field decodes under, per A1 §1.4.1: the version for
/// ProTx and commitment fields, the basic scheme for MnHF and shared-registrar
/// fields, and Core's flag, given at use, for the coinbase and asset-unlock
/// signatures. Core passes these in the payloads' serializers at both pins;
/// it prints no ProUpServTx or ProUpRevTx signature, so this also pins their
/// outcome.
#[test]
fn bls_fields_take_their_scheme_source() {
  use BlsSchemeKind::{Basic, Legacy};

  for (version, scheme) in [(1, Legacy), (2, Basic)] {
    for (sample, valid) in [("legacy", scheme == Legacy), ("basic", scheme == Basic)] {
      let name = format!("proupservtx_v{version}_sig_{sample}");
      let SpecialPayload::ProviderUpdateService(p) = crafted(&name) else {
        panic!("{name}")
      };
      assert_eq!((p.sig.scheme(), p.sig.is_valid()), (scheme, valid), "{name}");
      let name = format!("prouprevtx_v{version}_sig_{sample}");
      let SpecialPayload::ProviderUpdateRevoke(p) = crafted(&name) else {
        panic!("{name}")
      };
      assert_eq!((p.sig.scheme(), p.sig.is_valid()), (scheme, valid), "{name}");
      let name = format!("proregtx_v{version}_pk_{sample}");
      let SpecialPayload::ProviderRegister(p) = crafted(&name) else {
        panic!("{name}")
      };
      assert_eq!(p.pub_key_operator.scheme(), scheme, "{name}");
      let name = format!("proupregtx_v{version}_pk_{sample}");
      let SpecialPayload::ProviderUpdateRegistrar(p) = crafted(&name) else {
        panic!("{name}")
      };
      assert_eq!(p.pub_key_operator.scheme(), scheme, "{name}");
    }
  }
  for (version, scheme) in [(1, Legacy), (2, Legacy), (3, Basic), (4, Basic)] {
    let name = format!("qctx_v{version}_basic");
    let SpecialPayload::QuorumCommitment(p) = crafted(&name) else {
      panic!("{name}")
    };
    let qc = &p.commitment;
    let schemes = [
      qc.quorum_public_key.scheme(),
      qc.quorum_sig.scheme(),
      qc.members_sig.scheme(),
    ];
    assert_eq!(schemes, [scheme; 3], "{name}");
  }
  let SpecialPayload::CoinbaseCommitment(cbtx) = crafted("cbtx_v3_sig_basic") else {
    panic!()
  };
  let SpecialPayload::AssetUnlock(unlock) = crafted("assetunlock_v1_sig_basic") else {
    panic!()
  };
  // Basic-scheme samples: valid where the flag is basic, invalid where legacy.
  for (bls, valid) in [(BlsCtx::BASIC, true), (BlsCtx::LEGACY, false)] {
    assert_eq!(cbtx.best_cl_signature.as_ref().unwrap().get(bls).is_valid(), valid);
    assert_eq!(unlock.quorum_sig.get(bls).is_valid(), valid);
  }
  let SpecialPayload::MnhfSignal(p) = crafted("mnhf_sig_basic") else {
    panic!()
  };
  assert_eq!((p.sig.scheme(), p.sig.is_valid()), (Basic, true));
  let SpecialPayload::ProviderUpdateSharedRegistrar(p) = crafted("proupsharedregtx_pk_legacy") else {
    panic!()
  };
  assert_eq!(p.pub_key_operator.scheme(), Basic);
}

/// Core's `CFinalCommitment::IsNull` counts a BLS field that decoded invalid,
/// its bytes canonical only in the other scheme, as absent (A1 quirk 36).
#[test]
fn null_commitment_ignores_fields_of_the_other_scheme() {
  for (name, null) in [
    ("qctx_v1_basic", true),
    ("qctx_v3_basic", false),
    ("qctx_v3_legacy", true),
  ] {
    let mut raw = dash_dev::vec_from_hex(CRAFTED[name]["raw"].as_str().unwrap());
    // The crafted verification vector hash is 32 bytes of 0x06.
    let at = raw.windows(32).position(|w| w == [6u8; 32]).unwrap();
    raw[at..at + 32].fill(0);
    let tx = Transaction::decode(&mut &raw[..]).unwrap();
    let SpecialPayload::QuorumCommitment(p) = accepted(&tx).unwrap().payload else {
      panic!("{name}")
    };
    assert_eq!(p.commitment.is_null(), null, "{name}");
  }
}
