//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Built chain parameters equal the reference implementation's dumps, chain
//! by chain and option case by option case, at each release.
//!
//! dash-primitives checks the genesis block bytes, since it builds blocks.

#![expect(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_num::Hash256;
use dash_params::{
  BuriedDeployment, ChainParamsBuilder, ChainSetup, LlmqParams, LlmqType, Network, Release, MAX_LLMQ_SIZE,
};
use dash_pow::__deps::digest::Digest;
use dash_pow::X11;
use dash_types::Numeric;
use hex_conservative::DisplayHex;
use rstest::rstest;

use std::collections::{BTreeMap, BTreeSet};

/// Corpus keys holding block bytes, which dash-primitives checks.
const BLOCK_KEYS: [&str; 2] = ["params.genesisBlock", "ext.devnetGenesisBlock"];

/// Option cases the reference accepts and this crate refuses, with the
/// refusal. Heights are unsigned here, and LLMQ sizes and thresholds `u16`.
const REFUSED: [(&str, &str); 10] = [
  ("refused/vb_other_negative", "negative height -5 in -vbparams"),
  ("refused/budget_negative", "negative height -1 in -budgetparams"),
  ("refused/dip3_negative", "negative height -1 in -dip3params"),
  (
    "refused/llmq_negative",
    "LLMQ_TEST_INSTANTSEND size (-3) or threshold (-4) outside 0 to 65535",
  ),
  (
    "refused/llmq_devnet_negative",
    "LLMQ_DEVNET size (-2) or threshold (9) outside 0 to 65535",
  ),
  (
    "refused/llmq_threshold_70000",
    "LLMQ_TEST size (3) or threshold (70000) outside 0 to 65535",
  ),
  (
    "refused/llmq_threshold_negative",
    "LLMQ_TEST_PLATFORM size (3) or threshold (-1) outside 0 to 65535",
  ),
  (
    "refused/llmq_size_70000",
    "LLMQ_TEST size (70000) or threshold (2) outside 0 to 65535",
  ),
  (
    "refused/llmqtestplat_size_1000000",
    "LLMQ_TEST_PLATFORM size (1000000) or threshold (2) outside 0 to 65535",
  ),
  (
    "refused/llmq_range_then_min_spork_keys",
    "LLMQ_TEST size (-1) or threshold (2) outside 0 to 65535",
  ),
];

/// The hex of `hash` as the reference implementation prints it, big-endian.
fn hash_hex(hash: Hash256) -> String {
  hash.to_bendian().to_lower_hex_string()
}

/// The hash of an all-zero header, the devnet genesis hash off devnets.
fn null_block_hash() -> Hash256 {
  Hash256::from_lendian(X11::digest([0; 80]).into())
}

/// Leaf values keyed by dotted path; `#` is an array's length.
#[derive(Default)]
struct Flat(BTreeMap<String, Value>);

impl Flat {
  fn put(&mut self, path: &str, value: impl Into<Value>) {
    self.0.insert(path.into(), value.into());
  }

  fn put_all<V: Into<Value>>(&mut self, prefix: &str, fields: impl IntoIterator<Item = (&'static str, V)>) {
    for (name, value) in fields {
      self.put(&format!("{prefix}.{name}"), value);
    }
  }

  fn list<T>(&mut self, path: &str, items: &[T], mut each: impl FnMut(&mut Self, &str, &T)) {
    self.put(&format!("{path}.#"), items.len());
    for (i, item) in items.iter().enumerate() {
      each(self, &format!("{path}.{i}"), item);
    }
  }
}

fn llmq(out: &mut Flat, path: &str, llmq_type: LlmqType, q: &LlmqParams) {
  out.put(&format!("{path}.type"), llmq_type.to_base());
  out.put(&format!("{path}.name"), llmq_type.to_string());
  out.put(&format!("{path}.useRotation"), q.use_rotation);
  let fields = [
    ("size", q.size),
    ("minSize", q.min_size),
    ("threshold", q.threshold),
    ("dkgInterval", q.dkg_interval),
    ("dkgPhaseBlocks", q.dkg_phase_blocks),
    ("dkgMiningWindowStart", q.dkg_mining_window_start),
    ("dkgMiningWindowEnd", q.dkg_mining_window_end),
    ("dkgBadVotesThreshold", q.dkg_bad_votes_threshold),
    ("signingActiveQuorumCount", q.signing_active_quorum_count),
    ("keepOldConnections", q.keep_old_connections),
    ("keepOldKeys", q.keep_old_keys),
    ("recoveryMembers", q.recovery_members),
  ];
  out.put_all(path, fields);
}

/// [`llmq`] with the values the reference derives from the parameters.
fn llmq_ext(out: &mut Flat, path: &str, llmq_type: LlmqType, q: &LlmqParams) {
  llmq(out, path, llmq_type, q);
  out.put(&format!("{path}.max_store_depth"), q.max_store_depth());
  out.put(&format!("{path}.is_single_member"), q.is_single_member());
}

/// `p` in the shape of the corpus, flattened, without the [`BLOCK_KEYS`].
fn dump(p: &ChainSetup) -> BTreeMap<String, Value> {
  let mut out = Flat::default();
  let c = &p.consensus;
  let a = &p.addr_params;
  let devnet_genesis_hash = p.devnet_genesis().map_or_else(null_block_hash, |g| g.hash);
  out.put("params.networkID", p.network_id);
  out.put("params.messageStart", p.message_start.to_lower_hex_string());
  out.put("params.defaultPort", p.default_port);
  out.put("params.pruneAfterHeight", p.prune_after_height);
  out.put("params.genesisHash", hash_hex(c.hash_genesis_block));
  out.put("params.devnetGenesisHash", hash_hex(devnet_genesis_hash));
  out.put("params.extCoinType", a.bip44_idx);
  out.put("params.base58Prefixes.PUBKEY_ADDRESS", format!("{:02x}", a.pubkey_addr));
  out.put("params.base58Prefixes.SCRIPT_ADDRESS", format!("{:02x}", a.script_addr));
  out.put("params.base58Prefixes.SECRET_KEY", format!("{:02x}", a.secret_key));
  out.put(
    "params.base58Prefixes.EXT_PUBLIC_KEY",
    a.ext_pubkey.to_lower_hex_string(),
  );
  out.put(
    "params.base58Prefixes.EXT_SECRET_KEY",
    a.ext_secret.to_lower_hex_string(),
  );
  for (h, hash) in p.all_checkpoints() {
    out.put(&format!("params.checkpoints.{}", h.to_u32()), hash_hex(hash));
  }

  let hashes = [
    ("hashGenesisBlock", c.hash_genesis_block),
    ("hashDevnetGenesisBlock", c.hash_devnet_genesis_block),
    ("nSuperblockStartHash", c.superblock_start.1),
    ("BIP34Hash", c.bip34.1),
    ("DIP0003EnforcementHash", c.dip0003_enforcement.1),
    ("defaultAssumeValid", c.default_assume_valid),
  ];
  out.put_all("params.consensus", hashes.map(|(n, h)| (n, hash_hex(h))));
  let heights = [
    ("nMasternodePaymentsStartBlock", c.masternode_payments_start_block),
    ("nMasternodePaymentsIncreaseBlock", c.masternode_payments_increase_block),
    ("nBudgetPaymentsStartBlock", c.budget_payments_start_block),
    ("nSuperblockStartBlock", c.superblock_start.0),
    ("BIP34Height", c.bip34.0),
    ("BIP65Height", c.bip65_height),
    ("BIP66Height", c.bip66_height),
    ("BIP147Height", c.bip147_height),
    ("CSVHeight", c.csv_height),
    ("DIP0001Height", c.dip0001_height),
    ("DIP0003Height", c.dip0003_height),
    ("DIP0003EnforcementHeight", c.dip0003_enforcement.0),
    ("DIP0008Height", c.dip0008_height),
    ("BRRHeight", c.brr_height),
    ("DIP0020Height", c.dip0020_height),
    ("DIP0024Height", c.dip0024_height),
    ("DIP0024QuorumsHeight", c.dip0024_quorums_height),
    ("V19Height", c.v19_height),
    ("V20Height", c.v20_height),
    ("MN_RRHeight", c.mn_rr_height),
    ("WithdrawalsHeight", c.withdrawals_height),
    ("MinBIP9WarningHeight", c.min_bip9_warning_height),
    ("nPowKGWHeight", c.pow_kgw_height),
    ("nPowDGWHeight", c.pow_dgw_height),
  ];
  out.put_all("params.consensus", heights.map(|(n, h)| (n, h.to_u32())));
  let ints = [
    ("nSubsidyHalvingInterval", c.subsidy_halving_interval),
    (
      "nMasternodePaymentsIncreasePeriod",
      c.masternode_payments_increase_period,
    ),
    (
      "nInstantSendConfirmationsRequired",
      c.instant_send_confirmations_required,
    ),
    ("nInstantSendKeepLock", c.instant_send_keep_lock),
    ("nBudgetPaymentsCycleBlocks", c.budget_payments_cycle_blocks),
    ("nBudgetPaymentsWindowBlocks", c.budget_payments_window_blocks),
    ("nSuperblockCycle", c.superblock_cycle),
    ("nSuperblockMaturityWindow", c.superblock_maturity_window),
    ("nGovernanceMinQuorum", c.governance_min_quorum),
    ("nGovernanceFilterElements", c.governance_filter_elements),
    ("nMasternodeMinimumConfirmations", c.masternode_minimum_confirmations),
    ("nMinimumDifficultyBlocks", c.minimum_difficulty_blocks),
    ("nHighSubsidyBlocks", c.high_subsidy_blocks),
    ("nHighSubsidyFactor", c.high_subsidy_factor),
  ];
  out.put_all("params.consensus", ints);
  out.put(
    "params.consensus.nRuleChangeActivationThreshold",
    c.rule_change_activation_threshold,
  );
  out.put("params.consensus.nMinerConfirmationWindow", c.miner_confirmation_window);
  // The reference lists each deployment at its index.
  out.put("params.consensus.vDeployments.#", p.deployments().count());
  for (pos, d) in p.deployments() {
    let path = &format!("params.consensus.vDeployments.{}", pos.index());
    out.put(&format!("{path}.name"), pos.name());
    out.put(&format!("{path}.bit"), d.bit);
    out.put(
      &format!("{path}.min_activation_height"),
      d.min_activation_height.to_u32(),
    );
    let fields = [
      ("nStartTime", d.start_time),
      ("nTimeout", d.timeout),
      ("nWindowSize", d.window_size),
      ("nThresholdStart", d.threshold_start),
      ("nThresholdMin", d.threshold_min),
      ("nFalloffCoeff", d.falloff_coeff),
    ];
    out.put_all(path, fields);
    out.put(&format!("{path}.useEHF"), d.use_ehf);
  }
  out.put(
    "params.consensus.powLimit",
    c.pow_limit.to_bendian().to_lower_hex_string(),
  );
  out.put(
    "params.consensus.fPowAllowMinDifficultyBlocks",
    c.pow_allow_min_difficulty_blocks,
  );
  out.put("params.consensus.fPowNoRetargeting", c.pow_no_retargeting);
  out.put("params.consensus.nPowTargetSpacing", c.pow_target_spacing);
  out.put("params.consensus.nPowTargetTimespan", c.pow_target_timespan);
  out.put(
    "params.consensus.nMinimumChainWork",
    c.minimum_chain_work.to_bendian().to_lower_hex_string(),
  );
  let llmqs: Vec<_> = c.llmqs.iter().map(|&t| (t, c.llmq(t).unwrap())).collect();
  out.list("params.consensus.llmqs", &llmqs, |out, path, (t, q)| {
    llmq(out, path, *t, q)
  });
  out.put("params.consensus.llmqTypeChainLocks", c.llmq_type_chain_locks.to_base());
  out.put(
    "params.consensus.llmqTypeDIP0024InstantSend",
    c.llmq_type_dip0024_instant_send.to_base(),
  );
  out.put("params.consensus.llmqTypePlatform", c.llmq_type_platform.to_base());
  out.put("params.consensus.llmqTypeMnhf", c.llmq_type_mnhf.to_base());

  out.put("ext.dataDir", p.data_dir());
  out.put("ext.rpcPort", p.rpc_port);
  out.put("ext.onionServiceTargetPort", p.onion_service_target_port);
  out.put("ext.defaultPlatformP2PPort", p.default_platform_p2p_port);
  out.put("ext.defaultPlatformHTTPPort", p.default_platform_http_port);
  out.put("ext.minBlocksToKeep", p.min_blocks_to_keep);
  out.put("ext.assumedBlockchainSize", p.assumed_blockchain_size_gb);
  out.put("ext.assumedChainStateSize", p.assumed_chain_state_size_gb);
  out.list("ext.dnsSeeds", p.dns_seeds, |out, path, s| out.put(path, *s));
  out.put("ext.fixedSeeds", p.fixed_seeds.to_lower_hex_string());
  out.list("ext.sporkAddresses", &[p.spork_address], |out, path, s| {
    out.put(path, *s)
  });
  let flags = [
    ("defaultConsistencyChecks", p.default_consistency_checks),
    ("requireRoutableExternalIP", p.require_routable_external_ip),
    ("isTestChain", p.is_test_chain),
    ("isMockableChain", p.is_mockable_chain),
    ("mineBlocksOnDemand", c.pow_no_retargeting),
    ("allowMultipleAddressesFromGroup", p.allow_multiple_addresses_from_group),
  ];
  out.put_all("ext", flags);
  let ints = [
    ("llmqConnectionRetryTimeout", p.llmq_connection_retry_timeout),
    ("poolMinParticipants", p.pool_min_participants),
    ("poolMaxParticipants", p.pool_max_participants),
    ("fulfilledRequestExpireTime", p.fulfilled_request_expire_time),
    ("creditPoolPeriodBlocks", p.credit_pool_period_blocks),
  ];
  out.put_all("ext", ints);
  out.put("ext.chainTxData.nTime", p.chain_tx_data.timestamp);
  out.put("ext.chainTxData.nTxCount", p.chain_tx_data.tx_count);
  out.put(
    "ext.chainTxData.dTxRateBits",
    format!("{:016x}", p.chain_tx_data.tx_rate.to_bits()),
  );
  out.list("ext.assumeutxo", p.assumeutxo, |out, path, au| {
    out.put(&format!("{path}.height"), au.height.to_u32());
    out.put(&format!("{path}.hash_serialized"), hash_hex(au.hash_serialized));
    out.put(&format!("{path}.nChainTx"), au.chain_tx);
    if let Some(evo) = au.evo_hash {
      out.put(&format!("{path}.evo_hash"), hash_hex(evo));
    }
  });
  out.list("ext.deploymentInfo", p.release().deployments(), |out, path, d| {
    out.put(&format!("{path}.name"), d.name());
    out.put(&format!("{path}.gbt_force"), d.gbt_force());
  });
  for d in BuriedDeployment::ALL {
    out.put(
      &format!("ext.buriedDeployments.{}", d.name()),
      c.deployment_height(d).to_u32(),
    );
  }
  out.list("ext.llmqs", &llmqs, |out, path, (t, q)| llmq_ext(out, path, *t, q));
  let available = LlmqType::AVAILABLE.map(|t| (t, t.params().expect("a table entry")));
  out.list("ext.availableLlmqs", &available, |out, path, (t, q)| {
    llmq_ext(out, path, *t, q)
  });
  match p.release() {
    Release::V23_1 => {
      out.put(
        "ext.requireStandard",
        p.require_standard.expect("v23 has a standard policy"),
      );
      out.put(
        "ext.minSporkKeys",
        p.release().min_spork_keys().expect("v23 has a threshold"),
      );
    }
    Release::V24_0 => {
      out.put(
        "ext.bech32PlatformHRP",
        p.platform_hrp().expect("v24 has a Platform HRP"),
      );
      out.put("ext.MAX_LLMQ_SIZE", MAX_LLMQ_SIZE);
    }
  }
  let signers = &p.spork_signers;
  out.list("spork.keyIDs", &signers.key_ids, |out, path, id| {
    out.put(path, id.as_bytes().to_lower_hex_string())
  });
  if let Some(min) = signers.min_spork_keys {
    out.put("spork.minSporkKeys", min);
  }
  if let Some(warning) = &signers.warning {
    out.put("spork.warning", warning.as_str());
  }
  out.0
}

/// Leaf values of a corpus value keyed by dotted path, as [`Flat`] keys them.
fn flatten(value: &Value, prefix: &str, out: &mut BTreeMap<String, Value>) {
  match value {
    Value::Object(map) => {
      for (k, v) in map {
        flatten(v, &format!("{prefix}{k}."), out);
      }
    }
    Value::Array(items) => {
      out.insert(format!("{prefix}#"), items.len().into());
      for (i, v) in items.iter().enumerate() {
        flatten(v, &format!("{prefix}{i}."), out);
      }
    }
    leaf => {
      out.insert(prefix.trim_end_matches('.').into(), leaf.clone());
    }
  }
}

/// `value` flattened.
fn flat(value: &Value) -> BTreeMap<String, Value> {
  let mut out = BTreeMap::new();
  flatten(value, "", &mut out);
  out
}

/// The corpus `corpus`.
fn root(corpus: &str) -> Value {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus).into_value()
}

/// Each chain's base in `root`, flattened.
fn bases(root: &Value) -> BTreeMap<String, BTreeMap<String, Value>> {
  let bases = root["bases"].as_object().unwrap();
  bases.iter().map(|(chain, v)| (chain.clone(), flat(v))).collect()
}

fn corpus(release: Release) -> &'static str {
  match release {
    Release::V23_1 => "chainparams_v23_1",
    Release::V24_0 => "chainparams_v24_0",
  }
}

/// Asserts that `got` holds exactly the values of `want` but the
/// [`BLOCK_KEYS`].
fn assert_dump(got: &BTreeMap<String, Value>, mut want: BTreeMap<String, Value>, what: &str) {
  want.retain(|path, _| !BLOCK_KEYS.contains(&path.as_str()));
  for (path, v) in &want {
    assert_eq!(got.get(path), Some(v), "{what}: {path}");
  }
  assert_eq!(got.len(), want.len(), "{what}: extra keys");
}

#[rstest]
fn chain_setup_equals_the_reference(
  #[values(Release::V23_1, Release::V24_0)] release: Release,
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
) {
  let corpus = corpus(release);
  let chain = network.network_id();
  let want = bases(&root(corpus)).remove(chain).expect("a base per chain");
  let got = dump(&ChainParamsBuilder::new(network, release).build().unwrap());
  assert_dump(&got, want, &format!("{corpus} {chain}"));
}

/// The corpora hold the four chains and nothing else.
#[rstest]
fn corpora_hold_every_chain(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let chains: Vec<String> = bases(&root(corpus(release))).into_keys().collect();
  let mut want: Vec<_> = Network::ALL.map(|n| n.network_id().to_owned()).into();
  want.sort();
  assert_eq!(chains, want);
}

/// [`BuriedDeployment::ALL`] follows the order in which the dumps print the
/// buried deployments, the reference implementation's. A parsed corpus has
/// no key order, so this reads each chain's block of the corpus text.
#[rstest]
fn buried_deployments_keep_the_reference_order(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let path = format!("{}/corpus/{}.json5", env!("CARGO_MANIFEST_DIR"), corpus(release));
  let text = std::fs::read_to_string(&path).unwrap();
  let blocks: Vec<&str> = text.split("\"buriedDeployments\": {").skip(1).collect();
  assert_eq!(blocks.len(), Network::ALL.len(), "{path}");
  for block in blocks {
    let names: Vec<&str> = block
      .split('}')
      .next()
      .unwrap()
      .lines()
      .filter_map(|line| line.trim().strip_prefix('"')?.split('"').next())
      .collect();
    assert_eq!(names, BuriedDeployment::ALL.map(BuriedDeployment::name), "{path}");
  }
}

/// Each corpus holds exactly the cases of the case list, each once.
#[rstest]
fn corpora_hold_the_case_list(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let corpus = corpus(release);
  let list = Corpus::open(env!("CARGO_MANIFEST_DIR"), "chainparams_cases").into_value();
  let list = list[corpus].as_array().unwrap();
  let want: BTreeMap<&str, (&Value, &Value)> = list
    .iter()
    .map(|case| (case[0].as_str().unwrap(), (&case[1], &case[2])))
    .collect();
  assert_eq!(want.len(), list.len(), "{corpus}: a name twice in the case list");
  let root = root(corpus);
  let got: BTreeMap<&str, (&Value, &Value)> = root["cases"]
    .as_object()
    .unwrap()
    .iter()
    .map(|(name, case)| (name.as_str(), (&case["chain"], &case["args"])))
    .collect();
  assert_eq!(got, want, "{corpus}");
}

/// Every option case gives the reference's error text, or its parameters.
/// The [`REFUSED`] cases are refused instead.
#[rstest]
fn option_cases_equal_the_reference(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let corpus = corpus(release);
  let root = root(corpus);
  let bases = bases(&root);
  for (name, case) in root["cases"].as_object().unwrap() {
    let what = format!("{corpus} {name}");
    let chain = case["chain"].as_str().unwrap();
    let network = Network::from_network_id(chain).unwrap();
    let mut builder = ChainParamsBuilder::new(network, release);
    for arg in case["args"].as_array().unwrap() {
      builder = builder.parse_arg(arg.as_str().unwrap()).expect("a chain option");
    }
    let built = builder.build();
    if let Some((_, refusal)) = REFUSED.iter().find(|(n, _)| n == name) {
      assert!(case.get("delta").is_some(), "{what}: the reference refuses it too");
      assert_eq!(built.unwrap_err().to_string(), *refusal, "{what}");
      continue;
    }
    if let Some(error) = case.get("error") {
      assert_eq!(built.unwrap_err().to_string(), error.as_str().unwrap(), "{what}");
      continue;
    }
    let mut want = bases[chain].clone();
    for key in case.get("missing_keys").into_iter().flat_map(|k| k.as_array().unwrap()) {
      want.remove(key.as_str().unwrap());
    }
    for extra in [case.get("extra_keys"), case.get("delta")].into_iter().flatten() {
      want.extend(extra.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    let got = dump(&built.expect(&what));
    assert_dump(&got, want, &what);
  }
}

/// Every refused case is an option case of a corpus.
#[rstest]
fn refused_cases_are_option_cases() {
  let names: BTreeSet<String> = Release::ALL
    .into_iter()
    .flat_map(|r| {
      root(corpus(r))["cases"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>()
    })
    .collect();
  for (name, _) in REFUSED {
    assert!(names.contains(name), "{name}");
  }
}
