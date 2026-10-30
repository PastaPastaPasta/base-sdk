//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The genesis and devnet genesis blocks built from the chain setup equal
//! Dash Core's bytes, case by case, in dash-params' chain-params corpora.
//! dash-params checks every other value of those corpora itself. Each
//! corpus must hold exactly the cases of dash-params'
//! `corpus/chainparams_cases.json5`.

#![expect(clippy::panic, clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_params::{ChainOption, ChainParamsBuilder, ChainSetup, Network, Release};
use dash_primitives::{Block, BlockHeader};
use dash_types::codec::BaseCodec;
use hex_conservative::DisplayHex;
use rstest::rstest;

use std::collections::BTreeMap;

const GENESIS: &str = "params.genesisBlock";
const DEVNET_GENESIS: &str = "ext.devnetGenesisBlock";

fn serialize(block: &Block) -> String {
  let mut buf = Vec::new();
  block.encode(&mut buf);
  buf.to_lower_hex_string()
}

/// Core's `DevNetGenesisBlock()`: the devnet genesis block on a devnet, a
/// null `CBlock` elsewhere.
fn devnet_genesis(setup: &ChainSetup) -> Block {
  setup.devnet_genesis.as_ref().map_or_else(
    || Block {
      header: BlockHeader::default(),
      transactions: Vec::new(),
    },
    Block::from,
  )
}

/// Core's `InterpretBool`: empty is true, else `LocaleIndependentAtoi<int>`
/// (trimmed, one `+`, leading digits only) is compared to 0.
fn interpret_bool(s: &str) -> bool {
  let s = s.trim_matches(|c| matches!(c, ' ' | '\x0c' | '\n' | '\r' | '\t' | '\x0b'));
  if s.is_empty() {
    return true;
  }
  if s.starts_with("+-") {
    return false;
  }
  let s = s.strip_prefix('+').unwrap_or(s);
  let digits = s.strip_prefix('-').unwrap_or(s);
  digits.chars().take_while(char::is_ascii_digit).any(|c| c != '0')
}

/// Adds one command-line argument `-name[=value]` or `-noname[=value]` to
/// `builder`, as Core's `InterpretValue` stores it (a double negative is
/// stored as true if Core allows the negation).
fn add_arg(builder: ChainParamsBuilder, arg: &str) -> ChainParamsBuilder {
  let (key, value) = match arg.split_once('=') {
    Some((k, v)) => (k, Some(v)),
    None => (arg, None),
  };
  let option = |name: &str| ChainOption::from_name(name).expect("chain option");
  match key.strip_prefix("-no").map(|name| option(&format!("-{name}"))) {
    Some(o) if o.negatable() && value.is_some_and(|v| !interpret_bool(v)) => builder.arg(o, "1"),
    Some(o) => builder.negate(o),
    None => builder.arg(option(key), value.unwrap_or("")),
  }
}

/// The cases `corpus` must hold, from the hand-kept manifest
/// `corpus/chainparams_cases.json5` in `dir`: chain and arguments by name.
fn required_cases(dir: &str, corpus: &str) -> BTreeMap<String, Value> {
  let manifest = Corpus::open(dir, "chainparams_cases").into_value();
  let mut out = BTreeMap::new();
  for entry in manifest[corpus].as_array().unwrap() {
    let name = entry[0].as_str().unwrap();
    let case = Value::Array(vec![entry[1].clone(), entry[2].clone()]);
    assert!(
      out.insert(name.to_owned(), case).is_none(),
      "manifest {corpus}: duplicate {name}"
    );
  }
  out
}

/// Asserts that `cases` are exactly the required cases of `corpus` in
/// `dir`, each once, with its chain and arguments.
fn assert_required_cases(dir: &str, corpus: &str, cases: &[Value]) {
  let mut got = BTreeMap::new();
  for case in cases {
    let name = case["name"].as_str().unwrap();
    let chain_args = Value::Array(vec![case["chain"].clone(), case["args"].clone()]);
    assert!(
      got.insert(name, chain_args).is_none(),
      "{corpus}: duplicate case {name}"
    );
  }
  let want = required_cases(dir, corpus);
  let missing: Vec<&String> = want.keys().filter(|n| !got.contains_key(n.as_str())).collect();
  let unlisted: Vec<&&str> = got.keys().filter(|n| !want.contains_key(**n)).collect();
  assert!(
    missing.is_empty() && unlisted.is_empty(),
    "{corpus}: missing {missing:?}, not in the manifest {unlisted:?}"
  );
  for (name, chain_args) in &want {
    assert_eq!(&got[name.as_str()], chain_args, "{corpus} {name}: chain and arguments");
  }
}

#[rstest]
#[case::v23_1(Release::V23_1, "chainparams_v23_1")]
#[case::v24_0(Release::V24_0, "chainparams_v24_0")]
fn chain_params_blocks_equal_core(#[case] release: Release, #[case] corpus: &str) {
  let params_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../params");
  let root = Corpus::open(params_dir, corpus).into_value();
  let bases = root["bases"].as_object().unwrap();
  let cases = root["cases"].as_array().unwrap();
  assert_required_cases(params_dir, corpus, cases);
  for case in cases {
    if case.get("error").is_some() || case.get("refused").is_some() {
      continue;
    }
    let name = case["name"].as_str().unwrap();
    let chain = case["chain"].as_str().unwrap();
    let network = Network::from_network_id(chain).expect("one of Core's chains");
    let mut builder = ChainParamsBuilder::new(network, release);
    for arg in case["args"].as_array().unwrap() {
      builder = add_arg(builder, arg.as_str().unwrap());
    }
    let setup = builder.build().unwrap_or_else(|e| panic!("{corpus} {name}: {e}"));
    let delta = case["delta"].as_object().unwrap();
    let want = |key: &str| -> &Value {
      delta.get(key).unwrap_or_else(|| match key {
        GENESIS => &bases[chain]["params"]["genesisBlock"],
        _ => &bases[chain]["ext"]["devnetGenesisBlock"],
      })
    };
    let genesis = Block::from(&setup.genesis);
    assert_eq!(serialize(&genesis), want(GENESIS).as_str().unwrap(), "{corpus} {name}");
    let devnet = devnet_genesis(&setup);
    assert_eq!(
      serialize(&devnet),
      want(DEVNET_GENESIS).as_str().unwrap(),
      "{corpus} {name}"
    );
  }
}
