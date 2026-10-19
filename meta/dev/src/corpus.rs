//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Agnostic corpus read/write logic.

use crate::prelude::*;

use hex_conservative::decode_to_vec;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use core::fmt;
use std::fs;

/// Verifies the serde round-trip for a set of corpus entries.
///
/// Writes `items` to JSON via `write_corpus`, reads them back through
/// [`Corpus::entries`] (no-op check), and asserts equality.
///
/// # Panics
///
/// Panics on round-trip mismatch.
pub fn assert_serde_rt<T>(section: &str, items: &BTreeMap<String, T>)
where
  T: DeserializeOwned + Serialize + PartialEq + fmt::Debug,
{
  let json = write_corpus(section, items);
  let rt = Corpus::parse(section, &json).entries::<T>(section, |_, _, _| {});
  assert_eq!(*items, rt, "{section}: serde round-trip");
}

/// Serializes corpus entries to JSON in `{ raw, details }` format,
/// wrapped in a section key.
///
/// Produces `{ "section": { "label": { "raw": "", "details": T } } }`
/// so the output can be read back by [`Corpus::entries`] with a no-op
/// check function to verify the serde round-trip.
///
/// # Panics
///
/// Panics if serialization fails.
pub(crate) fn write_corpus<T: Serialize>(section: &str, entries: &BTreeMap<String, T>) -> String {
  #[derive(Serialize)]
  struct Raw<'a, T: Serialize> {
    raw: &'a str,
    details: &'a T,
  }
  let inner: BTreeMap<&str, Raw<T>> = entries
    .iter()
    .map(|(k, v)| (k.as_str(), Raw { raw: "", details: v }))
    .collect();
  let outer = BTreeMap::from([(section, inner)]);
  serde_json::to_string(&outer).unwrap_or_else(|e| panic!("write_corpus: {e}"))
}

/// A typed corpus entry pairing raw wire hex with expected details.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct CorpusEntry<T> {
  pub raw: String,
  pub details: T,
}

/// A parsed corpus file, opened once and queried by section.
///
/// Serves both operation KATs via [`Corpus::vectors`] (array sections) and
/// wire round-trip corpora via [`Corpus::entries`] (raw/details sections).
#[derive(Clone, Debug)]
pub struct Corpus {
  name: String,
  root: serde_json::Value,
}

impl Corpus {
  /// Parses corpus text (JSON5) under a diagnostic `name`.
  ///
  /// # Panics
  ///
  /// Panics if the text is not valid JSON5.
  pub(crate) fn parse(name: &str, text: &str) -> Self {
    let root = json5::from_str(text).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
    Self {
      name: name.into(),
      root,
    }
  }

  /// Consumes the handle and returns the parsed root value.
  pub fn into_value(self) -> serde_json::Value {
    self.root
  }

  /// Returns a named `{ label: { raw, details } }` section.
  ///
  /// Hex-decodes each `raw`, calls `check(raw_bytes, &details, label)`, and
  /// returns the details keyed by label.
  ///
  /// # Panics
  ///
  /// Panics if the section is missing, empty, or `check` panics.
  pub fn entries<T: DeserializeOwned>(
    &self,
    section: &str,
    mut check: impl FnMut(&[u8], &T, &str),
  ) -> BTreeMap<String, T> {
    let val = self
      .root
      .get(section)
      .unwrap_or_else(|| panic!("{}: missing section '{section}'", self.name));
    let entries: BTreeMap<String, CorpusEntry<T>> =
      serde_json::from_value(val.clone()).unwrap_or_else(|e| panic!("{}: section '{section}': {e}", self.name));
    assert!(!entries.is_empty(), "{}: section '{section}' empty", self.name);

    let mut result = BTreeMap::new();
    for (label, entry) in entries {
      let bytes = decode_to_vec(&entry.raw).unwrap_or_else(|e| panic!("{section}/{label}: hex: {e}"));
      check(&bytes, &entry.details, &label);
      result.insert(label, entry.details);
    }
    result
  }

  /// Opens and parses `<manifest_dir>/corpus/<name>.json5`.
  ///
  /// # Panics
  ///
  /// Panics if the file cannot be read or parsed.
  pub fn open(manifest_dir: &str, name: &str) -> Self {
    let path = format!("{manifest_dir}/corpus/{name}.json5");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    Self::parse(name, &text)
  }

  /// Returns a sub-corpus rooted at `key`, for files that nest their
  /// sections under an outer key such as the scheme name.
  ///
  /// # Panics
  ///
  /// Panics if the key is absent from the current root.
  pub fn scope(&self, key: &str) -> Self {
    let val = self
      .root
      .get(key)
      .unwrap_or_else(|| panic!("{}: missing key '{key}'", self.name));
    Self {
      name: format!("{}/{key}", self.name),
      root: val.clone(),
    }
  }

  /// Returns a named section as one typed value, `{ section: T }`, for
  /// sections that hold a single object rather than an array.
  ///
  /// # Panics
  ///
  /// Panics if the section is missing or does not deserialize as `T`.
  pub fn value<T: DeserializeOwned>(&self, section: &str) -> T {
    let val = self
      .root
      .get(section)
      .unwrap_or_else(|| panic!("{}: missing section '{section}'", self.name));
    serde_json::from_value(val.clone()).unwrap_or_else(|e| panic!("{}: section '{section}': {e}", self.name))
  }

  /// Returns a named array section as typed vectors: `{ section: [T, ...] }`.
  ///
  /// # Panics
  ///
  /// Panics if the section is missing, empty, or is not an array of `T`.
  pub fn vectors<T: ::serde::de::DeserializeOwned>(&self, section: &str) -> Vec<T> {
    let val = self
      .root
      .get(section)
      .unwrap_or_else(|| panic!("{}: missing section '{section}'", self.name));
    let out: Vec<T> =
      serde_json::from_value(val.clone()).unwrap_or_else(|e| panic!("{}: section '{section}': {e}", self.name));
    assert!(!out.is_empty(), "{}: section '{section}' empty", self.name);
    out
  }
}
