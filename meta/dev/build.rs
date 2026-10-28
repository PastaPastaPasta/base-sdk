//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Emits a `TypeId` collision-check table from workspace sources.

#![expect(clippy::expect_used, clippy::unwrap_used, clippy::panic, reason = "build script")]

use dash_types::type_id::mix;
use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{visit_item_enum, visit_item_impl, visit_item_macro, visit_item_struct, Visit};
use syn::{parse_file, Attribute, Generics, Ident, ItemEnum, ItemImpl, ItemMacro, ItemStruct};
use syn::{Type, TypeParam, TypeParamBound, WherePredicate};
use xxhash_rust::xxh32::xxh32;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::{env, fs};

const SCAN_DIRS: &[&str] = &[
  "pkgs/num/src",
  "pkgs/types/src",
  "pkgs/primitives/src",
  "pkgs/p2p_core/src",
  "pkgs/pkc/src",
];

fn main() {
  let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
  let ws_root = PathBuf::from(&manifest)
    .parent()
    .unwrap()
    .parent()
    .unwrap()
    .to_path_buf();

  let mut scan = ScanResult::default();

  for dir in SCAN_DIRS {
    let src = ws_root.join(dir);
    if src.is_dir() {
      walk_rs_files(&src, &mut |path| scan_file(path, &mut scan));
    }
    println!("cargo::rerun-if-changed={}", ws_root.join(dir).display());
  }

  for (macro_name, type_name) in &scan.pending {
    if scan.type_id_macros.contains(macro_name) {
      scan.names.push(type_name.clone());
    }
  }

  let ids = emitted_ids(&scan);
  assert!(!ids.is_empty(), "scanner produced no TypeId entries");

  check_unique(&ids);

  built::write_built_file().expect("failed to write built.rs metadata");
}

/// Expands every derive site into the ids its instantiations carry.
///
/// A generic's base name only seeds the fold, so it is not an id any value
/// holds. Parameters resolve through their bounds and the cross product
/// folds through [`mix`], the same function the derive expands to.
fn emitted_ids(scan: &ScanResult) -> Vec<(String, u32)> {
  let mut out: Vec<(String, u32)> = scan
    .names
    .iter()
    .map(|name| (name.clone(), xxh32(name.as_bytes(), 0)))
    .collect();

  let mut plain: Vec<&str> = scan.names.iter().map(String::as_str).collect();
  plain.sort_unstable();
  plain.dedup();

  for site in &scan.generics {
    let seed = xxh32(site.name.as_bytes(), 0);
    let per_param: Vec<Vec<String>> = site
      .bounds
      .iter()
      .map(|bounds| implementors(scan, &plain, bounds))
      .collect();
    for (idx, args) in per_param.iter().enumerate() {
      assert!(
        !args.is_empty(),
        "{}: parameter {idx} bound has no id-bearing implementors",
        site.name
      );
    }

    let mut combos = vec![(String::new(), seed)];
    for args in &per_param {
      combos = combos
        .iter()
        .flat_map(|(label, acc)| {
          args.iter().map(move |arg| {
            let sep = if label.is_empty() { "" } else { ", " };
            (format!("{label}{sep}{arg}"), mix(*acc, xxh32(arg.as_bytes(), 0)))
          })
        })
        .collect();
    }
    out.extend(
      combos
        .into_iter()
        .map(|(args, id)| (format!("{}<{args}>", site.name), id)),
    );
  }

  out
}

/// Returns the `TypeId`-bearing types implementing every trait in `bounds`.
///
/// The `TypeId` bound is skipped. The derive supplies it, so no impl records
/// to match. If that leaves no bounds, the result is empty, which the caller
/// turns into a build failure naming the site.
fn implementors(scan: &ScanResult, plain: &[&str], bounds: &[String]) -> Vec<String> {
  let required: Vec<&str> = bounds.iter().map(String::as_str).filter(|b| *b != "TypeId").collect();
  if required.is_empty() {
    return Vec::new();
  }

  let implements = |ty: &str, tr: &str| scan.impls.iter().any(|(t, y)| t == tr && y == ty);
  let mut found: Vec<String> = plain
    .iter()
    .filter(|ty| required.iter().all(|tr| implements(ty, tr)))
    .map(|ty| (*ty).to_string())
    .collect();
  found.sort_unstable();
  found.dedup();
  found
}

/// Fails the build on a shared id, as it'd decode one type into another's slot.
///
/// # Panics
///
/// Panics when two distinct entries carry the same id.
fn check_unique(entries: &[(String, u32)]) {
  // One type arrives from several macros, so equal labels are one entry.
  let mut seen: HashMap<u32, &str> = HashMap::new();
  for (label, id) in entries {
    if let Some(prev) = seen.insert(*id, label) {
      if prev != label {
        panic!("TypeId collision: {label} and {prev} share id {id:#010x}");
      }
    }
  }
}

/// A generic derive site and the bounds that gate each type parameter.
struct GenericSite {
  /// Bare type name, seeding the fold.
  name: String,
  /// Bound trait names per type parameter, in declaration order.
  bounds: Vec<Vec<String>>,
}

#[derive(Default)]
struct ScanResult {
  /// `macro_rules!` names whose body contains `TypeId`.
  type_id_macros: BTreeSet<String>,
  /// Non-generic derive sites, where id is exactly the XXH32 of the name.
  names: Vec<String>,
  /// Generic derive sites, where the name hash is only the fold's seed.
  generics: Vec<GenericSite>,
  /// `(trait_name, type_name)` for every non-generic trait impl seen.
  impls: Vec<(String, String)>,
  /// Unresolved `(macro_name, type_name)` from invocation sites.
  pending: Vec<(String, String)>,
}

fn walk_rs_files(dir: &Path, cb: &mut dyn FnMut(&Path)) {
  let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
  for entry in entries {
    let path = entry
      .unwrap_or_else(|e| panic!("cannot read entry in {}: {e}", dir.display()))
      .path();
    if path.is_dir() {
      walk_rs_files(&path, cb);
    } else if path.extension().is_some_and(|e| e == "rs") {
      cb(&path);
    }
  }
}

fn scan_file(path: &Path, scan: &mut ScanResult) {
  let src = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
  let Ok(file) = parse_file(&src) else {
    panic!("cannot parse {}", path.display());
  };

  struct V<'a> {
    scan: &'a mut ScanResult,
  }

  impl V<'_> {
    fn has_type_id_derive(attrs: &[Attribute]) -> bool {
      attrs.iter().any(|attr| attr_derives_ident(attr, "TypeId"))
    }

    fn record(&mut self, ident: &Ident, generics: &Generics) {
      let params: Vec<&TypeParam> = generics.type_params().collect();
      if params.is_empty() {
        self.scan.names.push(ident.to_string());
        return;
      }
      self.scan.generics.push(GenericSite {
        name: ident.to_string(),
        bounds: params.iter().map(|p| param_bounds(p, generics)).collect(),
      });
    }
  }

  impl<'ast> Visit<'ast> for V<'_> {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
      if Self::has_type_id_derive(&node.attrs) {
        self.record(&node.ident, &node.generics);
      }
      visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
      if Self::has_type_id_derive(&node.attrs) {
        self.record(&node.ident, &node.generics);
      }
      visit_item_enum(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
      if let Some((_, path, _)) = &node.trait_ {
        if let (Some(seg), Some(ty)) = (path.segments.last(), bare_type_ident(&node.self_ty)) {
          self.scan.impls.push((seg.ident.to_string(), ty));
        }
      }
      visit_item_impl(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast ItemMacro) {
      if let Some(ident) = &node.ident {
        if tokens_contain_ident(&node.mac.tokens, "TypeId") {
          self.scan.type_id_macros.insert(ident.to_string());
        }
      }
      if let Some((macro_name, type_name)) = extract_macro_invocation(node) {
        self.scan.pending.push((macro_name, type_name));
      }
      visit_item_macro(self, node);
    }
  }

  V { scan }.visit_file(&file);
}

/// Collects the trait names bounding `param`, inline and in `where`.
fn param_bounds(param: &TypeParam, generics: &Generics) -> Vec<String> {
  let mut bounds: Vec<String> = param.bounds.iter().filter_map(trait_bound_name).collect();

  let predicates = generics.where_clause.iter().flat_map(|w| w.predicates.iter());
  for pred in predicates {
    let WherePredicate::Type(pred) = pred else {
      continue;
    };
    if bare_type_ident(&pred.bounded_ty).as_deref() == Some(&param.ident.to_string()) {
      bounds.extend(pred.bounds.iter().filter_map(trait_bound_name));
    }
  }

  bounds
}

/// Returns the final path segment of a trait bound, skipping lifetimes.
fn trait_bound_name(bound: &TypeParamBound) -> Option<String> {
  match bound {
    TypeParamBound::Trait(bound) => Some(bound.path.segments.last()?.ident.to_string()),
    _ => None,
  }
}

/// Returns the name of a plain path type, or `None` if it carries arguments.
fn bare_type_ident(ty: &Type) -> Option<String> {
  let Type::Path(ty) = ty else {
    return None;
  };
  if ty.qself.is_some() {
    return None;
  }
  let seg = ty.path.segments.last()?;
  seg.arguments.is_none().then(|| seg.ident.to_string())
}

/// Checks whether a token stream contains `target`, recursing into groups.
fn tokens_contain_ident(tokens: &TokenStream, target: &str) -> bool {
  tokens.clone().into_iter().any(|tt| match tt {
    TokenTree::Ident(id) => id == target,
    TokenTree::Group(g) => tokens_contain_ident(&g.stream(), target),
    _ => false,
  })
}

/// Checks whether an attribute derives `target`.
///
/// A `derive` lists it directly, while a `cfg_attr` nests it inside a
/// `derive(..)` group its predicate guards.
fn attr_derives_ident(attr: &Attribute, target: &str) -> bool {
  let Ok(list) = attr.meta.require_list() else {
    return false;
  };
  if attr.path().is_ident("derive") {
    return list
      .tokens
      .clone()
      .into_iter()
      .any(|tt| matches!(tt, TokenTree::Ident(ref id) if id == target));
  }
  attr.path().is_ident("cfg_attr") && derive_group_contains(&list.tokens, target)
}

/// Checks whether a `derive(..)` group in `tokens` carries `target`.
///
/// Only the groups a `derive` introduces count, so a predicate naming the
/// same ident elsewhere is not mistaken for one.
fn derive_group_contains(tokens: &TokenStream, target: &str) -> bool {
  let mut after_derive = false;
  for tt in tokens.clone() {
    match tt {
      TokenTree::Ident(ref id) => after_derive = id == "derive",
      TokenTree::Group(ref group) => {
        if after_derive && tokens_contain_ident(&group.stream(), target) {
          return true;
        }
        if derive_group_contains(&group.stream(), target) {
          return true;
        }
        after_derive = false;
      }
      _ => after_derive = false,
    }
  }
  false
}

/// Returns `(macro_name, last_UpperCamelCase_ident)` from an invocation.
fn extract_macro_invocation(node: &ItemMacro) -> Option<(String, String)> {
  let macro_name = node.mac.path.segments.last()?.ident.to_string();

  let mut last = None;
  for tt in node.mac.tokens.clone() {
    if let TokenTree::Ident(id) = &tt {
      let s = id.to_string();
      if s.starts_with(|c: char| c.is_uppercase()) {
        last = Some(s);
      }
    }
  }
  last.map(|name| (macro_name, name))
}
