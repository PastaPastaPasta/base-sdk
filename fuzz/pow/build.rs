//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Builds the sphlib reference implementations behind a one-call shim.

const STAGES: [&str; 2] = ["blake", "bmw"];

fn main() {
  let mut build = cc::Build::new();
  build.include("sphlib/c").file("src/shim.c").warnings(false);
  for stage in STAGES {
    build.file(format!("sphlib/c/{stage}.c"));
  }
  build.compile("sph");
  println!("cargo::rerun-if-changed=src/shim.c");
  println!("cargo::rerun-if-changed=sphlib/c");
}
