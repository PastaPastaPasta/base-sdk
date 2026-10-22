/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Crate-specific policy configuration.
 */

import lib.files
import rust

/**
 * Holds if the crate `crate` answers to each policy `policies` lists.
 * Rows live in `crates.model.yml`.
 */
extensible private predicate cratePolicyEnable(string crate, string policies);

/** Gets the package name the directory path `segments` spells. */
bindingset[segments]
private string packageName(string segments) {
  result = "dash-" + segments.replaceAll("_", "-").replaceAll("/", "-")
}

/** Holds if a crate directory named `crate` holds `f`. */
private predicate encloses(string crate, File f) {
  exists(string path | path = f.getAbsolutePath() |
    crate = packageName(path.regexpCapture(".*/(?:meta|pkgs)/([^/]+)/.*", 1))
    or
    crate = packageName(path.regexpCapture(".*/(?:meta|pkgs)/([^/]+/[^/]+)/.*", 1))
    or
    crate = packageName(path.regexpCapture(".*/fuzz/([^/]+)/.*", 1)) + "-fuzz"
  )
}

/** Gets the name of the crate holding `f`. */
string crateOf(File f) {
  encloses(result, f) and
  cratePolicyEnable(result, _) and
  not exists(string inner |
    encloses(inner, f) and
    cratePolicyEnable(inner, _) and
    inner.matches(result + "-%")
  )
}

/** Holds if `f` belongs to a crate that answers to `policy`. */
private predicate hasPolicy(File f, string policy) {
  exists(string policies |
    cratePolicyEnable(crateOf(f), policies) and
    policy = policies.splitAt(",").trim() and
    policy != ""
  )
}

/** Holds if file `f` is in a crate subject to codec and ordering rules. */
predicate isEnforcedCrate(File f) { hasPolicy(f, "enforced") }

/** Holds if file `f` is in a crate that does not have a `serde` feature. */
predicate isNonSerdeCrate(File f) { hasPolicy(f, "no-serde") }

/** Holds if file `f` is in a crate whose single-field wrappers are opaque. */
predicate isOpaqueCrate(File f) { hasPolicy(f, "opaque") }

/** Holds if file `f` is in a crate with no public API. */
predicate isPrivateCrate(File f) { hasPolicy(f, "private") }

/** Holds if file `f` is in a crate with no derivations expected. */
predicate isNoDeriveCrate(File f) { hasPolicy(f, "no-derive") }

/** Holds if file `f` is in a crate that can derive `Unencodable`. */
predicate isUnencodableCrate(File f) { hasPolicy(f, "unencodable") }
