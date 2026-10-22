#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate Bazel's build files and hold its crate graph to cargo's.

The 'graph' verb queries Bazel, which fetches the toolchains, so 'lint_all'
leaves it to its own 'just lint' step.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from common import (
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  declare_verbs,
  format_table,
  formatted,
  relay,
  repo_files,
  require_bin,
  root_dir,
  touched,
)

# Base name of this script (equivalent to argv[0]).
SCRIPT = Path(__file__).stem

# Spellings of a Starlark file buildifier understands.
STARLARK_SUFFIXES: tuple[str, ...] = (".bazel", ".bzl")

# The crate whose manifest is the root of the graph 'crate_universe' reads.
ANCHOR = "dash-meta-bazel"

# Directory of every publishable crate, each of which the anchor depends on.
PUBLISHABLE = "pkgs"

# Rule kinds whose 'crate_features' is a transcription of cargo's.
RUST_KINDS = "rust_library|rust_proc_macro"

# A third-party crate's repository, 'crates__<name>-<version>'.
CRATE_REPO = re.compile(r"crate\+crates__(?P<name>.+?)-(?P<version>\d[^/]*)$")

# 'name vX.Y.Z (source)|feat,feat' as 'cargo tree -f "{p}|{f}"' writes it.
TREE_ENTRY = re.compile(
  r"^(?P<name>\S+) v(?P<version>\S+)(?: \([^)]*\))*\|(?P<f>.*)$",
)

Crate = tuple[str, str]


def _check_format(
  repo_root: Path,
  *,
  fix: bool,
  only: list[str] | None = None,
) -> int | None:
  """Format and lint Starlark, or None when buildifier is absent."""
  try:
    buildifier = require_bin("buildifier")
  except FileNotFoundError as e:
    print(f"{e}, skipping the Starlark check", file=sys.stderr)
    return None

  sources = (
    repo_files(repo_root, *(f"*{s}" for s in STARLARK_SUFFIXES))
    if only is None
    else [Path(n) for n in only]
  )
  mode = "fix" if fix else "check"
  return formatted(
    SCRIPT,
    "Starlark file",
    sources,
    lambda paths: [
      buildifier,
      f"--mode={mode}",
      f"--lint={'fix' if fix else 'warn'}",
      *[str(p) for p in paths],
    ],
    fix=fix,
    scoped=only is not None,
    cwd=repo_root,
    output=lambda out, err: (
      relay(out, repo_root),
      relay(err, repo_root, stream=sys.stderr),
    ),
  )


def _bazel_crates(bazel: str, repo_root: Path) -> dict[Crate, set[str]]:
  """Return the features Bazel hands rustc, per crate it builds.

  Asked of 'cquery' so a 'select()' arrives flattened to the arm this build
  takes. Third-party crates are keyed by repository, workspace crates by name.
  """
  result = subprocess.run(  # noqa: S603
    [
      bazel,
      # Matches the output root 'bazel/shim.py' hands Bazel.
      f"--output_user_root={repo_root / '.cache' / 'bazel'}",
      "cquery",
      f'kind("{RUST_KINDS}", deps(//...))',
      "--output=jsonproto",
    ],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    # Matches the bazelisk cache 'bazel/mod.just' exports.
    env={**os.environ, "BAZELISK_HOME": str(repo_root / ".cache" / "bazelisk")},
    text=True,
  )
  if result.returncode != 0:
    relay(result.stderr, repo_root, stream=sys.stderr)
    print(
      "hint: run 'just zglock' if 'MODULE.bazel.lock' is out of date",
      file=sys.stderr,
    )
    raise RuntimeError(f"bazel cquery failed with {result.returncode}")

  found: dict[Crate, set[str]] = {}
  for entry in json.loads(result.stdout).get("results", []):
    rule = entry["target"]["rule"]
    attrs = {a["name"]: a for a in rule["attribute"]}
    repo, _, _ = rule["name"].partition("//")
    third_party = CRATE_REPO.search(repo)
    if third_party is not None:
      key = (third_party["name"], third_party["version"])
    elif repo:
      continue
    else:
      name = attrs["crate_name"]["stringValue"].replace("_", "-")
      key = (name, "")
    features = attrs.get("crate_features", {}).get("stringListValue", [])
    found.setdefault(key, set()).update(features)
  return found


def _cargo_crates(
  cargo: str,
  repo_root: Path,
  scope: list[str],
  edges: str,
) -> dict[Crate, list[set[str]]]:
  """Return the feature sets cargo resolves for *scope*, per crate.

  A crate reached as a normal and as a build dependency can resolve twice,
  since cargo keeps host and target features apart; both sets are kept.
  """
  result = subprocess.run(  # noqa: S603
    [
      cargo,
      "tree",
      *scope,
      "--edges", edges,
      "--format", "{p}|{f}",
      "--color", "never",
      "--prefix", "none",
      "--quiet",
    ],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  if result.returncode != 0:
    relay(result.stderr, repo_root, stream=sys.stderr)
    raise RuntimeError(f"cargo tree failed with {result.returncode}")

  resolved: dict[Crate, list[set[str]]] = {}
  for raw in result.stdout.splitlines():
    line = raw.strip().removesuffix(" (*)")
    if not line:
      continue
    entry = TREE_ENTRY.match(line)
    if entry is None:
      raise ValueError(f"unparsed cargo tree line {line!r}")
    if entry["name"] == ANCHOR:
      continue
    is_workspace = entry["name"].startswith("dash-")
    # Bazel's repository names spell build metadata's '+' as '-'.
    version = entry["version"].replace("+", "-")
    key = (entry["name"], "" if is_workspace else version)
    found = {f for f in entry["f"].split(",") if f}
    seen = resolved.setdefault(key, [])
    if found not in seen:
      seen.append(found)
  return resolved


def _anchor_faults(cargo: str, repo_root: Path) -> list[tuple[str, ...]]:
  """Return a row per publishable crate the anchor misses and per extra one."""
  result = subprocess.run(  # noqa: S603
    [cargo, "metadata", "--format-version", "1", "--no-deps", "--quiet"],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  if result.returncode != 0:
    relay(result.stderr, repo_root, stream=sys.stderr)
    raise RuntimeError(f"cargo metadata failed with {result.returncode}")

  packages = json.loads(result.stdout)["packages"]
  publishable = {
    p["name"]
    for p in packages
    if Path(p["manifest_path"]).is_relative_to(repo_root / PUBLISHABLE)
  }
  anchor = next(p for p in packages if p["name"] == ANCHOR)
  anchored = {d["name"] for d in anchor["dependencies"] if d.get("path")}
  print(
    f"checking anchor: {ANCHOR} against {len(publishable)} crate(s) in "
    f"'{PUBLISHABLE}/'",
  )

  rows = [
    (name, "", "", f"missing in {ANCHOR}")
    for name in sorted(publishable - anchored)
  ]
  rows += [
    (name, "", "", f"not publishable, extra in {ANCHOR}")
    for name in sorted(anchored - publishable)
  ]
  return rows


def _check_graph(repo_root: Path) -> int | None:
  """Hold Bazel's crates and their features to cargo's; None without a tool."""
  try:
    cargo = require_bin("cargo")
    bazel = require_bin("bazel")
  except FileNotFoundError as e:
    print(f"{e}, skipping the crate graph check", file=sys.stderr)
    return None
  if sys.platform == "win32":
    print("unsupported host, skipping the crate graph check", file=sys.stderr)
    return None

  theirs = _bazel_crates(bazel, repo_root)
  built = sorted(name for name, version in theirs if version == "")

  # What the mapped crates reach with the anchor's features is the floor Bazel
  # must cover. 'crate_universe' unifies the whole workspace with every
  # feature on, which is the ceiling for third-party crates.
  anchored = _cargo_crates(
    cargo, repo_root, ["--package", ANCHOR], "normal,build",
  )
  scope = [arg for name in built for arg in ("--package", name)]
  scope += [
    arg
    for name in built
    if "full" in next(iter(anchored.get((name, ""), [set()])))
    for arg in ("--features", f"{name}/full")
  ]
  reached = (
    _cargo_crates(cargo, repo_root, scope, "normal,build") if built else {}
  )
  unified = _cargo_crates(
    cargo, repo_root, ["--workspace", "--all-features"], "normal,build,dev",
  )
  print(
    f"checking crate graph: {len(theirs)} crate(s) in bazel against "
    f"{len(reached)} cargo reaches from {len(built)} mapped crate(s)",
  )

  def show(features: set[str]) -> str:
    return ",".join(sorted(features)) or "(none)"

  rows = _anchor_faults(cargo, repo_root)
  for key in sorted(set(theirs) | set(reached)):
    label = f"{key[0]} {key[1]}".strip()
    if key not in theirs:
      rows.append((label, "absent", show(reached[key][0]), "missing in bazel"))
      continue
    if key not in unified:
      rows.append((label, show(theirs[key]), "absent", "extra in bazel"))
      continue
    # Workspace crates restate their features, so they must equal what the
    # anchor resolves. A third-party crate lies between the floor and ceiling.
    if key[1] == "":
      expected = anchored.get(key, [])
      fault = None if theirs[key] in expected else "features differ"
    elif not all(f <= theirs[key] for f in reached.get(key, [])):
      expected, fault = reached[key], "features fall short of cargo's"
    else:
      expected = unified[key]
      ok = any(theirs[key] <= f for f in expected)
      fault = None if ok else "features exceed cargo's"
    if fault is not None:
      rows.append((
        label,
        show(theirs[key]),
        " or ".join(show(f) for f in expected) or "absent",
        fault,
      ))

  if not rows:
    print(f"{len(theirs)} crate(s) match what cargo resolves")
    return RETCODE_PASS

  print(
    format_table(("crate", "bazel", "cargo", "fault"), rows),
    file=sys.stderr,
  )
  print(f"error: {len(rows)} crate(s) differ from cargo", file=sys.stderr)
  print(
    f"hint: {ANCHOR} depends on every crate in '{PUBLISHABLE}/'; workspace "
    "crates restate their features in 'crate_features'; third-party ones "
    "follow the manifests listed in 'MODULE.bazel', so run 'just zglock' "
    "after changing a manifest",
    file=sys.stderr,
  )
  return RETCODE_ERR


def main() -> int:
  args = declare_verbs(
    "Validate Starlark and the crate graph Bazel builds.",
    {
      "check": "report every Starlark fault, changing nothing",
      "apply": f"also rewrite Starlark this branch changed vs {DEFAULT_BASE}",
      "apply-all": "also rewrite every Starlark file in the tree",
      "graph": "hold the crates Bazel builds and their features to cargo's",
    },
  ).parse_args(sys.argv[1:])
  repo_root = root_dir()

  # The graph check queries Bazel, which fetches the toolchains, so it runs
  # only when asked; the Starlark passes are cheap enough for every lint run.
  if args.verb == "graph":
    verdict = _check_graph(repo_root)
  else:
    fix = args.verb.startswith("apply")
    only = (
      touched(repo_root, STARLARK_SUFFIXES) if args.verb == "apply" else None
    )
    verdict = _check_format(repo_root, fix=fix, only=only)

  return RETCODE_SKIP if verdict is None else verdict


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
