#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate Bazel's build files and hold what Bazel builds to cargo's.

The 'graph' verb queries Bazel, which fetches the toolchains, so 'lint_all'
leaves it to its own 'just lint' step.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
import urllib.request
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

# Every host lints with this buildifier release, as releases disagree on
# warnings. Digests from the release page, keyed by the asset suffix.
_BUILDIFIER_VERSION = "10.1.0"
_BUILDIFIER_SHA256S = {
  "darwin-amd64": (
    "e9e10ff52ec8786fcabccd251c8109ebf31ef7be1f667e27c6e069b96dbdc1f6"
  ),
  "darwin-arm64": (
    "e9804864c407f920f5ecbf03a5e056a8145e11a6ae6b90d2438a3fd106d34473"
  ),
  "linux-amd64": (
    "31b6a8aa1e5c746696788f428729701770ad91925873d8256cb885c60e12c77e"
  ),
  "linux-arm64": (
    "38d2ed845f560b4a16ddee41de906508a95f8dc85b04e0851b0a71e3a70d3890"
  ),
  "windows-amd64.exe": (
    "931a6e9c3844b90ccdb1467ccacd8dd72457e308d2709d624a3c5880d835ac3c"
  ),
  "windows-arm64.exe": (
    "aeffa5a342ce119b52cd7aa17bd9dda22b0406245d90643985749d01f51d2de1"
  ),
}
_BUILDIFIER_URL = (
  "https://github.com/bazelbuild/buildtools/releases/download"
  "/v{version}/buildifier-{asset}"
)

# The file restating the workspace lints.
_RUST_BZL = "bazel/rust.bzl"

# The file defining profiles, target flags and Rust edition.
_WORKSPACE_BZL = "bazel/workspace.bzl"

# The profile keys the toolchains restate. 'Cargo.toml' must pin each one, so a
# change of Cargo's defaults cannot shift either build.
_PROFILE_KEYS = (
  "codegen-units",
  "debug",
  "debug-assertions",
  "lto",
  "opt-level",
  "overflow-checks",
  "panic",
  "strip",
)

# The 'PROFILE_RUSTC_FLAGS' entry that restates each Cargo profile.
_PROFILE_ARMS = {"dev": "debug", "release": "release"}

# Cargo's named 'debug' levels, as the debuginfo level rustc takes.
_DEBUG_LEVELS = {"full": 2, "limited": 1, "none": 0}

# rustc's flag letter for each lint level.
_LINT_LEVELS = {"allow": "A", "deny": "D", "forbid": "F", "warn": "W"}

# A '.cargo/config.toml' target key naming one architecture.
_TARGET_ARCH_RE = re.compile(r'^cfg\(target_arch = "(\w+)"\)$')

# The halves of a `//bazel` platform name, as 'bazel/BUILD.bazel' spells
# them, keyed by the parts of the triple they stand for.
_PLATFORM_OS = {
  "apple-darwin": "macos",
  "pc-windows-gnu": "windows",
  "unknown-linux-gnu": "linux",
}
_PLATFORM_ARCH = {"aarch64": "arm64", "x86_64": "x86_64"}


def _platform(triple: str) -> str:
  """Return the `//bazel` platform label that builds for *triple*."""
  arch, _, rest = triple.partition("-")
  return f"//bazel:{_PLATFORM_OS[rest]}_{_PLATFORM_ARCH[arch]}"


def _profile_flags(settings: dict[str, object]) -> set[str]:
  """Return the rustc flags a Cargo profile's *settings* amount to."""
  yes = {True: "yes", False: "no"}
  # A bool is told apart first, since 'True == 1' would read level 1 as full.
  debug = settings["debug"]
  if isinstance(debug, bool):
    debug = 2 if debug else 0
  flags = {
    f"-Ccodegen-units={settings['codegen-units']}",
    f"-Cdebug-assertions={yes[bool(settings['debug-assertions'])]}",
    f"-Cdebuginfo={_DEBUG_LEVELS.get(debug, debug)}",
    f"-Copt-level={settings['opt-level']}",
    f"-Coverflow-checks={yes[bool(settings['overflow-checks'])]}",
    f"-Cpanic={settings['panic']}",
    f"-Cstrip={settings['strip']}",
  }
  # Cargo's 'false' leaves rustc's default, thin local LTO, in place. The
  # string 'off' disables it with '-Clto=off'.
  lto = settings["lto"]
  if lto is not False:
    flags.add(f"-Clto={'fat' if lto is True else lto}")
  return flags


def _rustflags(argv: list[str]) -> set[str]:
  """Return '-C' arguments split across two items as single flags."""
  flags: set[str] = set()
  pending = False
  for item in argv:
    if item == "-C":
      pending = True
      continue
    flags.add(f"-C{item}" if pending else item)
    pending = False
  return flags


def _literals(path: Path) -> dict[str, object]:
  """Return the top-level assignments of a Starlark file that are literals."""
  found: dict[str, object] = {}
  for node in ast.parse(path.read_text(encoding="utf-8"), str(path)).body:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
      continue
    target = node.targets[0]
    if not isinstance(target, ast.Name):
      continue
    try:
      found[target.id] = ast.literal_eval(node.value)
    except ValueError:
      continue
  return found


def _check_sync(repo_root: Path) -> int:
  """Hold Bazel's rustc flags and edition to the Cargo settings."""
  lints = _literals(repo_root / _RUST_BZL)
  defs = _literals(repo_root / _WORKSPACE_BZL)
  manifest = tomllib.loads(
    (repo_root / "Cargo.toml").read_text(encoding="utf-8"),
  )
  config = tomllib.loads(
    (repo_root / ".cargo" / "config.toml").read_text(encoding="utf-8"),
  )

  rows: list[tuple[str, str, str]] = []

  def hold(what: str, bazel: set[str], cargo: set[str]) -> None:
    if bazel != cargo:
      rows.append((
        what,
        " ".join(sorted(bazel - cargo)) or "-",
        " ".join(sorted(cargo - bazel)) or "-",
      ))

  profiles = manifest.get("profile", {})
  arms = defs["PROFILE_RUSTC_FLAGS"]
  for profile, arm in _PROFILE_ARMS.items():
    settings = profiles.get(profile, {})
    unpinned = [key for key in _PROFILE_KEYS if key not in settings]
    if unpinned:
      rows.append((f"profile.{profile}", "-", f"unpinned {' '.join(unpinned)}"))
      continue
    hold(f"profile.{profile}", set(arms.get(arm, [])), _profile_flags(settings))

  rust_lints = manifest["workspace"]["lints"]["rust"]
  hold(
    "workspace.lints.rust",
    set(lints["RUSTC_LINTS"]),
    {
      f"-{_LINT_LEVELS[v if isinstance(v, str) else v['level']]}{name}"
      for name, v in rust_lints.items()
    },
  )

  hold(
    "workspace.package.edition",
    {str(defs["RUST_EDITION"])},
    {str(manifest["workspace"]["package"]["edition"])},
  )

  # Only per-architecture tables have a toolchain to restate them in.
  if "rustflags" in config.get("build", {}):
    rows.append(("build.rustflags", "-", "unsupported, use a target table"))
  cargo_targets: dict[str, set[str]] = {}
  for key, table in config.get("target", {}).items():
    found = _TARGET_ARCH_RE.match(key)
    if found is None:
      rows.append((f"target.'{key}'", "-", "unsupported, key on target_arch"))
      continue
    cargo_targets[found.group(1)] = _rustflags(table.get("rustflags", []))

  # An architecture no host toolchain builds for has nothing to compare.
  targets = defs["TARGET_RUSTC_FLAGS"]
  built = {triple.split("-")[0] for triple in defs["HOST_TRIPLES"].values()}
  for arch in sorted(built | set(targets)):
    hold(
      f"target {arch}",
      set(targets.get(arch, [])),
      cargo_targets.get(arch, set()),
    )

  if not rows:
    print("bazel matches the Cargo profiles, lints, target flags and edition")
    return RETCODE_PASS
  print(
    format_table(("setting", "only in bazel", "only in cargo"), rows),
    file=sys.stderr,
  )
  print(f"error: {len(rows)} setting(s) differ from cargo", file=sys.stderr)
  return RETCODE_ERR


def _buildifier(repo_root: Path) -> str | None:
  """Return `BUILDIFIER`, else the pinned release fetched into '.cache'.

  None where no release is pinned for the host.
  """
  if override := os.environ.get("BUILDIFIER"):
    # The tool runs from the repository root, so a path relative to the
    # caller's directory is made absolute first.
    return str(Path(require_bin(override)).resolve())
  system = platform.system().lower()
  machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(
    platform.machine().lower(),
    platform.machine().lower(),
  )
  asset = f"{system}-{machine}" + (".exe" if system == "windows" else "")
  if asset not in _BUILDIFIER_SHA256S:
    return None
  want = _BUILDIFIER_SHA256S[asset]
  path = repo_root / ".cache" / "buildifier" / _BUILDIFIER_VERSION / asset
  if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == want:
    return str(path)

  url = _BUILDIFIER_URL.format(version=_BUILDIFIER_VERSION, asset=asset)
  with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
    data = response.read()
  got = hashlib.sha256(data).hexdigest()
  if got != want:
    raise ValueError(f"{url} has sha256 {got}, expected {want}")
  path.parent.mkdir(parents=True, exist_ok=True)
  partial = path.with_suffix(".partial")
  partial.write_bytes(data)
  partial.chmod(0o755)
  partial.replace(path)
  return str(path)


def _check_format(
  repo_root: Path,
  *,
  fix: bool,
  only: list[str] | None = None,
) -> int | None:
  """Format and lint Starlark, or None when buildifier is unavailable.

  A fetch that fails or a release whose digest differs is an error, so a
  network fault cannot pass the Starlark unchecked.
  """
  try:
    buildifier = _buildifier(repo_root)
  except FileNotFoundError as e:
    print(f"{e}, skipping Starlark", file=sys.stderr)
    return None
  except (OSError, ValueError) as e:
    print(f"error: fetching buildifier failed ({e})", file=sys.stderr)
    return RETCODE_ERR
  if buildifier is None:
    print("no buildifier pinned for this host, skipping", file=sys.stderr)
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


def _bazel_crates(
  bazel: str,
  repo_root: Path,
  platform: str,
) -> dict[Crate, set[str]]:
  """Return the features Bazel hands rustc, per crate it builds for *platform*.

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
      f"--platforms={platform}",
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
      "hint: run 'just lock' if 'MODULE.bazel.lock' is out of date",
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
  triple: str,
) -> dict[Crate, list[set[str]]]:
  """Return the feature sets cargo resolves for *scope* on *triple*, per crate.

  A crate reached as a normal and as a build dependency can resolve twice,
  since cargo keeps host and target features apart; both sets are kept.
  """
  result = subprocess.run(  # noqa: S603
    [
      cargo,
      "tree",
      *scope,
      "--target", triple,
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


def _annotated(repo_root: Path) -> dict[str, set[str]]:
  """Return the features each 'crate.annotation' in 'MODULE.bazel' adds."""
  source = (repo_root / "MODULE.bazel").read_text(encoding="utf-8")
  added: dict[str, set[str]] = {}
  for node in ast.walk(ast.parse(source, "MODULE.bazel")):
    if not (
      isinstance(node, ast.Call)
      and isinstance(node.func, ast.Attribute)
      and node.func.attr == "annotation"
    ):
      continue
    kwargs = {k.arg: ast.literal_eval(k.value) for k in node.keywords}
    features = set(kwargs.get("crate_features", []))
    added.setdefault(kwargs["crate"], set()).update(features)
  return added


def _graph_faults(
  cargo: str,
  bazel: str,
  repo_root: Path,
  triple: str,
  annotated: dict[str, set[str]],
) -> list[tuple[str, ...]]:
  """Return a row per crate Bazel builds for *triple* unlike cargo's."""
  theirs = _bazel_crates(bazel, repo_root, _platform(triple))
  # An annotation adds a feature cargo never resolves, so it is set aside.
  for (name, version), features in theirs.items():
    if version != "":
      features -= annotated.get(name, set())
  built = sorted(name for name, version in theirs if version == "")

  # What the mapped crates reach with the anchor's features is the floor Bazel
  # must cover. 'crate_universe' unifies the whole workspace with every
  # feature on, which is the ceiling for third-party crates.
  anchored = _cargo_crates(
    cargo, repo_root, ["--package", ANCHOR], "normal,build", triple,
  )
  scope = [arg for name in built for arg in ("--package", name)]
  scope += [
    arg
    for name in built
    if "full" in next(iter(anchored.get((name, ""), [set()])))
    for arg in ("--features", f"{name}/full")
  ]
  reached = (
    _cargo_crates(cargo, repo_root, scope, "normal,build", triple)
    if built
    else {}
  )
  unified = _cargo_crates(
    cargo,
    repo_root,
    ["--workspace", "--all-features"],
    "normal,build,dev",
    triple,
  )
  print(
    f"checking crate graph for {triple}: {len(theirs)} crate(s) in bazel "
    f"against {len(reached)} cargo reaches from {len(built)} mapped crate(s)",
  )

  def show(features: set[str]) -> str:
    return ",".join(sorted(features)) or "(none)"

  rows: list[tuple[str, ...]] = []
  for key in sorted(set(theirs) | set(reached)):
    label = f"{key[0]} {key[1]}".strip()
    if key not in theirs:
      rows.append(
        (triple, label, "absent", show(reached[key][0]), "missing in bazel"),
      )
      continue
    if key not in unified:
      rows.append(
        (triple, label, show(theirs[key]), "absent", "extra in bazel"),
      )
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
        triple,
        label,
        show(theirs[key]),
        " or ".join(show(f) for f in expected) or "absent",
        fault,
      ))
  if not rows:
    print(f"{triple}: {len(theirs)} crate(s) match what cargo resolves")
  return rows


def _check_graph(repo_root: Path) -> int | None:
  """Hold Bazel's crates and their features to cargo's; None without a tool.

  Each target is held apart, since a dependency can pick crates by the
  platform it is built for.
  """
  try:
    cargo = require_bin("cargo")
    bazel = require_bin("bazel")
  except FileNotFoundError as e:
    print(f"{e}, skipping the crate graph check", file=sys.stderr)
    return None
  if sys.platform == "win32":
    print("unsupported host, skipping the crate graph check", file=sys.stderr)
    return None

  annotated = _annotated(repo_root)
  rows = [("", *row) for row in _anchor_faults(cargo, repo_root)]
  for triple in _literals(repo_root / _WORKSPACE_BZL)["CROSS_TRIPLES"]:
    rows += _graph_faults(cargo, bazel, repo_root, triple, annotated)
  if not rows:
    return RETCODE_PASS

  print(
    format_table(("target", "crate", "bazel", "cargo", "fault"), rows),
    file=sys.stderr,
  )
  print(f"error: {len(rows)} crate(s) differ from cargo", file=sys.stderr)
  print(
    f"hint: {ANCHOR} depends on every crate in '{PUBLISHABLE}/'; workspace "
    "crates restate their features in 'crate_features'; third-party ones "
    "follow the manifests listed in 'MODULE.bazel', so run 'just lock' "
    "after changing a manifest",
    file=sys.stderr,
  )
  return RETCODE_ERR


def main() -> int:
  args = declare_verbs(
    "Validate Starlark and hold what Bazel builds to cargo's settings.",
    {
      "check": "report every Starlark fault and flag drift, changing nothing",
      "apply": f"also rewrite Starlark this branch changed vs {DEFAULT_BASE}",
      "apply-all": "also rewrite every Starlark file in the tree",
      "graph": "hold the crates Bazel builds and their features to cargo's",
    },
  ).parse_args(sys.argv[1:])
  repo_root = root_dir()

  # The graph check queries Bazel, which fetches the toolchains, so it runs
  # only when asked; the Starlark and flag passes are cheap enough for every
  # lint run.
  if args.verb == "graph":
    verdict = _check_graph(repo_root)
    return RETCODE_SKIP if verdict is None else verdict

  fix = args.verb.startswith("apply")
  only = touched(repo_root, STARLARK_SUFFIXES) if args.verb == "apply" else None
  verdicts = [
    _check_format(repo_root, fix=fix, only=only),
    _check_sync(repo_root),
  ]
  ran = [v for v in verdicts if v is not None]
  if not ran:
    return RETCODE_SKIP
  return RETCODE_ERR if any(v != RETCODE_PASS for v in ran) else RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
