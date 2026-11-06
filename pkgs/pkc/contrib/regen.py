#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Write the BLS corpora from the pinned reference implementation release.

Checks out the `dash` submodule next to this script if it is not yet, and
extracts the `src` tree of the release it pins into a build directory, with
relic's CMake configuration template patched back in and two steps of the
legacy map given external linkage for `gen_hash.cpp`. There CMake builds the
release's BLS library and each `gen_*.cpp` program here, and the build is kept
for later runs with the same compilers, flags, generator and patches. The
corpora are written only when every program succeeds.

Usage:

  ./pkgs/pkc/contrib/regen.py
  ./pkgs/pkc/contrib/regen.py --program keygen --corpus /tmp/bls
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import BinaryIO

HERE = Path(__file__).resolve().parent

# The repository root, which holds the submodule's pin.
ROOT = HERE.parents[2]

# The submodule pinned at the release the corpora are written from.
SUBMODULE = HERE / "dash"

# The patches applied to the release: relic's CMake configuration template,
# which the release omits, and the legacy map's steps `gen_hash.cpp` runs.
PATCHES = [
  HERE / "util" / name for name in ("relic_conf.patch", "legacy_steps.patch")
]

# Where the corpora are written by default.
CORPUS = HERE.parent / "corpus"

# Where the release is extracted and built by default.
BUILD = ROOT / "target" / "bls-corpus"

# The corpora written, each by the program of the same name.
PROGRAMS = sorted(
  path.stem.removeprefix("gen_") for path in HERE.glob("gen_*.cpp")
)

# The environment CMake reads when it first configures a build.
BUILD_ENV = ["CC", "CFLAGS", "CMAKE_GENERATOR", "CXX", "CXXFLAGS", "LDFLAGS"]

# The compilers CMake finds, by variable and the command it falls back to.
COMPILERS = {"CC": "cc", "CXX": "c++"}


class RegenError(Exception):
  """A step that failed."""


def run(
  cmd: list[str | Path],
  cwd: Path | None = None,
  log: BinaryIO | None = None,
  env: dict[str, str] | None = None,
) -> bytes:
  """Run *cmd* in *cwd* and return its output, or fail.

  With *log*, the output and errors go to that file instead.
  """
  try:
    proc = subprocess.run(  # noqa: S603
      cmd,
      cwd=cwd,
      check=True,
      env=env,
      stdout=log or subprocess.PIPE,
      stderr=subprocess.STDOUT if log else None,
    )
  except subprocess.CalledProcessError as err:
    name = Path(cmd[0]).name
    raise RegenError(f"{name} exited with {err.returncode}") from err
  return proc.stdout or b""


def pinned_release() -> str:
  """Return the staged pin, checking the submodule out if it is not yet.

  A submodule checked out at another commit is left as it is, and stops the
  run, so the corpora always come from the staged pin.
  """
  path = SUBMODULE.relative_to(ROOT).as_posix()
  git = ["git", "-C", ROOT]
  pin = run([*git, "rev-parse", f":{path}"]).decode().strip()
  if not (SUBMODULE / ".git").exists():
    update = ["submodule", "update", "--init", "--checkout", "--depth", "1"]
    run([*git, *update, "--", path])
  head = run(["git", "-C", SUBMODULE, "rev-parse", "HEAD"]).decode().strip()
  if head != pin:
    fix = f"git submodule update --init --checkout -- {path}"
    msg = f"the submodule is at {head}, not its staged pin {pin}"
    raise RegenError(f"{msg}, stage it or run {fix}")
  print(f"regen: writing from {pin}", file=sys.stderr)
  return pin


def build_dir(build: Path, pin: str) -> Path:
  """Return where *pin* is extracted and built under *build*.

  The name holds a digest of the environment CMake reads when it first
  configures, of the compilers it finds there and of the patches, so changing
  any of them, as a new compiler does, builds again.
  """
  env = [f"{n}={os.environ[n]}" for n in BUILD_ENV if os.environ.get(n)]
  for name, fallback in COMPILERS.items():
    command = (os.environ.get(name, "").split() or [fallback])[0]
    found = shutil.which(command)
    env.append(f"{name}:{Path(found).resolve() if found else command}")
  for patch in PATCHES:
    env.append(f"{patch.name}:{hashlib.sha256(patch.read_bytes()).hexdigest()}")
  digest = hashlib.sha256("\0".join(env).encode()).hexdigest()
  return build / f"{pin}-{digest[:12]}"


def extract(pin: str, src: Path) -> None:
  """Extract `src` of *pin* into *src* and apply the patches.

  The tree is prepared under a temporary name and then renamed, so an
  existing *src* is always complete.
  """
  src.parent.mkdir(parents=True, exist_ok=True)
  stage = Path(tempfile.mkdtemp(prefix=".extract-", dir=src.parent))
  try:
    archive = run(["git", "-C", SUBMODULE, "archive", pin, "src"])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
      tar.extractall(stage, filter="data")
    # The ceiling keeps git from finding the repository around the stage,
    # whose root the patch's paths would then be read against.
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(stage.parent)}
    for patch in PATCHES:
      run(["git", "apply", patch], cwd=stage, env=env)
    (stage / "src").rename(src)
  finally:
    shutil.rmtree(stage, ignore_errors=True)


def link_current(tree: Path) -> None:
  """Point `current` next to *tree* at it, for the C++ linters to read."""
  link = tree.with_name("current")
  stage = tree.with_name(".current")
  stage.unlink(missing_ok=True)
  stage.symlink_to(tree.name, target_is_directory=True)
  stage.replace(link)


def build(tree: Path, programs: list[str], jobs: int) -> Path:
  """Build *programs* in *tree* and return the directory holding them.

  The output goes to a log next to the build, named in the error when the
  build fails.
  """
  out = tree / "build"
  log = tree / "build.log"
  configure = ["cmake", "-S", HERE, "-B", out, f"-DDASH_SRC={tree / 'src'}"]
  targets = [f"gen_{name}" for name in programs]
  with log.open("wb") as sink:
    for cmd in [
      configure,
      ["cmake", "--build", out, "--parallel", str(jobs), "--target", *targets],
    ]:
      try:
        run(cmd, log=sink)
      except RegenError as err:
        msg = f"the build failed, see {log}; removing {tree} starts afresh"
        raise RegenError(msg) from err
  return out


def jobs_count(text: str) -> int:
  """Parse a number of parallel jobs, at least one."""
  jobs = int(text)
  if jobs < 1:
    raise argparse.ArgumentTypeError(f"{jobs} is not at least 1")
  return jobs


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description=__doc__.splitlines()[0] if __doc__ else None
  )
  parser.add_argument(
    "--program",
    action="append",
    choices=PROGRAMS,
    help="program whose corpus to write, by default every one",
  )
  parser.add_argument(
    "--corpus",
    type=Path,
    default=CORPUS,
    help="directory to write the corpora to, by default the crate's",
  )
  parser.add_argument(
    "--build",
    type=Path,
    default=BUILD,
    help=f"directory to build in, by default {BUILD.relative_to(ROOT)}",
  )
  parser.add_argument(
    "--jobs",
    type=jobs_count,
    default=os.cpu_count() or 1,
    help="parallel build jobs, by default one per processor",
  )
  return parser.parse_args()


def main() -> None:
  args = parse_args()
  programs = list(dict.fromkeys(args.program or PROGRAMS))
  pin = pinned_release()
  tree = build_dir(args.build.resolve(), pin)
  if not (tree / "src").is_dir():
    extract(pin, tree / "src")
  out = build(tree, programs, args.jobs)
  link_current(tree)
  output = {name: run([out / f"gen_{name}"]) for name in programs}
  args.corpus.mkdir(parents=True, exist_ok=True)
  for name, text in output.items():
    path = args.corpus / f"bls_{name}.json5"
    # Each corpus is replaced only once it is written in full, so a failed
    # run leaves the old one as it was.
    tmp = path.with_name(f".{path.name}.tmp")
    try:
      tmp.write_bytes(text)
      os.replace(tmp, path)
    finally:
      tmp.unlink(missing_ok=True)


if __name__ == "__main__":
  try:
    main()
  except (RegenError, OSError, tarfile.TarError) as err:
    sys.exit(f"regen: {err}")
