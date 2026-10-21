#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Build and test a probe for every supported target.

Usage:

  nix develop ./contrib/nix#dev --command ./contrib/smoke_test.py [DIR]
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Programs every toolchain builds, beside this script.
PROBES = Path(__file__).resolve().parent / "probes"

# Rust needs nothing beyond its own standard library to greet.
HELLO_RS = 'fn main() { println!("Hello, world!"); }\n'

# Targets the devshell may carry drivers for.
TARGETS = [
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "aarch64-unknown-linux-gnu",
  "x86_64-unknown-linux-gnu",
  "x86_64-pc-windows-gnu",
  "wasm32-unknown-unknown",
]

# `--macho` is a `llvm-objdump` flag, the GNU equivalent is unsupported.
OBJDUMP = shutil.which("llvm-objdump") or shutil.which("objdump")


def say(name: str, lang: str, result: str) -> None:
  print(f"  {name:<26} {lang:<4} {result}")


def produced(binary: Path) -> list[Path]:
  return sorted(binary.parent.glob(binary.name + "*"))


def minos(found: list[Path]) -> str:
  if OBJDUMP is None:
    return ""
  result = subprocess.run(  # noqa: S603
    [OBJDUMP, "--macho", "--private-headers", *map(str, found)],
    capture_output=True,
    check=False,
    text=True,
  )
  for line in result.stdout.splitlines():
    fields = line.split()
    if len(fields) > 1 and fields[0] == "minos":
      return fields[1]
  return ""


def describe(found: list[Path]) -> str:
  result = subprocess.run(  # noqa: S603
    ["file", "-b", *map(str, found)],  # noqa: S607
    capture_output=True,
    check=False,
    text=True,
  )
  lines = result.stdout.splitlines()
  return lines[0] if lines else ""


def attempt(
  out: Path, name: str, lang: str, argv: list[str], src: str = "hello"
) -> bool:
  binary = out / f"{name}.{lang}"
  source = out / f"{src}.{lang}"
  want = os.environ.get("MACOSX_DEPLOYMENT_TARGET", "")
  if not argv[0]:
    say(name, lang, "skipped")
    return True
  for stale in produced(binary):
    stale.unlink()
  built = subprocess.run(  # noqa: S603
    [*argv, str(source), "-o", str(binary)], check=False
  )
  found = produced(binary)
  if built.returncode != 0 or not found:
    say(name, lang, "FAILED")
    return False
  # An unreadable load command is a failure, not a reason to skip the check.
  if name.endswith("-apple-darwin"):
    got = minos(found)
    if not want or got != want:
      wanted = want or "<unset>"
      say(name, lang, f"FAILED, minos {got or 'unknown'}, wanted {wanted}")
      return False
  say(name, lang, describe(found) or "built")
  return True


def main() -> int:
  out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp())
  out.mkdir(parents=True, exist_ok=True)
  for name in ("hello.c", "hello.cpp", "free.c"):
    shutil.copy(PROBES / name, out)
  (out / "hello.rs").write_text(HELLO_RS, encoding="utf-8")

  ok = True
  ok &= attempt(out, "host", "c", [os.environ.get("CC", "cc")])
  ok &= attempt(out, "host", "cpp", [os.environ.get("CXX", "c++")])
  ok &= attempt(out, "host", "rs", ["rustc"])

  for target in TARGETS:
    key = target.replace("-", "_")
    driver = os.environ.get(f"CC_{key}", "")
    rust = "rustc" if driver else ""
    linker = driver
    if target.startswith("wasm32-"):
      # rustc links wasm32 with its own rust-lld.
      rust = "rustc"
      linker = ""
      ok &= attempt(out, target, "c", [driver, "-c"], src="free")
    else:
      ok &= attempt(out, target, "c", [driver])
    ok &= attempt(out, target, "cpp", [os.environ.get(f"CXX_{key}", "")])
    flags = [f"-Clinker={linker}"] if linker else []
    ok &= attempt(out, target, "rs", [rust, f"--target={target}", *flags])

  return 0 if ok else 1


if __name__ == "__main__":
  sys.exit(main())
