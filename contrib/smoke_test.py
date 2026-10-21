#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Build and test a probe for every supported target.

Usage:

  nix develop ./contrib/nix#dev --command ./contrib/smoke_test.py
  ./contrib/smoke_test.py --keep /tmp/smoke
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import lief
from common import (
  RETCODE_ERR,
  RETCODE_PASS,
  format_table,
)

# What every host binary prints.
GREETING = "Hello, world!"

# Programs every toolchain builds, beside this script.
PROBES = Path(__file__).resolve().parent / "probes"

# Rust needs nothing beyond its own standard library to greet.
HELLO_RS = 'fn main() { println!("Hello, world!"); }\n'

# LIEF reads no WebAssembly, which is told apart by its magic and version.
WASM_PREAMBLE = b"\0asm\x01\0\0\0"

# Seconds a build or a probe may run before it counts as hung.
TIMEOUT = 120

# Each target the devshell may carry drivers for, with the format and
# architecture its binaries must have. Mach-O versions come from the
# environment.
TARGETS = [
  ("aarch64-apple-darwin", "Mach-O", "arm64"),
  ("x86_64-apple-darwin", "Mach-O", "x86_64"),
  ("aarch64-unknown-linux-gnu", "ELF", "arm64"),
  ("x86_64-unknown-linux-gnu", "ELF", "x86_64"),
  ("x86_64-pc-windows-gnu", "PE", "x86_64"),
  ("wasm32-unknown-unknown", "wasm", "wasm32"),
]


@dataclass(frozen=True)
class Kind:
  """The format, architecture and Mach-O versions of a binary."""

  fmt: str
  arch: str
  minos: str | None = None
  sdk: str | None = None

  def __str__(self) -> str:
    minos = f", minos {self.minos}" if self.minos else ""
    sdk = f", sdk {self.sdk}" if self.sdk else ""
    return f"{self.fmt} {self.arch}{minos}{sdk}"

  def satisfies(self, want: Kind) -> bool:
    """Return whether this binary is what *want* asks for."""
    same = (self.fmt, self.arch) == (want.fmt, want.arch)
    minos = want.minos in (None, self.minos)
    return same and minos and want.sdk in (None, self.sdk)

  @staticmethod
  def of(path: Path) -> Kind | None:
    """Return the format and architecture *path* carries, or None."""
    try:
      with path.open("rb") as f:
        if f.read(len(WASM_PREAMBLE)) == WASM_PREAMBLE:
          return Kind("wasm", "wasm32")
    except OSError:
      return None

    binary = lief.parse(str(path))
    if binary is None:
      return None
    fmt = binary.format.name.replace("MACHO", "Mach-O")
    arch = binary.abstract.header.architecture.name.lower()
    minos = sdk = None
    if isinstance(binary, lief.MachO.Binary) and binary.has_build_version:
      minos = _version(binary.build_version.minos)
      sdk = _version(binary.build_version.sdk)
    return Kind(fmt, arch, minos, sdk)


def _version(parts: list[int]) -> str:
  """Return a Mach-O `major.minor.patch` version, dropping a zero patch."""
  major, minor, patch = parts
  return f"{major}.{minor}" + (f".{patch}" if patch else "")


def _canonical(version: str | None) -> str | None:
  """Return *version* as `_version` spells it, so `14` matches `14.0`."""
  if not version:
    return None
  try:
    parts = [int(part) for part in version.split(".")]
  except ValueError:
    return version
  return _version([*parts, 0, 0][:3])


class Report:
  """Collects one row per binary and whether every row passed."""

  def __init__(self) -> None:
    self.rows: list[tuple[str, str, str]] = []
    self.failed = False

  def add(self, name: str, lang: str, result: str, *, ok: bool = True) -> None:
    self.rows.append((name, lang, result if ok else f"FAILED, {result}"))
    self.failed |= not ok

  def held(
    self, name: str, lang: str, path: Path, want: Kind, *, note: str = ""
  ) -> bool:
    """Record whether the binary at *path*, or with a suffix, is *want*."""
    found = next(iter(_outputs(path)), None)
    got = Kind.of(found) if found is not None else None
    if got is None:
      self.add(name, lang, "nothing recognisable was built", ok=False)
    elif not got.satisfies(want):
      self.add(name, lang, f"{got}, wanted {want}", ok=False)
    else:
      self.add(name, lang, f"{got}{note}")
      return True
    return False

  def greets(self, name: str, lang: str, path: Path, want: Kind) -> None:
    """Record whether the host binary at *path* is *want* and greets."""
    try:
      result = _run([str(path)])
    except (OSError, subprocess.TimeoutExpired) as exc:
      self.add(name, lang, _unfinished(exc), ok=False)
      return
    if result.returncode != 0:
      self.add(name, lang, f"exited with {result.returncode}", ok=False)
      return
    if result.stdout.strip() != GREETING:
      self.add(name, lang, "no greeting", ok=False)
      return
    self.held(name, lang, path, want, note=", ran")


class Builder:
  """Builds the probes into one directory and records each result."""

  def __init__(self, report: Report, out: Path) -> None:
    self.report = report
    self.out = out
    self.src = {
      "c": PROBES / "hello.c",
      "cpp": PROBES / "hello.cpp",
      "rs": out / "hello.rs",
      "free": PROBES / "free.c",
    }
    self.src["rs"].write_text(HELLO_RS, encoding="utf-8")

  def build(self, name: str, lang: str, argv: list[str]) -> Path | None:
    """Return the binary *argv* built, or None after recording why not."""
    binary = self.out / f"{name}.{lang}"
    for stale in _outputs(binary):
      stale.unlink()
    try:
      result = _run([*argv, "-o", str(binary)])
    except (OSError, subprocess.TimeoutExpired) as exc:
      self.report.add(name, lang, _unfinished(exc), ok=False)
      return None
    if result.returncode != 0:
      # The first error names the cause; the drivers' last line rarely does.
      lines = result.stderr.strip().splitlines()
      cause = next((ln for ln in lines if "error" in ln), None)
      cause = cause or (lines[-1] if lines else "no output")
      self.report.add(name, lang, cause, ok=False)
      return None
    return binary

  def host(self) -> None:
    """Build with the host compilers, then run what they built."""
    want = host_kind()
    for lang, compiler in (
      ("c", os.environ.get("CC", "cc")),
      ("cpp", os.environ.get("CXX", "c++")),
      ("rs", "rustc"),
    ):
      binary = self.build("host", lang, [compiler, str(self.src[lang])])
      if binary is not None:
        self.report.greets("host", lang, binary, want)

  def target(self, triple: str, want: Kind) -> None:
    """Build with the drivers the devshell carries for *triple*."""
    key = triple.replace("-", "_")
    cc = os.environ.get(f"CC_{key}")
    cxx = os.environ.get(f"CXX_{key}")
    if want.fmt == "Mach-O":
      minos = _canonical(os.environ.get("MACOSX_DEPLOYMENT_TARGET"))
      # Set only when clang reads the version from `SDKSettings.json`.
      sdk = _canonical(os.environ.get("MACOS_SDK_VERSION"))
      if (cc or cxx) and not (minos and sdk):
        unset = "MACOSX_DEPLOYMENT_TARGET" if not minos else "MACOS_SDK_VERSION"
        self.report.add(triple, "all", f"no {unset}", ok=False)
        return
      want = dataclasses.replace(want, minos=minos, sdk=sdk)

    rs = str(self.src["rs"])
    # wasm32 has no libc to greet through, so it builds a bare object.
    if want.fmt == "wasm":
      free = str(self.src["free"])
      langs = [("c", [cc, "-c", free] if cc else None), ("cpp", None)]
      # rustc links wasm32 with its own rust-lld, so it needs no driver.
      rust = ["rustc", f"--target={triple}", rs]
    else:
      langs = [
        ("c", [cc, str(self.src["c"])] if cc else None),
        ("cpp", [cxx, str(self.src["cpp"])] if cxx else None),
      ]
      rust = None
      if cc:
        rust = ["rustc", f"--target={triple}", f"-Clinker={cc}", rs]

    for lang, argv in [*langs, ("rs", rust)]:
      if argv is None:
        self.report.add(triple, lang, "skipped")
        continue
      binary = self.build(triple, lang, argv)
      if binary is not None:
        self.report.held(triple, lang, binary, want)


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
  return subprocess.run(  # noqa: S603
    argv, capture_output=True, check=False, text=True, timeout=TIMEOUT
  )


def _unfinished(exc: OSError | subprocess.TimeoutExpired) -> str:
  """Return why a command never finished, for its report row."""
  if isinstance(exc, subprocess.TimeoutExpired):
    return f"timed out after {TIMEOUT}s"
  return f"could not run, {(exc.strerror or str(exc)).lower()}"


def _outputs(binary: Path) -> list[Path]:
  """Return *binary* and any file a driver named after it plus a suffix."""
  return sorted(
    p
    for p in binary.parent.glob(binary.name + "*")
    if p.name == binary.name or p.name.startswith(binary.name + ".")
  )


def host_kind() -> Kind:
  """Return what a binary built for the host is."""
  machine = platform.machine().lower()
  machine = {"aarch64": "arm64", "amd64": "x86_64"}.get(machine, machine)
  fmt = "Mach-O" if platform.system() == "Darwin" else "ELF"
  return Kind(fmt, machine)


def main() -> int:
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  parser.add_argument(
    "--keep",
    type=Path,
    metavar="DIR",
    help="build into DIR and keep it, instead of a temporary directory",
  )
  args = parser.parse_args()
  lief.logging.disable()

  report = Report()
  scratch = (
    contextlib.nullcontext(str(args.keep))
    if args.keep
    else tempfile.TemporaryDirectory(prefix="smoke-")
  )
  with scratch as where:
    # Absolute, so running a host binary never searches PATH.
    out = Path(where).resolve()
    out.mkdir(parents=True, exist_ok=True)
    builder = Builder(report, out)
    builder.host()
    for triple, fmt, arch in TARGETS:
      builder.target(triple, Kind(fmt, arch))
    print(format_table(("target", "lang", "result"), report.rows))

  return RETCODE_ERR if report.failed else RETCODE_PASS


if __name__ == "__main__":
  sys.exit(main())
