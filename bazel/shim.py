#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Shim that runs Bazel with its output root in `.cache/bazel`."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

OUTPUT_ROOT = Path(__file__).resolve().parents[1] / ".cache" / "bazel"


def main() -> int:
  real = os.environ.get("BAZEL_REAL")
  if not real:
    print("bazel: run bazelisk, which sets BAZEL_REAL", file=sys.stderr)
    return 2
  argv = [real, f"--output_user_root={OUTPUT_ROOT}", *sys.argv[1:]]
  if os.name == "nt":
    return subprocess.run(argv, check=False).returncode  # noqa: S603
  os.execv(real, argv)  # noqa: S606


if __name__ == "__main__":
  sys.exit(main())
