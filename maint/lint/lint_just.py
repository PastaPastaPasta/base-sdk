#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Check (and apply) just's formatting for the root Justfile and its modules."""

from __future__ import annotations

import sys
from pathlib import Path

from common import (
  RETCODE_ERR,
  RETCODE_SKIP,
  declare_verbs,
  format_verbs,
  formatted,
  relay,
  repo_files,
  require_bin,
  root_dir,
  touched,
)

SCRIPT = Path(__file__).stem


def main() -> int:
  args = declare_verbs(__doc__ or "", format_verbs("justfile")).parse_args()

  try:
    just = require_bin("just")
  except FileNotFoundError as e:
    print(f"{e}, skipping", file=sys.stderr)
    return RETCODE_SKIP

  repo_root = root_dir()
  fix = args.verb.startswith("apply")
  only = (
    touched(repo_root, ("Justfile", ".just")) if args.verb == "apply" else None
  )
  sources = (
    repo_files(repo_root, "Justfile", "*.just")
    if only is None
    else [repo_root / n for n in only]
  )
  return formatted(
    SCRIPT,
    "justfile",
    sources,
    lambda paths: [
      just,
      "--fmt",
      *([] if fix else ["--check"]),
      "--justfile",
      *[str(p) for p in paths],
    ],
    fix=fix,
    scoped=only is not None,
    cwd=repo_root,
    output=lambda out, err: relay(out + err, repo_root, stream=sys.stderr),
    per_file=True,
  )


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
