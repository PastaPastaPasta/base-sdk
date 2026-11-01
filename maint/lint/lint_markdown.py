#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Lint Markdown files with pymarkdownlnt."""

from __future__ import annotations

import subprocess
import sys
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import markdown
from common import (
  RETCODE_ERR,
  RETCODE_PASS,
  off_disk,
  relay,
  repo_files,
  require_bin,
  root_dir,
)

if TYPE_CHECKING:
  from pathlib import Path

DISABLED_RULES = "md025,md033,md041,md059"


class _LinkCollector(HTMLParser):
  """Collect `<a href>`/`<img src>` targets, skipping code and comments."""

  def __init__(self) -> None:
    super().__init__()
    self.targets: list[str] = []

  def handle_starttag(
    self, tag: str, attrs: list[tuple[str, str | None]],
  ) -> None:
    value = dict(attrs).get({"a": "href", "img": "src"}.get(tag))
    if value:
      self.targets.append(value)


def _link_targets(text: str) -> list[str]:
  """Return every link/image target rendering *text* as HTML exposes."""
  renderer = markdown.Markdown(extensions=["extra"])
  collector = _LinkCollector()
  collector.feed(renderer.convert(text))
  return [*collector.targets, *(url for url, _ in renderer.references.values())]


def _check_crate_readmes(repo_root: Path, sources: list[Path]) -> int:
  """Reject relative links in crate READMEs, which crates.io can't resolve."""
  ok = True
  pkgs = repo_root / "pkgs"
  for readme in sources:
    if readme.name != "README.md" or not readme.is_relative_to(pkgs):
      continue
    text = readme.read_text(encoding="utf-8")
    rel = readme.relative_to(repo_root)
    for target in _link_targets(text):
      if off_disk(target):
        continue
      ok = False
      lineno = next(
        (n for n, line in enumerate(text.splitlines(), 1) if target in line), 1,
      )
      print(
        f"{rel}:{lineno}: relative link '{target}' won't resolve on crates.io",
        file=sys.stderr,
      )
  return RETCODE_PASS if ok else RETCODE_ERR


def main() -> int:
  pymarkdown_bin = require_bin("pymarkdownlnt")
  repo_root = root_dir()
  sources = repo_files(repo_root, "*.md")
  result = subprocess.run(  # noqa: S603
    [
      pymarkdown_bin,
      "--disable-rules",
      DISABLED_RULES,
      "scan",
      *[str(p) for p in sources],
    ],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )

  relay(result.stdout, repo_root)
  relay(result.stderr, repo_root, stream=sys.stderr)

  readme_retcode = _check_crate_readmes(repo_root, sources)

  return result.returncode or readme_retcode


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
