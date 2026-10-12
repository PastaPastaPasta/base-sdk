#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from common import (
  DEFAULT_BASE,
  declare_verbs,
  find_up_file,
  git_out,
  git_run,
  root_dir,
)

# Vocabulary file, read from the nearest directory above this script.
CONFIG_FILENAME = "commit.toml"

# Matches the address in a 'Co-authored-by' trailer.
_CO_AUTHOR = re.compile(
  r"^co-authored-by:.*<(?P<email>[^>]+)>\s*$", re.IGNORECASE | re.MULTILINE
)

# Matches a commit subject, 'namespace%type[(scope)][!]: description'.
_PATTERN = re.compile(
  r"^(?P<namespace>[^\s%]+)"
  r"%(?P<type>[A-Za-z0-9_-]+)"
  r"(?:\((?P<scope>[^)\s]+)\))?"
  r"(?P<breaking>!)?"
  r": (?P<description>.+)$"
)


@dataclass(frozen=True)
class Commit:
  message: str
  author: str | None = None
  committer: str | None = None


@dataclass(frozen=True)
class NamespaceConfig:
  ignore_default: bool = False
  nouns: frozenset[str] = field(default_factory=frozenset)
  scopes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Config:
  max_width: int
  max_height: int
  block_authors: frozenset[str] = field(default_factory=frozenset)
  default_nouns: frozenset[str] = field(default_factory=frozenset)
  namespaces: dict[str, NamespaceConfig] = field(default_factory=dict)

  @classmethod
  def load(cls, path: Path) -> Config:
    with path.open("rb") as f:
      raw = tomllib.load(f)

    for key in ("max_width", "max_height"):
      if not isinstance(raw.get(key), int):
        raise ValueError(f"{path}: {key} must be an integer")
    default_nouns = frozenset(raw.get("default", {}).get("nouns", []))
    namespaces = {
      key: NamespaceConfig(
        ignore_default=value.get("ignore_default", False),
        nouns=frozenset(value.get("nouns", [])),
        scopes=frozenset(value.get("scopes", [])),
      )
      for key, value in raw.get("namespace", {}).items()
    }

    return cls(
      max_width=raw["max_width"],
      max_height=raw["max_height"],
      block_authors=frozenset(a.lower() for a in raw.get("block_authors", [])),
      default_nouns=default_nouns,
      namespaces=namespaces,
    )


def _allowed_nouns(namespace: str, config: Config) -> frozenset[str]:
  ns = config.namespaces.get(namespace)
  if ns is None:
    return config.default_nouns
  base = frozenset() if ns.ignore_default else config.default_nouns
  return base | ns.nouns


def _lint_shape(lines: list[str], config: Config) -> list[str]:
  """Return error strings for the width and height of a commit message."""
  errors: list[str] = []
  if len(lines) > config.max_height:
    errors.append(f"{len(lines)} lines tall, over {config.max_height}")
  wide = [n for n, line in enumerate(lines, 1) if len(line) > config.max_width]
  if wide:
    where = ", ".join(str(n) for n in wide)
    errors.append(f"line {where} wider than {config.max_width} characters")
  return errors


def _lint_authors(commit: Commit, config: Config) -> list[str]:
  """Return error strings for a blocked author, committer or co-author."""
  errors: list[str] = []
  blocked = config.block_authors
  roles = (("author", commit.author), ("committer", commit.committer))
  for role, email in roles:
    if email is not None and email.lower() in blocked:
      errors.append(f"{role} {email!r} is blocked")
  for m in _CO_AUTHOR.finditer(commit.message):
    email = m.group("email").strip()
    if email.lower() in blocked:
      errors.append(f"co-author {email!r} is blocked")
  return errors


def _lint_message(
  commit: Commit, config: Config, *, title: bool = False
) -> list[str]:
  """Return error strings for a commit message or, if *title*, a PR title"""
  lines = commit.message.strip().splitlines()
  subject = lines[0].strip() if lines else ""
  if title:
    return _lint_subject(subject, config)
  errors = _lint_authors(commit, config)
  if not subject or subject.startswith("#") or subject.startswith("Merge "):
    return errors
  return errors + _lint_subject(subject, config) + _lint_shape(lines, config)


def _lint_subject(subject: str, config: Config) -> list[str]:
  """Return error strings for one commit subject line"""

  m = _PATTERN.match(subject)
  if m is None:
    return ["does not match namespace%type[(scope)][!]: description"]

  namespace: str = m.group("namespace")
  commit_type: str = m.group("type")
  scope: str | None = m.group("scope")
  errors: list[str] = []

  if not namespace.isascii():
    errors.append(f"namespace {namespace!r} contains non-ASCII characters")

  if namespace not in config.namespaces:
    errors.append(f"unknown namespace {namespace!r}")

  allowed = _allowed_nouns(namespace, config)
  if allowed and commit_type.lower() not in allowed:
    errors.append(
      f"unknown type {commit_type!r} for namespace {namespace!r}"
      f" -- valid:{', '.join(sorted(allowed))}"
    )

  ns_config = config.namespaces.get(namespace)
  if scope is not None and ns_config is not None and ns_config.scopes:
    if scope not in ns_config.scopes:
      errors.append(
        f"unknown scope {scope!r} for namespace {namespace!r}"
        f" -- valid:{', '.join(sorted(ns_config.scopes))}"
      )

  return errors


def _current_branch() -> str | None:
  result = git_run(root_dir(), "rev-parse", "--abbrev-ref", "HEAD")
  if result.returncode != 0:
    return None
  return result.stdout.strip()


def _ref_exists(ref: str) -> bool:
  result = git_run(root_dir(), "rev-parse", "--verify", "--quiet", ref)
  return result.returncode == 0


def _default_range() -> str:
  branch = _current_branch()
  if branch is None or branch == "HEAD" or branch == DEFAULT_BASE:
    return "HEAD~1..HEAD"
  for ref in (DEFAULT_BASE, f"origin/{DEFAULT_BASE}"):
    if _ref_exists(ref):
      return f"{ref}..HEAD"
  return "HEAD~1..HEAD"


def _messages(*args: str) -> list[Commit]:
  out = git_out(
    root_dir(), "log", "--no-merges", "--format=%ae%x00%ce%x00%B%x1e", *args
  )
  commits: list[Commit] = []
  for record in out.split("\x1e"):
    author, _, rest = record.lstrip("\n").partition("\0")
    committer, _, message = rest.partition("\0")
    if message.strip():
      commits.append(Commit(message.strip(), author, committer))
  return commits


def _messages_from_commit(ref: str) -> list[Commit]:
  parents = git_out(root_dir(), "rev-list", "--parents", "-n", "1", ref)
  if len(parents.split()) > 2:
    return []
  return _messages("-1", ref)


def _messages_from_range(git_range: str) -> list[Commit]:
  return _messages(git_range)


def main() -> int:
  parser = declare_verbs(
    "Lint commit messages against the unconventional commits format.\n"
    "Format: [namespace]%type[(scope)]: description",
    {"run": "lint whichever messages the options below select"},
  )
  source = parser.add_mutually_exclusive_group(required=False)
  source.add_argument(
    "-m",
    metavar="MESSAGE",
    help="Lint a commit message string directly.",
  )
  source.add_argument(
    "-r",
    metavar="RANGE",
    help="Git log range to check (e.g. main..HEAD).",
  )
  source.add_argument(
    "-c",
    metavar="COMMIT",
    help="Git commit ref to check (e.g. HEAD, abc123).",
  )
  parser.add_argument(
    "-f",
    metavar="FILE",
    type=Path,
    help=f"Path to config file (default: nearest {CONFIG_FILENAME}).",
  )
  args = parser.parse_args()

  here = Path(__file__).resolve().parent
  config_path: Path | None = args.f
  if config_path is None:
    config_path = find_up_file(here, CONFIG_FILENAME, stop=root_dir())
    if config_path is None:
      print(
        f"error: no {CONFIG_FILENAME} between {here} and {root_dir()}",
        file=sys.stderr,
      )
      return 2
  if not config_path.is_file():
    print(f"error: {config_path} is not a file", file=sys.stderr)
    return 2

  try:
    config = Config.load(config_path)
  except ValueError as exc:
    print(f"error: {exc}", file=sys.stderr)
    return 2

  if args.m is not None:
    messages = [Commit(args.m)]
  elif args.r is not None:
    messages = _messages_from_range(args.r)
  elif args.c is not None:
    messages = _messages_from_commit(args.c)
  else:
    messages = _messages_from_range(_default_range())

  title = args.m is not None
  results = [(m, _lint_message(m, config, title=title)) for m in messages]
  failed = False

  for commit, errors in results:
    lines = commit.message.strip().splitlines()
    subject = lines[0] if lines else ""
    if errors:
      print(f"[FAIL] {subject} (reason: {'; '.join(errors)})")
      failed = True
    else:
      print(f"[PASS] {subject}")

  return 1 if failed else 0


if __name__ == "__main__":
  sys.exit(main())
