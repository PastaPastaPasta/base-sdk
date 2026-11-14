#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Print the literals of the BIP157 programs."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TypeVar

from util.rpc import Node, RpcError

T = TypeVar("T")

# The literals the programs take, by mainnet height. A block hash comes from
# getblockhash, a filter and a filter header from getblockfilter.
LITERALS = {
  999: ("HEADER",),
  1000: ("BLOCK_HASH", "FILTER", "HEADER"),
  1001: ("BLOCK_HASH", "FILTER"),
  1002: ("BLOCK_HASH", "FILTER"),
  2_000_000: ("BLOCK_HASH", "FILTER"),
}
def field(obj: object, key: str, kind: type[T]) -> T:
  value = obj.get(key) if isinstance(obj, dict) else None
  if not isinstance(value, kind) or (isinstance(value, bool) and kind is int):
    raise RpcError(f"{key!r} is not a {kind.__name__} in {obj!r:.300}")
  return value


def render(node: Node) -> str:
  """Return the literals of the programs, read from *node*."""
  lines = []
  for height, kinds in LITERALS.items():
    block_hash = node.call("getblockhash", height)
    if not isinstance(block_hash, str):
      raise RpcError(f"getblockhash {height} did not return a hash")
    result = node.call("getblockfilter", block_hash)
    for kind in kinds:
      if kind == "BLOCK_HASH":
        source, value = f"from getblockhash {height}", block_hash
      else:
        key = kind.lower()
        source = f"{key} from getblockfilter {block_hash}"
        value = field(result, key, str)
      lines.extend([
        f"    // Mainnet height {height:,}, {source}.",
        f'    constexpr char {kind}_{height}[] = "{value}";',
      ])
  return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    "--node", nargs=2, required=True, metavar=("HOST:PORT", "COOKIE")
  )
  return parser.parse_args()


def main() -> None:
  args = parse_args()
  print(render(Node(args.node[0], Path(args.node[1]).expanduser())), end="")


if __name__ == "__main__":
  main()
