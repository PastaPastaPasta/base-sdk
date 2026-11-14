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
import base64
import http.client
import ipaddress
import json
from pathlib import Path
from typing import TypeVar

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
RPC_TIMEOUT = 600


class RpcError(Exception):
  """A failed call, or a reply without the expected members."""


def is_loopback(host: str) -> bool:
  """Whether *host* is `localhost` or a loopback address."""
  if host == "localhost":
    return True
  if host.startswith("[") and host.endswith("]"):
    host = host[1:-1]
  try:
    return ipaddress.ip_address(host).is_loopback
  except ValueError:
    return False


class Node:
  """A JSON-RPC client of one node, authenticated with its cookie."""

  def __init__(self, address: str, cookie: Path) -> None:
    host, _, port = address.rpartition(":")
    if not host or not port.isdigit():
      raise RpcError(f"{address!r} is not a host:port address")
    if not is_loopback(host):
      raise RpcError(f"{host} is not a loopback address")
    self.host = host
    self.port = int(port)
    token = base64.b64encode(cookie.read_bytes().strip()).decode()
    self.headers = {
      "Authorization": f"Basic {token}",
      "Content-Type": "application/json",
    }

  def call(self, method: str, *params: object) -> object:
    """Return the result of RPC *method* with *params*."""
    body = json.dumps({"id": 0, "method": method, "params": list(params)})
    conn = http.client.HTTPConnection(self.host, self.port, timeout=RPC_TIMEOUT)
    try:
      conn.request("POST", "/", body, self.headers)
      response = conn.getresponse()
      data = response.read()
    except http.client.HTTPException as err:
      raise RpcError(f"{method}: {err!r}") from err
    finally:
      conn.close()
    try:
      reply = json.loads(data)
    except ValueError:
      reply = None
    error = reply.get("error") if isinstance(reply, dict) else None
    if error is not None:
      raise RpcError(f"{method}: {error!r:.300}")
    if response.status != http.client.OK or not isinstance(reply, dict):
      raise RpcError(f"{method}: HTTP {response.status}, {data[:300]!r}")
    return reply.get("result")


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
