#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Print the literals of the `merkleblock_payloads` program."""

from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

# Mainnet block 2,000,000, and for each proof the transactions it matches.
BLOCK_HEIGHT = 2_000_000
BLOCK_HASH = "0000000000000009bd68b5e00976c3f7482d4cc12b6596614fbba5678ef13a59"
FIRST_TXID = "8954c8546a4b19860afaaac95f14fc5909e9593b729b6d8228918d5deacfc222"
LAST_TXID = "ac745767380eac6ba7065a34b460fae44b56d5f2c4f96afba9cdb0ef6d14501e"
MATCHES = {
  "last": ((LAST_TXID,), "its last transaction"),
  "two": ((FIRST_TXID, LAST_TXID), "transactions at both ends"),
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


def render(node: Node) -> str:
  """Return the literals of the program, read from *node*."""
  block_hash = node.call("getblockhash", BLOCK_HEIGHT)
  if block_hash != BLOCK_HASH:
    raise RpcError(f"unexpected block hash {block_hash!r}")
  lines = []
  for label, (txids, matched) in MATCHES.items():
    proof = node.call("gettxoutproof", list(txids), BLOCK_HASH)
    if not isinstance(proof, str):
      raise RpcError(f"gettxoutproof {label} did not return hex")
    lines.extend([
      f"    // Mainnet height {BLOCK_HEIGHT:,}, block hash {BLOCK_HASH}, from"
      f" gettxoutproof for {matched}.",
      f"    constexpr char PROOF_{label.upper()}[] =",
      f'        "{proof}";',
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
