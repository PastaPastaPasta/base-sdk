#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Write the merkleblock section of the BIP37 corpus."""

from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

BLOCK_HEIGHT = 2_000_000
BLOCK_HASH = "0000000000000009bd68b5e00976c3f7482d4cc12b6596614fbba5678ef13a59"
FIRST_TXID = "8954c8546a4b19860afaaac95f14fc5909e9593b729b6d8228918d5deacfc222"
LAST_TXID = "ac745767380eac6ba7065a34b460fae44b56d5f2c4f96afba9cdb0ef6d14501e"
MATCHES = {
  "last": ((3, LAST_TXID),),
  "two": (
    (0, FIRST_TXID),
    (3, LAST_TXID),
  ),
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
  """Return member *key* of *obj*, checked to be a *kind*."""
  value = obj.get(key) if isinstance(obj, dict) else None
  if not isinstance(value, kind) or (isinstance(value, bool) and kind is int):
    raise RpcError(f"{key!r} is not a {kind.__name__} in {obj!r:.300}")
  return value


def compact_size(value: int) -> bytes:
  """Encode a CompactSize value."""
  if value < 253:
    return bytes([value])
  if value <= 0xFFFF:
    return b"\xfd" + value.to_bytes(2, "little")
  if value <= 0xFFFF_FFFF:
    return b"\xfe" + value.to_bytes(4, "little")
  return b"\xff" + value.to_bytes(8, "little")


def wire_hash(value: str) -> bytes:
  """Return a displayed hash in wire byte order."""
  return bytes.fromhex(value)[::-1]


def read_compact_size(raw: bytes, offset: int) -> tuple[int, int]:
  """Read a CompactSize value from *raw*."""
  prefix = raw[offset]
  offset += 1
  if prefix < 253:
    return prefix, offset
  size = {253: 2, 254: 4, 255: 8}[prefix]
  return int.from_bytes(raw[offset : offset + size], "little"), offset + size


def merkle_details(raw_hex: str) -> dict[str, object]:
  """Decode the fields displayed for a merkle block proof."""
  raw = bytes.fromhex(raw_hex)
  header = raw[:80]
  count = int.from_bytes(raw[80:84], "little")
  hash_count, offset = read_compact_size(raw, 84)
  hashes = [
    raw[offset + i * 32 : offset + (i + 1) * 32][::-1].hex()
    for i in range(hash_count)
  ]
  offset += hash_count * 32
  flag_count, offset = read_compact_size(raw, offset)
  flags = raw[offset : offset + flag_count]
  return {
    "header": {
      "version": int.from_bytes(header[:4], "little"),
      "prevHash": header[4:36][::-1].hex(),
      "merkleRoot": header[36:68][::-1].hex(),
      "time": int.from_bytes(header[68:72], "little"),
      "bits": int.from_bytes(header[72:76], "little"),
      "nonce": int.from_bytes(header[76:80], "little"),
    },
    "txn": {
      "num_transactions": count,
      "hashes": hashes,
      "bits": flags.hex(),
    },
  }


def merkle_none(header: object) -> str:
  """Build the no-match proof for a block header."""
  version = field(header, "version", int).to_bytes(4, "little", signed=False)
  previous = wire_hash(field(header, "previousblockhash", str))
  root = wire_hash(field(header, "merkleroot", str))
  timestamp = field(header, "time", int).to_bytes(4, "little", signed=False)
  bits = int(field(header, "bits", str), 16).to_bytes(4, "little", signed=False)
  nonce = field(header, "nonce", int).to_bytes(4, "little", signed=False)
  block_header = version + previous + root + timestamp + bits + nonce
  count = field(header, "nTx", int).to_bytes(4, "little", signed=False)
  return (
    block_header + count + compact_size(1) + root + compact_size(1) + b"\0"
  ).hex()


def render(node: Node) -> str:
  """Return the merkleblock section from one real block."""
  block_hash = node.call("getblockhash", BLOCK_HEIGHT)
  if block_hash != BLOCK_HASH:
    raise RpcError(f"unexpected block hash {block_hash!r}")
  header = node.call("getblockheader", block_hash)
  rows = []
  for label in ("none", "last", "two"):
    raw = (
      merkle_none(header)
      if label == "none"
      else node.call(
        "gettxoutproof", [txid for _, txid in MATCHES[label]], block_hash
      )
    )
    if not isinstance(raw, str):
      raise RpcError(f"gettxoutproof {label} did not return hex")
    comments = {
      "none": (
        "Pins no matching transactions; the script builds this proof from "
        "the block header because no node call returns one."
      ),
      "last": (
        "Pins the last transaction at index 3 ("
        f"{LAST_TXID})."
      ),
      "two": (
        "Pins transactions at indexes 0 ("
        f"{FIRST_TXID}) and 3 ({LAST_TXID}), covering both ends of the block."
      ),
    }
    rows.append(
      f"    // {comments[label]}\n"
      f'    "{label}": {{\n      "raw": "{raw}",\n'
      f'      "details": '
      f"{json.dumps(merkle_details(raw), separators=(', ', ': '))}\n    }},"
    )
  return '  "merkleblock": {\n' + "\n".join(rows) + "\n  },"


def write(path: Path, section: str) -> None:
  """Replace the merkleblock section in the existing BIP37 corpus."""
  text = path.read_text(encoding="latin-1")
  start = text.index('  "merkleblock": {')
  end = text.index("\n  },\n\n}", start) + len("\n  },")
  path.write_text(text[:start] + section + text[end:], encoding="latin-1")


def parse_args() -> argparse.Namespace:
  """Parse command-line arguments."""
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    "--node", nargs=2, required=True, metavar=("HOST:PORT", "COOKIE")
  )
  parser.add_argument("--output", type=Path)
  return parser.parse_args()


def main() -> None:
  """Fetch chain data and write the merkleblock section."""
  args = parse_args()
  root = Path(__file__).resolve().parents[3]
  output = args.output or root / "pkgs" / "p2p_core" / "corpus" / "bloom.json5"
  write(output, render(Node(args.node[0], Path(args.node[1]).expanduser())))


if __name__ == "__main__":
  main()
