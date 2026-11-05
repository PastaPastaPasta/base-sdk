#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Write the payload sign hash corpus.

For each transaction in `ROWS`, the corpus holds the transaction and the keys
its signers held at the block before, read from a node of its chain. Each node
needs `-txindex`.

Usage:

  ./pkgs/primitives/contrib/sighash.py \\
    --node 127.0.0.1:9998 ~/.dashcore/.cookie \\
    --node 127.0.0.1:19998 ~/.dashcore/testnet3/.cookie
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import sys
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

# Where the corpus is written by default.
CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "sighash.json5"

# The transactions the corpus holds by chain, each with what it pins.
ROWS: dict[str, list[tuple[str, str]]] = {
  "main": [
    (
      "4e84b507ff3dcd9819e9d04393c0a7b40c6267f46e531af08cbafd26720eb382",
      "A version 1 registration, signed by the collateral key.",
    ),
    (
      "62ab2736bf85c1e1251cdfb95e8229b05d3b3fd97b39d9b9baf414c5f93474b5",
      "A version 2 registration.",
    ),
    (
      "49a4887a2e7fc0bde104fc91478597b356520a61e6d27cd08a945edd5ceab3ca",
      "A version 1 service update, signed under the legacy scheme.",
    ),
    (
      "764460fc0d3303f5de75ff938bc397407e46574af6f72d054a31c81d3ea26baf",
      "A version 1 service update, signed under the basic scheme.",
    ),
    (
      "4e0d18e300d2ea0db81cb334aac6098848b7026439a43c78a90add2ca9a3eb01",
      "A version 2 service update.",
    ),
    (
      "9663a0f0503fdc680b05ed0d1ced0131695f1732be32a45e4d4bc5085865473d",
      "A version 2 service update of an Evo masternode.",
    ),
    (
      "6002c6e304dc609d28bdf0da5304ca47394152f21711d1ea1687c40dbec216de",
      "A version 1 registrar update.",
    ),
    (
      "39c7568aabf91fb8d27d3146aa13e16118c0d168a903f2c116fcd02132466ce7",
      "A version 2 registrar update.",
    ),
    (
      "1b521e8f348e2a01969e4a9aaa377c3ce350dab158a7add82eac6bba1d090594",
      "A version 1 revocation, signed under the legacy scheme.",
    ),
    (
      "21b5994a3cd21df0568eda024e15b54f380f914a2d749be96d00b31a18073767",
      "A version 2 revocation.",
    ),
    (
      "cb11eb2b4f2a5d2b4294e8c2965478f037dd36d90a0d4734c0e3e868a2f4d024",
      "A version 2 revocation under a legacy-encoded key.",
    ),
  ],
  "test": [
    (
      "13ccca675ed8a8a788693f46191e7237e2896701ede3058c20263e1b2343923d",
      "A version 3 registration.",
    ),
    (
      "2770d2493755b59b3426474b2a18eb5c34df636530ae8059aa1fe4b22ce47c3c",
      "A version 3 registration of an Evo masternode.",
    ),
    (
      "8699ef5afd141f7b02f170db4f4875468ace2f6c84c6889f3e0280633ba65f40",
      "A version 3 registration with shares, signed by each share owner.",
    ),
    (
      "d0faa9b0748eb837f5d55f6aad7d3e83352cf69de161521e7fc37fda877ba098",
      "A version 3 service update.",
    ),
    (
      "0b9ef4f3b1607841c5f98485ade8f1bdf4d5b8127a24343a53d501bed74b525c",
      "A version 3 service update of an Evo masternode.",
    ),
    (
      "7209b5bdb6881a69029a89501392b0ef05ff8ca83be7df03d7a247241b7ac4e7",
      "A version 3 service update under a legacy-encoded key.",
    ),
    (
      "4e0f211850f44c55e26e45f6bc10a59d6c08fe91be544a8fac0f7ce6cf96ad06",
      "A version 3 revocation.",
    ),
    (
      "d0b92723bd36450c2fcb51ef0886818ad40a09c07115dd55bc659a2546fa54fd",
      "A dissolution, signed by each share owner.",
    ),
  ],
}

# Members of `getrawtransaction` that hold the payload, by type.
PAYLOADS = {
  1: "proRegTx",
  2: "proUpServTx",
  3: "proUpRegTx",
  4: "proUpRevTx",
  7: "mnhfTx",
  9: "assetUnlockTx",
  10: "proDisTx",
}

# The service update and the revocation, which the operator key signs.
OPERATOR_SIGNED = {2, 4}

# The registrar update and the dissolution, which the owners of the
# masternode sign.
OWNER_SIGNED = {3, 10}

# Network names the corpus uses, by chain.
NETWORKS = {"main": "mainnet", "test": "testnet"}

# Quorum types that sign each payload on each public chain.
QUORUM_TYPES = {
  "mainnet": {7: 3, 9: 4},
  "testnet": {7: 1, 9: 6},
}

# Blocks after a quorum's base block that are read for its commitment, more
# than the mining window of any quorum type.
QUORUM_SCAN = 60

# Base58 digits.
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Seconds to wait for a reply.
RPC_TIMEOUT = 600


class RpcError(Exception):
  """A failed call, or a reply without the expected members."""


def is_loopback(host: str) -> bool:
  """Whether *host* is `localhost` or a loopback address."""
  if host == "localhost":
    return True
  # An IPv6 address in a host:port pair comes in brackets.
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
      hint = "reach a remote node through a tunnel"
      raise RpcError(f"{host} is not a loopback address; {hint}")
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
    if response.status == http.client.UNAUTHORIZED:
      raise RpcError(f"{method}: the cookie was refused")
    # The node sends an error with another status and a JSON body naming it,
    # so the body is decoded before the status is checked.
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
  """Return member *key* of the JSON object *obj*, checked to be a *kind*."""
  value = obj.get(key) if isinstance(obj, dict) else None
  # Python reads a JSON boolean as an int, so an int member refuses one.
  if not isinstance(value, kind) or (isinstance(value, bool) and kind is int):
    raise RpcError(f"{key!r} is not a {kind.__name__} in {obj!r:.300}")
  return value


def key_id(address: str) -> str:
  """Return the key id of a P2PKH *address*, checksum checked."""
  n = 0
  for c in address:
    n = n * 58 + B58.index(c)
  raw = n.to_bytes(25, "big")
  body, check = raw[:-4], raw[-4:]
  if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
    raise RpcError(f"bad checksum: {address}")
  return body[1:].hex()


def p2pkh_key_id(script: str) -> str:
  """Return the key id a P2PKH *script* pays."""
  if not (script.startswith("76a914") and script.endswith("88ac")):
    raise RpcError(f"not P2PKH: {script}")
  return script[6:46]


def scheme(*, legacy: bool) -> str:
  """Return the name of the BLS scheme, legacy or basic."""
  return "legacy" if legacy else "basic"


class Chain:
  """The reads of one node that the corpus rows need."""

  def __init__(self, node: Node) -> None:
    self.node = node
    deployments = field(node.call("getdeploymentinfo"), "deployments", dict)
    self.v19 = field(field(deployments, "v19", dict), "height", int)

  def masternode(self, pro_tx_hash: str, height: int) -> dict:
    """Return the state of masternode *pro_tx_hash* at *height*."""
    diff = self.node.call("protx", "listdiff", 1, height)
    for entry in field(diff, "addedMNs", list):
      if field(entry, "proTxHash", str) == pro_tx_hash:
        return field(entry, "state", dict)
    raise RpcError(f"no masternode {pro_tx_hash} at {height}")

  def quorums(self, quorum_hash: str) -> dict[str, str]:
    """Return the public keys of the quorums at *quorum_hash* by type."""
    header = self.node.call("getblockheader", quorum_hash)
    block_hash = field(header, "hash", str)
    found: dict[str, str] = {}
    for _ in range(QUORUM_SCAN):
      block = self.node.call("getblock", block_hash, 2)
      for tx in field(block, "tx", list):
        if "qcTx" not in tx:
          continue
        commitment = field(field(tx, "qcTx", dict), "commitment", dict)
        key = field(commitment, "quorumPublicKey", str)
        if field(commitment, "quorumHash", str) != quorum_hash:
          continue
        if set(key) != {"0"}:
          found[str(field(commitment, "llmqType", int))] = key
      if "nextblockhash" not in block:
        break
      block_hash = field(block, "nextblockhash", str)
    if not found:
      raise RpcError(f"no commitment for quorum {quorum_hash}")
    return dict(sorted(found.items()))

  def signer(self, tx: dict, height: int, network: str) -> dict:
    """Return the keys the signatures of *tx* verify under."""
    ttype = field(tx, "type", int)
    if ttype not in PAYLOADS:
      raise RpcError(f"{tx['txid']}: type {ttype} carries no signature")
    p = field(tx, PAYLOADS[ttype], dict)
    if ttype == 1:
      if p.get("shares"):
        return {}
      if set(field(p, "collateralHash", str)) == {"0"}:
        raise RpcError(f"{tx['txid']}: no payload signature")
      prev = self.node.call(
        "getrawtransaction", field(p, "collateralHash", str), True
      )
      out = field(prev, "vout", list)[field(p, "collateralIndex", int)]
      script = field(field(out, "scriptPubKey", dict), "hex", str)
      return {"key_ids": [p2pkh_key_id(script)]}
    if ttype in OPERATOR_SIGNED:
      state = self.masternode(field(p, "proTxHash", str), height - 1)
      return {
        "operator": field(state, "pubKeyOperator", str),
        "key_scheme": scheme(legacy=field(state, "version", int) == 1),
        "sig_scheme": scheme(legacy=height < self.v19),
      }
    if ttype in OWNER_SIGNED:
      state = self.masternode(field(p, "proTxHash", str), height - 1)
      shares = state.get("shares")
      owners = (
        [field(s, "ownerAddress", str) for s in shares]
        if shares
        else [field(state, "ownerAddress", str)]
      )
      return {"key_ids": [key_id(a) for a in owners]}
    quorum = field(p, "signal", dict) if ttype == 7 else p
    keys = self.quorums(field(quorum, "quorumHash", str))
    return {"quorum": keys[str(QUORUM_TYPES[network][ttype])]}

  def row(self, txid: str, network: str) -> dict:
    """Return the corpus row of transaction *txid*."""
    tx = self.node.call("getrawtransaction", txid, True)
    height = field(tx, "height", int)
    return {
      "source": f"{network} block {height}",
      "network": network,
      "raw": field(tx, "hex", str),
      "signer": self.signer(tx, height, network),
    }


def render(rows: list[tuple[str, str, dict]], version: str) -> str:
  """Return the corpus text, a comment header and then *rows*."""
  lines = [
    "//",
    "// Special transactions and the keys their signers held at the block",
    "// before. Generated by pkgs/primitives/contrib/sighash.py with the",
    f"// reference implementation (dashpay/dash {version}).",
    "//",
    "",
    "{",
    '  "sighash": {',
  ]
  for txid, note, row in rows:
    lines += [f"    // {note}", f"    {json.dumps(txid)}: {json.dumps(row)},"]
  lines += ["  },", "}", ""]
  return "\n".join(lines)


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description=__doc__.splitlines()[0] if __doc__ else None
  )
  parser.add_argument(
    "--node",
    nargs=2,
    action="append",
    required=True,
    metavar=("HOST:PORT", "COOKIE"),
    help="RPC address and cookie file of a node, once per chain",
  )
  parser.add_argument(
    "--output", type=Path, default=CORPUS, help="file to write"
  )
  return parser.parse_args()


def main() -> None:
  args = parse_args()
  chains: dict[str, Chain] = {}
  versions = set()
  for address, cookie in args.node:
    node = Node(address, Path(cookie).expanduser())
    chain = field(node.call("getblockchaininfo"), "chain", str)
    if chain in chains:
      raise RpcError(f"two nodes on chain {chain}")
    chains[chain] = Chain(node)
    versions.add(field(node.call("getnetworkinfo"), "buildversion", str))
  if sorted(chains) != sorted(ROWS):
    raise RpcError(f"the corpus needs nodes on {' and '.join(ROWS)}")
  if len(versions) != 1:
    raise RpcError(f"nodes run different versions {sorted(versions)}")
  rows = [
    (txid, note, chains[chain].row(txid, NETWORKS[chain]))
    for chain, listed in ROWS.items()
    for txid, note in listed
  ]
  args.output.write_text(render(rows, versions.pop()), encoding="latin-1")


if __name__ == "__main__":
  try:
    main()
  except (RpcError, OSError, ValueError) as err:
    sys.exit(f"sighash: {err}")
