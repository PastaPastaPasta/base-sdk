#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Write the payload sign-hash corpus.

The corpus holds special transactions the reference implementation signed,
each with the keys its signers held at the block before. The primitives tests
check each payload's sign hash by verifying the signature over it. Nothing is
computed here; key ids are the base58check payloads of the addresses the node
printed.

Each chain file is a JSON object read from one node:

  provenance.getblockchaininfo  the node's `getblockchaininfo`
  entries                       one object per special transaction

An entry holds `txid`, `type`, `hex`, `chain` (a name for the chain),
`height`, `core` (the payload as `getblock <hash> 2` prints it) and
`signer`, the signer's keys at the block before:

  kind                 `external_collateral`, `internal_collateral`,
                       `internal_collateral_with_shares`, `mn_state` or
                       `quorum`
  collateral_script    script of the external collateral output
  operator_pubkey      `pubKeyOperator` of the masternode state
  mn_version           `version` of the masternode state
  owner_address        `ownerAddress` of the masternode state
  share_owner_addresses
                       `ownerAddress` of each share of the state
  quorum               `llmq_type` and `quorum_public_key` of the
                       signing quorum (`quorum info`)

The masternode state comes from `protx info <proTxHash> <block hash>`, or
on mainnet from `protx listdiff 1 <block before>`.

Usage:

  ./pkgs/primitives/contrib/sighash.py --header header.txt \\
    regtest-feature_asset_locks.json mainnet.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# Where the corpus is written by default.
CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "sighash.json5"

# Base58 digits.
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Types whose payload carries no signature: the coinbase commitment and the
# asset lock.
NO_SIGNATURE = {5, 8}

# The quorum commitment type.
QUORUM_COMMITMENT = 6

# Types the operator key signs: the service update and the revocation.
OPERATOR_SIGNED = {2, 4}


class CorpusError(Exception):
  """An entry the corpus cannot hold."""


def key_id(address: str) -> str:
  """Return the key id of a P2PKH *address*, checksum checked."""
  n = 0
  for c in address:
    n = n * 58 + B58.index(c)
  raw = n.to_bytes(25, "big")
  body, check = raw[:-4], raw[-4:]
  if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
    raise CorpusError(f"bad checksum: {address}")
  return body[1:].hex()


def p2pkh_key_id(script: str) -> str:
  """Return the key id a P2PKH *script* pays."""
  if not (script.startswith("76a914") and script.endswith("88ac")):
    raise CorpusError(f"not P2PKH: {script}")
  return script[6:46]


def signer(entry: dict) -> dict | None:
  """Return the keys the entry's signatures verify under, or None."""
  ttype, s = entry["type"], entry.get("signer") or {}
  kind = s.get("kind")
  if ttype in NO_SIGNATURE or kind == "internal_collateral":
    return None
  if ttype == QUORUM_COMMITMENT:
    key = entry["core"]["commitment"]["quorumPublicKey"]
    return None if set(key) == {"0"} else {"commitment": True}
  if kind == "external_collateral":
    return {"key_ids": [p2pkh_key_id(s["collateral_script"])]}
  if kind == "internal_collateral_with_shares":
    return {"shares": True}
  if kind == "quorum":
    q = s["quorum"]
    return {"llmq_type": q["llmq_type"], "quorum": q["quorum_public_key"]}
  if ttype in OPERATOR_SIGNED:
    return {
      "operator": s["operator_pubkey"],
      "operator_legacy": s["mn_version"] == 1,
    }
  owners = [s["owner_address"]] if s.get("owner_address") else []
  owners += s.get("share_owner_addresses") or []
  return {"key_ids": [key_id(a) for a in owners]}


def entries(paths: list[Path]) -> dict[str, dict]:
  """Return the signed entries of the chain files at *paths* by txid."""
  out: dict[str, dict] = {}
  for path in paths:
    doc = json.loads(path.read_text())
    chain = doc["provenance"]["getblockchaininfo"]["chain"]
    network = "mainnet" if chain == "main" else chain
    for entry in doc["entries"]:
      keys = signer(entry)
      if keys is None or entry["txid"] in out:
        continue
      out[entry["txid"]] = {
        "source": f"{network}-{entry['chain']} block {entry['height']}",
        "network": network,
        "raw": entry["hex"],
        "signer": keys,
      }
  return out


def render(header: str, found: dict[str, dict]) -> str:
  """Return the corpus text for *found* under the comment *header*."""
  lines = [header.rstrip("\n"), "{", '  "sighash": {']
  lines += [f"    {json.dumps(t)}: {json.dumps(e)}," for t, e in found.items()]
  lines += ["  },", "}"]
  return "\n".join(lines) + "\n"


def main() -> None:
  parser = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  parser.add_argument("chains", nargs="+", type=Path, help="chain files")
  parser.add_argument(
    "--header",
    type=Path,
    required=True,
    help="the comment that heads the corpus",
  )
  parser.add_argument(
    "--output", type=Path, default=CORPUS, help="where to write the corpus"
  )
  args = parser.parse_args()
  text = render(args.header.read_text(), entries(args.chains))
  args.output.write_text(text, encoding="latin-1")


if __name__ == "__main__":
  try:
    main()
  except (CorpusError, KeyError, OSError, ValueError) as err:
    sys.exit(f"sighash: {err!r}")
