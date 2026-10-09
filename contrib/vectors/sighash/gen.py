#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Builds the payload sign-hash corpus from transactions Dash Core signed.

  gen.py --sigvec FILE... --regtest-vectors FILE --header FILE \\
    --out pkgs/primitives/corpus/sighash.json5

`--sigvec` takes the extractor's files: special transactions read from
dashd with `getblock 2`, each with the keys Core held for its signer at the
block before (`protx info` or `protx listdiff`, and `quorum info`).
`--regtest-vectors` takes rust-dashcore's
`dash/tests/data/core_v24_regtest.json`, whose asset unlocks carry dashd's
`txid`, and its `instanceHash` where Core prints one: for a version-2
unlock, whose txid is stable.

The corpus keeps each transaction and the keys only. Key ids are the
base58check payloads of the addresses Core printed; nothing is computed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NO_SIGNATURE = {5, 8}


def key_id(address: str) -> str:
  """The 20-byte hash of a P2PKH address, checksum checked."""
  n = 0
  for c in address:
    n = n * 58 + B58.index(c)
  raw = n.to_bytes(25, "big")
  body, check = raw[:-4], raw[-4:]
  digest = hashlib.sha256(hashlib.sha256(body).digest()).digest()
  if digest[:4] != check:
    raise ValueError(f"bad checksum: {address}")
  return body[1:].hex()


def p2pkh_key_id(script: str) -> str:
  if not (script.startswith("76a914") and script.endswith("88ac")):
    raise ValueError(f"not P2PKH: {script}")
  return script[6:46]


def signer(entry: dict) -> dict | None:
  """The keys the entry's signatures verify under, or None if unsigned."""
  ttype, s = entry["type"], entry.get("signer") or {}
  kind = s.get("kind")
  if ttype in NO_SIGNATURE or kind == "internal_collateral":
    return None
  if ttype == 6:
    key = entry["core"]["commitment"]["quorumPublicKey"]
    return None if set(key) == {"0"} else {"commitment": True}
  if kind == "external_collateral":
    return {"key_ids": [p2pkh_key_id(s["collateral_script"])]}
  if kind == "internal_collateral_with_shares":
    return {"shares": True}
  if kind == "quorum":
    q = s["quorum"]
    return {"llmq_type": q["llmq_type"], "quorum": q["quorum_public_key"]}
  if ttype in (2, 4):
    return {
      "operator": s["operator_pubkey"],
      "operator_legacy": s["mn_version"] == 1,
    }
  owners = [s["owner_address"]] if s.get("owner_address") else []
  owners += s.get("share_owner_addresses") or []
  return {"key_ids": [key_id(a) for a in owners]}


def sighash_entries(paths: list[str]) -> dict[str, dict]:
  out: dict[str, dict] = {}
  for path in paths:
    doc = json.loads(Path(path).read_text())
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


def stable_entries(path: str) -> dict[str, dict]:
  out: dict[str, dict] = {}
  for tx in json.loads(Path(path).read_text())["transactions"]:
    if tx["shape"][0] != 9:
      continue
    entry = {"source": tx["source"], "raw": tx["hex"]}
    # Core prints the instance hash exactly when the txid is stable.
    if "instanceHash" in tx["core"]:
      entry["instance_hash"] = tx["core"]["instanceHash"]
    out[tx["core"]["txid"]] = entry
  return out


def main() -> None:
  p = argparse.ArgumentParser(description=__doc__)
  p.add_argument("--sigvec", nargs="+", required=True)
  p.add_argument("--regtest-vectors", required=True)
  p.add_argument("--header", type=argparse.FileType(), required=True)
  p.add_argument("--out", required=True)
  args = p.parse_args()
  lines = [args.header.read().rstrip("\n"), "{"]
  sections = (
    ("sighash", sighash_entries(args.sigvec)),
    ("stable_txid", stable_entries(args.regtest_vectors)),
  )
  for name, entries in sections:
    lines.append(f"  {json.dumps(name)}: {{")
    for txid, entry in entries.items():
      lines.append(f"    {json.dumps(txid)}: {json.dumps(entry)},")
    lines.append("  },")
  lines.append("}")
  Path(args.out).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
  main()
