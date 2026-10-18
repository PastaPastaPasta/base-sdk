#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Extracts a regtest DKG transcript and has Dash Core check every step.

The transcript comes from a functional-test run of a release dashd under
-capturemessages (see README.md): the qcontrib, qcomplaint, qjustify,
qpcommit, qfcommit and qsigrec messages of each quorum, the members in
Core's order (from debug.log) and the operators' secret keys (from the
command lines the run logged). Every derived value (a decrypted share, an
aggregated verification vector, a recovered signature) and every verdict
comes from Core's BLS code through the oracle (probe.c, ABI 14).

  dkg.py --probe PROBE --run RUN_DIR --argv ARGV_LOG --out dkg.json5
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path
from typing import Any

import oracle as o
from gen import emit

BASIC = False  # regtest v24: V19 is active, so the basic scheme throughout
MAX_RECSIGS = 4  # recovered signatures kept per quorum
WANTED = (
  "qcontrib",
  "qcomplaint",
  "qjustify",
  "qpcommit",
  "qfcommit",
  "qsigrec",
)
ZERO_SIG = bytes(96)


class Reader:
  """Core's serialization, read field by field."""

  def __init__(self, data: bytes) -> None:
    self.data, self.pos = data, 0

  def take(self, n: int) -> bytes:
    if self.pos + n > len(self.data):
      msg = "message too short"
      raise ValueError(msg)
    out = self.data[self.pos : self.pos + n]
    self.pos += n
    return out

  def int(self, n: int) -> int:
    return int.from_bytes(self.take(n), "little")

  def compact(self) -> int:
    first = self.int(1)
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}.get(first)
    return first if width is None else self.int(width)

  def bits(self) -> list[bool]:
    n = self.compact()
    packed = self.take((n + 7) // 8)
    return [bool(packed[i // 8] >> (i % 8) & 1) for i in range(n)]

  def vec(self, size: int) -> list[bytes]:
    return [self.take(size) for _ in range(self.compact())]

  def end(self) -> None:
    if self.pos != len(self.data):
      msg = "trailing bytes"
      raise ValueError(msg)


def sign_hash(raw: bytes) -> bytes:
  """GetSignHash of a contribution, complaint or justification: the
  message serialized with a null signature."""
  return o.sha256d(raw[:-96] + ZERO_SIG)


def commitment_hash(
  llmq_type: int, quorum: bytes, valid: list[bool], pk: bytes, vvec: bytes
) -> bytes:
  """BuildCommitmentHash."""
  return o.sha256d(bytes([llmq_type]) + quorum + o.dynbitset(valid) + pk + vvec)


def captures(run: Path) -> list[tuple[str, bytes]]:
  """Every captured message of every node, each distinct one once."""
  seen: dict[tuple[str, bytes], None] = {}
  for path in sorted(run.glob("node*/regtest/message_capture/*/msgs_*.dat")):
    data, pos = path.read_bytes(), 0
    while pos < len(data):
      cmd = data[pos + 8 : pos + 20].rstrip(b"\0").decode()
      (n,) = struct.unpack_from("<I", data, pos + 20)
      seen.setdefault((cmd, data[pos + 24 : pos + 24 + n]))
      pos += 24 + n
  return list(seen)


def parse(cmd: str, raw: bytes) -> dict[str, Any]:
  r = Reader(raw)
  m: dict[str, Any] = {"raw": raw}
  if cmd == "qfcommit":
    version = r.int(2)
    m |= {"version": version, "llmq_type": r.int(1), "quorum": r.take(32)}
    if version in (2, 4):
      m["quorum_index"] = r.int(2)
    m |= {"signers": r.bits(), "valid": r.bits(), "pk": r.take(48)}
    m |= {"vvec_hash": r.take(32), "quorum_sig": r.take(96)}
    m["members_sig"] = r.take(96)
  elif cmd == "qsigrec":
    m |= {"llmq_type": r.int(1), "quorum": r.take(32), "id": r.take(32)}
    m |= {"msg_hash": r.take(32), "sig": r.take(96)}
  else:
    m |= {"llmq_type": r.int(1), "quorum": r.take(32), "pro_tx": r.take(32)}
    if cmd == "qcontrib":
      m["vvec"] = r.vec(48)
      start = r.pos
      r.take(48 + 32)
      for _ in range(r.compact()):
        r.take(r.compact())
      m["ies"] = raw[start : r.pos]
    elif cmd == "qcomplaint":
      m |= {"bad": r.bits(), "complain_for": r.bits()}
    elif cmd == "qjustify":
      m["keys"] = [(r.int(4), r.take(32)) for _ in range(r.compact())]
    elif cmd == "qpcommit":
      m |= {"valid": r.bits(), "pk": r.take(48), "vvec_hash": r.take(32)}
      m["quorum_sig"] = r.take(96)
    m["sig"] = r.take(96)
  r.end()
  return m


def member_orders(run: Path) -> dict[bytes, list[str]]:
  """Core's member order per quorum public key: the proTxHash prefixes
  CFinalCommitment::VerifySignatureAsync logs."""
  pat = re.compile(r"members\[([0-9a-f |]*)\] quorumPublicKey\[([0-9a-f]+)\]")
  out: dict[bytes, list[str]] = {}
  for log in run.glob("node*/regtest/debug.log"):
    for line in log.read_text(errors="replace").splitlines():
      if (found := pat.search(line)) is not None:
        prefixes = [p.strip() for p in found[1].split("|") if p.strip()]
        out.setdefault(bytes.fromhex(found[2]), prefixes)
  return out


def operator_keys(argv: Path) -> list[bytes]:
  keys = re.findall(r"-masternodeblsprivkey=([0-9a-f]{64})", argv.read_text())
  return [bytes.fromhex(k) for k in dict.fromkeys(keys)]


def display(h: bytes) -> str:
  """uint256::ToString: the stored bytes reversed."""
  return h[::-1].hex()


class Transcript:
  """The captured messages, checked through the oracle under the basic
  scheme."""

  def __init__(self, probe: o.Probe, messages: list[tuple[str, bytes]]) -> None:
    self.p = probe
    self.msgs: dict[str, list[dict[str, Any]]] = {}
    for cmd, raw in messages:
      if cmd in WANTED:
        self.msgs.setdefault(cmd, []).append(parse(cmd, raw))

  def call(self, op: int, *args: object) -> tuple[int, bytes]:
    return self.p.call(op, BASIC, *args)

  def must(self, op: int, *args: object) -> bytes:
    return self.p.must(op, BASIC, *args)

  def verify(self, pk: bytes, sig: bytes, h: bytes) -> bool:
    return self.p.holds(o.VERIFY, BASIC, o.Sig(sig), o.Pk(pk), o.Raw(h))

  def pubkey(self, sk: bytes) -> bytes:
    return self.must(o.PUBLIC_KEY, o.Sk(sk))

  def pk_share(self, vvec: list[bytes], pro_tx: bytes) -> bytes:
    return self.must(o.PK_SHARE, [o.Pk(v) for v in vvec], o.Raw(pro_tx))

  def of(self, cmd: str, fc: dict[str, Any]) -> list[dict[str, Any]]:
    """A session's messages: one LLMQ type's, for one quorum hash."""
    key = (fc["llmq_type"], fc["quorum"])
    return [
      m for m in self.msgs.get(cmd, []) if (m["llmq_type"], m["quorum"]) == key
    ]

  def operators(self, keys: list[bytes]) -> dict[bytes, bytes]:
    """proTxHash -> operator secret key: the key whose public key verifies
    a contribution the masternode signed."""
    pks = {sk: self.pubkey(sk) for sk in keys}
    out: dict[bytes, bytes] = {}
    for m in self.msgs.get("qcontrib", []):
      if m["pro_tx"] in out:
        continue
      for sk, pk in pks.items():
        if self.verify(pk, m["sig"], sign_hash(m["raw"])):
          out[m["pro_tx"]] = sk
          break
    return out

  def share_fits(self, vvec: list[bytes], pro_tx: bytes, sk: bytes) -> bool:
    """Whether a secret key share fits a verification vector at an id:
    PublicKeyShare(vvec, id) == GetPublicKey(share)."""
    ret, pk = self.call(o.PUBLIC_KEY, o.Sk(sk))
    return ret == o.OK and self.pk_share(vvec, pro_tx) == pk


def build_quorum(
  t: Transcript, fc: dict[str, Any], members: list[bytes],
  operators: dict[bytes, bytes],
) -> dict[str, Any]:  # fmt: skip
  """One quorum's DKG: every message, what Core derives from it, and the
  verdicts."""
  quorum, llmq_type = fc["quorum"], fc["llmq_type"]
  op_sks = [operators[m] for m in members]
  op_pks = [t.pubkey(sk) for sk in op_sks]
  index = {m: i for i, m in enumerate(members)}

  def signed(m: dict[str, Any]) -> dict[str, Any]:
    """A member's signed phase message and the verdict on its signature."""
    i, h = index[m["pro_tx"]], sign_hash(m["raw"])
    return {
      "member": i, "raw": m["raw"].hex(), "sign_hash": h.hex(),
      "sig_ok": t.verify(op_pks[i], m["sig"], h),
    }  # fmt: skip

  # Each contribution's shares, decrypted by every member and checked
  # against the contributor's verification vector.
  contribs, vvecs, received = [], {}, {}
  for m in t.of("qcontrib", fc):
    row = signed(m)
    i, vvec = row["member"], m["vvec"]
    vvecs[i] = vvec
    shares = []
    for j, sk in enumerate(op_sks):
      ret, share = t.call(
        o.IES_DECRYPT, o.Raw(o.u32(j)), o.Sk(sk), o.Raw(o.blob(m["ies"]))
      )
      fits = ret == o.OK and t.share_fits(vvec, members[j], share)
      shares.append(
        {"share": share.hex() if ret == o.OK else None, "fits": fits}
      )
      if fits:
        received[(i, j)] = share
    row |= {"vvec": [v.hex() for v in vvec], "ies": m["ies"].hex()}
    contribs.append(row | {"shares": shares})

  complaints = [
    signed(m) | {"bad": m["bad"], "complain_for": m["complain_for"]}
    for m in t.of("qcomplaint", fc)
  ]

  justifications = []
  for m in t.of("qjustify", fc):
    row = signed(m)
    i, keys = row["member"], []
    for j, key in m["keys"]:
      fits = i in vvecs and t.share_fits(vvecs[i], members[j], key)
      keys.append({"index": j, "key": key.hex(), "fits": fits})
      if fits:
        received[(i, j)] = key
    justifications.append(row | {"keys": keys})

  # BuildQuorumVerificationVector over the valid members' vectors, then
  # each member's share: the sum of what the valid members sent it.
  valid = fc["valid"]
  qualified = [i for i, v in enumerate(valid) if v]
  qvvec = [
    t.must(o.AGGREGATE_PK, [o.Pk(vvecs[i][k]) for i in qualified])
    for k in range(len(vvecs[qualified[0]]))
  ]
  member_shares = []
  for j in range(len(members)):
    parts = [received.get((i, j)) for i in qualified]
    if any(part is None for part in parts):
      member_shares.append(None)
      continue
    sk = t.must(o.AGGREGATE_SK, [o.Sk(part or b"") for part in parts])
    member_shares.append({
      "sk": sk.hex(), "pk_share": t.pk_share(qvvec, members[j]).hex(),
      "fits": t.share_fits(qvvec, members[j], sk),
    })  # fmt: skip

  pk = fc["pk"]
  chash = commitment_hash(llmq_type, quorum, valid, pk, fc["vvec_hash"])
  premature, by_member = [], {}
  for m in t.of("qpcommit", fc):
    i = index[m["pro_tx"]]
    h = commitment_hash(llmq_type, quorum, m["valid"], m["pk"], m["vvec_hash"])
    share_pk = t.pk_share(qvvec, members[i])
    premature.append({
      "member": i, "raw": m["raw"].hex(), "commitment_hash": h.hex(),
      "sig_ok": t.verify(op_pks[i], m["sig"], h),
      "share_ok": t.verify(share_pk, m["quorum_sig"], h),
      "matches_final": h == chash,
    })  # fmt: skip
    if h == chash:
      by_member[i] = m

  # The final commitment's two signatures, checked and rebuilt from the
  # signers' premature commitments.
  signer_ids = [i for i, s in enumerate(fc["signers"]) if s]
  shares = [by_member[i]["quorum_sig"] for i in signer_ids]
  msigs = [by_member[i]["sig"] for i in signer_ids]
  spks = [o.Pk(op_pks[i]) for i in signer_ids]
  final = {
    "raw": fc["raw"].hex(), "commitment_hash": chash.hex(),
    "signers": fc["signers"], "valid": valid, "quorum_pk": pk.hex(),
    "vvec_hash": fc["vvec_hash"].hex(),
    "quorum_vvec": [v.hex() for v in qvvec],
    "vvec_hash_ok": o.sha256d(o.vec(qvvec)) == fc["vvec_hash"],
    "quorum_pk_ok": qvvec[0] == pk,
    "quorum_sig_ok": t.verify(pk, fc["quorum_sig"], chash),
    "members_sig_ok": t.p.holds(
      o.VERIFY_SECURE, BASIC, o.Sig(fc["members_sig"]), spks, o.Raw(chash)
    ),
    "recovered_sig": t.must(
      o.RECOVER_SIG, [o.Sig(s) for s in shares],
      o.hashes(members[i] for i in signer_ids),
    ).hex(),
    "members_sig_rebuilt": t.must(
      o.AGGREGATE_SECURE, [o.Sig(s) for s in msigs], spks, o.Raw(chash)
    ).hex(),
  }  # fmt: skip

  recovered = []
  for m in t.of("qsigrec", fc)[:MAX_RECSIGS]:
    h = o.sha256d(bytes([llmq_type]) + quorum + m["id"] + m["msg_hash"])
    recovered.append({
      "raw": m["raw"].hex(), "sign_hash": h.hex(), "sig": m["sig"].hex(),
      "ok": t.verify(pk, m["sig"], h),
    })  # fmt: skip

  return {
    "llmq_type": llmq_type, "quorum_hash": quorum.hex(),
    "members": [
      {"pro_tx": m.hex(), "operator_sk": sk.hex(), "operator_pk": pk_.hex()}
      for m, sk, pk_ in zip(members, op_sks, op_pks, strict=True)
    ],
    "contributions": contribs, "complaints": complaints,
    "justifications": justifications, "member_shares": member_shares,
    "premature": premature, "final": final, "recovered": recovered,
  }  # fmt: skip


def main() -> int:
  ap = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  ap.add_argument("--probe", required=True)
  ap.add_argument("--run", type=Path, required=True)
  ap.add_argument("--argv", type=Path, required=True)
  ap.add_argument("--out", type=Path, required=True)
  args = ap.parse_args()

  probe = o.Probe(args.probe)
  t = Transcript(probe, captures(args.run))
  operators = t.operators(operator_keys(args.argv))
  orders = member_orders(args.run)
  by_prefix = {display(p)[:4]: p for p in operators}
  if len(by_prefix) != len(operators):
    msg = "two members share a debug.log prefix"
    raise o.OracleError(msg)
  quorums = []
  finals = sorted(
    (m for m in t.msgs.get("qfcommit", []) if any(m["signers"])),
    key=lambda m: m["raw"],
  )
  for fc in finals:
    members = [by_prefix[p] for p in orders[fc["pk"]]]
    quorums.append(build_quorum(t, fc, members, operators))
  header = (
    f"Dash Core {probe.core_version} regtest DKG transcript"
    " (feature_llmq_dkgerrors.py); see PROVENANCE.md."
  )
  probe.close()
  emit(args.out, header, {"scheme": "basic", "quorums": quorums})
  return 0


if __name__ == "__main__":
  sys.exit(main())
