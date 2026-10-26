#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Builds BLS vectors whose every outcome comes from Dash Core.

Inputs are derived from fixed labels; each output, verdict and decode
outcome is what Dash Core's own BLS code returns through the consensus
oracle (probe.c, ABI 14; relic.json5 ABI 19). See README.md.

  gen.py --probe PROBE --out-dir pkgs/pkc/corpus/bls_oracle [--only FILE]...
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import oracle as o

if TYPE_CHECKING:
  from collections.abc import Callable

  Row = dict[str, object]

# BLS12-381's group order.
R = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
SCHEMES = {"legacy": True, "basic": False}
WRAPPER_DIR = Path(__file__).resolve().parent.parent / "bls_wrapper"


def h(*parts: object) -> bytes:
  """A 32-byte value derived from a label."""
  text = "/".join(str(p) for p in parts)
  return hashlib.sha256(b"bs12 " + text.encode()).digest()


def sk_of(*parts: object) -> bytes:
  """A secret key derived from a label, as Core serializes one."""
  v = int.from_bytes(h("sk", *parts), "big") % R
  return (v or 1).to_bytes(32, "big")


def sks(items: list[bytes]) -> list[o.Obj]:
  return [o.Sk(b) for b in items]


def pk_list(items: list[bytes]) -> list[o.Obj]:
  return [o.Pk(b) for b in items]


def sigs(items: list[bytes]) -> list[o.Obj]:
  return [o.Sig(b) for b in items]


class Gen:
  """Generates one scheme's rows through the probe."""

  def __init__(self, probe: o.Probe, legacy: bool) -> None:
    self.p = probe
    self.legacy = legacy

  def must(self, op: int, *args: object) -> bytes:
    return self.p.must(op, self.legacy, *args)

  def holds(self, op: int, *args: object) -> bool:
    return self.p.holds(op, self.legacy, *args)

  def call(self, op: int, *args: object) -> tuple[int, bytes]:
    return self.p.call(op, self.legacy, *args)

  def obj(self, op: int, *args: object) -> str | None:
    """An object op's output, or None where Core yields an invalid one."""
    ret, out = self.call(op, *args)
    if ret == o.OK:
      return out.hex()
    if ret == o.REJECT:
      return None
    msg = f"op {op} returned {ret}"
    raise o.OracleError(msg)

  def pk(self, sk: bytes) -> bytes:
    return self.must(o.PUBLIC_KEY, o.Sk(sk))

  def sign(self, sk: bytes, msg: bytes) -> bytes:
    return self.must(o.SIGN, o.Sk(sk), o.Raw(msg))

  def verify(self, pk: bytes, sig: bytes, msg: bytes) -> bool:
    return self.holds(o.VERIFY, o.Sig(sig), o.Pk(pk), o.Raw(msg))


def hash_to_g2(g: Gen) -> list[Row]:
  msgs = [bytes(32), b"\xff" * 32, bytes(31) + b"\x01"]
  msgs += [h("h2g2", i) for i in range(13)]
  return [
    {"msg": m.hex(), "point": g.must(o.HASH_TO_G2, o.Raw(m)).hex()}
    for m in msgs
  ]


def flip_sign(raw: bytes, legacy: bool) -> bytes:
  """The negated point: the scheme's sign bit toggled."""
  out = bytearray(raw)
  out[0] ^= 0x80 if legacy else 0x20
  return bytes(out)


def sign_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "sign", i) for i in range(8)]
  pks = [g.pk(sk) for sk in keys]
  msgs = [h("sign msg", i) for i in range(2)]
  sign, verify = [], []
  for i, sk in enumerate(keys):
    for m in msgs:
      sig = g.sign(sk, m)
      sign.append({"key": i, "msg": m.hex(), "sig": sig.hex()})

  def check(pk: bytes, sig: bytes, msg: bytes, note: str) -> None:
    ok = g.verify(pk, sig, msg)
    verify.append(
      {"pk": pk.hex(), "sig": sig.hex(), "msg": msg.hex(), "ok": ok,
       "note": note}
    )  # fmt: skip

  for i, row in enumerate(sign[:8]):
    sig, msg = bytes.fromhex(str(row["sig"])), bytes.fromhex(str(row["msg"]))
    pk = pks[int(str(row["key"]))]
    check(pk, sig, msg, "signed")
    check(pk, sig, h("sign wrong", i), "other message")
    check(pks[(int(str(row["key"])) + 1) % 8], sig, msg, "other key")
    check(pk, flip_sign(sig, g.legacy), msg, "negated signature")
    check(flip_sign(pk, g.legacy), sig, msg, "negated key")
  check(bytes(48), bytes.fromhex(str(sign[0]["sig"])), msgs[0], "zero key")
  check(pks[0], bytes(96), msgs[0], "zero signature")
  return {
    "keys": [
      {"sk": sk.hex(), "pk": pk.hex()} for sk, pk in zip(keys, pks, strict=True)
    ],
    "sign": sign,
    "verify": verify,
  }


def aggregate_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "agg", i) for i in range(6)]
  pks = [g.pk(sk) for sk in keys]
  msg = h("agg msg")
  same = [g.sign(sk, msg) for sk in keys]
  msgs = [h("agg msg", i) for i in range(6)]
  distinct = [g.sign(sk, m) for sk, m in zip(keys, msgs, strict=True)]
  out: dict[str, list[Row]] = {
    "sk": [], "pk": [], "sig": [], "sub": [], "same_msg": [], "distinct": [],
  }  # fmt: skip
  for n in range(1, 7):
    out["sk"].append(
      {
        "sks": [k.hex() for k in keys[:n]],
        "agg": g.obj(o.AGGREGATE_SK, sks(keys[:n])),
      }
    )
    agg_pk = g.must(o.AGGREGATE_PK, pk_list(pks[:n]))
    out["pk"].append({"pks": [p.hex() for p in pks[:n]], "agg": agg_pk.hex()})
    agg = g.must(o.AGGREGATE_SIG, sigs(same[:n]))
    out["sig"].append({"sigs": [s.hex() for s in same[:n]], "agg": agg.hex()})
    # Core's same-message check: VerifyInsecure against the summed key.
    for m, note in ((msg, "signed"), (h("agg wrong"), "other message")):
      out["same_msg"].append({
        "pks": [p.hex() for p in pks[:n]], "sig": agg.hex(), "msg": m.hex(),
        "ok": g.verify(agg_pk, agg, m), "note": note,
      })  # fmt: skip
    dagg = g.must(o.AGGREGATE_SIG, sigs(distinct[:n]))
    cases = [(msgs[:n], "signed")]
    cases.append(([h("agg wrong"), *msgs[1:n]], "first message changed"))
    for ms, note in cases:
      ok = g.holds(
        o.VERIFY_AGGREGATED, o.Sig(dagg), pk_list(pks[:n]), o.hashes(ms)
      )
      out["distinct"].append({
        "pks": [p.hex() for p in pks[:n]], "msgs": [m.hex() for m in ms],
        "sig": dagg.hex(), "ok": ok, "note": note,
      })  # fmt: skip
  # Two signers over one message inside a distinct-message aggregate.
  dup = g.must(o.AGGREGATE_SIG, sigs([same[0], same[1], distinct[2]]))
  dup_msgs = [msg, msg, msgs[2]]
  out["distinct"].append({
    "pks": [p.hex() for p in pks[:3]], "msgs": [m.hex() for m in dup_msgs],
    "sig": dup.hex(),
    "ok": g.holds(
      o.VERIFY_AGGREGATED, o.Sig(dup), pk_list(pks[:3]), o.hashes(dup_msgs)
    ),
    "note": "a repeated message",
  })  # fmt: skip
  # A key and its negation sum to the identity.
  neg = flip_sign(pks[0], g.legacy)
  out["pk"].append(
    {
      "pks": [pks[0].hex(), neg.hex()],
      "agg": g.obj(o.AGGREGATE_PK, pk_list([pks[0], neg])),
    }
  )
  for i in range(1, 4):
    agg = g.must(o.AGGREGATE_SIG, sigs(same[: i + 1]))
    out["sub"].append({
      "sig": agg.hex(), "other": same[i].hex(),
      "out": g.obj(o.SUB_SIG, o.Sig(agg), o.Sig(same[i])),
    })  # fmt: skip
  return out


def secure_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "secure", i) for i in range(7)]
  pks = [g.pk(sk) for sk in keys]
  msg = h("secure msg")
  signed = [g.sign(sk, msg) for sk in keys]
  agg_rows, verify = [], []

  def aggregate(ss: list[bytes], ps: list[bytes], note: str) -> bytes | None:
    out = g.obj(o.AGGREGATE_SECURE, sigs(ss), pk_list(ps), o.Raw(msg))
    agg_rows.append({
      "sigs": [s.hex() for s in ss], "pks": [p.hex() for p in ps],
      "msg": msg.hex(), "agg": out, "note": note,
    })  # fmt: skip
    return None if out is None else bytes.fromhex(out)

  def check(sig: bytes, ps: list[bytes], m: bytes, note: str) -> None:
    ok = g.holds(o.VERIFY_SECURE, o.Sig(sig), pk_list(ps), o.Raw(m))
    verify.append({
      "sig": sig.hex(), "pks": [p.hex() for p in ps], "msg": m.hex(),
      "ok": ok, "note": note,
    })  # fmt: skip

  for n in (1, 2, 3, 5, 7):
    agg = aggregate(signed[:n], pks[:n], f"{n} signers")
    if agg is None:
      continue
    check(agg, pks[:n], msg, "signed")
    check(agg, pks[:n][::-1], msg, "keys reversed")
    check(agg, pks[:n], h("secure wrong"), "other message")
    if n > 1:
      check(agg, pks[: n - 1], msg, "a key missing")
      plain = g.must(o.AGGREGATE_SIG, sigs(signed[:n]))
      check(plain, pks[:n], msg, "insecure aggregate")
  twice = aggregate(
    [signed[0], signed[0]], [pks[0], pks[0]], "one signer twice"
  )
  if twice is not None:
    check(twice, [pks[0], pks[0]], msg, "one signer twice")
  rev = aggregate(signed[:3][::-1], pks[:3][::-1], "3 signers reversed")
  if rev is not None:
    check(rev, pks[:3], msg, "aggregated reversed")
  return {"aggregate": agg_rows, "verify": verify}


def threshold_rows(g: Gen, tag: str) -> list[Row]:
  cases = []
  for t in (1, 2, 3, 4):
    n = t + 2
    msk = [sk_of(tag, "msk", t, i) for i in range(t)]
    mpk = [g.pk(sk) for sk in msk]
    ids = [h("id", t, i) for i in range(n)]
    sk_shares = [g.obj(o.SK_SHARE, sks(msk), o.Raw(i)) for i in ids]
    pk_shares = [g.obj(o.PK_SHARE, pk_list(mpk), o.Raw(i)) for i in ids]
    msg = h("threshold msg", t)
    master_sig = g.sign(msk[0], msg)
    sig_shares = [
      g.sign(bytes.fromhex(s), msg) if s else None for s in sk_shares
    ]
    recover = []
    subsets = [list(range(t)), list(range(n - t, n)), list(range(n))]
    subsets += [list(range(t - 1)), [0, *range(t - 1)]]
    for subset in subsets:
      if not subset or any(sig_shares[i] is None for i in subset):
        continue
      shares = [sig_shares[i] or b"" for i in subset]
      sig = g.obj(o.RECOVER_SIG, sigs(shares), o.hashes(ids[i] for i in subset))
      recover.append({
        "subset": subset, "sig": sig,
        "is_master": sig == master_sig.hex(),
      })  # fmt: skip
    cases.append({
      "t": t, "msk": [k.hex() for k in msk], "mpk": [p.hex() for p in mpk],
      "ids": [i.hex() for i in ids], "sk_shares": sk_shares,
      "pk_shares": pk_shares, "msg": msg.hex(), "master_sig": master_sig.hex(),
      "sig_shares": [s.hex() if s else None for s in sig_shares],
      "recover": recover,
    })  # fmt: skip
  return cases


def ies_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "ies", i) for i in range(4)]
  pks = [g.pk(sk) for sk in keys]
  layouts = [
    ("one share", [32]),
    ("three shares", [32, 32, 32]),
    ("mixed lengths", [16, 48, 64, 32]),
    ("misaligned", [32, 33]),
    ("empty", [0]),
  ]
  multi, blobs = [], []
  for case, (note, lengths) in enumerate(layouts):
    eph = sk_of(tag, "ies eph", case)
    iv = h("ies iv", tag, case)
    recips = pks[: len(lengths)]
    plains = [h("ies data", case, i, "x") * 3 for i in range(len(lengths))]
    plains = [p[:n] for p, n in zip(plains, lengths, strict=True)]
    ret, enc = g.call(
      o.IES_ENCRYPT, o.Sk(eph), o.Raw(iv), pk_list(recips), o.blobs(plains)
    )
    if ret not in (o.OK, o.REJECT):
      msg = f"IES encrypt returned {ret}"
      raise o.OracleError(msg)
    out = enc.hex() if ret == o.OK else None
    row: Row = {
      "eph_sk": eph.hex(), "iv_seed": iv.hex(),
      "recipients": [p.hex() for p in recips],
      "plaintexts": [p.hex() for p in plains], "out": out, "note": note,
      "decrypt": [],
    }  # fmt: skip
    if out is not None:
      enc = bytes.fromhex(out)
      tries = [(i, keys[i]) for i in range(len(lengths))]
      tries += [(0, keys[-1]), (len(lengths), keys[0])]
      decrypts = []
      for idx, sk in tries:
        ret, plain = g.call(
          o.IES_DECRYPT, o.Raw(o.u32(idx)), o.Sk(sk), o.Raw(o.blob(enc))
        )
        if ret not in (o.OK, o.REJECT):
          msg = f"IES decrypt returned {ret}"
          raise o.OracleError(msg)
        decrypts.append({
          "idx": idx, "sk": sk.hex(),
          "plain": plain.hex() if ret == o.OK else None,
        })  # fmt: skip
      row["decrypt"] = decrypts
      eph_pk = enc[:48]
      for i in range(len(lengths)):
        ct = enc_blob(enc, i)
        one = eph_pk + iv + o.blob(ct)
        ret, plain = g.call(
          o.IES_DECRYPT_BLOB, o.Raw(o.u32(i)), o.Sk(keys[i]), o.Raw(o.blob(one))
        )
        blobs.append({
          "idx": i, "sk": keys[i].hex(), "blob": one.hex(),
          "plain": plain.hex() if ret == o.OK else None,
        })  # fmt: skip
    multi.append(row)
  return {"multi": multi, "blob": blobs}


def enc_blob(enc: bytes, index: int) -> bytes:
  """Blob `index` of a serialized CBLSIESMultiRecipientBlobs."""
  pos = 48 + 32
  count, pos = o.read_compact(enc, pos)
  for i in range(count):
    n, pos = o.read_compact(enc, pos)
    if i == index:
      return enc[pos : pos + n]
    pos += n
  msg = "no such blob"
  raise IndexError(msg)


EXOTIC = (
  "tors_",
  "nonsub_",
  "off_",
)  # bls_wrapper classes off G1/G2's subgroup


def edge_rows(probe: o.Probe, decoded: list[Row]) -> list[Row]:
  """Core's verifications over invalid and exotic operands: objects decoded
  under one scheme, verified under either flag."""
  exotic = {
    kind: [
      bytes.fromhex(str(r["in"]))
      for r in decoded
      if r["kind"] == kind
      and str(r["class"]).startswith(EXOTIC)
      and str(r["eager_legacy"]).startswith("V")
    ][:2]
    for kind in ("pk", "sig")
  }
  zero_pk, zero_sig = bytes(48), bytes(96)
  rows: list[Row] = []
  for decode, legacy in SCHEMES.items():
    g = Gen(probe, legacy)
    keys = [sk_of("edge", decode, i) for i in range(2)]
    pks = [g.pk(sk) for sk in keys]
    msgs = [h("edge msg", i) for i in range(2)]
    sig = g.sign(keys[0], msgs[0])
    agg = g.must(o.AGGREGATE_SIG, sigs([sig, g.sign(keys[1], msgs[1])]))
    same = [g.sign(sk, msgs[0]) for sk in keys]
    sec = g.must(o.AGGREGATE_SECURE, sigs(same), pk_list(pks), o.Raw(msgs[0]))
    # Core aggregates an invalid object's element, infinity, as it verifies.
    zero_sigs, zero_pks = [same[0], zero_sig], [pks[0], zero_pk]
    sec_zero = g.must(
      o.AGGREGATE_SECURE, sigs(zero_sigs), pk_list(zero_pks), o.Raw(msgs[0])
    )
    xpk, xsig = (exotic["pk"], exotic["sig"]) if legacy else ([], [])
    insecure = [(sig, pks[0], "signed"), (zero_sig, pks[0], "invalid sig")]
    insecure += [(sig, zero_pk, "invalid key")]
    insecure += [(sig, x, "exotic key") for x in xpk]
    insecure += [(x, pks[0], "exotic sig") for x in xsig]
    aggregated = [
      (agg, pks, msgs, "signed"),
      (agg, [pks[0], zero_pk], msgs, "an invalid key"),
      (zero_sig, [], [], "invalid sig, no keys"),
      (agg, pks, [msgs[0], msgs[0]], "a message twice"),
    ]
    aggregated += [(agg, [pks[0], x], msgs, "an exotic key") for x in xpk]
    aggregated += [(x, pks, msgs, "exotic sig") for x in xsig]
    secure = [
      (sec, pks, "signed"),
      (sec, [pks[0], zero_pk], "an invalid key"),
      (zero_sig, [zero_pk], "all invalid"),
      (zero_sig, [zero_pk, zero_pk], "all invalid, twice"),
      (sec, [zero_pk], "invalid key"),
      (sec_zero, zero_pks, "signed with an invalid key"),
      (sec_zero, zero_pks[::-1], "signed with an invalid key, reversed"),
    ]
    secure += [(sec, [pks[0], x], "an exotic key") for x in xpk]
    secure += [(x, pks, "exotic sig") for x in xsig]
    for flag, flag_legacy in SCHEMES.items():

      def row(
        op: str,
        s: bytes,
        ps: list[bytes],
        ms: list[bytes],
        ok: bool,
        note: str,
        decode: str = decode,
        flag: str = flag,
      ) -> Row:
        return {
          "op": op,
          "decode": decode,
          "flag": flag,
          "sig": s.hex(),
          "pks": [p.hex() for p in ps],
          "msgs": [m.hex() for m in ms],
          "ok": ok,
          "note": note,
        }

      for s, p, note in insecure:
        ok = probe.holds(
          o.VERIFY, legacy, o.Sig(s), o.Pk(p), o.Raw(msgs[0]), flag=flag_legacy
        )
        rows.append(row("insecure", s, [p], msgs[:1], ok, note))
      for s, ps, ms, note in aggregated:
        ok = probe.holds(
          o.VERIFY_AGGREGATED,
          legacy,
          o.Sig(s),
          pk_list(ps),
          o.hashes(ms),
          flag=flag_legacy,
        )
        rows.append(row("aggregated", s, ps, ms, ok, note))
      for s, ps, note in secure:
        ok = probe.holds(
          o.VERIFY_SECURE,
          legacy,
          o.Sig(s),
          pk_list(ps),
          o.Raw(msgs[0]),
          flag=flag_legacy,
        )
        rows.append(row("secure", s, ps, msgs[:1], ok, note))
  return rows


# Points outside the subgroup that the legacy scheme reads (bls_wrapper's
# rules): (0, +-2), G1's points of order 3, are x = 0 with the sign bit; x = 1
# is off G1 (1 + 4 is a non-residue) and off G2 (1 + 4(1 + u) is one).
G1_ORDER3 = b"\x80" + bytes(47)
G1_OFF = bytes(47) + b"\x01"
G2_OFF = bytes(47) + b"\x01" + bytes(48)
# The scalar of the reference implementation's relic probes.
K = b"\x3a" + b"\x5a" * 31


class Steps:
  """A script whose every op is logged and is a row's step; a step that
  stores names its register by the step's index. Objects are made under
  the script's scheme and the other ops run under `flag` (by default the
  same)."""

  def __init__(self, legacy: bool, flag: bool | None = None) -> None:
    self.script = o.Script(legacy)
    self.flag = flag
    self.steps: list[Row] = []
    self.regs: dict[int, int] = {}

  def add(
    self,
    op: int,
    name: str,
    operands: bytes,
    flag: bool | None = None,
    extra: int = 0,
    **fields: object,
  ) -> int:
    flag = self.flag if flag is None else flag
    self.script.emit(op, operands, flag, o.LOG | extra)
    index = len(self.steps)
    if op in o.STORES:
      self.regs[index] = self.script.regs - 1
    step: Row = {"op": name}
    if flag is not None and flag != self.script.legacy:
      step["flag"] = "legacy" if flag else "basic"
    self.steps.append(step | fields)
    return index

  def r(self, *steps: int) -> bytes:
    return bytes(self.regs[s] for s in steps)

  def decode(self, kind: str, raw: bytes) -> int:
    code = {"sk": o.SK, "pk": o.PK, "sig": o.SIG}[kind]
    operands = bytes([code, o.EAGER]) + o.blob(raw)
    legacy = self.script.legacy
    return self.add(
      o.DECODE, "decode", operands, legacy, kind=kind, input=raw.hex()
    )

  def pubkey(self, sk: int) -> int:
    legacy = self.script.legacy
    return self.add(o.PUBLIC_KEY, "pubkey", self.r(sk), legacy, a=sk)

  def sign(self, sk: int, msg: bytes) -> int:
    operands = self.r(sk) + msg
    legacy = self.script.legacy
    return self.add(o.SIGN, "sign", operands, legacy, a=sk, msg=msg.hex())

  def unary(self, op: int, name: str, a: int) -> int:
    return self.add(op, name, self.r(a), a=a)

  def binary(self, op: int, name: str, a: int, b: int) -> int:
    return self.add(op, name, self.r(a, b), a=a, b=b)

  def mul(self, a: int, k: bytes) -> int:
    return self.add(o.MUL, "mul", self.r(a) + k, a=a, k=k.hex())

  def verify(
    self, sig: int, pk: int, msg: bytes, flag: bool | None = None
  ) -> int:
    operands = self.r(sig, pk) + msg
    return self.add(
      o.VERIFY, "verify", operands, flag, sig=sig, pk=pk, msg=msg.hex()
    )

  def agg(self, kind: str, items: list[int], pair: bool = False) -> int:
    op = o.AGGREGATE_PK if kind == "pk" else o.AGGREGATE_SIG
    operands = o.vec(self.r(i) for i in items)
    extra = o.PAIR if pair else 0
    return self.add(
      op, f"agg_{kind}", operands, extra=extra, items=items, pair=pair
    )

  def dh(self, sk: int, pk: int, recv: int | None = None) -> int:
    if recv is None:
      return self.add(o.DH, "dh", self.r(sk, pk), sk=sk, pk=pk)
    operands = self.r(recv, sk, pk)
    return self.add(
      o.DH, "dh", operands, extra=o.INPLACE, sk=sk, pk=pk, recv=recv
    )

  def rl(self, steps: list[int]) -> bytes:
    return o.vec(self.r(s) for s in steps)

  def agg_sk(self, items: list[int]) -> int:
    return self.add(o.AGGREGATE_SK, "agg_sk", self.rl(items), items=items)

  def sub_sig(self, a: int, b: int) -> int:
    return self.binary(o.SUB_SIG, "sub_sig", a, b)

  def agg_secure(self, sigs: list[int], keys: list[int], msg: bytes) -> int:
    operands = self.rl(sigs) + self.rl(keys) + msg
    return self.add(
      o.AGGREGATE_SECURE, "agg_secure", operands, sigs=sigs, keys=keys,
      msg=msg.hex(),
    )  # fmt: skip

  def verify_sec(self, sig: int, keys: list[int], msg: bytes) -> int:
    operands = self.r(sig) + self.rl(keys) + msg
    return self.add(
      o.VERIFY_SECURE, "verify_sec", operands, sig=sig, keys=keys,
      msg=msg.hex(),
    )  # fmt: skip

  def share(
    self, kind: str, items: list[int], ident: bytes, recv: int | None = None
  ) -> int:
    op = o.SK_SHARE if kind == "sk" else o.PK_SHARE
    fields: dict[str, object] = {"items": items, "id": ident.hex()}
    operands = self.rl(items) + ident
    if recv is None:
      return self.add(op, f"{kind}_share", operands, **fields)
    return self.add(
      op, f"{kind}_share", self.r(recv) + operands, extra=o.INPLACE,
      recv=recv, **fields,
    )  # fmt: skip

  def recover(
    self, items: list[int], ids: list[bytes], recv: int | None = None
  ) -> int:
    fields: dict[str, object] = {"items": items, "ids": [i.hex() for i in ids]}
    operands = self.rl(items) + o.hashes(ids)
    if recv is None:
      return self.add(o.RECOVER_SIG, "recover_sig", operands, **fields)
    return self.add(
      o.RECOVER_SIG, "recover_sig", self.r(recv) + operands, extra=o.INPLACE,
      recv=recv, **fields,
    )  # fmt: skip

  def ies_encrypt(
    self, sk: int, seed: bytes, keys: list[int], plain: list[bytes]
  ) -> int:
    operands = self.r(sk) + seed + self.rl(keys) + o.blobs(plain)
    return self.add(
      o.IES_ENCRYPT, "ies_encrypt", operands, sk=sk, seed=seed.hex(),
      keys=keys, plain=[x.hex() for x in plain],
    )  # fmt: skip

  def ies_decrypt(self, blob: bool, idx: int, sk: int, data: bytes) -> int:
    op = o.IES_DECRYPT_BLOB if blob else o.IES_DECRYPT
    name = "ies_decrypt_blob" if blob else "ies_decrypt"
    operands = o.u32(idx) + self.r(sk) + o.blob(data)
    return self.add(op, name, operands, idx=idx, sk=sk, data=data.hex())

  def decode_as(self, kind: str, raw: bytes, flag: bool) -> int:
    """`DECODE` under `flag` rather than the script's scheme."""
    code = {"sk": o.SK, "pk": o.PK, "sig": o.SIG}[kind]
    operands = bytes([code, o.EAGER]) + o.blob(raw)
    return self.add(
      o.DECODE, "decode", operands, flag, kind=kind, input=raw.hex()
    )

  def run(self, probe: o.Probe) -> list[Row]:
    records = probe.exec(self.script)
    if len(records) != len(self.steps):
      msg = f"{len(records)} records for {len(self.steps)} steps"
      raise o.OracleError(msg)
    for step, rec in zip(self.steps, records, strict=True):
      log = [[symbol, code] for symbol, code in rec.log or []]
      step |= {
        "status": rec.status,
        "code": rec.code,
        "out": rec.output.hex(),
        "log": log,
      }
    return self.steps


def relic_rows(probe: o.Probe) -> list[Row]:
  """The reference implementation's relic arithmetic on points outside the
  subgroup, through its wrappers under the legacy scheme: the design's
  probes P1 to P5 and its fixed vectors, each op with relic's code and the
  relic calls it made. A legacy signature runs first: dashbls reads two
  constants once per process, and their calls would land in the first
  legacy hash's log."""
  if probe.abi < o.RELIC_ABI:
    msg = f"relic.json5 needs ABI {o.RELIC_ABI}, the probe has {probe.abi}"
    raise o.OracleError(msg)
  digest = h("relic msg")
  zero, one, three = (v.to_bytes(32, "big") for v in (0, 1, 3))
  rows: list[Row] = []
  warm = Steps(legacy=True)
  warm.sign(warm.decode("sk", one), digest)
  warm.run(probe)

  def row(probe_id: str, note: str, s: Steps) -> None:
    rows.append(
      {
        "probe": probe_id,
        "scheme": "legacy" if s.script.legacy else "basic",
        "note": note,
        "steps": s.run(probe),
      }
    )

  s = Steps(legacy=True)
  p = s.decode("pk", G1_ORDER3)
  s.unary(o.IS_VALID, "is_valid", p)
  q = s.mul(p, K)
  s.unary(o.IS_VALID, "is_valid", q)
  s.mul(p, one)
  s.mul(p, three)
  row(
    "P1 P2",
    "P2: [k](0, 2) for a 255-bit k gives (0, 0); P1, fp_inv(0) = 0 when"
    " normalizing a zero z, is its wrapper consequence, not observed here",
    s,
  )

  s = Steps(legacy=True)
  g = s.pubkey(s.decode("sk", one))
  q = s.mul(s.decode("pk", G1_ORDER3), K)
  projc = s.binary(o.ADD, "add", g, s.unary(o.NEG, "neg", g))
  basic = s.mul(g, zero)
  reset = s.unary(o.NEG, "neg", projc)
  for inf in (projc, basic, reset):
    s.binary(o.IMPL_EQ, "impl_eq", inf, q)
    s.binary(o.EQ, "eq", inf, q)
  row("fixed G1", "G + (-G), [0]G and -(G + (-G)) against [k](0, 2)", s)

  s = Steps(legacy=True)
  h2 = s.sign(s.decode("sk", one), digest)
  off = s.decode("sig", G2_OFF)
  zero_z = s.binary(o.ADD, "add", off, off)
  projc = s.binary(o.ADD, "add", h2, s.unary(o.NEG, "neg", h2))
  reset = s.unary(o.NEG, "neg", projc)
  for inf in (projc, reset, s.mul(h2, zero)):
    s.binary(o.IMPL_EQ, "impl_eq", inf, zero_z)
  s.unary(o.IS_VALID, "is_valid", zero_z)
  row("fixed G2", "infinities against a doubled off-curve G2 point (y = 0)", s)

  s = Steps(legacy=True)
  p = s.decode("pk", G1_OFF)
  s.unary(o.IS_VALID, "is_valid", p)
  s.binary(o.ADD, "add", p, p)
  s.mul(p, K)
  s.mul(p, one)
  row("P3", "g1_add and g1_mul on an off-curve point", s)

  s = Steps(legacy=True)
  g = s.pubkey(s.decode("sk", one))
  off = s.decode("sig", G2_OFF)
  s.verify(off, g, digest)
  s.verify(off, g, digest, flag=False)
  row(
    "P4 P5",
    "P5: an off-curve signature's zero Miller value, rejected; P4, FE(0) = 0,"
    " is its wrapper consequence, not observed here",
    s,
  )
  return rows


# relic's GLV and GLS constants: lambda = x^2 - 1 and |x|, the BLS12-381
# parameter, which bound bn_rec_glv's and bn_rec_frb's digits.
LAMBDA = 0xAC45A4010001A40200000000FFFFFFFF
X_ABS = 0xD201000000010000
G1_OFF_S1 = b"\x80" + bytes(46) + b"\x01"
ZEROS = {"pk": bytes(48), "sig": bytes(96)}  # Core's invalid objects


def arith_scalars() -> list[bytes]:
  """The design's scalar classes (section 8): the mul_dig boundary, r and
  its neighbours, 2^256 - 1, and scalars at the GLV and GLS recodings'
  boundaries."""
  values = [0, 1, 2, 2**64 - 1, 2**64, R - 1, R, R + 1, 2**256 - 1]
  values += [LAMBDA - 1, LAMBDA, LAMBDA + 1, R // 2, R // 2 + 1]
  values += [X_ABS, X_ABS + 1, X_ABS**2, X_ABS**3 % R, LAMBDA * LAMBDA % R]
  values += [int.from_bytes(h("arith k", i), "big") for i in range(2)]
  return [v.to_bytes(32, "big") for v in values]


def arith_rows(probe: o.Probe, decoded: list[Row]) -> list[Row]:
  """Core's element operations over mixed registers (BS11a-3 D17, the
  design's section 8 seeds), in both groups: every row of the design's
  section 3.1 shape table against Exotic values and a zero-z engine
  result, the scalar classes, the span and pair aggregations, DH with
  invalid sides and a kept element, and SER_HASH's cache. Each op is
  logged, as in relic.json5."""
  if probe.abi < o.ARITH_ABI:
    msg = f"arith.json5 needs ABI {o.ARITH_ABI}, the probe has {probe.abi}"
    raise o.OracleError(msg)
  digest = h("arith msg")
  zero, one = bytes(32), (1).to_bytes(32, "big")
  order = R.to_bytes(32, "big")
  warm = Steps(legacy=True)
  warm.sign(warm.decode("sk", one), digest)
  warm.run(probe)
  exotic = {
    kind: [
      bytes.fromhex(str(r["in"]))
      for r in decoded
      if r["kind"] == kind
      and str(r["class"]).startswith(EXOTIC)
      and str(r["eager_legacy"]).startswith("V")
    ][:3]
    for kind in ("pk", "sig")
  }
  exotic["pk"] += [G1_ORDER3, G1_OFF, G1_OFF_S1]
  exotic["sig"] += [G2_OFF]
  off = {"pk": G1_OFF, "sig": G2_OFF}
  rows: list[Row] = []

  def row(name: str, note: str, s: Steps) -> None:
    rows.append(
      {
        "probe": name,
        "scheme": "legacy" if s.script.legacy else "basic",
        "note": note,
        "steps": s.run(probe),
      }
    )

  def usable(s: Steps, kind: str) -> tuple[int, int]:
    sk1, sk2 = s.decode("sk", one), s.decode("sk", sk_of("arith", kind))
    if kind == "pk":
      return s.pubkey(sk1), s.pubkey(sk2)
    return s.sign(sk1, digest), s.sign(sk2, digest)

  def neg(s: Steps, a: int) -> int:
    return s.unary(o.NEG, "neg", a)

  def add(s: Steps, a: int, b: int) -> int:
    return s.binary(o.ADD, "add", a, b)

  def shapes(s: Steps, p: int, q: int) -> list[int]:
    """The shape table's producers on Usable values."""
    infb, infp, fin = s.mul(p, zero), add(s, p, neg(s, p)), add(s, p, q)
    return [
      p, infb, infp, fin, neg(s, infp), neg(s, infb), neg(s, fin),
      add(s, infb, p), add(s, p, infb), add(s, infp, infb),
      add(s, infb, infp), add(s, infp, p), add(s, p, infp),
      add(s, infp, infp),
    ]  # fmt: skip

  def engines(s: Steps, kind: str) -> list[int]:
    """An Exotic value, a zero-z engine result and an engine product."""
    e = s.decode(kind, exotic[kind][-1])
    o_ = s.decode(kind, off[kind])
    return [e, add(s, o_, o_), s.mul(e, K)]

  for kind in ("pk", "sig"):
    for flag in (True, False):
      s = Steps(legacy=True, flag=flag)
      p, q = usable(s, kind)
      shape, engine = shapes(s, p, q), engines(s, kind)
      for a in shape:
        s.unary(o.IS_VALID, "is_valid", a)
        for b in engine:
          s.binary(o.IMPL_EQ, "impl_eq", a, b)
          s.binary(o.EQ, "eq", a, b)
          add(s, a, b)
          add(s, b, a)
      for b in engine:
        s.unary(o.IS_VALID, "is_valid", b)
      row(
        f"shape {kind}",
        "the shape table's producers against an Exotic value, a zero-z"
        " engine result and an engine product",
        s,
      )

    s = Steps(legacy=False)
    p, q = usable(s, kind)
    shape = [*shapes(s, p, q), s.decode(kind, ZEROS[kind])]
    for i, a in enumerate(shape):
      s.unary(o.IS_VALID, "is_valid", a)
      for b in shape[i:]:
        s.binary(o.IMPL_EQ, "impl_eq", a, b)
        s.binary(o.EQ, "eq", a, b)
    row(f"shape {kind}", "the shape table's producers among themselves", s)

    s = Steps(legacy=True)
    p, q = usable(s, kind)
    infp = add(s, p, neg(s, p))
    bases = [p, infp, add(s, p, q), *engines(s, kind)]
    bases += [s.decode(kind, x) for x in exotic[kind][:-1]]
    for a in bases:
      for k in arith_scalars():
        s.mul(a, k)
    row(f"scalars {kind}", "the scalar classes on Usable and Exotic values", s)

    for flag in (True, False):
      s = Steps(legacy=True, flag=flag)
      p, q = usable(s, kind)
      invalid = s.decode(kind, ZEROS[kind])
      infp = add(s, p, neg(s, p))
      e, z, w = engines(s, kind)
      xs = [s.decode(kind, x) for x in exotic[kind][:-1]]
      spans = [[], [p], [e], [invalid], [p, q, e, invalid, infp, z]]
      spans += [[infp, s.mul(p, zero)], [z, e], [w, p, w]]
      spans += [[x, neg(s, x)] for x in xs] + [[x, p] for x in xs]
      for span in spans:
        s.agg(kind, span)
      for a, b in [(p, e), (e, z), (infp, p), (p, invalid), (invalid, e)]:
        s.agg(kind, [a, b], pair=True)
      row(f"agg {kind}", "span and pair aggregation over mixed registers", s)

  for flag in (True, False):
    for legacy in (True, False):
      s = Steps(legacy=legacy, flag=flag)
      p, _ = usable(s, "pk")
      sks = [s.decode("sk", one), s.decode("sk", sk_of("arith dh"))]
      sks += [s.decode("sk", zero)]
      if not legacy:
        sks.append(s.decode("sk", order))
      pks = [p, add(s, p, neg(s, p)), s.decode("pk", ZEROS["pk"])]
      kept = p
      if legacy:
        e, z, w = engines(s, "pk")
        pks += [e, z, w] + [s.decode("pk", x) for x in exotic["pk"][:-1]]
        kept = e
      for sk in sks:
        for pk in pks:
          d = s.dh(sk, pk)
          s.add(o.SER, "ser", s.r(d), flag=not flag, a=d)
      k = s.dh(sks[2], kept, recv=kept)
      s.unary(o.IS_VALID, "is_valid", k)
      s.binary(o.IMPL_EQ, "impl_eq", k, kept)
      s.binary(o.EQ, "eq", k, kept)
      s.unary(o.SER, "ser", k)
      add(s, k, p)
      note = "DH over valid, invalid and Exotic sides, and a kept element"
      row("dh", note, s)

  for kind in ("pk", "sig"):
    s = Steps(legacy=True)
    p, q = usable(s, kind)
    invalid = s.decode(kind, ZEROS[kind])
    infp = add(s, p, neg(s, p))
    regs = [p, add(s, p, q), infp, invalid, *engines(s, kind)]
    for a in regs:
      s.unary(o.SER, "ser", a)
      s.add(o.SER, "ser", s.r(a), flag=False, a=a)
      s.unary(o.SER_HASH, "ser_hash", a)
      s.add(o.SER_HASH, "ser_hash", s.r(a), flag=False, a=a)
    for a in regs:
      b = s.unary(o.NEG, "neg", s.unary(o.NEG, "neg", a))
      s.add(o.SER_HASH, "ser_hash", s.r(b), flag=False, a=b)
      s.unary(o.SER_HASH, "ser_hash", b)
    row(f"ser {kind}", "SER and SER_HASH's cache under both flags", s)
  return rows


def be(v: int) -> bytes:
  return (v % (1 << 256)).to_bytes(32, "big")


def warmed(probe: o.Probe, name: str) -> None:
  """Signs once under the legacy scheme, so call logs compare (relic.json5)."""
  if probe.abi < o.ARITH_ABI:
    msg = f"{name}.json5 needs ABI {o.ARITH_ABI}, the probe has {probe.abi}"
    raise o.OracleError(msg)
  warm = Steps(legacy=True)
  warm.sign(warm.decode("sk", (1).to_bytes(32, "big")), h("warm"))
  warm.run(probe)


def scripted(
  probe: o.Probe, builders: dict[str, Callable[[Steps], str]]
) -> list[Row]:
  """One row per builder and scheme; each builder returns its note."""
  rows: list[Row] = []
  for name, build in builders.items():
    for scheme, legacy in SCHEMES.items():
      s = Steps(legacy)
      note = build(s)
      rows.append(
        {"probe": name, "scheme": scheme, "note": note, "steps": s.run(probe)}
      )
  return rows


def ies_outputs(probe: o.Probe, s: Steps, steps: list[int]) -> list[bytes]:
  """The outputs `steps` give when `s` runs so far: IES containers fed back
  as decrypt operands. The steps are deterministic, so the full run
  reproduces them."""
  trial = Steps(s.script.legacy)
  trial.script.code = bytearray(s.script.code)
  trial.script.regs = s.script.regs
  trial.script.logged = list(s.script.logged)
  trial.steps = [dict(step) for step in s.steps]
  done = trial.run(probe)
  return [bytes.fromhex(str(done[i]["out"])) for i in steps]


def ops_rows(probe: o.Probe) -> list[Row]:
  """Core's wrapper operations BS11b ports (its notes, D5 to D17): secret
  key sums, SubInsecure, AggregateSecure and its verify, threshold shares
  and recovery, and multi-recipient IES, over valid, invalid and
  kept-element operands, each step logged as in arith.json5."""
  warmed(probe, "ops")
  msg = h("ops msg")

  def aggregates(s: Steps) -> str:
    k1 = sk_of("ops", 1)
    a, b = s.decode("sk", k1), s.decode("sk", sk_of("ops", 2))
    neg = s.decode("sk", be(R - int.from_bytes(k1, "big")))
    zero = s.decode("sk", bytes(32))
    s.agg_sk([a, b])
    s.agg_sk([a])
    s.agg_sk([])
    s.agg_sk([a, zero])
    total = s.agg_sk([a, neg])
    s.unary(o.SER, "ser", total)
    s.pubkey(total)
    if not s.script.legacy:
      order = s.decode("sk", be(R))
      s.agg_sk([order, a])
      s.pubkey(order)
    x, y = s.sign(a, msg), s.sign(b, msg)
    s.sub_sig(x, y)
    s.sub_sig(x, x)
    s.sub_sig(x, s.decode("sig", bytes(96)))
    return "secret key sums (zero, r, an invalid operand), SubInsecure"

  def secure(s: Steps) -> str:
    keys = [s.decode("sk", sk_of("ops sec", i)) for i in range(3)]
    pks = [s.pubkey(k) for k in keys]
    sigs_ = [s.sign(k, msg) for k in keys]
    no_pk = s.decode("pk", bytes(48))
    for n in (1, 2, 3):
      agg = s.agg_secure(sigs_[:n], pks[:n], msg)
      s.verify_sec(agg, pks[:n], msg)
      s.verify_sec(agg, list(reversed(pks[:n])), msg)
    s.agg_secure(sigs_[:2], [pks[0], pks[0]], msg)
    s.agg_secure([sigs_[1], sigs_[0]], [pks[0], pks[0]], msg)
    agg = s.agg_secure(sigs_[:2], [pks[0], no_pk], msg)
    s.verify_sec(agg, [pks[0], no_pk], msg)
    s.agg_secure(sigs_[:2], pks[:1], msg)
    s.agg_secure([], [], msg)
    return (
      "AggregateSecure of 1 to 3 signers and its verify, a repeated key,"
      " an invalid key, unequal and empty lists"
    )

  def shares(s: Steps) -> str:
    msk = [s.decode("sk", sk_of("ops msk", i)) for i in range(3)]
    mpk = [s.pubkey(k) for k in msk]
    rnd = h("ops id")
    shifted = be(int.from_bytes(rnd, "big") % R + R)
    for ident in (bytes(32), be(R), be(R + 5), be(5), rnd, shifted):
      sk = s.share("sk", msk, ident)
      pk = s.share("pk", mpk, ident)
      s.binary(o.EQ, "eq", s.pubkey(sk), pk)
    five = be(5)
    s.share("sk", msk[:1], five)
    s.share("pk", mpk[:1], five)
    s.share("sk", [], five)
    no_sk, no_pk = s.decode("sk", bytes(32)), s.decode("pk", bytes(48))
    s.share("sk", [msk[0], no_sk], five)
    s.share("pk", [mpk[0], no_pk], five)
    kept = s.share("pk", [mpk[0], no_pk], five, recv=mpk[2])
    s.binary(o.IMPL_EQ, "impl_eq", kept, mpk[2])
    s.share("pk", mpk, five, recv=mpk[2])
    kept = s.share("sk", [msk[0], no_sk], five, recv=msk[2])
    s.agg_sk([kept])
    s.agg_sk([kept, msk[0]])
    s.share("sk", msk, five, recv=msk[2])
    return (
      "SecretKeyShare and PublicKeyShare at ids 0, r, r + 5, 5, a random id"
      " and its r-shift; one and no coefficients; an invalid one; INPLACE,"
      " a failure's kept element read back by IMPL_EQ and key sums"
    )

  def recovery(s: Steps) -> str:
    msk = [s.decode("sk", sk_of("ops rec", i)) for i in range(3)]
    mpk = s.pubkey(msk[0])
    ids = [h("ops rec id", i) for i in range(5)]
    sigs_ = [s.sign(s.share("sk", msk, i), msg) for i in ids]
    s.verify(s.recover(sigs_[:3], ids[:3]), mpk, msg)
    s.verify(s.recover(sigs_[2:5], ids[2:5]), mpk, msg)
    s.verify(s.recover(sigs_[:2], ids[:2]), mpk, msg)
    s.recover(sigs_, ids)
    s.recover(sigs_[:1], ids[:1])
    s.recover([], [])
    s.recover(sigs_[:3], ids[:2])
    dup = be(int.from_bytes(ids[0], "big") % R + R)
    s.recover(sigs_[:3], [ids[0], dup, ids[2]])
    s.recover(sigs_[:3], [ids[0], bytes(32), ids[2]])
    s.recover(sigs_[:3], [ids[0], be(R), ids[2]])
    no_sig = s.decode("sig", bytes(96))
    s.recover([sigs_[0], no_sig, sigs_[2]], ids[:3])
    kept = s.recover([sigs_[0], no_sig, sigs_[2]], ids[:3], recv=sigs_[4])
    s.binary(o.IMPL_EQ, "impl_eq", kept, sigs_[4])
    s.recover(sigs_[:3], ids[:3], recv=sigs_[4])
    return (
      "Recover of full, other, short and long subsets, one share, none,"
      " unequal lists, ids equal mod r, zero and r ids, an invalid share,"
      " INPLACE, a failure's kept element read back by IMPL_EQ"
    )

  def ies(s: Steps) -> str:
    keys = [s.decode("sk", sk_of("ops ies", i)) for i in range(3)]
    pks = [s.pubkey(k) for k in keys]
    eph = s.decode("sk", sk_of("ops ies eph"))
    seed = h("ops ies seed")
    no_pk = s.decode("pk", bytes(48))
    data = [h("ops ies", i) for i in range(3)]
    cases = [
      (pks, data),
      (pks[:1], [b""]),
      (pks[:2], [data[0] + data[1][:16], data[1][:16]]),
      (pks[:2], [data[0][:17], data[1]]),
      ([pks[0], no_pk, pks[2]], data),
    ]
    encs = [s.ies_encrypt(eph, seed, r, d) for r, d in cases]
    containers = ies_outputs(probe, s, encs)
    for (recips, _), enc in zip(cases, containers, strict=True):
      for i in range(len(recips) + 1):
        s.ies_decrypt(False, i, keys[min(i, 2)], enc)
      s.ies_decrypt(False, 0, keys[1], enc)
      s.ies_decrypt(False, 0, s.decode("sk", bytes(32)), enc)
      s.ies_decrypt(False, 0, keys[0], enc[:-1])
      s.ies_decrypt(False, 0, keys[0], enc + b"\x00")
      first = enc_blob(enc, 0)
      one = enc[:80] + o.blob(first)
      s.ies_decrypt(True, 0, keys[0], one)
      s.ies_decrypt(True, 1, keys[0], one)
    return (
      "multi-recipient IES: three recipients, an empty plaintext, mixed and"
      " misaligned lengths, an invalid recipient; decrypt at every index,"
      " with another or an invalid key, a truncated or extended container,"
      " and the single blob"
    )

  return scripted(
    probe,
    {
      "aggregates": aggregates,
      "secure": secure,
      "shares": shares,
      "recovery": recovery,
      "ies": ies,
    },
  )


def quirk22_rows(probe: o.Probe, decoded: list[Row]) -> list[Row]:
  """Quirk 22 through BS11b's operations: an object whose bytes are
  canonical only in the other scheme decodes invalid holding the default
  element, which the ungated operations take as the infinity and the gated
  ones refuse; legacy keys outside the subgroup or off the curve go through
  them unchecked; and an IES plaintext of r, above r or zeros decodes as a
  secret key with Core's outcome under each flag."""
  warmed(probe, "quirk22")
  msg = h("quirk22 msg")

  def opposite(kind: str, scheme: str) -> bytes:
    return next(
      bytes.fromhex(str(r["in"]))
      for r in decoded
      if r["kind"] == kind
      and r[f"eager_{scheme}"] == "I"
      and any(bytes.fromhex(str(r["in"])))
    )

  def exotic(kind: str) -> list[bytes]:
    return [
      bytes.fromhex(str(r["in"]))
      for r in decoded
      if r["kind"] == kind
      and str(r["class"]).startswith(("nonsub_", "off_"))
      and str(r["eager_legacy"]).startswith("V")
    ][:2]

  def fallback(s: Steps) -> str:
    scheme = "legacy" if s.script.legacy else "basic"
    keys = [s.decode("sk", sk_of("q22", i)) for i in range(3)]
    p = [s.pubkey(k) for k in keys]
    x = [s.sign(k, msg) for k in keys]
    q = s.decode("pk", opposite("pk", scheme))
    t = s.decode("sig", opposite("sig", scheme))
    for reg in (q, t):
      s.unary(o.IS_VALID, "is_valid", reg)
      s.unary(o.SER, "ser", reg)
      s.unary(o.SER_HASH, "ser_hash", reg)
    s.binary(o.EQ, "eq", s.agg("pk", [p[0], q, p[1]]), s.agg("pk", p[:2]))
    s.binary(o.EQ, "eq", s.agg("sig", [x[0], t, x[1]]), s.agg("sig", x[:2]))
    s.agg("pk", [p[0], q], pair=True)
    s.agg("sig", [x[0], t], pair=True)
    agg = s.agg_secure(x[:2], [p[0], q], msg)
    s.verify_sec(agg, [p[0], q], msg)
    s.agg_secure([x[0], t], p[:2], msg)
    ids = [h("q22 id", i) for i in range(2)]
    s.share("pk", [p[0], q], ids[0])
    s.recover([x[0], t], ids)
    s.dh(keys[0], q)
    s.ies_encrypt(keys[0], h("q22 seed"), [p[1], q], [msg, msg])
    return (
      "an object canonical only in the other scheme through the wrapper"
      " operations"
    )

  def unchecked(s: Steps) -> str:
    keys = [s.decode("sk", sk_of("q22 x", i)) for i in range(3)]
    p = [s.pubkey(k) for k in keys]
    x = [s.sign(k, msg) for k in keys]
    q = [s.decode_as("pk", raw, True) for raw in exotic("pk")]
    t = [s.decode_as("sig", raw, True) for raw in exotic("sig")]
    ids = [h("q22 x id", i) for i in range(2)]
    for e in q:
      s.unary(o.IS_VALID, "is_valid", e)
      s.share("pk", [e, p[0]], ids[0])
      s.share("pk", [p[0], e], ids[1])
      s.dh(keys[0], e)
      s.agg_secure(x[:2], [p[0], e], msg)
    for e in t:
      s.recover([x[0], e], ids)
      s.recover([e, x[1]], ids)
      s.agg_secure([x[0], e], p[:2], msg)
    return (
      "legacy-decoded keys and signatures off the subgroup or the curve"
      " through shares, recovery, DH and AggregateSecure"
    )

  def secret(s: Steps) -> str:
    keys = [s.decode("sk", sk_of("q22 sk", i)) for i in range(2)]
    p = s.pubkey(keys[1])
    plains = [be(R), be(R + 1), bytes(32), be(R - 1)]
    encs = [s.ies_encrypt(keys[0], h("q22 sk seed"), [p], [d]) for d in plains]
    containers = ies_outputs(probe, s, encs)
    for d, enc in zip(plains, containers, strict=True):
      s.ies_decrypt(False, 0, keys[1], enc)
      for flag in (True, False):
        s.decode_as("sk", d, flag)
    return (
      "IES plaintexts r, r + 1, zero and r - 1 decoded as a secret key"
      " under each flag"
    )

  return scripted(
    probe, {"fallback": fallback, "unchecked": unchecked, "secret": secret}
  )


def decode_rows(probe: o.Probe) -> list[Row]:
  """bls_wrapper's eager inputs, decoded by the oracle eagerly and lazily."""
  # bls_wrapper's generator, loaded by path: it is also named gen. Its
  # directory goes on the path for its own imports.
  sys.path.insert(0, str(WRAPPER_DIR))
  spec = importlib.util.spec_from_file_location(
    "bls_wrapper_gen", WRAPPER_DIR / "gen.py"
  )
  if spec is None or spec.loader is None:
    msg = f"cannot load {WRAPPER_DIR / 'gen.py'}"
    raise o.OracleError(msg)
  wrapper = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(wrapper)

  inputs = wrapper.gen_inputs(random.Random(wrapper.SEED), 3)  # noqa: S311
  kinds = {"pk": o.PK, "sig": o.SIG, "sk": o.SK}
  rows = []
  for kind, entries in inputs.items():
    base = kind.removesuffix("_basic")
    for name, raw in entries:
      row: Row = {"kind": base, "class": name, "in": raw.hex()}
      for scheme, legacy in SCHEMES.items():
        modes = [("eager", o.EAGER)]
        if base != "sk":
          modes.append(("lazy", o.LAZY))
        for mode_name, mode in modes:
          ret, valid, out = probe.decode(kinds[base], mode, legacy, raw)
          row[f"{mode_name}_{scheme}"] = outcome(ret, valid, out)
      rows.append(row)
  return rows


def outcome(ret: int, valid: bool, out: bytes) -> str:
  """T (Core throws), I (invalid, serializes as zeros) or V:<serialization>."""
  if ret == o.E_DECODE:
    return "T"
  if ret != o.OK:
    msg = f"decode returned {ret}"
    raise o.OracleError(msg)
  return f"V:{out.hex()}" if valid else "I"


def per_scheme(probe: o.Probe, build: Callable[[Gen, str], object]) -> Row:
  return {s: build(Gen(probe, legacy), s) for s, legacy in SCHEMES.items()}


def render(value: object, depth: int = 0) -> str:
  """JSON with each record of a list of records on a line of its own."""
  pad = "  " * (depth + 1)
  if isinstance(value, dict) and value:
    items = [
      f"{pad}{json.dumps(k)}: {render(v, depth + 1)}" for k, v in value.items()
    ]
    return "{\n" + ",\n".join(items) + "\n" + "  " * depth + "}"
  if isinstance(value, list) and value and isinstance(value[0], dict):
    items = [pad + json.dumps(v) for v in value]
    return "[\n" + ",\n".join(items) + "\n" + "  " * depth + "]"
  return json.dumps(value)


def emit(path: Path, header: str, body: object) -> None:
  path.write_text(f"// {header}\n" + render(body) + "\n")


def main() -> int:
  ap = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  ap.add_argument("--probe", required=True)
  ap.add_argument("--out-dir", type=Path, required=True)
  ap.add_argument("--only", action="append", help="write only these files")
  args = ap.parse_args()

  probe = o.Probe(args.probe)
  core = probe.core_version
  decoded = functools.cache(lambda: decode_rows(probe))
  builders: dict[str, Callable[[], object]] = {
    "hash_to_g2": lambda: per_scheme(probe, lambda g, _: hash_to_g2(g)),
    "sign": lambda: per_scheme(probe, sign_rows),
    "aggregate": lambda: per_scheme(probe, aggregate_rows),
    "secure": lambda: per_scheme(probe, secure_rows),
    "threshold": lambda: per_scheme(probe, threshold_rows),
    "ies": lambda: per_scheme(probe, ies_rows),
    "decode": lambda: {"rows": decoded()},
    "edge": lambda: {"rows": edge_rows(probe, decoded())},
    "relic": lambda: {"rows": relic_rows(probe)},
    "arith": lambda: {"rows": arith_rows(probe, decoded())},
    "ops": lambda: {"rows": ops_rows(probe)},
    "quirk22": lambda: {"rows": quirk22_rows(probe, decoded())},
  }
  unknown = set(args.only or ()) - builders.keys()
  if unknown:
    ap.error(f"no such file: {', '.join(sorted(unknown))}")
  files = {
    name: build()
    for name, build in builders.items()
    if args.only is None or name in args.only
  }
  probe.close()
  args.out_dir.mkdir(parents=True, exist_ok=True)
  for name, body in files.items():
    header = f"Dash Core {core} BLS vectors ({name}); see PROVENANCE.md."
    emit(args.out_dir / f"{name}.json5", header, body)
  return 0


if __name__ == "__main__":
  sys.exit(main())
