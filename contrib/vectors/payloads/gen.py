#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Builds special-payload vectors whose outcomes come from Dash Core.

  gen.py v24 --fixtures DIR --header FILE \\
    --out pkgs/primitives/corpus/v24.json5
  gen.py probe --release v23.1.8=DIR --release v24.0.0-rc.3=DIR \\
    --work DIR --header FILE --out pkgs/primitives/corpus/payload_core.json5

`v24` copies special transactions and Core's JSON for their payloads out of
`getblock 2` fixtures. `probe` asks regtest dashds of each release, under
both BLS flags, what `decoderawtransaction` makes of crafted payloads.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
BLS_CORPUS = ROOT / "pkgs/pkc/corpus/bls_wrapper.json5"
PRIM_CORPUS = ROOT / "pkgs/primitives/corpus"

PAYLOAD_KEYS = (
  "proRegTx", "proUpServTx", "proUpRegTx", "proUpRevTx", "cbTx", "qcTx",
  "mnhfTx", "assetLockTx", "assetUnlockTx", "proDisTx", "proUpShareTx",
  "proUpSharedRegTx",
)  # fmt: skip

# Each flag's extra dashd arguments. Regtest activates V19 at height 1, so
# the basic scheme is in force once block 1 connects; moving V19 keeps the
# legacy one.
FLAGS = {"basic": [], "legacy": ["-testactivationheight=v19@1000"]}


def load_json5(path: Path) -> Any:  # noqa: ANN401
  """Reads the JSON5 subset the corpora use: comments, trailing commas."""
  text = re.sub(r"(?m)^\s*//.*$", "", path.read_text())
  return json.loads(re.sub(r",(\s*[}\]])", r"\1", text))


def cs(n: int) -> bytes:
  """A CompactSize."""
  if n < 0xFD:
    return bytes([n])
  if n <= 0xFFFF:
    return b"\xfd" + n.to_bytes(2, "little")
  return b"\xfe" + n.to_bytes(4, "little")


def var(b: bytes) -> bytes:
  """A CompactSize-prefixed byte string."""
  return cs(len(b)) + b


def u16(n: int) -> bytes:
  return n.to_bytes(2, "little")


def u32(n: int) -> bytes:
  return n.to_bytes(4, "little")


def i64(n: int) -> bytes:
  return n.to_bytes(8, "little", signed=True)


def special_tx(tx_type: int, payload: bytes) -> bytes:
  """A version-3 transaction of `tx_type` with one input, one OP_RETURN
  output and `payload`; decoderawtransaction checks nothing else."""
  ver = u32(3 | tx_type << 16)
  vin = cs(1) + bytes(range(32)) + u32(0) + var(b"") + u32(0xFFFFFFFF)
  vout = cs(1) + i64(0) + var(b"\x6a")
  return ver + vin + vout + u32(0) + var(payload)


def bls_samples() -> dict[str, str]:
  """Inputs of the classes the payload cases use, by Core's outcome under
  the legacy (L) and basic (B) flags in the BS11a-t wrapper corpus."""
  eager = load_json5(BLS_CORPUS)
  pick = {
    # name: (kind, class, L outcome, B outcome)
    "pk_legacy": ("pk", "sub_000", "V", "I"),
    "pk_exotic": ("pk", "off_000", "V", "I"),
    "pk_basic": ("pk", "sub_101", "I", "V"),
    "pk_both": ("pk", "sub_100", "V", "V"),
    "pk_throw": ("pk", "identity", "T", "T"),
    "sig_legacy": ("sig", "sub_legacy_s0", "V", "I"),
    "sig_basic": ("sig", "sub_basic_s1", "I", "V"),
    "sig_throw": ("sig", "identity", "T", "T"),
  }
  out = {}
  for name, (kind, cls, legacy, basic) in pick.items():
    for row in eager[kind]["eager"]:
      if row["class"] == cls and row["L"][0] == legacy and row["B"][0] == basic:
        out[name] = row["in"]
        break
    else:
      sys.exit(f"no {kind} sample of class {cls}")
  return out


def protx_service(ip: list[int], port: int) -> bytes:
  """A legacy CService: IPv4 in IPv6, big-endian port."""
  return bytes(10) + b"\xff\xff" + bytes(ip) + port.to_bytes(2, "big")


P2PKH = bytes.fromhex("76a914") + bytes(range(1, 21)) + bytes.fromhex("88ac")


def proregtx(version: int, pk: bytes) -> bytes:
  return (
    u16(version) + u16(0) + u16(0) + bytes(range(32)) + u32(0)
    + protx_service([1, 2, 3, 4], 9999) + bytes([7]) * 20 + pk
    + bytes([8]) * 20 + u16(0) + var(P2PKH) + bytes(32) + var(bytes(65))
  )  # fmt: skip


def proupregtx(version: int, pk: bytes) -> bytes:
  return (
    u16(version) + bytes([9]) * 32 + u16(0) + pk + bytes([8]) * 20
    + var(P2PKH) + bytes(32) + var(bytes(65))
  )  # fmt: skip


def netinfo(version: int, groups: list[tuple[int, list[bytes]]]) -> bytes:
  """An ExtNetInfo with `groups` in the order given."""
  body = cs(len(groups)) + b"".join(
    bytes([p]) + cs(len(e)) + b"".join(e) for p, e in groups
  )
  return bytes([version]) + body


def proupservtx(version: int, net: bytes, sig: bytes) -> bytes:
  head = u16(version) + (u16(0) if version >= 2 else b"")
  return head + bytes([9]) * 32 + net + var(b"") + bytes(32) + sig


def svc(net: int, addr: bytes, port: int) -> bytes:
  """A NetInfo service entry of any BIP155 network and length."""
  return b"\x01" + bytes([net]) + var(addr) + port.to_bytes(2, "big")


def svc4(ip: list[int], port: int) -> bytes:
  """A NetInfo service entry: tag 1, BIP155 IPv4."""
  return svc(1, bytes(ip), port)


def domain(name: bytes, port: int) -> bytes:
  return b"\x02" + var(name) + port.to_bytes(2, "big")


def cbtx(version: int, sig: bytes, root: bool) -> bytes:
  body = u16(version) + u32(5) + bytes([1]) * 32 + bytes([2]) * 32
  body += cs(0) + sig + i64(1000)
  return body + (bytes([3]) * 32 if root else b"")


def qctx(version: int, pk: bytes, sig: bytes) -> bytes:
  index = u16(0) if version in (2, 4) else b""
  bits = cs(4) + b"\x00"
  commitment = (
    u16(version) + bytes([100]) + bytes([5]) * 32 + index + bits + bits
    + pk + bytes([6]) * 32 + sig + sig
  )  # fmt: skip
  return u16(1) + u32(10) + commitment


def corpus_tx(name: str, section: str, txid: str) -> bytes:
  """A transaction from a section of a base-sdk corpus, by txid."""
  corpus = load_json5(PRIM_CORPUS / f"{name}.json5")
  return bytes.fromhex(corpus[section][txid]["raw"])


def cases() -> dict[str, tuple[bytes, str]]:
  """Crafted transactions and what each one is for."""
  b = {k: bytes.fromhex(v) for k, v in bls_samples().items()}
  out: dict[str, tuple[bytes, str]] = {}

  def add(name: str, tx_type: int, payload: bytes, note: str) -> None:
    out[name] = (special_tx(tx_type, payload), note)

  # Version-sourced lazy keys: legacy for version 1 only, whatever the flag.
  for v in (1, 2):
    for k in ("legacy", "exotic", "basic", "both", "throw"):
      add(f"proregtx_v{v}_pk_{k}", 1, proregtx(v, b[f"pk_{k}"]),
          "operator key; scheme from the version")  # fmt: skip
    for k in ("legacy", "basic"):
      add(f"proupregtx_v{v}_pk_{k}", 3, proupregtx(v, b[f"pk_{k}"]),
          "operator key; scheme from the version")  # fmt: skip
  # Version-sourced eager signatures; Core prints none, only the verdict.
  net = protx_service([1, 2, 3, 4], 9999)
  for v in (1, 2):
    for k in ("legacy", "basic", "throw"):
      add(f"proupservtx_v{v}_sig_{k}", 2, proupservtx(v, net, b[f"sig_{k}"]),
          "operator signature; scheme from the version")  # fmt: skip
      rev = u16(v) + bytes([9]) * 32 + u16(0) + bytes(32) + b[f"sig_{k}"]
      add(f"prouprevtx_v{v}_sig_{k}", 4, rev,
          "operator signature; scheme from the version")  # fmt: skip
  # Final commitments: legacy for versions 1 and 2.
  for v in (1, 2, 3, 4):
    for k in ("legacy", "basic", "throw"):
      add(f"qctx_v{v}_{k}", 6, qctx(v, b[f"pk_{k}"], b[f"sig_{k}"]),
          "commitment BLS fields; scheme from the version")  # fmt: skip
  # Global-sourced eager signatures: the flag decides.
  for k in ("legacy", "basic", "throw"):
    add(f"cbtx_v3_sig_{k}", 5, cbtx(3, b[f"sig_{k}"], root=False),
        "ChainLock signature; scheme from the flag")  # fmt: skip
    au = (
      bytes([1]) + i64(7) + u32(1000) + u32(20) + bytes([4]) * 32
      + b[f"sig_{k}"]
    )  # fmt: skip
    add(f"assetunlock_v1_sig_{k}", 9, au,
        "quorum signature; scheme from the flag")  # fmt: skip
    mnhf = bytes([1, 10]) + bytes([4]) * 32 + b[f"sig_{k}"]
    add(f"mnhf_sig_{k}", 7, mnhf, "quorum signature; always basic")
    shared = (
      u16(1) + bytes([9]) * 32 + b[f"pk_{k}"] + bytes([8]) * 20
      + bytes(32) + cs(1) + bytes(65)
    )  # fmt: skip
    add(f"proupsharedregtx_pk_{k}", 12, shared,
        "operator key; always basic (v24 type)")  # fmt: skip
  # Only types 3 and 4 are probed; see PLAN §7 handling.
  for tx_type, name in ((3, "proupregtx"), (4, "prouprevtx")):
    for version, tail in ((0, b""), (4, b""), (0xFFFF, b""), (4, b"\x00")):
      label = f"{name}_unknown_v{version}" + ("_trailing" if tail else "")
      add(label, tx_type, u16(version) + tail, "unknown ProTx version")
  # CbTx version 4: v24 reads the asset-unlock root, v23.1 does not.
  sig = b["sig_basic"]
  add("cbtx_v4_root", 5, cbtx(4, sig, root=True), "v4 with the root")
  add("cbtx_v4_no_root", 5, cbtx(4, sig, root=False), "v4 without the root")
  # NetInfo entries as Core reads them (ProUpServTx v3, regular node).
  zsig = bytes(96)
  ext_cases = {
    "valid": [svc4([1, 2, 3, 4], 1)],
    "domain_upper": [svc4([1, 2, 3, 4], 1), domain(b"Example.com", 443)],
    "domain_valid": [svc4([1, 2, 3, 4], 1), domain(b"example.com", 443)],
    "domain_port0": [svc4([1, 2, 3, 4], 1), domain(b"example.com", 0)],
    "domain_253": [svc4([1, 2, 3, 4], 1), domain(b"a." * 125 + b"com", 1)],
    "domain_254": [svc4([1, 2, 3, 4], 1), domain(b"a." * 125 + b"comx", 1)],
    "unknown_tag": [svc4([1, 2, 3, 4], 1), b"\x03"],
    "ipv4_any": [svc4([0, 0, 0, 0], 1), svc4([1, 2, 3, 4], 1)],
    "ipv4_none": [svc4([255, 255, 255, 255], 1), svc4([1, 2, 3, 4], 1)],
    "ipv6_fc": [svc(2, bytes([0xFC]) + bytes(14) + b"\x01", 1)],
    "ipv6_doc": [svc(2, bytes.fromhex("20010db8") + bytes(11) + b"\x01", 1)],
    "ipv6_mapped": [svc(2, bytes(10) + b"\xff\xff\x01\x02\x03\x04", 1)],
    "cjdns_bad": [svc(6, bytes([0xFD]) + bytes(14) + b"\x01", 1)],
    "cjdns": [svc(6, bytes([0xFC]) + bytes(14) + b"\x01", 1)],
    "unknown_net": [svc(7, b"\x01\x02\x03\x04", 1), svc4([1, 2, 3, 4], 1)],
    "torv2_net": [svc(3, bytes(10), 1), svc4([1, 2, 3, 4], 1)],
    # IPv4 with length 5 throws before reading the address. Core marks the
    # entry invalid and reads the next entry where the address would start.
    "ipv4_len5": [b"\x01\x01\x05", svc4([5, 6, 7, 8], 2)],
    # A non-canonical or oversized length throws once the size is read.
    "size_noncanonical": [b"\x01\x01\xfd\x04\x00", svc4([5, 6, 7, 8], 2)],
    "size_513": [b"\x01\x01\xfd\x01\x02", svc4([5, 6, 7, 8], 2)],
  }
  for name, entries in ext_cases.items():
    net = netinfo(1, [(0, entries)])
    add(f"netinfo_{name}", 2, proupservtx(3, net, zsig),
        "ProUpServTx v3 NetInfo")  # fmt: skip
  # A version Core does not know reads nothing past it.
  add("netinfo_version_2", 2, proupservtx(3, b"\x02", zsig),
      "ExtNetInfo version 2")  # fmt: skip
  legacy_zero = proupservtx(2, protx_service([0, 0, 0, 0], 9999), zsig)
  add("legacy_netinfo_any", 2, legacy_zero, "MnNetInfo 0.0.0.0")
  # EVO-14: version-3 ProRegTx in the v23.1 layout (one payout script).
  for txid in (
    "f137aa6f6e0a8895086f5eb18a3de18acf2cba5a1a598a13722a7d8cbdfb1261",
    "a51324799403f291cef55feb42d68d4e226187b83faf5e44b38112dc3bfbf5dc",
    "ecf23a8aee664a60783d5db8b0bdd4d345dd4f71f9c9dcf0bf500f855ea800c0",
  ):
    out[f"proregtx_v3_v23_layout_{txid[:8]}"] = (
      corpus_tx("proregtx", "proregtx_v23_layout", txid),
      "v3 ProRegTx with one payout script (rpc_netinfo.py)",
    )
  return out


def cli(release: Path, datadir: Path, *args: str) -> str:
  cmd = [str(release / "bin/dash-cli"), f"-datadir={datadir}", *args]
  r = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
  if r.returncode:
    raise RuntimeError(r.stderr.strip())
  return r.stdout


CONF = """regtest=1
server=1
listen=0
dnsseed=0
fixedseeds=0
printtoconsole=0
rpcuser=bs6a
rpcpassword=bs6a
[regtest]
rpcport={rpc}
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
"""


def start(release: Path, datadir: Path, rpc: int, extra: list[str]) -> None:
  datadir.mkdir(parents=True, exist_ok=True)
  (datadir / "dash.conf").write_text(CONF.format(rpc=rpc))
  log = (datadir / "stdout.log").open("a")
  subprocess.Popen(  # noqa: S603
    [str(release / "bin/dashd"), f"-datadir={datadir}", *extra],
    stdout=log,
    stderr=subprocess.STDOUT,
    start_new_session=True,
  )
  for _ in range(600):
    try:
      cli(release, datadir, "getblockcount")
      break
    except RuntimeError:
      time.sleep(1)
  else:
    sys.exit(f"dashd in {datadir} did not start")
  # A fresh chain keeps Core's flag legacy until a block connects; block 1
  # then sets it from V19.
  cli(release, datadir, "generatetodescriptor", "1", "raw(51)")


def stop(release: Path, datadir: Path) -> None:
  try:
    cli(release, datadir, "stop")
  except RuntimeError:
    return
  for _ in range(120):
    if not (datadir / "regtest/.lock").exists():
      return
    time.sleep(1)


def verdict(release: Path, datadir: Path, tx: bytes) -> object:
  """The payload object Core prints, or null when GetTxPayload fails."""
  try:
    d = json.loads(cli(release, datadir, "decoderawtransaction", tx.hex()))
  except RuntimeError as e:
    return {"rpc-error": str(e)}
  objs = {k: d[k] for k in PAYLOAD_KEYS if k in d}
  return objs or None


def cmd_probe(args: argparse.Namespace) -> None:
  releases = {
    rel: Path(path) for rel, path in (r.split("=", 1) for r in args.release)
  }
  work = Path(args.work)
  todo = cases()
  core: dict[str, dict[str, dict[str, object]]] = {k: {} for k in todo}
  port = args.port
  for rel, path in releases.items():
    for flag, extra in FLAGS.items():
      datadir = work / f"{rel}-{flag}"
      start(path, datadir, port, extra)
      port += 1
      try:
        for name, (tx, _) in todo.items():
          core[name].setdefault(rel, {})[flag] = verdict(path, datadir, tx)
      finally:
        stop(path, datadir)
  lines = [args.header.rstrip("\n"), "{"]
  for name, (tx, note) in todo.items():
    entry = {"note": note, "raw": tx.hex(), "core": core[name]}
    lines.append(f"  {json.dumps(name)}: {json.dumps(entry)},")
  lines.append("}")
  Path(args.out).write_text("\n".join(lines) + "\n")


def cmd_v24(args: argparse.Namespace) -> None:
  seen: dict[str, dict[str, object]] = {}
  for path in sorted(Path(args.fixtures).glob("*.json")):
    block = json.loads(path.read_text())
    for tx in block["getblock2"]["tx"]:
      keys = [k for k in PAYLOAD_KEYS if k in tx]
      if tx.get("type", 0) == 0 or not keys or tx["txid"] in seen:
        continue
      seen[tx["txid"]] = {
        "source": f"{path.stem} block {block['height']}",
        "raw": tx["hex"],
        "core": {k: tx[k] for k in keys},
      }
  lines = [args.header.rstrip("\n"), "{", '  "v24": {']
  for txid, entry in seen.items():
    lines.append(f"    {json.dumps(txid)}: {json.dumps(entry)},")
  lines += ["  },", "}"]
  Path(args.out).write_text("\n".join(lines) + "\n")


def main() -> None:
  p = argparse.ArgumentParser(description=__doc__)
  sub = p.add_subparsers(dest="cmd", required=True)
  v24 = sub.add_parser("v24")
  v24.add_argument("--fixtures", required=True)
  v24.add_argument("--header", type=argparse.FileType(), required=True)
  v24.add_argument("--out", required=True)
  probe = sub.add_parser("probe")
  probe.add_argument("--release", action="append", required=True)
  probe.add_argument("--work", required=True)
  probe.add_argument("--port", type=int, default=29851)
  probe.add_argument("--header", type=argparse.FileType(), required=True)
  probe.add_argument("--out", required=True)
  args = p.parse_args()
  args.header = args.header.read()
  if args.cmd == "v24":
    cmd_v24(args)
  else:
    cmd_probe(args)


if __name__ == "__main__":
  main()
