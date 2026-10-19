#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Create, list and destroy ramdisks for write-heavy jobs.

Fuzzers rewrite files constantly and would wear down an SSD. Every ramdisk
made here is named `mrd-<label>`, and only RAM-backed disks with that prefix
are listed or destroyed. Refuses on Windows, which has no built-in ramdisk.

Usage:

  sudo ./contrib/manage_ramdisk.py create --size 4G
  sudo ./contrib/manage_ramdisk.py create --size 8G --label fuzz --exist-ok
  sudo ./contrib/manage_ramdisk.py list
  sudo ./contrib/manage_ramdisk.py destroy mrd-fuzz
  sudo ./contrib/manage_ramdisk.py --unmount-all
"""

from __future__ import annotations

import argparse
import os
import platform
import plistlib
import re
import secrets
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from common import RETCODE_ERR, RETCODE_PASS, format_table, require_bin

MIB = 1 << 20
GIB = 1 << 30
# Smallest ramdisk worth creating.
MIN_SIZE = 256 * MIB
# Smaller hosts would swap heavily or hit the OOM killer under a ramdisk.
MIN_HOST_MEMORY = GIB
# Marks a ramdisk as made here. Ramdisks without it are never destroyed.
PREFIX = "mrd-"
# Maximum time allocated for a single command before it considered a failure.
RUN_TIMEOUT = 120

_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,15}")
_SIZE_RE = re.compile(r"(\d+)([MG])(?:i?B)?", re.IGNORECASE)
_PAGE_SIZE_RE = re.compile(r"page size of (\d+) bytes")


@dataclass(frozen=True)
class Disk:
  name: str
  mount: Path
  # Whole RAM device on macOS. Detaching the device frees the memory.
  device: str


def _run(*args: str) -> str:
  """Run *args* and return stdout, raising with stderr on failure."""
  try:
    proc = subprocess.run(  # noqa: S603
      [require_bin(args[0]), *args[1:]],
      capture_output=True,
      check=False,
      text=True,
      timeout=RUN_TIMEOUT,
    )
  except subprocess.TimeoutExpired as exc:
    raise RuntimeError(
      f"{' '.join(args)} took over {RUN_TIMEOUT} seconds",
    ) from exc
  if proc.returncode != 0:
    detail = proc.stderr.strip() or proc.stdout.strip()
    raise RuntimeError(f"{' '.join(args)} failed: {detail}")
  return proc.stdout


def _owner() -> tuple[int, int]:
  """Return the uid and gid of the user who invoked `sudo`."""
  # Without `SUDO_UID` the caller is root itself, so root owns the ramdisk.
  uid = int(os.environ.get("SUDO_UID", os.getuid()))
  gid = int(os.environ.get("SUDO_GID", os.getgid()))
  return uid, gid


class Ramdisk(ABC):
  """How one host creates, finds and destroys managed ramdisks."""

  # Directory every managed ramdisk mounts under.
  root: Path

  @staticmethod
  def for_host() -> Ramdisk:
    """Return the implementation for this host, or raise without one."""
    system = platform.system()
    if system == "Darwin":
      return RamdiskDarwin()
    if system == "Linux":
      return RamdiskLinux()
    raise RuntimeError(f"no ramdisk support on {system}")

  def mount_path(self, name: str) -> Path:
    """Return where ramdisk *name* mounts."""
    return self.root / name

  @abstractmethod
  def total_memory(self) -> int:
    """Return the physical memory the host has."""

  @abstractmethod
  def available_memory(self) -> int:
    """Return the memory the host can hand out without swapping."""

  @abstractmethod
  def managed(self) -> list[Disk]:
    """Return every managed ramdisk on this host."""

  @abstractmethod
  def attach(self, name: str, size: int) -> None:
    """Create ramdisk *name* of *size* bytes at its mount path."""

  @abstractmethod
  def detach(self, disk: Disk) -> None:
    """Unmount *disk* and free its memory."""


class RamdiskDarwin(Ramdisk):
  """RAM devices from `hdiutil`, formatted as APFS volumes.

  A user-space helper backs these, so macOS can page them out. The cap at
  half of available memory is what keeps them resident.
  """

  root = Path("/Volumes")

  def total_memory(self) -> int:
    return int(_run("sysctl", "-n", "hw.memsize"))

  def available_memory(self) -> int:
    out = _run("vm_stat")
    page = _PAGE_SIZE_RE.search(out)
    if page is None:
      raise RuntimeError("vm_stat reported no page size")
    # Inactive and speculative pages are reclaimed before anything swaps.
    wanted = ("Pages free", "Pages inactive", "Pages speculative")
    pages = 0
    for line in out.splitlines():
      key, _, value = line.partition(":")
      if key.strip() in wanted:
        pages += int(value.strip().rstrip("."))
    return pages * int(page.group(1))

  def managed(self) -> list[Disk]:
    info = plistlib.loads(_run("hdiutil", "info", "-plist").encode())
    disks = []
    for image in info.get("images", []):
      if not image.get("image-path", "").startswith("ram://"):
        continue
      entities = image.get("system-entities", [])
      if not entities:
        continue
      # The RAM device itself comes first. APFS volumes on the device follow.
      device = entities[0]["dev-entry"]
      for entity in entities:
        mount = Path(entity.get("mount-point", "/"))
        if mount.parent == self.root and mount.name.startswith(PREFIX):
          disks.append(Disk(mount.name, mount, device))
    return disks

  def attach(self, name: str, size: int) -> None:
    device = _run("hdiutil", "attach", "-nomount", f"ram://{size // 512}")
    device = device.split()[0]
    try:
      # The volume mounts at `/Volumes/<name>`, so the name picks the path.
      _run("diskutil", "erasevolume", "APFS", name, device)
      os.chown(self.mount_path(name), *_owner())
    except (RuntimeError, OSError):
      _run("hdiutil", "detach", device)
      raise

  def detach(self, disk: Disk) -> None:
    _run("hdiutil", "detach", disk.device)


class RamdiskLinux(Ramdisk):
  """Size-capped tmpfs mounts, each mounted with its name as source."""

  root = Path("/mnt")

  @staticmethod
  def _meminfo(key: str) -> int:
    """Return *key* from `/proc/meminfo` in bytes."""
    with Path("/proc/meminfo").open(encoding="utf-8") as meminfo:
      for line in meminfo:
        if line.startswith(f"{key}:"):
          return int(line.split()[1]) * 1024
    raise RuntimeError(f"/proc/meminfo reported no {key}")

  def total_memory(self) -> int:
    return self._meminfo("MemTotal")

  def available_memory(self) -> int:
    return self._meminfo("MemAvailable")

  def managed(self) -> list[Disk]:
    disks = []
    with Path("/proc/mounts").open(encoding="utf-8") as mounts:
      for line in mounts:
        source, target, fstype, *_ = line.split()
        mount = Path(target)
        if (
          fstype == "tmpfs"
          and mount.parent == self.root
          and mount.name == source
          and source.startswith(PREFIX)
        ):
          disks.append(Disk(source, mount, source))
    return disks

  def attach(self, name: str, size: int) -> None:
    mount = self.mount_path(name)
    uid, gid = _owner()
    # `noswap` (Linux 6.4+) keeps the pages off disk-backed swap.
    options = f"size={size},noswap,mode=0700,uid={uid},gid={gid}"
    mount.mkdir()
    try:
      _run("mount", "-t", "tmpfs", "-o", options, name, str(mount))
    except RuntimeError:
      mount.rmdir()
      raise

  def detach(self, disk: Disk) -> None:
    _run("umount", str(disk.mount))
    disk.mount.rmdir()


def _parse_size(text: str) -> int:
  """Parse a size such as `512M` or `16G` into bytes."""
  match = _SIZE_RE.fullmatch(text)
  if match is None:
    raise argparse.ArgumentTypeError(f"{text!r} is not a size like 512M or 16G")
  unit = MIB if match.group(2).upper() == "M" else GIB
  return int(match.group(1)) * unit


def _parse_label(text: str) -> str:
  """Return the ramdisk name for label *text*."""
  if _LABEL_RE.fullmatch(text) is None:
    raise argparse.ArgumentTypeError(
      f"{text!r} is not 1 to 16 letters, digits, '-' or '_', "
      "starting with a letter or digit",
    )
  return PREFIX + text


def _destroy_one(host: Ramdisk, disk: Disk) -> None:
  host.detach(disk)
  print(f"destroyed {disk.name}")


def _create(host: Ramdisk, args: argparse.Namespace) -> int:
  name = args.label or PREFIX + secrets.token_hex(4)
  size = args.size
  existing = next((d for d in host.managed() if d.name == name), None)
  if existing is not None:
    if not args.exist_ok:
      raise RuntimeError(f"{name} already exists at {existing.mount}")
    # Filesystem overhead takes a little off the device size.
    if shutil.disk_usage(existing.mount).total < size * 9 // 10:
      raise RuntimeError(f"{name} is smaller than asked, destroy it first")
    print(existing.mount)
    return RETCODE_PASS

  mount = host.mount_path(name)
  if mount.exists():
    raise RuntimeError(f"{mount} exists but is not a managed ramdisk")
  if size < MIN_SIZE:
    raise RuntimeError(f"ramdisks take at least {MIN_SIZE // MIB} MiB")
  available = host.available_memory()
  if size > available // 2:
    raise RuntimeError(
      f"{size // MIB} MiB asked, at most {available // 2 // MIB} MiB allowed, "
      f"half of the {available // MIB} MiB available",
    )

  host.attach(name, size)
  print(mount)
  return RETCODE_PASS


def _destroy(host: Ramdisk, args: argparse.Namespace) -> int:
  disks = {d.name: d for d in host.managed()}
  targets = []
  for given in args.names:
    name = Path(given).name
    if not name.startswith(PREFIX):
      raise RuntimeError(f"{given} is not named {PREFIX}*, refusing")
    if name not in disks:
      raise RuntimeError(f"{name} is not a mounted ramdisk")
    targets.append(disks[name])
  for disk in targets:
    _destroy_one(host, disk)
  return RETCODE_PASS


def _list(host: Ramdisk, _args: argparse.Namespace) -> int:
  disks = host.managed()
  if not disks:
    print("no managed ramdisks")
    return RETCODE_PASS
  rows = []
  for disk in disks:
    usage = shutil.disk_usage(disk.mount)
    rows.append(
      (
        disk.name,
        str(disk.mount),
        f"{usage.total // MIB} MiB",
        f"{usage.used // MIB} MiB",
      ),
    )
  print(format_table(("Name", "Mount", "Size", "Used"), rows))
  return RETCODE_PASS


def _unmount_all(host: Ramdisk) -> int:
  failed = False
  for disk in host.managed():
    try:
      _destroy_one(host, disk)
    except RuntimeError as exc:
      print(exc, file=sys.stderr)
      failed = True
  return RETCODE_ERR if failed else RETCODE_PASS


def _parse_args() -> tuple[argparse.ArgumentParser, argparse.Namespace]:
  parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
  )
  parser.add_argument(
    "--unmount-all",
    action="store_true",
    help=f"destroy every {PREFIX}* ramdisk",
  )
  sub = parser.add_subparsers(dest="command")

  create = sub.add_parser("create", help="create a ramdisk, print its mount")
  create.add_argument(
    "--size",
    type=_parse_size,
    required=True,
    help=(
      "size such as 512M or 8G "
      "(minimum: 256M, maximum: half of available memory)"
    ),
  )
  create.add_argument(
    "--label",
    type=_parse_label,
    help=f"name it {PREFIX}<label> instead of {PREFIX}<8 hex digits>",
  )
  create.add_argument(
    "--exist-ok",
    action="store_true",
    help="reuse a ramdisk of that label if it is large enough",
  )
  create.set_defaults(handler=_create)

  destroy = sub.add_parser("destroy", help="destroy ramdisks by name")
  destroy.add_argument("names", nargs="+", help=f"{PREFIX}* name or mount")
  destroy.set_defaults(handler=_destroy)

  listing = sub.add_parser("list", help="list ramdisks made here")
  listing.set_defaults(handler=_list)
  return parser, parser.parse_args()


def main() -> int:
  parser, args = _parse_args()
  if args.unmount_all == (args.command is not None):
    parser.error("give one command or --unmount-all")
  host = Ramdisk.for_host()
  if os.geteuid() != 0:
    raise RuntimeError("mounting ramdisks needs root, run with sudo")
  total = host.total_memory()
  if total < MIN_HOST_MEMORY:
    raise RuntimeError(
      f"{total // MIB} MiB of memory, ramdisks need at least "
      f"{MIN_HOST_MEMORY // MIB} MiB",
    )
  if args.unmount_all:
    return _unmount_all(host)
  return args.handler(host, args)


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
