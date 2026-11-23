#!/usr/bin/env python3
"""Launch one KVM lab guest the way libvirt does (contracts/lab-kvm.md, research R4, R10).

root part : enter mvr-cn1 and open TAP pN, enter mvr-mgmt and open TAP mN, open /dev/vhost-net
            twice, write the pid file, drop to the developer's uid/gid with no_new_privs
then      : exec QEMU, which only receives the descriptors (-netdev tap,fd=..,vhostfd=..)

The pure functions (GUESTS, build_qemu_argv, meta_data_json, render_user_data) need no root and
no KVM and are unit tested by tests/lab/test_kvm_launch.py. Standard library only.
"""
import argparse
import ctypes
import json
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MEMORY_MB = 192
VCPUS = 1

# data-model.md, "Guest" table
GUESTS = {
    "vm1": {"data_mac": "02:00:00:00:01:01", "data_addr": "10.0.1.11/24", "gw": "10.0.1.1",
            "port": "p1", "mgmt_mac": "02:00:00:00:02:01", "mgmt_addr": "10.99.0.11/24",
            "mgmt_tap": "m1"},
    "vm2": {"data_mac": "02:00:00:00:01:02", "data_addr": "10.0.1.12/24", "gw": "10.0.1.1",
            "port": "p2", "mgmt_mac": "02:00:00:00:02:02", "mgmt_addr": "10.99.0.12/24",
            "mgmt_tap": "m2"},
    "vm3": {"data_mac": "02:00:00:00:01:03", "data_addr": "10.0.2.13/24", "gw": "10.0.2.1",
            "port": "p3", "mgmt_mac": "02:00:00:00:02:03", "mgmt_addr": "10.99.0.13/24",
            "mgmt_tap": "m3"},
}
# Overlay lab (specs/003 contracts/lab-overlay.md): TAP name = guest name inside its node namespace
for _n, _node, _mac, _addr, _gw, _mip, _mtap in (
        ("red1", 1, "02:00:00:01:01:11", "10.1.1.11/24", "10.1.1.1", 21, "mr1"),
        ("blue1", 1, "02:00:00:02:01:11", "10.1.1.11/24", "10.1.1.1", 22, "mb1"),
        ("red2", 2, "02:00:00:01:02:12", "10.1.1.12/24", "10.1.1.1", 23, "mr2"),
        ("red3", 2, "02:00:00:01:02:13", "10.1.2.13/24", "10.1.2.1", 24, "mr3"),
        ("blue2", 2, "02:00:00:02:02:12", "10.1.1.12/24", "10.1.1.1", 25, "mb2"),
        # phase 3 spare guests (specs/005 contracts/lab-ctl.md): started at runtime by `guest start`
        ("red4", 3, "02:00:00:01:03:14", "10.1.1.14/24", "10.1.1.1", 26, "mr4"),
        ("red5", 2, "02:00:00:01:02:15", "10.1.2.15/24", "10.1.2.1", 27, "mr5")):
    GUESTS[_n] = {"data_mac": _mac, "data_addr": _addr, "gw": _gw, "port": _n, "node": _node,
                  "mgmt_mac": f"02:00:00:00:02:{_mip:02x}", "mgmt_addr": f"10.99.0.{_mip}/24",
                  "mgmt_tap": _mtap}
for _n, _g in GUESTS.items():
    _g["name"] = _n

# FR-008: no checksum or segmentation offload between guest and forwarder
OFFLOADS = ("csum", "gso", "host_tso4", "host_tso6", "host_ecn", "host_ufo",
            "guest_csum", "guest_tso4", "guest_tso6", "guest_ecn", "guest_ufo")
NIC_FLAGS = ",".join(f"{f}=off" for f in OFFLOADS)


def build_qemu_argv(guest, data_fd, data_vhostfd, mgmt_fd, mgmt_vhostfd, disk, config_drive,
                    console):
    n = guest["name"]
    return [
        "qemu-system-x86_64",
        "-machine", "pc,accel=kvm", "-cpu", "host",
        "-name", f"mvr-{n},process=mvr-{n}",
        "-m", str(MEMORY_MB), "-smp", str(VCPUS),
        "-nodefaults", "-no-user-config", "-display", "none",
        "-sandbox", "on",
        "-serial", f"file:{console}",
        "-drive", f"file={disk},if=virtio,format=qcow2",
        "-drive", f"file={config_drive},if=virtio,format=raw,read-only=on",
        "-netdev", f"tap,id=data,fd={data_fd},vhost=on,vhostfd={data_vhostfd}",
        "-device", f"virtio-net-pci,netdev=data,mac={guest['data_mac']},addr=0x3,{NIC_FLAGS}",
        "-netdev", f"tap,id=mgmt,fd={mgmt_fd},vhost=on,vhostfd={mgmt_vhostfd}",
        "-device", f"virtio-net-pci,netdev=mgmt,mac={guest['mgmt_mac']},addr=0x4,{NIC_FLAGS}",
    ]


def meta_data_json(guest, pubkey):
    n = guest["name"]
    return json.dumps({"uuid": f"mvr-{n}", "hostname": n, "name": n,
                       "public_keys": {"mvr-lab": pubkey.strip()}}, indent=1) + "\n"


def render_user_data(guest):
    text = (HERE / "guest-init.sh.in").read_text()
    for key, val in (("NAME", guest["name"]), ("DATA_ADDR", guest["data_addr"]),
                     ("GW", guest["gw"]), ("MGMT_ADDR", guest["mgmt_addr"])):
        text = text.replace(f"@{key}@", val)
    return text


def write_seed(outdir, guest, pubkey):
    latest = Path(outdir) / "openstack" / "latest"
    latest.mkdir(parents=True, exist_ok=True)
    (latest / "meta_data.json").write_text(meta_data_json(guest, pubkey))
    (latest / "user_data").write_text(render_user_data(guest))


# ---- privileged part ------------------------------------------------------------------------
TUNSETIFF = 0x400454CA
IFF_TAP, IFF_NO_PI, IFF_VNET_HDR = 0x0002, 0x1000, 0x4000
PR_SET_NO_NEW_PRIVS = 38


class LaunchError(Exception):
    pass


def step(what, fn, *a):
    try:
        return fn(*a)
    except OSError as e:
        raise LaunchError(f"{what} failed: {os.strerror(e.errno) if e.errno else e}") from e


def open_tap(netns, tap):
    """Enter network namespace `netns` (stay there) and attach to persistent TAP `tap`."""
    import fcntl
    nsfd = step(f"open /run/netns/{netns}", os.open, f"/run/netns/{netns}", os.O_RDONLY)
    try:
        step(f"setns {netns}", os.setns, nsfd, os.CLONE_NEWNET)
    finally:
        os.close(nsfd)
    fd = step("open /dev/net/tun", os.open, "/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", tap.encode(), IFF_TAP | IFF_NO_PI | IFF_VNET_HDR)
    step(f"TUNSETIFF {tap}", fcntl.ioctl, fd, TUNSETIFF, ifr)
    return fd


def privileged_exec(a):
    if os.geteuid() != 0:
        raise LaunchError("must run as root")
    if a.uid == 0 or a.gid == 0:
        raise LaunchError("refusing to run QEMU as root (uid/gid 0)")
    guest = GUESTS[a.name]
    data_fd = open_tap(a.cn_netns, a.data_tap)
    mgmt_fd = open_tap(a.mgmt_netns, a.mgmt_tap)
    vh1 = step("open /dev/vhost-net", os.open, "/dev/vhost-net", os.O_RDWR)
    vh2 = step("open /dev/vhost-net", os.open, "/dev/vhost-net", os.O_RDWR)
    fds = (data_fd, vh1, mgmt_fd, vh2)
    for fd in fds:
        os.set_inheritable(fd, True)

    def write_pid():
        Path(a.pidfile).parent.mkdir(parents=True, exist_ok=True)
        Path(a.pidfile).write_text(f"{os.getpid()}\n")
    step("write pid file", write_pid)

    # QEMU stderr next to the console log, owned by the developer
    qlog = Path(a.console).parent / f"{a.name}.qemu.log"
    efd = step("open qemu log", os.open, str(qlog), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    step("chown qemu log", os.fchown, efd, a.uid, a.gid)
    os.dup2(efd, 2)
    os.close(efd)

    argv = build_qemu_argv(guest, data_fd, vh1, mgmt_fd, vh2, a.disk, a.config_drive, a.console)
    step("setgroups", os.setgroups, [])
    step("setresgid", os.setresgid, a.gid, a.gid, a.gid)
    step("setresuid", os.setresuid, a.uid, a.uid, a.uid)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        e = ctypes.get_errno()
        raise LaunchError(f"prctl(NO_NEW_PRIVS) failed: {os.strerror(e)}")
    step("exec qemu-system-x86_64", os.execvp, argv[0], argv)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "seed":
        p = argparse.ArgumentParser(prog="launch.py seed")
        p.add_argument("seed")
        p.add_argument("dir")
        p.add_argument("--name", required=True, choices=sorted(GUESTS))
        p.add_argument("--pubkey", required=True)
        a = p.parse_args(argv)
        write_seed(a.dir, GUESTS[a.name], Path(a.pubkey).read_text())
        return 0
    p = argparse.ArgumentParser(prog="launch.py")
    p.add_argument("--name", required=True, choices=sorted(GUESTS))
    p.add_argument("--uid", type=int, required=True)
    p.add_argument("--gid", type=int, required=True)
    p.add_argument("--cn-netns", required=True)
    p.add_argument("--data-tap", required=True)
    p.add_argument("--mgmt-netns", required=True)
    p.add_argument("--mgmt-tap", required=True)
    p.add_argument("--pidfile", required=True)
    p.add_argument("--console", required=True)
    p.add_argument("--disk", required=True)
    p.add_argument("--config-drive", required=True)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    if a.dry_run:
        print(json.dumps(build_qemu_argv(GUESTS[a.name], 3, 4, 5, 6, a.disk, a.config_drive,
                                         a.console)))
        return 0
    try:
        privileged_exec(a)
    except LaunchError as e:
        print(f"launch.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
