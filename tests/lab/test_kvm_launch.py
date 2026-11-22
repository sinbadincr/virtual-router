"""Unit tests for lab/kvm/launch.py: the pure functions only (no root, no KVM, no network).

Run: python3 -m unittest discover -s tests/lab -p 'test_*.py' -v   (the `lab-unit` gate)
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCH = ROOT / "lab" / "kvm" / "launch.py"

_spec = importlib.util.spec_from_file_location("mvr_kvm_launch", LAUNCH)
launch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(launch)

# data-model.md, "Guest" table
EXPECTED = {
    "vm1": ("02:00:00:00:01:01", "10.0.1.11/24", "10.0.1.1", "p1", "02:00:00:00:02:01", "10.99.0.11/24", "m1"),
    "vm2": ("02:00:00:00:01:02", "10.0.1.12/24", "10.0.1.1", "p2", "02:00:00:00:02:02", "10.99.0.12/24", "m2"),
    "vm3": ("02:00:00:00:01:03", "10.0.2.13/24", "10.0.2.1", "p3", "02:00:00:00:02:03", "10.99.0.13/24", "m3"),
    # overlay lab, specs/003 contracts/lab-overlay.md
    "red1": ("02:00:00:01:01:11", "10.1.1.11/24", "10.1.1.1", "red1", "02:00:00:00:02:15", "10.99.0.21/24", "mr1"),
    "blue1": ("02:00:00:02:01:11", "10.1.1.11/24", "10.1.1.1", "blue1", "02:00:00:00:02:16", "10.99.0.22/24", "mb1"),
    "red2": ("02:00:00:01:02:12", "10.1.1.12/24", "10.1.1.1", "red2", "02:00:00:00:02:17", "10.99.0.23/24", "mr2"),
    "red3": ("02:00:00:01:02:13", "10.1.2.13/24", "10.1.2.1", "red3", "02:00:00:00:02:18", "10.99.0.24/24", "mr3"),
    "blue2": ("02:00:00:02:02:12", "10.1.1.12/24", "10.1.1.1", "blue2", "02:00:00:00:02:19", "10.99.0.25/24", "mb2"),
}
OFFLOADS = ("csum", "gso", "host_tso4", "host_tso6", "host_ecn", "host_ufo",
            "guest_csum", "guest_tso4", "guest_tso6", "guest_ecn", "guest_ufo")
FDS = dict(data_fd=3, data_vhostfd=4, mgmt_fd=5, mgmt_vhostfd=6)


def argv_for(name):
    return launch.build_qemu_argv(launch.GUESTS[name], disk="/w/disk.qcow2",
                                  config_drive="/w/config-2.iso", console="/l/c.log", **FDS)


def opt(argv, flag):
    """All values that follow `flag` in argv."""
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


class GuestTable(unittest.TestCase):
    def test_matches_data_model(self):
        self.assertEqual(sorted(launch.GUESTS), sorted(EXPECTED))
        for name, (dmac, daddr, gw, port, mmac, maddr, mtap) in EXPECTED.items():
            g = launch.GUESTS[name]
            self.assertEqual((g["data_mac"], g["data_addr"], g["gw"], g["port"],
                              g["mgmt_mac"], g["mgmt_addr"], g["mgmt_tap"]),
                             (dmac, daddr, gw, port, mmac, maddr, mtap), name)

    def test_memory_and_cpu_limits(self):
        self.assertLessEqual(launch.MEMORY_MB, 256)  # FR-009a
        self.assertEqual(launch.VCPUS, 1)


class QemuArgv(unittest.TestCase):
    def test_kvm_only_never_tcg(self):
        for name in launch.GUESTS:
            argv = argv_for(name)
            self.assertIn("accel=kvm", " ".join(argv))
            self.assertNotIn("tcg", " ".join(argv))

    def test_sandbox_and_hygiene(self):
        argv = argv_for("vm2")
        self.assertEqual(opt(argv, "-sandbox"), ["on"])
        self.assertEqual(opt(argv, "-name"), ["mvr-vm2,process=mvr-vm2"])
        self.assertEqual(opt(argv, "-m"), ["192"])
        self.assertEqual(opt(argv, "-smp"), ["1"])
        self.assertEqual(opt(argv, "-display"), ["none"])
        for flag in ("-nodefaults", "-no-user-config"):
            self.assertIn(flag, argv)
        self.assertEqual(opt(argv, "-serial"), ["file:/l/c.log"])

    def test_drives(self):
        drives = opt(argv_for("vm1"), "-drive")
        self.assertIn("file=/w/disk.qcow2,if=virtio,format=qcow2", drives)
        iso = [d for d in drives if "config-2.iso" in d]
        self.assertEqual(len(iso), 1)
        self.assertIn("format=raw", iso[0])
        self.assertIn("read-only=on", iso[0])

    def test_nics_addresses_macs_offloads(self):
        for name, (dmac, _, _, _, mmac, _, _) in EXPECTED.items():
            devs = [d for d in opt(argv_for(name), "-device") if d.startswith("virtio-net-pci")]
            self.assertEqual(len(devs), 2, name)
            data = next(d for d in devs if "netdev=data" in d)
            mgmt = next(d for d in devs if "netdev=mgmt" in d)
            self.assertIn(f"mac={dmac}", data)
            self.assertIn("addr=0x3", data)  # -> eth0
            self.assertIn(f"mac={mmac}", mgmt)
            self.assertIn("addr=0x4", mgmt)  # -> eth1
            for dev in (data, mgmt):  # FR-008: no checksum or segmentation offload
                for f in OFFLOADS:
                    self.assertIn(f"{f}=off", dev.split(","), f"{name}: {f}")

    def test_fd_wiring(self):
        netdevs = opt(argv_for("vm3"), "-netdev")
        self.assertIn("tap,id=data,fd=3,vhost=on,vhostfd=4", netdevs)
        self.assertIn("tap,id=mgmt,fd=5,vhost=on,vhostfd=6", netdevs)


class FirstBoot(unittest.TestCase):
    def test_meta_data(self):
        md = json.loads(launch.meta_data_json(launch.GUESTS["vm1"], "ssh-ed25519 AAAA mvr-lab"))
        self.assertEqual(md["uuid"], "mvr-vm1")
        self.assertEqual(md["hostname"], "vm1")
        self.assertEqual(list(md["public_keys"].values()), ["ssh-ed25519 AAAA mvr-lab"])

    def test_user_data(self):
        for name, (_, daddr, gw, _, _, maddr, _) in EXPECTED.items():
            ud = launch.render_user_data(launch.GUESTS[name])
            self.assertTrue(ud.startswith("#!/bin/sh"), name)
            self.assertIsNone(re.search(r"@[A-Z_]+@", ud), name)
            self.assertIn(f"ip addr add {daddr} dev eth0", ud)
            self.assertIn(f"ip route replace default via {gw} dev eth0", ud)
            self.assertIn(f"ip addr add {maddr} dev eth1", ud)
            for line in ud.splitlines():  # FR-014a: nothing routed via eth1
                if "eth1" in line and "route" in line:
                    self.assertRegex(line, r"ip route del default", line)
            # the connected route 10.99.0.0/24 that `ip addr add` creates must survive: without it
            # the guest answers ARP but sends every reply out of eth0 (first bring-up: ping and
            # ssh over the management network timed out)
            self.assertNotIn("route flush", ud, name)
            self.assertIn("passwd -l cirros", ud)
            self.assertIn("passwd -l root", ud)
            self.assertRegex(ud, r"dropbear\b[^\n]*-s")
            self.assertIn(f"MVR-READY {name}", ud)
            self.assertIn(f"MVR-FAILED {name} step=", ud)

    def test_seed_writes_config_drive_tree(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "k.pub"
            key.write_text("ssh-ed25519 AAAA mvr-lab\n")
            out = Path(d) / "seed"
            subprocess.run([sys.executable, str(LAUNCH), "seed", str(out), "--name", "vm2",
                            "--pubkey", str(key)], check=True)
            latest = out / "openstack" / "latest"
            self.assertEqual(json.loads((latest / "meta_data.json").read_text())["uuid"], "mvr-vm2")
            self.assertIn("MVR-READY vm2", (latest / "user_data").read_text())


class DryRun(unittest.TestCase):
    def test_dry_run_prints_argv_and_opens_nothing(self):
        r = subprocess.run([sys.executable, str(LAUNCH), "--dry-run", "--name", "vm1",
                            "--uid", "1000", "--gid", "1000", "--cn-netns", "mvr-cn1",
                            "--data-tap", "p1", "--mgmt-netns", "mvr-mgmt", "--mgmt-tap", "m1",
                            "--pidfile", "/nonexistent/vm1.pid", "--console", "/l/vm1.log",
                            "--disk", "/w/disk.qcow2", "--config-drive", "/w/config-2.iso"],
                           capture_output=True, text=True, check=True)
        argv = json.loads(r.stdout)
        self.assertEqual(argv[0], "qemu-system-x86_64")
        self.assertIn("mvr-vm1,process=mvr-vm1", argv)
        self.assertFalse(os.path.exists("/nonexistent/vm1.pid"))


if __name__ == "__main__":
    unittest.main()
