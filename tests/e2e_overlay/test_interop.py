"""US6: blue VMs talk to an independent VXLAN implementation, the Linux kernel's (quickstart O13,
SC-008). The endpoint is brought up here with `lab.sh up --interop` (idempotent)."""
import hashlib
import os
import random
import subprocess
import time

import pytest

from capture import Capture, tunnel_packets
from conftest import UL_MAC, VARIANT, lab_args, run_lab, v, vm, ns_exec

IX_MAC = "02:00:00:ff:00:03"


@pytest.fixture()
def interop(fresh):
    r = run_lab(*lab_args("--interop"))
    assert r.returncode == 0, r.stderr
    assert "interop endpoint up" in r.stdout
    # the forwarders were started before the endpoint existed: ARP resolves `ix` on first use
    yield


def test_endpoint_is_an_mvr_namespace_with_the_documented_shape(interop):
    out = ns_exec("mvr-ix", "ip", "-d", "link", "show", "vx200").stdout
    assert "vxlan id 200" in out and "local 172.16.0.3" in out and "dstport 4789" in out
    assert "nolearning" in out and IX_MAC in out
    assert "10.1.3.33" in ns_exec("mvr-ix", "ip", "-br", "addr", "show", "ix0").stdout
    assert run_lab(*lab_args("--interop")).returncode == 0  # idempotent


def test_o13_blue_pings_the_kernel_endpoint(interop):
    with Capture("udp port 4789") as cap:
        loss, ttls, out = vm("blue1").ping("10.1.3.33", count=10)
        assert loss == 0, out
    pk = tunnel_packets(cap)
    to_ix = [p for p in pk if p["dst"] == "172.16.0.3"]
    from_ix = [p for p in pk if p["src"] == "172.16.0.3"]
    assert len(to_ix) == len(from_ix) == 10
    assert all(p["kind"] == "vxlan" and p["vni"] == 200 for p in pk)
    for p in to_ix:  # forwarder -> kernel: inner dst is the endpoint's router MAC
        assert p["inner_eth"] == (UL_MAC["cn1"], IX_MAC)
    for p in from_ix:  # kernel -> forwarder: inner src is the endpoint's MAC, dst our router MAC
        assert p["inner_eth"] == (IX_MAC, UL_MAC["cn1"])
    n = {x["name"]: x for x in v("cn1", "node", "show")["data"]["nodes"]}["ix"]
    assert n["encap"]["vxlan"]["pkts"] == 10 and n["decap"]["vxlan"]["pkts"] == 10
    # the same address from the other node, and red cannot reach it (not in red)
    loss, _, out = vm("blue2").ping("10.1.3.33", count=3)
    assert loss == 0, out
    loss, _, out = vm("red1").ping("10.1.3.33", count=1, extra="-W 2")
    assert loss == 100, out


def test_sc008_100mb_tcp_from_blue2_to_the_endpoint_is_byte_identical(interop):
    mb = int(os.environ.get("MINIVR_E2E_INTEROP_MB", "100"))
    recv = subprocess.Popen(
        ["ip", "netns", "exec", "mvr-ix", "sh", "-c", "socat -u TCP-LISTEN:9000,reuseaddr STDOUT | sha256sum"],
        stdout=subprocess.PIPE, text=True)
    try:
        time.sleep(0.7)
        with Capture("udp port 4789", count=200) as cap:
            if VARIANT == "harness":
                rng = random.Random(77)
                send = subprocess.Popen(["ip", "netns", "exec", "mvr-blue2", "socat", "-u", "STDIN",
                                         "TCP:10.1.3.33:9000,retry=10,interval=0.2"], stdin=subprocess.PIPE)
                digest = hashlib.sha256()
                for _ in range(mb):
                    chunk = rng.randbytes(1024 * 1024)
                    digest.update(chunk)
                    send.stdin.write(chunk)
                send.stdin.close()
                assert send.wait(timeout=300) == 0
                sent = digest.hexdigest()
            else:
                vm("blue2").run("rm -f /tmp/f /tmp/s; mkfifo /tmp/f; (sha256sum </tmp/f >/tmp/s &); "
                                f"dd if=/dev/urandom bs=1M count={mb} 2>/dev/null | tee /tmp/f | nc 10.1.3.33 9000; "
                                "sleep 1", timeout=900)
                sent = vm("blue2").run("cat /tmp/s").stdout.split()[0]
        out, _ = recv.communicate(timeout=120)
    finally:
        if recv.poll() is None:
            recv.kill()
    assert out.split()[0] == sent
    assert all(p["kind"] == "vxlan" and p["vni"] == 200 for p in tunnel_packets(cap))
    assert v("cn2", "stats", "show")["data"]["mbuf"]["in_use"] == 0
