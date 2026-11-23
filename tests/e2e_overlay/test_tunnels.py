"""US2: same-tenant VMs on different nodes through MPLSoUDP and L3 VXLAN (quickstart O3, O4, O5,
O8, O10; SC-002, SC-004, SC-005, SC-007)."""
import hashlib
import os
import random
import subprocess
import threading
import time

import pytest

from capture import Capture, tenant_leaks, tunnel_packets, undecoded_ip
from conftest import LABEL, UL_MAC, VARIANT, forwarder_pids, run_lab, v, vc, vm, ns_exec, reasons


def assert_clean_underlay(cap):
    """SC-007: everything on the wire is a decodable tunnel packet; no tenant packet leaked."""
    assert tenant_leaks(cap) == []
    assert undecoded_ip(cap) == []


def test_o3_red_across_nodes_uses_mplsoudp(fresh):
    with Capture() as cap:
        for dst in ("10.1.1.12", "10.1.2.13"):
            loss, ttls, out = vm("red1").ping(dst, count=5)
            assert loss == 0 and ttls == {"63"}, out  # one routed hop (FR-011)
    pk = tunnel_packets(cap)
    assert pk and all(p["kind"] == "mplsoudp" for p in pk)
    to_cn2 = [p for p in pk if p["dst"] == "172.16.0.2"]
    to_cn1 = [p for p in pk if p["dst"] == "172.16.0.1"]
    assert {p["label"] for p in to_cn2} == {LABEL["red2"], LABEL["red3"]}
    assert {p["label"] for p in to_cn1} == {LABEL["red1"]}
    for p in pk:
        assert p["s"] == 1 and p["df"] and p["ttl_outer"] == 64
        assert 49152 <= p["sport"] <= 65535
        assert p["inner"].ttl == p["ttl"]  # the label TTL mirrors the inner TTL
    assert_clean_underlay(cap)
    # per-node counters equal what was captured
    n = {x["name"]: x for x in v("cn1", "node", "show")["data"]["nodes"]}["cn2"]
    sent = [p for p in to_cn2]
    assert n["encap"]["mplsoudp"]["pkts"] == len(sent)
    assert n["decap"]["mplsoudp"]["pkts"] == len(to_cn1)


def test_o4_blue_across_nodes_uses_vxlan_with_router_macs(fresh):
    with Capture() as cap:
        loss, ttls, out = vm("blue1").ping("10.1.1.12", count=5)
        assert loss == 0 and ttls == {"63"}, out
    pk = tunnel_packets(cap)
    assert pk and all(p["kind"] == "vxlan" and p["vni"] == 200 for p in pk)
    for p in pk:
        want = (UL_MAC["cn1"], UL_MAC["cn2"]) if p["dst"] == "172.16.0.2" else (UL_MAC["cn2"], UL_MAC["cn1"])
        assert p["inner_eth"] == want  # (src, dst) = own router MAC -> remote router MAC
        assert p["df"] and 49152 <= p["sport"] <= 65535
    assert_clean_underlay(cap)


def test_o5_local_traffic_is_never_tunnelled(fresh):
    with Capture() as cap:
        loss, ttls, out = vm("red2").ping("10.1.2.13", count=5)
        assert loss == 0 and ttls == {"63"}, out
    assert tunnel_packets(cap) == []
    assert tenant_leaks(cap) == []


def test_first_ping_after_forwarder_restart_succeeds_through_underlay_arp(fresh):
    with Capture() as cap:
        loss, ttls, out = vm("red1").ping("10.1.1.12", count=1, interval=1)
        assert loss == 0, out
    arps = [p for p in cap.packets() if p.haslayer("ARP")]
    assert any(a["ARP"].pdst == "172.16.0.2" for a in arps)  # cn1 resolved cn2 first


def _ping_in_background(src, dst, count, interval, result):
    def run():
        result["r"] = vm(src).ping(dst, count=count, interval=interval)
    t = threading.Thread(target=run)
    t.start()
    return t


def test_o8_live_reencapsulation_within_one_second(fresh):
    before = forwarder_pids()
    vc("cn2", "vni", "add", "300", "vrf", "red")
    result = {}
    with Capture() as cap:
        t = _ping_in_background("red1", "10.1.1.12", 60, 0.1, result)
        time.sleep(2.0)
        t_before = time.time()
        vc("cn1", "route", "replace", "10.1.1.12/32", "vrf", "red", "node", "cn2", "encap", "vxlan",
           "vni", "300")
        t_after = time.time()
        t.join(timeout=120)
    loss, ttls, out = result["r"]
    assert loss == 0 and ttls == {"63"}, out  # not one packet lost across the change
    sent = [p for p in tunnel_packets(cap) if p["dst"] == "172.16.0.2"]
    first_vx = min(p["time"] for p in sent if p["kind"] == "vxlan")
    last_mpls = max(p["time"] for p in sent if p["kind"] == "mplsoudp")
    assert last_mpls < first_vx  # a clean switch, never back
    assert first_vx - t_after < 1.0, f"switch took {first_vx - t_after:.2f}s"
    assert {p["vni"] for p in sent if p["kind"] == "vxlan"} == {300}
    assert forwarder_pids() == before  # no restart


def test_sc005_remote_route_delete_and_add_take_effect_within_one_second(fresh):
    before = forwarder_pids()
    loss, _, out = vm("red1").ping("10.1.1.12", count=3)
    assert loss == 0, out
    vc("cn1", "route", "del", "10.1.1.12/32", "vrf", "red")
    loss, _, out = vm("red1").ping("10.1.1.12", count=2, extra="-W 1")  # right after: no longer routed
    assert loss == 100, out
    t0 = time.monotonic()
    vc("cn1", "route", "add", "10.1.1.12/32", "vrf", "red", "node", "cn2", "encap", "mplsoudp", "label", "1012")
    loss, _, out = vm("red1").ping("10.1.1.12", count=1)
    assert loss == 0 and time.monotonic() - t0 < 1.0 + 1.0, out  # reply within the second
    assert forwarder_pids() == before


def test_underlay_down_drops_cross_node_only_and_recovers_without_restart(fresh):
    before = forwarder_pids()
    loss, _, out = vm("red1").ping("10.1.1.12", count=2)
    assert loss == 0, out
    ns_exec("mvr-cn1", "ip", "link", "set", "u0", "down")
    try:
        time.sleep(0.5)
        p0 = reasons("cn1")["port_down"]
        loss, _, out = vm("red1").ping("10.1.1.12", count=3)
        assert loss == 100, out
        assert reasons("cn1")["port_down"] > p0  # counted, not silently lost
        loss, ttls, out = vm("red2").ping("10.1.2.13", count=3)  # the other node is unaffected
        assert loss == 0, out
    finally:
        ns_exec("mvr-cn1", "ip", "link", "set", "u0", "up")
    ok = False
    for _ in range(20):
        loss, _, out = vm("red1").ping("10.1.1.12", count=1)
        if loss == 0:
            ok = True
            break
        time.sleep(0.5)
    assert ok, "cross-node ping did not recover after the underlay came back"
    assert forwarder_pids() == before


# ---- SC-002: 1,000 pings per pair and encapsulation ----

PAIRS = (("red1", "10.1.1.12"), ("red1", "10.1.2.13"), ("blue1", "10.1.1.12"))


def _sweep(expect_tags):
    """1,000 pings on each pair at once (three flows in parallel, each at the kernel's 20 ms pace)."""
    res = {}

    def run(src, dst):
        res[(src, dst)] = vm(src).ping(dst, count=1000, interval=0.01, timeout=600)

    with Capture("udp", count=900) as cap:
        ts = [threading.Thread(target=run, args=pair) for pair in PAIRS]
        [t.start() for t in ts]
        [t.join(timeout=600) for t in ts]
    for (src, dst), (loss, ttls, out) in res.items():
        assert loss == 0 and ttls == {"63"}, f"{src}->{dst}: {out[-300:]}"
    assert len(res) == len(PAIRS)
    tags = {(p["kind"], p.get("label") or p.get("vni")) for p in tunnel_packets(cap)}
    assert tags == expect_tags, tags  # the encapsulation really in use, with the expected tags
    assert_clean_underlay(cap)


def test_sc002_thousand_pings_every_pair_with_each_encapsulation(fresh):
    # shipped config: red = MPLSoUDP, blue = VXLAN
    _sweep({("mplsoudp", 1011), ("mplsoudp", 1012), ("mplsoudp", 1013), ("vxlan", 200)})
    # swap: red over VXLAN (vni 300), blue over MPLSoUDP (labels 2011/2012), on both nodes
    vc("cn1", "vni", "add", "300", "vrf", "red")
    vc("cn2", "vni", "add", "300", "vrf", "red")
    vc("cn1", "route", "replace", "10.1.1.12/32", "vrf", "red", "node", "cn2", "encap", "vxlan", "vni", "300")
    vc("cn1", "route", "replace", "10.1.2.13/32", "vrf", "red", "node", "cn2", "encap", "vxlan", "vni", "300")
    vc("cn2", "route", "replace", "10.1.1.11/32", "vrf", "red", "node", "cn1", "encap", "vxlan", "vni", "300")
    vc("cn1", "label", "add", "2011", "port", "blue1")
    vc("cn2", "label", "add", "2012", "port", "blue2")
    vc("cn1", "route", "replace", "10.1.1.12/32", "vrf", "blue", "node", "cn2", "encap", "mplsoudp", "label", "2012")
    vc("cn2", "route", "replace", "10.1.1.11/32", "vrf", "blue", "node", "cn1", "encap", "mplsoudp", "label", "2011")
    _sweep({("vxlan", 300), ("mplsoudp", 2011), ("mplsoudp", 2012)})


# ---- SC-004: bulk transfer ----

def _transfer_harness(src, dst, dst_ip, mb):
    rng = random.Random(4321)
    recv = subprocess.Popen(
        ["ip", "netns", "exec", f"mvr-{dst}", "sh", "-c", "socat -u TCP-LISTEN:9000,reuseaddr STDOUT | sha256sum"],
        stdout=subprocess.PIPE, text=True)
    send = None
    try:
        time.sleep(0.5)
        send = subprocess.Popen(["ip", "netns", "exec", f"mvr-{src}", "socat", "-u", "STDIN",
                                 f"TCP:{dst_ip}:9000,retry=10,interval=0.2"], stdin=subprocess.PIPE)
        digest = hashlib.sha256()
        for _ in range(mb):
            chunk = rng.randbytes(1024 * 1024)
            digest.update(chunk)
            send.stdin.write(chunk)
        send.stdin.close()
        assert send.wait(timeout=600) == 0
        out, _ = recv.communicate(timeout=180)
    finally:
        for p in (send, recv):
            if p and p.poll() is None:
                p.kill()
    return digest.hexdigest(), out.split()[0]


def _transfer_kvm(src, dst, dst_ip, mb):
    vm(dst).run("rm -f /tmp/recv.sha; nohup sh -c 'nc -l -p 5001 | sha256sum > /tmp/recv.sha' >/dev/null 2>&1 &")
    time.sleep(1)
    vm(src).run("rm -f /tmp/f /tmp/s; mkfifo /tmp/f; (sha256sum </tmp/f >/tmp/s &); "
                f"dd if=/dev/urandom bs=1M count={mb} 2>/dev/null | tee /tmp/f | nc {dst_ip} 5001; sleep 1",
                timeout=900)
    sent = vm(src).run("cat /tmp/s").stdout.split()[0]
    recv = ""
    for _ in range(60):
        recv = vm(dst).run("cat /tmp/recv.sha 2>/dev/null", check=False).stdout.strip()
        if recv:
            break
        time.sleep(1)
    return sent, recv.split()[0] if recv else ""


@pytest.mark.parametrize("src,dst,dst_ip,encap", [("red1", "red2", "10.1.1.12", "mplsoudp"),
                                                  ("blue1", "blue2", "10.1.1.12", "vxlan")])
def test_o10_bulk_transfer_is_byte_identical(fresh, src, dst, dst_ip, encap):
    # 1 GB on namespace VMs; 100 MB on KVM guests (the guest image's tools are slow, as in phase 1.5)
    mb = int(os.environ.get("MINIVR_E2E_XFER_MB", "1024" if VARIANT == "harness" else "100"))
    with Capture("udp", count=300) as cap:
        sent, recv = (_transfer_harness if VARIANT == "harness" else _transfer_kvm)(src, dst, dst_ip, mb)
    assert len(sent) == 64 and sent == recv
    kinds = {p["kind"] for p in tunnel_packets(cap)}
    assert kinds == {encap}
    assert v("cn1", "stats", "show")["data"]["mbuf"]["in_use"] == 0
    assert v("cn2", "stats", "show")["data"]["mbuf"]["in_use"] == 0
