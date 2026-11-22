"""US5: malformed and unexpected underlay traffic is attributed to named reasons and never hurts
tenant traffic (quickstart O11, O12; SC-006, SC-011)."""
import re
import threading
import time

from conftest import VARIANT, forwarder_pids, ns_exec, reasons, run_lab, v, vc, vm
from injector import Injector, corpus

NOISE = {"non_arp_bcast_mcast"}  # kernel IGMP/ND chatter on the bridge is not under test


def delta(before, after):
    return {k: after[k] - before[k] for k in after if after[k] != before[k] and k not in NOISE}


def test_every_corpus_case_lands_in_exactly_its_reason_while_traffic_flows(fresh):
    cases = corpus("cn2")
    assert len(cases) >= 20
    pids = forwarder_pids()
    results = {}

    def ping(src, dst, key):
        results[key] = vm(src).ping(dst, count=300, interval=0.1)

    bg = [threading.Thread(target=ping, args=("red1", "10.1.1.12", "red")),
          threading.Thread(target=ping, args=("blue1", "10.1.1.12", "blue"))]
    [t.start() for t in bg]
    time.sleep(1.0)
    failures = []
    with Injector("cn2") as inj:
        for c in cases:
            before = reasons("cn2")
            inj.send(c["name"])
            time.sleep(0.2)
            d = delta(before, reasons("cn2"))
            if d != {c["reason"]: 1}:
                failures.append((c["name"], c["reason"], d))
    assert failures == [], failures
    [t.join(timeout=120) for t in bg]
    for key in ("red", "blue"):
        loss, ttls, out = results[key]
        assert loss == 0 and ttls == {"63"}, f"{key}: {out[-300:]}"  # SC-006: valid traffic unharmed
    assert forwarder_pids() == pids  # neither forwarder restarted or crashed
    for node in ("cn1", "cn2"):
        assert v(node, "stats", "show")["data"]["mbuf"]["in_use"] == 0
        s = v(node, "stats", "show")["data"]["drops"]
        assert s["total"] == sum(s["reasons"].values())


def test_o11_oversize_gets_frag_needed_with_the_tunnel_mtu(fresh):
    # underlay MTU 1600: a 1500-byte DF packet plus 32 bytes of encapsulation fits
    loss, _, out = vm("red1").ping("10.1.2.13", count=1, extra="-M do -s 1472")
    assert loss == 0, out
    pids = forwarder_pids()
    try:
        # the fabric shrinks to 1500: the forwarder reads the MTU when it opens the port
        ns_exec("mvr-cn1", "ip", "link", "set", "u0", "mtu", "1500")
        ns_exec("mvr-ul", "ip", "link", "set", "ul-cn1", "mtu", "1500")
        assert run_lab("run", "--node", "cn1").returncode == 0
        assert v("cn1", "port", "show")["data"]["ports"][0]["mtu"] == 1500
        loss, _, out = vm("red1").ping("10.1.2.13", count=1, extra="-M do -s 1472")
        assert loss == 100 and "Frag needed" in out and "mtu = 1468" in out, out  # MPLSoUDP: 1500 - 32
        assert reasons("cn1")["tunnel_mtu_exceeded"] >= 1
        loss, _, out = vm("blue1").ping("10.1.1.12", count=1, extra="-M do -s 1472")
        assert loss == 100 and "mtu = 1450" in out, out  # VXLAN: 1500 - 50
        assert reasons("cn1")["tunnel_mtu_exceeded"] >= 2
    finally:
        ns_exec("mvr-cn1", "ip", "link", "set", "u0", "mtu", "1600")
        ns_exec("mvr-ul", "ip", "link", "set", "ul-cn1", "mtu", "1600")
        run_lab("run", "--node", "cn1")
        for g in ("red1", "blue1"):  # forget the path MTU learned above (not all guests have `flush cache`)
            vm(g).run(("sudo " if VARIANT == "kvm" else "") + "ip route flush cache", check=False)
    assert forwarder_pids()["cn2"] == pids["cn2"]
