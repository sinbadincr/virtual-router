"""US2 (quickstart C4-C8, C18): VMs boot, stop and move at runtime; routes follow within 2 s."""
import threading
import time

import pytest

from capture import Capture, tunnel_packets
from conftest import (VARIANT, agent, agent_ok, ctl, ctl_ok, fwd_ok, node_states, ping_ok, run_lab, vm_exec,
                      wait_converged, wait_for)

TRIALS = 20 if VARIANT == "harness" else 2


def routes(node, vrf="red"):
    return {r["prefix"]: r for r in fwd_ok(node, "route", "show", "vrf", vrf)["routes"]}


def has_route(node, prefix, vrf="red"):
    return prefix in routes(node, vrf)


def labels(node):
    return {l["label"]: l for l in fwd_ok(node, "tunnel", "show")["labels"]}


def vmi(name):
    return next(v for v in ctl_ok("vmi", "show")["vmis"] if v["name"] == name)


@pytest.fixture(scope="module", autouse=True)
def _lab(ctl_lab):
    yield


def start(g, node=None):
    r = run_lab("guest", "start", g, *([node] if node else []))
    assert r.returncode == 0, r.stdout + r.stderr


def stop(g):
    r = run_lab("guest", "stop", g)
    assert r.returncode == 0, r.stdout + r.stderr


def test_c4_a_defined_but_unbound_vmi_exists_nowhere():
    assert vmi("red5")["state"] == "unbound"
    for n in ("cn1", "cn2"):
        assert not has_route(n, "10.1.2.15/32")
        assert all(l["port"] != "red5" for l in labels(n).values())
        assert all(p["name"] != "red5" for p in fwd_ok(n, "port", "show")["ports"])


def test_c5_plug_makes_the_vm_reachable_within_two_seconds():
    start("red5")
    try:
        assert vmi("red5")["state"] == "bound" and vmi("red5")["node"] == "cn2"
        assert ping_ok("red1", "10.1.2.15", count=3)
        lat = []
        for _ in range(TRIALS):  # the plug/unplug path alone, guest stays up
            agent_ok("cn2", "unplug", "red5")
            wait_for(lambda: not has_route("cn1", "10.1.2.15/32"), 3, 0.05, "route withdrawal")
            t0 = time.monotonic()
            agent_ok("cn2", "plug", "red5", "port", "red5")
            wait_for(lambda: has_route("cn1", "10.1.2.15/32") and "red5" in
                     {p["name"] for p in fwd_ok("cn2", "port", "show")["ports"]}, 2.0, 0.02, "route after plug")
            lat.append(time.monotonic() - t0)
        assert max(lat) < 2.0, lat
        assert ping_ok("red1", "10.1.2.15", count=3)
        print(f"plug->route latency over {TRIALS} trials: max {max(lat):.3f}s")
    finally:
        pass


def test_c6_stopping_the_vm_removes_it_everywhere_within_two_seconds():
    assert vmi("red5")["state"] == "bound"
    stop("red5")
    for n in ("cn1", "cn2"):
        wait_for(lambda: not has_route(n, "10.1.2.15/32"), 2.0, 0.05, f"no route on {n}")
        assert all(l["port"] != "red5" for l in labels(n).values())
    assert vmi("red5")["state"] == "unbound"
    sudo = "sudo " if VARIANT == "kvm" else ""
    r = vm_exec("red1", f"{sudo}ping -c 1 -W 1 10.1.2.15", check=False)
    assert r.returncode != 0
    assert "Unreachable" in r.stdout and "10.1.1.1" in r.stdout, r.stdout  # ICMP from the gateway
    wait_converged(10)


def test_c7_moving_a_vm_follows_it():
    old_label = vmi("red2")["label"]
    r = run_lab("guest", "move", "red2", "cn1")
    assert r.returncode == 0, r.stdout + r.stderr
    t0 = time.monotonic()
    assert vmi("red2")["node"] == "cn1"
    wait_for(lambda: ping_ok("red3", "10.1.1.12", count=1), 5.0, 0.2, "red3 reaches red2 on cn1")
    r2 = routes("cn2")["10.1.1.12/32"]                    # cn2 now tunnels to cn1 ...
    assert r2["origin"] == "remote" and r2["node"] == "cn1"
    r1 = routes("cn1")["10.1.1.12/32"]                    # ... and cn1 holds it locally: no route to cn2
    assert r1["origin"] == "host" and r1["port"] == "red2"
    assert "red" in {v["name"] for v in fwd_ok("cn2", "vrf", "show")["vrfs"]}   # red3 keeps VRF red there
    assert vmi("red2")["node"] == "cn1"
    del old_label, t0
    wait_converged(10)
    # and back, so later tests see the shipped layout
    r = run_lab("guest", "move", "red2", "cn2")
    assert r.returncode == 0, r.stdout + r.stderr
    wait_converged(10)


def test_c8_definitions_are_guarded():
    e = ctl("vmi", "del", "red1")
    assert not e["ok"] and e["error"]["code"] == "busy" and "cn1" in e["error"]["message"]
    e = ctl("tenant", "del", "red")
    assert not e["ok"] and e["error"]["code"] == "busy"
    e = ctl("vmi", "add", "dup", "tenant", "red", "ip", "10.1.1.11", "mac", "02:00:00:09:09:09")
    assert not e["ok"] and e["error"]["code"] == "exists"
    assert ctl("vmi", "add", "dupblue", "tenant", "blue", "ip", "10.1.1.77", "mac", "02:00:00:09:09:08")["ok"]
    assert ctl("vmi", "del", "dupblue")["ok"]
    # a plug of an undefined VMI: the controller refuses it and the agent shows why
    import conftest
    conftest.sh("ip", "link", "add", "mvr-tstport", "type", "dummy", check=False)
    conftest.sh("ip", "link", "set", "mvr-tstport", "netns", "mvr-cn1", "name", "tstport", check=False)
    try:
        assert agent("cn1", "plug", "ghost", "port", "tstport")["ok"]
        wait_for(lambda: any(b["vmi"] == "ghost" for b in agent_ok("cn1", "status")["bind_errors"]), 5, 0.2,
                 "bind error in agent status")
        err = next(b for b in agent_ok("cn1", "status")["bind_errors"] if b["vmi"] == "ghost")
        assert err["code"] == "unknown-vmi"
        assert ctl_ok("stats", "show")["sessions"]["accepted"] >= 2
    finally:
        agent("cn1", "unplug", "ghost")
        conftest.sh("ip", "netns", "exec", "mvr-cn1", "ip", "link", "del", "tstport", check=False)


def _pinger(src, dst, seconds, result):
    sudo = "sudo " if VARIANT == "kvm" else ""
    r = vm_exec(src, f"{sudo}ping -c {int(seconds * 10)} -i 0.1 -W 1 {dst}", check=False, timeout=seconds * 3 + 60)
    import re
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", r.stdout)
    result["loss"] = float(m.group(1)) if m else 100.0
    result["out"] = r.stdout


def _switch_and_check(encap, want_kind, want_vni=None):
    result = {}
    with Capture() as cap:
        t = threading.Thread(target=_pinger, args=("red1", "10.1.1.12", 12, result))
        t.start()
        time.sleep(2.0)
        t0 = time.time()
        assert ctl("tenant", "set", "red", "encap", encap)["ok"]
        t.join(timeout=120)
    assert result["loss"] == 0, result["out"]
    sent = [p for p in tunnel_packets(cap) if p["dst"] == "172.16.0.2" and p["inner"].src == "10.1.1.11"
            if hasattr(p["inner"], "src")]
    kinds = [(p["time"], p["kind"]) for p in sent]
    after = [k for k in kinds if k[0] > t0 + 2.0]
    assert after and all(k == want_kind for _, k in after), after[:5]
    if want_vni:
        assert {p["vni"] for p in sent if p["kind"] == "vxlan" and p["time"] > t0 + 2.0} == {want_vni}


def test_c18_encap_change_is_hitless_both_ways():
    assert ctl_ok("tenant", "show")["tenants"][0]["encap"] in ("mplsoudp", "vxlan")
    _switch_and_check("vxlan", "vxlan", 100)
    _switch_and_check("mplsoudp", "mplsoudp")
    wait_converged(10)
