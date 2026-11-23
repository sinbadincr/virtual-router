"""US1 (specs/005 quickstart C1-C3): the overlay lab driven by controller and agents."""
import re
import time

import pytest

from conftest import (BUDGET_S, GUESTS, LAB_OUT, NODE_OF, VARIANT, agent_ok, ctl_ok, fwd_ok, host_snapshot,
                      lab_args, mvr_ns, node_states, ping_ok, run_lab, wait_converged, wait_for, ROOT)

UP_RUN_BUDGET_S = 150 if VARIANT == "kvm" else 15
DOWN_BUDGET_S = 20 if VARIANT == "kvm" else 15
KIND = f"ctl/{VARIANT}"


def test_c1_bootstrap_configs_declare_only_the_underlay(ctl_lab):
    forbidden = re.compile(r"^\s*(vrf|port|route|label|vni|neigh|node)\b")
    for n in ("cn1", "cn2", "cn3"):
        text = (ROOT / "lab" / "ctl" / f"{n}.conf").read_text()
        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        assert not any(forbidden.match(l) for l in lines), (n, lines)
        assert any(l.startswith("underlay add u0") for l in lines)


def test_c1_every_node_established_and_in_sync(ctl_lab):
    nodes = node_states()
    for n in ("cn1", "cn2"):
        assert nodes[n]["session"]["state"] == "in-sync" and nodes[n]["in_sync"] is True, nodes[n]
        assert nodes[n]["entry_errors"] == []
        st = agent_ok(n, "status")
        assert st["sync"] == "in-sync" and st["forwarder"]["state"] == "up" and st["failed"] == []
    assert nodes["cn3"]["session"]["state"] == "none"  # allowed, not started


def test_c1_forwarder_state_comes_from_the_controller(ctl_lab):
    for n in ("cn1", "cn2"):
        routes = fwd_ok(n, "route", "show", "vrf", "red")["routes"]
        remote = [r for r in routes if r["origin"] == "remote"]
        assert remote and all(r["owner"] == "agent" for r in remote)
        assert all(p["owner"] == "agent" for p in fwd_ok(n, "port", "show")["ports"] if p["role"] == "vm")
        assert fwd_ok(n, "version")["boot_id"]
    # the same tenants and VRFs the phase 2 config declared
    assert {v["name"] for v in fwd_ok("cn1", "vrf", "show")["vrfs"]} == {"default", "red", "blue"}
    assert {v["name"] for v in fwd_ok("cn2", "vrf", "show")["vrfs"]} == {"default", "red", "blue"}


def test_c2_tenants_reach_each_other_and_stay_isolated(ctl_lab):
    assert ping_ok("red1", "10.1.1.12")      # red across nodes (MPLSoUDP)
    assert ping_ok("red1", "10.1.2.13")
    assert ping_ok("blue1", "10.1.1.12")     # blue across nodes (VXLAN), same address as red's
    assert ping_ok("red2", "10.1.2.13")      # same node, routed locally


def test_c1_remote_labels_follow_the_allocation(ctl_lab):
    vmis = {v["name"]: v for v in ctl_ok("vmi", "show")["vmis"]}
    for g in GUESTS:
        assert vmis[g]["state"] == "bound" and vmis[g]["node"] == NODE_OF[g]
        assert 1000 <= vmis[g]["label"] <= 1999 and vmis[g]["port"] == g
    assert vmis["red4"]["state"] == "unbound" and vmis["red5"]["state"] == "unbound"
    for n in ("cn1", "cn2"):
        labels = {l["label"]: l for l in fwd_ok(n, "tunnel", "show")["labels"]}
        mine = {v["label"] for v in vmis.values() if v["node"] == n}
        assert set(labels) == mine and all(l["owner"] == "agent" for l in labels.values())


def test_c3_lifecycle_times_idempotence_and_refusals():
    """SC-001: up + run under the budget, teardown under its budget, snapshot identical."""
    run_lab("down")
    before = host_snapshot()
    t0 = time.monotonic()
    r = run_lab(*lab_args())
    assert r.returncode == 0, r.stderr
    r = run_lab("run")
    assert r.returncode == 0, r.stderr
    up_s = time.monotonic() - t0
    assert up_s < UP_RUN_BUDGET_S, f"up+run took {up_s:.0f}s (budget {UP_RUN_BUDGET_S}s)"
    wait_converged(15)
    # second up is idempotent: nothing recreated, daemons untouched
    ns_before = mvr_ns()
    pids = {f.name: f.read_text() for f in LAB_OUT.glob("*.pid")}
    r = run_lab(*lab_args())
    assert r.returncode == 0, r.stderr
    assert mvr_ns() == ns_before
    assert {f.name: f.read_text() for f in LAB_OUT.glob("*.pid")} == pids
    # other lab kinds are refused while the ctl lab is up
    for args in (["up", "--topo", "overlay"], ["up", "--topo", "overlay", "--harness"], ["up"], ["up", "--harness"]):
        r = run_lab(*args)
        assert r.returncode == 1 and f"{KIND} lab is up; run 'sudo make lab-clean' first" in r.stderr \
            or (r.returncode == 1 and "lab is up; run 'sudo make lab-clean' first" in r.stderr), (args, r.stderr)
        assert mvr_ns() == ns_before
    assert run_lab("status").stdout.splitlines()[0] == f"lab: {KIND}"
    t1 = time.monotonic()
    assert run_lab("down").returncode == 0
    down_s = time.monotonic() - t1
    assert down_s < DOWN_BUDGET_S, f"teardown took {down_s:.0f}s"
    assert host_snapshot() == before, "teardown left the host network changed"
    assert not (LAB_OUT / "ctl").exists()
