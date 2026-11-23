"""US3 (quickstart C9-C12): control-plane failures do not stop traffic and everything reconverges."""
import re
import time
from pathlib import Path

import pytest

from conftest import (LAB_OUT, VARIANT, agent_ok, ctl_ok, fwd_ok, node_states, ping_ok, run_lab, wait_converged,
                      wait_for)
from pinger import Pinger

HOLD_S = 60 if VARIANT == "harness" else 45


@pytest.fixture(autouse=True)
def _lab(ctl_lab):
    yield
    # every test leaves the lab converged for the next one
    run_lab("svc", "start", "ctld") if not (LAB_OUT / "ctld.pid").exists() else None
    wait_converged(15)


def labels():
    return {v["name"]: v["label"] for v in ctl_ok("vmi", "show")["vmis"] if v["label"]}


def test_c9_controller_down_for_a_minute_costs_no_packet(request):
    before = labels()
    pingers = [Pinger("red1", "10.1.1.12", HOLD_S + 25).start(), Pinger("blue1", "10.1.1.12", HOLD_S + 25).start()]
    time.sleep(2)
    assert run_lab("svc", "stop", "ctld").returncode == 0
    time.sleep(HOLD_S / 2)
    for n in ("cn1", "cn2"):
        wait_for(lambda: agent_ok(n, "status")["sync"] == "headless", 15, 0.5, f"{n} headless")
    r = run_lab("guest", "start", "red5")       # a VM boots while the controller is away
    assert r.returncode == 0, r.stdout + r.stderr
    b = {x["vmi"]: x for x in agent_ok("cn2", "bindings", "show")["bindings"]}
    assert "red5" in b and b["red5"]["reported"] is False
    time.sleep(HOLD_S / 2)
    t0 = time.monotonic()
    assert run_lab("svc", "start", "ctld").returncode == 0
    wait_for(lambda: all(n["session"]["state"] == "in-sync" for n in
                         (v for k, v in node_states().items() if k in ("cn1", "cn2"))), 10, 0.2, "nodes in sync")
    wait_converged(10)
    assert time.monotonic() - t0 <= 10
    assert ping_ok("red1", "10.1.2.15", count=3)
    after = labels()
    assert all(after[k] == v for k, v in before.items()), (before, after)
    assert [p.join() for p in pingers] == [0.0, 0.0]
    run_lab("guest", "stop", "red5")


def test_c10_agent_restart_keeps_traffic_and_bindings():
    p = Pinger("red1", "10.1.1.12", 30).start()
    time.sleep(2)
    flog = LAB_OUT / "minivrd-cn1.log"
    deleted_before = flog.read_text().count("runtime port deleted")
    assert run_lab("svc", "kill", "agent-cn1").returncode == 0
    time.sleep(3)
    assert run_lab("svc", "start", "agent-cn1").returncode == 0
    wait_for(lambda: agent_ok("cn1", "status")["sync"] == "in-sync", 15, 0.3, "agent resynced")
    assert {b["vmi"] for b in agent_ok("cn1", "bindings", "show")["bindings"]} == {"red1", "blue1"}
    assert flog.read_text().count("runtime port deleted") == deleted_before   # nothing was flushed
    assert "adopted=" in (LAB_OUT / "agent-cn1.log").read_text()
    assert p.join() == 0.0
    wait_converged(10)


def test_c11_forwarder_restart_is_reprogrammed_within_five_seconds():
    old = fwd_ok("cn1", "version")["boot_id"]
    assert run_lab("svc", "kill", "minivrd-cn1").returncode == 0
    assert run_lab("svc", "start", "minivrd-cn1").returncode == 0   # returns when its socket answers
    t0 = time.monotonic()
    wait_for(lambda: ping_ok("red1", "10.1.1.12", count=1), 5.0, 0.3, "traffic back")
    assert time.monotonic() - t0 <= 5.0
    new = fwd_ok("cn1", "version")["boot_id"]
    assert new != old
    wait_for(lambda: agent_ok("cn1", "status")["forwarder"]["boot_id"] == new, 5, 0.3, "agent saw the new boot_id")
    wait_converged(10)


def test_c12_control_network_cut_and_restored():
    pinger = Pinger("red1", "10.1.1.12", 55).start()
    assert run_lab("ctl-cut", "cn1", "down").returncode == 0
    r = run_lab("guest", "start", "red5")
    assert r.returncode == 0, r.stdout + r.stderr
    r = run_lab("guest", "stop", "red3")
    assert r.returncode == 0, r.stdout + r.stderr
    time.sleep(30)
    st = node_states()["cn1"]
    assert st["session"]["state"] == "none" and "hold" in (st["session"]["last_error"] or ""), st["session"]
    assert agent_ok("cn1", "status")["sync"] == "headless"
    assert run_lab("ctl-cut", "cn1", "up").returncode == 0
    wait_for(lambda: agent_ok("cn1", "status")["sync"] == "in-sync", 12, 0.3, "cn1 back in sync")
    wait_converged(10)
    pinger.join()
    run_lab("guest", "stop", "red5")
    run_lab("guest", "start", "red3")
    wait_converged(10)
