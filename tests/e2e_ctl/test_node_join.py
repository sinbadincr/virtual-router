"""US5 (quickstart C13, SC-007): a new compute node joins and leaves without touching the others."""
import hashlib
import time

import pytest

from conftest import (LAB_OUT, ROOT, agent_ok, ctl_ok, fwd, fwd_ok, host_snapshot, node_states, ping_ok, run_lab,
                      wait_converged, wait_for)


@pytest.fixture(scope="module", autouse=True)
def _lab(ctl_lab):
    yield


def md5(p):
    return hashlib.md5(p.read_bytes()).hexdigest()


def test_c13_cn3_joins_serves_red4_and_leaves():
    confs = {n: md5(ROOT / "lab" / "ctl" / f"{n}.conf") for n in ("cn1", "cn2")}
    pids = {n: (LAB_OUT / f"minivrd-{n}.pid").read_text() for n in ("cn1", "cn2")}
    boots = {n: fwd_ok(n, "version")["boot_id"] for n in ("cn1", "cn2")}
    r = run_lab("node", "up", "cn3", timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    t0 = time.monotonic()
    wait_for(lambda: node_states()["cn3"]["session"]["state"] == "in-sync", 10, 0.3, "cn3 in sync")
    wait_for(lambda: ping_ok("red1", "10.1.1.14", count=1) and ping_ok("red2", "10.1.1.14", count=1), 10, 0.5,
             "red1 and red2 reach red4")
    assert time.monotonic() - t0 <= 10
    wait_converged(10)
    # the others were not touched
    assert {n: (LAB_OUT / f"minivrd-{n}.pid").read_text() for n in ("cn1", "cn2")} == pids
    assert {n: fwd_ok(n, "version")["boot_id"] for n in ("cn1", "cn2")} == boots
    assert {n: md5(ROOT / "lab" / "ctl" / f"{n}.conf") for n in ("cn1", "cn2")} == confs
    # cn3 hosts red only: no blue anything
    assert {v["name"] for v in fwd_ok("cn3", "vrf", "show")["vrfs"]} == {"default", "red"}
    assert not [r for r in fwd_ok("cn3", "route", "show", "vrf", "red")["routes"] if r["prefix"].startswith("10.1.1.11")
                and r["origin"] == "host"]
    t = fwd_ok("cn3", "tunnel", "show")
    assert all(l["port"] == "red4" for l in t["labels"]) and all(v["vrf"] == "red" for v in t["vnis"])
    assert {p["name"] for p in fwd_ok("cn3", "port", "show")["ports"] if p["role"] == "vm"} == {"red4"}
    # leaving: no route to cn3 anywhere
    assert run_lab("node", "down", "cn3", timeout=120).returncode == 0
    for n in ("cn1", "cn2"):
        wait_for(lambda: not any(r.get("node") == "cn3" for r in fwd_ok(n, "route", "show", "vrf", "red")["routes"]),
                 5, 0.3, f"{n} forgets cn3")
    wait_converged(10)
    assert ctl_ok("vmi", "show")["vmis"] and next(v for v in ctl_ok("vmi", "show")["vmis"]
                                                  if v["name"] == "red4")["state"] == "unbound"
