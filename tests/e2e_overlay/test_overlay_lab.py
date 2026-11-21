"""US1: the running overlay lab (quickstart O1, O2). Destructive checks: test_overlay_lifecycle.py."""
import os
import re
import tempfile
import time
from pathlib import Path

from conftest import (GUESTS, NODE_OF, UL_MAC, VARIANT, forwarder_pids, host_snapshot, lab_args,
                      mvr_ns, ns_exec, run_lab, v)

BRING_UP_BUDGET_S = 15 if VARIANT == "harness" else 120
TEARDOWN_BUDGET_S = 15
KIND = f"overlay/{VARIANT}"


def test_topology_matches_contract(overlay_lab):
    ns = mvr_ns()
    for n in ("mvr-cn1", "mvr-cn2", "mvr-ul", "mvr-inj"):
        assert n in ns, ns
    assert ("mvr-mgmt" in ns) == (VARIANT == "kvm")
    assert ("mvr-red1" in ns) == (VARIANT == "harness")
    for node in ("cn1", "cn2"):
        # the compute node never forwards or answers for tenant traffic (FR-004)
        assert ns_exec(f"mvr-{node}", "sysctl", "-n", "net.ipv4.ip_forward").stdout.strip() == "0"
        u0 = ns_exec(f"mvr-{node}", "ip", "-j", "-d", "link", "show", "u0").stdout
        assert f'"mtu":1600' in u0.replace(" ", "")
        assert UL_MAC[node] in u0
        assert ns_exec(f"mvr-{node}", "sysctl", "-n", "net.ipv4.conf.u0.arp_ignore").stdout.strip() == "8"
        assert ns_exec(f"mvr-{node}", "sysctl", "-n", "net.ipv6.conf.u0.disable_ipv6").stdout.strip() == "1"
    for g in GUESTS:
        node = NODE_OF[g]
        assert ns_exec(f"mvr-{node}", "sysctl", "-n", f"net.ipv4.conf.{g}.arp_ignore").stdout.strip() == "8"
        link = ns_exec(f"mvr-{node}", "ip", "-j", "link", "show", g).stdout
        assert '"mtu":1500' in link.replace(" ", "")
        assert "UP" in link
    br = ns_exec("mvr-ul", "ip", "-j", "link", "show", "br0").stdout
    assert '"mtu":1600' in br.replace(" ", "")
    # injector on the underlay with the documented address
    assert "172.16.0.9/24" in ns_exec("mvr-inj", "ip", "-br", "addr", "show", "i0").stdout


def test_forwarders_run_with_all_ports_up(forwarders):
    assert all(forwarders.values())
    for node, want in (("cn1", {"u0", "red1", "blue1"}), ("cn2", {"u0", "red2", "red3", "blue2"})):
        ports = v(node, "port", "show")["data"]["ports"]
        assert {p["name"] for p in ports} == want
        assert all(p["admin"] == "up" and p["oper"] == "up" for p in ports), ports
        u = next(p for p in ports if p["name"] == "u0")
        assert u["role"] == "underlay" and u["mtu"] == 1600 and u["mac"] == UL_MAC[node]
    st = run_lab("status")
    assert st.stdout.splitlines()[0] == f"lab: {KIND}", st.stdout
    ident = (Path(__file__).resolve().parents[2] / "build" / "lab" / "minivrd-cn1.log").read_text()
    assert f"mode={KIND}" in ident


def test_up_is_idempotent(forwarders):
    pids_before = forwarder_pids()
    ns_before = mvr_ns()
    r = run_lab(*lab_args())
    assert r.returncode == 0, r.stderr
    assert mvr_ns() == ns_before
    assert forwarder_pids() == pids_before  # `up` does not touch running forwarders


def test_other_kinds_refused_with_exact_message(overlay_lab):
    before = mvr_ns()
    for args in (["up"], ["up", "--harness"], ["up", "--topo", "single"],
                 ["up", "--topo", "single", "--harness"]):
        r = run_lab(*args)
        assert r.returncode == 1, (args, r.stdout, r.stderr)
        assert f"{KIND} lab is up; run 'sudo make lab-clean' first" in r.stderr, r.stderr
        assert mvr_ns() == before
    other = "harness" if VARIANT == "kvm" else "kvm"
    r = run_lab(*lab_args()[:-1] if VARIANT == "harness" else lab_args("--harness"))  # the other variant
    assert r.returncode == 1
    assert f"{KIND} lab is up; run 'sudo make lab-clean' first" in r.stderr, (other, r.stderr)


def test_status_lists_every_guest_and_node(overlay_lab):
    st = run_lab("status").stdout
    assert st.splitlines()[0] == f"lab: {KIND}"
    for node in ("mvr-cn1", "mvr-cn2", "mvr-ul", "mvr-inj"):
        assert f"== {node}" in st
    if VARIANT == "kvm":
        for g in GUESTS:
            assert re.search(rf"^{g}\s+ready\s", st, re.M), st
