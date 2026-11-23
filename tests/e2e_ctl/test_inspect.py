"""US4 (quickstart C15, SC-010): the views separate "not known", "not received" and "not applied"."""
import pytest

from conftest import (agent, agent_ok, ctl, ctl_ok, fwd, fwd_ok, node_states, run_lab, sh, wait_converged, wait_for)


@pytest.fixture(scope="module", autouse=True)
def _lab(ctl_lab):
    yield


def test_unknown_vmi_is_visible_on_both_sides():
    sh("ip", "link", "add", "mvr-tst1", "type", "dummy", check=False)
    sh("ip", "link", "set", "mvr-tst1", "netns", "mvr-cn1", "name", "tst1", check=False)
    before = ctl_ok("stats", "show")["sessions"]["rejected_by_reason"]["unknown-vmi"]
    try:
        assert agent("cn1", "plug", "nosuchvmi", "port", "tst1")["ok"]
        wait_for(lambda: any(b["vmi"] == "nosuchvmi" for b in agent_ok("cn1", "status")["bind_errors"]), 5, 0.2,
                 "bind error in agent status")
        assert ctl_ok("stats", "show")["sessions"]["rejected_by_reason"]["unknown-vmi"] == before + 1
    finally:
        agent("cn1", "unplug", "nosuchvmi")
        sh("ip", "netns", "exec", "mvr-cn1", "ip", "link", "del", "tst1", check=False)


def test_conflicting_static_route_is_a_conflict_not_an_overwrite():
    # an operator route for a VM that is not up yet, in the forwarder's own CLI (owner cli)
    assert fwd("cn1", "route", "add", "10.1.2.15/32", "vrf", "red", "dev", "red1")["ok"]
    try:
        r = run_lab("guest", "start", "red5")
        assert r.returncode == 0, r.stdout + r.stderr
        wait_for(lambda: agent_ok("cn1", "diff", "show")["conflicts"], 8, 0.3, "conflict in diff show")
        c = agent_ok("cn1", "diff", "show")["conflicts"][0]
        assert c["kind"] == "route" and c["prefix"] == "10.1.2.15/32" and c["owner"] == "cli"
        assert next(r for r in fwd_ok("cn1", "route", "show", "vrf", "red")["routes"]
                    if r["prefix"] == "10.1.2.15/32")["owner"] == "cli"   # never overwritten
        wait_for(lambda: not node_states()["cn1"]["in_sync"], 8, 0.3, "controller sees the rejection")
        errs = node_states()["cn1"]["entry_errors"]
        assert errs and errs[0]["code"] == "entry-rejected" and errs[0]["kind"] == "route", errs
    finally:
        fwd("cn1", "route", "del", "10.1.2.15/32", "vrf", "red")
        run_lab("guest", "stop", "red5")
        run_lab("svc", "kill", "agent-cn1")
        run_lab("svc", "start", "agent-cn1")   # a full sync clears the recorded error
        wait_converged(15)
    wait_for(lambda: node_states()["cn1"]["in_sync"] is True, 10, 0.3, "cn1 in sync again")


def test_control_network_cut_is_visible_from_both_ends():
    assert run_lab("ctl-cut", "cn2", "down").returncode == 0
    try:
        wait_for(lambda: node_states()["cn2"]["session"]["state"] == "none", 15, 0.5, "controller drops cn2")
        s = node_states()["cn2"]["session"]
        assert s["last_error"] == "hold-expired", s
        wait_for(lambda: agent_ok("cn2", "status")["sync"] == "headless", 15, 0.5, "agent headless")
    finally:
        run_lab("ctl-cut", "cn2", "up")
        wait_converged(20)


def test_every_documented_field_is_present():
    n = ctl_ok("node", "show")["nodes"][0]
    assert {"name", "underlay_ip", "rmac", "session", "in_sync", "entries", "entry_errors", "proto_errors"} <= set(n)
    assert {"state", "peer", "since", "last_error", "msgs_in", "msgs_out", "bytes_in", "bytes_out", "last_seq",
            "acked_seq"} <= set(n["session"])
    st = agent_ok("cn1", "status")
    assert {"node", "session", "sync", "gen", "forwarder", "entries", "failed"} <= set(st)
    assert {"state", "controller", "since", "last_error", "msgs_in", "msgs_out", "bytes_in", "bytes_out",
            "backoff_s", "proto_errors"} <= set(st["session"])
    assert {"state", "boot_id", "last_error"} <= set(st["forwarder"])
    assert set(agent_ok("cn1", "diff", "show")) == {"missing", "stale", "conflicts"}
    v = ctl_ok("vmi", "show")["vmis"][0]
    assert {"name", "tenant", "ip", "mac", "state", "node", "port", "label", "since"} <= set(v)
    es = ctl_ok("node", "state", "cn1")
    assert es["total"] > 0 and {"kind"} <= set(es["entries"][0])
    st = ctl_ok("stats", "show")
    assert {"sessions", "updates_sent", "entries_sent", "ack_errors", "proto_errors", "state_writes"} <= set(st)
    assert ctl_ok("version")["daemon"] == "minivr-ctld" and agent_ok("cn1", "version")["daemon"] == "minivr-agent"
