"""US6 (quickstart C14, SC-006): hostile control traffic closes one session with a named reason and
never disturbs the rest."""
import os
import socket
import time

import pytest

import fakepeer as fp
import proto_corpus as pc
from conftest import (agent_ok, ctl_ok, fwd, fwd_ok, node_states, run_lab, wait_converged, wait_for)
from pinger import Pinger

CTL_ADDR = ("10.98.0.254", 7700)


def in_netns(ns, make):
    """Run make() (creates a socket) inside network namespace `ns`, then come back."""
    orig = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/var/run/netns/{ns}", os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        return make()
    finally:
        os.setns(orig, os.CLONE_NEWNET)
        os.close(orig)
        os.close(target)


def connect_ctld():
    def mk():
        s = socket.create_connection(CTL_ADDR, timeout=5)
        return s
    return in_netns("mvr-ctl", mk)


def listen_in_ctl():
    def mk():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(CTL_ADDR)
        s.listen(8)
        return s
    return in_netns("mvr-ctl", mk)


def proto_errors():
    return ctl_ok("stats", "show")["proto_errors"]


def drain_close(sock, seconds=3.0):
    """Read until the peer closes; returns what arrived (a REJECT is expected first)."""
    sock.settimeout(seconds)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return data, True
            data += chunk
    except socket.timeout:
        return data, False
    except ConnectionResetError:   # closed with our unread bytes still queued: a reset is a close
        return data, True


@pytest.fixture(scope="module", autouse=True)
def _lab(ctl_lab):
    yield


@pytest.mark.parametrize("name,pre,payload,counter", pc.AGENT_CASES, ids=[c[0] for c in pc.AGENT_CASES])
def test_a_each_malformed_case_closes_only_its_session(name, pre, payload, counter):
    before = proto_errors()[counter]
    pinger = Pinger("red1", "10.1.1.12", 6).start()
    s = connect_ctld()
    try:
        if pre:
            s.sendall(pc.hello())
            first = fp.read_message(s)
            assert fp.decode(first)[0] == fp.HELLO_ACK
        s.sendall(payload)
        if name.startswith("truncated"):
            s.shutdown(socket.SHUT_WR)   # the connection ends inside the message
        data, closed = drain_close(s)
        assert closed, f"{name}: the controller did not close the session"
    finally:
        s.close()
    wait_for(lambda: proto_errors()[counter] == before + 1, 5, 0.2, f"counter {counter}")
    for n in ("cn1", "cn2"):
        assert node_states()[n]["session"]["state"] == "in-sync"
    assert pinger.join() == 0.0


def test_a_unknown_node_and_duplicate_session_are_rejected_without_touching_the_live_one():
    stats = ctl_ok("stats", "show")["sessions"]["rejected_by_reason"]
    s = connect_ctld()
    s.sendall(pc.hello("nosuchnode"))
    data, closed = drain_close(s)
    s.close()
    assert closed and fp.decode(data)[2][0] == (fp.ERR_CODE, b"\x00\x02")
    s = connect_ctld()
    s.sendall(pc.hello("cn1"))
    data, closed = drain_close(s)
    s.close()
    assert closed and fp.decode(data)[2][0] == (fp.ERR_CODE, b"\x00\x03")
    after = ctl_ok("stats", "show")["sessions"]["rejected_by_reason"]
    assert after["unknown-node"] == stats["unknown-node"] + 1
    assert after["duplicate-session"] == stats["duplicate-session"] + 1
    assert node_states()["cn1"]["session"]["state"] == "in-sync"


def test_a_ten_seconds_of_silence_is_hold_expired():
    before = proto_errors()["hold-expired"]
    s = connect_ctld()
    s.sendall(pc.hello())
    assert fp.decode(fp.read_message(s))[0] == fp.HELLO_ACK
    t0 = time.monotonic()
    data, closed = drain_close(s, 14)
    s.close()
    assert closed and 8 <= time.monotonic() - t0 <= 12
    assert proto_errors()["hold-expired"] == before + 1


AGENT_SIDE_CASES = [  # what a hostile controller can send to the agent: same decoder, agent counters
    ("length_11", fp.message(fp.KEEPALIVE, 1, length=11), "bad-length"),
    ("too_large", fp.message(fp.KEEPALIVE, 1, length=65537), "too-large"),
    ("wrong_version", fp.message(fp.HELLO_ACK, 1, fp.u16(fp.KEEPALIVE_S, 3) + fp.u16(fp.HOLD_S, 9), version=2), "bad-version"),
    ("flags_set", fp.message(fp.HELLO_ACK, 1, fp.u16(fp.KEEPALIVE_S, 3) + fp.u16(fp.HOLD_S, 9), flags=1), "bad-flags"),
    ("unknown_type", fp.message(99, 1), "unknown-type"),
    ("update_before_sync_begin", fp.update(2, 999), "unexpected"),
]


def test_b_hostile_controller_cannot_hurt_the_agent():
    """A fake controller in place of ctld: the agent closes on each bad message, counts it, keeps
    forwarding headless, and applies a well-formed UPDATE entry by entry."""
    assert fwd("cn1", "route", "add", "10.1.9.9/32", "vrf", "red", "dev", "red1")["ok"]   # owner cli
    # the entries the real controller intends for cn1: the fake re-sends exactly that state
    state = []
    off = 0
    while True:
        d = ctl_ok("node", "state", "cn1", *(["offset", str(off)] if off else []))
        state += d["entries"]
        if d["next_offset"] is None:
            break
        off = d["next_offset"]
    pinger = Pinger("red1", "10.1.1.12", 40).start()
    run_lab("svc", "kill", "agent-cn2")
    run_lab("svc", "stop", "ctld")
    srv = listen_in_ctl()
    try:
        def accept_agent():
            srv.settimeout(15)
            c, _ = srv.accept()
            hello = fp.decode(fp.read_message(c))
            assert hello[0] == fp.HELLO
            return c

        for name, payload, counter in AGENT_SIDE_CASES:
            before = agent_ok("cn1", "status")["session"]["proto_errors"][counter]
            c = accept_agent()
            if name == "update_before_sync_begin":
                c.sendall(fp.hello_ack(1))
            c.sendall(payload)
            data, closed = drain_close(c, 5)
            c.close()
            assert closed, name
            wait_for(lambda: agent_ok("cn1", "status")["session"]["proto_errors"][counter] == before + 1, 5, 0.2,
                     f"agent counter {counter}")
            assert agent_ok("cn1", "status")["sync"] in ("headless", "in-sync", "syncing")
        # a well-formed full sync: the real state plus three bad entries
        c = accept_agent()
        c.sendall(fp.hello_ack(1))
        seen_end = False
        c.settimeout(5)
        while not seen_end:
            m = fp.decode(fp.read_message(c))
            seen_end = m[0] == fp.BIND_END
        ents = b""
        K = fp
        for e in state:
            k = e["kind"]
            if k == "vrf": ents += K.entry(K.K_VRF, name=e["name"], id=e["id"])
            elif k == "vni": ents += K.entry(K.K_VNI, vni=e["vni"], vrf=e["vrf"])
            elif k == "node": ents += K.entry(K.K_NODE, name=e["name"], ip=e["ip"], rmac=e["rmac"])
            elif k == "port":
                a, l = e["prefix"].split("/")
                ents += K.entry(K.K_PORT, name=e["name"], vrf=e["vrf"], prefix=a, plen=int(l))
            elif k == "neigh": ents += K.entry(K.K_NEIGH, vrf=e["vrf"], ip=e["ip"], mac=e["mac"], port=e["port"])
            elif k == "label": ents += K.entry(K.K_LABEL, label=e["label"], port=e["port"])
            elif k == "route":
                a, l = e["prefix"].split("/")
                ents += K.entry(K.K_ROUTE, vrf=e["vrf"], prefix=a, plen=int(l), node=e["node"],
                                encap=K.ENCAP_MPLSOUDP if e["encap"] == "mplsoudp" else K.ENCAP_VXLAN, tag=e["tag"])
        bad = (K.entry(K.K_ROUTE, vrf="nosuch", prefix="10.77.0.1", plen=32, node="cn2", encap=1, tag=1000) +
               K.entry(K.K_LABEL, label=15, port="red1") +
               K.entry(K.K_ROUTE, vrf="red", prefix="10.1.9.9", plen=32, node="cn2", encap=1, tag=1000))
        c.sendall(fp.sync_begin(2, 5) + fp.update(3, 5, ents + bad) + fp.sync_end(4, 5))
        acks = []
        while len(acks) < 2:
            acks.append(fp.decode(fp.read_message(c)))
        acks = [a for a in acks if a[0] == fp.ACK]
        errors = [a for t, a in [(t, v) for t, v in acks[-1][2]] if t == fp.ERROR] if acks else []
        # the SYNC_END ack carries the failures of applying; the UPDATE ack carries the decode error
        all_errs = [v for a in acks for t, v in a[2] if t == fp.ERROR]
        assert len(all_errs) == 3, all_errs
        codes = sorted(fp.parse_attrs(v)[[x for x, _ in fp.parse_attrs(v)].index(fp.ERR_CODE)][1] for v in all_errs)
        assert codes == [b"\x00\x0a", b"\x00\x0a", b"\x00\x0c"]   # 2 x entry-rejected, 1 x bad-entry
        assert session_still_up(c)
        c.close()
    finally:
        srv.close()
        fwd("cn1", "route", "del", "10.1.9.9/32", "vrf", "red")
    # the forwarder kept the previous state of the rejected keys (the cli route is still the cli's)
    assert pinger.join() == 0.0
    run_lab("svc", "start", "ctld")
    run_lab("svc", "start", "agent-cn2")
    wait_converged(20)


def session_still_up(c):
    try:
        c.sendall(fp.keepalive(9))
        return True
    except OSError:
        return False
