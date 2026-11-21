"""US3: inspect and change forwarder state at runtime (contracts/cli.md; V9-V11; SC-005, SC-007)."""
import concurrent.futures
import os
import re
import subprocess
import time

import pytest

from conftest import (ROOT, VRCTL_BIN, forwarder_pid, lab_sh, ns_exec, reasons, sh, start_forwarder,
                      stats, vrctl, vrctl_raw)


def ping(ns, *args, timeout=30):
    return ns_exec(ns, "ping", *args, check=False, timeout=timeout)


def test_table_output_matches_the_contract(forwarder):
    out = vrctl_raw("route", "show").stdout.splitlines()
    assert out[0].split() == ["PREFIX", "PORT", "GATEWAY", "ORIGIN"]
    rows = [l.split() for l in out[1:]]
    assert ["10.0.1.0/24", "-", "-", "connected"] in rows
    assert ["10.0.1.11/32", "p1", "-", "host"] in rows
    assert ["10.0.2.13/32", "p3", "-", "host"] in rows
    assert [r[0] for r in rows] == sorted([r[0] for r in rows], key=lambda p: (
        tuple(int(x) for x in p.split("/")[0].split(".")), int(p.split("/")[1])))

    out = vrctl_raw("port", "show").stdout.splitlines()
    assert out[0].split() == ["NAME", "IFNAME", "MAC", "IP", "MTU", "ADMIN", "OPER", "RX_PKTS",
                              "RX_BYTES", "TX_PKTS", "TX_BYTES", "DROPS"]
    assert out[1].split()[:7] == ["p1", "p1", "02:00:00:00:00:01", "10.0.1.1/24", "1500", "up", "up"]

    out = vrctl_raw("neigh", "show").stdout.splitlines()
    assert out[0].split() == ["IP", "MAC", "PORT", "KIND", "STATE", "HELD"]
    assert out[1].split() == ["10.0.1.11", "02:00:00:00:01:01", "p1", "static", "REACHABLE", "0"]

    out = vrctl_raw("stats", "show").stdout
    assert "DROPS total 0" in out and "MBUF in_use 0 / 4096" in out and "no_route" in out

    assert vrctl_raw("version").stdout.startswith("minivrd 0.1.0")


def test_json_shapes(forwarder):
    r = vrctl("route", "show")
    assert r["ok"] is True
    # phase 2 adds `vrf` (always "default" here) to every route (specs/003 contracts/cli.md)
    assert {"vrf": "default", "prefix": "10.0.1.0/24", "port": None, "gateway": None,
            "origin": "connected"} in r["data"]["routes"]
    p = vrctl("port", "show")["data"]["ports"][0]
    assert set(p) == {"name", "ifname", "role", "vrf", "mac", "ip", "mtu", "admin", "oper", "rx_pkts",
                      "rx_bytes", "tx_pkts", "tx_bytes", "drops"}
    assert p["role"] == "vm" and p["vrf"] == "default"
    s = stats()
    assert set(s) == {"ports", "drops", "events", "nodes", "mbuf"}  # nodes: phase 2
    assert set(s["ports"][0]) == {"name", "rx_pkts", "rx_bytes", "tx_pkts", "tx_bytes", "drops"}
    assert s["mbuf"] == {"total": 4096, "in_use": 0}
    e = vrctl("route", "del", "10.0.2.13/32")
    assert e["ok"] is False and e["error"]["code"] == "immutable"
    v = vrctl("version")["data"]
    assert v["protocol"] == 1 and v["build"] in ("debug", "release")


def test_v9_connected_and_host_routes_are_immutable(forwarder):
    r = vrctl_raw("route", "del", "10.0.2.13/32")
    assert r.returncode == 1
    assert r.stderr.startswith("immutable:")
    assert vrctl_raw("route", "del", "10.0.2.0/24").returncode == 1
    assert any(x["prefix"] == "10.0.2.13/32" for x in vrctl("route", "show")["data"]["routes"])


def test_v10_live_route_change_without_restart(lab):
    pid = start_forwarder("cn1-nobind.conf")
    ns_exec("mvr-vm3", "ip", "addr", "add", "10.0.9.1/32", "dev", "lo")
    assert vrctl("route", "add", "10.0.9.0/24", "dev", "p3", "via", "10.0.2.13")["ok"]
    r = ping("mvr-vm1", "-c", "2", "-W", "2", "10.0.9.1")
    assert " 0% packet loss" in r.stdout, r.stdout

    t0 = time.monotonic()
    assert vrctl("route", "del", "10.0.9.0/24")["ok"]
    r = ping("mvr-vm1", "-c", "1", "-W", "1", "10.0.9.1")
    assert "Destination Net Unreachable" in r.stdout, r.stdout
    assert time.monotonic() - t0 < 1.0

    t0 = time.monotonic()
    assert vrctl("route", "add", "10.0.9.0/24", "dev", "p3", "via", "10.0.2.13")["ok"]
    r = ping("mvr-vm1", "-c", "1", "-W", "1", "10.0.9.1")
    assert " 0% packet loss" in r.stdout, r.stdout
    assert time.monotonic() - t0 < 1.0
    assert forwarder_pid() == pid and os.path.exists(f"/proc/{pid}")  # never restarted


def test_v11_drop_counters_add_up(forwarder):
    for dst in ("10.9.9.9", "10.8.8.8"):
        ping("mvr-vm1", "-c", "2", "-W", "1", dst)
    ping("mvr-vm1", "-c", "1", "-t", "1", "-W", "1", "10.0.2.13")
    d = stats()["drops"]
    assert d["total"] >= 5
    assert d["total"] == sum(d["reasons"].values())  # SC-007
    assert len(d["reasons"]) == 30  # 21 of phase 1 + 9 tunnel reasons (phase 2)


def test_stats_clear_zeroes_counters_but_not_gauges(forwarder):
    ping("mvr-vm1", "-c", "2", "-W", "1", "10.9.9.9")
    assert stats()["drops"]["total"] > 0
    assert vrctl("stats", "clear")["ok"]
    s = stats()
    assert s["drops"]["total"] == 0 and all(v == 0 for v in s["drops"]["reasons"].values())
    assert s["mbuf"]["total"] == 4096


def test_admin_down_and_neighbour_commands(forwarder):
    assert vrctl("port", "set", "p3", "admin", "down")["ok"]
    p3 = [p for p in vrctl("port", "show")["data"]["ports"] if p["name"] == "p3"][0]
    assert p3["admin"] == "down"
    r = ping("mvr-vm1", "-c", "1", "-W", "1", "10.0.2.13")
    assert " 100% packet loss" in r.stdout
    assert reasons()["port_down"] >= 1
    assert vrctl("port", "set", "p3", "admin", "up")["ok"]
    assert " 0% packet loss" in ping("mvr-vm1", "-c", "1", "-W", "1", "10.0.2.13").stdout

    assert vrctl("route", "lookup", "10.0.2.13")["data"]["route"]["prefix"] == "10.0.2.13/32"
    assert vrctl("neigh", "del", "10.0.2.13")["ok"]
    assert vrctl("neigh", "del", "10.0.2.13")["error"]["code"] == "not-found"
    assert not any(r["prefix"] == "10.0.2.13/32" for r in vrctl("route", "show")["data"]["routes"])
    assert vrctl("neigh", "add", "10.0.2.13", "lladdr", "02:00:00:00:01:03", "dev", "p3")["ok"]
    assert " 0% packet loss" in ping("mvr-vm1", "-c", "1", "-W", "1", "10.0.2.13").stdout


def test_errors_leave_state_unchanged(forwarder):
    before = vrctl("route", "show")
    for args, code in [(("route", "add", "10.0.9.1/24", "dev", "p3"), "bad-prefix"),
                       (("route", "add", "10.0.9.0/24", "dev", "p3", "via", "9.9.9.9"), "gw-not-connected"),
                       (("route", "add", "10.0.9.0/24", "dev", "nope"), "unknown-port"),
                       (("port", "add", "p9", "ifname", "p9", "ip", "10.9.9.1/24"), "config-only")]:
        r = vrctl(*args)
        assert r["ok"] is False and r["error"]["code"] == code, (args, r)
    assert vrctl("route", "show") == before


def test_exit_codes(forwarder):
    assert vrctl_raw("route", "show").returncode == 0
    assert vrctl_raw("route", "del", "10.0.2.13/32").returncode == 1
    assert vrctl_raw("frobnicate").returncode == 2
    assert vrctl_raw().returncode == 2
    assert vrctl_raw("route").returncode == 2
    lab_sh("down")  # stops the forwarder and removes its socket
    r = vrctl_raw("version")
    assert r.returncode == 3 and "cannot connect" in r.stderr


def test_two_concurrent_clients_do_not_disturb_each_other(forwarder):
    def loop(cmd):
        bad = 0
        for _ in range(200):
            r = subprocess.run([str(VRCTL_BIN), *cmd], capture_output=True, text=True)
            bad += r.returncode != 0
        return bad

    with concurrent.futures.ThreadPoolExecutor(2) as ex:
        a = ex.submit(loop, ["route", "show"])
        b = ex.submit(loop, ["-j", "stats", "show"])
        assert (a.result(), b.result()) == (0, 0)


def test_other_users_are_not_permitted(forwarder):
    probe = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        pytest.skip("cannot switch uid here (user-namespace sandbox?)")
    # Open the filesystem permissions so the request reaches the server: it must still refuse the
    # peer by SO_PEERCRED (FR-022).
    os.chmod("/run/mvr-cn1", 0o755)
    os.chmod("/run/mvr-cn1/minivr.sock", 0o666)
    r = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                        str(VRCTL_BIN), "-s", "/run/mvr-cn1/minivr.sock", "route", "show"],
                       capture_output=True, text=True)
    assert r.returncode == 3 and "not-permitted" in r.stderr, (r.returncode, r.stderr)


def test_sc010_full_route_table_still_updates_live(lab, tmp_path):
    """10,000 routes loaded: listing pages correctly, the table refuses an extra route, and a
    route change still takes effect within 1 s on live traffic."""
    conf = (ROOT / "lab" / "cn1-nobind.conf").read_text().splitlines()
    conf.append("route add 10.0.9.0/24 dev p3 via 10.0.2.13")
    base = 4 + 1  # connected p1/p2 (shared), connected p3, two host routes, the route above
    conf += [f"route add 100.{i >> 8}.{i & 255}.0/24 dev p3 via 10.0.2.13"
             for i in range(10000 - base)]
    cfg = tmp_path / "full.conf"
    cfg.write_text("\n".join(conf) + "\n")
    pid = start_forwarder(str(cfg))
    ns_exec("mvr-vm3", "ip", "addr", "add", "10.0.9.1/32", "dev", "lo")

    first = vrctl("route", "show", "limit", "1")["data"]
    assert first["total"] == 10000 and first["next_offset"] == 1
    # page through everything: 20 pages of 500, no overlap, nothing lost
    seen, offset = [], 0
    while offset is not None:
        page = vrctl("route", "show", "offset", str(offset))["data"]
        seen += [r["prefix"] for r in page["routes"]]
        offset = page["next_offset"]
    assert len(seen) == 10000 and len(set(seen)) == 10000
    # the human-readable table follows the pages by itself
    assert len(vrctl_raw("route", "show").stdout.splitlines()) == 10001

    r = vrctl("route", "add", "200.0.0.0/24", "dev", "p3")
    assert r["ok"] is False and r["error"]["code"] == "table-full"
    assert " 0% packet loss" in ping("mvr-vm1", "-c", "2", "-W", "2", "10.0.9.1").stdout

    t0 = time.monotonic()
    assert vrctl("route", "del", "10.0.9.0/24")["ok"]
    assert "Destination Net Unreachable" in ping("mvr-vm1", "-c", "1", "-W", "1", "10.0.9.1").stdout
    assert time.monotonic() - t0 < 1.0
    t0 = time.monotonic()
    assert vrctl("route", "add", "10.0.9.0/24", "dev", "p3", "via", "10.0.2.13")["ok"]
    assert " 0% packet loss" in ping("mvr-vm1", "-c", "1", "-W", "1", "10.0.9.1").stdout
    assert time.monotonic() - t0 < 1.0
    assert forwarder_pid() == pid
