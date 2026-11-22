"""US4: configure and inspect tenants, tunnels and mappings at runtime (quickstart O9)."""
from capture import Capture, tunnel_packets
from conftest import VRCTL_BIN, forwarder_pids, sh, v, vc, vm


def vraw(node, *args):
    """vrctl in table mode without -j; returns the CompletedProcess (exit code, stderr)."""
    return sh(VRCTL_BIN, "-s", f"/run/mvr-{node}/minivr.sock", *args, check=False)


def test_o9_json_fields_match_the_contract(fresh):
    d = v("cn1", "vrf", "show")["data"]["vrfs"]
    by = {x["name"]: x for x in d}
    assert set(by) == {"default", "red", "blue"}
    assert set(by["red"]) == {"name", "id", "ports", "routes", "neighbours", "labels", "vnis"}
    assert by["red"]["ports"] == ["red1"] and by["red"]["labels"] == 1 and by["blue"]["vnis"] == 1
    routes = v("cn1", "route", "show", "vrf", "red")["data"]["routes"]
    remote = [r for r in routes if r["origin"] == "remote"]
    assert {(r["prefix"], r["node"], r["encap"], r["tag"]) for r in remote} == {
        ("10.1.1.12/32", "cn2", "mplsoudp", 1012), ("10.1.2.13/32", "cn2", "mplsoudp", 1013)}
    assert all(r["vrf"] == "red" and r["port"] is None for r in remote)
    n = v("cn1", "node", "show")["data"]["nodes"][0]
    assert set(n) == {"name", "ip", "rmac", "underlay_mac", "state", "encap", "decap"}
    assert n["name"] == "cn2" and n["rmac"] == "02:00:00:ff:00:02"
    assert set(n["encap"]) == {"mplsoudp", "vxlan"} and set(n["encap"]["vxlan"]) == {"pkts", "bytes"}
    t = v("cn2", "tunnel", "show")["data"]
    assert [(x["label"], x["port"], x["vrf"]) for x in t["labels"]] == [(1012, "red2", "red"), (1013, "red3", "red")]
    assert t["vnis"] == [{"vni": 200, "vrf": "blue"}]
    assert t["underlay"] == {"port": "u0", "ip": "172.16.0.2/24", "mac": "02:00:00:ff:00:02", "mtu": 1600}
    nb = v("cn1", "neigh", "show", "vrf", "blue")["data"]["neighbours"]
    assert {x["vrf"] for x in nb} == {"blue"}
    assert v("cn1", "stats", "show")["data"]["drops"]["reasons"]["tunnel_mtu_exceeded"] == 0


def test_o9_table_output(fresh):
    out = vraw("cn1", "vrf", "show").stdout
    assert out.splitlines()[0].split() == ["NAME", "ID", "PORTS", "ROUTES", "NEIGHBOURS", "LABELS", "VNIS"]
    assert "red" in out and "red1" in out
    out = vraw("cn1", "route", "show", "vrf", "red").stdout
    assert out.splitlines()[0].split() == ["VRF", "PREFIX", "PORT", "GATEWAY", "ORIGIN", "REMOTE"]
    assert "cn2 mplsoudp 1012" in out
    out = vraw("cn1", "node", "show").stdout
    assert "cn2" in out and "172.16.0.2" in out
    out = vraw("cn2", "tunnel", "show").stdout
    assert out.startswith("underlay u0 172.16.0.2/24 mac 02:00:00:ff:00:02 mtu 1600")
    assert "1012" in out and "red2" in out and "200" in out
    out = vraw("cn1", "neigh", "show", "underlay").stdout
    assert out.splitlines()[0].split()[0] == "IP" or out.strip() == ""


def test_node_counters_equal_the_packets_captured_on_the_underlay(fresh):
    with Capture() as cap:
        loss, _, out = vm("red1").ping("10.1.1.12", count=100, interval=0.05)
    assert loss == 0, out
    pk = tunnel_packets(cap)
    sent = [p for p in pk if p["dst"] == "172.16.0.2"]
    recv = [p for p in pk if p["dst"] == "172.16.0.1"]
    assert len(sent) == len(recv) == 100
    n = v("cn1", "node", "show")["data"]["nodes"][0]
    assert n["encap"]["mplsoudp"]["pkts"] == 100 and n["decap"]["mplsoudp"]["pkts"] == 100
    assert n["encap"]["vxlan"]["pkts"] == 0
    assert n["encap"]["mplsoudp"]["bytes"] == sum(len(bytes(p)) for p in cap.packets()
                                                   if p.haslayer("IP") and p["IP"].dst == "172.16.0.2"
                                                   and p.haslayer("UDP") and p["UDP"].dport == 6635)
    n2 = v("cn2", "node", "show")["data"]["nodes"][0]
    assert n2["decap"]["mplsoudp"]["pkts"] == 100 and n2["encap"]["mplsoudp"]["pkts"] == 100
    assert v("cn1", "stats", "show")["data"]["nodes"][0]["encap"]["mplsoudp"]["pkts"] == 100


def test_cli_only_tenant_green_carries_traffic_within_a_second(fresh):
    pids = forwarder_pids()
    for node in ("cn1", "cn2"):
        vc(node, "vrf", "add", "green", "id", "3")
    vc("cn1", "port", "set", "red1", "vrf", "green")
    vc("cn2", "port", "set", "red3", "vrf", "green")
    vc("cn1", "route", "add", "10.1.2.13/32", "vrf", "green", "node", "cn2", "encap", "mplsoudp", "label", "1013")
    vc("cn2", "route", "add", "10.1.1.11/32", "vrf", "green", "node", "cn1", "encap", "mplsoudp", "label", "1011")
    try:
        # the port left red: red1's addresses are gone from red and present in green
        red = {r["prefix"] for r in v("cn1", "route", "show", "vrf", "red")["data"]["routes"]}
        green = {r["prefix"] for r in v("cn1", "route", "show", "vrf", "green")["data"]["routes"]}
        assert "10.1.1.11/32" not in red and {"10.1.1.0/24", "10.1.1.11/32", "10.1.2.13/32"} <= green
        loss, ttls, out = vm("red1").ping("10.1.2.13", count=3, extra="-W 1")
        assert loss == 0 and ttls == {"63"}, out
        loss, _, out = vm("red3").ping("10.1.1.11", count=3, extra="-W 1")
        assert loss == 0, out
        assert v("cn1", "vrf", "show")["data"]["vrfs"][-1]["name"] == "green"
        # US4-4: a VRF still in use cannot be deleted; the failed command changes nothing
        r = vraw("cn1", "vrf", "del", "green")
        assert r.returncode == 1 and r.stderr.startswith("busy:"), r
    finally:
        for node, port in (("cn1", "red1"), ("cn2", "red3")):
            vc(node, "route", "del", "10.1.2.13/32" if node == "cn1" else "10.1.1.11/32", "vrf", "green")
            vc(node, "port", "set", port, "vrf", "red")
            vc(node, "vrf", "del", "green")
    assert [x["name"] for x in v("cn1", "vrf", "show")["data"]["vrfs"]] == ["default", "red", "blue"]
    loss, _, out = vm("red1").ping("10.1.1.12", count=3)  # back in red: the shipped routes work again
    assert loss == 0, out
    assert forwarder_pids() == pids


def test_us4_error_cases_leave_state_unchanged(fresh):
    before = v("cn1", "tunnel", "show")["data"], v("cn1", "route", "show", "vrf", "red")["data"]
    cases = [
        (("vni", "add", "200", "vrf", "red"), "exists"),
        (("label", "add", "1011", "port", "red1"), "exists"),
        (("label", "add", "5", "port", "red1"), "bad-syntax"),
        (("vrf", "del", "red"), "busy"),
        (("vrf", "del", "default"), "immutable"),
        (("node", "del", "cn2"), "busy"),
        (("route", "add", "10.7.0.1/32", "vrf", "red", "node", "nosuch", "encap", "mplsoudp", "label", "100"), "unknown-node"),
        (("route", "add", "10.7.0.1/32", "vrf", "nosuch", "node", "cn2", "encap", "mplsoudp", "label", "100"), "unknown-vrf"),
        (("route", "add", "10.7.0.1/32", "vrf", "red", "node", "cn2", "encap", "vxlan", "vni", "0"), "bad-syntax"),
        (("port", "set", "red1", "vrf", "nosuch"), "unknown-vrf"),
    ]
    for args, code in cases:
        r = v("cn1", *args)
        assert r["ok"] is False and r["error"]["code"] == code, (args, r)
        assert vraw("cn1", *args).returncode == 1
    # config-only commands are refused at runtime
    r = v("cn1", "underlay", "add", "u1", "ifname", "u1", "ip", "172.16.9.1/24")
    assert r["error"]["code"] == "config-only"
    assert (v("cn1", "tunnel", "show")["data"], v("cn1", "route", "show", "vrf", "red")["data"]) == before
