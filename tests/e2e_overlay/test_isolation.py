"""US3: tenants with overlapping addresses never see each other (quickstart O6, O7; SC-003)."""
import threading
import time

from scapy.all import ICMP, IP

from capture import Capture, tunnel_packets
from conftest import VARIANT, forwarder_pids, reasons, v, vc, vm, ns_exec
from injector import Injector

PAT = {"red": "a1", "blue": "b2"}  # ping -p: payload byte of each tenant's traffic
PORT_NS = {"red1": "mvr-cn1", "blue1": "mvr-cn1", "red2": "mvr-cn2", "red3": "mvr-cn2", "blue2": "mvr-cn2"}


def tenant_of(port):
    return "red" if port.startswith("red") else "blue"


def echo_payloads(cap):
    """ICMP echo request/reply payloads seen on a capture."""
    out = []
    for p in cap.packets():
        if p.haslayer(ICMP) and p[ICMP].type in (0, 8):
            out.append(bytes(p[ICMP].payload))
    return out


def has_pattern(payloads, tenant):
    pat = bytes.fromhex(PAT[tenant]) * 8
    return [x for x in payloads if pat in x]


class PortCaptures:
    """tcpdump on VM ports (inside the node namespaces), one per port."""

    def __init__(self, ports):
        self.caps = {p: Capture(iface=p, netns=PORT_NS[p]) for p in ports}

    def __enter__(self):
        for c in self.caps.values():
            c.__enter__()
        return self

    def __exit__(self, *exc):
        for c in self.caps.values():
            c.__exit__(*exc)
        return False


def assert_no_foreign_frames(caps):
    for port, cap in caps.caps.items():
        mine, other = tenant_of(port), ("blue" if tenant_of(port) == "red" else "red")
        pl = echo_payloads(cap)
        assert has_pattern(pl, other) == [], f"{other} traffic seen on {mine} port {port}"


def test_o6_same_address_both_tenants_simultaneously(fresh):
    res = {}

    def run(src, tenant):
        res[tenant] = vm(src).ping("10.1.1.12", count=20, interval=0.2, extra=f"-p {PAT[tenant]}")

    with PortCaptures(["red2", "blue2"]) as caps:
        ts = [threading.Thread(target=run, args=a) for a in (("red1", "red"), ("blue1", "blue"))]
        [t.start() for t in ts]
        [t.join(timeout=120) for t in ts]
    for tenant in ("red", "blue"):
        loss, ttls, out = res[tenant]
        assert loss == 0 and ttls == {"63"}, out
    assert_no_foreign_frames(caps)
    # each port did see its own tenant's requests
    assert len(has_pattern(echo_payloads(caps.caps["red2"]), "red")) >= 20
    assert len(has_pattern(echo_payloads(caps.caps["blue2"]), "blue")) >= 20


SWEEP = ("for n in 0 1 2 3; do h=1; while [ $h -le 254 ]; do i=0; "
         "while [ $i -lt 32 ] && [ $h -le 254 ]; do ping -c1 -W1 -p {pat} 10.1.$n.$h >/dev/null 2>&1 & "
         "h=$((h+1)); i=$((i+1)); done; wait; done; done")


def test_sc003_sweep_of_the_shared_address_space_leaks_nothing(fresh):
    ports = list(PORT_NS)
    t0 = time.monotonic()
    with PortCaptures(ports) as caps:
        ts = [threading.Thread(target=lambda s=s, t=t: vm(s).run(SWEEP.format(pat=PAT[t]), timeout=300))
              for s, t in (("red1", "red"), ("blue1", "blue"))]
        [t.start() for t in ts]
        [t.join(timeout=300) for t in ts]
    assert time.monotonic() - t0 >= 25  # the sweep ran for its 30 s (1,016 addresses each)
    assert_no_foreign_frames(caps)
    # the sweep did produce tenant traffic where it should: red reached red3's address
    assert has_pattern(echo_payloads(caps.caps["red3"]), "red")
    assert has_pattern(echo_payloads(caps.caps["blue2"]), "red") == []


def test_o7_address_that_only_the_other_tenant_has_is_unreachable(fresh):
    r0 = reasons("cn1")["no_route"]
    with Capture() as cap:
        loss, _, out = vm("blue1").ping("10.1.2.13", count=2, extra="-W 2")
    assert loss == 100 and "Destination Net Unreachable" in out and "From 10.1.1.1" in out, out
    assert tunnel_packets(cap) == []  # nothing left the node
    assert reasons("cn1")["no_route"] >= r0 + 2


def test_us3_3_foreign_tags_are_counted_and_deliver_nothing(fresh):
    before = reasons("cn2")["decap_no_local_dest"]
    with PortCaptures(["red2", "red3", "blue2"]) as caps, Injector("cn2") as inj:
        inj.send("mpls_label_of_another_port")
        inj.send("blue_vni_with_red_only_destination")
        time.sleep(0.5)
    assert reasons("cn2")["decap_no_local_dest"] == before + 2
    for port, cap in caps.caps.items():
        assert [p for p in cap.packets() if p.haslayer(IP) and p[IP].src.startswith("10.1.1.11")] == []


def _on_link(src, prefix):
    """Make `prefix` on-link for the guest, so it ARPs for the address itself."""
    sudo = "sudo " if VARIANT == "kvm" else ""
    vm(src).run(f"{sudo}ip route add {prefix} dev eth0", check=False)


def _off_link(src, prefix):
    sudo = "sudo " if VARIANT == "kvm" else ""
    vm(src).run(f"{sudo}ip route del {prefix} dev eth0", check=False)


def test_us3_4_arp_is_answered_only_for_the_tenants_own_addresses(fresh):
    _on_link("red1", "10.1.2.0/24")
    _on_link("blue1", "10.1.2.0/24")
    try:
        # 10.1.2.13 is a red VM (remote /32 in red): red1's ARP is answered, blue1's is not
        loss, _, out = vm("red1").ping("10.1.2.13", count=2, extra="-W 2")
        assert loss == 0, out
        a0 = reasons("cn1")["arp_unknown_target"]
        loss, _, out = vm("blue1").ping("10.1.2.13", count=2, extra="-W 2")
        assert loss == 100, out
        assert reasons("cn1")["arp_unknown_target"] > a0
        # an address both tenants have (blue2/red2 on 10.1.1.12) is answered in each
        for src in ("red1", "blue1"):
            loss, _, out = vm(src).ping("10.1.1.12", count=2)
            assert loss == 0, out
    finally:
        _off_link("red1", "10.1.2.0/24")
        _off_link("blue1", "10.1.2.0/24")


def test_us3_5_a_route_added_in_red_exists_only_in_red(fresh):
    vc("cn1", "route", "add", "10.9.0.0/24", "vrf", "red", "dev", "red1", "via", "10.1.1.50")
    red = {r["prefix"] for r in v("cn1", "route", "show", "vrf", "red")["data"]["routes"]}
    blue = {r["prefix"] for r in v("cn1", "route", "show", "vrf", "blue")["data"]["routes"]}
    assert "10.9.0.0/24" in red and "10.9.0.0/24" not in blue
    loss, _, out = vm("blue1").ping("10.9.0.5", count=1, extra="-W 2")
    assert loss == 100 and "Destination Net Unreachable" in out, out
    loss, _, out = vm("red1").ping("10.9.0.5", count=1, extra="-W 2")
    assert "Net Unreachable" not in out, out  # red has the route (its next hop just does not answer)
