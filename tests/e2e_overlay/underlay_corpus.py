#!/usr/bin/env python3
"""Malformed and unexpected underlay traffic (US5, quickstart O12), sent from the injector
namespace mvr-inj (172.16.0.9) to a compute node's underlay port.

  underlay_corpus.py list [--target cn2]     JSON: [{"name", "reason", "what"}] (no root, no sending)
  underlay_corpus.py send NAME [--target ..] send one case on i0
  underlay_corpus.py serve [--target ..]     read case names on stdin, send each, print "DONE NAME"
Frames are built with struct (not a high-level library) so every malformation is exact.
Standard library only. Expected reasons are the drop-reason names of docs/drop-reasons.md."""
import argparse
import json
import socket
import struct
import sys

INJ_MAC = "02:00:00:ff:00:09"
INJ_IP = "172.16.0.9"
NODES = {"cn1": ("02:00:00:ff:00:01", "172.16.0.1"), "cn2": ("02:00:00:ff:00:02", "172.16.0.2")}
# receive mappings of lab/overlay/cn2.conf
VNI_BLUE = 200
LABEL_RED2 = int(__import__("os").environ.get("MINIVR_LABEL_RED2", "1012"))
LABEL_RED3 = int(__import__("os").environ.get("MINIVR_LABEL_RED3", "1013"))
IPV4, ARP = 0x0800, 0x0806


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip_bytes(s):
    return socket.inet_aton(s)


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def ipv4(payload, proto, src, dst, ttl=64, flags_frag=0x4000, ihl=5, bad_csum=False, total=None):
    opts = b"\x01" * ((ihl - 5) * 4)
    hdr_len = ihl * 4
    total = hdr_len + len(payload) if total is None else total
    h = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, 0, flags_frag, ttl, proto, 0,
                    ip_bytes(src), ip_bytes(dst)) + opts
    c = csum(h)
    if bad_csum:
        c ^= 0xffff
    return h[:10] + struct.pack("!H", c) + h[12:] + payload


def udp(payload, dport, sport=51000, length=None):
    length = 8 + len(payload) if length is None else length
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def mpls(label, ttl=63, s=1):
    return struct.pack("!I", (label << 12) | (s << 8) | ttl)


def vxlan(vni, flags=0x08):
    return struct.pack("!II", flags << 24, vni << 8)


def inner_ip(dst, src="10.1.1.11", bad_csum=False):
    return ipv4(b"\x42" * 12, 17, src, dst, ttl=63, flags_frag=0, bad_csum=bad_csum)


def cases(target="cn2"):
    tmac, tip = NODES[target]
    other_ip = NODES["cn1" if target == "cn2" else "cn2"][1]

    def outer(l4, proto=17, dst_ip=tip, **kw):
        return eth(tmac, INJ_MAC, IPV4, ipv4(l4, proto, INJ_IP, dst_ip, **kw))

    def tunnel(dport, payload, **kw):
        return outer(udp(payload, dport, **kw))

    good_inner = inner_ip("10.1.1.12")
    vx_eth = lambda dst=tmac, et=IPV4, ip=good_inner: mac(dst) + mac(INJ_MAC) + struct.pack("!H", et) + ip  # noqa: E731
    return [
        # (name, expected reason, what, frame)
        ("trunc_outer_ipv4", "truncated", "Ethernet + 10 bytes of IPv4",
         eth(tmac, INJ_MAC, IPV4, b"\x45" * 10)),
        ("outer_ip_options", "ip_options", "outer IPv4 with IHL 6",
         eth(tmac, INJ_MAC, IPV4, ipv4(udp(b"x" * 8, 4789), 17, INJ_IP, tip, ihl=6))),
        ("outer_ip_fragment", "ip_fragment", "outer IPv4 with MF set",
         outer(udp(b"x" * 8, 4789), flags_frag=0x2000)),
        ("bad_outer_ip_checksum", "bad_ip_checksum", "outer IPv4 checksum wrong",
         outer(udp(mpls(LABEL_RED2) + good_inner, 6635), bad_csum=True)),
        ("trunc_outer_udp", "bad_udp", "IP payload shorter than a UDP header", outer(b"\x00" * 4)),
        ("udp_length_too_big", "bad_udp", "UDP length larger than the IP payload",
         tunnel(6635, mpls(LABEL_RED2) + good_inner, length=500)),
        ("trunc_mpls", "bad_mpls", "MPLS stack entry cut to 2 bytes", tunnel(6635, b"\x00\x3f")),
        ("mpls_s0", "bad_mpls", "MPLS bottom-of-stack bit clear",
         tunnel(6635, mpls(LABEL_RED2, s=0) + good_inner)),
        ("trunc_vxlan", "bad_vxlan", "VXLAN header cut to 5 bytes", tunnel(4789, b"\x08\x00\x00\x00\x00")),
        ("vxlan_no_i_flag", "bad_vxlan", "VXLAN header without the I flag",
         tunnel(4789, vxlan(VNI_BLUE, flags=0) + vx_eth())),
        ("unknown_label", "unknown_tag", "MPLS label nobody maps", tunnel(6635, mpls(4000) + good_inner)),
        ("unknown_vni", "unknown_tag", "VXLAN VNI nobody maps", tunnel(4789, vxlan(777) + vx_eth())),
        ("not_for_us", "tunnel_not_for_us", "tunnel addressed to the other node's IP, sent to this MAC",
         outer(udp(mpls(LABEL_RED2) + good_inner, 6635), dst_ip=other_ip)),
        ("udp_port_9999", "underlay_unexpected", "UDP to port 9999", tunnel(9999, b"hello")),
        ("tcp_segment", "underlay_unexpected", "TCP", outer(b"\x00" * 20, proto=6)),
        ("ipv6_ethertype", "underlay_unexpected", "EtherType 0x86dd",
         eth(tmac, INJ_MAC, 0x86dd, b"\x60" + b"\x00" * 39)),
        ("inner_bad_checksum", "bad_ip_checksum", "valid MPLS, inner IPv4 checksum wrong",
         tunnel(6635, mpls(LABEL_RED2) + inner_ip("10.1.1.12", bad_csum=True))),
        ("vxlan_inner_wrong_dst_mac", "bad_inner_l2", "inner destination MAC is not the router MAC",
         tunnel(4789, vxlan(VNI_BLUE) + vx_eth(dst="02:00:00:00:00:99"))),
        ("vxlan_inner_arp", "bad_inner_l2", "inner EtherType ARP",
         tunnel(4789, vxlan(VNI_BLUE) + vx_eth(et=ARP, ip=b"\x00" * 28))),
        # US3-3: a tag of one tenant must never reach a VM of another
        ("mpls_label_of_another_port", "decap_no_local_dest",
         "red3's label carrying red2's address (per-interface binding)",
         tunnel(6635, mpls(LABEL_RED3) + inner_ip("10.1.1.12"))),
        ("blue_vni_with_red_only_destination", "decap_no_local_dest",
         "blue VNI carrying 10.1.2.13, an address only red has",
         tunnel(4789, vxlan(VNI_BLUE) + vx_eth(ip=inner_ip("10.1.2.13")))),
        ("mpls_unbound_destination", "decap_no_local_dest", "red2's label, destination nobody has",
         tunnel(6635, mpls(LABEL_RED2) + inner_ip("10.1.1.99"))),
    ]


def open_sock():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("i0", 0))
    return s


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["list", "send", "serve"])
    p.add_argument("name", nargs="?")
    p.add_argument("--target", default="cn2", choices=sorted(NODES))
    a = p.parse_args(argv)
    table = {n: (r, w, f) for n, r, w, f in cases(a.target)}
    if a.mode == "list":
        print(json.dumps([{"name": n, "reason": r, "what": w, "bytes": len(f)} for n, (r, w, f) in table.items()]))
        return 0
    s = open_sock()
    if a.mode == "send":
        s.send(table[a.name][2])
        return 0
    print("READY", flush=True)
    for line in sys.stdin:
        name = line.strip()
        if not name:
            continue
        s.send(table[name][2])
        print("DONE " + name, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
