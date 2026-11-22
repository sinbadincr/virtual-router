"""Capture and decode the underlay (SC-007): tcpdump on the bridge of mvr-ul, decoded with tshark
when it is installed, else with scapy (MPLS over UDP 6635 via bind_layers, VXLAN built in)."""
import os
import shutil
import signal
import subprocess
import tempfile
import time

from scapy.all import ARP, Ether, IP, UDP, bind_layers, rdpcap
from scapy.contrib.mpls import MPLS
from scapy.layers.vxlan import VXLAN

bind_layers(UDP, MPLS, dport=6635)

TENANT_PREFIX = "10.1."


class Capture:
    """`with Capture() as cap: ...` then cap.packets() (scapy packets with .time)."""

    def __init__(self, bpf=None, iface="br0", netns="mvr-ul", count=None):
        self.bpf, self.iface, self.netns, self.count = bpf, iface, netns, count
        fd, self.path = tempfile.mkstemp(suffix=".pcap", prefix="mvr-ul-")
        os.close(fd)
        os.chmod(self.path, 0o644)
        self._pkts = None

    def __enter__(self):
        cmd = ["ip", "netns", "exec", self.netns, "tcpdump", "-i", self.iface, "-nn", "-U", "--immediate-mode", "-s", "0",
               "-w", self.path]
        if self.count:  # bulk transfers: only the first packets are kept (the dump stays small)
            cmd += ["-c", str(self.count)]
        if self.bpf:
            cmd.append(self.bpf)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            line = self.proc.stderr.readline()
            if "listening" in line:
                break
            if self.proc.poll() is not None:
                raise RuntimeError("tcpdump exited: " + line)
        return self

    def __exit__(self, *exc):
        time.sleep(0.4)  # let the last frames reach the dump
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return False

    def packets(self):
        if self._pkts is None:
            self._pkts = list(rdpcap(self.path))
            os.unlink(self.path)
        return self._pkts


def decode(pkt):
    """Tunnel packets -> dict, anything else -> None.
    mplsoudp: label, ttl, s, inner (scapy IP); vxlan: vni, inner_eth (src, dst), inner (IP)."""
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
        return None
    ip, udp = pkt[IP], pkt[UDP]
    out = {"time": float(pkt.time), "src": ip.src, "dst": ip.dst, "sport": udp.sport,
           "df": bool(ip.flags.DF), "ttl_outer": ip.ttl, "eth_src": pkt[Ether].src,
           "eth_dst": pkt[Ether].dst}
    if udp.dport == 6635 and pkt.haslayer(MPLS):
        m = pkt[MPLS]
        inner = m.payload if isinstance(m.payload, IP) else IP(bytes(m.payload))
        out.update(kind="mplsoudp", label=m.label, ttl=m.ttl, s=m.s, inner=inner)
        return out
    if udp.dport == 4789 and pkt.haslayer(VXLAN):
        vx = pkt[VXLAN]
        eth = vx.payload if isinstance(vx.payload, Ether) else Ether(bytes(vx.payload))
        out.update(kind="vxlan", vni=vx.vni, inner_eth=(eth.src, eth.dst), inner=eth.payload)
        return out
    return None


def tunnel_packets(cap):
    return [d for d in (decode(p) for p in cap.packets()) if d]


def tenant_leaks(cap):
    """Frames whose outer IP addresses are tenant addresses: none may exist (SC-007)."""
    leaks = []
    for p in cap.packets():
        if p.haslayer(IP) and (p[IP].src.startswith(TENANT_PREFIX) or p[IP].dst.startswith(TENANT_PREFIX)):
            leaks.append(p.summary())
    return leaks


def undecoded_ip(cap):
    """IPv4 frames that are neither tunnel packets, IGMP, nor underlay ICMP echo between node addresses."""
    bad = []
    for p in cap.packets():
        if not p.haslayer(IP) or p.haslayer(ARP):
            continue
        if decode(p):
            continue
        if p[IP].proto == 1 and p[IP].src.startswith("172.16.") and p[IP].dst.startswith("172.16."):
            continue
        if p[IP].proto == 2:  # IGMP: the kernel bridge/ports announcing themselves, not tenant traffic
            continue
        bad.append(p.summary())
    return bad
