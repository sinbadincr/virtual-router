# Overlay: VRFs and tunnels (phase 2)

Two compute nodes (`cn1`, `cn2`, one `minivrd` each) carry traffic of two tenants, **red** and
**blue**, between VMs on different nodes. The tenants reuse the same addresses (`10.1.1.11`,
`10.1.1.12`) and never see each other. Red travels as **MPLS over UDP** (RFC 7510) with one label
per VM interface, blue as **L3 VXLAN** (RFC 7348) with one VNI per tenant, the same two
encapsulations Tungsten Fabric uses. The lab is [lab.md](lab.md#the-overlay-lab-phase-2); the
code is `src/dp/encap.c` and `src/dp/decap.c`; the decisions are in
`specs/003-vrf-overlay-tunnels/research.md`.

```
  red1 10.1.1.11 ─┐                                                   ┌─ red2 10.1.1.12
  blue1 10.1.1.11 ┘ cn1 (u0 172.16.0.1) ══ underlay br0 (MTU 1600) ══ cn2 (u0 172.16.0.2) ┘─ red3 10.1.2.13
                                                                                           └─ blue2 10.1.1.12
```

## Packet walk: red1 to red2 (MPLSoUDP)

`red1` (10.1.1.11) pings 10.1.1.12. Everything below was captured on the underlay bridge
(`ip netns exec mvr-ul tcpdump -i br0`) of the harness lab and decoded with scapy.

1. **ARP.** `10.1.1.12` is on red1's own subnet, so red1 ARPs for it. `minivrd` on cn1 answers
   with the port's MAC: a `/32` **remote route** for that address exists in VRF red (proxy ARP for
   VMs that live elsewhere; a wider remote prefix, or an address with no route, is not answered).
2. **Route.** The ICMP echo reaches cn1 on port `red1`, passes the phase 1 checks (anti-spoofing,
   IPv4 validation, TTL) and is looked up in the LPM root of VRF red. The hit is
   `REMOTE {node cn2, mplsoudp, label 1012}`.
3. **Size and TTL.** 84 bytes + 32 of overhead fits the 1600-byte underlay MTU; the inner TTL is
   decremented once (64 to 63).
4. **Encapsulation**, in place in the mbuf headroom. The 14-byte inner Ethernet header is replaced
   by the outer headers; the inner IPv4 packet is not copied:

```
 outer Eth  02:00:00:ff:00:02 <- 02:00:00:ff:00:01   type 0x0800        14   cn2's underlay MAC (resolved by ARP on the underlay)
 outer IPv4 172.16.0.1 -> 172.16.0.2  proto 17  ttl 64  DF  id 0       20   checksum computed
 UDP        54983 -> 6635   length 96   checksum 0                       8   source port = 49152 + flow hash % 16384
 MPLS       label 1012  tc 0  s 1  ttl 63                               4   one label, bottom of stack
 inner IPv4 10.1.1.11 -> 10.1.1.12  proto 1 (ICMP)  ttl 63   (84 bytes)
                                                              total frame 130 bytes = 98 + 32
 hex: 02 00 00 ff 00 02 02 00 00 ff 00 01 08 00 45 00 00 74 00 00 40 00 40 11 e2 55 ac 10 00 01
      ac 10 00 02 d6 c7 19 eb 00 60 00 00 | 00 3f 41 3f | 45 00 00 54 07 89 40 00 3f 01 1e 08 0a 01 01 0b ...
```

5. **Receive on cn2** (`decap.c`): Ethernet to our MAC, outer IPv4 valid and addressed to
   172.16.0.2, UDP port 6635, MPLS entry valid (S = 1), **label 1012 maps to port `red2`**. The
   inner IPv4 is validated with the phase 1 rules; its destination must be the address bound to
   `red2` (10.1.1.12). The Ethernet header is rebuilt (dst = red2's MAC, src = the port's MAC),
   the inner TTL is **not** decremented, and the frame goes out on `red2`. red2's reply takes the
   mirror path with label 1011, which is why the ping shows `ttl=63`: one routed hop.

Any failure on the way lands in one named reason (`bad_mpls`, `unknown_tag`, `decap_no_local_dest`,
...): [drop-reasons.md](drop-reasons.md).

## Packet walk: blue1 to blue2 (L3 VXLAN)

Blue's route for 10.1.1.12 is `REMOTE {node cn2, vxlan, VNI 200}`. A VXLAN packet needs an inner
Ethernet header but there is no L2 segment to learn a MAC from, so the sender writes the **router
MAC** of the next hop: its own underlay port MAC as source, the remote node's router MAC
(configured with `node add cn2 ip ... rmac ...`) as destination. The inner Ethernet header of the
VM frame is rewritten in place and the outer headers are prepended:

```
 outer Eth  02:00:00:ff:00:02 <- 02:00:00:ff:00:01   type 0x0800        14
 outer IPv4 172.16.0.1 -> 172.16.0.2  proto 17  ttl 64  DF  id 0       20
 UDP        54983 -> 4789   length 114  checksum 0                       8
 VXLAN      flags 0x08 (I)  VNI 200                                     8
 inner Eth  02:00:00:ff:00:02 <- 02:00:00:ff:00:01   type 0x0800        14   router MACs, not VM MACs
 inner IPv4 10.1.1.11 -> 10.1.1.12  proto 1  ttl 63   (84 bytes)
                                                              total frame 148 bytes = 98 + 50
 hex: 02 00 00 ff 00 02 02 00 00 ff 00 01 08 00 45 00 00 86 00 00 40 00 40 11 e2 43 ac 10 00 01
      ac 10 00 02 d6 c7 12 b5 00 72 00 00 | 08 00 00 00 00 00 c8 00 | 02 00 00 ff 00 02 02 00 00 ff 00 01 08 00 ...
```

On cn2 the VNI selects **VRF blue** (`vni add 200 vrf blue`), the inner destination MAC must equal
cn2's own router MAC, and the inner destination must be a VM of blue on this node (a host route
with a known neighbour): a blue VNI carrying an address that only exists in red is dropped as
`decap_no_local_dest`, and nothing received on the underlay is ever forwarded back out.

## Overhead and MTU

| | Outer IPv4 | UDP | tag | inner Ethernet | total |
|---|---|---|---|---|---|
| MPLSoUDP | 20 | 8 | 4 (label) | none (replaced) | **32** |
| VXLAN | 20 | 8 | 8 (VXLAN) | 14 | **50** |

The lab underlay MTU is **1600**: a 1500-byte VM packet plus the largest overhead (1550) fits with
room to spare, so a bulk TCP transfer never stalls on size (SC-011). The forwarder never
fragments: if `inner length + overhead` exceeds the underlay MTU, a DF packet gets ICMP type 3
code 4 with `MTU = underlay MTU - overhead` (1468 for MPLSoUDP, 1450 for VXLAN when the underlay is
1500), a non-DF packet is dropped silently, both counted as `tunnel_mtu_exceeded`
(`tests/e2e_overlay/test_underlay_corpus.py::test_o11_*`).

## Compared with Tungsten Fabric's vRouter

| | minivr | Tungsten Fabric |
|---|---|---|
| MPLS label | one per VM **interface**, mapped to a port | one per VM interface, in the vRouter's label table |
| Remote routes | static `/32` per remote VM (`route add ... node ... label`) | pushed by the controller over XMPP as each VM appears |
| VXLAN | L3 only: VNI = VRF, inner dst MAC = remote router MAC | VXLAN with an L2 (bridge) VRF as well as L3 |
| Delivery check | label -> port **and** inner destination must be that port's bound address; VNI -> VRF and a local host route | label -> next hop in the label table |
| Underlay MTU | 1600 so 1500-byte guests never fragment | operators raise the fabric MTU or lower the guest MTU |
| Missing in minivr | no controller (phase 3), no BGP EVPN (phase 5), no ECMP, no encryption | |

## Compared with the Linux kernel

The kernel can do the same with a VRF and a VXLAN device. `lab/overlay/interop.sh` builds exactly
that in `mvr-ix` (172.16.0.3) as an *independent* implementation: VRF `blue`, `vx200` (VNI 200,
`nolearning`, fixed MAC `02:00:00:ff:00:03`), a dummy `10.1.3.33/32`, and, per compute node, one
transit next hop with a **permanent neighbour** carrying the node's router MAC plus a static FDB
entry for its VTEP. That is the kernel's way of saying "this is the L3 VXLAN peer's router MAC",
and it matches what minivr puts on the wire: the blue VMs ping the kernel endpoint and move 100 MB
through it with identical digests (`tests/e2e_overlay/test_interop.py`). Differences worth knowing:
the kernel learns inner MACs unless told not to (`nolearning`), computes a UDP checksum where
minivr sends 0 (both are legal for IPv4), and replies with TTL 64 because it originates the reply
(the ping from blue1 to `10.1.3.33` therefore shows `ttl=64` while a VM-to-VM ping shows `63`).
