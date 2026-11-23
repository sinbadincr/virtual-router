# Drop reasons

31 reasons: the 21 of phase 1 below, the 9 tunnel reasons of phase 2 and `port_deleted` of phase 3.

Every packet `minivrd` discards increments exactly one named reason counter, and
`total == sum(reasons)` always holds (`vrctl -j stats show`, `.data.drops`). The counter is
also added to the **ingress** port's `drops`. Counters are cleared by `vrctl stats clear`.

"ICMP" is the error sent back to the sender; it is rate-limited per ingress port (default
100/s, burst 20) and a rate-limited error counts as `events.icmp_ratelimited`, not as a drop.
No ICMP error is ever sent in reply to an ICMP error or to a source of `0.0.0.0`, loopback or
multicast.

Checks run in this order: Ethernet → anti-spoofing → ARP / IPv4 validation → local delivery →
TTL → route → egress state → MTU → neighbour. The first failing check names the reason.

| Reason | Trigger | ICMP sent | Covered by |
|---|---|---|---|
| `truncated` | frame shorter than the headers it claims (Ethernet < 14, IPv4 < 20, echo < 8) | none | `test_pkt_eth_ipv4` (every boundary), `test_forward`, `corpus.py` |
| `bad_ip_version` | IPv4 version ≠ 4 | none | `test_pkt_eth_ipv4`, `corpus.py` |
| `bad_ip_hdr_len` | IHL < 5, or header longer than the frame | none | `test_pkt_eth_ipv4`, `corpus.py` |
| `ip_options` | IHL > 5 (options unsupported) | none | `test_pkt_eth_ipv4`, `corpus.py` |
| `bad_ip_total_len` | total length < header length or > frame | none | `test_pkt_eth_ipv4`, `corpus.py` |
| `bad_ip_checksum` | header checksum wrong | none | `test_pkt_eth_ipv4`, `corpus.py` |
| `ip_fragment` | MF set or fragment offset ≠ 0 | none | `test_pkt_eth_ipv4`, `corpus.py` |
| `unsupported_ethertype` | IPv6, VLAN, anything that is not IPv4 or ARP | none | `test_pkt_eth_ipv4`, `test_forward`, `corpus.py` |
| `non_arp_bcast_mcast` | broadcast or multicast destination MAC that is not ARP | none | `test_pkt_eth_ipv4`, `test_forward`, `corpus.py` |
| `not_for_us_l2` | unicast destination MAC ≠ the ingress port's MAC | none | `test_pkt_eth_ipv4`, `test_forward`, `corpus.py` |
| `bad_arp` | malformed ARP: htype ≠ 1, ptype ≠ 0x0800, hlen ≠ 6, plen ≠ 4, op ∉ {1, 2}, or short | none | `test_pkt_arp`, `corpus.py` |
| `arp_unknown_target` | ARP request for an IP that is neither the port's gateway nor a known neighbour | none | `test_forward`, `test_forwarding.py::v3` |
| `source_spoofed` | on a bound port: Ethernet src MAC, ARP sender MAC/IP or IPv4 src IP ≠ the bound VM (includes using the gateway IP as a source) | none | `test_antispoof`, `test_forward`, `test_forwarding.py::v12` |
| `no_route` | no matching route (ICMP net unreachable), or a multi-port subnet with no `/32` for the host (host unreachable) | type 3 code 0 / code 1 | `test_forward`, `test_forwarding.py::v5` |
| `ttl_exceeded` | TTL ≤ 1 on a packet that must be forwarded | type 11 code 0 | `test_forward`, `test_forwarding.py::v6` |
| `mtu_exceeded` | IP length > egress MTU (never fragmented) | type 3 code 4 with the MTU, only if DF is set | `test_forward` |
| `neighbour_unresolved` | hold queue full (3), entry `FAILED`, or the 1 s resolution deadline passed (held packets) | type 3 code 1 when an entry fails; none when the hold queue is full | `test_neigh`, `test_forwarding.py::v16` |
| `port_deleted` | the port was deleted (runtime `port del`) while packets were held on its neighbours | none | `test_owner::port_del_cascades`, `test_stats` |
| `port_down` | egress port admin- or oper-down, or its port went down while packets were held | none | `test_forward`, `test_neigh`, `test_robustness.py` |
| `local_unsupported` | addressed to a forwarder address and not an ICMP echo request | none | `test_forward` |
| `nobuf` | mbuf pool (4,096) exhausted on receive | none | AF_PACKET backend; drained so the socket cannot stay readable |
| `tx_error` | the kernel refused a transmit | none | AF_PACKET backend |

### Tunnel reasons (phase 2)

Reasons 22 to 30. They come from the underlay port (`src/dp/decap.c`) and from the tunnel transmit
path (`src/dp/encap.c`). On the underlay the order is: Ethernet (phase 1 reasons) -> outer IPv4
(phase 1 reasons) -> outer destination -> protocol -> UDP -> tunnel header -> tag lookup -> inner
headers -> delivery. "Unit" is `tests/unit/test_decap.c` / `test_encap.c`; "corpus" is the case name
in `tests/e2e_overlay/underlay_corpus.py`, run by `test_underlay_corpus.py`.

| Reason | Trigger | ICMP sent | Wire example (outer headers elided) | Unit | Corpus case |
|---|---|---|---|---|---|
| `tunnel_not_for_us` | valid outer IPv4 whose destination is not this node's underlay address | none | tunnel to `172.16.0.1` delivered to cn2's MAC | `outer_destination_other_than_our_underlay_ip_is_not_for_us` | `not_for_us` |
| `underlay_unexpected` | underlay frame that is not ARP, ICMP echo to the node, or UDP 4789 / 6635: other EtherType (IPv6 ...), TCP, GRE, UDP to another port, an ICMP that is not an echo request | none | `UDP dport 9999`, EtherType `0x86dd` | `unexpected_underlay_traffic_is_counted_not_delivered` | `udp_port_9999`, `tcp_segment`, `ipv6_ethertype` |
| `bad_udp` | UDP header cut short, UDP length < 8 or larger than the IP payload | none | UDP length 500 in a 36-byte payload | `malformed_udp_and_tunnel_headers_have_their_own_reasons`, `test_pkt_udp` | `trunc_outer_udp`, `udp_length_too_big` |
| `bad_vxlan` | VXLAN header < 8 bytes or I flag (`0x08`) clear; reserved bits are ignored (RFC 7348) | none | flags byte `0x00` | same, `test_pkt_vxlan` | `trunc_vxlan`, `vxlan_no_i_flag` |
| `bad_mpls` | MPLS stack entry < 4 bytes, or bottom-of-stack bit clear (one label only, RFC 7510) | none | label word `0x003f403f` (S = 0) | same, `test_pkt_mpls` | `trunc_mpls`, `mpls_s0` |
| `bad_inner_l2` | VXLAN inner Ethernet < 14 bytes, destination not this node's router MAC, or EtherType not IPv4 | none | inner EtherType `0x0806` | `bad_inner_ethernet_in_vxlan` | `vxlan_inner_wrong_dst_mac`, `vxlan_inner_arp` |
| `unknown_tag` | MPLS label or VXLAN VNI with no receive mapping | none | label 4000, VNI 777 | `unmapped_label_and_vni_are_unknown_tag` | `unknown_label`, `unknown_vni` |
| `decap_no_local_dest` | the inner packet is not for a local VM of the mapped tenant: MPLS inner destination is not the address bound to the label's port; VXLAN destination has no host route / connected-subnet neighbour in the VNI's VRF, or the route is remote, via a gateway or egress-less (never transit) | none | red3's label carrying red2's address; blue VNI carrying a red-only address | `mpls_with_another_inner_destination_is_decap_no_local_dest`, `vxlan_never_transits_to_a_remote_or_absent_destination`, the US3 cases | `mpls_label_of_another_port`, `blue_vni_with_red_only_destination`, `mpls_unbound_destination` |
| `tunnel_mtu_exceeded` | inner IPv4 length + overhead (32 MPLSoUDP / 50 VXLAN) > underlay MTU; never fragmented | type 3 code 4 with MTU = underlay MTU - overhead, only if DF is set | 1500-byte DF packet, underlay MTU 1500: "mtu = 1468" | `size_rule_*` in `test_encap` | e2e `test_o11_*` |

Inner IPv4 faults on the underlay use the phase 1 reasons (`bad_ip_checksum`, `bad_ip_version`,
`truncated` ...): corpus cases `inner_bad_checksum`, `trunc_outer_ipv4`, `outer_ip_options`,
`outer_ip_fragment`, `bad_outer_ip_checksum`. The tunnel path also reuses `port_down` (underlay or
egress VM port down), `no_route`/`ttl_exceeded` before encapsulation and `neighbour_unresolved`
(remote node never answered ARP; the source VM gets host unreachable).

Not drops: ARP replies and gratuitous ARP consumed by the forwarder, echo replies, and ICMP
errors the forwarder generates (`events.icmp_sent`, `events.arp_replies_sent`).
