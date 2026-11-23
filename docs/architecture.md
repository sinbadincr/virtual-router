# minivr architecture (phases 1 and 2)

`minivrd` is a single-threaded, run-to-completion L3 forwarder. `vrctl` is its CLI. Everything
below describes what is built, not what is planned; see `specs/001-lab-l3-forwarder/` for the
requirements and decisions (R1 to R17).

## Processes and libraries

```
 vrctl ──(Unix socket, length-prefixed, JSON replies)──► minivrd
                                                          │
 libminivr_dp  = src/common + src/dp + src/ctl/{cmd,frame}.c   (linked by minivrd, vrctl, unit tests)
 minivrd only  = src/daemon + src/pio/pio_afpacket.c + src/ctl/{config,ctl_server}.c
```

`src/dp` makes **no syscalls**: no allocation, locks, blocking calls, I/O or unthrottled logging
(`scripts/check-fastpath.sh` enforces it in `make check`). All packet I/O goes through the
`pio_ops` table in `src/pio/pio.h`; time comes from `src/common/clock.h`. That is what lets
`tests/unit` run the whole forwarding pipeline against `pio_fake` and a fake clock, and it is the
seam a DPDK backend will use later.

## Event loop and file descriptors

One `epoll` loop (`src/daemon/evloop.c`) owns every fd, each wrapped in an `evsrc` with a callback:

| fd | Callback | Does |
|---|---|---|
| one AF_PACKET socket per port | `on_port` | `rx_burst` up to 32 frames, `forward_burst` |
| `signalfd` (SIGINT, SIGTERM, SIGHUP) | `on_signal` | TERM/INT: leave the loop; HUP: ignored with a log line |
| `timerfd`, 10 ms | `on_tick` | `neigh_tick` (ARP retries, resolution deadlines), idle control clients |
| rtnetlink `RTMGRP_LINK` | `linkmon` | `IFF_RUNNING` changes become `port.oper_up`; down releases held packets |
| control listener + up to 8 clients | `ctl_server` | frame, `SO_PEERCRED` check, `cmd_exec`, reply |

Control commands run on the same thread **between** packet bursts, so a route change is visible to
the very next packet and no data structure needs a lock.

Start-up order is fixed: parse config (opens the port sockets) -> rtnetlink -> control socket ->
create `/var/tmp/minivr` -> drop to `nobody` with zero capabilities and `no_new_privs`, then
verify it from `/proc/self/status` -> loop. A failure at any step exits non-zero before a single
packet is processed.

## Packet path (`src/dp/forward.c`)

```
epoll(port fd) -> pio.rx_burst(<=32 mbufs)
 for each mbuf:
   Ethernet classify ─ truncated / bcast-mcast non-ARP / not our MAC / not IPv4+ARP ──► drop(reason)
   kernel-stripped VLAN tag (PACKET_AUXDATA) ───────────────────────────────────────► drop(unsupported_ethertype)
   anti-spoof, if the port is bound to a VM ────────────────────────────────────────► drop(source_spoofed)
   ARP: validate; learn (unbound ports only); reply for own IP / known neighbour; else drop
   IPv4: validate (version, IHL, options, length, checksum, fragments) ─────────────► drop(reason)
         own address? echo request -> reply, else drop(local_unsupported)
         TTL <= 1 -> ICMP time exceeded (rate-limited) + drop(ttl_exceeded)
         LPM -> miss -> net unreachable;  multi-port subnet without /32 -> host unreachable
         egress down -> drop(port_down);  > MTU -> frag-needed if DF, drop(mtu_exceeded)
         TTL--, incremental checksum (RFC 1624)
         neighbour: REACHABLE -> rewrite MACs -> tx batch[egress]
                    unresolved -> hold (<=3) and ARP, or drop(neighbour_unresolved)
 flush tx batches per egress port (pio.tx_burst)
```

Every drop increments exactly one named counter (`docs/drop-reasons.md`), and
`total == sum(reasons)`.

## Data structures and who owns them

| Structure | Where | Size | Owner / mutated by |
|---|---|---|---|
| mbuf pool | `common/mbuf.c` | 4,096 x 2 KiB (128 B headroom), allocated once | main thread; LIFO free list |
| route table | `dp/route.c` + `dp/lpm_trie.c` | 10,000 routes; binary trie over a node pool | main thread |
| neighbour table | `dp/neigh.c` | open addressing, 2,048 slots, 1,024 entries | main thread |
| port table | `dp/port.c` | 16 ports; created at start-up only | main thread |
| counters | `dp/stats.c` | global + per-port | main thread |
| token buckets | `dp/ratelimit.c`, in `struct port` | one per ingress port | main thread |

Static neighbours give each VM port a **binding** (the source-binding check) and a `/32` host
route. Ports that share a subnet (the anycast gateway `10.0.1.1` on p1 and p2) have a connected
route with no egress, so they are reached only through those `/32` routes.

## mbuf lifecycle

1. `pio.rx_burst` allocates from the pool and fills `off/len`; on exhaustion it drains the socket
   and counts `nobuf`.
2. `forward_burst` owns every mbuf of the burst. Each one ends in exactly one place: freed by a
   drop, queued in a tx batch (the backend frees it after sending), consumed (ARP reply
   learned), or held by a neighbour entry.
3. A held mbuf (at most 3 per unresolved next hop) is released by ARP resolution (sent in
   order), by the 1 s deadline (dropped, ICMP host unreachable), by port down, or by neighbour
   or gateway-route deletion. The unit tests assert that `mbuf_in_use` returns to its baseline
   in every path, and the e2e suite asserts the same gauge after traffic.

## Why there is no RCU in phase 1

There is one thread, and the control plane runs on it between bursts, so readers and writers
never overlap. The tables are still reached through single owners (one route table, per-port
stats) so that phase 4, when forwarding moves to several cores, can add RCU-style table swaps
and per-core counters without changing the packet-path logic. The first performance work
planned for then (trie -> DIR-24-8) will be the first entry in `docs/perf.md`; phase 1 makes no
performance claims.

## Lab specifics that shape the code

- The kernel hands an AF_PACKET socket frames whose TCP/UDP checksum is still to be offloaded
  (`CHECKSUM_PARTIAL`) and GSO super-frames. Re-injected, such a frame carries a wrong checksum
  and the receiving VM drops it, so `lab/lab.sh` turns tx checksum, SG, TSO, GSO and GRO off on
  every veth end. A forwarder on a real NIC would instead complete the checksum itself.
- The kernel strips 802.1Q tags before a raw socket sees the frame; the backend asks for
  `PACKET_AUXDATA` to know it happened.

# Phase 2: VRFs and overlay tunnels

Phase 2 turns the single-table router into a multi-tenant one that reaches VMs on other compute
nodes through tunnels. The phase 1 pipeline above is unchanged for a lab that only uses the
`default` VRF. Decisions: `specs/003-vrf-overlay-tunnels/research.md` (R1 to R13).

## Tables

| Structure | Where | Size | Notes |
|---|---|---|---|
| VRF table | `dp/vrf.c` | 64 (`default` = id 0) | each VRF owns one root in the LPM pool |
| LPM node pool | `dp/lpm_trie.c` | 10,000 rules x 32 levels + 64 roots, allocated once | **one pool, one root per VRF**: memory stays at the phase 1 size and "10,000 routes" is a total across tenants |
| route array | `dp/route.c` | 10,000 | indexed by the trie value; entry = `(vrf, prefix, len)` + next hop `LOCAL {port, gateway}` or `REMOTE {node, encap, tag}` |
| neighbour table | `dp/neigh.c` | 2,048 slots, 1,024 entries | key `(table, ip)`; table = VRF id or `NEIGH_UNDERLAY` (255); the whole FSM (hold <= 3, retries, 1 s deadline) serves the underlay too |
| ports | `dp/port.c` | 16 VM + 1 underlay | `role`, `vrf`; a gateway address may repeat across VRFs |
| remote nodes | `dp/tunnel.c` | 64 | name, underlay IP, router MAC; counters in `g_stats.node[id]` (+ `unknown`) |
| label map | `dp/tunnel.c` | 1,024 in a 2,048-slot hash with tombstones | MPLS label -> one VM port |
| VNI map | `dp/tunnel.c` | 64, linear scan | VXLAN VNI -> one VRF |

Everything is a fixed array: nothing is allocated on the packet path and the tables are mutated
only by the single loop between bursts.

## Transmit path (`dp/encap.c`)

```
VM port ingress -> phase 1 checks -> LPM in port.vrf -> REMOTE {node, encap, tag}
   TTL <= 1 -> time exceeded                                   (as phase 1)
   underlay down -> port_down
   inner length + overhead (32 | 50) > underlay MTU
        -> DF: ICMP frag needed (MTU - overhead), drop(tunnel_mtu_exceeded)
   TTL-- once, flow hash over (src, dst, proto, ports)
   MPLSoUDP: drop the inner Ethernet header, prepend Eth|IPv4(DF,TTL 64,ID 0)|UDP 6635|label
   VXLAN   : inner Ethernet becomes (own router MAC -> remote router MAC), prepend Eth|IPv4|UDP 4789|VXLAN
        both in place in the 128-byte mbuf headroom: the inner packet is never copied
   UDP source port = 49152 + hash % 16384 (one flow, one underlay path), UDP checksum 0
   underlay neighbour of the node: REACHABLE -> tx on u0;  unresolved -> hold (the frame is already
   encapsulated, only its destination MAC is missing) and ARP; 1 s deadline -> neighbour_unresolved
   and ICMP host unreachable to the VM (the mbuf remembers the tenant's source MAC and where the
   inner header sits, so the error can still quote the original packet)
```

## Receive path (`dp/decap.c`)

```
underlay ingress -> Ethernet classify
   ARP   : only the underlay table; answers for the node's own address; learns configured nodes only
   IPv4  : phase 1 validation -> dst == own underlay IP (else tunnel_not_for_us)
           ICMP echo request -> reply;  other protocols -> underlay_unexpected
           UDP -> bad_udp | dport 4789 VXLAN | 6635 MPLS | else underlay_unexpected
   VXLAN : header (bad_vxlan) -> VNI -> VRF (unknown_tag) -> inner Ethernet (bad_inner_l2)
           -> inner IPv4 validation -> route in that VRF must be a host/connected route to a VM port
              with a known neighbour (else decap_no_local_dest) -> rewrite MACs -> tx on the VM port
   MPLS  : entry (bad_mpls) -> label -> port (unknown_tag) -> inner IPv4 validation
           -> inner destination must equal the address bound to that port (decap_no_local_dest)
   inner TTL is NOT decremented; per-source-node decap counters (unknown source -> `unknown`)
```

Nothing received on the underlay is ever forwarded back out (no transit, FR-015), and ARP on the
underlay never touches a tenant table (FR-010).

## Why per-interface labels, and why the router MAC

Tungsten Fabric's vRouter allocates one MPLS label per VM interface: the label alone says which
interface gets the packet, so the receiver needs no route lookup and a label can never deliver
to a VM of the wrong tenant (the binding check also requires the inner destination to be that
interface's address). The price is one `/32` remote route per remote VM on the sender, which is
what a controller programs (phase 3). VXLAN is used the way EVPN uses it for symmetric routing:
the VNI names the VRF and the inner Ethernet header carries the *router* MAC of the next hop,
because there is no L2 segment to learn from. The router MAC of a node is its underlay port's MAC,
so there is no extra address to invent and the Linux kernel's VXLAN device interoperates with a
static FDB and permanent neighbour entries (`lab/overlay/interop.sh`).

## Phase 3: three processes and the control network

```
 mvr-ctl           mvr-cnN (one per compute node)
 minivr-ctld ──TCP── minivr-agent ──unix socket (+SCM_RIGHTS)── minivrd ── guests
 (intent, bindings,   (want/pending/have,                        (forwarding; unchanged
  compute, state)      reconcile, plug)                           apart from owner and ports)
```

- **`minivrd` is still the only thing on the packet path.** It gained an `owner` on every entry
  (`config` file, `cli`, `agent`), a connection *role* (`session agent`) and runtime ports: the
  agent opens the AF_PACKET socket and passes it over the control socket, so the forwarder keeps
  zero capabilities (`docs/agent.md`). `port del` removes a port with its connected/host routes,
  neighbours (held packets counted as `port_deleted`) and labels, between bursts, like every change.
- **Two libraries**: `libminivr_dp` (syscall-free forwarding) and `libminivr_ctrl` (syscall-free
  protocol codec, node-state sets, controller model/compute/grammar, agent reconcile); the I/O around
  them (`session.c`, `store.c`, `fwd.c`, `main.c`) is thin. `scripts/check-fastpath.sh` audits both.
- **Control network** (`mvr-ctl`) is separate from the underlay so control traffic never races the
  forwarder's ownership of `u0`; see `docs/lab.md`.
- Design notes: [protocol](protocol.md), [controller](controller.md), [agent](agent.md).
