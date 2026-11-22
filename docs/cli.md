# `vrctl` reference

`vrctl` sends one command to a running `minivrd` over its control socket and prints the result.
The same command grammar, one command per line, is the start-up config file format (`#` starts
a comment).

```
vrctl [-s <socket>] [-j] <command> [args...]
```

| Option | Default | Meaning |
|---|---|---|
| `-s <socket>` | `/run/minivr/minivr.sock`, overridden by `$MINIVR_SOCK` | control socket path |
| `-j` | off | print the raw JSON response instead of a table |

In the lab the socket is `/run/mvr-cn1/minivr.sock`: `export MINIVR_SOCK=/run/mvr-cn1/minivr.sock`.
The socket is mode `0600`, so run `vrctl` as the user that started the forwarder, or as root.

On every invocation `vrctl` first asks the server for its `version` and refuses to continue
(exit 3) if the protocol number is not 1.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the forwarder rejected the command (`error.code: message` on stderr) |
| 2 | usage error detected locally (unknown command, missing argument) |
| 3 | forwarder unreachable: socket missing, connection refused, permission denied, protocol mismatch |

## Commands

Address syntax: IPv4 dotted quad; prefix `a.b.c.d/len` (host bits must be zero); MAC `xx:xx:xx:xx:xx:xx`.

| Command | Where | Effect |
|---|---|---|
| `port add <name> ifname <if> ip <a.b.c.d/len> [vrf <vrf>]` | config only | create a VM port and its connected route in the VRF (default `default`); at most 16 VM ports |
| `icmp-ratelimit rate <1..100000> burst <1..10000>` | config, CLI | ICMP error limiter applied to every port (defaults 100 / 20) |
| `port show` | CLI | name, ifname, role, vrf, mac, ip/len, mtu, admin, oper, rx/tx packets and bytes, drops |
| `port set <name> admin up\|down` | CLI | change admin state; going down releases held packets |
| `port set <name> vrf <vrf>` | CLI | move a VM port to another VRF (see "VRFs") |
| `route show [vrf <vrf>] [offset <n>] [limit <n>]` | CLI | vrf, prefix, port, gateway, origin (+ node/encap/tag for remote routes), in prefix order; paged (default 500 per page) |
| `route add <prefix> [vrf <vrf>] dev <port> [via <gw>]` | config, CLI | add a static route in the VRF (default `default`); `dev` must be in that VRF; `gw` must be inside the egress port's subnet |
| `route del <prefix> [vrf <vrf>]` | CLI | delete a static or remote route; `connected` and `host` routes are `immutable` |
| `route lookup <ip> [vrf <vrf>]` | CLI | the route the longest-prefix match selects in that VRF |
| `neigh show [vrf <vrf> \| underlay] [offset <n>] [limit <n>]` | CLI | vrf, ip, mac, port, kind (`static`/`learned`), state, held packets; all tables unless one is named; paged like `route show` |
| `neigh add <ip> lladdr <mac> dev <port>` | config, CLI | static neighbour; also installs the `/32` host route and binds the port to that VM (anti-spoofing) |
| `neigh del <ip> [vrf <vrf>]` | CLI | delete a neighbour (and its host route and binding) from that VRF's table |
| `stats show` | CLI | per-port counters, every drop reason (30), event counters, per-node tunnel counters, mbuf gauge |
| `stats clear` | CLI | zero all counters (gauges are untouched) |
| `version` | CLI | protocol, version, build type, uptime |
| `debug crash` | CLI, debug builds | deliberate NULL dereference, for the crash drill |

### VRFs, the underlay and tunnels (phase 2)

| Command | Where | Effect |
|---|---|---|
| `vrf add <name> id <1-63>` | config, CLI | create a VRF; name 1..15 of `[a-z0-9_-]`; at most 64 including `default` (id 0) |
| `vrf del <name>` | CLI | delete; `busy` while a port, route (other than a port's own connected/host routes), label or VNI references it; `default` is `immutable` |
| `vrf show` | CLI | per VRF: name, id, ports, route / neighbour / label / VNI counts |
| `underlay add <name> ifname <if> ip <a.b.c.d/len>` | config only | the one underlay port (`exists` if there is already one); its MAC is this node's router MAC |
| `node add <name> ip <a.b.c.d> [rmac <mac>]` | config, CLI | a remote compute node; its address must be inside the underlay subnet (`bad-prefix`); `no-underlay` before `underlay add`; at most 64 |
| `node set <name> rmac <mac>` | CLI | set or replace the node's router MAC (needed for VXLAN routes) |
| `node del <name>` | CLI | delete; `busy` while a route uses it |
| `node show` | CLI | name, ip, rmac, underlay MAC and resolution state, encap/decap packets and bytes per encapsulation |
| `route add <prefix> vrf <vrf> node <n> encap mplsoudp label <16..1048575>` | config, CLI | remote route: send through the node as MPLS over UDP (port 6635) with that label |
| `route add <prefix> vrf <vrf> node <n> encap vxlan vni <1..16777215>` | config, CLI | remote route as L3 VXLAN (port 4789); the node must have an `rmac` |
| `route replace <prefix> [vrf <vrf>] ...` | CLI | atomically replace a static or remote route (same forms as `add`); the next packet sees the new next hop |
| `label add <label> port <port>` | config, CLI | receive mapping: an MPLS label delivers to one VM port (per-interface label) |
| `label del <label>` | CLI | remove a label mapping |
| `vni add <id> vrf <vrf>` | config, CLI | receive mapping: a VXLAN VNI delivers into one VRF |
| `vni del <id>` | CLI | remove a VNI mapping |
| `tunnel show` | CLI | `labels` (label, port, vrf), `vnis` (vni, vrf), `underlay` (port, ip, mac, mtu) |

**VRFs.** Everything in a phase 1 config lives in `default`; a phase 1 config file loads unchanged.
`port set <name> vrf <vrf>` flushes the port's learned neighbours and moves its static neighbour,
`/32` host route and connected route; it is refused with `busy` while a static route still names
the port and with `exists` if the new VRF already has the same static neighbour or a conflicting
prefix. A remote route's VRF, node and tag are checked when it is added (`unknown-vrf`,
`unknown-node`, `no-underlay`, `bad-syntax` for a tag out of range or a VXLAN route to a node
without `rmac`). The MPLS label of a remote route is the label the *receiving* node maps with
`label add`; the VNI is the one it maps with `vni add`.

A failed command never changes forwarder state.

**Paging.** A response is limited to 65,536 bytes, so `route show` and `neigh show` return at
most `limit` entries (default 500, at least 1) starting at `offset`, plus `total`, `offset` and
`next_offset` (`null` on the last page). In table mode `vrctl` follows `next_offset` itself and
prints everything; with `-j` you get one page and ask for the next with `offset <next_offset>`.
Any other response that would still exceed the limit is rejected with `bad-syntax` and the message
"use offset/limit".

## Error codes

| `error.code` | Meaning |
|---|---|
| `bad-syntax` | unknown command, wrong arguments, value out of range |
| `bad-prefix` | malformed prefix, length > 32, or host bits set |
| `bad-address` | malformed IPv4 address |
| `bad-mac` | malformed MAC address |
| `unknown-port` | no port with that name (or, for a route, not in that VRF) |
| `unknown-vrf` | no VRF with that name or id |
| `unknown-node` | no remote node with that name |
| `no-underlay` | no underlay port is configured yet |
| `immutable` | deleting a `connected` or `host` route, or the `default` VRF |
| `exists` | duplicate route / neighbour / VRF / node / label / VNI, a second underlay, or the port already has a static neighbour |
| `not-found` | no such route / neighbour |
| `table-full` | route table (10,000, shared by all VRFs), neighbour table (1,024), 64 VRFs / nodes / VNIs, or 1,024 labels full |
| `gw-not-connected` | route gateway outside the egress port's subnet |
| `config-only` | command only valid in the config file |
| `not-permitted` | peer uid is neither the launching user nor root |
| `busy` | more than 8 concurrent clients, or (`vrf del`, `node del`, `port set ... vrf`) the object is still in use |

## JSON shapes (`-j`)

Success is `{"ok": true, "data": {...}}`, failure is `{"ok": false, "error": {"code": ..., "message": ...}}`.
Mutating commands return `"data": {}`.

```json
{"ok": true, "data": {"total": 2, "offset": 0, "next_offset": null, "routes": [
  {"vrf": "default", "prefix": "10.0.1.0/24", "port": null, "gateway": null, "origin": "connected"},
  {"vrf": "default", "prefix": "10.0.9.0/24", "port": "p3", "gateway": "10.0.2.13", "origin": "static"}]}}

{"ok": true, "data": {"total": 1, "offset": 0, "next_offset": null, "routes": [
  {"vrf": "red", "prefix": "10.1.1.12/32", "port": null, "gateway": null, "origin": "remote",
   "node": "cn2", "encap": "mplsoudp", "tag": 1012}]}}

{"ok": true, "data": {"total": 1, "offset": 0, "next_offset": null, "neighbours": [
  {"vrf": "default", "ip": "10.0.2.13", "mac": "02:00:00:00:01:03", "port": "p3",
   "kind": "static", "state": "REACHABLE", "held": 0}]}}

{"ok": true, "data": {"ports": [
  {"name": "p1", "ifname": "p1", "role": "vm", "vrf": "default", "mac": "02:00:00:00:00:01",
   "ip": "10.0.1.1/24", "mtu": 1500,
   "admin": "up", "oper": "up", "rx_pkts": 10, "rx_bytes": 980,
   "tx_pkts": 10, "tx_bytes": 980, "drops": 0}]}}

{"ok": true, "data": {"ports": [{"name": "p1", "rx_pkts": 10, "rx_bytes": 980,
   "tx_pkts": 10, "tx_bytes": 980, "drops": 0}],
  "drops": {"total": 3, "reasons": {"no_route": 2, "source_spoofed": 1}},
  "events": {"icmp_ratelimited": 0, "neighbour_table_full": 0,
             "arp_replies_sent": 0, "icmp_sent": 0},
  "nodes": [{"name": "cn2", "encap": {"mplsoudp": {"pkts": 0, "bytes": 0}, "vxlan": {"pkts": 0, "bytes": 0}},
             "decap": {"mplsoudp": {"pkts": 0, "bytes": 0}, "vxlan": {"pkts": 0, "bytes": 0}}},
            {"name": "unknown", "encap": {...}, "decap": {...}}],
  "mbuf": {"total": 4096, "in_use": 0}}}

{"ok": true, "data": {"vrfs": [
  {"name": "red", "id": 1, "ports": ["red1"], "routes": 4, "neighbours": 1, "labels": 1, "vnis": 0}]}}

{"ok": true, "data": {"nodes": [
  {"name": "cn2", "ip": "172.16.0.2", "rmac": "02:00:00:ff:00:02",
   "underlay_mac": "02:00:00:ff:00:02", "state": "reachable",
   "encap": {"mplsoudp": {"pkts": 100, "bytes": 14000}, "vxlan": {"pkts": 0, "bytes": 0}},
   "decap": {"mplsoudp": {"pkts": 100, "bytes": 14000}, "vxlan": {"pkts": 0, "bytes": 0}}}]}}

{"ok": true, "data": {
  "labels": [{"label": 1012, "port": "red2", "vrf": "red"}], "vnis": [{"vni": 200, "vrf": "blue"}],
  "underlay": {"port": "u0", "ip": "172.16.0.2/24", "mac": "02:00:00:ff:00:02", "mtu": 1600}}}

{"ok": true, "data": {"protocol": 1, "version": "0.1.0", "build": "debug", "uptime_s": 12}}
```

Every one of the 30 drop reasons is always present in `reasons` (zero if unused; the example abbreviates it),
so `sum(reasons) == total` can be asserted. `mac` in `neigh show` is `null` while a neighbour is
still `INCOMPLETE`. `node.state` is `unresolved`, `resolving`, `reachable` or `failed` (the underlay
neighbour entry of the node); `nodes` in `stats show` ends with the pseudo-node `unknown`, which
collects tunnel packets from a source address that is no configured node. For the reasons see
`drop-reasons.md`.

## Human output

In a lab that only uses the `default` VRF the tables below are unchanged from phase 1. Once a
listing shows a tenant VRF, a remote route or the underlay, `vrctl` adds columns (`VRF` first,
`REMOTE` last for routes; `ROLE`/`VRF` for ports). `vrf show`, `node show` and `tunnel show` have
their own tables.

```
$ vrctl route show
PREFIX          PORT  GATEWAY     ORIGIN
10.0.1.0/24     -     -           connected
10.0.1.11/32    p1    -           host
10.0.2.0/24     p3    -           connected
10.0.9.0/24     p3    10.0.2.13   static
```
