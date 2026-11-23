# The controller (`minivr-ctld`)

One process, one `epoll` loop, no threads, no locks (constitution II applies to the tools around
the packet path too: the controller is simple enough to reason about line by line). It holds the
operator's **intent**, the nodes' reported **bindings**, allocates MPLS labels, computes what every
node must look like and pushes it over the [protocol](protocol.md).

## What it knows (`include/minivr/ctl_model.h`, `src/controller/model.c`)

| Layer | Content | Who writes it |
|---|---|---|
| Intent | tenants (name, id, VNI, encap), subnets (prefix, gateway), allowed nodes, VM interfaces (VMI: name, tenant, IP, MAC) | the operator: intent file, state file, `vrctl` |
| Bindings | which VMI sits on which node/port, with its label | the nodes, through their agents (`plug`/`unplug`) |
| Allocations | per node labels 1000–1999, lowest free first, plus **quarantine** | the controller |

A VMI that is defined but not bound exists nowhere: no VRF, no route, no label on any node.

## compute-then-diff (`src/controller/compute.c`)

`cm_compute(model, node)` is one pure function from the model to the entry set of a node:
VRF, VNI and the PORT/NEIGH/LABEL of every local VMI, plus NODE and `/32` ROUTE entries for the VMIs
of the same tenants on *other* nodes (never for a VMI on the node itself, never for a tenant that is
not present). After **every** change the controller recomputes each connected node and sends
`diff(last sent, new)`. Why not hand-write an update per event: events are where control planes
accumulate bugs (a missed "move" case, a forgotten label). With one function, correctness is a
property test (`tests/unit/test_compute.c`: isolation, locality, determinism) and a node that
missed an update is repaired by recomputing, not by replaying.

## Labels and quarantine (`src/controller/alloc.c`)

A VMI keeps its label for as long as it stays on the same node, across restarts of anything. An
unbind or a move puts the label in **quarantine** on that node: it is never handed out again until
the node ACKs the update that deleted the mapping (or its next full sync), because a label reused
while a frame with the old meaning is still in flight would deliver a packet to the wrong VM.

## State file and crash safety (`src/controller/store.c`)

The state file uses the same grammar as the CLI plus three state-only lines (`bind`, `quarantine`,
`learned`). It is rewritten as temp file + `fsync` + `rename` + `fsync` of the directory, **before**
the updates it justifies are sent. A missing, empty or unparsable state file is a start-up error
with a line number, never "start empty": silently forgetting every label would renumber the fabric.
`learned` keeps each node's underlay address so that a controller restart does not withdraw routes
to nodes that have not yet reconnected.

## Sessions (`src/controller/session.c`)

```
accepted → HELLO_WAIT → BINDING → SYNCING ⇄ IN_SYNC / OUT_OF_SYNC → closed
```

`HELLO` is checked (unknown node, a second live session for the same node, version) → `HELLO_ACK`
(3 s keepalive, 9 s hold) → the agent's `BIND` list replaces that node's bindings → `BIND_END` →
`SYNC_BEGIN`, `UPDATE`s as large as 64 KiB allows, `SYNC_END`. A node is *in sync* when everything it
was sent is ACKed without errors; forwarder refusals come back as `ERROR(entry-rejected)` and are
shown by `node show`. A peer that stops reading (send buffer over 1 MiB) is closed as `slow-peer`.
Every protocol error has its own counter (`stats show`).

## Operating it

```
minivr-ctld --state build/lab/ctl/state.conf --init lab/ctl/intent.conf
vrctl -s /run/mvr-ctl/ctld.sock tenant show | vmi show | node show | node state cn1 | stats show
```

Start-up order is fixed: state → TCP listener → control socket → drop privileges (to the invoking
user in the lab, `nobody` by default; zero capabilities, `no_new_privs`, self-verified) → loop.

## Compared with the Tungsten Fabric control node

| | TF control node | `minivr-ctld` |
|---|---|---|
| Config source | Neutron / config API via IF-MAP | the operator's intent file and CLI |
| Node protocol | XMPP (XML over TCP) | binary TLV over TCP |
| Between controllers | BGP (EVPN, L3VPN) | none (single controller) |
| Port binding | nova-compute → vrouter agent port IPC | `plug`/`unplug` on the agent, reported as `BIND` |
| State pushed | routes, as XMPP publications | the whole node state as keyed entries, diffed |

The mapping is the learning goal: VMI = TF virtual-machine-interface, tenant = virtual network
plus routing instance, node state = what the agent programs into the vrouter.
