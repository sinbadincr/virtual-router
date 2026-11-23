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

## Demo (real output, namespace-VM lab)

Captured from `sudo make lab TOPO=ctl && sudo make lab-run` (harness variant; the KVM variant behaves
the same, the guests just take longer to boot). `vc` = `vrctl -s /run/mvr-ctl/ctld.sock`.

**1. After `lab-run`: two nodes in sync, five VMs bound, two defined but not yet plugged**

```
$ vc node show
NODE    UNDERLAY_IP    RMAC               SESSION     IN_SYNC  ENTR  SINCE   LAST_ERROR
cn1     172.16.0.1     02:00:00:ff:00:01  in-sync     yes      14    0       -
cn2     172.16.0.2     02:00:00:ff:00:02  in-sync     yes      16    0       -
cn3     -              -                  none        no       0     0       -
$ vc vmi show
VMI       TENANT  IP              MAC                STATE    NODE    PORT      LABEL
red1      red     10.1.1.11       02:00:00:01:01:11  bound    cn1     red1      1000
blue1     blue    10.1.1.11       02:00:00:02:01:11  bound    cn1     blue1     1001
red2      red     10.1.1.12       02:00:00:01:02:12  bound    cn2     red2      1000
red3      red     10.1.2.13       02:00:00:01:02:13  bound    cn2     red3      1001
blue2     blue    10.1.1.12       02:00:00:02:02:12  bound    cn2     blue2     1002
red4      red     10.1.1.14       02:00:00:01:03:14  unbound  -       -         -
red5      red     10.1.2.15       02:00:00:01:02:15  unbound  -       -         -
```

**2. A VM boots: `lab.sh guest start red5` plugs it on cn2; cn1 learns the route within a second**

```
$ v1 route show vrf red                      # before
VRF       PREFIX          PORT  GATEWAY     ORIGIN    REMOTE  OWNER
red       10.1.1.0/24     red1  -           connected   agent
red       10.1.1.11/32    red1  -           host        agent
red       10.1.1.12/32    -     -           remote    cn2 mplsoudp 1000  agent
red       10.1.2.13/32    -     -           remote    cn2 mplsoudp 1001  agent
$ lab/lab.sh guest start red5
$ v1 route show vrf red                      # after: one new remote route, label 1003 allocated on cn2
red       10.1.2.15/32    -     -           remote    cn2 mplsoudp 1003  agent
$ ping -c2 10.1.2.15   (from red1)
2 packets transmitted, 2 received, 0% packet loss
```

**3. The controller stops; the agent goes headless, the forwarder keeps every route**

```
$ lab/lab.sh svc stop ctld
$ va1 status
node cn1  sync headless  gen 1
controller 10.98.0.254:7700  session connecting  since 0s  last_error connect: Connection refused
forwarder up  boot_id 9aec0d9f8b563dbf  last_error -
```

The agent retries with backoff (`retry_ms=1000, 2000, 4000, 5000` in its log). A `ping -i 0.1` from
red1 to red2 runs through the whole outage.

**4. The controller returns; nodes resync, nothing was flushed**

```
$ lab/lab.sh svc start ctld
$ vc node show
cn1     172.16.0.1     02:00:00:ff:00:01  in-sync     yes      15    0       -
cn2     172.16.0.2     02:00:00:ff:00:02  in-sync     yes      19    2       -
$ lab/lab.sh ctl-diff; echo $?
0
150 packets transmitted, 150 received, 0% packet loss, time 16455ms
```

The entry counts grew (14 → 15, 16 → 19) because red5 stayed plugged during the outage; the
controller reloaded its bindings and labels from the state file, so every label is unchanged and no
route was withdrawn.
