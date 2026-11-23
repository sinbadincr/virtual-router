# The agent (`minivr-agent`)

One per compute node, in the node's namespace, next to its `minivrd`. It is the only thing that
talks to both worlds: the controller (protocol over TCP) and the forwarder (its text control socket).
One `epoll` loop, no threads. It starts even if neither is reachable yet and retries both.

## Data it keeps (`src/agent/`)

| Name | Meaning |
|---|---|
| **want** | the node state last *completely* received |
| **pending** | entries of a full sync still arriving; becomes `want` at `SYNC_END` |
| **have** | the agent-owned entries read back from the forwarder at each reconcile |
| **bindings** | `vmi → port`, persisted in `<state-dir>/bindings` (survives an agent restart) |
| **failed** | entries the forwarder refused: command, error code, message |

## Reconcile (`src/agent/reconcile.c`, pure)

`rc_plan(want, have, foreign)` produces the ordered list of forwarder commands:
deletes `route → label,vni → neigh → port → node → vrf`, then adds in the reverse order. A PORT whose
VRF or gateway changes is deleted and re-added together with its neighbour and label; a changed route
is `route replace`, a changed router MAC `node set`. Keys that the forwarder holds for another owner
(`config` file, operator `cli`) are **conflicts**: reported, never overwritten (`diff show`).

**Mark and sweep.** A full sync goes into `pending`; nothing is deleted until `SYNC_END` with the same
`GEN`. A session lost halfway discards `pending` only. An agent that has never completed a sync
produces no commands at all, so a fresh agent cannot wipe a forwarder it has not read yet.

## Headless operation

When the controller is gone (stopped, cut, crashed) the agent keeps `want` and the forwarder keeps
its tables: **traffic does not depend on the control plane being up**. The agent reconnects with
backoff 0.5 → 1 → 2 → 4 → 5 s (reset once a session is established), re-reports its bindings and
accepts the new full sync. A forwarder restart is noticed through `boot_id` (in `version`); the agent
re-reads `have` (empty) and re-adds everything. An agent restart reads `have` first and logs
`adopted=<n>`: matching state is adopted, not flushed.

## Fd passing into a zero-capability forwarder

The forwarder drops every capability after start-up (phase 1), yet VMs boot later and need new
AF_PACKET sockets. The agent opens the socket for the new TAP (`afp_socket_open`) and passes it with
`SCM_RIGHTS` in the same frame as `port add <name> … fd`. The forwarder verifies it before adopting
(`src/ctl/fdcheck.c`): `AF_PACKET`, `SOCK_RAW`, bound to `if_nametoindex(ifname)`; anything else is
`bad-fd` and the descriptor is closed. A frame carrying a descriptor on a non-agent session is refused.

**Privilege trade-off (R15).** The agent keeps uid 0 but only `CAP_NET_RAW` (all other capabilities
dropped, bounding set cleared, `no_new_privs`, self-verified from `/proc/self/status`). It stays root
because the forwarder's `SO_PEERCRED` check accepts its launcher or uid 0, and an agent restarted by
init must be able to reconnect; teaching the forwarder a second trusted uid adds configuration for
no learning value.

## Plug flow

`vrctl -s /run/mvr-cn1/agent.sock plug red5 port red5` — as nova's VIF driver would after creating
the TAP: validate the interface exists, persist the binding, report `BIND`. The controller answers
with the VM's label and, a moment later, the node state that makes it reachable; `unplug` reverses
it. Compare TF: nova-compute tells the vrouter agent about a port over its port-IPC; the agent then
learns the rest from the control node.

## Commands

`plug`, `unplug`, `status` (session, sync state, forwarder, per-kind want/have counts, failures,
bind errors), `bindings show`, `want show`, `diff show` (`missing`, `stale`, `conflicts`), `version`.
