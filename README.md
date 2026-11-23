# minivr

A learning/portfolio **vRouter data plane** in C17 for Linux, built the way a production
forwarder would be: a single-threaded L3 forwarder with a pluggable packet I/O backend, a live
control CLI, structured logs, crash dumps, sanitizer-clean unit tests and one-command end-to-end
suites on a reproducible lab of real KVM guests.

It models the data-plane half of Tungsten Fabric's vRouter. The compute node is a namespace
(`mvr-cn1`) running `minivrd`; the VMs are three KVM guests (CirrOS, virtio-net) attached to it
through TAP ports, the way nova/libvirt attach VMs to a vRouter. The forwarder presents an
**anycast gateway** to every guest, answers ARP only for hosts it knows (proxy ARP), drops spoofed
sources, routes IPv4 by longest-prefix match and counts every drop under a named reason.

```
 vm1 (KVM) ─┐                                 ┌─ vm3 (KVM)
 10.0.1.11  ├── p1 ┐                     ┌ p3 ┤ 10.0.2.13
 vm2 (KVM) ─┤      ├── minivrd (AF_PACKET) ┤    └─ gw 10.0.2.1
 10.0.1.12  └── p2 ┘     mvr-cn1          └
   gw 10.0.1.1 (anycast on p1 and p2)
```

## Quickstart

```bash
sudo apt install build-essential cmake clang gdb iproute2 iputils-ping socat jq python3-venv \
                 qemu-system-x86 qemu-utils genisoimage openssh-client
cmake --preset debug && cmake --build --preset debug
ctest --preset debug                               # unit tests (also: --preset asan)

sudo make lab && sudo make lab-run                 # three KVM guests + minivrd with lab/cn1.conf
sudo lab/lab.sh ssh vm1 ping -c3 10.0.2.13         # vm1 -> vm3 through the forwarder, ttl=63
export MINIVR_SOCK=/run/mvr-cn1/minivr.sock
sudo -E build/debug/vrctl route show
sudo -E build/debug/vrctl -j stats show | jq .data.drops
sudo make lab-clean                                # leaves the host network exactly as it was

# phase 2: two compute nodes, tenants with overlapping addresses, MPLSoUDP and VXLAN tunnels
sudo make lab TOPO=overlay && sudo make lab-run
# phase 3: the same overlay lab programmed by a controller and per-node agents
sudo make lab TOPO=ctl && sudo make lab-run
sudo lab/lab.sh ssh red1 ping -c3 10.1.1.12        # red1 on cn1 -> red2 on cn2 through MPLSoUDP, ttl=63
sudo lab/lab.sh ssh blue1 ping -c3 10.1.1.12       # same address, other tenant, through VXLAN
```

The lab needs KVM (`/dev/kvm`, usable by your user; run `sudo` from your own user). Without it
`make lab` stops with exit code 3 (no KVM) or 4 (KVM not usable by you) and creates nothing;
there is no fallback. Details: [`docs/kvm.md`](docs/kvm.md).

`sudo make e2e` is the harness suite: forwarding, CLI, robustness corpus, privilege drop and crash
drill, run on throw-away namespace VMs because it crafts frames no guest kernel would send; it
needs no KVM. It then runs the phase 2 overlay suite (two compute nodes, VRFs, MPLSoUDP and VXLAN
tunnels, isolation, malformed underlay traffic, the Linux VXLAN interop endpoint) on namespace
VMs too. `sudo make e2e-kvm` runs the same behaviours that a guest can show, inside the KVM
lab, and then the overlay suite on KVM guests. Both compare the host network state before and
after and are part of the merge gate, with
`make check`: GCC and Clang with `-Werror`, ctest plain and under ASan/UBSan, and the fast-path
audit.

## Demo

`sudo scripts/demo.sh` walks through the whole thing on KVM guests: lab up, forwarder start, pings
between guests, TTL exceeded and unreachable, a spoofed source dropped and counted, a live route
`del`/`add` while pinging, the route/neighbour/port tables, and teardown. A captured run is in
[`docs/demo.md`](docs/demo.md); `docs/demo.cast` is a terminal cast of it
(`asciinema play docs/demo.cast`).

## Benchmarks

None in phase 1, on purpose: phase 1 optimises for correctness and observability. Any
optimisation from phase 4 on needs a committed benchmark, perf evidence and an entry in
`docs/perf.md` (constitution VI), and numbers will be labelled as VM/virtual-device results,
not line rate.

## Documentation

| | |
|---|---|
| `docs/architecture.md` | event loop, packet path, data structures, mbuf lifecycle |
| `docs/lab.md` | topology, addressing, commands, safety guarantees, the test harness, the overlay lab |
| `docs/overlay.md` | phase 2: packet walk of both tunnels with real captures, comparison with Tungsten Fabric and the Linux kernel |
| `docs/protocol.md`, `docs/controller.md`, `docs/agent.md` | phase 3: the agent⇄controller wire protocol, the controller (model, compute-then-diff, labels, state file) and the agent (reconcile, headless operation, fd passing), compared with Tungsten Fabric |
| `docs/kvm.md` | the KVM guests: prerequisites, wiring, images, troubleshooting |
| `docs/cli.md` | every `vrctl` command, exit code, error code and JSON shape |
| `docs/drop-reasons.md` | every named drop reason, its trigger and its test |
| `docs/demo.md` | captured output of the scripted demo |
| `docs/traceability.md` | each requirement and success criterion mapped to a test |
| `incidents/` | post-mortems, starting with the forced-crash drill |
| `specs/001-lab-l3-forwarder/`, `specs/004-kvm-default-lab/`, `specs/003-vrf-overlay-tunnels/` | spec, plan, research decisions, data model, contracts, tasks |

## Layout

`src/dp` forwarding logic (no syscalls), `src/proto` + `src/controller` + `src/agent` the phase 3 control plane (`libminivr_ctrl` is pure), `src/pio` packet I/O backends, `src/ctl` command grammar
and control socket, `src/daemon` the `minivrd` main/loop/privileges/crash/link monitor,
`src/vrctl` the CLI, `lab/` lab scripts and shipped configs, `tests/unit` C unit tests,
`tests/e2e` pytest + scapy harness suite, `tests/e2e_kvm` KVM suite, `tests/e2e_overlay` the phase 2 suite (both variants), `tests/e2e_ctl` the phase 3 suite. Third-party test dependencies: `THIRD_PARTY.md`.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1. Lab + L3 forwarder | Namespace lab (`mvr-cn1` + 3 VM namespaces, now the test harness); AF_PACKET/epoll forwarder with proxy ARP, anycast gateway, LPM trie, neighbour FSM, ICMP rate limit, anti-spoofing; `vrctl` CLI; privilege drop; crash dumps and post-mortem | **Done** |
| 1.5. KVM lab | Real KVM guests (CirrOS, virtio-net) attached to `minivrd` through TAP ports, as nova/libvirt attach VMs to a vRouter; no forwarder changes; since feature 004 it is the default lab (`make lab`), the namespace VMs stay as the test harness (`lab.sh up --harness`); see [docs/kvm.md](docs/kvm.md) | **Done** |
| 2. VRFs + overlay tunnels | Two compute nodes over an emulated underlay; tenants with overlapping addresses; MPLSoUDP (RFC 7510) and VXLAN (RFC 7348); interop with the Linux kernel VXLAN; see [docs/overlay.md](docs/overlay.md) | **Implemented** (see `specs/003-vrf-overlay-tunnels/tasks.md`) |
| 3. Agent + controller | Controller `minivr-ctld` holding tenants, VM interfaces and bindings; per-node `minivr-agent` programming `minivrd` over a documented binary protocol, fd passing for runtime ports, headless operation; the overlay lab driven from `make lab TOPO=ctl`; see [docs/controller.md](docs/controller.md), [docs/agent.md](docs/agent.md), [docs/protocol.md](docs/protocol.md) | **Implemented** (see `specs/005-agent-controller/tasks.md`) |
| 4. Multi-core + DPDK + perf | Worker threads with RCU-updated tables, DIR-24-8 LPM; optional DPDK backend on virtual devices and vhost-user for KVM guests; benchmarks, perf and flame graphs in `docs/perf.md` | Planned |
| 5. BGP EVPN + incidents | EVPN peering with FRR (type-5/type-2 routes); post-mortems of deliberately reproduced faults (races, use-after-free, deadlocks) | Planned |

## Status

Phases 1, 1.5, 2 and 3 (single-node lab, L3 forwarder, VRFs and overlay tunnels, controller and
agents). Not claimed: performance (see Benchmarks), multi-core, controller redundancy, protocol
authentication or encryption, IPv6, VLANs, ARP/neighbour aging, tunnel authentication or encryption. See the specs' assumptions.
