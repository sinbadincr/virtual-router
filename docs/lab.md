# The minivr lab

A single-host lab: one **compute-node** namespace (`mvr-cn1`, where `minivrd` runs), three
**KVM guests** (`vm1`–`vm3`, CirrOS, virtio-net) on TAP ports `p1`–`p3`, and a management
namespace `mvr-mgmt` (bridge `br0`, `10.99.0.0/24`) the lab uses to reach the guests over SSH.
It mimics a vRouter host with three guests. The lab needs `/dev/kvm`; without it `make lab` exits
3 or 4 and creates nothing. Prerequisites, wiring, images and troubleshooting: [kvm.md](kvm.md).

```
 vm1 (KVM)                  mvr-cn1 (compute node)                    vm3 (KVM)
 eth0 10.0.1.11/24 ──TAP── p1 ┐                                ┌ p3 ──TAP── eth0 10.0.2.13/24
 gw 10.0.1.1                  │      minivrd (AF_PACKET)       │              gw 10.0.2.1
 vm2 (KVM)                    ├── gateway 10.0.1.1/24 on p1,p2 ┤
 eth0 10.0.1.12/24 ──TAP── p2 ┘   gateway 10.0.2.1/24 on p3   │
 gw 10.0.1.1                 (each guest also has eth1 on mvr-mgmt, no gateway)
```

p1 and p2 both carry the gateway `10.0.1.1/24`: an **anycast gateway**, as vRouter presents on
every VM interface. The ports in `mvr-cn1` have **no IPv4 address**; the gateway IPs exist only
in the forwarder's config, so the kernel never answers ARP or forwards (`ip_forward=0`,
`arp_ignore=8`, IPv6 off). `tcpdump` in a guest therefore proves that `minivrd` answered.

## Addressing

| Where | Interface | MAC | Address | Gateway |
|---|---|---|---|---|
| guest `vm1` | `eth0` | `02:00:00:00:01:01` | `10.0.1.11/24` | `10.0.1.1` |
| guest `vm2` | `eth0` | `02:00:00:00:01:02` | `10.0.1.12/24` | `10.0.1.1` |
| guest `vm3` | `eth0` | `02:00:00:00:01:03` | `10.0.2.13/24` | `10.0.2.1` |
| `mvr-cn1` | `p1`, `p2`, `p3` | `02:00:00:00:00:01..03` | none | n/a |

## Commands

| Command | Effect |
|---|---|
| `sudo make lab` / `sudo lab/lab.sh up` | create the KVM lab (image, TAPs, guests, wait for ready); idempotent, repairs partial state. Exit 3 without KVM, 4 if KVM is not usable by you, 2 for missing tools |
| `sudo make lab-run` / `sudo lab/lab.sh run [--config FILE]` | start `minivrd` in `mvr-cn1` (default `lab/cn1.conf`); replaces a running one |
| `sudo make lab-clean` / `sudo lab/lab.sh down` | stop the forwarder, remove every `mvr-*` object and `/run/mvr-cn1/` |
| `lab/lab.sh status` | `lab: kvm` (or `harness`, `none`), namespaces, links, forwarder pid, guest table |
| `sudo lab/lab.sh ssh vm1 [CMD...]` | shell or command in a guest over the management network |
| `lab/lab.sh console vm1 [-f]` | the guest's console log |
| `sudo lab/lab.sh snapshot` | normalised host network state (JSON) for before/after diffs |

`minivrd` listens on `/run/mvr-cn1/minivr.sock` in the lab:

```bash
export MINIVR_SOCK=/run/mvr-cn1/minivr.sock
sudo -E build/debug/vrctl route show
```

## Safety guarantees (FR-002 to FR-004)

- Every object the lab creates is named `mvr-*` (namespaces, TAPs, veths, `/run/mvr-cn1/`). The
  scripts never reference the host NIC (`ens33`) or any root-namespace route.
- `lab.sh` refuses to run if a root-namespace link called `mvr-*` exists and is not a veth.
- `up` and `down` are idempotent and tolerate partial state.
- `sudo lab/lab.sh snapshot` before `up` and after `down` must be byte-identical; the e2e suite
  checks this for the whole session.

## Inspecting

```bash
sudo lab/lab.sh ssh vm1 ping -c3 10.0.1.12
sudo lab/lab.sh ssh vm1 sudo tcpdump -ni eth0 arp
sudo ip netns exec mvr-cn1 ip -d link show p1
tail -f build/lab/minivrd.log
```

## Test harness (namespace VMs)

`sudo lab/lab.sh up --harness` builds the phase 1 topology instead: three namespaces `mvr-vm1..3`
joined to `mvr-cn1` by veth pairs, with the same addresses and MACs as above. It is what
`sudo make e2e` uses. It exists because some tests must put frames on the wire that no guest
kernel would send (malformed ARP/IPv4, spoofed addresses, truncated packets) and because it runs
on a host without KVM. It is **not** the lab: the README, the demo and `make lab` never use it,
and there is no `make` target for it.

The harness and the KVM lab exclude each other: `up` while the harness is up and `up --harness`
while the KVM lab is up both stop with exit 1 until `sudo make lab-clean`, which removes either.
`lab.sh status` prints `lab: harness` as its first line. Which tests run where, and why, is in
[traceability.md](traceability.md).

## The overlay lab (phase 2)

`sudo make lab TOPO=overlay` (= `sudo lab/lab.sh up --topo overlay`) builds two compute nodes, an
emulated underlay and five guests; `sudo make lab-run` starts one forwarder per node.

```
                       mvr-ul: br0 (MTU 1600), the emulated fabric
        ┌──────────────┬──────────────┬─────────────────┬────────────────┐
   mvr-cn1 u0     mvr-cn2 u0     mvr-ix (optional)   mvr-inj (injector)
   172.16.0.1     172.16.0.2     172.16.0.3          172.16.0.9
   red1  blue1    red2 red3 blue2      Linux VXLAN, VRF blue, 10.1.3.33
```

| Guest | Node | Tenant (VRF) | MAC | Address | Gateway | Mgmt |
|---|---|---|---|---|---|---|
| `red1` | cn1 | red | `02:00:00:01:01:11` | `10.1.1.11/24` | `10.1.1.1` | `10.99.0.21` |
| `blue1` | cn1 | blue | `02:00:00:02:01:11` | `10.1.1.11/24` | `10.1.1.1` | `10.99.0.22` |
| `red2` | cn2 | red | `02:00:00:01:02:12` | `10.1.1.12/24` | `10.1.1.1` | `10.99.0.23` |
| `red3` | cn2 | red | `02:00:00:01:02:13` | `10.1.2.13/24` | `10.1.2.1` | `10.99.0.24` |
| `blue2` | cn2 | blue | `02:00:00:02:02:12` | `10.1.1.12/24` | `10.1.1.1` | `10.99.0.25` |

Red and blue reuse the same addresses on purpose. Red uses MPLSoUDP (per-interface labels 1011,
1012, 1013), blue uses L3 VXLAN (VNI 200). `u0` of cn1 / cn2 has MAC `02:00:00:ff:00:01` / `02`
(their router MACs); the underlay MTU is 1600 and the guests' 1500.

| Command | Effect |
|---|---|
| `sudo make lab TOPO=overlay` | the overlay lab with KVM guests (about 7 s once the image is cached); `sudo lab/lab.sh up --topo overlay --harness` for namespace VMs |
| `sudo lab/lab.sh up --topo overlay [--harness] --interop` | also the Linux kernel VXLAN endpoint `mvr-ix` (idempotent) |
| `sudo lab/lab.sh run [--node cn1\|cn2] [--config FILE]` | start the forwarders with `lab/overlay/cn1.conf` / `cn2.conf` (sockets `/run/mvr-cn1/minivr.sock`, `/run/mvr-cn2/minivr.sock`; logs `build/lab/minivrd-cn1.log`, `-cn2.log`) |
| `lab/lab.sh status` | first line `lab: overlay/kvm` or `lab: overlay/harness`, then every namespace and guest |
| `sudo lab/lab.sh ssh red1 [CMD...]` | guests: `red1 blue1 red2 red3 blue2` |
| `sudo make lab-clean` | removes every lab kind |

Exactly one lab kind exists at a time (`kvm`, `harness`, `overlay/kvm`, `overlay/harness`): `up`
of another kind stops with exit 1 and `<kind> lab is up; run 'sudo make lab-clean' first`. Every
object is `mvr-*` and lives inside a namespace, so the host snapshot is identical after `down`.

```bash
export MINIVR_SOCK=/run/mvr-cn1/minivr.sock           # or -s per call
sudo -E build/debug/vrctl vrf show
sudo -E build/debug/vrctl route show vrf red
sudo -E build/debug/vrctl node show                   # per-node encap/decap counters
sudo lab/lab.sh ssh red1 ping -c3 10.1.1.12           # ttl=63, MPLSoUDP label 1012
sudo ip netns exec mvr-ul tcpdump -ni br0 udp port 6635 or udp port 4789
```

The **injector** `mvr-inj` (172.16.0.9, MAC `02:00:00:ff:00:09`) sends crafted underlay traffic
for the malformed-packet corpus (`tests/e2e_overlay/underlay_corpus.py`). The overlay suite is
`tests/e2e_overlay`, run on both variants by `sudo make e2e` (namespace VMs) and
`sudo make e2e-kvm` (KVM guests).

## The controller lab (phase 3, `TOPO=ctl`)

`sudo make lab TOPO=ctl && sudo make lab-run` brings up the overlay lab plus a control network and
starts the controller and one agent per node; the forwarders get only their bootstrap config
(`lab/ctl/cnN.conf`: the underlay port and the ICMP limiter). Everything else — VRFs, ports, routes,
labels, VNIs — is derived from `lab/ctl/intent.conf` and the guests' plugs.

```
            mvr-ctl: br0 10.98.0.254/24   (minivr-ctld :7700, /run/mvr-ctl/ctld.sock)
        ┌──────────────┬──────────────┬──────────────┐
   mvr-cn1 c0     mvr-cn2 c0     mvr-cn3 c0 (node up cn3)
   10.98.0.1      10.98.0.2      10.98.0.3            ── u0 on mvr-ul as in the overlay lab
```

`c0` is an ordinary kernel interface (ARP, MTU 1500); the forwarder never opens it, so control traffic
does not depend on the data path. Spare guests: `red5` (cn2, 10.1.2.15) and `red4` (cn3, 10.1.1.14).

| Command | Effect |
|---|---|
| `sudo lab/lab.sh guest start\|stop <g> [node]` | create the TAP/veth, `plug` through the node's agent, boot the guest — and the reverse |
| `sudo lab/lab.sh guest move <g> <node>` | `stop`, then `start` on the other node (same MAC and address) |
| `sudo lab/lab.sh node up\|down cn3` | add or remove the third compute node with its guest red4 |
| `sudo lab/lab.sh svc stop\|start\|kill\|pause\|resume ctld\|agent-cnN\|minivrd-cnN` | failure injection |
| `sudo lab/lab.sh ctl-cut <node> up\|down` | cut or restore the node's control link |
| `sudo lab/lab.sh ctl-diff` | controller intent vs agent-owned forwarder entries, exit 0 only if equal |

Sockets: `/run/mvr-ctl/ctld.sock`, `/run/mvr-cnN/agent.sock`, `/run/mvr-cnN/minivr.sock`; state in
`build/lab/ctl/state.conf`; logs `build/lab/{ctld,agent-cnN,minivrd-cnN}.log`.
