# shellcheck shell=bash
# Independent VXLAN endpoint for the overlay lab (US6, SC-008): the Linux kernel's own VXLAN in
# L3 mode, so the forwarder is checked against a second, unrelated implementation.
#
#   mvr-ix  172.16.0.3 on mvr-ul/br0 (MTU 1600)
#     VRF blue (table 20, unreachable default)
#       vx200   VNI 200, local 172.16.0.3, dstport 4789, nolearning, MAC 02:00:00:ff:00:03
#               (the router MAC the forwarders' config gives node `ix`)
#       ix0     dummy, 10.1.3.33/32: the tenant address the blue VMs ping
#     routes 10.1.1.11/32 and 10.1.1.12/32 in blue via transit addresses whose permanent neighbour
#     entries carry the cn1/cn2 router MACs, and a static FDB entry per peer (no learning): exactly
#     what the forwarder needs to see on the wire.
# Sourced by lab/overlay/overlay.sh. Only an mvr-* namespace is created; `lab.sh down` removes it.

IX_NS=mvr-ix
IX_IP=172.16.0.3/24
IX_RMAC=02:00:00:ff:00:03
IX_UL_MAC=02:00:00:ff:01:03
IX_TENANT=10.1.3.33/32

lab_interop_up() {
  need_root
  ns_exists mvr-cn2 || die "the overlay lab is not up (run: sudo make lab TOPO=overlay)"
  ns_exists mvr-ul || die "the underlay is missing; run 'sudo make lab-clean' and bring the overlay up again"
  ns_exists $IX_NS || ip netns add $IX_NS
  nsx $IX_NS ip link set lo up
  if ! nsx $IX_NS ip link show i3 >/dev/null 2>&1 || ! nsx mvr-ul ip link show ul-ix >/dev/null 2>&1; then
    nsx $IX_NS ip link del i3 2>/dev/null || true
    nsx mvr-ul ip link del ul-ix 2>/dev/null || true
    nsx $IX_NS ip link add i3 address $IX_UL_MAC mtu $UL_MTU type veth peer name ul-ix netns mvr-ul
  fi
  nsx mvr-ul ip link set ul-ix mtu $UL_MTU master br0 up
  no_offload $IX_NS i3
  no_offload mvr-ul ul-ix
  nsx $IX_NS sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 || true
  # sockets outside the VRF (nc, socat) must also see connections that arrive through it
  nsx $IX_NS sysctl -qw net.ipv4.tcp_l3mdev_accept=1 net.ipv4.udp_l3mdev_accept=1 \
    net.ipv4.raw_l3mdev_accept=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
  nsx $IX_NS ip link set i3 up
  nsx $IX_NS ip addr replace $IX_IP dev i3
  wait_carrier $IX_NS i3

  nsx $IX_NS ip link show blue >/dev/null 2>&1 || nsx $IX_NS ip link add blue type vrf table 20
  nsx $IX_NS ip link set blue up
  nsx $IX_NS ip route replace vrf blue unreachable default metric 4278198272
  if ! nsx $IX_NS ip link show vx200 >/dev/null 2>&1; then
    nsx $IX_NS ip link add vx200 type vxlan id 200 local 172.16.0.3 dstport 4789 nolearning
  fi
  nsx $IX_NS ip link set vx200 address $IX_RMAC mtu 1500 master blue
  nsx $IX_NS sysctl -qw net.ipv4.conf.vx200.rp_filter=0
  nsx $IX_NS ip link set vx200 up
  nsx $IX_NS ip link show ix0 >/dev/null 2>&1 || nsx $IX_NS ip link add ix0 type dummy
  nsx $IX_NS ip link set ix0 master blue up
  nsx $IX_NS ip addr replace $IX_TENANT dev ix0
  # one transit next hop per compute node: permanent neighbour = its router MAC, FDB = its VTEP
  local n=1 dst
  for dst in 10.1.1.11 10.1.1.12; do
    nsx $IX_NS ip neigh replace 169.254.100.$n lladdr "02:00:00:ff:00:0$n" dev vx200 nud permanent
    nsx $IX_NS bridge fdb replace "02:00:00:ff:00:0$n" dev vx200 dst "172.16.0.$n" static
    nsx $IX_NS ip route replace vrf blue "$dst/32" via 169.254.100.$n dev vx200 onlink
    n=$((n + 1))
  done
  echo "interop endpoint up: $IX_NS vx200 VNI 200, tenant address ${IX_TENANT%/*} in VRF blue"
}
