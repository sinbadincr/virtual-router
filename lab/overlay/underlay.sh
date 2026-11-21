# shellcheck shell=bash
# The emulated fabric of the overlay lab (specs/003 contracts/lab-overlay.md): namespace mvr-ul with
# a kernel bridge br0 (MTU 1600), one veth to u0 of each compute node and one to the injector
# namespace mvr-inj. Kernel switching is allowed here; the compute nodes themselves never forward.
# Sourced by lab/overlay/overlay.sh. Every object lives inside an mvr-* namespace, so the host
# network is untouched and `ip netns del` removes it all. Idempotent.

UL_NS=mvr-ul
INJ_NS=mvr-inj
UL_MTU=1600
INJ_IP=172.16.0.9/24
INJ_MAC=02:00:00:ff:00:09

# node-ns  n(1|2)  : veth u0 in the node (fixed MAC 02:00:00:ff:00:0N) <-> ul-cnN on br0
underlay_node_link() {
  local ns=$1 n=$2 peer=ul-cn$2
  if ! nsx "$ns" ip link show u0 >/dev/null 2>&1 || ! nsx $UL_NS ip link show "$peer" >/dev/null 2>&1; then
    nsx "$ns" ip link del u0 2>/dev/null || true
    nsx $UL_NS ip link del "$peer" 2>/dev/null || true
    nsx "$ns" ip link add u0 address "02:00:00:ff:00:0$n" mtu $UL_MTU type veth peer name "$peer" netns $UL_NS
  fi
  nsx $UL_NS ip link set "$peer" mtu $UL_MTU master br0 up
  no_offload "$ns" u0
  no_offload $UL_NS "$peer"
  nsx "$ns" sysctl -qw net.ipv4.conf.u0.arp_ignore=8
  nsx "$ns" sysctl -qw net.ipv6.conf.u0.disable_ipv6=1 || echo "warning: cannot disable IPv6 on $ns/u0" >&2
  nsx "$ns" ip link set u0 mtu $UL_MTU up
}

underlay_up() {
  local ns
  for ns in $UL_NS $INJ_NS; do
    ns_exists "$ns" || ip netns add "$ns"
    nsx "$ns" ip link set lo up
  done
  nsx $UL_NS sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 \
    || echo "warning: cannot disable IPv6 in $UL_NS" >&2
  nsx $UL_NS ip link show br0 >/dev/null 2>&1 || nsx $UL_NS ip link add br0 type bridge
  nsx $UL_NS ip link set br0 mtu $UL_MTU up
  underlay_node_link mvr-cn1 1
  underlay_node_link mvr-cn2 2
  # injector: 172.16.0.9 on the same bridge (scapy source of malformed underlay traffic)
  if ! nsx $INJ_NS ip link show i0 >/dev/null 2>&1 || ! nsx $UL_NS ip link show ul-inj >/dev/null 2>&1; then
    nsx $INJ_NS ip link del i0 2>/dev/null || true
    nsx $UL_NS ip link del ul-inj 2>/dev/null || true
    nsx $INJ_NS ip link add i0 address $INJ_MAC mtu $UL_MTU type veth peer name ul-inj netns $UL_NS
  fi
  nsx $UL_NS ip link set ul-inj mtu $UL_MTU master br0 up
  no_offload $INJ_NS i0
  no_offload $UL_NS ul-inj
  nsx $INJ_NS sysctl -qw net.ipv6.conf.i0.disable_ipv6=1 || true
  nsx $INJ_NS ip link set i0 up
  nsx $INJ_NS ip addr replace $INJ_IP dev i0
}
