#!/usr/bin/env bash
# Control network of the ctl lab (specs/005 contracts/lab-ctl.md): namespace mvr-ctl with bridge
# br0 10.98.0.254/24 and, per compute node, a veth whose node end `c0` has 10.98.0.N/24. Ordinary
# kernel networking (ARP, MTU 1500): the forwarder never opens c0. Only mvr-* objects, idempotent.
# Usage: ctlnet.sh up|node <cn1|cn2|cn3>|cut <node> up|down|down
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"
CTL=mvr-ctl

ns_exists() { ip netns list | awk '{print $1}' | grep -qx "$1"; }
node_n() { case "$1" in cn1) echo 1 ;; cn2) echo 2 ;; cn3) echo 3 ;; *) echo "bad node $1" >&2; exit 2 ;; esac; }

ctl_ns() {
  ns_exists $CTL || ip netns add $CTL
  ip netns exec $CTL ip link set lo up
  ip netns exec $CTL ip link show br0 >/dev/null 2>&1 || ip netns exec $CTL ip link add br0 type bridge
  ip netns exec $CTL ip link set br0 mtu 1500 up
  ip netns exec $CTL ip addr replace 10.98.0.254/24 dev br0
}

node_link() { # cnN
  local n; n=$(node_n "$1")
  local ns=mvr-$1
  ns_exists "$ns" || { echo "ctlnet: namespace $ns does not exist" >&2; exit 1; }
  if ! ip netns exec "$ns" ip link show c0 >/dev/null 2>&1; then
    ip netns exec $CTL ip link del "mvr-ct$n" 2>/dev/null || true
    ip netns exec $CTL ip link add "mvr-ct$n" type veth peer name c0 netns "$ns"
  fi
  ip netns exec $CTL ip link set "mvr-ct$n" master br0
  ip netns exec $CTL ip link set "mvr-ct$n" up
  ip netns exec "$ns" ip link set c0 mtu 1500 up
  ip netns exec "$ns" ip addr replace "10.98.0.$n/24" dev c0
}

case "${1:-}" in
  up) shift; ctl_ns; for n in "$@"; do node_link "$n"; done ;;
  node) ctl_ns; node_link "$2" ;;
  cut) # cut <node> up|down: the control link of a node
    ip netns exec "mvr-$2" ip link set c0 "${3:-down}" ;;
  *) echo "usage: $0 up cn1 cn2 | node cn3 | cut <node> up|down" >&2; exit 2 ;;
esac
