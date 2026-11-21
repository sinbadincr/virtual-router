#!/usr/bin/env bash
# minivr lab: one compute-node namespace (mvr-cn1) + three KVM guests on TAP ports (default),
# or, as the test harness behind `make e2e`, three VM namespaces over veth (up --harness).
# Only objects named mvr-* are created or removed; the host NIC and root routes are never touched.
# With --topo overlay: two compute nodes (mvr-cn1, mvr-cn2) behind an emulated underlay (mvr-ul), see
# specs/003-vrf-overlay-tunnels/contracts/lab-overlay.md.
# Usage: lab.sh up [--harness] [--topo single|overlay] | down | run [--node N] [--config FILE] | status | snapshot | ssh VM [CMD] | console VM [-f]
set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${MINIVR_BUILD:-debug}"
CN=mvr-cn1
RUN_DIR=/run/mvr-cn1
SOCK=$RUN_DIR/minivr.sock
LAB_OUT="$ROOT/build/lab"
PIDFILE="$LAB_OUT/minivrd.pid"
LOGFILE="$LAB_OUT/minivrd.log"

# name  VM-MAC  VM-address  gateway  cn1-port  port-MAC
VMS=(
  "mvr-vm1 02:00:00:00:01:01 10.0.1.11/24 10.0.1.1 p1 02:00:00:00:00:01"
  "mvr-vm2 02:00:00:00:01:02 10.0.1.12/24 10.0.1.1 p2 02:00:00:00:00:02"
  "mvr-vm3 02:00:00:00:01:03 10.0.2.13/24 10.0.2.1 p3 02:00:00:00:00:03"
)

die() { echo "lab.sh: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"; }
ns_exists() { ip netns list | awk '{print $1}' | grep -qx "$1"; }
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
# lab kind, derived from the namespaces (data-model.md "Lab kind"):
#   kvm | harness (single node, names unchanged since 004) | overlay/kvm | overlay/harness | none
lab_mode() {
  if ns_exists mvr-cn2; then
    if ns_exists mvr-mgmt; then echo overlay/kvm; else echo overlay/harness; fi
  elif ns_exists mvr-mgmt; then echo kvm
  elif ns_exists mvr-vm1; then echo harness
  else echo none
  fi
}
lab_kind() { lab_mode; }

# the single-node messages are the 004 strings (the phase 1 suites assert them verbatim)
kind_message() {
  case "$1" in
    kvm) echo "KVM lab is up" ;;
    harness) echo "namespace test harness is up" ;;
    *) echo "$1 lab is up" ;;
  esac
}
# Exactly one lab kind at a time: refuse (exit 1) when another kind is up.
refuse_other_kind() { # wanted-kind
  local cur
  cur=$(lab_mode)
  if [ "$cur" != none ] && [ "$cur" != "$1" ]; then
    die "$(kind_message "$cur"); run 'sudo make lab-clean' first"
  fi
}

# shellcheck source=lab/kvm/kvm.sh
. "$ROOT/lab/kvm/kvm.sh"
# shellcheck source=lab/overlay/overlay.sh
. "$ROOT/lab/overlay/overlay.sh"
kvm_use_topo single

# Refuse to continue if a root-namespace link with a lab name is not one of ours (a veth).
check_collisions() {
  local name type
  while read -r name type; do
    case "$name" in
      mvr-*) [ "$type" = veth ] || die "link $name exists and is not a veth; refusing to touch it" ;;
    esac
  done < <(ip -j -d link show 2>/dev/null | jq -r '.[] | "\(.ifname) \(.linkinfo.info_kind // "none")"')
}

# The forwarder re-injects frames through AF_PACKET, so the kernel must not hand it frames whose
# TCP/UDP checksum is still "to be offloaded" (CHECKSUM_PARTIAL) or GSO super-frames: switch tx
# checksum, scatter-gather, TSO, GSO and GRO off on both ends of every veth (ethtool ioctls;
# no ethtool binary needed).
no_offload() { # ns dev
  nsx "$1" python3 - "$2" <<'PY'
import array, fcntl, socket, struct, sys
ifname = sys.argv[1].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# ETHTOOL_S{TXCSUM,SG,TSO,GSO,GRO}
for cmd in (0x17, 0x19, 0x1f, 0x24, 0x2c):
    buf = array.array("B", struct.pack("II", cmd, 0))
    ifr = struct.pack("16sP", ifname, buf.buffer_info()[0])
    try:
        fcntl.ioctl(s.fileno(), 0x8946, ifr)  # SIOCETHTOOL
    except OSError:
        pass  # a feature this device does not have
PY
}

lab_up_harness() {
  need_root
  refuse_other_kind harness
  check_collisions
  local ns
  for ns in $CN $(for v in "${VMS[@]}"; do echo "${v%% *}"; done); do
    ns_exists "$ns" || ip netns add "$ns"
    nsx "$ns" ip link set lo up
  done

  # cn1 kernel isolation (research R3): no forwarding, no IPv6 on ports, no kernel ARP answers
  nsx $CN sysctl -qw net.ipv4.ip_forward=0

  local spec name vmmac addr gw port pmac
  for spec in "${VMS[@]}"; do
    read -r name vmmac addr gw port pmac <<<"$spec"
    # half-created pair left in the root namespace by an interrupted run
    ip link show "$name-e0" >/dev/null 2>&1 && ip link del "$name-e0"
    if ! nsx "$name" ip link show eth0 >/dev/null 2>&1 || ! nsx $CN ip link show "$port" >/dev/null 2>&1; then
      nsx "$name" ip link del eth0 2>/dev/null || true
      nsx $CN ip link del "$port" 2>/dev/null || true
      ip link add "$name-e0" address "$vmmac" type veth peer name "mvr-$port" address "$pmac"
      ip link set "$name-e0" netns "$name" name eth0
      ip link set "mvr-$port" netns $CN name "$port"
    fi
    # VM side
    nsx "$name" sysctl -qw net.ipv6.conf.eth0.disable_ipv6=1 || echo "warning: cannot disable IPv6 on $name/eth0" >&2
    no_offload "$name" eth0
    no_offload $CN "$port"
    nsx "$name" ip link set eth0 up
    nsx "$name" ip addr replace "$addr" dev eth0
    nsx "$name" ip route replace default via "$gw" dev eth0
    # cn1 side: no IPv4 address; the forwarder owns the gateway IP
    nsx $CN sysctl -qw "net.ipv4.conf.$port.arp_ignore=8"
    nsx $CN sysctl -qw "net.ipv6.conf.$port.disable_ipv6=1" || echo "warning: cannot disable IPv6 on $CN/$port" >&2
    nsx $CN ip link set "$port" up
  done
  echo "lab up (harness): $CN + mvr-vm1..3"
}

# `up`: contracts/lab-kvm.md, specs/004-kvm-default-lab/contracts/lab.md, checks in contract order.
lab_up_kvm() {
  local rc=0 vm avail todo=() state
  "$ROOT/scripts/check-prereqs.sh" --kvm >&2 || rc=$?
  [ "$rc" -eq 0 ] || exit "$rc"
  if [ "$(id -u)" -ne 0 ] || [ -z "${SUDO_UID:-}" ] || [ "$SUDO_UID" = 0 ]; then
    echo "lab.sh: run via sudo from your own user; QEMU never runs as root" >&2
    exit 2
  fi
  refuse_other_kind kvm
  avail=$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo)
  # guests already running hold their memory; only demand it when nothing is up yet
  if [ -z "$(for vm in "${KVM_GUESTS[@]}"; do kvm_pid "$vm"; done)" ] && [ "$avail" -lt 768 ]; then
    die "need 768 MB available for 3 guests, have $avail MB"
  fi
  check_collisions
  kvm_image_fetch
  kvm_image_verify
  kvm_image_layer
  kvm_net_up
  kvm_keys
  for vm in "${KVM_GUESTS[@]}"; do
    state=$(kvm_guest_state "$vm")
    case "$state" in
      ready|booting) ;;
      *) kvm_stop_guest "$vm"; kvm_seed "$vm"; kvm_boot "$vm"; todo+=("$vm") ;;
    esac
  done
  # guests that were still booting from an earlier run are waited for too
  for vm in "${KVM_GUESTS[@]}"; do
    [ "$(kvm_guest_state "$vm")" = booting ] && todo+=("$vm")
  done
  if [ ${#todo[@]} -gt 0 ]; then
    mapfile -t todo < <(printf '%s\n' "${todo[@]}" | sort -u)
    kvm_wait_all "${todo[@]}" || exit 1
  fi
  echo "lab up (kvm): $CN + vm1..3, mgmt $KVM_MGMT_NS"
}

# every forwarder of the lab: minivrd.pid (single) and minivrd-cn1/-cn2.pid (overlay)
stop_forwarder() {
  local f
  shopt -s nullglob
  for f in "$LAB_OUT"/minivrd.pid "$LAB_OUT"/minivrd-cn?.pid; do stop_forwarder_file "$f"; done
  shopt -u nullglob
}

stop_forwarder_file() { # pidfile
  local pidfile=$1
  [ -f "$pidfile" ] || return 0
  local pid
  pid=$(cat "$pidfile")
  if [ -n "$pid" ] && [ -d "/proc/$pid" ] && grep -q minivrd "/proc/$pid/comm" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 50); do [ -d "/proc/$pid" ] || break; sleep 0.1; done
    if [ -d "/proc/$pid" ]; then
      echo "forwarder did not stop within 5s; killing" >&2
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pidfile"
}

lab_down() {
  need_root
  stop_forwarder
  kvm_stop
  local ns link
  for ns in $(ip netns list | awk '{print $1}' | grep '^mvr-' || true); do
    ip netns del "$ns" || true
  done
  for link in $(ip -j link show | jq -r '.[].ifname | select(startswith("mvr-"))'); do
    ip link del "$link" 2>/dev/null || true
  done
  rm -rf "$RUN_DIR" /run/mvr-cn1 /run/mvr-cn2
  echo "lab down"
}

lab_run() {
  case "$(lab_mode)" in overlay/*) lab_run_overlay "$@"; return ;; esac
  need_root
  local config="$ROOT/lab/cn1.conf"
  while [ $# -gt 0 ]; do
    case "$1" in
      --config) [ $# -ge 2 ] || die "--config needs a file"; config=$2; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -f "$config" ] || die "config not found: $config"
  local bin="$ROOT/build/$BUILD/minivrd" ctl="$ROOT/build/$BUILD/vrctl"
  [ -x "$bin" ] && [ -x "$ctl" ] || die "build first: cmake --preset $BUILD && cmake --build --preset $BUILD"
  ns_exists $CN || die "lab is not up (run: sudo make lab)"
  stop_forwarder_file "$PIDFILE"
  mkdir -p "$LAB_OUT"
  echo "identity minivrd=$(sha256sum "$bin" | awk '{print $1}') config=$(sha256sum "$config" | awk '{print $1}') mode=$(lab_mode)" >>"$LOGFILE"
  rm -rf "$RUN_DIR"
  install -d -m 0700 -o root -g root "$RUN_DIR"
  # shellcheck disable=SC2086
  setsid ip netns exec $CN "$bin" --config "$config" --sock "$SOCK" ${MINIVR_ARGS:-} \
      >>"$LOGFILE" 2>&1 </dev/null &
  echo $! >"$PIDFILE"
  local i
  for i in $(seq 1 30); do
    if "$ctl" -s "$SOCK" version >/dev/null 2>&1; then
      echo "forwarder running (pid $(cat "$PIDFILE")), log $LOGFILE"
      echo "alias vrctl='$ctl -s $SOCK'    # or: export MINIVR_SOCK=$SOCK"
      return 0
    fi
    [ -d "/proc/$(cat "$PIDFILE")" ] || { tail -n 20 "$LOGFILE" >&2; die "forwarder exited during start-up"; }
    sleep 0.1
  done
  tail -n 20 "$LOGFILE" >&2
  die "forwarder did not answer within 3s"
}

lab_status() {
  local ns pid=none
  echo "lab: $(lab_mode)"
  for ns in $(ip netns list | awk '{print $1}' | grep '^mvr-' || true); do
    echo "== $ns"
    nsx "$ns" ip -brief link show | grep -v '^lo ' || true
    nsx "$ns" ip -brief addr show | grep -v '^lo ' | grep -v UNKNOWN || true
  done
  if [ -f "$PIDFILE" ] && [ -d "/proc/$(cat "$PIDFILE")" ]; then pid=$(cat "$PIDFILE"); fi
  case "$(lab_mode)" in
    overlay/*)
      local n
      for n in cn1 cn2; do
        pid=none
        f="$LAB_OUT/minivrd-$n.pid"
        if [ -f "$f" ] && [ -d "/proc/$(cat "$f")" ]; then pid=$(cat "$f"); fi
        echo "forwarder $n pid: $pid"
      done ;;
    *) echo "forwarder pid: $pid" ;;
  esac
  case "$(lab_mode)" in overlay/*) kvm_use_topo overlay ;; esac
  if [ "$(lab_mode)" = kvm ] || [ "$(lab_mode)" = overlay/kvm ]; then
    echo "== guests (mode $(lab_mode))"
    printf '%-5s %-8s %-6s %-5s %-18s %-13s %-12s %s\n' NAME STATE PID PORT MAC DATA MGMT CONSOLE
    local vm
    for vm in "${KVM_GUESTS[@]}"; do
      printf '%-5s %-8s %-6s %-5s %-18s %-13s %-12s %s\n' "$vm" "$(kvm_guest_state "$vm")" \
        "$(kvm_pid "$vm" | grep . || echo -)" "${KVM_PORT[$vm]}" "${KVM_DATA_MAC[$vm]}" \
        "${KVM_DATA_ADDR[$vm]}" "${KVM_MGMT_IP[$vm]}" "build/lab/kvm/logs/$vm.console.log"
    done
  fi
}

kvm_vm_arg() { # validate a guest name
  case "${1:-}" in
    vm1|vm2|vm3|red1|blue1|red2|red3|blue2) ;;
    *) die "usage: $0 ssh|console vm1|vm2|vm3 (single) or red1|blue1|red2|red3|blue2 (overlay) ..." ;;
  esac
  case "$(lab_mode)" in overlay/*) kvm_use_topo overlay ;; esac
}

lab_ssh() {
  need_root
  kvm_vm_arg "${1:-}"
  case "$(lab_mode)" in kvm|overlay/kvm) ;; *) die "KVM lab is not up (run: sudo make lab)" ;; esac
  local vm=$1; shift
  kvm_ssh "$vm" "$@"
}

lab_console() {
  kvm_vm_arg "${1:-}"
  local log="$ROOT/build/lab/kvm/logs/$1.console.log"
  [ -f "$log" ] || die "no console log yet: build/lab/kvm/logs/$1.console.log"
  if [ "${2:-}" = "-f" ]; then exec tail -n 40 -f "$log"; fi
  echo "build/lab/kvm/logs/$1.console.log"
  tail -n 40 "$log"
}

# Host network state in the root namespace, normalised (sorted, volatile fields removed).
lab_snapshot() {
  local link addr r4 r6 nets
  link=$(ip -j link show | jq -c 'map({ifname, address, mtu, operstate, link_type, flags}) | sort_by(.ifname)')
  addr=$(ip -j addr show | jq -c 'map({ifname, addr_info: (.addr_info | map({family, local, prefixlen, scope, label}) | sort_by(.local))}) | sort_by(.ifname)')
  r4=$(ip -j route show | jq -c 'map(del(.expires, .cache)) | sort_by(.dst, .dev)')
  r6=$(ip -j -6 route show | jq -c 'map(del(.expires, .cache)) | sort_by(.dst, .dev)')
  nets=$(ip netns list | awk '{print $1}' | sort | jq -R . | jq -sc .)
  jq -nS --argjson link "$link" --argjson addr "$addr" --argjson r4 "$r4" --argjson r6 "$r6" \
        --argjson netns "$nets" '{link: $link, addr: $addr, route: $r4, route6: $r6, netns: $netns}'
}

lab_up() {
  local harness=0 topo=single interop=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --harness) harness=1; shift ;;
      --topo) [ $# -ge 2 ] || { echo "usage: $0 up [--harness] [--topo single|overlay] [--interop]" >&2; exit 2; }
              topo=$2; shift 2 ;;
      --interop) interop=1; shift ;;
      *) echo "usage: $0 up [--harness] [--topo single|overlay] [--interop]" >&2; exit 2 ;;
    esac
  done
  case "$topo" in single|overlay) ;; *) echo "usage: $0 up [--harness] [--topo single|overlay] [--interop]" >&2; exit 2 ;; esac
  [ $interop -eq 0 ] || [ "$topo" = overlay ] || { echo "lab.sh: --interop needs --topo overlay" >&2; exit 2; }
  if [ "$topo" = overlay ]; then
    if [ $harness -eq 1 ]; then lab_up_overlay_harness; else lab_up_overlay_kvm; fi
    [ $interop -eq 0 ] || lab_interop_up
  else
    if [ $harness -eq 1 ]; then lab_up_harness; else lab_up_kvm; fi
  fi
}

case "${1:-}" in
  up) shift; lab_up "$@" ;;
  down) lab_down ;;
  run) shift; lab_run "$@" ;;
  status) lab_status ;;
  snapshot) lab_snapshot ;;
  ssh) shift; lab_ssh "$@" ;;
  console) shift; lab_console "$@" ;;
  *) echo "usage: $0 up [--harness] [--topo single|overlay] [--interop] | down | run [--node cn1|cn2] [--config FILE] | status | snapshot | ssh VM [CMD...] | console VM [-f]" >&2; exit 2 ;;
esac
