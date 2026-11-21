# shellcheck shell=bash
# Two-node overlay lab (specs/003 contracts/lab-overlay.md). Sourced by lab/lab.sh, which provides
# ROOT, BUILD, LAB_OUT, die, ns_exists, nsx, no_offload, need_root and the kvm_* functions.

# name  node  data-MAC  address  gateway  port-MAC (node side)  mgmt-IP  mgmt-TAP
OV_GUESTS=(
  "red1 1 02:00:00:01:01:11 10.1.1.11/24 10.1.1.1 02:00:00:0a:01:01 10.99.0.21 mr1"
  "blue1 1 02:00:00:02:01:11 10.1.1.11/24 10.1.1.1 02:00:00:0a:01:02 10.99.0.22 mb1"
  "red2 2 02:00:00:01:02:12 10.1.1.12/24 10.1.1.1 02:00:00:0a:02:01 10.99.0.23 mr2"
  "red3 2 02:00:00:01:02:13 10.1.2.13/24 10.1.2.1 02:00:00:0a:02:02 10.99.0.24 mr3"
  "blue2 2 02:00:00:02:02:12 10.1.1.12/24 10.1.1.1 02:00:00:0a:02:03 10.99.0.25 mb2"
)
OV_NODES=(1 2)

# shellcheck source=lab/overlay/underlay.sh
. "$ROOT/lab/overlay/underlay.sh"

# The kind marker namespaces come first, so an interrupted `up` is still recognised as this kind.
overlay_markers() { # kvm|harness
  local ns
  for ns in mvr-cn2 mvr-cn1; do ns_exists "$ns" || ip netns add "$ns"; done
  if [ "$1" = kvm ]; then ns_exists mvr-mgmt || ip netns add mvr-mgmt; fi
}

overlay_nodes_isolation() {
  local ns
  for ns in mvr-cn1 mvr-cn2; do
    nsx "$ns" ip link set lo up
    nsx "$ns" sysctl -qw net.ipv4.ip_forward=0
  done
}

lab_up_overlay_harness() {
  need_root
  refuse_other_kind overlay/harness
  check_collisions
  overlay_markers harness
  overlay_nodes_isolation
  local spec name node vmmac addr gw pmac mip mtap cn
  for spec in "${OV_GUESTS[@]}"; do
    read -r name node vmmac addr gw pmac mip mtap <<<"$spec"
    cn=mvr-cn$node
    ns_exists "mvr-$name" || ip netns add "mvr-$name"
    nsx "mvr-$name" ip link set lo up
    if ! nsx "mvr-$name" ip link show eth0 >/dev/null 2>&1 || ! nsx $cn ip link show "$name" >/dev/null 2>&1; then
      nsx "mvr-$name" ip link del eth0 2>/dev/null || true
      nsx $cn ip link del "$name" 2>/dev/null || true
      nsx $cn ip link add "$name" address "$pmac" type veth peer name eth0 address "$vmmac" netns "mvr-$name"
    fi
    nsx "mvr-$name" sysctl -qw net.ipv6.conf.eth0.disable_ipv6=1 || echo "warning: cannot disable IPv6 on mvr-$name" >&2
    no_offload "mvr-$name" eth0
    no_offload $cn "$name"
    nsx "mvr-$name" ip link set eth0 up
    nsx "mvr-$name" ip addr replace "$addr" dev eth0
    nsx "mvr-$name" ip route replace default via "$gw" dev eth0
    nsx $cn sysctl -qw "net.ipv4.conf.$name.arp_ignore=8"
    nsx $cn sysctl -qw "net.ipv6.conf.$name.disable_ipv6=1" || echo "warning: cannot disable IPv6 on $cn/$name" >&2
    nsx $cn ip link set "$name" up
  done
  underlay_up
  echo "lab up (overlay/harness): mvr-cn1 mvr-cn2 mvr-ul + 5 namespace VMs"
}

lab_up_overlay_kvm() {
  local rc=0 vm avail todo=() state
  "$ROOT/scripts/check-prereqs.sh" --kvm >&2 || rc=$?
  [ "$rc" -eq 0 ] || exit "$rc"
  if [ "$(id -u)" -ne 0 ] || [ -z "${SUDO_UID:-}" ] || [ "$SUDO_UID" = 0 ]; then
    echo "lab.sh: run via sudo from your own user; QEMU never runs as root" >&2
    exit 2
  fi
  refuse_other_kind overlay/kvm
  kvm_use_topo overlay
  avail=$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo)
  if [ -z "$(for vm in "${KVM_GUESTS[@]}"; do kvm_pid "$vm"; done)" ] && [ "$avail" -lt "$KVM_MIN_MB" ]; then
    die "need $KVM_MIN_MB MB available for 5 guests, have $avail MB"
  fi
  check_collisions
  overlay_markers kvm
  kvm_image_fetch
  kvm_image_verify
  kvm_image_layer
  kvm_net_up
  underlay_up
  kvm_keys
  for vm in "${KVM_GUESTS[@]}"; do
    state=$(kvm_guest_state "$vm")
    case "$state" in
      ready|booting) ;;
      *) kvm_stop_guest "$vm"; kvm_seed "$vm"; kvm_boot "$vm"; todo+=("$vm") ;;
    esac
  done
  for vm in "${KVM_GUESTS[@]}"; do
    [ "$(kvm_guest_state "$vm")" = booting ] && todo+=("$vm")
  done
  if [ ${#todo[@]} -gt 0 ]; then
    mapfile -t todo < <(printf '%s\n' "${todo[@]}" | sort -u)
    kvm_wait_all "${todo[@]}" || exit 1
  fi
  echo "lab up (overlay/kvm): mvr-cn1 mvr-cn2 mvr-ul + red1 blue1 red2 red3 blue2, mgmt $KVM_MGMT_NS"
}

# run [--node cn1|cn2] [--config FILE]: one minivrd per compute node with its shipped config
lab_run_overlay() {
  need_root
  local only="" config=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --node) [ $# -ge 2 ] || die "--node needs cn1 or cn2"; only=$2; shift 2 ;;
      --config) [ $# -ge 2 ] || die "--config needs a file"; config=$2; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  case "$only" in ""|cn1|cn2) ;; *) die "--node must be cn1 or cn2" ;; esac
  [ -z "$config" ] || [ -n "$only" ] || die "--config needs --node for the overlay lab"
  local bin="$ROOT/build/$BUILD/minivrd" ctl="$ROOT/build/$BUILD/vrctl" n node cfg variant
  [ -x "$bin" ] && [ -x "$ctl" ] || die "build first: cmake --preset $BUILD && cmake --build --preset $BUILD"
  ns_exists mvr-cn2 || die "overlay lab is not up (run: sudo make lab TOPO=overlay)"
  variant=$(lab_kind)
  mkdir -p "$LAB_OUT"
  for n in 1 2; do
    node=cn$n
    [ -z "$only" ] || [ "$only" = "$node" ] || continue
    cfg=${config:-$ROOT/lab/overlay/$node.conf}
    [ -f "$cfg" ] || die "config not found: $cfg"
    stop_forwarder_file "$LAB_OUT/minivrd-$node.pid"
    echo "identity minivrd=$(sha256sum "$bin" | awk '{print $1}') config=$(sha256sum "$cfg" | awk '{print $1}') mode=$variant" >>"$LAB_OUT/minivrd-$node.log"
    rm -rf "/run/mvr-$node"
    install -d -m 0700 -o root -g root "/run/mvr-$node"
    # shellcheck disable=SC2086
    setsid ip netns exec "mvr-$node" "$bin" --config "$cfg" --sock "/run/mvr-$node/minivr.sock" ${MINIVR_ARGS:-} \
        >>"$LAB_OUT/minivrd-$node.log" 2>&1 </dev/null &
    echo $! >"$LAB_OUT/minivrd-$node.pid"
  done
  local i ok
  for n in 1 2; do
    node=cn$n
    [ -z "$only" ] || [ "$only" = "$node" ] || continue
    ok=0
    for i in $(seq 1 30); do
      if "$ctl" -s "/run/mvr-$node/minivr.sock" version >/dev/null 2>&1; then ok=1; break; fi
      [ -d "/proc/$(cat "$LAB_OUT/minivrd-$node.pid")" ] || { tail -n 20 "$LAB_OUT/minivrd-$node.log" >&2; die "forwarder $node exited during start-up"; }
      sleep 0.1
    done
    [ $ok -eq 1 ] || { tail -n 20 "$LAB_OUT/minivrd-$node.log" >&2; die "forwarder $node did not answer within 3s"; }
    echo "forwarder $node running (pid $(cat "$LAB_OUT/minivrd-$node.pid")), log $LAB_OUT/minivrd-$node.log"
  done
  echo "alias v1='$ctl -s /run/mvr-cn1/minivr.sock'; alias v2='$ctl -s /run/mvr-cn2/minivr.sock'"
}

# replaced by lab/overlay/interop.sh (US6)
lab_interop_up() { die "--interop is not available yet"; }
