# shellcheck shell=bash
# KVM lab building blocks (the default lab), sourced by lab/lab.sh (contracts/lab-kvm.md, research R1-R11).
# Needs from lab.sh: ROOT, CN, die, ns_exists, nsx, no_offload. Everything here only creates or
# removes mvr-* namespaces, mvr-vmN processes, /run/mvr-kvm and build/lab/kvm.

KVM_MGMT_NS=mvr-mgmt
KVM_RUN=/run/mvr-kvm
KVM_OUT="$ROOT/build/lab/kvm"
KVM_LOGS="$KVM_OUT/logs"
# Guest table of the active topology (kvm_use_topo): single = vm1..3 behind mvr-cn1 (unchanged);
# overlay = red1 blue1 (mvr-cn1) red2 red3 blue2 (mvr-cn2), the table in lab/overlay/overlay.sh.
KVM_ALL_GUESTS=(vm1 vm2 vm3 red1 blue1 red2 red3 blue2)
KVM_GUESTS=()
KVM_NODES=()
declare -A KVM_NODE_NS KVM_PORT KVM_PORT_MAC KVM_MTAP KVM_MGMT_IP KVM_DATA_MAC KVM_DATA_ADDR
KVM_MIN_MB=768

kvm_use_topo() { # single | overlay
  KVM_GUESTS=(); KVM_NODES=()
  KVM_NODE_NS=(); KVM_PORT=(); KVM_PORT_MAC=(); KVM_MTAP=(); KVM_MGMT_IP=(); KVM_DATA_MAC=(); KVM_DATA_ADDR=()
  if [ "$1" = overlay ]; then
    local spec name node mac addr gw pmac mip mtap
    KVM_NODES=(mvr-cn1 mvr-cn2)
    KVM_MIN_MB=1280
    for spec in "${OV_GUESTS[@]}"; do
      read -r name node mac addr gw pmac mip mtap <<<"$spec"
      KVM_GUESTS+=("$name")
      KVM_NODE_NS[$name]=mvr-cn$node
      KVM_PORT[$name]=$name
      KVM_PORT_MAC[$name]=$pmac
      KVM_MTAP[$name]=$mtap
      KVM_MGMT_IP[$name]=$mip
      KVM_DATA_MAC[$name]=$mac
      KVM_DATA_ADDR[$name]=$addr
    done
  else
    KVM_NODES=($CN)
    KVM_MIN_MB=768
    KVM_GUESTS=(vm1 vm2 vm3)
    KVM_NODE_NS=([vm1]=$CN [vm2]=$CN [vm3]=$CN)
    KVM_PORT=([vm1]=p1 [vm2]=p2 [vm3]=p3)
    KVM_PORT_MAC=([vm1]=02:00:00:00:00:01 [vm2]=02:00:00:00:00:02 [vm3]=02:00:00:00:00:03)
    KVM_MTAP=([vm1]=m1 [vm2]=m2 [vm3]=m3)
    KVM_MGMT_IP=([vm1]=10.99.0.11 [vm2]=10.99.0.12 [vm3]=10.99.0.13)
    KVM_DATA_MAC=([vm1]=02:00:00:00:01:01 [vm2]=02:00:00:00:01:02 [vm3]=02:00:00:00:01:03)
    KVM_DATA_ADDR=([vm1]=10.0.1.11/24 [vm2]=10.0.1.12/24 [vm3]=10.0.2.13/24)
  fi
}

# ---- image (R2) -------------------------------------------------------------------------------
# shellcheck source=lab/kvm/image.lock
. "$ROOT/lab/kvm/image.lock"

kvm_owner() { echo "${SUDO_UID:-0}:${SUDO_GID:-0}"; }

kvm_image_dir() { echo "${MINIVR_KVM_CACHE:-$ROOT/build/cache/images}"; }
kvm_image_path() { echo "$(kvm_image_dir)/$CIRROS_FILE"; }

kvm_image_fetch() {
  local path dir
  path=$(kvm_image_path); dir=$(dirname "$path")
  [ -f "$path" ] && return 0
  mkdir -p "$dir"
  echo "downloading $CIRROS_FILE ..." >&2
  curl -fL --retry 2 -o "$path.part" "$CIRROS_URL" || { rm -f "$path.part"; die "download failed: $CIRROS_URL"; }
  if [ "$(sha256sum "$path.part" | awk '{print $1}')" != "$CIRROS_SHA256" ]; then
    rm -f "$path.part"
    die "image checksum mismatch (deleted); re-run to download again"
  fi
  mv "$path.part" "$path"
  chown "$(kvm_owner)" "$dir" "$path"
}

kvm_image_verify() {
  local path
  path=$(kvm_image_path)
  [ -f "$path" ] || die "image missing: $path"
  if [ "$(sha256sum "$path" | awk '{print $1}')" != "$CIRROS_SHA256" ]; then
    rm -f "$path"
    die "image checksum mismatch (deleted); re-run to download again"
  fi
}

# The layer of research R15 (thin qcow2 over the golden image, recipe in lab/kvm/image-patch/).
# image.py verifies every pin (recipe hash, logical hash, backing file) and rebuilds when needed.
KVM_LAYER=""
kvm_image_layer() {
  local cache out
  cache=$(kvm_image_dir)
  out=$("$ROOT/lab/kvm/image.py" ensure --lock "$ROOT/lab/kvm/image.lock" --cache "$cache" \
        --patch-dir "$ROOT/lab/kvm/image-patch") || die "image layer failed (see image.py message above)"
  KVM_LAYER=$out
  chown "$(kvm_owner)" "$cache" "$KVM_LAYER" "$KVM_LAYER.json" 2>/dev/null || true
}

# ---- network (R4, R7) -------------------------------------------------------------------------
kvm_tap() { # ns name mac [master]
  local ns=$1 name=$2 mac=$3 master=${4:-}
  if ! nsx "$ns" ip link show "$name" >/dev/null 2>&1; then
    nsx "$ns" ip tuntap add dev "$name" mode tap vnet_hdr user "${SUDO_UID:?}" group "${SUDO_GID:?}"
  fi
  [ -z "$mac" ] || nsx "$ns" ip link set "$name" address "$mac"
  [ -z "$master" ] || nsx "$ns" ip link set "$name" master "$master"
}

kvm_net_up() {
  local ns vm port node
  for ns in "${KVM_NODES[@]}" $KVM_MGMT_NS; do
    ns_exists "$ns" || ip netns add "$ns"
    nsx "$ns" ip link set lo up
  done
  # phase 1 isolation of every compute node
  for ns in "${KVM_NODES[@]}"; do nsx "$ns" sysctl -qw net.ipv4.ip_forward=0; done
  # management namespace: IPv6 off before any device exists, so every device inherits it
  nsx $KVM_MGMT_NS sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 \
    || echo "warning: cannot disable IPv6 in $KVM_MGMT_NS" >&2
  if ! nsx $KVM_MGMT_NS ip link show br0 >/dev/null 2>&1; then
    nsx $KVM_MGMT_NS ip link add br0 type bridge
    nsx $KVM_MGMT_NS ip addr add 10.99.0.1/24 dev br0
  fi
  nsx $KVM_MGMT_NS ip link set br0 up
  for vm in "${KVM_GUESTS[@]}"; do
    port=${KVM_PORT[$vm]}
    node=${KVM_NODE_NS[$vm]}
    kvm_tap "$node" "$port" "${KVM_PORT_MAC[$vm]}"
    nsx "$node" sysctl -qw "net.ipv4.conf.$port.arp_ignore=8"
    nsx "$node" sysctl -qw "net.ipv6.conf.$port.disable_ipv6=1" || echo "warning: cannot disable IPv6 on $node/$port" >&2
    no_offload "$node" "$port"
    nsx "$node" ip link set "$port" up
    kvm_tap $KVM_MGMT_NS "${KVM_MTAP[$vm]}" "" br0
    nsx $KVM_MGMT_NS ip link set "${KVM_MTAP[$vm]}" up
  done
}

# ---- keys, seeds (R3) -------------------------------------------------------------------------
kvm_keys() {
  install -d -m 0700 -o root -g root "$KVM_RUN"
  if [ ! -f "$KVM_RUN/id_ed25519" ]; then
    ssh-keygen -q -t ed25519 -N '' -C mvr-lab -f "$KVM_RUN/id_ed25519"
  fi
}

kvm_seed() { # vmN
  local vm=$1 dir="$KVM_OUT/$1" img
  [ -n "$KVM_LAYER" ] || kvm_image_layer
  img=$(realpath "$KVM_LAYER")
  rm -rf "$dir"
  # a new overlay is a new machine: it generates new SSH host keys, so forget the old ones
  # (known_hosts lives in the root-only /run/mvr-kvm and is only used on the lab's mgmt namespace)
  ssh-keygen -q -R "${KVM_MGMT_IP[$vm]}" -f "$KVM_RUN/known_hosts" >/dev/null 2>&1 || true
  rm -f "$KVM_RUN/known_hosts.old"
  mkdir -p "$dir/seed" "$KVM_LOGS"
  qemu-img create -q -f qcow2 -b "$img" -F qcow2 "$dir/disk.qcow2"
  # chain: guest overlay <- layer <- golden image (3 images)
  [ "$(qemu-img info --backing-chain --output=json "$dir/disk.qcow2" | jq length)" -eq 3 ] \
    || die "unexpected backing chain for $vm (want overlay <- layer <- golden)"
  "$ROOT/lab/kvm/launch.py" seed "$dir/seed" --name "$vm" --pubkey "$KVM_RUN/id_ed25519.pub"
  genisoimage -quiet -o "$dir/config-2.iso" -V config-2 -J -r "$dir/seed"
  chown -R "$(kvm_owner)" "$KVM_OUT"
}

# ---- access and state (R7, R8) ----------------------------------------------------------------
kvm_ssh() { # vmN [CMD...]
  local vm=$1; shift
  local tty=() bound=()
  [ $# -eq 0 ] && [ -t 0 ] && tty=(-t)
  [ -n "${KVM_SSH_MAXTIME:-}" ] && bound=(timeout "$KVM_SSH_MAXTIME")  # probes only, never a shell
  "${bound[@]}" ip netns exec $KVM_MGMT_NS ssh "${tty[@]}" -i "$KVM_RUN/id_ed25519" \
    -o UserKnownHostsFile="$KVM_RUN/known_hosts" -o StrictHostKeyChecking=accept-new \
    -o BatchMode=yes -o ConnectTimeout="${KVM_SSH_TIMEOUT:-5}" -o LogLevel=ERROR \
    "cirros@${KVM_MGMT_IP[$vm]}" "$@"
}

kvm_pid() { # vmN -> pid if the process is alive and ours, else empty
  local pid
  pid=$(cat "$KVM_RUN/$1.pid" 2>/dev/null) || return 0
  if [ -n "$pid" ] && [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "mvr-$1" ]; then echo "$pid"; fi
}

kvm_guest_state() { # vmN -> booting|ready|stopped|failed
  local vm=$1 log="$KVM_LOGS/$1.console.log" pid
  pid=$(kvm_pid "$vm")
  if [ -z "$pid" ]; then
    [ -f "$KVM_RUN/$vm.failed" ] && { echo failed; return; }
    echo stopped; return
  fi
  if grep -q "MVR-FAILED $vm" "$log" 2>/dev/null || [ -f "$KVM_RUN/$vm.failed" ]; then echo failed; return; fi
  if grep -q "MVR-READY $vm" "$log" 2>/dev/null && KVM_SSH_TIMEOUT=2 KVM_SSH_MAXTIME=5 kvm_ssh "$vm" true </dev/null >/dev/null 2>&1; then
    echo ready; return
  fi
  echo booting
}

# ---- boot, wait, stop (R8) --------------------------------------------------------------------
kvm_stop_guest() { # vmN
  local vm=$1 pid i
  pid=$(kvm_pid "$vm")
  if [ -n "$pid" ]; then
    kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 50); do [ -d "/proc/$pid" ] || break; sleep 0.1; done
    [ -d "/proc/$pid" ] && kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$KVM_RUN/$vm.pid" "$KVM_RUN/$vm.failed"
}

kvm_boot() { # vmN
  local vm=$1 dir="$KVM_OUT/$1" uid gid
  uid=${SUDO_UID:?}; gid=${SUDO_GID:?}
  kvm_stop_guest "$vm"
  mkdir -p "$KVM_LOGS"
  : >"$KVM_LOGS/$vm.console.log"
  chown -R "$uid:$gid" "$KVM_OUT"
  setsid "$ROOT/lab/kvm/launch.py" --name "$vm" --uid "$uid" --gid "$gid" \
    --cn-netns "${KVM_NODE_NS[$vm]}" --data-tap "${KVM_PORT[$vm]}" \
    --mgmt-netns $KVM_MGMT_NS --mgmt-tap "${KVM_MTAP[$vm]}" \
    --pidfile "$KVM_RUN/$vm.pid" --console "$KVM_LOGS/$vm.console.log" \
    --disk "$dir/disk.qcow2" --config-drive "$dir/config-2.iso" \
    </dev/null >"$KVM_LOGS/$vm.launch.log" 2>&1 &
}

kvm_wait_ready() { # vmN
  local vm=$1 timeout=${MINIVR_KVM_BOOT_TIMEOUT:-120} t=0 log="$KVM_LOGS/$1.console.log"
  local seen_marker=0 last_err=""
  while [ "$t" -lt "$timeout" ]; do
    if grep -q "MVR-FAILED $vm" "$log" 2>/dev/null; then
      touch "$KVM_RUN/$vm.failed"
      echo "$vm reported $(grep "MVR-FAILED $vm" "$log" | tail -n1); console: ${log#"$ROOT"/}" >&2
      tail -n 20 "$log" >&2
      return 1
    fi
    if [ -s "$KVM_LOGS/$vm.launch.log" ] && [ -z "$(kvm_pid "$vm")" ]; then
      touch "$KVM_RUN/$vm.failed"
      echo "$vm failed to start:" >&2; cat "$KVM_LOGS/$vm.launch.log" >&2
      return 1
    fi
    if [ $seen_marker -eq 0 ] && grep -q "MVR-READY $vm" "$log" 2>/dev/null; then seen_marker=1; fi
    if [ $seen_marker -eq 1 ]; then
      if last_err=$(KVM_SSH_MAXTIME=8 kvm_ssh "$vm" true </dev/null 2>&1); then
        rm -f "$KVM_RUN/$vm.failed"
        return 0
      fi
    fi
    # progress, so a slow or failing guest is visible instead of looking stuck
    if [ $((t % 10)) -eq 9 ]; then
      echo "waiting for $vm (${t}s): $([ $seen_marker -eq 1 ] && echo "console ready, ssh not yet: ${last_err:-no answer}" || echo "no MVR-READY on the console yet")" >&2
    fi
    sleep 1; t=$((t + 1))
  done
  touch "$KVM_RUN/$vm.failed"
  echo "$vm not ready after ${timeout}s; console: ${log#"$ROOT"/}" >&2
  [ -z "$last_err" ] || echo "last ssh error: $last_err" >&2
  tail -n 20 "$log" >&2 2>/dev/null || true
  return 1
}

kvm_wait_all() { # vm...
  local vm rc=0 pids=() p
  for vm in "$@"; do kvm_wait_ready "$vm" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  return $rc
}

kvm_stop() {
  local f vm
  shopt -s nullglob
  for f in "$KVM_RUN"/*.pid; do
    vm=$(basename "$f" .pid)
    kvm_stop_guest "$vm"
  done
  for vm in "${KVM_ALL_GUESTS[@]}"; do rm -rf "$KVM_OUT/$vm"; done
  rm -rf "$KVM_RUN"
  shopt -u nullglob
}
