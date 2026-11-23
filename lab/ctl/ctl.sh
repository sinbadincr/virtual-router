# shellcheck shell=bash
# Controller lab (specs/005 contracts/lab-ctl.md): the overlay lab + mvr-ctl + controller + agents.
# Sourced by lab/lab.sh (ROOT, BUILD, LAB_OUT, die, ns_exists, nsx, need_root, lab_kind, overlay_*).

CTL_RUN=/run/mvr-ctl
CTL_SOCK=$CTL_RUN/ctld.sock
CTL_ADDR=10.98.0.254:7700
CTL_NODES=(cn1 cn2)

ctl_bins() {
  CTLD_BIN="$ROOT/build/$BUILD/minivr-ctld"; AGENT_BIN="$ROOT/build/$BUILD/minivr-agent"
  FWD_BIN="$ROOT/build/$BUILD/minivrd"; VRCTL="$ROOT/build/$BUILD/vrctl"
  [ -x "$CTLD_BIN" ] && [ -x "$AGENT_BIN" ] && [ -x "$FWD_BIN" ] && [ -x "$VRCTL" ] ||
    die "build first: cmake --preset $BUILD && cmake --build --preset $BUILD"
}

ctl_node_n() { echo "${1#cn}"; }

pid_alive() { # pidfile
  [ -f "$1" ] && [ -d "/proc/$(cat "$1")" ]
}

# stop <pidfile> [signal]
ctl_stop_pid() {
  local f=$1 sig=${2:-TERM} pid i
  [ -f "$f" ] || return 0
  pid=$(cat "$f")
  if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
    kill -"$sig" "$pid" 2>/dev/null || true
    for i in $(seq 1 50); do [ -d "/proc/$pid" ] || break; sleep 0.1; done
    [ -d "/proc/$pid" ] && kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$f"
}

lab_up_ctl() { # harness(0|1)
  export MINIVR_CTL_UP=1
  if [ "$1" -eq 1 ]; then lab_up_overlay_harness; else lab_up_overlay_kvm; fi
  unset MINIVR_CTL_UP
  "$ROOT/lab/ctl/ctlnet.sh" up "${CTL_NODES[@]}"
  echo "lab up (ctl/$([ "$1" -eq 1 ] && echo harness || echo kvm)): overlay lab + mvr-ctl control network"
}

ctl_start_ctld() {
  ctl_bins
  ctl_stop_pid "$LAB_OUT/ctld.pid"
  mkdir -p "$LAB_OUT/ctl"
  install -d -m 0700 -o nobody "$LAB_OUT/ctl"
  install -d -m 0700 -o root "$CTL_RUN"
  rm -f "$CTL_SOCK"
  setsid ip netns exec mvr-ctl "$CTLD_BIN" --state "$LAB_OUT/ctl/state.conf" --init "$ROOT/lab/ctl/intent.conf" \
      --listen "$CTL_ADDR" --sock "$CTL_SOCK" >>"$LAB_OUT/ctld.log" 2>&1 </dev/null &
  echo $! >"$LAB_OUT/ctld.pid"
  local i
  for i in $(seq 1 50); do
    "$VRCTL" -s "$CTL_SOCK" version >/dev/null 2>&1 && return 0
    pid_alive "$LAB_OUT/ctld.pid" || { tail -n 20 "$LAB_OUT/ctld.log" >&2; die "controller exited during start-up"; }
    sleep 0.1
  done
  die "controller did not answer within 5s"
}

ctl_start_fwd() { # cnN
  ctl_bins
  local node=$1
  ctl_stop_pid "$LAB_OUT/minivrd-$node.pid"
  mkdir -p "$LAB_OUT"
  install -d -m 0700 -o root "/run/mvr-$node"
  echo "identity minivrd=$(sha256sum "$FWD_BIN" | awk '{print $1}') config=$(sha256sum "$ROOT/lab/ctl/$node.conf" | awk '{print $1}') mode=$(lab_kind)" >>"$LAB_OUT/minivrd-$node.log"
  # shellcheck disable=SC2086
  setsid ip netns exec "mvr-$node" "$FWD_BIN" --config "$ROOT/lab/ctl/$node.conf" \
      --sock "/run/mvr-$node/minivr.sock" ${MINIVR_ARGS:-} >>"$LAB_OUT/minivrd-$node.log" 2>&1 </dev/null &
  echo $! >"$LAB_OUT/minivrd-$node.pid"
  local i
  for i in $(seq 1 50); do
    "$VRCTL" -s "/run/mvr-$node/minivr.sock" version >/dev/null 2>&1 && return 0
    pid_alive "$LAB_OUT/minivrd-$node.pid" || { tail -n 20 "$LAB_OUT/minivrd-$node.log" >&2; die "forwarder $node exited during start-up"; }
    sleep 0.1
  done
  die "forwarder $node did not answer within 5s"
}

ctl_start_agent() { # cnN
  ctl_bins
  local node=$1 n; n=$(ctl_node_n "$1")
  ctl_stop_pid "$LAB_OUT/agent-$node.pid"
  install -d -m 0700 -o root "/run/mvr-$node"
  setsid ip netns exec "mvr-$node" "$AGENT_BIN" --node "$node" --controller "$CTL_ADDR" --bind "10.98.0.$n" \
      --fwd-sock "/run/mvr-$node/minivr.sock" --sock "/run/mvr-$node/agent.sock" \
      --state-dir "/run/mvr-$node/agent" >>"$LAB_OUT/agent-$node.log" 2>&1 </dev/null &
  echo $! >"$LAB_OUT/agent-$node.pid"
  local i
  for i in $(seq 1 50); do
    "$VRCTL" -s "/run/mvr-$node/agent.sock" version >/dev/null 2>&1 && return 0
    pid_alive "$LAB_OUT/agent-$node.pid" || { tail -n 20 "$LAB_OUT/agent-$node.log" >&2; die "agent $node exited during start-up"; }
    sleep 0.1
  done
  die "agent $node did not answer within 5s"
}

# plug every guest that has its port in the node, as nova would
ctl_plug_guests() {
  local spec name node rest
  for spec in "${OV_GUESTS[@]}"; do
    read -r name node rest <<<"$spec"
    nsx "mvr-cn$node" ip link show "$name" >/dev/null 2>&1 || continue
    "$VRCTL" -s "/run/mvr-cn$node/agent.sock" plug "$name" port "$name" >/dev/null ||
      echo "warning: plug $name on cn$node failed" >&2
  done
}

ctl_wait_sync() { # seconds
  local i n sync
  for i in $(seq 1 $(( $1 * 10 ))); do
    sync=1
    for n in "${CTL_NODES[@]}"; do
      [ "$("$VRCTL" -j -s "/run/mvr-$n/agent.sock" status 2>/dev/null | jq -r '.data.sync // "none"')" = in-sync ] || sync=0
    done
    # in sync as far as the agents know AND the forwarders really hold the intended state
    if [ $sync -eq 1 ] && python3 "$ROOT/lab/ctl/ctl_diff.py" "$VRCTL" "$CTL_SOCK" /run/mvr >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

lab_run_ctl() {
  need_root
  ns_exists mvr-ctl || die "ctl lab is not up (run: sudo make lab TOPO=ctl)"
  local interop=0 only=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --interop) interop=1; shift ;;
      --node) [ $# -ge 2 ] || die "--node needs cn1 or cn2"; only=$2; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  ctl_bins
  if [ -n "$only" ]; then # restart one forwarder; its agent reconnects and re-programs it
    case "$only" in cn1|cn2) ;; *) die "--node must be cn1 or cn2" ;; esac
    ctl_start_fwd "$only"
    ctl_wait_sync 15 || echo "warning: agents not in sync after 15s" >&2
    return 0
  fi
  rm -rf "$LAB_OUT/ctl"
  ctl_start_ctld
  local n
  for n in "${CTL_NODES[@]}"; do ctl_start_fwd "$n"; done
  for n in "${CTL_NODES[@]}"; do ctl_start_agent "$n"; done
  ctl_plug_guests
  if [ $interop -eq 1 ]; then ctl_interop_routes; fi
  ctl_wait_sync 15 || echo "warning: agents not in sync after 15s" >&2
  echo "controller running (pid $(cat "$LAB_OUT/ctld.pid")), socket $CTL_SOCK"
  echo "alias vc='$VRCTL -s $CTL_SOCK'; alias va1='$VRCTL -s /run/mvr-cn1/agent.sock'; alias v1='$VRCTL -s /run/mvr-cn1/minivr.sock'"
}

# interop endpoint (phase 2): static node + blue route owned by `cli`, outside the controller's model
ctl_interop_routes() {
  local n
  for n in "${CTL_NODES[@]}"; do
    "$VRCTL" -s "/run/mvr-$n/minivr.sock" node add ix ip 172.16.0.3 rmac 02:00:00:ff:00:03 >/dev/null || true
  done
}

lab_ctl_down() {
  local f
  shopt -s nullglob
  for f in "$LAB_OUT"/agent-cn?.pid "$LAB_OUT"/ctld.pid; do ctl_stop_pid "$f"; done
  shopt -u nullglob
  rm -rf "$LAB_OUT/ctl" /run/mvr-ctl /run/mvr-cn3
}

lab_svc() { # stop|start|kill|pause|resume <svc>
  need_root
  local act=${1:-} svc=${2:-}
  case "$svc" in
    ctld) pidf="$LAB_OUT/ctld.pid"; starter=ctl_start_ctld ;;
    agent-cn?) pidf="$LAB_OUT/$svc.pid"; starter="ctl_start_agent ${svc#agent-}" ;;
    minivrd-cn?) pidf="$LAB_OUT/$svc.pid"; starter="ctl_start_fwd ${svc#minivrd-}" ;;
    *) die "usage: $0 svc stop|start|kill|pause|resume ctld|agent-cnN|minivrd-cnN" ;;
  esac
  case "$act" in
    stop) ctl_stop_pid "$pidf" TERM ;;
    kill) ctl_stop_pid "$pidf" KILL ;;
    start)
      # a controller restart keeps its state file: --init is only used when it is missing
      $starter ;;
    pause) kill -STOP "$(cat "$pidf")" ;;
    resume) kill -CONT "$(cat "$pidf")" ;;
    *) die "usage: $0 svc stop|start|kill|pause|resume <svc>" ;;
  esac
}

lab_ctl_cut() { # node [up|down]
  need_root
  "$ROOT/lab/ctl/ctlnet.sh" cut "${1:?node}" "${2:-down}"
}

lab_ctl_diff() {
  ctl_bins
  python3 "$ROOT/lab/ctl/ctl_diff.py" "$VRCTL" "$CTL_SOCK" /run/mvr
}

lab_status_ctl() {
  ctl_bins
  local n
  echo "controller pid: $(pid_alive "$LAB_OUT/ctld.pid" && cat "$LAB_OUT/ctld.pid" || echo none)"
  "$VRCTL" -s "$CTL_SOCK" node show 2>/dev/null || echo "controller not answering"
  for n in "${CTL_NODES[@]}" cn3; do
    pid_alive "$LAB_OUT/agent-$n.pid" || continue
    echo "agent $n pid $(cat "$LAB_OUT/agent-$n.pid"): $("$VRCTL" -j -s "/run/mvr-$n/agent.sock" status 2>/dev/null | jq -r '.data.sync // "?"')"
  done
}
