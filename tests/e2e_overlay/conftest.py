"""Fixtures for the overlay suite (`tests/e2e_overlay`, specs/003-vrf-overlay-tunnels).

The same tests run on two lab variants, chosen by MINIVR_LAB_VARIANT:
  harness  namespace VMs over veth (no KVM needed; `make e2e`)
  kvm      CirrOS guests on TAP ports (`make e2e-kvm`); SKIP only when check-prereqs exits 3
Everything needs root. Time budget: MINIVR_E2E_OVERLAY_BUDGET_S (default 300 s harness, 600 s KVM).
"""
import json
import os
import re
import shutil
import subprocess
import time
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VARIANT = os.environ.get("MINIVR_LAB_VARIANT", "harness")
assert VARIANT in ("harness", "kvm"), "MINIVR_LAB_VARIANT must be harness or kvm"
# overlay (default): static per-node configs; ctl: the same lab driven by controller + agents
TOPO = os.environ.get("MINIVR_OVERLAY_TOPO", "overlay")
assert TOPO in ("overlay", "ctl"), "MINIVR_OVERLAY_TOPO must be overlay or ctl"
# tests about static config contents or the overlay lab's own lifecycle do not apply to the ctl lab
CTL_SKIP_FILES = ("test_cli_overlay.py", "test_overlay_lab.py", "test_overlay_lifecycle.py",
                  "test_interop.py")
# tests that rewrite forwarder tables by hand: the agent would (rightly) put them back
CTL_SKIP_TESTS = ("test_o8_live_reencapsulation_within_one_second",
                  "test_sc005_remote_route_delete_and_add_take_effect_within_one_second",
                  "test_sc002_thousand_pings_every_pair_with_each_encapsulation",
                  "test_us3_5_a_route_added_in_red_exists_only_in_red")
BUDGET_S = int(os.environ.get("MINIVR_E2E_OVERLAY_BUDGET_S", "300" if VARIANT == "harness" else "600"))
LAB = ROOT / "lab" / "lab.sh"
BUILD = os.environ.get("MINIVR_BUILD", "debug")
VRCTL_BIN = ROOT / "build" / BUILD / "vrctl"
LAB_OUT = ROOT / "build" / "lab"

# phase 1 helpers (sh, host_snapshot, ...) without their pytest hooks
_spec = importlib.util.spec_from_file_location("mvr_e2e_common", ROOT / "tests" / "e2e" / "conftest.py")
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)
sh = common.sh
host_snapshot = common.host_snapshot
ARTIFACT_DIR = common.ARTIFACT_DIR

GUESTS = ("red1", "blue1", "red2", "red3", "blue2")
NODE_OF = {"red1": "cn1", "blue1": "cn1", "red2": "cn2", "red3": "cn2", "blue2": "cn2"}
ADDR = {"red1": "10.1.1.11", "blue1": "10.1.1.11", "red2": "10.1.1.12", "red3": "10.1.2.13",
        "blue2": "10.1.1.12"}
GATEWAY = {"red1": "10.1.1.1", "blue1": "10.1.1.1", "red2": "10.1.1.1", "red3": "10.1.2.1",
           "blue2": "10.1.1.1"}
UL_MAC = {"cn1": "02:00:00:ff:00:01", "cn2": "02:00:00:ff:00:02"}
UL_IP = {"cn1": "172.16.0.1", "cn2": "172.16.0.2"}
_session_start = time.monotonic()
_prereq = {"rc": 0, "msg": ""}


# MPLS labels of the shipped lab: fixed by lab/overlay/*.conf, or allocated by the controller
LABEL = {"red1": 1011, "red2": 1012, "red3": 1013}


def refresh_labels():
    """Under the ctl topology read the labels the controller allocated; export them to the
    injector processes (underlay_corpus.py reads MINIVR_LABEL_*)."""
    if TOPO == "ctl":
        r = subprocess.run([str(VRCTL_BIN), "-s", "/run/mvr-ctl/ctld.sock", "-j", "vmi", "show"],
                           capture_output=True, text=True)
        for x in json.loads(r.stdout)["data"]["vmis"]:
            if x["name"] in LABEL and x["label"] is not None:
                LABEL[x["name"]] = x["label"]
    os.environ["MINIVR_LABEL_RED2"] = str(LABEL["red2"])
    os.environ["MINIVR_LABEL_RED3"] = str(LABEL["red3"])


def lab_args(*extra):
    """`up` arguments for the overlay lab of this variant."""
    return ["up", "--topo", TOPO] + (["--harness"] if VARIANT == "harness" else []) + list(extra)


def run_lab(*args, env=None, timeout=300):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([str(LAB), *map(str, args)], capture_output=True, text=True, timeout=timeout, env=e)


def mvr_ns():
    out = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    return sorted(n.split()[0] for n in out.splitlines() if n.split() and n.split()[0].startswith("mvr-"))


def pytest_collection_modifyitems(config, items):
    if TOPO == "ctl":
        why = pytest.mark.skip(reason="not applicable to the controller-driven lab (FR-028)")
        for item in items:
            if item.fspath.basename in CTL_SKIP_FILES or item.name.split("[")[0] in CTL_SKIP_TESTS:
                item.add_marker(why)
    if os.geteuid() != 0:
        skip = pytest.mark.skip(reason="overlay e2e needs root: run with sudo")
        for item in items:
            item.add_marker(skip)
        return
    if VARIANT == "kvm":
        r = subprocess.run([str(ROOT / "scripts" / "check-prereqs.sh"), "--kvm"],
                           capture_output=True, text=True)
        _prereq["rc"], _prereq["msg"] = r.returncode, (r.stderr or r.stdout).strip()
        if r.returncode == 3:
            skip = pytest.mark.skip(reason=f"no KVM on this host: {_prereq['msg']}")
            for item in items:
                item.add_marker(skip)


@pytest.fixture(autouse=True)
def _kvm_host_usable():
    if _prereq["rc"] in (2, 4):
        pytest.fail(f"KVM host misconfigured (exit {_prereq['rc']}): {_prereq['msg']}")


class Vm:
    """A guest: `run` executes a shell command inside it (SSH on KVM, `ip netns exec` on harness)."""

    def __init__(self, name):
        self.name = name
        self.node = NODE_OF[name]
        self.ip = ADDR[name]

    def run(self, cmd, check=True, timeout=60):
        if VARIANT == "kvm":
            r = run_lab("ssh", self.name, cmd, timeout=timeout)
        else:
            r = subprocess.run(["ip", "netns", "exec", f"mvr-{self.name}", "sh", "-c", cmd],
                               capture_output=True, text=True, timeout=timeout)
        if check:
            assert r.returncode == 0, f"{self.name}: {cmd!r} exited {r.returncode}\n{r.stdout}\n{r.stderr}"
        return r

    def ping(self, dst, count=3, interval=0.2, extra="", timeout=300):
        """Run ping; returns (loss_percent, ttl_set, stdout). Intervals below 0.2 s need root."""
        sudo = "sudo " if VARIANT == "kvm" else ""
        r = self.run(f"{sudo}ping -c {count} -i {interval} -W 1 {extra} {dst}", check=False, timeout=timeout)
        out = r.stdout
        m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
        loss = float(m.group(1)) if m else 100.0
        return loss, set(re.findall(r"ttl=(\d+)", out)), out


def vm(name):
    return Vm(name)


def v(node, *args, json_out=True):
    """vrctl against one forwarder: parsed JSON (-j) or stdout text."""
    sock = f"/run/mvr-{node}/minivr.sock"
    if json_out:
        r = sh(VRCTL_BIN, "-s", sock, "-j", *args, check=False)
        if r.returncode not in (0, 1):
            raise RuntimeError(f"vrctl {node} exit {r.returncode}: {r.stderr}")
        return json.loads(r.stdout)
    return sh(VRCTL_BIN, "-s", sock, *args, check=True).stdout


def vc(node, *args):
    """vrctl command that must succeed; returns the parsed response."""
    r = v(node, *args)
    assert r["ok"] is True, f"vrctl {node} {' '.join(map(str, args))}: {r}"
    return r


def reasons(node):
    return v(node, "stats", "show")["data"]["drops"]["reasons"]


@pytest.fixture()
def fresh(overlay_lab):
    """Both forwarders freshly started with the shipped configs (zeroed counters and tables)."""
    r = run_lab("run")
    assert r.returncode == 0, r.stderr
    refresh_labels()
    yield forwarder_pids()


def forwarder_pids():
    out = {}
    for n in ("cn1", "cn2"):
        f = LAB_OUT / f"minivrd-{n}.pid"
        out[n] = int(f.read_text()) if f.exists() else None
    return out


def ns_exec(ns, *cmd, check=True, timeout=60):
    return common.ns_exec(ns, *cmd, check=check, timeout=timeout)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """On failure keep both forwarder logs, tables, lab status and (KVM) guest consoles."""
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call" or not rep.failed or os.geteuid() != 0:
        return
    d = ARTIFACT_DIR / item.name
    d.mkdir(parents=True, exist_ok=True)
    for n in ("cn1", "cn2"):
        log = LAB_OUT / f"minivrd-{n}.log"
        if log.exists():
            (d / log.name).write_text(log.read_text())
        for name, args in (("stats", ("stats", "show")), ("routes", ("route", "show")),
                           ("neighbours", ("neigh", "show")), ("ports", ("port", "show")),
                           ("nodes", ("node", "show")), ("tunnel", ("tunnel", "show"))):
            r = subprocess.run([str(VRCTL_BIN), "-s", f"/run/mvr-{n}/minivr.sock", "-j", *args],
                               capture_output=True, text=True)
            (d / f"{n}-{name}.json").write_text(r.stdout or r.stderr)
    logs = LAB_OUT / "kvm" / "logs"
    if logs.is_dir():
        for f in logs.iterdir():
            shutil.copy(f, d / f.name)
    (d / "lab-status.txt").write_text(run_lab("status").stdout)
    (d / "host-snapshot.json").write_text(run_lab("snapshot").stdout)


@pytest.fixture(scope="session", autouse=True)
def _session_guard():
    """Host network identical after the run; time budget respected."""
    if os.geteuid() != 0 or _prereq["rc"] != 0:
        yield
        return
    run_lab("down")
    before = host_snapshot()
    yield
    run_lab("down")
    after = host_snapshot()
    assert before == after, "host network state changed during the overlay e2e run"
    elapsed = time.monotonic() - _session_start
    assert elapsed <= BUDGET_S, f"overlay e2e took {elapsed:.0f}s, budget {BUDGET_S}s"


@pytest.fixture(scope="module")
def overlay_lab():
    """The overlay lab of this variant is up (idempotent); the session guard tears it down."""
    r = run_lab(*lab_args())
    assert r.returncode == 0, f"up failed ({r.returncode}):\n{r.stderr}"
    yield


@pytest.fixture(scope="module")
def forwarders(overlay_lab):
    """Fresh minivrd on both nodes with the shipped lab/overlay configs."""
    r = run_lab("run")
    assert r.returncode == 0, r.stderr
    refresh_labels()
    yield forwarder_pids()
