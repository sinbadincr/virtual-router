"""Fixtures for the controller/agent suite (`tests/e2e_ctl`, specs/005-agent-controller).

Variants (MINIVR_LAB_VARIANT): harness = namespace VMs (`make e2e`), kvm = CirrOS guests
(`make e2e-kvm`, SKIP only when check-prereqs exits 3). Needs root except test_fakepeer_codec.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VARIANT = os.environ.get("MINIVR_LAB_VARIANT", "harness")
assert VARIANT in ("harness", "kvm")
LAB = ROOT / "lab" / "lab.sh"
BUILD = os.environ.get("MINIVR_BUILD", "debug")
VRCTL_BIN = ROOT / "build" / BUILD / "vrctl"
LAB_OUT = ROOT / "build" / "lab"
CTLD_SOCK = "/run/mvr-ctl/ctld.sock"
BUDGET_S = int(os.environ.get("MINIVR_E2E_CTL_BUDGET_S", "600" if VARIANT == "harness" else "1500"))

_spec = importlib.util.spec_from_file_location("mvr_e2e_common", ROOT / "tests" / "e2e" / "conftest.py")
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)
sh = common.sh
host_snapshot = common.host_snapshot
ARTIFACT_DIR = common.ARTIFACT_DIR

GUESTS = ("red1", "blue1", "red2", "red3", "blue2")
NODE_OF = {"red1": "cn1", "blue1": "cn1", "red2": "cn2", "red3": "cn2", "blue2": "cn2",
           "red4": "cn3", "red5": "cn2"}
ADDR = {"red1": "10.1.1.11", "blue1": "10.1.1.11", "red2": "10.1.1.12", "red3": "10.1.2.13",
        "blue2": "10.1.1.12", "red4": "10.1.1.14", "red5": "10.1.2.15"}
_start = time.monotonic()
_prereq = {"rc": 0, "msg": ""}


def lab_args(*extra):
    return ["up", "--topo", "ctl"] + (["--harness"] if VARIANT == "harness" else []) + list(extra)


def run_lab(*args, env=None, timeout=600):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([str(LAB), *map(str, args)], capture_output=True, text=True, timeout=timeout, env=e)


def mvr_ns():
    out = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    return sorted(n.split()[0] for n in out.splitlines() if n.split() and n.split()[0].startswith("mvr-"))


def _vr(sock, *args, check=True):
    r = subprocess.run([str(VRCTL_BIN), "-s", sock, "-j", *map(str, args)], capture_output=True, text=True)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"vrctl {sock} {args}: exit {r.returncode} {r.stderr}")
    return json.loads(r.stdout)


def ctl(*args):
    """Controller command; returns the whole envelope."""
    return _vr(CTLD_SOCK, *args)


def ctl_ok(*args):
    r = ctl(*args)
    assert r["ok"], f"ctld {' '.join(map(str, args))}: {r}"
    return r["data"]


def agent(node, *args):
    return _vr(f"/run/mvr-{node}/agent.sock", *args)


def agent_ok(node, *args):
    r = agent(node, *args)
    assert r["ok"], f"agent {node} {' '.join(map(str, args))}: {r}"
    return r["data"]


def fwd(node, *args):
    return _vr(f"/run/mvr-{node}/minivr.sock", *args)


def fwd_ok(node, *args):
    r = fwd(node, *args)
    assert r["ok"], f"minivrd {node} {' '.join(map(str, args))}: {r}"
    return r["data"]


def wait_for(cond, timeout=10.0, interval=0.1, what="condition"):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


def ctl_diff():
    r = run_lab("ctl-diff")
    return r.returncode, r.stdout + r.stderr


def wait_converged(timeout=10.0):
    wait_for(lambda: ctl_diff()[0] == 0, timeout, 0.3, "ctl-diff to be clean")


def node_states():
    return {n["name"]: n for n in ctl_ok("node", "show")["nodes"]}


def vm_exec(name, cmd, check=True, timeout=60):
    if VARIANT == "kvm":
        r = run_lab("ssh", name, cmd, timeout=timeout)
    else:
        r = subprocess.run(["ip", "netns", "exec", f"mvr-{name}", "sh", "-c", cmd],
                           capture_output=True, text=True, timeout=timeout)
    if check:
        assert r.returncode == 0, f"{name}: {cmd!r}: {r.stdout}{r.stderr}"
    return r


def ping_ok(src, dst, count=2, wait=1):
    sudo = "sudo " if VARIANT == "kvm" else ""
    r = vm_exec(src, f"{sudo}ping -c {count} -W {wait} {dst}", check=False)
    return r.returncode == 0


def pytest_collection_modifyitems(config, items):
    needs_root = [i for i in items if "fakepeer_codec" not in i.fspath.basename]
    if os.geteuid() != 0:
        for item in needs_root:
            item.add_marker(pytest.mark.skip(reason="ctl e2e needs root: run with sudo"))
        return
    if VARIANT == "kvm":
        r = subprocess.run([str(ROOT / "scripts" / "check-prereqs.sh"), "--kvm"], capture_output=True, text=True)
        _prereq["rc"], _prereq["msg"] = r.returncode, (r.stderr or r.stdout).strip()
        if r.returncode == 3:
            for item in needs_root:
                item.add_marker(pytest.mark.skip(reason=f"no KVM on this host: {_prereq['msg']}"))


@pytest.fixture(autouse=True)
def _kvm_host_usable(request):
    if "fakepeer_codec" in request.node.fspath.basename:
        return
    if _prereq["rc"] in (2, 4):
        pytest.fail(f"KVM host misconfigured (exit {_prereq['rc']}): {_prereq['msg']}")


@pytest.fixture(scope="session", autouse=True)
def _session_guard(request):
    if os.geteuid() != 0 or _prereq["rc"] != 0 or not any("fakepeer" not in i.fspath.basename for i in request.session.items):
        yield
        return
    run_lab("down")
    before = host_snapshot()
    yield
    run_lab("down")
    assert before == host_snapshot(), "host network state changed during the ctl e2e run"
    assert time.monotonic() - _start <= BUDGET_S, f"ctl e2e exceeded {BUDGET_S}s"


@pytest.fixture(scope="module")
def ctl_lab():
    """ctl lab up and running (controller, forwarders, agents, guests plugged), converged."""
    r = run_lab(*lab_args())
    assert r.returncode == 0, f"up failed ({r.returncode}):\n{r.stderr}"
    r = run_lab("run")
    assert r.returncode == 0, f"run failed:\n{r.stdout}\n{r.stderr}"
    wait_converged(15)
    yield


@pytest.fixture(scope="module")
def fresh_lab(ctl_lab):
    return ctl_lab


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call" or not rep.failed or os.geteuid() != 0:
        return
    d = ARTIFACT_DIR / item.name
    d.mkdir(parents=True, exist_ok=True)
    for f in LAB_OUT.glob("*.log"):
        shutil.copy(f, d / f.name)
    for n in ("cn1", "cn2", "cn3"):
        for name, args in (("routes", ("route", "show")), ("tunnel", ("tunnel", "show")), ("ports", ("port", "show"))):
            r = subprocess.run([str(VRCTL_BIN), "-s", f"/run/mvr-{n}/minivr.sock", "-j", *args],
                               capture_output=True, text=True)
            if r.stdout:
                (d / f"{n}-{name}.json").write_text(r.stdout)
        r = subprocess.run([str(VRCTL_BIN), "-s", f"/run/mvr-{n}/agent.sock", "-j", "status"],
                           capture_output=True, text=True)
        if r.stdout:
            (d / f"{n}-agent-status.json").write_text(r.stdout)
    r = subprocess.run([str(VRCTL_BIN), "-s", CTLD_SOCK, "-j", "node", "show"], capture_output=True, text=True)
    (d / "ctld-nodes.json").write_text(r.stdout or r.stderr)
    (d / "lab-status.txt").write_text(run_lab("status").stdout)
    (d / "host-snapshot.json").write_text(run_lab("snapshot").stdout)
