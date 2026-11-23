"""US3 churn (quickstart C17): seeded random plug/unplug/move/kill/cut operations with recoveries;
afterwards the controller's intent and every forwarder agree and no frame crossed tenants."""
import random
import subprocess
import time

import pytest

from conftest import LAB_OUT, VARIANT, agent, agent_ok, ping_ok, run_lab, wait_converged, wait_for

@pytest.fixture(scope="module", autouse=True)
def _lab(ctl_lab):
    yield


OPS = 100 if VARIANT == "harness" else 20
SEED = 42


class LeakWatch:
    """tcpdump -e inside the stable guests (harness): foreign-tenant source MACs must never show up."""
    GUESTS = {"red1": "02:00:00:02:", "red3": "02:00:00:02:", "blue1": "02:00:00:01:", "blue2": "02:00:00:01:"}

    def __enter__(self):
        self.procs = {}
        if VARIANT != "harness":
            return self
        for g in self.GUESTS:
            self.procs[g] = subprocess.Popen(
                ["ip", "netns", "exec", f"mvr-{g}", "tcpdump", "-i", "eth0", "-e", "-nn", "-l", "-q"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(1)
        return self

    def __exit__(self, *a):
        self.leaks = []
        for g, p in self.procs.items():
            p.terminate()
            out = p.communicate(timeout=10)[0]
            self.leaks += [f"{g}: {l}" for l in out.splitlines() if self.GUESTS[g] in l.split(" > ")[0]]
        return False


def test_c17_churn_converges_and_never_leaks():
    rnd = random.Random(SEED)
    state = {"red5": False, "red2": "cn2", "agent_down": set(), "cut": set(), "red3_plugged": True}
    log = []
    with LeakWatch() as watch:
        for i in range(OPS):
            kind = rnd.choice(["plug_cycle", "back_to_back", "red5", "move", "kill_agent", "cut", "traffic"])
            log.append((i, kind))
            if kind == "plug_cycle" and "cn2" not in state["agent_down"]:
                if state["red3_plugged"]:
                    agent("cn2", "unplug", "red3")
                else:
                    agent("cn2", "plug", "red3", "port", "red3")
                state["red3_plugged"] = not state["red3_plugged"]
            elif kind == "back_to_back" and "cn2" not in state["agent_down"]:
                if state["red3_plugged"]:  # unplug then plug again with no wait in between
                    agent("cn2", "unplug", "red3")
                    agent("cn2", "plug", "red3", "port", "red3")
                else:
                    agent("cn2", "plug", "red3", "port", "red3")
                    agent("cn2", "unplug", "red3")
            elif kind == "red5" and not state["agent_down"] and not state["cut"]:
                run_lab("guest", "stop" if state["red5"] else "start", "red5")
                state["red5"] = not state["red5"]
            elif kind == "move" and not state["agent_down"] and not state["cut"]:
                to = "cn1" if state["red2"] == "cn2" else "cn2"
                run_lab("guest", "move", "red2", to)
                state["red2"] = to
            elif kind == "kill_agent":
                n = rnd.choice(["cn1", "cn2"])
                if n in state["agent_down"]:
                    run_lab("svc", "start", f"agent-{n}")
                    state["agent_down"].discard(n)
                else:
                    run_lab("svc", "kill", f"agent-{n}")
                    state["agent_down"].add(n)
            elif kind == "cut":
                n = rnd.choice(["cn1", "cn2"])
                if n in state["cut"]:
                    run_lab("ctl-cut", n, "up")
                    state["cut"].discard(n)
                else:
                    run_lab("ctl-cut", n, "down")
                    state["cut"].add(n)
            elif kind == "traffic":
                ping_ok("red1", "10.1.1.12", count=1, wait=1)
                ping_ok("blue1", "10.1.1.12", count=1, wait=1)
            time.sleep(rnd.choice([0, 0, 0.05, 0.2]))
        # recoveries
        for n in sorted(state["cut"]):
            run_lab("ctl-cut", n, "up")
        for n in sorted(state["agent_down"]):
            run_lab("svc", "start", f"agent-{n}")
        if not state["red3_plugged"]:
            agent_ok("cn2", "plug", "red3", "port", "red3")
        # a guest the churn moved may have been left half-way by a cut agent: put it back
        if run_lab("guest", "stop", "red5").returncode == 0:
            pass
        t0 = time.monotonic()
        wait_converged(30)
        assert time.monotonic() - t0 <= 30
        for n in ("cn1", "cn2"):
            wait_for(lambda: agent_ok(n, "status")["sync"] == "in-sync", 15, 0.3, f"{n} in sync")
        # tenants still reach their own
        assert ping_ok("red1", "10.1.2.13", count=2) and ping_ok("blue1", "10.1.1.12", count=2)
    assert watch.leaks == [], watch.leaks[:5]
