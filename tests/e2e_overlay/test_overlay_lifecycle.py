"""US1: bring-up, teardown, exclusion and exit codes (quickstart O1, O14). These tests take the lab
down, so they live apart from the tests that share one running lab. Runs first (alphabetical)."""
import time

from conftest import VARIANT, host_snapshot, lab_args, mvr_ns, run_lab

BRING_UP_BUDGET_S = 15 if VARIANT == "harness" else 120
TEARDOWN_BUDGET_S = 15


def test_lifecycle_times_snapshot_and_exit_codes():
    """SC-001 times, idempotent down, host snapshot identical after teardown (FR-002)."""
    run_lab("down")
    before = host_snapshot()
    t0 = time.monotonic()
    r = run_lab(*lab_args())
    up_s = time.monotonic() - t0
    assert r.returncode == 0, r.stderr
    assert up_s < BRING_UP_BUDGET_S, f"bring-up took {up_s:.0f}s"
    t0 = time.monotonic()
    r = run_lab("down")
    down_s = time.monotonic() - t0
    assert r.returncode == 0 and down_s < TEARDOWN_BUDGET_S, f"teardown took {down_s:.0f}s"
    assert mvr_ns() == []
    assert host_snapshot() == before
    assert run_lab("down").returncode == 0  # nothing to do is not an error


def test_single_node_labs_refuse_while_overlay_is_down_kind_changes():
    """Down, bring up the single harness, then the overlay must refuse it (and vice versa)."""
    run_lab("down")
    try:
        assert run_lab("up", "--harness").returncode == 0
        r = run_lab(*lab_args())
        assert r.returncode == 1
        assert "namespace test harness is up; run 'sudo make lab-clean' first" in r.stderr, r.stderr
        assert "mvr-cn2" not in mvr_ns()
    finally:
        run_lab("down")


def test_without_kvm_exit_3_and_nothing_created():
    """The KVM overlay needs /dev/kvm: a host without it exits 3 and leaves nothing behind."""
    run_lab("down")
    r = run_lab("up", "--topo", "overlay", env={"MINIVR_KVM_DEVICE": "/nonexistent/kvm"})
    assert r.returncode == 3, (r.returncode, r.stderr)
    assert mvr_ns() == []


