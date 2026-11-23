#!/usr/bin/env bash
# Merge gate (constitution gates 1-2). Gate 3 is `sudo make e2e` (the phase 1 harness suite, then
# the phase 2 overlay suite on namespace VMs) plus `sudo make e2e-kvm` (the phase 1 KVM suite, then
# the overlay suite on KVM guests; SKIP only on a host without /dev/kvm). Phase 3 adds the controller
# suite and the overlay suite on the controller-driven lab to both.
set -u
cd "$(dirname "$0")/.."
fail=0
gate() { # name, command...
    local name=$1; shift
    if "$@" >"build/check-${name}.log" 2>&1; then
        echo "PASS  $name"
    else
        echo "FAIL  $name (see build/check-${name}.log)"
        fail=1
    fi
}
mkdir -p build

if ! scripts/check-prereqs.sh >build/check-prereqs.log 2>&1; then
    # clang is mandatory for the gate; other missing tools only matter for e2e
    if ! command -v clang >/dev/null 2>&1; then
        echo "FAIL  prereqs: clang not installed" >&2
        cat build/check-prereqs.log >&2
        exit 1
    fi
fi

gate gcc-build   sh -c 'cmake --preset debug && cmake --build --preset debug -j'
gate clang-build sh -c 'cmake --preset clang-debug && cmake --build --preset clang-debug -j'
gate ctest-debug sh -c 'ctest --preset debug'
gate ctest-asan  sh -c 'cmake --preset asan && cmake --build --preset asan -j && ctest --preset asan'
# lab-unit: unit tests of lab/kvm/launch.py (no root, no KVM). Must run at least one test.
lab_unit() {
    local out
    out=$(python3 -m unittest discover -s tests/lab -p 'test_*.py' -v 2>&1) || { echo "$out"; return 1; }
    echo "$out"
    echo "$out" | grep -Eq '^Ran [1-9][0-9]* tests?' || { echo "no lab unit tests found" >&2; return 1; }
}
gate lab-unit lab_unit
if [ -x scripts/check-fastpath.sh ]; then
    gate fastpath scripts/check-fastpath.sh
fi
[ $fail -eq 0 ] && echo "ALL GATES PASSED" || echo "GATES FAILED"
exit $fail
