#!/usr/bin/env bash
# One-command end-to-end verification (US5, extended by phase 2 US7): prerequisites -> build -> venv ->
# pytest -> cleanup. Runs the phase 1 suite (unchanged) and then the overlay suite on the same
# lab variant: harness (no KVM) for `make e2e`, KVM guests for `make e2e-kvm`.
# Prints PASS/FAIL/SKIP per check, always tears the lab down, keeps artifacts on failure.
set -u
cd "$(dirname "$0")/../.."
ROOT=$PWD
BUILD="${MINIVR_BUILD:-debug}"
OUT="$ROOT/build/e2e"
STAMP=$(date +%Y%m%d-%H%M%S)
export MINIVR_E2E_ARTIFACTS="$OUT/artifacts/$STAMP"
export MINIVR_BUILD="$BUILD"

cleanup() { "$ROOT/lab/lab.sh" down >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

KVM=0
case "${1:-}" in
    "") ;;
    --kvm) KVM=1 ;;
    *) echo "usage: $0 [--kvm]" >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "e2e needs root: run 'sudo make e2e'" >&2; exit 2; }
scripts/check-prereqs.sh --e2e || exit 2
if [ $KVM -eq 1 ]; then
    # exit 3 = this host has no KVM: the only reason to skip. 2/4 = misconfigured host: FAIL.
    scripts/check-prereqs.sh --kvm
    case $? in
        0) ;;
        3) echo "SKIP  kvm suite: hardware virtualization unavailable"; exit 0 ;;
        *) echo "FAIL  kvm suite: host is not set up for KVM (see above)" >&2; exit 2 ;;
    esac
    SUITE=tests/e2e_kvm REPORT="$OUT/report-kvm.xml" NAME="e2e-kvm"
    OVERLAY_REPORT="$OUT/report-overlay-kvm.xml" VARIANT=kvm
    export MINIVR_E2E_BUDGET_S="${MINIVR_E2E_BUDGET_S:-300}"
else
    SUITE=tests/e2e REPORT="$OUT/report.xml" NAME="e2e"
    OVERLAY_REPORT="$OUT/report-overlay.xml" VARIANT=harness
fi

mkdir -p "$OUT"
case "$BUILD" in
    sandbox*) ;; # hand-built binaries in build/<name>/ (no preset)
    *)
        { cmake --preset "$BUILD" && cmake --build --preset "$BUILD" -j; } >"$OUT/build.log" 2>&1 \
            || { echo "build failed, see $OUT/build.log" >&2; exit 2; }
        ;;
esac

if [ ! -x .venv/bin/pytest ]; then
    if ! python3 -m venv .venv >/dev/null 2>&1; then
        rm -rf .venv
        command -v uv >/dev/null 2>&1 || { echo "cannot create .venv: install python3-venv (apt) or uv" >&2; exit 2; }
        uv venv .venv -q
        uv pip install -q -p .venv/bin/python -r tests/e2e/requirements.txt || exit 2
    else
        .venv/bin/pip install -q -r tests/e2e/requirements.txt || exit 2
    fi
fi

cleanup
rm -f "$REPORT" "$OVERLAY_REPORT"
.venv/bin/pytest -v --junitxml="$REPORT" -o junit_family=xunit2 "$SUITE"
rc=$?
# phase 2: the overlay suite on the same variant; the lab of the first suite is torn down first
cleanup
MINIVR_LAB_VARIANT=$VARIANT .venv/bin/pytest -v --junitxml="$OVERLAY_REPORT" -o junit_family=xunit2 tests/e2e_overlay
rc2=$?
[ $rc -ne 0 ] || rc=$rc2

echo
.venv/bin/python - "$REPORT" "$OVERLAY_REPORT" <<'PY'
import sys, xml.etree.ElementTree as ET
for path, prefix in ((sys.argv[1], ""), (sys.argv[2], "overlay/")):
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as e:
        print(f"FAIL  {prefix}suite: no report ({e})")
        continue
    for tc in root.iter("testcase"):
        state = "PASS"
        if tc.find("failure") is not None or tc.find("error") is not None:
            state = "FAIL"
        elif tc.find("skipped") is not None:
            state = "SKIP"
        print(f"{state}  {prefix}{tc.get('classname', '').split('.')[-1]}::{tc.get('name')}")
PY
if [ $rc -ne 0 ]; then
    echo "$NAME FAILED (artifacts: $MINIVR_E2E_ARTIFACTS)" >&2
else
    echo "$NAME PASSED"
fi
exit $rc
