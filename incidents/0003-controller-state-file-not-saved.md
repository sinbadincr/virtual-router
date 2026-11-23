# Incident 0003: the controller never saved its state after start-up

| | |
|---|---|
| Date | 2026-11-23 |
| Kind | **Real defect** found while writing the failure tests (phase 3, US3) |
| Severity | medium: a controller restart briefly withdrew routes (about 3% ping loss); no data loss in the lab |
| Build | `debug` preset, `minivr-ctld`, harness lab (`lab/lab.sh up --harness --topo ctl`) |
| Status | closed (lab fix); follow-ups below are **not** done |
| Regression test | `tests/e2e_ctl/test_ctl_lab.py::test_state_file_is_rewritten_after_the_privilege_drop` |

## Symptom

`test_c9_controller_down_for_a_minute_costs_no_packet` failed: after stopping and restarting the
controller, the two background pingers (red1→red2, blue1→blue2) lost about 3% of their packets
(`[3.05882, 2.94118]` instead of `[0.0, 0.0]`), where the design says a controller restart costs no
packet. `ctld.log` carried the clue the whole time, once per change:
`level=error comp=ctl msg="cannot write state file" … errno=13`.

## Timeline

| Step | Event |
|---|---|
| start-up | `minivr-ctld --init lab/ctl/intent.conf` ran as root, wrote `build/lab/ctl/state.conf` (intent only, no bindings), then dropped privileges to `nobody` |
| run | agents connected, bindings and labels were allocated; every `store_save()` failed with `EACCES`, so the file on disk stayed the initial intent |
| restart | the new controller loaded that file: no bindings, no learned node addresses. cn1 reconnected first and got a full sync **without** routes to cn2's VMs (cn2 unknown), the sweep removed them, and they came back when cn2 reconnected |
| diagnosis | `grep "cannot write" build/lab/ctld.log`; `ls -ld` on the path showed `build/lab/ctl` owned by `nobody` but the path to it runs through a home directory that `nobody` cannot traverse |

## Root cause

Two independent facts that were each fine alone:

1. The controller drops to `nobody` after opening its listener and control socket (constitution:
   least privilege). `store_save()` runs afterwards, as `nobody`, and needs to create
   `state.conf.tmp` and `rename` it in the state directory.
2. The lab put that directory under the repository, i.e. under a `0700` home directory. Owning the
   directory (`install -d -o nobody`) is not enough: every parent must be traversable, so `open()`
   failed with `EACCES`. The first state file survived only because it was written *before* the drop.

The controller treated a failed save as a logged event and carried on, so nothing visible broke until
a restart needed the file.

## Fix

`lab/ctl/ctl.sh` starts the controller with `--user "${SUDO_USER:-nobody}"` and creates the state
directory for that user: the invoking user can reach their own repository, and the privilege drop is
unchanged (non-root uid, zero capabilities, `no_new_privs`, self-verified). Re-running the
reproduction below with the fix leaves `state.conf` containing the `bind`, `quarantine` and
`learned` lines, and `test_c9` shows 0% loss (150 of 150 pings across a restart in the demo,
`docs/controller.md`).

## Reproduction

```bash
sudo bash -c 'unset SUDO_USER; lab/lab.sh up --harness --topo ctl && lab/lab.sh run'
grep -c "cannot write state file" build/lab/ctld.log   # > 0
grep -c "^bind " build/lab/ctl/state.conf              # 0: only the intent is on disk
```

With the fix (`SUDO_USER` set, as under `sudo` from your own account) the first count is 0 and the
second is 5. The regression test asserts the file content and the absence of the log line, and was
run both ways: it fails with `nobody` and passes with the invoking user.

## Lessons and follow-ups (not implemented)

- **A failed save must not be silent.** `ctl_commit()` logs and continues; a controller that cannot
  persist is a controller whose next restart loses labels. Candidates: count failures in
  `stats show` (`state_write_errors`), show a persistent warning in `node show`, or refuse
  changes that cannot be saved.
- **Check writability at start-up, after the drop.** A one-line probe (create and remove a temp file
  in the state directory) would have turned this into a start-up error with the path in the message,
  as the constitution asks for the other start-up checks.
- The label-withdrawal on restart was a second, smaller design flaw that this defect exposed: a
  controller that knows a node's VMIs but not yet its underlay address omits the routes. Persisting
  `learned node …` (done, see `docs/controller.md`) removes it for restarts; an unreachable node still
  withholds routes to it by design.
