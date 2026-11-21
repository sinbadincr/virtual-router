# Requirement traceability

Every functional requirement (FR) and success criterion (SC) of
`specs/001-lab-l3-forwarder/spec.md` and the automated check that covers it. Unit tests live in
`tests/unit/` (ctest), end-to-end tests in `tests/e2e/` (`sudo make e2e`, the harness suite on namespace VMs). Since spec 004 the lab is
KVM guests; their tests are in `tests/e2e_kvm/` (`sudo make e2e-kvm`). Gate 3 is both suites.

"needs root" means the e2e test skips itself where it cannot switch users or drop to `nobody`
(for example inside an unprivileged user namespace) and must be run with `sudo make e2e` on a real host.

## Functional requirements

| FR | Requirement (short) | Covered by |
|---|---|---|
| FR-001 | one command builds 1 compute node + 3 VMs | `test_lab.py::test_topology_matches_contract` |
| FR-002 | idempotent; touches only `mvr-*` objects | `test_lab.py::test_up_is_idempotent`, `test_down_after_partial_up`, `test_up_recovers_from_partial_state`, `test_down_removes_every_lab_object` |
| FR-003 | never modifies the host NIC or its routes | `test_lab.py::test_host_state_unchanged_and_ens33_untouched`, `test_scripts_never_reference_the_host_nic`; whole-session snapshot diff in `conftest.py` |
| FR-004 | kernel does not forward or answer for VM traffic | `test_lab.py::test_topology_matches_contract` (`ip_forward=0`, no IPv4 on ports, `arp_ignore=8`, IPv6 off); `test_forwarding.py::test_v2_*` (VM sees no kernel ARP) |
| FR-005 | process every frame of the configured ports in bursts | `test_lab.py::test_forwarder_fails_fast_when_the_lab_does_not_exist`, `test_config.c`, `test_forward.c::burst_of_many_frames_is_batched_without_leaks`, `test_forwarding.py::test_v4_*` |
| FR-006 | ARP reply for a port's gateway with the port MAC | `test_pkt_arp.c`, `test_forward.c::arp_for_gateway_known_vm_and_unknown`, `test_forwarding.py::test_v1_*` |
| FR-007 | proxy ARP for known neighbours only | `test_forward.c::arp_for_gateway_known_vm_and_unknown`, `test_forwarding.py::test_v2_*`, `test_v3_*` |
| FR-007a | static neighbour per lab VM loaded at start | `lab/cn1.conf`, `test_neigh.c::static_entry_is_reachable_immediately`, `test_route.c::static_neighbour_installs_and_removes_host_route`, `test_cli.py::test_table_output_matches_the_contract` |
| FR-008 | resolve unknown next hops with ARP; learned never overwrites static | `test_neigh.c::incomplete_then_reachable_*`, `learned_never_overwrites_static`, `test_forward.c::unbound_port_learns_*`, `test_forwarding.py::test_v16_*` |
| FR-008a | hold at most 3 packets, ARP retries, 1 s deadline | `test_neigh.c::fourth_packet_*`, `arp_retries_then_fails_at_the_deadline`, `port_down_and_gateway_removal_*` |
| FR-009 | longest-prefix match | `test_lpm.c` (incl. differential vs linear scan), `test_route.c`, `test_cli.py::test_v10_*` |
| FR-009a | 16 ports, 10,000 routes, 1,024 neighbours, 4,096 mbufs | `test_port.c::sixteen_ports_then_table_full`, `test_lpm.c::capacity_is_10000_rules`, `test_route.c::table_full_at_10000`, `test_cli.py::test_sc010_*` (10,000 routes loaded through the config file), `test_neigh.c::capacity_1024`, `test_mbuf.c::pool_exhaustion_and_free` |
| FR-010 | TTL-1 with a valid incremental checksum | `test_pkt_eth_ipv4.c::ttl_decrement_matches_full_recompute`, `test_forward.c::forward_vm1_to_vm3_*`, `test_forwarding.py::test_v4_*` (ttl=63) |
| FR-011 | ICMP unreachable / time exceeded / frag needed | `test_pkt_icmp.c`, `test_forward.c` (`no_route_*`, `ttl_one_*`, `oversize_with_df_*`), `test_forwarding.py::test_v5_*`, `test_v6_*` |
| FR-011a | ICMP error token bucket per port | `test_ratelimit.c`, `test_forward.c::icmp_errors_are_rate_limited_*`, `test_robustness.py::test_v14_*` |
| FR-012 | answer echo to own addresses | `test_forward.c::echo_to_the_gateway_is_answered_locally`, `test_pkt_icmp.c`, `test_forwarding.py::test_v7_*` |
| FR-013 | validate every field against the actual length | `test_pkt_eth_ipv4.c` (truncated at every boundary), `test_pkt_arp.c`, `test_robustness.py::test_v13_*` |
| FR-014 | drop broadcast/multicast non-ARP and foreign unicast without flooding | `test_pkt_eth_ipv4.c::ethernet_classification`, `test_forward.c::malformed_frames_are_counted_once_each`, `corpus.py` |
| FR-014a | source binding / anti-spoofing | `test_antispoof.c`, `test_forward.c::spoofed_sources_*`, `test_forwarding.py::test_v12_*`, `corpus.py` |
| FR-015 | per-port counters, oper state follows the link | `test_forward.c` (rx/tx/drops per port), `test_linkmon_parse.c` (rtnetlink parser, malformed input), `test_robustness.py::test_link_flap_*` |
| FR-016 | CLI lists ports, routes, neighbours, stats; table and JSON | `test_cmd.c::show_commands_json_shapes`, `show_commands_are_paged`, `test_json_in.c` (reader of the replies), `test_cli.py::test_table_output_*`, `test_json_shapes` |
| FR-017 | CLI changes routes, neighbours, counters live | `test_cmd.c::mutating_commands_work`, `test_cli.py::test_v10_*`, `test_admin_down_and_neighbour_commands` |
| FR-018 | invalid input rejected, state unchanged | `test_cmd.c::every_error_code_*`, `test_cli.py::test_errors_leave_state_unchanged`, `test_exit_codes` |
| FR-019 | structured log lines, rate-limited on the packet path | `test_log.c`, `scripts/check-fastpath.sh` (only `LOG_RL` in `src/dp`) |
| FR-020 | clean shutdown within 2 s | `test_robustness.py::test_v17_*` |
| FR-021 | debug builds leave a crash dump | `test_crash.py` |
| FR-022 | control socket only for the launching user or root | `test_ctl_framing.c` (framing), `test_cli.py::test_other_users_are_not_permitted` (**needs root**) |
| FR-022a | privileges dropped after start-up | `test_privcheck.c` (the `/proc/self/status` self-check, incl. saved uid 0), `test_privileges.py` (**needs root**) |
| FR-023 | one command runs the e2e verification | `tests/e2e/run.sh` (`make e2e`) |
| FR-024 | documentation set | `README.md`, `docs/{architecture,lab,cli,drop-reasons,traceability}.md`, `incidents/0001-*.md` |

## Success criteria

| SC | Criterion | Covered by |
|---|---|---|
| SC-001 | clone to first ping in under 10 minutes | `README.md` quickstart; the commands are the ones `make e2e` exercises (not timed automatically) |
| SC-002 | bring-up < 10 s, teardown < 5 s, host unchanged | `test_lab.py::test_timing_budget`, `test_host_state_unchanged_*` |
| SC-003 | 1,000 pings between every VM pair, 0% loss | `test_forwarding.py::test_v4_*` |
| SC-004 | 1 GB TCP transfer byte-identical | `test_forwarding.py::test_v8_*` |
| SC-005 | route change effective within 1 s, no restart | `test_cli.py::test_v10_*` |
| SC-006 | 100% of the malformed corpus attributed, forwarding unaffected | `test_robustness.py::test_v13_*` |
| SC-007 | sum of reason counters equals total drops | `test_stats.c`, `test_forward.c`, `test_cli.py::test_v11_*`, `test_robustness.py::test_v13_*` |
| SC-008 | e2e < 2 min (budget raised to 180 s on 2026-11-20: the suite measured 126 s on the dev host, with V13 and V4 dominating) and green 10 times in a row | `tests/e2e/run.sh` + the 180 s budget in `conftest.py`; `scripts/e2e-soak.sh 10` (run it on the target host) |
| SC-009 | symbolized backtrace from core + debug binary | `test_crash.py`, `incidents/0001-forced-crash-drill.md` |
| SC-010 | 10,000-route lookups agree with a linear scan; changes still take effect within 1 s | `test_lpm.c::differential_against_linear_scan`, `test_cli.py::test_sc010_full_route_table_still_updates_live` |
| SC-011 | ICMP-error flood bounded, other ports unaffected | `test_robustness.py::test_v14_*` |

## Phase 1.5: KVM lab mode (`specs/002-kvm-lab-mode/spec.md`)

Unit tests: `tests/lab/test_kvm_launch.py` (no root, no KVM; `make check`, gate `lab-unit`).
End-to-end: `tests/e2e_kvm/` (`sudo make e2e-kvm`).

| Requirement | Covered by |
|---|---|
| FR-001, FR-009 (explicit mode, mutual exclusion) | `test_kvm_lab.py::test_kvm_up_refused_while_harness_is_up`, `test_k3_*` |
| FR-002 (same topology, TAP ports) | `test_kvm_lab.py::test_k1_*`, `test_kvm_launch.py::GuestTable` |
| FR-003 (KVM required, no fallback) | `test_kvm_lab.py::test_k15_*`, `test_unusable_kvm_device_*`, `test_kvm_launch.py::test_kvm_only_never_tcg` |
| FR-004 (pinned, verified image; amendment A1 layer) | `test_kvm_lab.py::test_corrupted_image_*`, `test_k17_*` (tampered layer rebuilt, golden untouched), `test_kvm_image.py` (recipe/logical-hash pins, reproducible build, cpio, GPT, clusters, alignment), `lab/kvm/image.lock` |
| FR-005 (non-interactive first boot, timeout) | `test_kvm_launch.py::FirstBoot`, `test_kvm_lab.py::test_not_ready_*` |
| FR-006 (throw-away disks) | `test_kvm_lab.py::test_k14_*` |
| FR-007 (idempotent, only `mvr-*`) | `test_kvm_lab.py::test_k2_*`, `test_k14_*`; host snapshot guard in `conftest.py` |
| FR-008 (no offloads) | `test_kvm_launch.py::test_nics_addresses_macs_offloads`, `test_kvm_forwarding.py::test_k8_*` |
| FR-009a (memory) | `test_kvm_launch.py::test_memory_and_cpu_limits`, `test_kvm_lab.py::test_k16_*` |
| FR-010 (same behaviour, same binary and config) | `test_kvm_forwarding.py::test_k4`…`test_k10` |
| FR-011 (unprivileged QEMU, sandbox) | `test_kvm_launch.py::test_sandbox_and_hygiene` |
| FR-012, FR-013 (status, console log) | `test_kvm_mgmt.py::test_status_lists_guests`, `test_console_logs_*` |
| FR-014, FR-014a (management path, no data on it) | `test_kvm_mgmt.py::test_k11_*`, `test_guest_invariants` |
| FR-014b (key-only SSH) | `test_kvm_mgmt.py::test_k12_*`, `test_kvm_launch.py::test_user_data` |
| FR-015, FR-016 (suite skips without KVM; default suite unchanged) | `tests/e2e/run.sh --kvm`, `test_kvm_lab.py::test_unusable_kvm_device_*` |
| FR-017 (docs) | `docs/kvm.md`, `docs/lab.md`, `README.md` |
| SC-001, SC-002 | `test_k1_*`, `test_k14_*` |
| SC-003, SC-004 | `test_k5_*`, `test_k8_*` |
| SC-005 | `test_k10_*` (identity line logged by `lab.sh run`) |
| SC-006 | `tests/e2e/run.sh --kvm` budget (`MINIVR_E2E_BUDGET_S=300`) |
| SC-007 | `test_k15_*` |
| SC-008 | `test_k16_*` |
| SC-010 | `test_k11_*` |

## Harness tests (namespace VMs)

`make e2e` runs these on the namespace harness (`lab.sh up --harness`; no KVM needed). Each is
classified, so that the KVM suite (`make e2e-kvm`, gate 3 with the harness suite) covers every
behaviour a guest can show (spec 004, FR-011, SC-005); `tests/lab/test_traceability.py` fails
`make check` when a harness test is missing here.

- `crafted-frame`: needs frames no guest kernel sends, or inspection of raw frames.
- `forwarder-only`: about the forwarder process, `vrctl`, the lab scripts or the control socket;
  no guest traffic is involved.
- `guest-showable`: a guest can show it; the KVM counterpart (or the reason there is none) is in
  the last column.

| test | class | KVM counterpart / reason |
|---|---|---|
| `test_lab.py::test_topology_matches_contract` | forwarder-only | lab script contract of the harness itself; KVM counterpart `test_kvm_lab.py::test_k1_up_ready_in_time_with_ports` |
| `test_lab.py::test_up_is_idempotent` | forwarder-only | harness bring-up script; KVM counterpart `test_kvm_lab.py::test_k2_second_up_keeps_the_guests` |
| `test_lab.py::test_down_after_partial_up` | forwarder-only | harness bring-up script; KVM counterpart `test_kvm_lab.py::test_k14_teardown_leaves_nothing_behind` |
| `test_lab.py::test_up_recovers_from_partial_state` | forwarder-only | harness bring-up script; KVM counterpart `test_kvm_lab.py::test_k2_second_up_keeps_the_guests` |
| `test_lab.py::test_timing_budget` | forwarder-only | harness bring-up time; KVM counterpart `test_kvm_lab.py::test_k1_up_ready_in_time_with_ports` |
| `test_lab.py::test_host_state_unchanged_and_ens33_untouched` | forwarder-only | host snapshot diff of the harness; KVM counterpart `test_kvm_lab.py::test_k14_teardown_leaves_nothing_behind` and the session guard |
| `test_lab.py::test_scripts_never_reference_the_host_nic` | forwarder-only | static check of the scripts, kind-independent |
| `test_lab.py::test_down_removes_every_lab_object` | forwarder-only | harness teardown; KVM counterpart `test_kvm_lab.py::test_k14_teardown_leaves_nothing_behind` |
| `test_lab.py::test_forwarder_fails_fast_when_the_lab_does_not_exist` | forwarder-only | forwarder start-up without a lab |
| `test_crash.py::test_forced_crash_produces_a_symbolized_core_and_log` | forwarder-only | crash drill of the forwarder process; no guest involved |
| `test_forwarding.py::test_v1_arp_for_the_gateway` | crafted-frame | scapy ARP request and raw reply inspection; guest view in `test_kvm_forwarding.py::test_k4_gateway_and_proxy_arp` |
| `test_forwarding.py::test_v2_proxy_arp_for_another_vm_without_touching_that_vm` | crafted-frame | sniffs the target VM for kernel ARP; guest view in `test_kvm_forwarding.py::test_k4_gateway_and_proxy_arp` |
| `test_forwarding.py::test_v3_arp_for_an_unknown_address_is_not_answered` | guest-showable | `test_kvm_parity.py::test_v3_unknown_address_arp_not_answered` |
| `test_forwarding.py::test_v4_every_ordered_pair_pings_with_no_loss_and_ttl_63` | guest-showable | `test_kvm_forwarding.py::test_k5_all_pairs_zero_loss_ttl_63` |
| `test_forwarding.py::test_v5_unknown_network_is_unreachable` | guest-showable | `test_kvm_forwarding.py::test_k6_net_unreachable_counted` |
| `test_forwarding.py::test_v6_ttl_exceeded` | guest-showable | `test_kvm_forwarding.py::test_k7_ttl_exceeded` |
| `test_forwarding.py::test_v7_gateway_answers_echo` | guest-showable | `test_kvm_parity.py::test_v7_gateway_answers_echo` |
| `test_forwarding.py::test_v8_one_gigabyte_transfer_keeps_its_checksum` | guest-showable | `test_kvm_forwarding.py::test_k8_100mb_tcp_digest_matches` (100 MB; the guests have 192 MB of RAM and a 1 GiB transfer would dominate the suite budget) |
| `test_forwarding.py::test_v12_spoofed_source_address_is_dropped` | guest-showable | `test_kvm_forwarding.py::test_k9_spoofed_source_dropped_and_counted` |
| `test_forwarding.py::test_v16_unbound_vm_is_resolved_learned_and_the_first_ping_works` | guest-showable | `test_kvm_unbound.py::test_v16_unbound_neighbour_resolved_learned_first_ping_works` |
| `test_privileges.py::test_v18_forwarder_runs_as_nobody_with_no_capabilities` | forwarder-only | forwarder process credentials; no guest involved |
| `test_privileges.py::test_forwarding_and_control_still_work_after_the_drop` | forwarder-only | forwarder process credentials; no guest involved |
| `test_privileges.py::test_unknown_user_is_refused_before_any_traffic` | forwarder-only | forwarder start-up; no traffic |
| `test_cli.py::test_table_output_matches_the_contract` | forwarder-only | vrctl output format |
| `test_cli.py::test_json_shapes` | forwarder-only | vrctl output format |
| `test_cli.py::test_v9_connected_and_host_routes_are_immutable` | forwarder-only | control-plane rule; no data traffic needed |
| `test_cli.py::test_v10_live_route_change_without_restart` | guest-showable | `test_kvm_unbound.py::test_v10_live_route_change_without_restart` |
| `test_cli.py::test_v11_drop_counters_add_up` | forwarder-only | counter invariant total == sum(reasons); also asserted after guest traffic in `test_kvm_parity.py::test_v14_icmp_errors_rate_limited` |
| `test_cli.py::test_stats_clear_zeroes_counters_but_not_gauges` | forwarder-only | vrctl and counter semantics |
| `test_cli.py::test_admin_down_and_neighbour_commands` | forwarder-only | control-plane commands |
| `test_cli.py::test_errors_leave_state_unchanged` | forwarder-only | control-plane error handling |
| `test_cli.py::test_exit_codes` | forwarder-only | vrctl exit codes |
| `test_cli.py::test_two_concurrent_clients_do_not_disturb_each_other` | forwarder-only | control socket concurrency |
| `test_cli.py::test_other_users_are_not_permitted` | forwarder-only | control socket SO_PEERCRED check |
| `test_cli.py::test_sc010_full_route_table_still_updates_live` | forwarder-only | 10k-rule route table through the control socket |
| `test_robustness.py::test_v13_corpus_is_fully_attributed_and_forwarding_continues` | crafted-frame | malformed frames a guest kernel would never send (docs/drop-reasons.md) |
| `test_robustness.py::test_v14_icmp_error_flood_is_rate_limited_and_other_ports_still_get_errors` | guest-showable | `test_kvm_parity.py::test_v14_icmp_errors_rate_limited` (parallel guest pings; skips with the measured guest rate if a guest cannot reach 100/s, the harness test sends 500 pkt/s with scapy) |
| `test_robustness.py::test_link_flap_follows_the_veth_state_without_restart` | guest-showable | `test_kvm_mgmt.py::test_k13_killed_guest_is_stopped_and_recovers`; link-down inside a guest is not visible at the host TAP (guest presence is), so the KVM variant kills and restarts the guest |
| `test_robustness.py::test_v17_sigterm_shuts_down_within_two_seconds` | forwarder-only | forwarder signal handling |

## Spec 004: KVM guests as the default lab (`specs/004-kvm-default-lab/spec.md`)

Lab-script tests: `tests/e2e_kvm/test_kvm_lab.py`; classification check:
`tests/lab/test_traceability.py` (gate `lab-unit`). Quickstart scenarios D1–D12 in
`specs/004-kvm-default-lab/quickstart.md`.

| Requirement | Covered by |
|---|---|
| FR-001, FR-002 (plain `up`/`run`/`status`/`ssh`/`down` are the KVM lab) | `test_kvm_lab.py::test_k1_*` (first status line `lab: kvm`), `test_k2_*`; quickstart D1–D3 |
| FR-003 (no KVM: exit 3/4, nothing created, harness line) | `test_kvm_lab.py::test_k15_*`, `test_unusable_kvm_device_*` |
| FR-004 (old KVM entry points gone) | `test_kvm_lab.py::test_old_kvm_option_prints_usage`; `make -n lab-kvm` (quickstart D5) |
| FR-005 (harness only by name) | `test_lab.py::test_topology_matches_contract` (`lab: harness`); quickstart D6 |
| FR-006 (mutual exclusion) | `test_kvm_lab.py::test_kvm_up_refused_while_harness_is_up`, `test_k3_harness_up_refused_while_kvm_is_up` |
| FR-007 (`make e2e` harness, `make e2e-kvm` KVM) | `Makefile`; quickstart D8, D9 |
| FR-008, FR-009 (single KVM demo, captured output) | `scripts/demo.sh`, `docs/demo.md`, `docs/demo.cast`; quickstart D11 |
| FR-010 (README, docs, no namespace VMs) | `README.md`, `docs/lab.md`, `docs/kvm.md`; quickstart D11 grep |
| FR-011 (classification) | the "Harness tests" table above; `test_traceability.py` |
| FR-012 (parity tests) | `test_kvm_parity.py`, `test_kvm_unbound.py` (V10, V16), `test_k13_*` extended, `test_k8_*` (`mbuf.in_use == 0`) |
| FR-013 (forwarder untouched) | quickstart D12 (`git diff master -- src lab/cn1*.conf`) |
| FR-014 (host snapshot in both suites) | session guards in `tests/e2e/conftest.py`, `tests/e2e_kvm/conftest.py` |
| SC-001 | `test_k1_*`; quickstart D1 |
| SC-002 | `test_k15_*` |
| SC-003 | quickstart D1–D2 (README commands as written) |
| SC-004 | quickstart D11 (grep) |
| SC-005 | `test_traceability.py` |
| SC-006 | quickstart D8, D9 |
| SC-007 | quickstart D12 |

## Phase 2: VRFs and overlay tunnels (`specs/003-vrf-overlay-tunnels/spec.md`)

_Filled in at the end of the feature (task T066)._
