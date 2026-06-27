Run the following pre-implementation checklist BEFORE writing any code for the requested change.
Output each section as a numbered checklist with a PASS / WARN / FAIL status per item.
Do not begin implementation until all items are either PASS or the user has acknowledged a WARN/FAIL.

---

## 1. SCOPE & PLAN ALIGNMENT

- [ ] Re-state what the change is in one sentence.
- [ ] Identify which file(s) and function(s) will be touched.
- [ ] Confirm the change fits the 7-step threat model in memory (project-threat-model). If it introduces behaviour outside those 7 steps, flag it.
- [ ] If a plan file exists (`~/.claude/plans/`), confirm the change matches the plan. List any deviation explicitly.
- [ ] Confirm no DTP / PVST+ / 802.1Q trunking code is being re-introduced (regression guard).

## 2. HOST STATE & TEARDOWN COVERAGE

For every host-level change the feature introduces:
- [ ] List each new iptables rule (`-A`). Confirm there is a matching `-D` call in the teardown path.
- [ ] List each new `ip route add` or `ip rule add`. Confirm there is a matching `del` in teardown.
- [ ] List each new `/proc` write. Confirm the old value is saved and restored.
- [ ] List each `subprocess.Popen` (background processes). Confirm they are terminated in teardown or atexit.
- [ ] List each new file created on disk (loopback aliases, temp files). Confirm they are removed in teardown.
- [ ] Confirm that teardown runs whether the tool exits normally, on KeyboardInterrupt, or on exception (i.e. is inside a `finally` block or registered via `atexit`/signal handler).

## 3. PACKET CORRECTNESS

If the change touches any packet construction:
- [ ] Option 121 next-hop: confirm it is `relay_ip` (physical interface IP, ARP-resolvable) for direct clients, and `giaddr` for relayed clients. Flag if `source_ip` (loopback alias) is used as next-hop.
- [ ] OSPF packets: confirm `area` field matches `context["area_id"]`, not a hardcoded `"0.0.0.0"`.
- [ ] Any new OSPF LSA: confirm it will be included in `withdraw_injected_routes()` on exit.
- [ ] Any new DHCP option: confirm it doesn't break `IMPERSONATE_REAL_SERVER` path (spoofed ACK must also carry the new option).

## 4. CONCURRENCY & THREAD SAFETY

- [ ] If the change reads or writes `context["neighbors"]`, `context["local_lsdb"]`, or `context["manual_router_links"]`, confirm it holds `context["lock"]`.
- [ ] If the change adds a new background thread, confirm it is a daemon thread (so it doesn't block clean exit).
- [ ] If the change shares mutable state between threads (e.g. a new list or dict), confirm access is synchronised.

## 5. VERSION & MEMORY

- [ ] Identify the version string at the top of each modified file (e.g. `# v3.0`). State what it should be incremented to.
- [ ] Confirm the program-execution memory (`program_execution.md`) needs updating. If so, list which section(s) and what needs to change. Do NOT update the memory file yet — flag it so it can be done after implementation is confirmed working.
- [ ] Confirm whether any other memory file (threat model, feedback, project) needs updating.

## 6. EDGE CASES

- [ ] What happens if the feature is invoked when no OSPF adjacency is up yet?
- [ ] What happens if the VPN tunnel is absent / tun interface is down?
- [ ] What happens for direct clients (giaddr=0.0.0.0) vs relayed clients (giaddr≠0.0.0.0)?
- [ ] What happens on a P2P OSPF link (DR=0.0.0.0) vs a broadcast segment (DR elected)?
- [ ] Is there a timeout / failure path? Does it degrade gracefully or abort the whole tool?

---

After completing the checklist, output a one-paragraph **GO / NO-GO** summary stating:
- What will be implemented
- Any WARN or FAIL items the user must acknowledge
- Which version strings will be bumped
- Which memory sections need updating post-implementation

Then wait for the user to say "go" before writing any code.
