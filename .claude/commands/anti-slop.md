You are running the **anti-slop** audit. Your job is to strip waste from the codebase — no explanations, no suggestions for future work, no hedging. Read every file in the target directory (default: the current working directory, or the path passed as an argument), then run each check below and report only real findings.

---

## SETUP

1. Determine the target directory: use the argument passed to this skill, or fall back to the project root (`scapy/final/` if no argument is given, since that is where the implementation lives).
2. Read **every `.py` file** in that directory. Skip all other file types (markdown, JSON, text, config, etc.).
3. Read the project memory files to establish the end goal:
   - `~/.claude/projects/c--Users-ryash-OneDrive-Documents-GitHub-netsec/memory/project_threat_model.md` — the 7-step attack chain is the **only** required functionality.
   - `~/.claude/projects/c--Users-ryash-OneDrive-Documents-GitHub-netsec/memory/program_execution.md` — per-function execution trace to identify what is actually used at runtime.

---

## CHECKLIST

Run every check. For each finding, output a block in this exact format:

```
[SEVERITY] CHECK-N — <offence in one line>
  File: <path>:<line(s)>
  Offence: <what is wrong>
  Remediation: <what to do, specifically>
```

Severity scale:
- **CRITICAL** — ships broken behaviour or exposes internals (debug flags left on, hardcoded credentials, verbose logging that leaks packet contents to stdout in a non-debug build)
- **HIGH** — reimplementing something the OS/platform already provides, or duplicated logic that diverges silently
- **MEDIUM** — dead code that inflates the file and must be maintained (unused imports, uncalled functions, redundant branches)
- **LOW** — scope creep: functional code that goes beyond what the 7-step threat model requires

If a check produces **zero findings**, output a single line: `CHECK-N CLEAN`.

---

### CHECK-1: Reimplemented system primitives

Scan for manual reimplementations of functionality already provided by:
- **Python stdlib**: `socket`, `struct`, `ipaddress`, `subprocess`, `threading`, `queue`, `hashlib`, `hmac`, `time`, `os`, `signal`, `atexit`, `random`, `itertools`, `collections`, `functools`
- **Scapy built-ins**: IP/TCP/UDP/ICMP/DHCP/BOOTP/OSPF/Ether layer construction and parsing, `sr1`, `srp`, `sendp`, `sniff`, `hexdump`, `get_if_addr`, `get_if_hwaddr`, `conf.iface`
- **Kali/Linux system tools** (invoked via subprocess rather than wrapping a library): `ip`, `iptables`, `ip6tables`, `nft`, `dhclient`, `arping`, `ping`, `ss`, `netstat`, `nmcli`
- **Windows equivalents** (if any Windows-specific paths exist): `netsh`, `ipconfig`, `route`, `arp`

Flag any function that manually constructs, parses, or computes something a listed primitive already does.

---

### CHECK-2: Duplicated functions

Find functions (or blocks of ≥5 lines) that do the same thing twice, even under different names. Look for:
- Identical logic copy-pasted with minor variable renames
- Two functions that produce the same output from the same input via different code paths
- Helper wrappers that do nothing but call another function with the same arguments

Flag each pair, not just one side.

---

### CHECK-3: Redundant code

Find code that executes but has no effect on observable behaviour:
- A variable assigned and never read again before being overwritten or going out of scope
- A condition that is always true or always false given the surrounding invariants
- A branch whose body is identical to the else-branch
- A loop that always executes exactly once and could be replaced with its body
- A `try/except` that catches an exception and silently passes or re-raises the same exception without adding information

---

### CHECK-4: Unused imports and dead functions

- **Unused imports**: any `import` or `from X import Y` where the imported name never appears in the file body (outside of the import line itself).
- **Uncalled functions**: any function defined in the file that is never called within the file AND is not exported/referenced by another file in the directory. Check cross-file references before flagging.

For each finding state the import/function name and confirm it is not called anywhere in the directory.

---

### CHECK-5: Debug artifacts

Flag anything that should be stripped before a final release:
- `print(...)` statements that emit raw packet bytes, hex dumps, or internal state (legitimate user-facing status prints are acceptable — flag only debug-style prints)
- `logging.debug(...)` calls where the logger level is hardcoded to `DEBUG` at the module level (not controlled by a flag)
- `breakpoint()` or `pdb.set_trace()` calls
- Commented-out code blocks of ≥3 lines that look like prior implementations
- `verbose = True` or similar hardcoded debug flags that should default to `False` or be removed
- Test-only payloads hardcoded in production paths (e.g. a fixed MAC, IP, or hostname that is only meaningful in a lab)

---

### CHECK-6: Scope creep — functionality beyond the 7-step threat model

The **only** required end goal is the 7-step attack chain from memory:
1. OSPF recon (passive LSA read)
2. DHCP recon (lease read)
3. OSPF adjacency (Full state with SVI)
4. Route injection (/32 stub LSA)
5. Rogue DHCP with option 121 (CVE-2024-3661)
6. MITM forwarding (policy routing + iptables MASQUERADE)
7. DNS tunneling (exfil/C2)

Flag any function, class, or module that implements behaviour outside these 7 steps and is not a direct utility (teardown, logging, locking, argument parsing) required to make one of the 7 steps work correctly. Examples of scope creep: ARP spoofing, STP manipulation, port scanning, credential harvesting UI, alternative MITM paths, reporting/export features, interactive menus beyond what is needed to trigger the 7 steps.

---

### CHECK-7: Hardcoded magic numbers

Flag inline literals that belong in named constants or in the `context` dict:
- Raw IP addresses, MAC addresses, or CIDRs embedded directly in function bodies (not in argument defaults or top-level `DEFAULT_*` constants)
- Port numbers, protocol numbers, or OSPF area IDs hardcoded inside packet construction calls
- Timer/interval values (e.g. `time.sleep(5)`, `hello_interval = 10`) hardcoded inline rather than derived from `context` or a named constant
- MTU, cost, or priority values hardcoded in OSPF packet fields

Do **not** flag: string literals used for logging/printing, protocol field names, or constants that are legitimately fixed by the standard (e.g. OSPF multicast `224.0.0.5` is not magic — it is the protocol-defined address).

---

### CHECK-8: Silent exception swallowing

Flag `except` blocks that mask failures on code paths that are part of the 7-step attack chain:
- `except ...: pass` — swallows the error entirely with no trace
- `except ...: continue` inside a loop that drives a chain-critical operation (adjacency, packet sniff, route inject)
- `except` blocks that only log at DEBUG level and then return `None` or a sentinel, where the caller does not check the return value
- Broad `except Exception:` or bare `except:` clauses that catch more than intended, hiding unexpected failures

Do **not** flag: `except KeyboardInterrupt` used for clean teardown, or `except` blocks that explicitly re-raise after logging.

Severity guide: CRITICAL if on an OSPF/DHCP/routing path where silent failure breaks the chain; MEDIUM if on a utility/logging path where failure is truly non-fatal.

---

### CHECK-9: Global state mutations outside `context`

The established synchronisation boundary in this project is the shared `context` dict, protected by `context["lock"]`. Flag any code that bypasses it:
- Use of the `global` keyword to mutate module-level variables that represent runtime state (not constants)
- Module-level mutable variables (lists, dicts, sets) that are written to from more than one function without holding `context["lock"]`
- State that logically belongs in `context` (e.g. neighbour tables, LSDBs, lease info) stored instead in a bare module-level variable
- Functions that read or write such variables from a background thread without any locking

Do **not** flag: module-level constants, `argparse` result objects assigned once at startup, or logger instances.

---

## OUTPUT FORMAT

After all checks, output a **Summary Table**:

```
| Severity | Count |
|----------|-------|
| CRITICAL |   N   |
| HIGH     |   N   |
| MEDIUM   |   N   |
| LOW      |   N   |
| TOTAL    |   N   |
```

Then a single **Verdict** line:
- `SLOP-FREE` — zero findings across all checks
- `NEEDS CLEANUP` — one or more findings; do not auto-fix, wait for the user to say "fix it"

Do **not** implement any changes. Report only.
