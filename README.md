# 🌳 Cthaeh

*"It sees all the ways the future can branch and blossom from a single moment."*

Ghidra-powered triage scanner for Windows kernel drivers. Scores drivers on 60+ vulnerability heuristics: dangerous primitives, IOCTL attack surface, missing validation, BYOVD patterns, and more. So you know which `.sys` files to pull apart first.

Named after the all-seeing tree from *The Kingkiller Chronicle*.

Cthaeh doesn't find vulnerabilities. It finds the drivers most likely to *have* them.

## Quick Start

```bash
# Install pefile for pre-filtering
pip install pefile

# Extract third-party drivers from your machine
python extract_driverstore.py --output C:\drivers\extracted

# Run triage (smart defaults: auto-detect Ghidra, parallel workers, prefilter on)
python run_triage.py C:\drivers\extracted

# Or point at your Ghidra install explicitly
python run_triage.py C:\drivers\extracted --ghidra C:\ghidra_11.3

# Single driver
python run_triage.py --single C:\path\to\suspicious.sys

# Explain a specific driver's score (no rescan needed)
python run_triage.py --explain example.sys
```

**That's it.** Pre-filter, parallel workers, JSON output, and markdown report are all on by default. Set `GHIDRA_HOME` env var and you never need `--ghidra` again.

## What It Does

1. **Pre-filter** (pefile): eliminates uninteresting drivers in milliseconds (~37% dropped)
2. **Parallel Ghidra headless**: analyzes remaining drivers with N workers (auto = half your CPUs)
3. **60+ heuristic checks**: scores each driver on vulnerability indicators
4. **Ranked output**: CSV, JSON, and markdown report with full scoring breakdowns

## Scoring

All weights are configurable via the `WEIGHTS` dict at the top of `driver_triage.py`.

### Check Categories

| Category | Checks | What it catches |
|----------|--------|-----------------|
| **Device security** | IoCreateDevice vs Secure, symlink+no ACL, WDM vs WDF | Weak access controls |
| **IOCTL surface** | Dispatched IOCTL count, METHOD_NEITHER, FILE_ANY_ACCESS | Attack surface size |
| **Dangerous primitives** | MSR R/W, CR access, physical memory mapping, port I/O | Kernel-level capabilities |
| **BYOVD** | Process open + terminate, token steal, DSE bypass | Weaponizable drivers |
| **Validation gaps** | No ProbeForRead/Write, no auth imports, unchecked memcpy | Missing input validation |
| **USB/BT** | URB construction, HCI passthrough, eFuse access | Hardware control passthrough |
| **Firmware** | UEFI variables, HAL bus data, hardcoded crypto keys | Firmware manipulation |
| **Vendor context** | CNA status, bounty programs, driver class (WiFi bonus, audio penalty) | Vuln assignment likelihood |
| **Compound scoring** | MSR+PhysMem=god-mode, IOCTL+no-auth+named-device=easy target | Multi-primitive combinations |
| **Kernel Rhabdomancer** | Per-function candidate point mapping, call graph from IOCTL dispatch, missing validation detection | Pinpoints *where* dangerous APIs are called, not just that they're imported |
| **Vuln pattern** | IOCTL surface + dangerous primitive + missing validation | Pattern from 8 confirmed vulns |
| **WDAC block policy** | Checks Win10/Win11 driver block policy by SHA256 + filename | Skips already-blocked drivers |
| **LOLDrivers (HolyGrail)** | Cross-references SHA256 against HolyGrail's curated LOLDrivers list | Flags known LOLDrivers for variant research |
| **Comms capability** | IoCreateDevice, IoCreateSymbolicLink, FltRegisterFilter, FltCreateCommunicationPort | User-mode attackable bridge detection |
| **PPL killer** | ZwTerminateProcess + ZwOpenProcess/PsLookupProcessByProcessId combo | Protected process termination potential |
| **Enhanced imports** | MmCopyMemory, ZwReadVirtualMemory, KeStackAttachProcess, IoAllocateMdl, etc. | Expanded dangerous primitive coverage |
| **Memory corruption** | UAF, double-free, free-without-null in IOCTL dispatch paths | Instruction-level pattern analysis |
| **BYOVD expanded** | Arbitrary R/W via MmMapIoSpace, kernel execute via APC/WorkItem, PID termination | Full exploitation primitive coverage |
| **IORING surface** | IORING APIs, shared memory section patterns | Novel kernel attack surface detection |
| **Killer driver** | Process enum+kill, callback removal, minifilter unload, EDR product strings | EDR/AV termination pattern detection |
| **Bloatware/OEM** | Consumer OEM vendor boost, utility driver strings, PE age | Prioritizes historically weak vendors |

### Priority Tiers

| Tier | Threshold | Meaning |
|------|-----------|---------|
| 💀 CRITICAL | ≥250 | Drop everything and analyze (~1% of drivers) |
| 🔴 HIGH | ≥150 | Strong candidate, investigate soon |
| 🟡 MEDIUM | ≥75 | Worth a look |
| 🟢 LOW | ≥30 | Probably boring |
| ⚪ SKIP | <30 | Move on |

### Investigated Drivers

Drivers you've already analyzed go in `investigated.json`:

```json
{
  "investigated": {
    "example.sys": "4 vulns submitted to vendor PSIRT",
    "another.sys": "FP - WDF device interface blocks unprivileged access"
  }
}
```

These are skipped on future scans, labeled `INVESTIGATED` in output.

## Output

Every scan produces (by default):

| File | Content |
|------|---------|
| `triage_results.csv` | Ranked results with top checks |
| `triage_results.json` | Full results with all findings per driver |
| `triage_report.md` | Markdown report with scoring breakdowns for top 20 |

### Explain Mode

Inspect any driver's scoring without re-scanning:

```bash
python run_triage.py --explain example.sys
```

```
============================================================
  EXPLAIN: example.sys
============================================================
  Score: 285 | Priority: CRITICAL
  Vendor: Example Corp.

  Scored checks:
    +  25  [msr_write] Contains WRMSR instruction(s)
    +  20  [symlink_no_acl] Symbolic link + IoCreateDevice without IoCreateDeviceSecure
    +  20  [port_io_rw] Port I/O: 12 IN + 8 OUT instructions
    +  15  [wifi_driver] WiFi driver - massive IOCTL/WDI attack surface
    ...
```

The top scorer is auto-explained after every scan.

## Files

| File | Purpose |
|------|---------|
| `driver_triage.py` | Ghidra headless script (60+ checks, configurable weights) |
| `run_triage.py` | Orchestrator (parallel, prefilter, explain, smart defaults) |
| `prefilter.py` | Fast PE import pre-filter |
| `extract_driverstore.py` | Extracts third-party .sys from Windows DriverStore |
| `investigated.json` | Drivers already analyzed (skipped on scan) |
| `policies/` | WDAC block policy JSONs and HolyGrail LOLDrivers data |
| `test_regression.py` | Regression tests against known ground-truth samples |

## CLI Reference

```
python run_triage.py C:\drivers                    # Scan with smart defaults
python run_triage.py C:\drivers --no-prefilter     # Skip pre-filter
python run_triage.py --single C:\path\to\driver.sys
python run_triage.py --explain example.sys        # Explain existing results
python run_triage.py C:\drivers --workers 8        # Override worker count
python run_triage.py C:\drivers --no-json --no-report  # CSV only
```

**Environment variables:**
- `GHIDRA_HOME` - Path to Ghidra installation (auto-detected if not set)
- `CTHAEH_FP_PATH` - Override path to investigated.json

## Performance

| Drivers | Mode | Time |
|---------|------|------|
| 340 | Pre-filter + 5 workers | ~1.5 hours |
| 340 | Pre-filter + sequential | ~6 hours |
| 533 | No filter + sequential | ~44 hours |

## The Workflow

```
DriverStore --> extract --> Cthaeh triage --> ranked list --> manual audit
                                                                  |
                                             Claude Code + Ghidra MCP --> vuln
```

## Requirements

- Python 3.8+
- Ghidra 10.x+ (headless mode)
- `pefile`: `pip install pefile`
- Windows (for DriverStore extraction; analysis works on any OS)

## Acknowledgments

- WDAC block policy checking and LOLDrivers cross-reference inspired by [HolyGrail](https://github.com/BlackSnufkin/Holygrail) by BlackSnufkin.
- Kernel Rhabdomancer candidate point strategy inspired by [Rhabdomancer.java](https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java) by Marco Ivaldi (0xdea). See also: [Automating binary vulnerability discovery with Ghidra and Semgrep](https://hnsecurity.it/blog/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/).

## License

MIT

---

*"The Cthaeh does not lie. The Cthaeh sees the true shape of the world."*
