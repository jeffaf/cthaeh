# Cthaeh Reference

Detailed technical reference. For quick start and overview, see [README.md](README.md).

## Check Categories (97 heuristics)

| Category | Checks | What it catches |
|----------|--------|-----------------|
| **Device security** | IoCreateDevice vs Secure, symlink+no ACL, WDM vs WDF | Weak access controls |
| **IOCTL surface** | Dispatched IOCTL count, METHOD_NEITHER, FILE_ANY_ACCESS | Attack surface size |
| **Dangerous primitives** | MSR R/W, CR access, physical memory mapping, port I/O | Kernel-level capabilities |
| **BYOVD** | Process open + terminate, token steal, DSE bypass, arb R/W, kernel execute | Weaponizable drivers |
| **Validation gaps** | No ProbeForRead/Write, no auth imports, unchecked memcpy | Missing input validation |
| **USB/BT** | URB construction, HCI passthrough, eFuse access | Hardware control passthrough |
| **Firmware** | UEFI variables, HAL bus data, hardcoded crypto keys | Firmware manipulation |
| **Vendor context** | CNA status, bounty programs, driver class ranking | Vuln assignment likelihood |
| **Compound scoring** | MSR+PhysMem=god-mode, IOCTL+no-auth+named-device=easy target | Multi-primitive combinations |
| **Kernel Rhabdomancer** | Per-function candidate point mapping, call graph from IOCTL dispatch | Pinpoints *where* dangerous APIs are called |
| **Vuln pattern** | IOCTL surface + dangerous primitive + missing validation | Pattern from 8 confirmed vulns |
| **WDAC block policy** | Win10/Win11 driver block policy by SHA256 + filename | Skips already-blocked drivers |
| **LOLDrivers** | SHA256 cross-ref against HolyGrail's curated list | Flags known LOLDrivers |
| **Comms capability** | IoCreateDevice, IoCreateSymbolicLink, FltRegisterFilter | User-mode bridge detection |
| **PPL killer** | ZwTerminateProcess + ZwOpenProcess combo | Protected process termination |
| **Memory corruption** | UAF, double-free, free-without-null in IOCTL dispatch paths | Instruction-level pattern analysis |
| **IORING surface** | IORING APIs, shared memory section patterns | Novel kernel attack surface |
| **Killer driver** | Process enum+kill, callback removal, minifilter unload, EDR strings | EDR/AV termination patterns |
| **Bloatware/OEM** | Consumer OEM vendor boost, utility strings, PE age | Prioritizes weak vendors |
| **Double-fetch / TOCTOU** | User buffer pointer read multiple times without local capture | Race conditions in IOCTL handlers |
| **On-disk offset trust** | Parsed offsets without bounds checking | Trusted offset → OOB read/write |
| **Framework detection** | WDF vs WDM detection, auto-adjusts scoring | WDF less noise, WDM more scrutiny |

## Anti-Pattern Tags

Findings are tagged with KernelSight anti-patterns (AP1-AP6):

| Tag | Pattern | CVE frequency |
|-----|---------|---------------|
| AP1 | Trusting user-supplied lengths | ~60% of driver CVEs |
| AP2 | Missing synchronization on shared state | ~14% |
| AP3 | Trusting on-disk/file-embedded offsets | FS/minifilter bugs |
| AP4 | Exposing physical memory or MSR access | God-mode primitives |
| AP5 | No IOCTL auth / open device ACLs | Easy targets |
| AP6 | Double-fetch / TOCTOU on user buffers | Race conditions |

## Research Feeds

| Source | Why it matters |
|--------|----------------|
| [Exploit Reversing](https://exploitreversing.com/) | Alexandre Borges' long-form reversing/exploitation series. High-value Cthaeh reading queue material, especially the Windows kernel exploitation articles on CVE-2024-30085, the minifilter driver N-day deep dive, I/O Ring, ALPC, token stealing, and PreviousMode techniques. Use it to harvest v5 scoring ideas for minifilter surfaces, exploitation primitives, and Stage 2 Ghidra/Claude prompts. |

## All CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `drivers_dir` (positional) | – | Directory of `.sys` files to scan |
| `--drivers-dir` | – | Same as positional, explicit form |
| `--single` | – | Analyze one `.sys` file |
| `--explain NAME` | – | Show scoring breakdown for a driver (by name) |
| `--ghidra` | auto | Path to Ghidra install (else `GHIDRA_HOME`/common paths) |
| `--running-only` | ON | Only scan loaded drivers (Windows) |
| `--all` | OFF | Scan all drivers |
| `--hw-check` | OFF | Post-triage hardware presence check |
| `--device-check` | OFF | Post-triage device DACL check |
| `--device-check-min-score` | 75 | Min score for device check |
| `--research` | OFF | hardware_absent is informational only |
| `--workers N` | auto | Parallel Ghidra instances (auto = half CPUs) |
| `--max N` | 0 | Cap number of drivers analyzed (0 = all) |
| `--no-prefilter` | OFF | Disable pefile pre-filter |
| `--prefilter-min N` | 1 | Min prefilter risk_hint to survive the pre-filter (higher = more aggressive) |
| `--max-size` | 5 | Max driver size in MB for pre-filter |
| `--output PATH` | triage_results.csv | CSV output path |
| `--no-json` | OFF | Disable JSON output |
| `--json-output PATH` | triage_results.json | JSON output path |
| `--no-report` | OFF | Disable markdown report |
| `--report PATH` | triage_report.md | Markdown report path |
| `--report-top` | 20 | Drivers in markdown report |
| `--min-tier` | HIGH | Minimum tier shown in the console summary |

## Environment Variables

- `GHIDRA_HOME` - Path to Ghidra installation
- `CTHAEH_FP_PATH` - Override path to `investigated.json`
- `CTHAEH_DTA_PATH` - Override path to `.gdt` data type archive
- `CTHAEH_SCORING_PATH` - Override path to `scoring_rules.yaml` (highest-priority search location)
- `CTHAEH_CNA_PATH` - Override path to `cna_vendors.json`
- `CTHAEH_CVES_PATH` - Override path to `driver_cves.json`

## Ghidra Startup

Cthaeh reads `Ghidra/application.properties` to select the launcher. Ghidra
10/11 uses `support/analyzeHeadless`; Ghidra 12+ uses
`support/pyghidraRun --headless` because Python scripting moved to PyGhidra.
Both launchers must be initialized interactively before a batch scan: select a
supported JDK for Ghidra, and on Ghidra 12 install PyGhidra when prompted.

The runner checks startup once with noninteractive input. A setup problem is
reported before pre-filtering and worker creation, and failed analyses include
the tail of Ghidra's output instead of only `no triage output`. A scan where
every Ghidra analysis fails exits with a nonzero status.

## Files

| File | Purpose |
|------|---------|
| `driver_triage.py` | Ghidra headless script (97 checks) |
| `run_triage.py` | Orchestrator (parallel, prefilter, running-only, explain) |
| `prefilter.py` | Fast PE import pre-filter |
| `extract_driverstore.py` | Extracts third-party .sys from DriverStore |
| `scoring_rules.yaml` | All scoring weights and thresholds |
| `apply_dta.py` | Ghidra pre-script: loads Talos DTA |
| `download_dta.py` | Downloads the Talos .gdt file |
| `calibrate_scoring.py` | Reports score distribution and calibration guardrails |
| `hw_check.py` | Hardware presence check via PnP enumeration |
| `device_check.py` | Device object DACL check |
| `cna_vendors.json` | CNA status + bounty URLs per vendor |
| `driver_cves.json` | Prior CVE history per driver family |
| `investigated.json` | Already-analyzed drivers (skipped on scan) |
| `policies/` | WDAC block policies + LOLDrivers data |
| `test_regression.py` | Regression tests |
| `IMPROVEMENTS.md` | Review findings + prioritized recommendations |
| `ROADMAP.md` | Forward-looking heuristic + workflow roadmap (v5) |
