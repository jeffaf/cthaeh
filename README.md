# 🌳 Cthaeh

*"It sees all the ways the future can branch and blossom from a single moment."*

Automated triage scanner for Windows kernel drivers. Identifies vulnerability indicators to prioritize manual security review. Named after the all-seeing tree from *The Kingkiller Chronicle*.

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
python run_triage.py --explain amdfendr.sys
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
| **Vendor context** | CNA status, bounty programs, driver class (WiFi bonus, audio penalty) | CVE assignment likelihood |
| **Compound scoring** | MSR+PhysMem=god-mode, IOCTL+no-auth+named-device=easy target | Multi-primitive combinations |
| **Vuln pattern** | IOCTL surface + dangerous primitive + missing validation | Pattern from 8 confirmed vulns |

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
    "ssudbus2.sys": "4 vulns submitted to Samsung PSIRT (Feb 2026)",
    "nvpcf.sys": "FP - WDF device interface blocks unprivileged access"
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
python run_triage.py --explain athw8x.sys
```

```
============================================================
  EXPLAIN: athw8x.sys
============================================================
  Score: 285 | Priority: CRITICAL
  Vendor: Qualcomm Technologies, Inc.

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
| `test_regression.py` | Regression tests against known ground-truth samples |

## CLI Reference

```
python run_triage.py C:\drivers                    # Scan with smart defaults
python run_triage.py C:\drivers --no-prefilter     # Skip pre-filter
python run_triage.py --single C:\path\to\driver.sys
python run_triage.py --explain amdfendr.sys        # Explain existing results
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
DriverStore ──→ extract ──→ Cthaeh triage ──→ ranked list ──→ manual audit
                                                                   │
                                              Claude Code + Ghidra MCP ──→ CVE
```

## Results

Used this workflow to find 8 kernel driver vulnerabilities across multiple vendors in a single day. Submissions pending with vendor PSIRTs.

More at [Cred Relay](https://credrelay.com), a monthly newsletter on offensive security and AI.

## Requirements

- Python 3.8+
- Ghidra 10.x+ (headless mode)
- `pefile`: `pip install pefile`
- Windows (for DriverStore extraction; analysis works on any OS)

## License

MIT

---

*"The Cthaeh does not lie. The Cthaeh sees the true shape of the world."*
