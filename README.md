# 🌳 Cthaeh

*"It sees all the ways the future can branch and blossom from a single moment."*

Automated triage scanner for Windows kernel drivers. Identifies vulnerability indicators to prioritize manual security review. Named after the all-seeing tree from *The Kingkiller Chronicle*.

Cthaeh doesn't find vulnerabilities. It finds the drivers most likely to *have* them.

## How it works

1. Extract third-party drivers from DriverStore (or point at any folder of .sys files)
2. Ghidra headless ingests and auto-analyzes each driver
3. `driver_triage.py` scores each driver on vulnerability indicators
4. Outputs a ranked CSV - highest-scoring drivers are your audit targets

## Quick Start

```bash
# 1. Install pefile for pre-filtering (optional but recommended)
pip install pefile

# 2. Extract third-party drivers from your machine
python extract_driverstore.py --output C:\drivers\extracted

# 3. Run triage with pre-filter + parallel (fastest)
python run_triage.py --drivers-dir C:\drivers\extracted --ghidra C:\ghidra_11.3 --prefilter --workers 4

# 4. Or run without pre-filter (analyzes everything)
python run_triage.py --drivers-dir C:\drivers\extracted --ghidra C:\ghidra_11.3

# 5. Or just pre-filter to see what's interesting
python prefilter.py C:\drivers\extracted --list

# 6. Single driver analysis
python run_triage.py --single C:\path\to\suspicious.sys --ghidra C:\ghidra_11.3

# 7. Open triage_results.csv, pick HIGH priority targets
# 8. Deep dive with Claude Code + Ghidra MCP
```

## Scoring Criteria

| Check | Points | Why |
|-------|--------|-----|
| IoCreateDevice (not Secure) | +15 | Weak default ACL |
| Has IOCTL handler | +10 | Attack surface exists |
| METHOD_BUFFERED IOCTLs | +5 | Common vuln pattern |
| METHOD_NEITHER IOCTLs | +15 | Most dangerous method |
| FILE_ANY_ACCESS | +15 | No privilege checks |
| No ProbeForRead/ProbeForWrite | +10 | Missing user buffer validation |
| Deprecated ExAllocatePool | +10 | No NX pool flag |
| MmMapIoSpace | +15 | Physical memory mapping |
| Named device object | +10 | Easier to open |
| Dynamic function resolution | +5 | Potential evasion |

**Priority levels:** HIGH (60+) | MEDIUM (40-59) | LOW (20-39) | SKIP (<20)

## Files

| File | Purpose |
|------|---------|
| `driver_triage.py` | Ghidra headless script - scores a single driver |
| `run_triage.py` | Orchestrator - batch processes with optional parallelism |
| `prefilter.py` | Fast PE import check - eliminates uninteresting drivers in ms |
| `extract_driverstore.py` | Extracts third-party .sys from Windows DriverStore |

## Performance

| Mode | 533 drivers | Notes |
|------|-------------|-------|
| Sequential | ~44 hours | Original, one at a time |
| Pre-filter only | ~2 seconds | Eliminates 60-70% of drivers |
| Pre-filter + sequential | ~15 hours | Fewer drivers to analyze |
| Pre-filter + 4 workers | ~4 hours | Recommended for most systems |

## BYOVD & LOLDrivers

Cthaeh has built-in support for BYOVD (Bring Your Own Vulnerable Driver) hunting:

```bash
# Show only BYOVD process killer candidates
python prefilter.py C:\drivers\extracted --byovd --list

# Cross-reference against LOLDrivers known-vulnerable database
python prefilter.py C:\drivers\extracted --loldrivers --list

# Combine: find NEW BYOVD candidates not yet in LOLDrivers
python prefilter.py C:\drivers\extracted --byovd --loldrivers --list
```

The pre-filter detects:
- 🎯 **BYOVD candidates**: Drivers that import both process open + terminate functions
- 🔓 **Physical memory R/W**: Multiple memory mapping imports (potential arbitrary R/W)
- ⚠️ **Known vulnerable**: Hashes matching the [LOLDrivers](https://www.loldrivers.io/) database

## Requirements

- Python 3.8+
- Ghidra 10.x+ (headless mode)
- `pefile` (optional, for pre-filter): `pip install pefile`
- `requests` (optional, for LOLDrivers cross-reference): `pip install requests`
- Windows (for DriverStore extraction; analysis works on any OS)

## The Workflow

```
DriverStore ──→ extract ──→ Cthaeh triage ──→ ranked list ──→ manual audit
                                                                   │
vendor sites ──→ download ──→ Cthaeh triage ──→ ranked list ──→────┘
                                                                   │
                                                    Claude Code + Ghidra MCP
                                                           │
                                                      CVE submission
```

## Writing

I'm documenting this workflow in [Cred Relay](https://credrelay.com), my monthly newsletter on offensive security and AI. Issue #2 covers how I used Cthaeh + Claude Code + Ghidra to find 8 kernel driver vulnerabilities in a single day.

## License

MIT

---

*"The Cthaeh does not lie. The Cthaeh sees the true shape of the world."*
