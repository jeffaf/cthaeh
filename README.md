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
# 1. Extract third-party drivers from your machine
python extract_driverstore.py --output C:\drivers\extracted

# 2. Run triage on all of them
python run_triage.py --drivers-dir C:\drivers\extracted --ghidra C:\ghidra_11.3

# 3. Analyze a single driver
python run_triage.py --single C:\path\to\suspicious.sys --ghidra C:\ghidra_11.3

# 4. Open triage_results.csv, pick HIGH priority targets
# 5. Deep dive with Claude Code + Ghidra MCP
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
| `run_triage.py` | Orchestrator - batch processes a folder of drivers |
| `extract_driverstore.py` | Extracts third-party .sys from Windows DriverStore |

## Requirements

- Python 3.8+
- Ghidra 10.x+ (headless mode)
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

## License

MIT

---

*"The Cthaeh does not lie. The Cthaeh sees the true shape of the world."*
