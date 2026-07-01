# 🌳 Cthaeh

Ghidra-powered triage scanner for Windows kernel drivers. Scores drivers on 97 vulnerability heuristics so you know which `.sys` files to pull apart first.

Cthaeh doesn't find vulnerabilities. It finds the drivers most likely to *have* them, so you can focus your reverse engineering time where it matters.

## Sample Output

```
============================================================
  🌳 CTHAEH TRIAGE COMPLETE: 340 drivers analyzed
============================================================
  💀 CRITICAL:        2
  🔴 HIGH priority:   14
  🟡 MEDIUM priority: 38
  🟢 LOW priority:    72
  ⚪ SKIP:            214

Top targets (>= HIGH):

   1. [CRITICAL] 360 pts  athw8x.sys
   2. [CRITICAL] 310 pts  vhdmp.sys
   3. [HIGH    ] 245 pts  vmci.sys
   4. [HIGH    ] 240 pts  hvservice.sys
```

### Explain Mode

```
============================================================
  Driver: ssudbus2.sys v2.21.0.0 (Samsung Electronics)
============================================================
  Vendor: Samsung (CNA: YES) | Bounty: PRESENT
  Score: 285 | Priority: CRITICAL
  Priority: CRITICAL - IMMEDIATE - full reverse engineering, build PoC exploit

  Scored checks:
    + 25  [msr_write] Contains WRMSR instruction(s)
    + 20  [symlink_no_acl] Symbolic link + IoCreateDevice without Secure
    + 20  [port_io_rw] Port I/O: 12 IN + 8 OUT instructions
    ...
```

## Quick Start

```bash
pip install -r requirements.txt
python download_dta.py                              # Talos type archive (once)
python extract_driverstore.py --output C:\drivers   # Pull third-party drivers

python run_triage.py C:\drivers                     # Scan (only loaded drivers by default)
python run_triage.py C:\drivers --all               # Scan everything
python run_triage.py --single C:\path\to\driver.sys # Single driver
python run_triage.py --explain example.sys          # Explain a score
```

Set `GHIDRA_HOME` and you never need `--ghidra`. Pre-filter, parallel workers, JSON, and markdown report are all on by default.

## How It Works

1. **Running-only filter** (Windows default): scans only loaded drivers. `--all` to override.
2. **Pre-filter** (pefile): drops uninteresting drivers in milliseconds (~37% eliminated)
3. **Parallel Ghidra headless**: N workers (auto = half CPUs)
4. **97 heuristic checks**: dangerous primitives, IOCTL surface, BYOVD, validation gaps, memory corruption, vendor context, and more
5. **Enriched output**: CSV + JSON + markdown report with vendor/CNA status, prior CVEs, and actionable recommendations

## Priority Tiers

| Tier | Threshold | Action |
|------|-----------|--------|
| 💀 CRITICAL | ≥250 | Drop everything and analyze |
| 🔴 HIGH | ≥150 | Investigate soon |
| 🟡 MEDIUM | ≥75 | Worth a look |
| 🟢 LOW | ≥30 | Probably boring |
| ⚪ SKIP | <30 | Move on |

## Investigated Drivers

Already-analyzed drivers go in `investigated.json` and are skipped on future scans. Supports version-aware skipping: if a driver is updated (version changes), it gets re-scanned automatically.

```json
{
  "investigated": {
    "example.sys": {
      "reason": "4 vulns submitted to vendor PSIRT",
      "version": "2.21.0.0"
    }
  }
}
```

## The Workflow

```
DriverStore --> extract --> running-only --> pre-filter --> Cthaeh --> ranked list --> manual audit
                                                                                        |
                                                           Claude Code + Ghidra MCP --> vuln
```

## Requirements

- Python 3.8+ with `pefile`, `pyyaml`
- Ghidra 10.x+ (headless mode)
- Ghidra 12.x: run `support/pyghidraRun` once if prompted so PyGhidra is installed
- Windows for DriverStore extraction (analysis works on any OS)

See [REFERENCE.md](REFERENCE.md) for the full technical reference (all 97 heuristics, CLI flags, anti-pattern tags).

## Review Artifacts

- [IMPROVEMENTS.md](IMPROVEMENTS.md) - prioritized review findings and recommendations.
- [ROADMAP.md](ROADMAP.md) - v5 scoring, regression, research-feed, and Stage 2 workflow roadmap.

## Acknowledgments

- WDAC block policy checking and LOLDrivers cross-reference inspired by [HolyGrail](https://github.com/BlackSnufkin/Holygrail) by BlackSnufkin.
- Kernel Rhabdomancer candidate point strategy inspired by [Rhabdomancer.java](https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java) by Marco Ivaldi (0xdea). See also: [Automating binary vulnerability discovery with Ghidra and Semgrep](https://hnsecurity.it/blog/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/).
- Anti-pattern tagging (AP1-AP6) based on [KernelSight](https://splintersfury.github.io/KernelSight/guides/secure-driver-anatomy/) vulnerability root cause analysis across 134 CVEs.
- Framework detection and YAML scoring inspired by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) by splintersfury.
- Ghidra Data Type Archive for Windows drivers by [Talos Intelligence](https://blog.talosintelligence.com/ghidra-data-type-archive-for-windows-drivers/).

## License

MIT

---

*"The Cthaeh does not lie. The Cthaeh sees the true shape of the world."*
