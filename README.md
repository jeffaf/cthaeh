# Cthaeh

Ghidra powered triage scanner for Windows kernel drivers. Cthaeh scores `.sys`
files across 97 vulnerability heuristics so vulnerability researchers can decide
which drivers deserve manual reverse engineering first.

Cthaeh is not a vulnerability finder and does not generate exploits. It is a
ranking and evidence collection tool for driver attack surface, dangerous
kernel primitives, validation gaps, BYOVD utility, vendor context, and prior
CVE history.

## Sample Output

```text
============================================================
  CTHAEH TRIAGE COMPLETE: 340 drivers analyzed
============================================================
  CRITICAL:        2
  HIGH priority:   14
  MEDIUM priority: 38
  LOW priority:    72
  SKIP:            214

Top targets (>= HIGH):

   1. [CRITICAL] 360 pts  athw8x.sys
   2. [CRITICAL] 310 pts  vhdmp.sys
   3. [HIGH    ] 245 pts  vmci.sys
   4. [HIGH    ] 240 pts  hvservice.sys
```

## Quick Start

```bash
pip install -r requirements.txt
python Cthaeh.py --ghidra "C:\ghidra\ghidra_12.0.3_PUBLIC"
```

That one command runs the normal Windows workflow: it downloads the Talos DTA
when needed, extracts loaded third-party drivers from DriverStore into
`C:\drivers`, then pre-filters and scans the corpus with Ghidra. Parallel workers,
JSON output, and markdown reporting are enabled by default.

Pass `--ghidra` the extracted Ghidra install directory: the directory that
contains `support\analyzeHeadless.bat` or `support\pyghidraRun.bat`. Do not pass
the `support` directory or the launcher itself. For example:

```text
C:\ghidra\ghidra_12.0.3_PUBLIC\
    support\
        analyzeHeadless.bat
```

In that layout, the correct argument is:

```bash
python Cthaeh.py --ghidra "C:\ghidra\ghidra_12.0.3_PUBLIC"
```

The parent directory also works when it contains an extracted `ghidra_*`
directory, so `--ghidra "C:\ghidra"` is valid for the layout above. Cthaeh will
select the newest Ghidra install beneath it.

To avoid passing the flag each time, set `GHIDRA_HOME` to either of those same
directories. In PowerShell:

```powershell
$env:GHIDRA_HOME = "C:\ghidra\ghidra_12.0.3_PUBLIC"
python Cthaeh.py
```

Use `--drivers-dir` to change the corpus directory and `--all` to extract and
scan every driver instead of only loaded drivers:

```bash
python Cthaeh.py --ghidra "C:\ghidra\ghidra_12.0.3_PUBLIC" --drivers-dir D:\cthaeh\drivers --all
```

For an existing corpus, a single driver, or an existing result file, use the
same entry point's scan mode:

```bash
python Cthaeh.py scan C:\drivers --ghidra "C:\ghidra\ghidra_12.0.3_PUBLIC" --all
python Cthaeh.py scan --single C:\path\to\driver.sys --ghidra "C:\ghidra\ghidra_12.0.3_PUBLIC"
python Cthaeh.py scan --explain example.sys
```

For repeatable DTA setup, pin the Talos archive hash:

```bash
python Cthaeh.py setup --sha256 <expected_sha256>
```

You can also set `CTHAEH_DTA_SHA256` in the environment.

## Research Workflow

1. Extract a candidate corpus from DriverStore.
2. Run the pre-filter to keep obvious low-signal drivers out of Ghidra.
3. Run Ghidra headless analysis in parallel.
4. Review HIGH and CRITICAL drivers first.
5. Use `--explain` to inspect why a driver ranked highly.
6. Validate device accessibility and hardware presence when relevant.
7. Record completed work in `investigated.json` so known results are skipped.

```text
DriverStore -> extract -> running-only -> pre-filter -> Cthaeh -> ranked list -> manual audit
```

## Priority Tiers

| Tier | Threshold | Action |
|------|-----------|--------|
| CRITICAL | >= 250 | Analyze immediately |
| HIGH | >= 150 | Investigate soon |
| MEDIUM | >= 75 | Worth a look |
| LOW | >= 30 | Park unless new context appears |
| SKIP | < 30 | Deprioritize |

Thresholds and weights live in `scoring_rules.yaml`. Treat threshold changes as
calibration events, not one-off edits.

## Useful Commands

```bash
# Scan only loaded drivers, the default on Windows
python Cthaeh.py scan C:\drivers

# Scan every driver in the directory
python Cthaeh.py scan C:\drivers --all

# Include post-triage hardware and device DACL checks
python Cthaeh.py scan C:\drivers --hw-check --device-check

# Extract a corpus without immediately scanning it
python Cthaeh.py extract --output C:\drivers

# Generate a calibration report from prior results
# Reports precision@K, recall@HIGH, and fp_leakage — the outcome metrics
# for "did the ranking do its job?", not just shape metrics.
python Cthaeh.py calibrate --json triage_results.json

# Snapshot the outcome metrics as a baseline for future drift checks
python Cthaeh.py calibrate --json triage_results.json --write-baseline calibration_baseline.json

# Detect regression vs. the saved baseline (fails on drift beyond tolerance)
python Cthaeh.py calibrate --json triage_results.json --baseline calibration_baseline.json

# Unit checks that do not require Ghidra output:
#   tier boundaries, disposition split, synthetic scoring profiles that
#   catch weight edits silently crossing a tier boundary.
python Cthaeh.py test --unit

# Run regression checks against a real scan
python Cthaeh.py test --json triage_results.json --strict-missing
```

See [ROADMAP.md](ROADMAP.md#what-better-means) for the outcome-metric contract
and the recalibration loop.

## Investigated Drivers

Already analyzed drivers go in `investigated.json` and are skipped on future
scans. Version-aware skipping is supported: if a driver version changes, Cthaeh
will re-scan it.

```json
{
  "investigated": {
    "example.sys": {
      "reason": "4 vulns submitted to vendor PSIRT",
      "version": "2.21.0.0",
      "disposition": "confirmed_vuln"
    }
  }
}
```

`disposition` classifies the entry for calibration: `confirmed_vuln` (should
score HIGH+ when scanned), `false_positive` (scored high but not exploitable,
must rank below HIGH), or `investigated` (analyzed, no calibration assertion).
`calibrate_scoring.py` only flags `false_positive` drivers that still rank
HIGH+, so confirmed vulns are no longer mistaken for false positives.

## Requirements

- Python 3.8+ with `pefile` and `pyyaml`
- Ghidra 10.x+ in headless mode
- Ghidra 12.x users may need to run `support/pyghidraRun` once if prompted
- Windows for DriverStore extraction, hardware checks, and device DACL checks
- Analysis can run on any OS with Ghidra and extracted `.sys` files

See [REFERENCE.md](REFERENCE.md) for the full technical reference, CLI flags,
environment variables, and heuristic categories.

## Review Artifacts

- [IMPROVEMENTS.md](IMPROVEMENTS.md) - prioritized review findings, actions, and recommendations.
- [ROADMAP.md](ROADMAP.md) - scoring, regression, research-feed, and Stage 2 workflow roadmap.

## Acknowledgments

- WDAC block policy checking and LOLDrivers cross-reference inspired by [HolyGrail](https://github.com/BlackSnufkin/Holygrail) by BlackSnufkin.
- Kernel Rhabdomancer candidate point strategy inspired by [Rhabdomancer.java](https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java) by Marco Ivaldi.
- Anti-pattern tagging based on [KernelSight](https://splintersfury.github.io/KernelSight/guides/secure-driver-anatomy/) vulnerability root cause analysis.
- Framework detection and YAML scoring inspired by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) by splintersfury.
- Ghidra Data Type Archive for Windows drivers by [Talos Intelligence](https://blog.talosintelligence.com/ghidra-data-type-archive-for-windows-drivers/).

## License

MIT
