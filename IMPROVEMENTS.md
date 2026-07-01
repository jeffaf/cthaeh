# Cthaeh - Review Findings & Recommendations

Static review of the triage pipeline, scoring model, tests, and docs.
Scope: architecture, scoring calibration, false-positive control, regression testing,
operational workflow, and documentation. No exploit code or PoCs added.

Reviewer note: this is a triage/ranking tool, not a vulnerability finder. Everything
below is measured against that goal - **rank the drivers most likely to have bugs
first, with few false positives near the top, cheaply and repeatably.**

Findings are ranked by leverage (impact / effort). Each is grounded in a specific file/line.

---

## Actions taken in this pass

- Added `calibrate_scoring.py` so threshold changes can be evaluated against tier distribution, CRITICAL rate, score percentiles, and investigated drivers that still rank HIGH+.
- Added pure scoring helpers in `driver_triage.py` for score summation and priority bucketing, then routed triage priority through them.
- Fixed version-aware investigated skips by populating `driver.version`, reading `FileVersion`/`ProductVersion`, and matching `investigated.json` case-insensitively.
- Reduced `double_fetch_indicator` false positives by scoring it only when prior METHOD_NEITHER evidence exists; otherwise it remains an informational finding.
- Reused one Ghidra `DecompInterface` per double-fetch pass instead of recreating it for each function.
- Expanded IOCTL, PPL, BYOVD, memory-corruption, and comms detection to include common `IoCompleteRequest`, `IofCompleteRequest`, `WdfRequestComplete`, and `Nt*` import variants.
- Fixed the OEM/bloatware age signal so it receives the Ghidra `program` object explicitly instead of relying on a missing global.
- Hardened `download_dta.py` with timeout handling, atomic writes, `--force`, and optional SHA256 pinning via `--sha256` or `CTHAEH_DTA_SHA256`.
- Updated `test_regression.py` to load investigated drivers from `investigated.json`, count missing expected drivers as warnings, support `--strict-missing`, and provide `--unit` checks without Ghidra.
- Rewrote `README.md` in a cleaner researcher-facing style with no emojis or em dashes, and documented calibration plus DTA hash pinning.

## What-better-means pass (2026-07)

- Defined outcome metrics (precision@K, recall@HIGH, fp_leakage) as the primary "did the ranking do its job?" measure. Documented the contract in `ROADMAP.md` and `README.md`.
- Labeled `investigated.json` entries with a `disposition` field: `confirmed_vuln`, `false_positive`, or `investigated`. This is now the single source of truth for calibration; tests and reports derive everything from it.
- Extended `calibrate_scoring.py`:
  - Reports precision@10/25/50, recall@HIGH, and fp_leakage alongside the shape metrics (kept, but marked as proxies).
  - `--write-baseline PATH` snapshots outcome metrics for drift checks.
  - `--baseline PATH` compares current metrics to the snapshot and fails on regression beyond `DRIFT_TOLERANCE`.
- Restructured `test_regression.py`:
  - Removed the tautological "confirmed vuln + INVESTIGATED override = auto PASS" logic. Overridden confirmed vulns now WARN with instructions for how to re-evaluate scoring on merit.
  - `Investigated Drivers by Disposition` now asserts differently per class: confirmed_vuln must be HIGH+ (either on merit or via override), false_positive must be below HIGH on merit, investigated has no scoring assertion.
  - Added `SYNTHETIC_PROFILES` calibrated against real CRITICAL/HIGH drivers in a 340-driver scan. These validate scoring math without Ghidra and fire immediately when a weight edit crosses a tier boundary.
- Regression fired on first run: `amd_dpfc.sys` (disposition=`false_positive`) scores 190 (HIGH) on raw signals with no reducer. See new finding #13 below.

---

## P0 - Scoring calibration (highest leverage)

### 1. Additive scoring with no cap or normalization
`driver_triage.py:3328` sums every finding's weight into one number, then buckets it
against fixed thresholds (`scoring_rules.yaml:9-13`, CRITICAL=250 / HIGH=150 / MEDIUM=75 / LOW=30).

The check set has grown wave over wave (inline `v2`…`v8` tags in `run()`,
`driver_triage.py:3266-3320`) from ~40 checks to 97 weighted checks, but the thresholds
have not moved. Every new wave adds positive points, so the *same* driver scores higher
today than it did at v4 calibration. The practical effect is **tier inflation**: more
drivers drift into HIGH/CRITICAL over time even though nothing about them changed.
The regression suite already encodes an awareness of this risk (`SANITY_CHECKS`
in `test_regression.py:63-66`: max score <= 500, CRITICAL <= 5%), but nothing enforces
recalibration when checks are added.

**Recommend:**
- Recalibrate `thresholds` against a labeled corpus (the 9 entries in `investigated.json`
  plus any additional ground truth) every time the weight set changes. Treat thresholds
  as *derived from data*, not hand-set constants.
- Add per-category caps or diminishing returns so twenty weak signals can't out-vote one
  strong primitive. Group weights by category (device/IOCTL, primitives, BYOVD, validation,
  vendor) and cap each group's contribution.
- Consider reporting a **normalized 0-100 score** alongside the raw sum so the tier
  boundaries are stable as checks are added.

**Status:** partially actioned. `calibrate_scoring.py` now reports distribution,
percentiles, CRITICAL rate, and investigated drivers that still rank HIGH+. Category
caps and normalized 0-100 scoring remain open.

### 2. Compound/composite checks double-count the primitives they summarize
`check_compound_primitives` (`driver_triage.py:1764`) and `check_vuln_pattern_composite`
(`driver_triage.py:1802`) add *additional* points (15-25 each) on top of the individual
findings they are built from. A god-mode driver gets `msr_write` (25) + `physical_memory_rw`
(15) + `compound_god_mode` (15) + very likely `vuln_pattern_composite` (25) = 80 points for
what is really one observation. This is a deliberate boost, but it compounds finding #1's
inflation and is a major driver of the top of the CRITICAL list.

**Recommend:** keep the compound signals (they encode real exploitability judgment) but
make them *rescoring* signals, not additive ones - e.g. a compound match promotes the tier
by one level or applies a small multiplier, rather than stacking a flat 25. Document the
intent in `scoring_rules.yaml` so it survives future edits.

**Status:** open. This should be handled with corpus-backed calibration rather than a
blind weight edit.

### 3. `previousmode_relevant` weight is 0 (dead signal)
`scoring_rules.yaml:139` and `driver_triage.py:151` set `previousmode_relevant: 0`. The
check runs and tags the finding but contributes nothing. That's fine as "informational,"
but it's invisible in the score and undocumented as intentionally-zero. See ROADMAP for
turning PreviousMode into a real signal.

---

## P1 - False-positive control

### 4. `check_double_fetch` is coarse and FP-prone
`driver_triage.py:2774`. The decompiler path fires when any user-buffer token
(`type3inputbuffer`, `userbuffer`, …) appears **>=2 times** in a dispatch function
(`:2836`); the fallback fires when an IRP field offset (`0x18`/`0x60`/`0x70`) appears
**>=3 times** in mov/lea instructions (`:2867`). Both conditions occur routinely in
*correct* handlers that legitimately read a field more than once, and the hardcoded
offsets assume a specific struct layout/calling convention. At weight 20 this can push a
benign driver up a tier.

**Recommend:** require a corroborating signal before scoring (METHOD_NEITHER IOCTL present,
*and* no local capture between reads), or drop the weight and keep it as an informational
tag until it can be validated against known double-fetch CVEs in a canary set.

**Status:** partially actioned. `double_fetch_indicator` now scores only when prior
METHOD_NEITHER evidence exists; otherwise it remains informational. Local-capture
validation and known-CVE canaries remain open.

### 5. FP reducers are sound but unfloored and untested
Negative weights (`has_internal_validation: -10`, `wdf_device_interface: -15`,
`loldrivers_known: -30`, `whql_signed_inbox: -20`) are the main FP controls and match the
documented lessons (nvpcf WDF FP, `driver_triage.py:1837-1846`). There is no test asserting
that these reducers actually move a known-FP driver below CRITICAL - the only FP coverage is
the *investigated-skip* path, which never exercises the scoring math.

**Recommend:** add unit-level tests (see #7) that feed synthetic finding sets through the
reducer logic and assert the resulting tier, so a future weight edit can't silently
neutralize a reducer.

---

## P2 - Regression & test coverage

### 6. Ground truth in tests lags reality
`test_regression.py` docstring claims "8 confirmed vulnerabilities" but `CONFIRMED_VULNS`
lists **3** (`:28-44`), and `INVESTIGATEDS` lists **3** (`:47-60`) while `investigated.json`
now has **9** entries (mtkwl6ex, amd_dpfc, amdfendr, AsusSAIO, etc. are missing from tests).
The tests silently `SKIP` any driver not present in results, so this gap is invisible in a
passing run.

**Recommend:** regenerate `CONFIRMED_VULNS`/`INVESTIGATEDS` from `investigated.json` (single
source of truth), and make a missing expected driver a *soft warning that's counted*, not a
silent skip.

**Status:** actioned for investigated drivers and missing-driver accounting.
`test_regression.py` now loads all 9 investigated entries from `investigated.json`,
counts missing expected drivers as warnings, and supports `--strict-missing`.

### 7. Tests are integration-only - no unit coverage of scoring logic
`test_regression.py` needs a real `triage_results.json` (produced by a full Ghidra run) to
do anything. On this host with no results file it exits 1 with a clear message (verified).
That means the pure-Python decision logic - compound/composite rules, tier bucketing,
anti-pattern mapping (`compute_anti_patterns`, `driver_triage.py:277`), version-aware skip
(`run()` `:3217-3232`) - has **zero automated coverage** and can only be tested by running
Ghidra.

**Recommend:** add a `pytest`-style unit suite that imports the pure functions and feeds
synthetic `findings` lists. These functions take plain dicts, not Ghidra objects, so they're
directly testable without Ghidra:
- `check_compound_primitives`, `check_vuln_pattern_composite` - assert firing conditions.
- tier bucketing - assert threshold boundaries (74->MEDIUM-1, 75->MEDIUM, etc.).
- `compute_anti_patterns` - assert tag mapping.
- version-aware skip - assert re-scan on version change, skip on match.

**Status:** partially actioned. `test_regression.py --unit` now validates score
threshold boundaries and investigated source-of-truth loading without Ghidra.
Direct unit coverage for Ghidra-script helpers remains open because `driver_triage.py`
imports Ghidra modules at load time.

### 8. Canary corpus is still a TODO
The canary concept is well-specified in `test_regression.py:11-19` but unimplemented. This
is the single highest-value guardrail against the calibration drift in P0: without it,
weight tuning has no automated "did I just bury a known-vulnerable driver?" check.

**Recommend:** stand up `canary/` with **download scripts** (not redistributed binaries) for
5-10 drivers with public CVEs, and a `--canary` mode that verifies each still scores its
expected tier. See ROADMAP for the concrete design.

---

## P3 - Performance & code quality

### 9. `DecompInterface` is re-created per function
`check_double_fetch` constructs a new `DecompInterface`, calls `openProgram`, and `dispose`s
it *inside* the per-function loop (`driver_triage.py:2819-2827`). Decompiler setup is
expensive; doing it once per function multiplies analysis time on large drivers. If
`check_candidate_points` (`:2483`) does the same, the cost stacks.

**Recommend:** hoist one `DecompInterface` per program (open once, reuse across functions,
dispose at the end) and pass it into the checks that need decompilation. Measure before/after
on a large `.sys`.

**Status:** partially actioned for `check_double_fetch`. `check_ondisk_offset_trust`
still creates a decompiler per function and should be refactored the same way.

### 10. Invalid escape sequence in a docstring
`driver_triage.py:1458` - the `\\.\DeviceName` docstring triggers a `SyntaxWarning: invalid
escape sequence "\D"` (reproduced on CPython 3.13). Harmless today but will become an error
in a future Python. Trivial fix: make the docstring raw (`r"""`) or escape the backslash.
Fixed in this review by making `check_symlink_creation` use a raw docstring.

**Status:** verified fixed.

---

## P1 - False-positive control (continued)

### 13. `amd_dpfc.sys` false-positive has no raw-signal suppression
Surfaced by the outcome-metric pass. `amd_dpfc.sys` is labeled
`disposition: false_positive` in `investigated.json` and was analyzed as
"nothing exploitable" in Feb 2026, but its raw signals still score **190
(HIGH)** on the 340-driver reference scan. Because the driver was added to
`investigated.json` after the scan, the runtime override does not fire on
this record - so the score is exposed and shows that no reducer captures
why the driver was ruled out. `calibrate_scoring.py` reports it as
`fp_leakage`; `test_regression.py` FAILs on it in the disposition split.

**Recommend:** either (a) attach a specific reducer explaining why the AMD
DPFC signal profile is not exploitable (e.g. `has_internal_validation`,
missing `usb_request_forwarding`, or a new AMD-specific reducer), or (b)
re-review the driver and update the disposition if the FP conclusion no
longer holds. Do not just add another entry to `investigated.json` - the
whole point of the outcome metric is that overrides must not hide missing
reducers.

**Status:** open, flagged by the new eval.

---

## P4 - Documentation

### 11. Undocumented CLI flags and env vars (FIXED in this review)
`REFERENCE.md` was missing `--single`, `--explain`, `--ghidra`, `--max`, `--prefilter-min`,
`--output`, `--json-output`, `--report`, `--min-tier`, and `--drivers-dir`, plus the
`CTHAEH_SCORING_PATH`, `CTHAEH_CNA_PATH`, and `CTHAEH_CVES_PATH` env vars (all present in
`run_triage.py:822-861` / `driver_triage.py:331`). The CLI table and env-var list have been
completed.

### 12. Version labeling is ad-hoc
The `v2`…`v8` tags scattered through `run()` are *check-wave* labels, not release versions,
and there is no CHANGELOG. Newcomers (and future-you) can't tell what "v5" means. The
externally-facing README has no version at all.

**Recommend:** add a short `CHANGELOG.md` (or a `## History` section) that maps each wave to
its research source and the checks it added, and pin a single tool version constant.

---

## Verification performed

- `python3 -m py_compile run_triage.py prefilter.py test_regression.py driver_triage.py download_dta.py extract_driverstore.py hw_check.py device_check.py calibrate_scoring.py apply_dta.py` -> OK.
- `python3 test_regression.py --unit` -> OK, 16 passed and 0 failed (tier boundaries + disposition split + 6 synthetic profiles).
- `python3 test_regression.py --json ~/triage_results.json` -> exposes the amd_dpfc.sys FP-leakage regression documented as finding #13.
- `python3 calibrate_scoring.py --json ~/triage_results.json` -> precision@10=1.00, precision@50=0.98, recall@HIGH=1.00 (3/3), fp_leakage=1.
- `python3 calibrate_scoring.py ... --write-baseline` and `--baseline` round-trip verified; drift detection fires when fp_leakage_count grows or precision/recall drop past `DRIFT_TOLERANCE`.
- `scoring_rules.yaml` -> valid YAML, **97 weights**, thresholds 250/150/75/30.
- `investigated.json`, `driver_cves.json`, and `cna_vendors.json` -> valid JSON. `investigated.json` now carries a `disposition` field on every entry.
- Not verified: a fresh Ghidra triage run with `amd_dpfc.sys` temporarily removed from `investigated.json` to confirm the raw-signal FP-leakage without cache effects. Requires a live scan.
