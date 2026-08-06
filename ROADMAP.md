# Cthaeh Roadmap

This roadmap is intentionally practical: Cthaeh is a ranking and triage tool, not
a vuln oracle. The highest-value work is making the ranking more trustworthy,
repeatable, and easy to hand off into deeper Ghidra/Claude analysis.

## What "better" means

Cthaeh has exactly one job: **rank the drivers most likely to have bugs first,
with few false positives near the top, cheaply and repeatably.** Every
optimization is measured against that contract, not against shape metrics.

**Outcome metrics** (what "better" actually is):

- `precision@10 / @25 / @50` - of the top K by score, what fraction are NOT
  confirmed false positives? A regression here means analyst time is being
  wasted at the top of the list.
- `recall@HIGH` - of confirmed-vuln drivers scored on merit (i.e. not
  overridden by `investigated.json`), what fraction landed >= HIGH? A drop
  means real bugs are being buried.
- `fp_leakage` - count of confirmed-FP drivers whose raw signals still land
  HIGH+. Any non-zero value is a reducer-suppression bug, not just noise.

**Proxy metrics** (kept for shape, distrusted for correctness):

- `CRITICAL rate <= 5%`, `max_score <= 500`, `score_median`, `score_p90` -
  these describe the distribution. Both can pass while the ranking is wrong,
  so they are guardrails, not goals.

**Ground-truth source of truth:** `investigated.json`. Each entry carries a
`disposition` in `{confirmed_vuln, false_positive, investigated}`. The tests
and calibration report derive everything from this file. Adding a new label
is a two-line change; the eval will pick it up on the next run.

**Where the project was optimizing the wrong proxy:**

- `test_regression.SANITY_CHECKS` (max=500, CRITICAL <=5%) enforced score
  *shape*, not ranking quality. Both currently pass on a 340-driver scan
  while `amd_dpfc.sys` (a confirmed FP) still ranks HIGH.
- The old `CONFIRMED_VULNS` test auto-PASSed when a confirmed vuln was
  overridden to `INVESTIGATED` ("skip is correct"). Once a driver was added
  to `investigated.json`, the test became tautological.
- The old `INVESTIGATEDS` test treated confirmed vulns and confirmed FPs as
  a single "should be skipped" bucket - rewarding Cthaeh for *hiding* both,
  when the actual goal is scoring the vulns HIGH and the FPs LOW.

**Recalibration loop:**

1. Change a weight, threshold, or check.
2. Run `python test_regression.py --unit`. Synthetic profiles catch tier
   boundary drift immediately (no Ghidra needed).
3. On the next full scan, run
   `python calibrate_scoring.py --json triage_results.json --baseline calibration_baseline.json`.
   Baseline drift beyond `DRIFT_TOLERANCE` (calibrate_scoring.py:24-30) fails
   the check.
4. If the change is intentional (heuristic wave), re-baseline with
   `--write-baseline calibration_baseline.json` and record the reason next
   to the threshold change.

## Current State

- 97 weighted heuristics across device security, IOCTL surface, BYOVD
  primitives, validation gaps, file-system/minifilter patterns, IORING,
  double-fetch, vendor context, and known-bad-driver enrichment.
- Fast `pefile` prefilter keeps uninteresting drivers away from Ghidra.
- YAML scoring rules are externalized in `scoring_rules.yaml`.
- Known investigated drivers are tracked in `investigated.json`.
- Markdown/JSON/CSV output exists, plus explain mode.
- Intrinsic research priority is separated from host exposure: stopped drivers
  are excluded from the default scan, hardware absence is informational, and
  hardware-absent binaries are excluded from actionable local rankings while
  remaining in JSON/CSV for traceability.

## v5 Focus

### 1. Scoring Calibration

Problem: new checks keep adding points, but thresholds are still static. That
creates score inflation over time.

Deliverables:

- Add a calibration script that consumes a labeled `triage_results.json`.
- Report tier distribution, critical percentage, max score, median score, and
  false-positive drivers above HIGH.
- Store calibration notes next to each threshold change.
- Consider category caps so many weak signals cannot overwhelm one strong
  primitive.

Suggested output:

```text
thresholds:
  CRITICAL: 275
  HIGH: 165
  MEDIUM: 80
  LOW: 30

calibration:
  corpus: win11-laptop-2026-07
  drivers: 340
  critical_rate: 1.8%
  confirmed_vulns_high_or_better: 100%
  investigated_false_positives_high_or_better: 0%
```

### 2. Canary Regression Harness

Problem: `test_regression.py` knows the canary idea, but it still depends on an
external full scan and silently skips missing expected drivers.

Deliverables:

- Create a `canary/` directory for metadata and download/build scripts, not
  redistributed binaries.
- Track expected minimum tier per driver and version.
- Add a `--canary` check that fails when known-vulnerable drivers fall below
  expected tier.
- Add a warning count for expected drivers missing from scan results.

Initial canary classes:

- Weak device object / missing ACL driver.
- USB or Bluetooth passthrough driver.
- BYOVD process killer driver.
- Physical memory or MSR primitive driver.
- FS/minifilter offset-trust driver.

### 3. Heuristic Quality Pass

Problem: some high-value checks are intentionally coarse and need corroboration.

Priority checks:

- `double_fetch_indicator`: require METHOD_NEITHER and no obvious local capture
  before scoring at full weight.
- `ondisk_offset_trust`: keep FS/minifilter gating, but record the specific
  parsed field and whether a bounds check was absent or merely not detected.
- `previousmode_relevant`: promote from zero-point info tag only if paired with
  a dangerous dereference or caller-mode decision.
- BYOVD primitives: split process-kill, arbitrary R/W, kernel execute, and
  callback/minifilter interference into separate categories for clearer
  recommendations.

### 4. Research Feeds to Checks

Use research feeds as inputs to bounded static signals, not as vague inspiration.

Exploit Reversing:

- Minifilter exploitation: improve FS/minifilter offset trust and callback-path
  prioritization.
- I/O Ring: keep IORING surface informational unless paired with shared memory,
  file object, or user-mode bridge signals.
- PreviousMode: score only when the driver reads or trusts caller mode around
  user-controlled buffers.
- Token/ALPC material: add static indicators for token object manipulation and
  ALPC communication surfaces when they appear in imports/strings.

Atos/BYOVD-style work:

- Keep process-killer scoring, but add explicit "weaponization class" labels so
  Cthaeh can distinguish EDR-kill, arbitrary R/W, and code-execute candidates.

PhantomRPC-style work:

- Treat RPC/ALPC/named-pipe style user-mode bridges as attack-surface amplifiers
  only when paired with privileged kernel actions. Avoid boosting pure comms
  drivers too aggressively.

### 5. Stage 2 Workflow

Problem: the README says "Claude Code + Ghidra MCP -> vuln", but the handoff is
not formalized.

Deliverables:

- Add a prompt generator that turns one HIGH/CRITICAL result into a Stage 2
  Ghidra/Claude checklist.
- Include triggered checks, anti-pattern tags, likely device names, suspected
  IOCTL paths, and "prove/disprove" questions.
- Store analyst notes with result hash, driver version, and investigated status.

Recommended Stage 2 prompt sections:

- Driver identity and signer.
- Why Cthaeh ranked it high.
- Entry points to inspect first.
- Dangerous APIs and caller context questions.
- User-accessibility checks.
- False-positive hypotheses to disprove.
- Evidence checklist for vendor report quality.

## Near-Term Tasks

1. Add calibration report command.
2. Add synthetic unit tests for pure scoring helpers.
3. Implement canary metadata format.
4. Tune or demote `double_fetch_indicator`.
5. Add Stage 2 prompt generator.
6. Add changelog/history for heuristic waves.

## Guardrails

- Prefer static ranking and analyst handoff over exploit automation.
- Keep known LOLDrivers useful for context but deprioritized for novel research.
- Require a second corroborating signal before high-weighting noisy checks.
- Preserve `scoring_rules.yaml` as the human-editable scoring surface.
- Treat every threshold change as a calibration event.
