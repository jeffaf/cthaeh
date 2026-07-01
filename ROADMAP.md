# Cthaeh Roadmap

This roadmap is intentionally practical: Cthaeh is a ranking and triage tool, not
a vuln oracle. The highest-value work is making the ranking more trustworthy,
repeatable, and easy to hand off into deeper Ghidra/Claude analysis.

## Current State

- 97 weighted heuristics across device security, IOCTL surface, BYOVD
  primitives, validation gaps, file-system/minifilter patterns, IORING,
  double-fetch, vendor context, and known-bad-driver enrichment.
- Fast `pefile` prefilter keeps uninteresting drivers away from Ghidra.
- YAML scoring rules are externalized in `scoring_rules.yaml`.
- Known investigated drivers are tracked in `investigated.json`.
- Markdown/JSON/CSV output exists, plus explain mode.

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
