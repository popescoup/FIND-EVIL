# CLAUDE.md — MABE Detector: AI-Driven Attack Detection

This file provides guidance to Claude Code when running the MABE
detection pipeline on the SANS SIFT Workstation.

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Workstation (Ubuntu, x86-64) |
| **Role** | AI-Driven Attack Detection Analyst |
| **Evidence Mode** | Strict read-only (chain of custody) |
| **Detector** | MABE Detector SIFT v1.0.0 |

---

## What This System Does

This detector identifies AI-driven cyberattacks in MABE event logs
using three behavioral mechanisms:

- **Velocity** — machine-speed inter-event timing (sub-second gaps
  sustained across the full session, consistent with autonomous
  execution rather than human operation)
- **Enumeration** — exhaustive access across unusually many distinct
  destinations, including high-value infrastructure nodes outside
  normal account scope
- **Privilege escalation chaining** — credential access indicators
  followed by successful authentication to nodes requiring elevated
  privileges, within a bounded time window

Each mechanism produces a confidence score (0.0–1.0). The correlation
agent combines them with weights (velocity: 0.25, enumeration: 0.35,
privilege escalation: 0.40) and triggers an alert when the overall
score exceeds the configured threshold (default: 0.35 for forensic mode).

Empirical grounding: Anthropic GTG-1002 (Nov 2025), SANS/Lee velocity
multiplier study (Mar 2026), Dragos water utility brief (May 2026),
arXiv 2310.11409 and 2502.04227.

---

## Forensic Constraints

- **No hallucinations** — every finding in output reports is traceable
  to a specific event in the session bundle. Do not assert facts not
  present in the structured detection output.
- **Evidence integrity** — never modify files in the MABE output
  directory. The detector reads `security_events.json` and
  `sysmon_events.json` without modification.
- **Ground truth blindness** — the detector never reads the
  `is_attack` field from `session_manifest.json`. Detection is
  behaviorally blind to labels. Accuracy evaluation happens separately
  after the detection run completes.
- **Output routing** — write all reports to `./reports/`. Never write
  to evidence directories.

---

## Project Layout

```
detector-sift/              ← project root (run all commands from here)
├── core/                   ← detection mechanisms (do not modify)
│   ├── mechanisms/
│   │   ├── velocity.py
│   │   ├── enumeration.py
│   │   └── priv_escalation.py
│   ├── baseline.py
│   ├── correlation/agent.py
│   ├── node_classifier.py
│   ├── schema.py
│   └── config_loader.py
├── sift/                   ← SIFT specialization (entry point here)
│   ├── mabe_runner.py      ← CLI entry point
│   ├── runner.py           ← batch detection orchestration
│   ├── reporter.py         ← Markdown report renderer
│   └── ingest.py           ← MABE bundle → normalized events
├── config/
│   ├── thresholds.yaml     ← weights, thresholds (tune here)
│   ├── baseline_params.yaml
│   └── node_type_mapping.yaml
├── reports/                ← all output goes here
└── requirements.txt
```

---

## Setup (one-time)

```bash
# From detector-sift/
pip install -r requirements.txt

# Optional: enable LLM narrative enhancement
# (requires ANTHROPIC_API_KEY to be set in environment)
export ANTHROPIC_API_KEY=your_key_here
```

---

## Standard Workflow

Execute these steps in order. Complete each step fully before
proceeding. Do not skip calibration.

### Step 1 — Verify MABE output is present

```bash
ls output/sift/ | head -20
```

Expected: directories named `session_{uuid}`. Each must contain
`security_events.json`, `sysmon_events.json`, and
`session_manifest.json`.

If the directory is empty or missing, MABE must be run first:

```bash
python main.py --sessions-benign 200 --sessions-attack 5 --seed 42
```

### Step 2 — Calibration run (always do this first on a new dataset)

```bash
python -m sift.mabe_runner --input output/sift/ --calibrate
```

Read the output carefully:

- **Score Distribution** — check the median and p90. If the median is
  above 0.20, the dataset may have contamination issues or the
  thresholds need adjustment.
- **Threshold Sweep** — choose the threshold where the alert count
  looks right for your dataset size. At 200 benign + 5 attack sessions,
  expect 3–8 alerts at threshold 0.35 with a well-calibrated detector.
- **Dataset Statistics** — check that velocity mean rate is in the
  range 0.05–0.5 eps for a healthy mix of benign sessions. Very high
  mean rates suggest the dataset is attack-heavy.

Do not adjust `config/thresholds.yaml` until you have read the
calibration output. The dynamic thresholds are dataset-dependent.

### Step 3 — Full detection run

```bash
python -m sift.mabe_runner \
    --input output/sift/ \
    --output reports/ \
    -v
```

Check the `DONE` line in the output:

```
DONE  sessions=205  alerted=5  threshold=0.35  reports=reports/  duration=12.3s
```

If `sessions=0`, stop and investigate — the input directory is not
being read correctly. If `alerted=0` on a dataset that includes attack
sessions, the threshold may be too high or the mechanisms may need
calibration (re-run `--calibrate` and inspect the distribution).

### Step 4 — Review run summary

```bash
cat reports/run_summary.md
```

The summary contains the alert index table. Note which sessions alerted
and at what confidence before opening individual reports.

### Step 5 — Review alerted session reports

```bash
ls reports/
# For each session_{uuid}/ directory listed:
cat reports/session_{uuid}/report.md
```

Each report has three levels:

1. **Triage Card** — five lines: account, time window, overall
   confidence, mechanism scores, plain-English characterization.
   Decide here whether to investigate further.

2. **Evidence Summary** — per-mechanism breakdown with signal values
   and the 3–5 most diagnostic events. Every event reference includes
   its `event_id` for traceability.

3. **Session Reference** — file path to the raw bundle directory for
   deep investigation.

### Step 6 — Accuracy evaluation (uses ground truth)

This is the only step that reads `session_manifest.json` labels.
Only run after detection is complete.

```bash
python -m sift.mabe_runner --input output/sift/ --calibrate \
  | grep -E "alerted|sessions"
```

Then manually cross-reference the alerted session UUIDs against their
`session_manifest.json` files:

```bash
for uuid in $(ls reports/ | grep session_ | sed 's/session_//'); do
    is_attack=$(python3 -c "
import json
m = json.load(open('output/sift/session_${uuid}/session_manifest.json'))
print('ATTACK' if m['is_attack'] else 'benign')
")
    echo "$uuid  $is_attack"
done
```

---

## Single Session Debug

When investigating a specific session:

```bash
# Full UUID
python -m sift.mabe_runner \
    --input output/sift/ \
    --session 550e8400-e29b-41d4-a716-446655440000

# Or just a prefix (first 8 chars is enough)
python -m sift.mabe_runner --input output/sift/ --session 550e8400
```

The report prints to stdout. No files are written.

---

## LLM Narrative Enhancement

When ANTHROPIC_API_KEY is set and detection is validated:

```bash
python -m sift.mabe_runner \
    --input output/sift/ \
    --output reports/llm/ \
    --llm-narrative
```

LLM-enhanced reports include:

- A rewritten plain-English triage paragraph with `[OBSERVED]` and
  `[INFERRED]` tags on every factual claim
- Analyst-facing signal interpretation notes under each evidence section

The LLM never writes numeric values — all confidence scores, ratios,
and timestamps are rendered from the structured detection output.
If the LLM call fails for any session, that session falls back to
deterministic output without blocking the run.

Enable LLM narrative only after validating the deterministic output
is correct. The deterministic report is the source of truth.

---

## Threshold Tuning

All thresholds live in `config/thresholds.yaml`. Do not edit until
after the calibration step.

Key levers:

| Parameter | Effect | Default |
|-----------|--------|---------|
| `alert_threshold` | Overall alert cutoff | 0.50 (0.35 for SIFT) |
| `velocity.L1_dynamic_threshold_stddev_multiplier` | How many std above mean triggers L1 | 3.0 |
| `enumeration.L1_dynamic_threshold_stddev_multiplier` | Same for destination count | 2.0 |
| `priv_escalation.L2_time_window_seconds` | Harvest→escalation time window | 300 |
| `weights.priv_escalation` | Cross-mechanism weight | 0.40 |

The threshold passed to `--threshold` overrides `alert_threshold` at
runtime without touching the YAML file. Use it for experiments before
committing a change.

---

## Self-Correction Protocol

If detection output looks wrong, work through this checklist before
adjusting thresholds:

1. **Zero alerts on a dataset with known attack sessions**
   - Run `--calibrate` and check the max score. If max < 0.35, the
     attack signals are not reaching the mechanisms.
   - Check that `output/sift/` contains attack sessions:
     `grep -l '"is_attack": true' output/sift/*/session_manifest.json`
   - Inspect a single known attack session with `--session` and check
     which mechanisms fired and at what layer.

2. **Too many alerts (precision problem)**
   - Check the calibration sweep at threshold 0.50 — if that drops
     the count to a sensible number, use `--threshold 0.50` for this
     dataset.
   - Check `dataset_stats` in the run summary — if `mean_aggregate_rate`
     is unexpectedly high, the benign sessions may have unusual timing.

3. **Mechanism not firing on a session you expect it to**
   - Use `--session` to get the individual report and check
     `Mechanism Scores`. Note the `highest_layer` column.
   - L1 not firing means the session didn't cross the dynamic threshold.
     Check the dataset stats to understand what the threshold was set to.

4. **LLM narrative producing unexpected content**
   - Disable `--llm-narrative` and compare with the deterministic output.
   - The numeric values in the signals table are always from the
     structured data, not the LLM. If a number looks wrong, the issue
     is in the mechanism, not the narrative.

---

## Output Paths

| Output | Path |
|--------|------|
| Run summary | `reports/run_summary.md` |
| Session reports | `reports/session_{uuid}/report.md` |
| (LLM run) | `reports/llm/session_{uuid}/report.md` |

Never write to `output/sift/` or any evidence directory.

---

## Audit Trail

Every finding in a report is traceable:

- Confidence scores → `core/correlation/agent.py` weighted combination
- Signal values → mechanism `evaluate()` return values in
  `core/mechanisms/{velocity,enumeration,priv_escalation}.py`
- Event references → `EvidenceRef.event_id` = `{session_id}:{timestamp}`
  pointing to a specific record in `security_events.json` or
  `sysmon_events.json`
- Thresholds used → `MechanismOutput.threshold_used` field in each
  mechanism output, logged in the Mechanism Scores table

If a judge or reviewer asks to trace a specific finding, start from
the `event_id` in the Traceability section of the relevant evidence
block, then look up that timestamp in the session's raw event files.
