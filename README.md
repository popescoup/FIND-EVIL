# MABE Detector SIFT — AI-Driven Attack Detection
## SANS Find Evil Hackathon 2026 Submission

---

## What this is

MABE Detector is a behavioral detection system for AI-driven cyberattacks —
a class of threat with no public dataset and no existing detection tooling as
of May 2026. It detects the three signatures that distinguish autonomous AI
agents from human operators: machine-speed inter-event timing (47–158x faster
than humans), exhaustive BFS network enumeration across every reachable host,
and credential harvest → privilege escalation chaining within bounded time
windows. The detector is paired with an agentic Claude Code workflow that
runs fully autonomous forensic investigation on the SANS SIFT Workstation,
producing CISO-readable incident reports and handing off to Protocol SIFT
tools (EvtxECmd, log2timeline, YARA) with zero human prompting between phases.

---

## Architecture

```
MABE Generator
(synthetic dataset — 1,425 sessions)
        │
        ▼
  output/sift/
  session_{uuid}/
    security_events.json
    sysmon_events.json
    session_manifest.json
        │
        ▼
MABE Detector Core
  sift/ingest.py        — EVTX → normalized events
  core/mechanisms/      — velocity, enumeration, priv_escalation
  core/baseline.py      — unsupervised per-account baselines
  core/correlation/     — weighted confidence combination
        │
        ▼
  MCP Server
  detector_mcp/server.py
  ┌─────────────────────────────┐
  │ run_batch_detection()       │
  │ detect_session()            │  ← structured JSON, no text parsing
  │ get_account_sessions()      │
  │ get_top_sessions()          │
  └─────────────────────────────┘
        │
        ▼
  Claude Code (claude)
  /cases/mabe-investigation/CLAUDE.md
        │
        ├── Phase 1: Detection (fully autonomous)
        │     run_batch_detection → calibration → queue
        │
        ├── Phase 2: Investigation (interactive at action prompts)
        │     detect_session → reporter_v2 → investigation_loop
        │     ┌──────────────────────────────────────┐
        │     │ Protocol SIFT Skills                  │
        │     │  windows-artifacts → EvtxECmd         │
        │     │  plaso-timeline    → log2timeline      │
        │     │  yara-hunting      → YARA sweeps       │
        │     └──────────────────────────────────────┘
        │
        └── Phase 3: Case Summary (fully autonomous)
              Aggregated findings → case_summary.md

        ▼
  Forensic Reports
  /cases/mabe-investigation/reports/
    report_{sid8}.md      — per-session incident report
    case_summary.md       — full case summary
  /cases/mabe-investigation/analysis/
    notes_{sid8}.md       — investigation notes per session
```

---

## Quick Start (3 steps)

**Prerequisites:** SANS SIFT Workstation, Python 3.10+, Claude Code installed,
`ANTHROPIC_API_KEY` set.

```bash
# 1. Set your API key and run setup (handles everything)
cd /opt/detector-sift
export ANTHROPIC_API_KEY=your_key_here
bash setup.sh

# 2. Open the case
cd /cases/mabe-investigation && claude
```

When the Claude Code prompt appears, type:

```
begin
```

Claude Code runs Phase 1 (detection across all 1,425 sessions) fully
autonomously and prints the alerted account list. When it stops, open
a second SSH terminal and run:

```bash
bash /cases/mabe-investigation/run_phase2.sh
```

The triage queue lets you select which accounts to investigate interactively.

---

## Pre-generated vs Fresh Data

The repository ships with a pre-generated dataset at
`/opt/detector-sift/mabe/output/sift/` (1,425 sessions: 1,350 benign +
75 attack). This dataset is fixed for reproducibility.

To generate a fresh dataset:
```bash
cd /opt/detector-sift/mabe
python main.py \
  --sessions-benign 1350 \
  --sessions-attack 75 \
  --seed 42 \
  --formats evtx
```

Requires `ANTHROPIC_API_KEY` for one-time vocabulary generation only.
All subsequent runs use the cached `vocabulary.json`.

---

## Running the Detector Standalone (without Claude Code)

```bash
cd /opt/detector-sift

# Calibration — examine score distribution first
PYTHONPATH=/opt/detector-sift python3 -m sift.mabe_runner \
  --input mabe/output/sift/ \
  --calibrate

# Full detection run
PYTHONPATH=/opt/detector-sift python3 -m sift.mabe_runner \
  --input mabe/output/sift/ \
  --output reports/ \
  --threshold 0.35 \
  -v

# Single session debug
PYTHONPATH=/opt/detector-sift python3 -m sift.mabe_runner \
  --input mabe/output/sift/ \
  --session 58f40118

# MCP server smoke test
cd /tmp && PYTHONPATH=/opt/detector-sift \
  python3 /opt/detector-sift/detector_mcp/server.py --test
```

---

## Empirical Grounding

Every behavioral parameter traces to a published source:

| Source | What it justifies |
|--------|------------------|
| Anthropic GTG-1002 (Nov 2025) | Sub-second velocity, exhaustive enumeration, credential harvesting, autonomous BFS traversal |
| SANS/Lee (Dec 2025) | 47–158x velocity multiplier; human baseline ~3 min inter-event median |
| Dragos water utility (May 2026) | Scope expansion — AI agents probing targets outside stated objective |
| arXiv 2310.11409 | Dead-end backtracking, file-based credential discovery |
| arXiv 2502.04227 | Multi-hop credential chaining, AS-REP roasting, assumed-breach framing |
| arXiv 2508.02942 (LMDG) | Three-engine architecture, benign behavioral model |

---

## Detection Performance

Validated on 1,425-session MABE dataset (1,350 benign + 75 attack):

| Metric | Value |
|--------|-------|
| Sessions evaluated | 1,425 |
| Sessions alerted (threshold 0.35) | 75 |
| Sessions skipped (errors) | 0 |
| Precision | 100% (0 false positives) |
| Recall | 100% (0 missed attacks) |

Score distribution:

| Percentile | Benign | Attack |
|-----------|--------|--------|
| Median | 0.0200 | ~0.49 |
| p90 | 0.0200 | — |
| p95 | 0.3749 | — |
| Max | — | 0.5809 |

The score distributions do not overlap — every session scoring ≥ 0.35 is
an attack session in this dataset. The gap between p90 (0.02) and the
lowest alert (0.3749) is 0.355 confidence units.

All three mechanisms fire at Layer 3 on high-confidence sessions, meaning
the detection reached the deepest behavioral baseline deviation layer for
velocity (timing consistency), enumeration (new host ratio + node type
shift), and privilege escalation (chain depth + escalation velocity).

---

## Hackathon Submission Context

**Competition:** SANS Find Evil Hackathon — findevil.devpost.com

**The detection problem:** As of May 2026, no public dataset captures the
behavioral signatures of AI-driven attacks. MABE addresses this gap through
synthetic generation from first principles, with every parameter traceable
to a published empirical source. The detector uses fully unsupervised
baselines — no ground truth labels required — making it deployable against
real network logs with no prior labeling.

**The agentic layer:** The MCP server is the hallucination guardrail.
Without it, Claude Code would parse text output and could misread a
confidence score or fabricate a signal value. With it, `run_batch_detection()`
returns `{sessions_evaluated: 1425, sessions_alerted: 75, ...}` as a
structured dict. The agent cannot hallucinate a detection result because
the result is a field value, not a sentence to interpret.

**Evidence integrity:** The detector never reads `session_manifest.json`
ground truth labels during detection. The `is_attack` field is deliberately
excluded from all ingestion paths. Detection is blind to labels; accuracy
evaluation happens separately via post-hoc cross-reference.

---

## Repository Structure

```
/opt/detector-sift/
├── core/                     — detection mechanisms (read-only)
│   ├── mechanisms/           — velocity, enumeration, priv_escalation
│   ├── baseline.py           — unsupervised per-account baselines
│   ├── correlation/agent.py  — weighted confidence combination
│   ├── node_classifier.py    — port → node type inference
│   ├── recommendations.py    — deterministic recommendation engine [NEW]
│   └── schema.py             — immutable interface contract
├── sift/                     — SIFT specialization
│   ├── ingest.py             — EVTX bundle → normalized events
│   ├── runner.py             — batch detection orchestration
│   ├── reporter.py           — v1 deterministic report renderer
│   ├── reporter_v2.py        — v2 LLM narrative + appendix [NEW]
│   ├── investigation_loop.py — interactive terminal UX [NEW]
│   └── mabe_runner.py        — CLI entry point
├── detector_mcp/             — MCP server [NEW]
│   └── server.py             — 4 typed tools for Claude Code
├── skills/                   — Claude Code skills [NEW]
│   └── ai-attack-detection/
│       └── SKILL.md
├── case/                     — Case directory template [NEW]
│   └── CLAUDE.md
├── mabe/                     — Synthetic dataset generator
│   └── output/sift/          — Pre-generated 1,425-session dataset
├── config/                   — Thresholds, baselines, node mapping
├── requirements.txt          — Unified dependencies [NEW]
└── setup.sh                  — One-command judge setup [NEW]
```

---

## Citation

```bibtex
@software{mabe_detector_2026,
  author = {Popescu, Luca},
  title  = {MABE Detector SIFT: Autonomous AI-Driven Attack Detection},
  year   = {2026},
  url    = {https://github.com/popescoup/Malicious-Agent-Behavior-Emulator}
}
```