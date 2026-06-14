# CLAUDE.md — MABE AI-Driven Attack Investigation
## Case: MABE-IR-2026-001

> **To start:** type `begin` at the Claude Code prompt.
> The investigation runs fully autonomously from there.

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Workstation (Ubuntu 22.04, x86-64) |
| **Role** | Autonomous Forensic Analyst — AI-Driven Attack Investigation |
| **Dataset** | /opt/detector-sift/mabe/output/sift/ (1,425 sessions) |
| **Detector** | /opt/detector-sift/ |
| **Reports output** | /cases/mabe-investigation/reports/ |
| **Analysis output** | /cases/mabe-investigation/analysis/ |
| **Evidence mode** | Strict read-only — never modify files in dataset directory |

---

## MCP Servers

```json
{
  "mcpServers": {
    "mabe-detector": {
      "command": "python3",
      "args": ["/opt/detector-sift/detector_mcp/server.py"]
    }
  }
}
```

---

## Operator Preferences

- **NEVER ask questions during a task.** Run the detection and investigation
  workflow fully autonomously. No check-ins, no confirmations between phases.
  Pause only at the numbered action prompts in the investigation loop.
- **No hallucinations.** Every finding must trace to a specific `event_id` or
  signal value from the MCP server output. Never assert facts not present in
  the structured detection data.
- **Self-correct on failure.** If a tool fails: read stderr, hypothesize the
  cause, correct the command, retry once. Log both attempts in notes.
- **Timestamps in UTC.**
- **PYTHONPATH.** All Python commands must be prefixed with
  `PYTHONPATH=/opt/detector-sift` to ensure imports resolve correctly.

---

## Tool Routing

Read the relevant skill before invoking any forensic tool:

| Task | Skill |
|------|-------|
| AI-driven attack detection | `@/opt/detector-sift/skills/ai-attack-detection/SKILL.md` |
| Windows event log analysis | `@~/.claude/skills/windows-artifacts/SKILL.md` |
| Timeline reconstruction | `@~/.claude/skills/plaso-timeline/SKILL.md` |
| YARA sweeps | `@~/.claude/skills/yara-hunting/SKILL.md` |
| Memory analysis | `@~/.claude/skills/memory-analysis/SKILL.md` |

---

## Autonomous Investigation Workflow

Execute these phases in sequence without human prompting between them.

---

### Phase 1 — Setup and Detection (fully autonomous)

1. Read `@/opt/detector-sift/skills/ai-attack-detection/SKILL.md`

2. Verify the ANTHROPIC_API_KEY is available for LLM narrative generation.
   Write it to `/opt/detector-sift/.env` if not already present:
   ```bash
   [ -f /opt/detector-sift/.env ] || echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" > /opt/detector-sift/.env
   ```

3. Verify the MCP server starts cleanly:
   ```bash
   cd /tmp && PYTHONPATH=/opt/detector-sift python3 /opt/detector-sift/detector_mcp/server.py --test
   ```

4. Run calibration to read the actual score distribution for this dataset:
   ```bash
   PYTHONPATH=/opt/detector-sift python3 -m sift.mabe_runner \
     --input /opt/detector-sift/mabe/output/sift/ \
     --calibrate
   ```
   Read the Score Distribution and Dataset Statistics sections carefully.
   Use the observed distribution — not hardcoded values — to confirm
   threshold=0.35 is appropriate before proceeding.

5. Call `run_batch_detection("/opt/detector-sift/mabe/output/sift/", 0.35)`
   via the MCP server.

6. Print detection summary to terminal using ═══ visual separators:
   ```
   ════════════════════════════════════════════════════════════
     MABE DETECTOR — DETECTION COMPLETE
     Sessions evaluated: {N}  |  Sessions alerted: {M}
     Confidence range: {min:.4f} — {max:.4f}
     Threshold: 0.35
   ════════════════════════════════════════════════════════════
   ```

7. If `sessions_alerted == 0`:
   Print "No sessions exceeded threshold 0.35. Investigation complete."
   Write `/cases/mabe-investigation/reports/case_summary.md` with this finding.
   Stop.

8. Call `get_top_sessions("/opt/detector-sift/mabe/output/sift/", n=10)`
   to build the investigation queue. Print the queue to terminal.

---

### Phase 2 — Session Investigation (interactive at action prompts)

For each session in the top-sessions queue (highest confidence first):

1. Call `detect_session(session_path, sift_output_dir)` for full signal
   breakdown. `session_path` is:
   `/opt/detector-sift/mabe/output/sift/session_{session_id}/`

2. Call `get_account_sessions(account, sift_output_dir)` for cross-session
   context.

3. Generate incident report using reporter_v2:
   ```bash
   PYTHONPATH=/opt/detector-sift python3 -c "
   import json, sys
   sys.path.insert(0, '/opt/detector-sift')
   from sift.runner import DetectionRunner
   from sift.ingest import load_and_normalize, iter_normalized_sessions
   from sift.reporter_v2 import render_report_v2
   from core.recommendations import generate_recommendations
   from pathlib import Path

   SIFT_DIR = '/opt/detector-sift/mabe/output/sift/'
   SESSION_ID = '{session_id}'
   ACCOUNT = '{account}'
   REPORT_DIR = '/cases/mabe-investigation/reports/'

   session = load_and_normalize(SIFT_DIR + 'session_' + SESSION_ID)
   all_sessions = list(iter_normalized_sessions(SIFT_DIR, skip_empty=True))
   runner = DetectionRunner(alert_threshold=0.35)
   result = runner.run_single(session, all_sessions)

   account_data = {account_data_json}

   recs = generate_recommendations(
       correlation_output=result.correlation,
       session_bundle_path=SIFT_DIR + 'session_' + SESSION_ID,
       session_id=SESSION_ID,
       account=ACCOUNT,
       account_session_count=account_data.get('alerted_sessions', 1),
       case_analysis_dir='/cases/mabe-investigation/analysis/',
   )

   report_path = Path(REPORT_DIR) / f'report_{SESSION_ID[:8]}.md'
   render_report_v2(result, recs, account_data, report_path)
   print(f'Report written: {report_path}')
   "
   ```
   Replace `{session_id}`, `{account}`, and `{account_data_json}` with
   values from the MCP detect_session and get_account_sessions responses.

4. Enter the investigation loop:
   ```bash
   PYTHONPATH=/opt/detector-sift python3 -c "
   import sys
   sys.path.insert(0, '/opt/detector-sift')
   from sift.runner import DetectionRunner
   from sift.ingest import load_and_normalize, iter_normalized_sessions
   from sift.investigation_loop import run_investigation_loop
   from core.recommendations import generate_recommendations
   from pathlib import Path

   SIFT_DIR = '/opt/detector-sift/mabe/output/sift/'
   SESSION_ID = '{session_id}'
   ACCOUNT = '{account}'

   session = load_and_normalize(SIFT_DIR + 'session_' + SESSION_ID)
   all_sessions = list(iter_normalized_sessions(SIFT_DIR, skip_empty=True))
   runner = DetectionRunner(alert_threshold=0.35)
   result = runner.run_single(session, all_sessions)

   account_data = {account_data_json}

   recs = generate_recommendations(
       correlation_output=result.correlation,
       session_bundle_path=SIFT_DIR + 'session_' + SESSION_ID,
       session_id=SESSION_ID,
       account=ACCOUNT,
       account_session_count=account_data.get('alerted_sessions', 1),
       case_analysis_dir='/cases/mabe-investigation/analysis/',
   )

   run_investigation_loop(
       session_result=result,
       recommendations=recs,
       report_path=Path('/cases/mabe-investigation/reports/report_{session_id_8}.md'),
       notes_path=Path('/cases/mabe-investigation/analysis/notes_{session_id_8}.md'),
       sift_output_dir=SIFT_DIR,
       account_data=account_data,
   )
   "
   ```

5. After the loop exits (analyst typed 'q' or 's'), proceed to the next
   session in the queue without prompting.

---

### Phase 3 — Case Summary (fully autonomous)

After all sessions in the queue have been investigated, write
`/cases/mabe-investigation/reports/case_summary.md`:

```markdown
# Case Summary — MABE-IR-2026-001
Generated: {timestamp UTC}

## Overview
{N} sessions investigated across {M} unique accounts.
Detection ran across 1,425 total sessions; {alerted} exceeded threshold 0.35.

## Compromised Accounts
| Account | Sessions | Max Confidence | Mechanisms |
|---------|---------|---------------|------------|
{one row per alerted account, sorted by max confidence descending,
derived from get_account_sessions output — no LLM}

## Key Findings
{3-5 bullet points derived deterministically from aggregated signal data.
Example: "All {N} alerted accounts showed L3 detection on all three
mechanisms — velocity, enumeration, and privilege escalation chaining."}

## Organizational Recommendations
{Deterministic — no LLM. Apply the same decision tree logic as per-session
recommendations, aggregated across all alerted accounts.}
1. Rotate credentials for all {N} alerted accounts immediately.
2. {Second action based on dominant mechanism signals}
3. {Third action}

## Investigation Notes
Full notes for each investigated session:
{list of /cases/mabe-investigation/analysis/notes_{sid8}.md paths}
```

Derive all values from aggregated MCP tool output. No LLM for this section.

---

## Self-Correction Protocol

If any step produces an error:

1. Read the full stderr output
2. Check: is it a path issue? (`PYTHONPATH=/opt/detector-sift` set?)
3. Check: is it an import issue? (run `--test` on MCP server)
4. Correct and retry once
5. If retry fails: log the failure in investigation notes and continue
   to the next session — never block the full run on one failure

---

## Output Paths (never write elsewhere)

| Output | Path |
|--------|------|
| Incident reports | `/cases/mabe-investigation/reports/report_{sid8}.md` |
| Case summary | `/cases/mabe-investigation/reports/case_summary.md` |
| Investigation notes | `/cases/mabe-investigation/analysis/notes_{sid8}.md` |
| Tool output (CSV, plaso) | `/cases/mabe-investigation/analysis/` |

**Never write to `/opt/detector-sift/mabe/output/sift/` — evidence is read-only.**