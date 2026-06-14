# CLAUDE.md — MABE AI-Driven Attack Investigation
## Case: MABE-IR-2026-001

> **To start:** type `begin` at the Claude Code prompt.
> Claude Code runs Phase 1 (detection) fully autonomously, then prints
> the exact command for you to run Phase 2 (investigation) in your terminal.

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Workstation (Ubuntu 22.04, x86-64) |
| **Role** | Autonomous Forensic Analyst — AI-Driven Attack Detection |
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
      "args": ["/opt/detector-sift/detector_mcp/server.py"],
      "env": {"PYTHONPATH": "/opt/detector-sift"}
    }
  }
}
```

---

## Operator Preferences

- **NEVER ask questions during a task.** Phase 1 runs fully autonomously.
  Do not pause, check in, or ask for confirmation at any point.
- **No hallucinations.** Every finding must trace to a specific `event_id`
  or signal value from the MCP server output. Never assert facts not
  present in the structured detection data.
- **Self-correct on failure.** If a tool fails: read stderr, hypothesize
  the cause, correct the command, retry once. Log both attempts in notes.
- **Timestamps in UTC.**
- **PYTHONPATH.** All Python commands must be prefixed with
  `PYTHONPATH=/opt/detector-sift` to ensure imports resolve correctly.
- **Phase 2 is NOT run by Claude Code.** It requires a real terminal TTY
  for interactive input. Claude Code prints the command; the analyst runs it.

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

## Workflow

---

### Phase 1 — Detection (Claude Code runs this autonomously)

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

6. If `sessions_alerted == 0`:
   Print "No sessions exceeded threshold 0.35. Detection complete."
   Write `/cases/mabe-investigation/reports/case_summary.md` with this
   finding and stop.

7. Build the alerted account list — one entry per unique account, sorted
   by max confidence descending. For each account collect:
   - account name
   - max_confidence (highest confidence session for that account)
   - alerted_sessions (count of alerted sessions for that account)
   - highest_session_id (UUID of the highest-confidence session)
   - highest_layer (e.g. "Enumeration:L3, Velocity:L3, PrivEsc:L3")

8. Write a JSON file with the account list for Phase 2 to consume:
   ```bash
   # Write to /cases/mabe-investigation/analysis/alerted_accounts.json
   ```

9. Print the detection summary using these exact visual separators:
   ```
   ════════════════════════════════════════════════════════════
     MABE DETECTOR — DETECTION COMPLETE
     Sessions evaluated: {N}  |  Sessions alerted: {M}
     Accounts flagged: {K}  |  Threshold: 0.35
     Confidence range: {min:.4f} — {max:.4f}
   ════════════════════════════════════════════════════════════

   ALERTED ACCOUNTS:
   ────────────────────────────────────────────────────────────
   [ 1] joseph.davis          0.5809   1 session    all L3
   [ 2] george.winfield       0.5791   2 sessions   all L3
   ...
   ────────────────────────────────────────────────────────────
   ```

10. Write the Phase 2 script to `/cases/mabe-investigation/run_phase2.sh`:
    ```bash
    cat > /cases/mabe-investigation/run_phase2.sh << 'EOF'
    #!/bin/bash
    PYTHONPATH=/opt/detector-sift python3 -c "
    import json
    from sift.investigation_loop import run_triage_queue
    accounts = json.load(open('/cases/mabe-investigation/analysis/alerted_accounts.json'))
    run_triage_queue(
        alerted_accounts=accounts,
        sift_output_dir='/opt/detector-sift/mabe/output/sift/',
        case_analysis_dir='/cases/mabe-investigation/analysis/',
        case_reports_dir='/cases/mabe-investigation/reports/',
    )
    "
    EOF
    chmod +x /cases/mabe-investigation/run_phase2.sh
    ```

11. Print the handoff message:
    ```
    ════════════════════════════════════════════════════════════
      DETECTION COMPLETE.

      To begin interactive investigation, open a new terminal and run:

          bash /cases/mabe-investigation/run_phase2.sh

    ════════════════════════════════════════════════════════════
    ```

12. Stop. Do not attempt to run Phase 2.

---

### Phase 2 — Interactive Investigation (analyst runs this in terminal)

**This phase is NOT run by Claude Code.** In a separate SSH terminal, run:

```bash
bash /cases/mabe-investigation/run_phase2.sh
```

The triage queue will display the alerted account list and prompt:

```
Investigate accounts [1-15], enter numbers (e.g. 1,2,5), (a)ll, or (q)uit:
```

Enter the account numbers you want to investigate. For each selected
account the loop will:
1. Run detection for the highest-confidence session
2. Generate an incident report with LLM narrative
3. Present recommended actions with numbered prompts
4. Execute tools, summarize output, detect follow-on actions
5. Append findings to investigation_notes.md
6. Move to the next selected account

Type `q` at any action prompt to finish that account and move to the next.

---

### Phase 3 — Case Summary (Claude Code runs this after Phase 2)

After the analyst finishes Phase 2 and Phase 2 exits, return to Claude Code
and type:

```
write case summary
```

Claude Code will read the generated reports and notes from
`/cases/mabe-investigation/` and write
`/cases/mabe-investigation/reports/case_summary.md` covering:

- Overview: total sessions, alerted sessions, accounts flagged
- Compromised accounts table (sorted by max confidence)
- Key findings (3-5 bullets, derived from aggregated signal data, no LLM)
- Organizational recommendations (deterministic decision tree, no LLM)
- Links to all investigation notes

Derive all values from the report files and JSON artifacts in
`/cases/mabe-investigation/analysis/`. No LLM for this section.

---

## Self-Correction Protocol

If any step produces an error:

1. Read the full stderr output
2. Check: is it a path issue? (`PYTHONPATH=/opt/detector-sift` set?)
3. Check: is it an import issue? (run `--test` on MCP server)
4. Correct and retry once
5. If retry fails: log the failure and continue — never block the full
   run on one failure

---

## Output Paths (never write elsewhere)

| Output | Path |
|--------|------|
| Alerted accounts JSON | `/cases/mabe-investigation/analysis/alerted_accounts.json` |
| Incident reports | `/cases/mabe-investigation/reports/report_{sid8}.md` |
| Case summary | `/cases/mabe-investigation/reports/case_summary.md` |
| Investigation notes | `/cases/mabe-investigation/analysis/notes_{sid8}.md` |
| Tool output (CSV, plaso) | `/cases/mabe-investigation/analysis/` |

**Never write to `/opt/detector-sift/mabe/output/sift/` — evidence is read-only.**