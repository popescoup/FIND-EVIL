# AI-Driven Attack Detection Skill
## MABE Detector v1.0 — Protocol SIFT Extension

### When to use this skill
Invoke when a case contains Windows Security Event logs or Sysmon records
(`security_events.json` / `sysmon_events.json`). These may contain AI-driven
attack behavioral signatures invisible to traditional rule-based detection.

### What this skill detects
Three behavioral mechanisms that distinguish AI-driven attacks from humans:

**VELOCITY** — Sub-second inter-event timing
  AI agents operate at 47–158x human speed (SANS/Lee, Dec 2025).
  Baseline: human median ~3 minutes between events.
  Attack signal: median ~800ms, coefficient of variation < 0.30.

**ENUMERATION** — Exhaustive network traversal
  AI agents probe every reachable host systematically (GTG-1002, Nov 2025).
  Signal: 180+ distinct hosts, all network segments, high-value node contacts
  that no standard user account should make.

**PRIVILEGE ESCALATION CHAINING** — Credential harvest → high-priv auth
  Signal: file access or Kerberos TGT request within 300s of successful
  domain controller or database authentication (arXiv 2502.04227).

### Starting the MCP server
```bash
python3 /opt/detector-sift/detector_mcp/server.py
```
Test: `python3 /opt/detector-sift/detector_mcp/server.py --test`

### Detection workflow
1. `run_batch_detection(sift_output_dir, threshold=0.35)`
2. `get_top_sessions(sift_output_dir, n=10)`
3. `detect_session(session_path, sift_output_dir)` — per session
4. `get_account_sessions(account, sift_output_dir)` — cross-session

### Interpreting confidence scores

Run `--calibrate` first on any dataset to read the actual score distribution
before selecting a threshold. Do not use hardcoded thresholds.

Severity (applied after reading calibration output):
- **HIGH (>= 0.55):** immediate investigation
- **MEDIUM (0.40–0.54):** priority queue
- **LOW (0.35–0.39):** review after higher-priority sessions

In a well-separated dataset you should see a clear gap between the benign
mass (low scores) and the alerted sessions. If scores are uniformly
distributed, re-run calibration and check the dataset statistics section
before adjusting thresholds.

### After detection — handoff to Protocol SIFT
Use the investigation loop and recommendation engine to hand off to:
- `@~/.claude/skills/windows-artifacts/SKILL.md` — EvtxECmd
- `@~/.claude/skills/plaso-timeline/SKILL.md` — log2timeline
- `@~/.claude/skills/yara-hunting/SKILL.md` — YARA sweeps
- `@~/.claude/skills/memory-analysis/SKILL.md` — if memory image available

### Evidence integrity
Detector is read-only. Never modify files in the sift output directory.
All analysis output goes to `/cases/.../analysis/`.
