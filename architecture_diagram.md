# MAD Detector Architecture

```
  ┌───────────────────────────────────────────────────────────┐
  │ mabe/output/sift/session_{uuid}/                          │
  │ security_events.json, sysmon_events.json,                 │
  │ session_manifest.json  [read-only — never modified]       │
  └───────────────────────────────┬───────────────────────────┘
                                  │
                                  ▼
              ┌────────────────────────────────────────────────┐
              │ sift/ingest.py                                 │
              │ Maps EVTX-style and Sysmon fields to normalized│
              │ event dicts. Reads manifest for account name   │
              │ only — is_attack is never accessed.            │
              └─────────────────────────┬──────────────────────┘
                                        │  list[NormalizedSession]
                                        ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ sift/runner.py — DetectionRunner                                    │
  │ Ingests full corpus, computes dataset-level statistics, builds      │
  │ per-account baselines (each session excluded from its own           │
  │ baseline), then evaluates all three mechanisms per session.         │
  └──────────┬──────────────────────────────────────────────────────────┘
             │
             │  feeds into
             ▼
  ┌─────────────────────────────────────┐   ┌─────────────────────────────────────┐
  │ core/baseline.py                    │   │ config/thresholds.yaml              │
  │ Builds unsupervised per-account     │   │ config/baseline_params.yaml         │
  │ behavioral baselines. Falls back to │   │ config/node_type_mapping.yaml       │
  │ population baseline for sparse      │   │ All weights, thresholds, and layer  │
  │ accounts. No labels required.       │   │ params. Nothing hardcoded.          │
  └────────────────────┬────────────────┘   └──────────────┬──────────────────────┘
                       └──────────────┬────────────────────┘
                                      │
                                      ▼
              ┌────────────────────────────────────────────────┐
              │ core/node_classifier.py                        │
              │ Infers node type from dst_port using the       │
              │ node_type_mapping config. Used by all three    │
              │ mechanisms to identify high-value targets.     │
              └─────────────────────────┬──────────────────────┘
                                        │
                                        ▼
  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────────┐
  │ mechanisms/         │  │ mechanisms/          │  │ mechanisms/             │
  │ velocity.py         │  │ enumeration.py       │  │ priv_escalation.py      │
  │                     │  │                      │  │                         │
  │ L1: aggregate rate  │  │ L1: destination      │  │ L1: high-priv node      │
  │ vs dynamic thresh.  │  │ count vs dynamic     │  │ auth beyond session     │
  │ L2: median inter-   │  │ thresh.              │  │ starting privilege.     │
  │ event gap vs dist.  │  │ L2: segment and      │  │ L2: credential access   │
  │ percentile.         │  │ high-value node      │  │ indicator precedes      │
  │ L3: timing CV       │  │ type anomaly.        │  │ priv auth within 300s.  │
  │ (machine vs human   │  │ L3: baseline         │  │ L3: chain depth,        │
  │ consistency).       │  │ deviation across     │  │ privilege gap, and      │
  │                     │  │ three components.    │  │ escalation velocity.    │
  └──────────┬──────────┘  └──────────┬──────────┘  └────────────┬────────────┘
             │  MechanismOutput        │  MechanismOutput          │  MechanismOutput
             └─────────────────────┬──┴──────────────────────────-┘
                                   │
                                   ▼
              ┌────────────────────────────────────────────────┐
              │ core/correlation/agent.py                      │
              │ Combines mechanism outputs with configured     │
              │ weights (vel 0.25, enum 0.35, priv 0.40).     │
              │ Applies high-confidence floor rule. Produces   │
              │ TriageCard, EvidenceSummary, and session_ref.  │
              └─────────────────────────┬──────────────────────┘
                                        │  CorrelationOutput
                                        ▼
              ┌────────────────────────────────────────────────┐
              │ detector_mcp/server.py                         │
              │ Exposes four typed MCP tools to Claude Code:   │
              │ run_batch_detection, detect_session,           │
              │ get_account_sessions, get_top_sessions.        │
              │ Returns structured dicts — never prose.        │
              │ [ARCHITECTURAL GUARDRAIL: no shell passthrough,│
              │ no arbitrary command execution, structured     │
              │ data only — LLM cannot misread a float field.] │
              └──────────────┬─────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
  ┌───────────────────────┐     ┌───────────────────────────────┐
  │ Phase 1 (autonomous)  │     │ Phase 2 (interactive)         │
  │ case/CLAUDE.md        │     │ sift/investigation_loop.py    │
  │                       │     │                               │
  │ Claude Code calls     │     │ Analyst selects accounts from │
  │ run_batch_detection,  │     │ triage queue. Loop calls      │
  │ calibrates threshold, │     │ detect_session, generates     │
  │ builds alerted        │     │ report, presents Protocol     │
  │ account list, writes  │     │ SIFT recommendations, executes│
  │ all_sessions.json.    │     │ tools, summarizes output.     │
  │ [PROMPT GUARDRAIL:    │     │ [PROMPT GUARDRAIL: every LLM  │
  │ never write to        │     │ claim tagged [OBSERVED] or    │
  │ evidence directory.]  │     │ [INFERRED]. Numeric values    │
  │                       │     │ from structured data only.]   │
  └──────────┬────────────┘     └──────────────┬────────────────┘
             │                                  │
             └──────────────┬───────────────────┘
                            │
                            ▼
              ┌────────────────────────────────────────────────┐
              │ core/recommendations.py                        │
              │ Deterministic decision tree. Maps signal values│
              │ to prioritized Protocol SIFT actions. Kerberos │
              │ timing → EvtxECmd. Low timing CV → YARA.      │
              │ Multiple sessions → MCP cross-correlation.     │
              │ No LLM involved.                               │
              └──────────────┬─────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
  ┌───────────────────────┐     ┌───────────────────────────────┐
  │ sift/reporter_v2.py   │     │ Protocol SIFT tools           │
  │ Part 1: LLM narrative │     │ (where applicable)            │
  │ (exec summary,        │     │                               │
  │ timeline). Falls back │     │ EvtxECmd  [NEEDS NATIVE EVTX] │
  │ to deterministic if   │     │ log2timeline  [NEEDS NATIVE   │
  │ LLM unavailable.      │     │               EVTX]           │
  │ Part 2: fully         │     │ YARA  [READY — runs against   │
  │ deterministic signal  │     │        JSON bundle dir]       │
  │ tables and evidence   │     │ MCP tools  [READY]            │
  │ chain. All numeric    │     │                               │
  │ values from structured│     │                               │
  │ detection output.     │     │                               │
  └──────────┬────────────┘     └───────────────────────────────┘
             │
             ▼
  ┌───────────────────────────────────────────────────────────┐
  │ /cases/mabe-investigation/                                │
  │ reports/report_{sid8}.md — per-session incident report.  │
  │ reports/case_summary.md  — Phase 3 deterministic summary.│
  │ analysis/notes_{sid8}.md — investigation notes per acct. │
  │ analysis/all_sessions.json — full per-session cache.     │
  └───────────────────────────────────────────────────────────┘
```
