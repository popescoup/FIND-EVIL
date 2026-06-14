"""
MABE Detector — MCP Server
============================
Version: 1.0.0

Exposes the MABE detection pipeline as typed MCP tools for Claude Code.
All tools return structured JSON dicts — Claude Code receives typed data,
not text, eliminating a class of hallucination risk.

ARCHITECTURAL ROLE
------------------
This server is the hallucination guardrail described in the submission.
Without MCP: Claude Code calls shell commands, receives text, interprets
that text. The model could misread a confidence score, fabricate a signal
value, or draw conclusions from partially understood output.

With MCP: `run_batch_detection()` returns
    {sessions_evaluated: 1425, sessions_alerted: 75, top_sessions: [...]}
The confidence score 0.5809 comes from a field in a dict, not from parsing
a sentence. The agent physically cannot hallucinate a detection result
because the MCP server returns structured data, not prose.

LIFECYCLE
---------
On-demand: started by Claude Code when a case opens via the mcpServers
block in CLAUDE.md. Does not run as a persistent background service.

TOOLS
-----
  run_batch_detection   — full corpus detection, returns DetectionResult summary
  detect_session        — single session full signal breakdown
  get_account_sessions  — all sessions for one account, sorted by confidence
  get_top_sessions      — top N alerted sessions for investigation queue

USAGE (test mode)
-----------------
  python3 /opt/detector-sift/mcp/server.py --test
"""

from __future__ import annotations

import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Optional

# ── Ensure detector root is on path ──────────────────────────────────
DETECTOR_ROOT = Path("/opt/detector-sift")
sys.path.insert(0, str(DETECTOR_ROOT))

from mcp.server import FastMCP

from sift.runner import DetectionRunner, DetectionResult, SessionResult
from sift.ingest import (
    load_and_normalize,
    iter_normalized_sessions,
    NormalizedSession,
)
from core.baseline import BaselineBuilder
from core.schema import (
    CorrelationOutput,
    MechanismOutput,
    Signal,
    EvidenceRef,
    EvidenceSummary,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP("mabe-detector")

# ---------------------------------------------------------------------------
# Tool: run_batch_detection
# ---------------------------------------------------------------------------

@mcp.tool()
def run_batch_detection(
    sift_output_dir: str,
    threshold: float = 0.35,
) -> dict:
    """
    Run full detection across all sessions in a MABE sift output directory.

    This is the primary entry point for a case. Runs all three mechanisms
    (velocity, enumeration, privilege escalation) across every session bundle
    found under sift_output_dir. Dynamic thresholds are derived from the full
    corpus — no labels required.

    Args:
        sift_output_dir: Absolute path to MABE output/sift/ directory
                         containing session_* bundles.
        threshold: Alert confidence threshold (default 0.35, recall-optimized
                   for SIFT forensic mode). Lower = more alerts.

    Returns:
        sessions_evaluated: Total sessions processed
        sessions_alerted: Sessions where confidence >= threshold
        alert_threshold: Threshold used for this run
        run_duration_s: Wall-clock runtime in seconds
        score_distribution: {min, p25, median, p75, p90, p95, max}
        top_sessions: Top 10 alerted sessions sorted by confidence descending,
                      each with {session_id, account, confidence,
                      mechanisms_fired, highest_layer_per_mechanism,
                      data_window: {start, end}}
        skipped_sessions: List of session_ids that failed evaluation
    """
    runner = DetectionRunner(alert_threshold=threshold)
    result = runner.run(sift_output_dir)

    top_sessions = [
        _session_result_to_summary(r)
        for r in result.alerted_results[:10]
    ]

    return {
        "sessions_evaluated":  result.sessions_evaluated,
        "sessions_alerted":    result.sessions_alerted,
        "alert_threshold":     result.alert_threshold,
        "run_duration_s":      result.run_duration_s,
        "score_distribution":  result.score_distribution,
        "top_sessions":        top_sessions,
        "skipped_sessions":    result.skipped_sessions,
    }


# ---------------------------------------------------------------------------
# Tool: detect_session
# ---------------------------------------------------------------------------

@mcp.tool()
def detect_session(
    session_path: str,
    sift_output_dir: str,
    threshold: float = 0.35,
) -> dict:
    """
    Run all three detection mechanisms against a single session bundle.

    The target session is automatically excluded from baseline construction
    to prevent contamination of its own deviation scores. The full corpus
    from sift_output_dir is used for baseline and dataset statistics.

    Args:
        session_path: Absolute path to a single session_* bundle directory.
        sift_output_dir: Absolute path to MABE output/sift/ directory.
                         Required for baseline construction — the target
                         session is excluded from its own baseline.
        threshold: Alert threshold (default 0.35).

    Returns:
        session_id: str
        account: str
        overall_confidence: float (0.0–1.0)
        alert_triggered: bool
        mechanisms_fired: list of mechanism ids that fired
        highest_layer_per_mechanism: {velocity: int, enumeration: int,
                                      priv_escalation: int}
        triage_plain_english: str — programmatic one-sentence characterization
        data_window: {start: ISO str, end: ISO str}
        signal_summary:
            velocity: list of {name, observed, baseline, ratio, contribution}
            enumeration: list of {name, observed, baseline, ratio, contribution}
            priv_escalation: list of {name, observed, baseline, ratio,
                                      contribution}
        evidence_summary:
            velocity: {headline, top_events: [{event_id, timestamp,
                       event_type, significance}]}
            enumeration: {headline, top_events: [...]}
            priv_escalation: {headline, top_events: [...]}
        high_confidence_floor_applied: bool
        weights_used: {velocity: float, enumeration: float,
                       priv_escalation: float}
    """
    # Load target session
    target = load_and_normalize(session_path)

    # Load full corpus for baseline construction
    all_sessions = list(
        iter_normalized_sessions(sift_output_dir, skip_empty=True)
    )

    runner = DetectionRunner(alert_threshold=threshold)
    result = runner.run_single(target, all_sessions)

    return _full_session_result_to_dict(result)


# ---------------------------------------------------------------------------
# Tool: get_account_sessions
# ---------------------------------------------------------------------------

@mcp.tool()
def get_account_sessions(
    account: str,
    sift_output_dir: str,
    threshold: float = 0.35,
) -> dict:
    """
    Return all sessions for an account with confidence scores and context.

    Runs detection across the full corpus and filters to sessions belonging
    to the specified account. Useful for cross-session correlation after
    identifying a compromised account.

    Args:
        account: Username / account identifier (e.g. "joseph.davis").
        sift_output_dir: Absolute path to MABE output/sift/ directory.
        threshold: Alert threshold (default 0.35).

    Returns:
        account: str
        total_sessions: Total sessions found for this account
        alerted_sessions: Sessions where confidence >= threshold
        confidence_range: {min: float, max: float} — across alerted sessions
        first_seen: ISO timestamp of earliest session start
        last_seen: ISO timestamp of latest session end
        sessions: List sorted by confidence descending, each with
                  {session_id, confidence, alert_triggered, mechanisms_fired,
                   data_window: {start, end}}
    """
    runner = DetectionRunner(alert_threshold=threshold)
    result = runner.run(sift_output_dir)

    # Filter to this account
    account_results = [
        r for r in result.results
        if (r.session.account or "").lower() == account.lower()
    ]

    if not account_results:
        return {
            "account":            account,
            "total_sessions":     0,
            "alerted_sessions":   0,
            "confidence_range":   {"min": 0.0, "max": 0.0},
            "first_seen":         "",
            "last_seen":          "",
            "sessions":           [],
        }

    alerted = [r for r in account_results if r.correlation.alert_triggered]
    alerted_confidences = [r.correlation.overall_confidence for r in alerted]

    # Collect timestamps across all sessions
    all_starts = []
    all_ends = []
    for r in account_results:
        tw = r.correlation.triage_card.time_window
        if tw.start:
            all_starts.append(tw.start)
        if tw.end:
            all_ends.append(tw.end)

    first_seen = min(all_starts) if all_starts else ""
    last_seen  = max(all_ends)   if all_ends   else ""

    sessions_list = [
        {
            "session_id":      r.correlation.session_id,
            "confidence":      r.correlation.overall_confidence,
            "alert_triggered": r.correlation.alert_triggered,
            "mechanisms_fired": r.correlation.mechanisms_fired,
            "data_window": {
                "start": r.correlation.triage_card.time_window.start,
                "end":   r.correlation.triage_card.time_window.end,
            },
        }
        for r in sorted(
            account_results,
            key=lambda r: r.correlation.overall_confidence,
            reverse=True,
        )
    ]

    return {
        "account":          account,
        "total_sessions":   len(account_results),
        "alerted_sessions": len(alerted),
        "confidence_range": {
            "min": round(min(alerted_confidences), 4) if alerted_confidences else 0.0,
            "max": round(max(alerted_confidences), 4) if alerted_confidences else 0.0,
        },
        "first_seen":  first_seen,
        "last_seen":   last_seen,
        "sessions":    sessions_list,
    }


# ---------------------------------------------------------------------------
# Tool: get_top_sessions
# ---------------------------------------------------------------------------

@mcp.tool()
def get_top_sessions(
    sift_output_dir: str,
    n: int = 10,
    threshold: float = 0.35,
) -> list:
    """
    Return top N alerted sessions sorted by confidence descending.

    Use at the start of a case to build the investigation queue.
    Runs full detection across the corpus — results are consistent with
    run_batch_detection() called with the same parameters.

    Args:
        sift_output_dir: Absolute path to MABE output/sift/ directory.
        n: Number of top sessions to return (default 10).
        threshold: Alert threshold (default 0.35).

    Returns:
        List of up to n sessions, each with:
            session_id: str
            account: str
            confidence: float
            mechanisms_fired: list[str]
            highest_layer_per_mechanism: {velocity, enumeration,
                                          priv_escalation} → int
            data_window: {start: str, end: str}
    """
    runner = DetectionRunner(alert_threshold=threshold)
    result = runner.run(sift_output_dir)

    return [
        _session_result_to_summary(r)
        for r in result.alerted_results[:n]
    ]


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _session_result_to_summary(result: SessionResult) -> dict:
    """
    Serialize a SessionResult to the compact summary dict returned by
    run_batch_detection and get_top_sessions.
    """
    c = result.correlation
    return {
        "session_id":   c.session_id,
        "account":      c.triage_card.account,
        "confidence":   c.overall_confidence,
        "mechanisms_fired": c.mechanisms_fired,
        "highest_layer_per_mechanism": c.highest_layer_per_mechanism,
        "data_window": {
            "start": c.triage_card.time_window.start,
            "end":   c.triage_card.time_window.end,
        },
    }


def _full_session_result_to_dict(result: SessionResult) -> dict:
    """
    Serialize a SessionResult to the full dict returned by detect_session.
    Includes signal details and evidence for each mechanism.
    """
    c = result.correlation

    signal_summary  = {}
    evidence_summary = {}

    for summary in c.evidence_summary:
        mid = summary.mechanism_id
        signal_summary[mid] = [
            {
                "name":         s.name,
                "observed":     s.observed,
                "baseline":     s.baseline,
                "ratio":        s.ratio,
                "contribution": s.contribution,
            }
            for s in summary.top_signals
        ]
        evidence_summary[mid] = {
            "headline": summary.headline,
            "top_events": [
                {
                    "event_id":    e.event_id,
                    "timestamp":   e.timestamp,
                    "event_type":  e.event_type,
                    "significance": e.significance,
                }
                for e in summary.top_events
            ],
        }

    # Fill in empty dicts for mechanisms that didn't fire
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        if mid not in signal_summary:
            signal_summary[mid]  = []
        if mid not in evidence_summary:
            evidence_summary[mid] = {"headline": "", "top_events": []}

    return {
        "session_id":        c.session_id,
        "account":           c.triage_card.account,
        "overall_confidence": c.overall_confidence,
        "alert_triggered":   c.alert_triggered,
        "mechanisms_fired":  c.mechanisms_fired,
        "highest_layer_per_mechanism": c.highest_layer_per_mechanism,
        "triage_plain_english": c.triage_card.plain_english,
        "data_window": {
            "start": c.triage_card.time_window.start,
            "end":   c.triage_card.time_window.end,
        },
        "signal_summary":    signal_summary,
        "evidence_summary":  evidence_summary,
        "high_confidence_floor_applied": c.high_confidence_floor_applied,
        "weights_used":      c.weights_used,
    }


# ---------------------------------------------------------------------------
# Test mode
# ---------------------------------------------------------------------------

def _run_test() -> int:
    """
    Smoke test: verify all imports resolve and tool functions are registered.
    Does not require a live MABE dataset.
    """
    print("MABE Detector MCP Server — import test")
    print("=" * 50)

    errors = []

    # Import checks
    checks = [
        ("sift.runner.DetectionRunner",      DetectionRunner),
        ("sift.ingest.load_and_normalize",   load_and_normalize),
        ("core.schema.CorrelationOutput",    CorrelationOutput),
        ("core.baseline.BaselineBuilder",    BaselineBuilder),
    ]
    for label, obj in checks:
        if obj is not None:
            print(f"  ✓  {label}")
        else:
            print(f"  ✗  {label}  — import failed")
            errors.append(label)

    # Tool registration check
    try:
        tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    except AttributeError:
        tool_names = list(mcp._tools.keys()) if hasattr(mcp, "_tools") else []
    expected_tools = [
        "run_batch_detection",
        "detect_session",
        "get_account_sessions",
        "get_top_sessions",
    ]
    print()
    print("Registered MCP tools:")
    for name in expected_tools:
        if name in tool_names:
            print(f"  ✓  {name}")
        else:
            print(f"  ✗  {name}  — NOT registered")
            errors.append(name)

    print()
    if errors:
        print(f"FAIL  {len(errors)} error(s): {errors}")
        return 1
    else:
        print("PASS  All imports and tool registrations OK")
        print()
        print("MCP server config block for case CLAUDE.md:")
        print(json.dumps({
            "mcpServers": {
                "mabe-detector": {
                    "command": "python3",
                    "args": ["/opt/detector-sift/mcp/server.py"],
                }
            }
        }, indent=2))
        return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MABE Detector MCP Server",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run import and registration smoke test, then exit",
    )
    args = parser.parse_args()

    if args.test:
        sys.exit(_run_test())
    else:
        # Start MCP server in stdio mode (Claude Code connects via stdio)
        mcp.run()