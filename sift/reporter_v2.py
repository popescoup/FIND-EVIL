"""
MABE Detector — Forensic Report Renderer v2
=============================================
Version: 1.0.0

Generates two-part incident reports for alerted sessions.

PART 1 — ANALYST REPORT (LLM-generated narrative)
    Readable by a CISO in 90 seconds. Tells a story. Every claim tagged
    [OBSERVED] or [INFERRED]. No signal names, no ratio tables, no jargon.
    Answers: what happened, when, who, how severe, what to do right now.

PART 2 — TECHNICAL APPENDIX (fully deterministic, no LLM)
    Mechanism scores, signal tables, evidence chain, raw bundle reference.
    Identical to the output of reporter.py (v1) — analysts use this for
    traceability and threshold calibration.

LLM CALL SPECIFICATION
-----------------------
Model: claude-sonnet-4-6
max_tokens: 800
Input: signal_summary dict + event_sequence tuples — NEVER raw event records
Output: {executive_summary: str, incident_timeline: str}
Fallback: deterministic template from CorrelationOutput.triage_card.plain_english
on any failure — a failed LLM call never blocks report generation.

DO NOT MODIFY reporter.py (v1). This is an additive file.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.schema import (
    CorrelationOutput,
    EvidenceSummary,
    Signal,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)
from core.recommendations import Recommendation
from sift.runner import SessionResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------

SEVERITY_HIGH   = 0.55
SEVERITY_MEDIUM = 0.40
SEVERITY_LOW    = 0.35  # == alert threshold

# ---------------------------------------------------------------------------
# Mechanism display names
# ---------------------------------------------------------------------------

MECHANISM_DISPLAY = {
    MECHANISM_VELOCITY:    "Velocity",
    MECHANISM_ENUMERATION: "Enumeration",
    MECHANISM_PRIV_ESC:    "Privilege Escalation",
}

# ---------------------------------------------------------------------------
# LLM system prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a forensic analyst writing an incident report for a CISO.
Every factual claim must be tagged [OBSERVED] (directly in event logs) or
[INFERRED] (pattern-based conclusion from behavioral analysis).
Write in plain English. No jargon, no signal names, no ratio values.
The executive summary must answer: what happened, when, how severe.
The incident timeline must read as a briefing paragraph to a non-technical
executive — not a log dump.

Respond with JSON only, no preamble, no markdown fences:
{"executive_summary": "string", "incident_timeline": "string"}

Do not include attacker_accomplishments — that section is rendered
deterministically from structured data. Do not reproduce raw event records.\
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_report_v2(
    session_result: SessionResult,
    recommendations: list[Recommendation],
    account_data: dict,
    output_path: Path,
    anthropic_client=None,
) -> Path:
    """
    Render a two-part incident report and write it to output_path.

    Parameters
    ----------
    session_result : SessionResult
        Detection result for the session being reported.
    recommendations : list[Recommendation]
        Ordered recommendations from generate_recommendations().
    account_data : dict
        Output of get_account_sessions() MCP call — provides cross-session
        context for the Account Context section.
    output_path : Path
        Where to write the report. Parent directory is created if needed.
    anthropic_client : anthropic.Anthropic | None
        Pre-instantiated client. If None, instantiates from
        ANTHROPIC_API_KEY environment variable. Falls back to deterministic
        output if unavailable.

    Returns
    -------
    Path
        The path the report was written to.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    c = session_result.correlation
    client = anthropic_client or _init_client()

    # Fetch LLM narrative (fails gracefully)
    llm = _fetch_llm_narrative(c, client) if client else None

    content = _build_report(c, recommendations, account_data, llm)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Report written: %s", output_path)
    return output_path


def render_report_v2_string(
    session_result: SessionResult,
    recommendations: list[Recommendation],
    account_data: dict,
    anthropic_client=None,
) -> str:
    """
    Render the report and return as a string without writing to disk.
    Used by the investigation loop for terminal display.
    """
    c = session_result.correlation
    client = anthropic_client or _init_client()
    llm = _fetch_llm_narrative(c, client) if client else None
    return _build_report(c, recommendations, account_data, llm)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def _build_report(
    c: CorrelationOutput,
    recommendations: list[Recommendation],
    account_data: dict,
    llm: Optional[dict],
) -> str:
    now_utc = _now_iso()
    severity = _severity_label(c.overall_confidence)
    sid8 = c.session_id[:8]

    lines: list[str] = []
    a = lines.append

    # ══════════════════════════════════════════════════════════════════
    # PART 1 — ANALYST REPORT
    # ══════════════════════════════════════════════════════════════════

    a(f"# INCIDENT REPORT — {c.triage_card.account}")
    a("")
    a(f"**Severity:** {severity}  |  "
      f"**Confidence:** `{c.overall_confidence:.4f}`  |  "
      f"**Session:** `{c.session_id}`")
    a(f"**Period:** {c.triage_card.time_window.start} → "
      f"{c.triage_card.time_window.end}  |  "
      f"**Generated:** {now_utc}")
    a("")
    a("---")
    a("")

    # ── Executive Summary ─────────────────────────────────────────────
    a("## Executive Summary")
    a("")
    if llm and llm.get("executive_summary"):
        a(llm["executive_summary"])
    else:
        a(_deterministic_executive_summary(c))
    a("")
    a("---")
    a("")

    # ── Incident Timeline ─────────────────────────────────────────────
    a("## Incident Timeline")
    a("")
    if llm and llm.get("incident_timeline"):
        a(llm["incident_timeline"])
    else:
        a(_deterministic_timeline(c))
    a("")
    a("---")
    a("")

    # ── Account Context ───────────────────────────────────────────────
    a("## Account Context")
    a("")
    alerted   = account_data.get("alerted_sessions", 1)
    cr        = account_data.get("confidence_range", {})
    conf_min  = cr.get("min", c.overall_confidence)
    conf_max  = cr.get("max", c.overall_confidence)
    first_seen = account_data.get("first_seen", c.triage_card.time_window.start)
    last_seen  = account_data.get("last_seen",  c.triage_card.time_window.end)
    mech_str   = ", ".join(
        MECHANISM_DISPLAY.get(m, m) for m in c.mechanisms_fired
    ) or "—"

    a("| | |")
    a("|---|---|")
    a(f"| **Account** | `{c.triage_card.account}` |")
    a(f"| **Alerted sessions** | {alerted} "
      f"(confidence {conf_min:.4f} — {conf_max:.4f}) |")
    a(f"| **First seen** | {first_seen} |")
    a(f"| **Last seen** | {last_seen} |")
    a(f"| **Detection mechanisms** | {mech_str} |")
    a("")
    if alerted > 1:
        cross_id = next(
            (r.id for r in recommendations
             if r.command_template == "mcp:get_account_sessions"),
            None,
        )
        ref = f" Run action [{cross_id}] to correlate all sessions." \
              if cross_id else ""
        a(f"This account has **{alerted} alerted sessions**. "
          f"This report covers the highest-confidence session.{ref}")
        a("")
    a("---")
    a("")

    # ── Attacker Accomplishments ──────────────────────────────────────
    a("## Attacker Accomplishments")
    a("")
    ev_by_mech = {s.mechanism_id: s for s in c.evidence_summary}

    # Destination count
    dest_count = _get_signal_value(ev_by_mech, MECHANISM_ENUMERATION,
                                   "distinct_destination_count")
    a(f"- **Hosts contacted:** "
      f"{int(dest_count) if dest_count else 'Unknown'} distinct")

    # High-value targets
    hv_events = []
    en_summary = ev_by_mech.get(MECHANISM_ENUMERATION)
    if en_summary:
        hv_events = [
            e for e in en_summary.top_events
            if "high-value" in e.significance.lower()
            or "domain_controller" in e.significance
            or "database" in e.significance
        ]
    # Deduplicate while preserving order
    _seen_hv: set = set()
    _hv_deduped: list = []
    for e in hv_events:
        if e.inline:
            h = e.inline.get("dst_host", "")
            if h and h not in _seen_hv:
                _seen_hv.add(h)
                _hv_deduped.append(h)
    hv_names = ", ".join(_hv_deduped) if _hv_deduped else "None detected"
    a(f"- **High-value targets reached:** {hv_names or 'None detected'}")

    # Segments
    seg_count = _get_signal_value(ev_by_mech, MECHANISM_ENUMERATION,
                                  "distinct_segment_count")
    a(f"- **Network segments accessed:** "
      f"{int(seg_count) if seg_count else 'Unknown'}")

    # Privilege escalation
    chain_depth = _get_signal_value(ev_by_mech, MECHANISM_PRIV_ESC,
                                    "chain_depth")
    if chain_depth:
        a(f"- **Privilege escalation:** Yes — {int(chain_depth)} level(s)")
        a(f"- **Credential harvest:** Probable — {int(chain_depth)} "
          f"credential(s) inferred")
    else:
        a("- **Privilege escalation:** Not detected")
        a("- **Credential harvest:** Not detected")

    a("")
    a("---")
    a("")

    # ── Recommended Actions ───────────────────────────────────────────
    a("## Recommended Actions")
    a("")
    for rec in recommendations:
        status_pad = rec.status.ljust(16)
        a(f"[{rec.id}] **{rec.title}**  [{rec.status}]")
        a(f"     {rec.basis}")
        a(f"     Tool: {rec.tool}")
        a("")
    a("---")
    a("")
    a("*(Technical appendix follows — mechanism scores, signal tables, "
      "evidence chain)*")
    a("")

    # ══════════════════════════════════════════════════════════════════
    # PART 2 — TECHNICAL APPENDIX (fully deterministic)
    # ══════════════════════════════════════════════════════════════════

    a("---")
    a("")
    a(f"# Technical Appendix — {sid8}")
    a("")

    # ── Mechanism scores table ────────────────────────────────────────
    a("## Detection Mechanism Scores")
    a("")
    a("| Mechanism | Weight | Confidence | Highest Layer | Status |")
    a("|-----------|--------|-----------|--------------|--------|")
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        score  = c.triage_card.mechanism_scores.get(mid, 0.0)
        layer  = c.highest_layer_per_mechanism.get(mid, 0)
        name   = MECHANISM_DISPLAY.get(mid, mid)
        weight = c.weights_used.get(mid, 0.0)
        if mid in c.mechanisms_absent:
            status = "absent"
        elif mid in c.mechanisms_fired:
            status = f"fired (L{layer})"
        else:
            status = "no signal"
        a(f"| {name} | {weight} | `{score:.4f}` | "
          f"{'L' + str(layer) if layer > 0 else '—'} | {status} |")
    a("")
    if c.high_confidence_floor_applied:
        a("*⚠ High-confidence floor applied: single mechanism exceeded "
          "0.90 trigger threshold.*")
        a("")

    # ── Signal details ────────────────────────────────────────────────
    a("## Signal Details")
    a("")
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        name = MECHANISM_DISPLAY.get(mid, mid)
        a(f"### {name}")
        a("")
        summary = ev_by_mech.get(mid)
        if summary and summary.top_signals:
            a("| Signal | Observed | Baseline | Ratio | Contribution |")
            a("|--------|---------|---------|-------|-------------|")
            for sig in summary.top_signals:
                a(f"| `{sig.name}` | `{sig.observed}` | `{sig.baseline}` "
                  f"| `{sig.ratio:.4f}x` | `{sig.contribution:.2f}` |")
        else:
            a("*No signals fired.*")
        a("")

    # ── Evidence chain ────────────────────────────────────────────────
    a("## Evidence Chain")
    a("")
    a("Every finding above traces to one of these event references.")
    a("")
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        name = MECHANISM_DISPLAY.get(mid, mid)
        summary = ev_by_mech.get(mid)
        if not summary or not summary.top_events:
            continue
        a(f"### {name}")
        a("")
        for ev in summary.top_events:
            a(f"- **`{ev.event_id}`** — {ev.event_type} @ {ev.timestamp}")
            a(f"  *{ev.significance}*")
            if ev.inline:
                dst  = ev.inline.get("dst_host", "")
                user = ev.inline.get("user", "")
                ok   = ev.inline.get("success")
                parts = []
                if user: parts.append(f"user=`{user}`")
                if dst:  parts.append(f"dst=`{dst}`")
                if ok is not None: parts.append(f"success=`{ok}`")
                if parts:
                    a(f"  {', '.join(parts)}")
        a("")

    # ── Raw bundle reference ──────────────────────────────────────────
    a("## Raw Bundle Reference")
    a("")
    a("```")
    a(c.session_ref)
    a("```")
    a("")
    a("Files: `security_events.json`, `sysmon_events.json`, "
      "`session_manifest.json`")
    a("")
    a("*Note: `session_manifest.json` contains ground truth labels — "
      "do not use for detection. Detection is performed blind to ground truth.*")
    a("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LLM narrative
# ---------------------------------------------------------------------------

def _fetch_llm_narrative(
    c: CorrelationOutput,
    client,
) -> Optional[dict]:
    """
    Call claude-sonnet-4-6 for executive summary and incident timeline.
    Returns None on any failure — caller uses deterministic fallback.
    """
    payload = _build_llm_payload(c)

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=800,
            system=_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": (
                    f"Write an incident report narrative for the following "
                    f"detection result.\n\n"
                    f"```json\n{json.dumps(payload, indent=2)}\n```"
                ),
            }],
        )
        raw = response.content[0].text.strip()

        # Strip accidental markdown fences
        if raw.startswith("```"):
            raw = "\n".join(
                l for l in raw.splitlines()
                if not l.startswith("```")
            ).strip()

        data = json.loads(raw)

        # Validate required keys
        if "executive_summary" not in data or "incident_timeline" not in data:
            logger.warning("LLM response missing required keys — using fallback")
            return None

        return data

    except Exception as exc:
        logger.warning(
            "LLM narrative call failed for session %s: %s — using deterministic fallback",
            c.session_id, exc,
        )
        return None


def _build_llm_payload(c: CorrelationOutput) -> dict:
    """
    Build the structured payload sent to the LLM.
    Never includes raw event records — only summaries.
    """
    ev_by_mech = {s.mechanism_id: s for s in c.evidence_summary}

    signal_summary = {}
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        summary = ev_by_mech.get(mid)
        if summary:
            signal_summary[mid] = [
                {
                    "name":      s.name,
                    "observed":  s.observed,
                    "baseline":  s.baseline,
                    "ratio":     s.ratio,
                }
                for s in summary.top_signals
            ]

    # Event sequence: (timestamp, event_type, dst_host, success) tuples only
    event_sequence = []
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        summary = ev_by_mech.get(mid)
        if not summary:
            continue
        for ev in summary.top_events:
            dst = ""
            if ev.inline:
                dst = ev.inline.get("dst_host") or ev.inline.get("dest", "")
            event_sequence.append({
                "timestamp":  ev.timestamp,
                "event_type": ev.event_type,
                "dst_host":   dst,
                "success":    ev.inline.get("success") if ev.inline else None,
            })

    event_sequence.sort(key=lambda e: e.get("timestamp", ""))

    return {
        "account":         c.triage_card.account,
        "confidence":      c.overall_confidence,
        "mechanisms_fired": c.mechanisms_fired,
        "period": {
            "start": c.triage_card.time_window.start,
            "end":   c.triage_card.time_window.end,
        },
        "signal_summary":  signal_summary,
        "event_sequence":  event_sequence[:20],  # cap to avoid context overflow
    }


# ---------------------------------------------------------------------------
# Deterministic fallbacks
# ---------------------------------------------------------------------------

def _deterministic_executive_summary(c: CorrelationOutput) -> str:
    """
    Fallback executive summary when LLM is unavailable.
    Uses triage_card.plain_english as the base and adds severity framing.
    """
    severity = _severity_label(c.overall_confidence)
    base = c.triage_card.plain_english
    return (
        f"[OBSERVED] {base}\n\n"
        f"[INFERRED] Overall detection confidence: {c.overall_confidence:.4f} "
        f"({severity}). "
        f"Mechanisms fired: {', '.join(c.mechanisms_fired) or 'none'}."
    )


def _deterministic_timeline(c: CorrelationOutput) -> str:
    """
    Fallback incident timeline when LLM is unavailable.
    Renders top evidence events as a readable sequence.
    """
    ev_by_mech = {s.mechanism_id: s for s in c.evidence_summary}
    events = []
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        summary = ev_by_mech.get(mid)
        if summary:
            for ev in summary.top_events:
                events.append((ev.timestamp, ev.event_type, ev.significance))

    if not events:
        return "[OBSERVED] No event timeline available — no evidence events recorded."

    events.sort(key=lambda e: e[0])
    lines = []
    for ts, etype, sig in events[:8]:
        lines.append(f"[OBSERVED] {ts} — {etype}: {sig}")
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_label(confidence: float) -> str:
    if confidence >= SEVERITY_HIGH:
        return "HIGH"
    if confidence >= SEVERITY_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _get_signal_value(
    ev_by_mech: dict,
    mechanism_id: str,
    signal_name: str,
) -> Optional[float]:
    """Extract a specific signal's observed value from evidence summaries."""
    summary = ev_by_mech.get(mechanism_id)
    if not summary:
        return None
    for sig in summary.top_signals:
        if sig.name == signal_name:
            return sig.observed
    return None


def _now_iso() -> str:
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _init_client():
    """Attempt to initialise Anthropic client from environment or .env file."""
    try:
        # Load from .env file if present — needed when running inside Claude Code
        # which does not inherit the parent shell environment
        from dotenv import load_dotenv
        load_dotenv("/opt/detector-sift/.env", override=False)
        load_dotenv(str(Path(__file__).parent.parent / ".env"), override=False)
    except ImportError:
        pass

    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set — using deterministic report")
            return None
        return anthropic.Anthropic(api_key=api_key)
    except ImportError:
        logger.warning("anthropic package not installed — using deterministic report")
        return None