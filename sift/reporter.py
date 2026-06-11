"""
MABE Detector — SIFT Forensic Report Renderer
===============================================
Version: 1.0.0

Converts DetectionResult into structured Markdown forensic reports.
One report file is written per alerted session. A summary index is
written for the full run.

OUTPUT STRUCTURE
----------------
reports/
    run_summary.md                      ← full-run index, score distribution,
                                          calibration data for all sessions
    session_{uuid}/
        report.md                       ← per-session forensic report
                                          (only for alerted sessions)

REPORT STRUCTURE (per session)
-------------------------------
Each report has three levels, mirroring CorrelationOutput:

    # ALERT — {account}             ← header with confidence badge
    ## Triage Card                  ← Level 1: rapid 5-line triage
    ## Evidence Summary             ← Level 2: per-mechanism breakdown
       ### Velocity                 ←   (only for fired mechanisms)
       ### Enumeration
       ### Privilege Escalation
    ## Session Reference            ← Level 3: file path to raw bundle
    ---
    *Metadata footer*               ← run timestamp, versions, threshold

LLM NARRATIVE ENHANCEMENT
--------------------------
Controlled by the `llm_narrative` parameter on ForensicReporter.

When DISABLED (default, llm_narrative=False):
    - plain_english field from CorrelationAgent is used verbatim
    - Evidence descriptions use the significance field from EvidenceRef
    - All content is deterministic and traceable to specific events

When ENABLED (llm_narrative=True):
    - The triage card's plain_english paragraph is rewritten by Claude
      for analyst-facing clarity
    - Each evidence summary headline and signal interpretation gets
      an LLM-written explanatory sentence
    - CRITICAL: LLM output is clearly labeled as AI-generated narrative
    - CRITICAL: Every claim is anchored to a specific event_id or signal
      name — the LLM is instructed not to assert facts not present in
      the structured data it receives
    - Claims are labeled: [OBSERVED] for direct log evidence,
      [INFERRED] for pattern-based conclusions
    - The LLM call is made once per alerted session, not per mechanism

HALLUCINATION REDUCTION DESIGN
--------------------------------
The LLM prompt is structured to minimize fabrication:
    1. The LLM receives only the structured CorrelationOutput fields —
       no free-form text it could pattern-match against
    2. The system prompt explicitly prohibits asserting facts not
       present in the structured input
    3. Every sentence must be tagged [OBSERVED] or [INFERRED]
    4. The LLM output replaces only the narrative prose fields —
       all numeric values (confidence, ratios, timestamps) are rendered
       from the structured data, never from LLM output
    5. If the LLM call fails, the reporter falls back to deterministic
       output silently — a failed LLM call never blocks report generation

CLAIM TRACEABILITY
------------------
Every finding in the report must be traceable to a specific source.
The reporter enforces this by:
    - Rendering signal values directly from Signal.observed/baseline/ratio
    - Rendering event references directly from EvidenceRef.event_id +
      EvidenceRef.timestamp + EvidenceRef.significance
    - Never interpolating values from LLM output into numeric fields
    - Including a "Traceability" section in each evidence block that
      lists the event_ids supporting the finding
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.schema import (
    CorrelationOutput,
    EvidenceSummary,
    Signal,
    EvidenceRef,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)
from sift.runner import DetectionResult, SessionResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

REPORTER_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Mechanism display names
# ---------------------------------------------------------------------------

MECHANISM_DISPLAY_NAMES = {
    MECHANISM_VELOCITY:    "Velocity",
    MECHANISM_ENUMERATION: "Enumeration",
    MECHANISM_PRIV_ESC:    "Privilege Escalation",
}

# Confidence thresholds for badge text in report headers
_BADGE_HIGH   = 0.55
_BADGE_MEDIUM = 0.50
_BADGE_LOW    = 0.35   # == alert threshold


# ---------------------------------------------------------------------------
# ForensicReporter
# ---------------------------------------------------------------------------

class ForensicReporter:
    """
    Renders DetectionResult into Markdown forensic reports.

    Parameters
    ----------
    output_dir : Path | str
        Root directory for report output. Created if it does not exist.
        Default: ./reports/
    llm_narrative : bool
        Enable LLM-enhanced narrative generation. Default: False.
        Set to True only after core detection is validated — the
        deterministic output is the ground truth; LLM narrative is
        cosmetic enhancement.
    anthropic_client : object | None
        Pre-instantiated Anthropic client. If None and llm_narrative=True,
        the reporter instantiates one using the ANTHROPIC_API_KEY
        environment variable. Ignored when llm_narrative=False.
    """

    def __init__(
        self,
        output_dir: Path | str = Path("reports"),
        llm_narrative: bool = False,
        anthropic_client: object | None = None,
    ) -> None:
        self._output_dir = Path(output_dir)
        self._llm_narrative = llm_narrative
        self._client = None

        if llm_narrative:
            self._client = anthropic_client or _init_anthropic_client()
            if self._client is None:
                logger.warning(
                    "llm_narrative=True but Anthropic client could not be "
                    "initialised — falling back to deterministic output. "
                    "Set ANTHROPIC_API_KEY environment variable to enable."
                )
                self._llm_narrative = False

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def render(self, result: DetectionResult) -> list[Path]:
        """
        Render all reports for a DetectionResult and return written paths.

        Writes:
            - reports/run_summary.md  (always)
            - reports/session_{uuid}/report.md  (per alerted session)

        Parameters
        ----------
        result : DetectionResult

        Returns
        -------
        list[Path]
            All paths written, summary first.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []

        # ── Run summary (always written) ───────────────────────────────
        summary_path = self._output_dir / "run_summary.md"
        summary_path.write_text(
            self._render_summary(result), encoding="utf-8"
        )
        written.append(summary_path)
        logger.info("Wrote run summary: %s", summary_path)

        # ── Per-session reports (alerted sessions only) ────────────────
        for session_result in result.alerted_results:
            report_path = self._render_session_report(session_result)
            if report_path:
                written.append(report_path)

        logger.info(
            "Reporter complete: %d report(s) written (%d alerted sessions)",
            len(written), result.sessions_alerted,
        )
        return written

    def render_single(self, session_result: SessionResult) -> str:
        """
        Render a single session report as a string (no disk write).

        Useful for testing and interactive inspection.

        Parameters
        ----------
        session_result : SessionResult

        Returns
        -------
        str
            Full Markdown report content.
        """
        return self._build_session_report(session_result)

    # ------------------------------------------------------------------
    # Run summary
    # ------------------------------------------------------------------

    def _render_summary(self, result: DetectionResult) -> str:
        lines: list[str] = []
        a = lines.append

        a("# MABE Detector — Run Summary")
        a("")
        a(f"**Run timestamp:** {result.run_timestamp}  ")
        a(f"**Runner version:** {result.runner_version}  ")
        a(f"**Reporter version:** {REPORTER_VERSION}  ")
        a(f"**Alert threshold:** {result.alert_threshold}  ")
        a(f"**Duration:** {result.run_duration_s:.1f}s  ")
        a("")

        # ── Counts ────────────────────────────────────────────────────
        a("## Detection Summary")
        a("")
        a(f"| Metric | Value |")
        a(f"|--------|-------|")
        a(f"| Sessions evaluated | {result.sessions_evaluated} |")
        a(f"| Sessions alerted | **{result.sessions_alerted}** |")
        a(f"| Sessions skipped (errors) | {len(result.skipped_sessions)} |")
        a(f"| Alert threshold | {result.alert_threshold} |")
        a(f"| LLM narrative | {'enabled' if self._llm_narrative else 'disabled'} |")
        a("")

        # ── Score distribution ─────────────────────────────────────────
        dist = result.score_distribution
        if dist:
            a("## Score Distribution")
            a("")
            a("*Use this table to calibrate thresholds before adjusting "
              "any values in `thresholds.yaml`.*")
            a("")
            a("| Percentile | Confidence |")
            a("|-----------|-----------|")
            a(f"| Min       | {dist['min']:.4f} |")
            a(f"| p25       | {dist['p25']:.4f} |")
            a(f"| Median    | {dist['median']:.4f} |")
            a(f"| p75       | {dist['p75']:.4f} |")
            a(f"| p90       | {dist['p90']:.4f} |")
            a(f"| p95       | {dist['p95']:.4f} |")
            a(f"| Max       | {dist['max']:.4f} |")
            a("")

        # ── Alert index ────────────────────────────────────────────────
        if result.alerted_results:
            a("## Alerted Sessions")
            a("")
            a("Sorted by overall confidence (highest first).")
            a("")
            a("| Session | Account | Confidence | Mechanisms Fired | "
              "Highest Layer | Report |")
            a("|---------|---------|-----------|-----------------|"
              "--------------|--------|")

            for r in result.alerted_results:
                c = r.correlation
                mech_str = ", ".join(
                    MECHANISM_DISPLAY_NAMES.get(m, m)
                    for m in c.mechanisms_fired
                ) or "—"
                layer_str = ", ".join(
                    f"{MECHANISM_DISPLAY_NAMES.get(m, m)}:L{l}"
                    for m, l in c.highest_layer_per_mechanism.items()
                    if l > 0
                ) or "—"
                report_path = (
                    f"session_{c.session_id}/report.md"
                )
                a(
                    f"| `{c.session_id[:8]}…` "
                    f"| {c.triage_card.account} "
                    f"| **{c.overall_confidence:.4f}** "
                    f"| {mech_str} "
                    f"| {layer_str} "
                    f"| [report]({report_path}) |"
                )
            a("")
        else:
            a("## Alerted Sessions")
            a("")
            a("*No sessions exceeded the alert threshold.*")
            a("")

        # ── Skipped sessions ───────────────────────────────────────────
        if result.skipped_sessions:
            a("## Skipped Sessions (Errors)")
            a("")
            a("*These sessions failed to evaluate. Investigate the logs.*")
            a("")
            for sid in result.skipped_sessions:
                a(f"- `{sid}`")
            a("")

        # ── Dataset stats ──────────────────────────────────────────────
        vel = result.dataset_stats.get("velocity", {})
        en  = result.dataset_stats.get("enumeration", {})
        if vel or en:
            a("## Dataset Statistics")
            a("")
            a("*These are the baseline distributions used for dynamic "
              "threshold derivation. They are dataset-specific.*")
            a("")
            a("| Statistic | Value |")
            a("|-----------|-------|")
            if vel:
                a(f"| Velocity mean rate (eps) | "
                  f"{vel.get('mean_aggregate_rate', 0):.4f} |")
                a(f"| Velocity std rate (eps) | "
                  f"{vel.get('std_aggregate_rate', 0):.4f} |")
            if en:
                a(f"| Enumeration mean destinations | "
                  f"{en.get('mean_destination_count', 0):.2f} |")
                a(f"| Enumeration std destinations | "
                  f"{en.get('std_destination_count', 0):.2f} |")
            a("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Per-session report
    # ------------------------------------------------------------------

    def _render_session_report(
        self,
        session_result: SessionResult,
    ) -> Optional[Path]:
        """Write one session report to disk. Returns path on success."""
        c = session_result.correlation
        report_dir = self._output_dir / f"session_{c.session_id}"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.md"

        try:
            content = self._build_session_report(session_result)
            report_path.write_text(content, encoding="utf-8")
            logger.info(
                "Wrote session report: %s (confidence=%.4f)",
                report_path, c.overall_confidence,
            )
            return report_path
        except Exception as exc:
            logger.error(
                "Failed to write report for session %s: %s",
                c.session_id, exc, exc_info=True,
            )
            return None

    def _build_session_report(
        self,
        session_result: SessionResult,
    ) -> str:
        """Build the full Markdown content for one session report."""
        c = session_result.correlation

        # Optionally fetch LLM narrative — done once per session
        llm_content: Optional[dict] = None
        if self._llm_narrative and c.alert_triggered:
            llm_content = self._fetch_llm_narrative(session_result)

        lines: list[str] = []
        a = lines.append

        # ── Header ────────────────────────────────────────────────────
        badge = _confidence_badge(c.overall_confidence)
        a(f"# {badge} — {c.triage_card.account}")
        a("")
        a(f"**Session:** `{c.session_id}`  ")
        a(f"**Overall confidence:** `{c.overall_confidence:.4f}`  ")
        a(f"**Alert threshold:** `{c.alert_threshold}`  ")
        a(f"**Alert triggered:** {'✓ YES' if c.alert_triggered else '✗ NO'}  ")
        if c.high_confidence_floor_applied:
            a("**⚠ High-confidence floor applied** (single mechanism "
              "exceeded 0.90 trigger)  ")
        a("")

        # ── Level 1: Triage Card ───────────────────────────────────────
        a("---")
        a("")
        a("## Level 1 — Triage Card")
        a("")
        a(_render_triage_card(c.triage_card, llm_content))
        a("")

        # ── Level 2: Evidence Summary ──────────────────────────────────
        if c.evidence_summary:
            a("---")
            a("")
            a("## Level 2 — Evidence Summary")
            a("")
            for summary in c.evidence_summary:
                a(_render_evidence_summary(
                    summary,
                    c.highest_layer_per_mechanism.get(summary.mechanism_id, 0),
                    llm_content,
                ))
                a("")

        # ── Mechanism scores table ─────────────────────────────────────
        a("---")
        a("")
        a("## Mechanism Scores")
        a("")
        a("| Mechanism | Confidence | Highest Layer | Status |")
        a("|-----------|-----------|--------------|--------|")
        for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
            score   = c.triage_card.mechanism_scores.get(mid, 0.0)
            layer   = c.highest_layer_per_mechanism.get(mid, 0)
            name    = MECHANISM_DISPLAY_NAMES.get(mid, mid)
            if mid in c.mechanisms_absent:
                status = "absent (no output)"
            elif mid in c.mechanisms_fired:
                status = f"fired (L{layer})"
            else:
                status = "evaluated, no signal"
            weight  = c.weights_used.get(mid, 0.0)
            a(
                f"| {name} (w={weight}) "
                f"| `{score:.4f}` "
                f"| {'L' + str(layer) if layer > 0 else '—'} "
                f"| {status} |"
            )
        a("")

        # ── Level 3: Session Reference ─────────────────────────────────
        a("---")
        a("")
        a("## Level 3 — Session Reference")
        a("")
        a("Raw event data for deep investigation:")
        a("")
        a(f"```")
        a(c.session_ref)
        a(f"```")
        a("")
        a("Files in this bundle:")
        a("")
        a("- `security_events.json` — Windows Security Events (label-free)")
        a("- `sysmon_events.json`   — Sysmon records (label-free)")
        a("- `session_manifest.json` — Ground truth labels *(do not use "
          "for detection)*")
        a("")

        # ── LLM attribution footer ─────────────────────────────────────
        if llm_content:
            a("---")
            a("")
            a("*Narrative sections marked* `[OBSERVED]` *indicate claims "
              "directly traceable to a specific event in the session logs. "
              "Sections marked* `[INFERRED]` *indicate conclusions drawn "
              "from behavioral patterns across multiple events. "
              "All numeric values are rendered from structured detection "
              "output, not from AI-generated content.*")
            a("")

        # ── Metadata footer ────────────────────────────────────────────
        a("---")
        a("")
        a(f"*Generated by MABE Detector SIFT v{REPORTER_VERSION} · "
          f"Evaluated at {c.triage_card.time_window.start} — "
          f"{c.triage_card.time_window.end} · "
          f"LLM narrative: {'enabled' if self._llm_narrative else 'disabled'}*")
        a("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM narrative
    # ------------------------------------------------------------------

    def _fetch_llm_narrative(
        self,
        session_result: SessionResult,
    ) -> Optional[dict]:
        """
        Call the Anthropic API to generate enhanced narrative.

        Returns a dict with keys:
            "triage_paragraph"   str  — enhanced plain_english paragraph
            "evidence_headlines" dict — mechanism_id → enhanced headline
            "evidence_notes"     dict — mechanism_id → list of signal notes

        Returns None on any failure — caller falls back to deterministic.
        """
        if self._client is None:
            return None

        c = session_result.correlation

        # Build structured payload — the LLM receives only structured
        # data, never raw event records that could be reproduced
        payload = _build_llm_payload(session_result)

        prompt = _build_llm_prompt(payload)

        try:
            response = self._client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                system=_LLM_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text
            return _parse_llm_response(raw, c.session_id)
        except Exception as exc:
            logger.warning(
                "LLM narrative call failed for session %s: %s — "
                "using deterministic output",
                c.session_id, exc,
            )
            return None


# ---------------------------------------------------------------------------
# Rendering helpers — deterministic
# ---------------------------------------------------------------------------

def _render_triage_card(triage, llm_content: Optional[dict]) -> str:
    """Render the Level 1 triage card section."""
    lines: list[str] = []
    a = lines.append

    # Use LLM paragraph if available, otherwise deterministic plain_english
    if llm_content and llm_content.get("triage_paragraph"):
        a(llm_content["triage_paragraph"])
        a("")
        a("*[AI-generated narrative — all numeric values from structured "
          "detection output]*")
    else:
        a(triage.plain_english)

    a("")
    a(f"**Time window:** {triage.time_window.start} → {triage.time_window.end}  ")
    a(f"**Account:** `{triage.account}`  ")
    a(f"**Overall confidence:** `{triage.overall_confidence:.4f}`  ")
    a("")

    # Mechanism score summary
    a("| Mechanism | Score |")
    a("|-----------|-------|")
    for mid in (MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC):
        score = triage.mechanism_scores.get(mid, 0.0)
        name  = MECHANISM_DISPLAY_NAMES.get(mid, mid)
        bar   = _score_bar(score)
        a(f"| {name} | `{score:.4f}` {bar} |")

    return "\n".join(lines)


def _render_evidence_summary(
    summary: EvidenceSummary,
    highest_layer: int,
    llm_content: Optional[dict],
) -> str:
    """Render one mechanism's Level 2 evidence summary section."""
    lines: list[str] = []
    a = lines.append

    name = MECHANISM_DISPLAY_NAMES.get(summary.mechanism_id, summary.mechanism_id)
    a(f"### {name} (Layer {highest_layer})")
    a("")

    # Headline — LLM or deterministic
    if llm_content:
        enh = llm_content.get("evidence_headlines", {})
        headline = enh.get(summary.mechanism_id) or summary.headline
    else:
        headline = summary.headline
    a(f"**{headline}**")
    a("")

    # Signals table — always deterministic, never from LLM
    if summary.top_signals:
        a("#### Signals")
        a("")
        a("| Signal | Observed | Baseline | Ratio | Contribution |")
        a("|--------|---------|---------|-------|-------------|")
        for sig in summary.top_signals:
            a(_render_signal_row(sig))

        # LLM signal notes (explanatory sentences) if available
        if llm_content:
            notes = llm_content.get("evidence_notes", {}).get(
                summary.mechanism_id, []
            )
            if notes:
                a("")
                a("*Signal interpretation:*")
                a("")
                for note in notes:
                    a(f"- {note}")
        a("")

    # Evidence events — always deterministic
    if summary.top_events:
        a("#### Supporting Events")
        a("")
        for ev in summary.top_events:
            a(_render_evidence_ref(ev))
        a("")

    # Traceability block — explicit audit trail
    if summary.top_events:
        a("#### Traceability")
        a("")
        a("The following event IDs support the findings above:")
        a("")
        for ev in summary.top_events:
            a(f"- `{ev.event_id}` ({ev.event_type}, {ev.timestamp})")
        a("")

    return "\n".join(lines)


def _render_signal_row(sig: Signal) -> str:
    """Render one Signal as a Markdown table row."""
    # Direction hint: for velocity, low ratio is anomalous;
    # for others, high ratio is anomalous. We show the raw ratio
    # and let the analyst interpret direction from context.
    return (
        f"| `{sig.name}` "
        f"| `{sig.observed}` "
        f"| `{sig.baseline}` "
        f"| `{sig.ratio:.4f}x` "
        f"| `{sig.contribution:.2f}` |"
    )


def _render_evidence_ref(ev: EvidenceRef) -> str:
    """Render one EvidenceRef as a Markdown list item."""
    lines = [
        f"- **`{ev.event_id}`** — {ev.event_type} @ {ev.timestamp}  ",
        f"  *{ev.significance}*",
    ]
    # If inline event data is present, render key fields
    if ev.inline:
        dst = ev.inline.get("dst_host", "")
        user = ev.inline.get("user", "")
        success = ev.inline.get("success")
        detail_parts = []
        if user:
            detail_parts.append(f"user=`{user}`")
        if dst:
            detail_parts.append(f"dst=`{dst}`")
        if success is not None:
            detail_parts.append(f"success=`{success}`")
        if detail_parts:
            lines.append(f"  {', '.join(detail_parts)}")
    return "\n".join(lines)


def _confidence_badge(confidence: float) -> str:
    """Return a text badge for the report header."""
    if confidence >= _BADGE_HIGH:
        return "🔴 HIGH CONFIDENCE ALERT"
    if confidence >= _BADGE_MEDIUM:
        return "🟠 MEDIUM CONFIDENCE ALERT"
    return "🟡 LOW CONFIDENCE ALERT"


def _score_bar(score: float, width: int = 10) -> str:
    """Render a simple ASCII confidence bar."""
    filled = round(score * width)
    return "█" * filled + "░" * (width - filled)


# ---------------------------------------------------------------------------
# LLM prompt construction
# ---------------------------------------------------------------------------

_LLM_SYSTEM_PROMPT = """You are a forensic analyst assistant helping write
clear, evidence-grounded reports about potential AI-driven cyberattacks.

You receive structured detection data (confidence scores, signal values,
event references) and must produce plain-English narrative for a report.

RULES YOU MUST FOLLOW:
1. Every factual claim must be tagged [OBSERVED] (directly in logs) or
   [INFERRED] (concluded from a behavioral pattern).
2. Never assert facts that are not present in the structured data
   you receive. Do not fabricate event details, timestamps, or hostnames
   beyond what is provided.
3. Write for a senior security analyst — precise, direct, no filler.
4. Do not reproduce raw event records verbatim.
5. Do not speculate about attacker intent beyond what the signals show.
6. Respond ONLY with a valid JSON object — no preamble, no markdown fences.

The JSON must have exactly these keys:
{
  "triage_paragraph": "string — 2-3 sentence analyst-facing summary",
  "evidence_headlines": {
    "velocity": "string or null",
    "enumeration": "string or null",
    "priv_escalation": "string or null"
  },
  "evidence_notes": {
    "velocity": ["string", ...],
    "enumeration": ["string", ...],
    "priv_escalation": ["string", ...]
  }
}

For mechanisms that did not fire, set the value to null or [].
Each evidence_note should be one sentence explaining what one signal means
for an analyst who may not know the technical definition.
"""


def _build_llm_payload(session_result: SessionResult) -> dict:
    """
    Build the structured payload sent to the LLM.

    Contains only the fields the LLM needs for narrative generation.
    Raw event records are summarized, not passed in full, to avoid
    context overflow and to prevent the LLM from reproducing them.
    """
    c = session_result.correlation

    payload = {
        "session_id":         c.session_id,
        "account":            c.triage_card.account,
        "time_window":        {
            "start": c.triage_card.time_window.start,
            "end":   c.triage_card.time_window.end,
        },
        "overall_confidence": c.overall_confidence,
        "mechanisms_fired":   c.mechanisms_fired,
        "plain_english_base": c.triage_card.plain_english,
        "mechanism_details":  {},
    }

    for summary in c.evidence_summary:
        mid = summary.mechanism_id
        payload["mechanism_details"][mid] = {
            "headline":   summary.headline,
            "top_signals": [
                {
                    "name":        s.name,
                    "observed":    s.observed,
                    "baseline":    s.baseline,
                    "ratio":       s.ratio,
                    "contribution": s.contribution,
                }
                for s in summary.top_signals
            ],
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

    return payload


def _build_llm_prompt(payload: dict) -> str:
    """Build the user-facing LLM prompt from the structured payload."""
    return (
        "Generate analyst narrative for the following detection result.\n\n"
        "Structured data:\n"
        f"```json\n{json.dumps(payload, indent=2)}\n```\n\n"
        "Remember: tag every factual claim [OBSERVED] or [INFERRED]. "
        "Respond only with the JSON object described in the system prompt."
    )


def _parse_llm_response(raw: str, session_id: str) -> Optional[dict]:
    """
    Parse and validate the LLM response JSON.

    Returns None if the response is malformed — caller falls back to
    deterministic output.
    """
    # Strip any accidental markdown fences
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(
            l for l in lines
            if not l.startswith("```")
        ).strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning(
            "LLM response for session %s failed JSON parse: %s",
            session_id, exc,
        )
        return None

    # Validate required keys
    required = {"triage_paragraph", "evidence_headlines", "evidence_notes"}
    if not required.issubset(data.keys()):
        logger.warning(
            "LLM response for session %s missing keys: %s",
            session_id, required - data.keys(),
        )
        return None

    return data


# ---------------------------------------------------------------------------
# Anthropic client initialisation
# ---------------------------------------------------------------------------

def _init_anthropic_client() -> Optional[object]:
    """
    Attempt to initialise an Anthropic client from the environment.

    Returns None if the anthropic package is not installed or
    ANTHROPIC_API_KEY is not set.
    """
    try:
        import anthropic  # type: ignore
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning(
                "ANTHROPIC_API_KEY not set — LLM narrative disabled"
            )
            return None
        return anthropic.Anthropic(api_key=api_key)
    except ImportError:
        logger.warning(
            "anthropic package not installed — LLM narrative disabled. "
            "Run: pip install anthropic"
        )
        return None


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def render_reports(
    result: DetectionResult,
    output_dir: Path | str = Path("reports"),
    llm_narrative: bool = False,
) -> list[Path]:
    """
    Module-level convenience wrapper.

    Parameters
    ----------
    result : DetectionResult
    output_dir : Path | str
    llm_narrative : bool

    Returns
    -------
    list[Path]
        All written report paths.
    """
    reporter = ForensicReporter(
        output_dir=output_dir,
        llm_narrative=llm_narrative,
    )
    return reporter.render(result)
