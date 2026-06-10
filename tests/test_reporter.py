"""
Tests for sift/reporter.py
===========================

Tests cover:
    - Deterministic rendering (llm_narrative=False) — default mode
    - Report structure: required sections present in correct order
    - Numeric values always from structured data, never from LLM output
    - LLM fallback: failed LLM call produces valid deterministic output
    - LLM disabled by default: no API calls without explicit opt-in
    - Score bar and badge helpers
    - Summary report structure
    - render_single returns a string (no disk write)
    - render() writes files to correct paths

LLM narrative tests use a mock client — no real API calls are made.

Run from detector-sift/:
    python -m pytest tests/test_reporter.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
for candidate in [_HERE.parent / "sift", _HERE / "sift", _HERE]:
    if (candidate / "reporter.py").exists():
        sys.path.insert(0, str(candidate.parent))
        break

from sift.reporter import (
    ForensicReporter,
    render_reports,
    _confidence_badge,
    _score_bar,
    _render_signal_row,
    _render_evidence_ref,
    _build_llm_payload,
    _build_llm_prompt,
    _parse_llm_response,
    REPORTER_VERSION,
    MECHANISM_DISPLAY_NAMES,
)
from sift.runner import DetectionResult, SessionResult
from core.schema import (
    CorrelationOutput,
    TriageCard,
    EvidenceSummary,
    TimeWindow,
    Signal,
    EvidenceRef,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
_T1 = "2025-11-14T09:00:00.000Z"
_T2 = "2025-11-14T09:05:00.000Z"


def _make_signal(
    name: str = "aggregate_rate_eps",
    observed: float = 5.0,
    baseline: float = 0.5,
    ratio: float = 10.0,
    contribution: float = 1.0,
) -> Signal:
    return Signal(
        name=name,
        observed=observed,
        baseline=baseline,
        ratio=ratio,
        contribution=contribution,
    )


def _make_evidence_ref(
    event_id: str = "sess:ts",
    timestamp: str = _T1,
    event_type: str = "auth_attempt",
    significance: str = "fastest gap: 80ms",
    inline: dict | None = None,
) -> EvidenceRef:
    return EvidenceRef(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        significance=significance,
        inline=inline,
    )


def _make_correlation(
    overall_confidence: float = 0.72,
    alert_triggered: bool = True,
    mechanisms_fired: list | None = None,
    mechanisms_absent: list | None = None,
    evidence_summary: list | None = None,
) -> CorrelationOutput:
    mechanisms_fired = mechanisms_fired or [MECHANISM_VELOCITY, MECHANISM_ENUMERATION]
    mechanisms_absent = mechanisms_absent or [MECHANISM_PRIV_ESC]

    triage = TriageCard(
        account="j.harrison",
        time_window=TimeWindow(start=_T1, end=_T2),
        overall_confidence=overall_confidence,
        plain_english=(
            "Account j.harrison showed event rate 47x above baseline; "
            "31 distinct hosts contacted including 3 high-value node types "
            f"between {_T1} and {_T2}."
        ),
        mechanism_scores={
            MECHANISM_VELOCITY:    0.82,
            MECHANISM_ENUMERATION: 0.71,
            MECHANISM_PRIV_ESC:    0.0,
        },
    )

    summary = evidence_summary
    if summary is None and alert_triggered:
        summary = [
            EvidenceSummary(
                mechanism_id=MECHANISM_VELOCITY,
                headline="Event rate 47x above baseline (5.2 eps vs 0.11 baseline)",
                top_signals=[_make_signal()],
                top_events=[_make_evidence_ref()],
            ),
            EvidenceSummary(
                mechanism_id=MECHANISM_ENUMERATION,
                headline="31 distinct hosts contacted (7.8x baseline of 4)",
                top_signals=[_make_signal(
                    name="distinct_destination_count",
                    observed=31.0,
                    baseline=4.0,
                    ratio=7.75,
                )],
                top_events=[_make_evidence_ref(
                    event_id="sess:ts2",
                    event_type="auth_attempt",
                    significance="access to high-value node type: domain_controller (DC-01)",
                    inline={"dst_host": "DC-01", "user": "j.harrison", "success": True},
                )],
            ),
        ]

    return CorrelationOutput(
        session_id=_UUID,
        overall_confidence=overall_confidence,
        alert_triggered=alert_triggered,
        alert_threshold=0.35,
        weights_used={
            MECHANISM_VELOCITY: 0.25,
            MECHANISM_ENUMERATION: 0.35,
            MECHANISM_PRIV_ESC: 0.40,
        },
        mechanisms_fired=mechanisms_fired,
        mechanisms_absent=mechanisms_absent,
        highest_layer_per_mechanism={
            MECHANISM_VELOCITY:    2,
            MECHANISM_ENUMERATION: 3,
            MECHANISM_PRIV_ESC:    0,
        },
        high_confidence_floor_applied=False,
        triage_card=triage,
        evidence_summary=summary or [],
        session_ref=f"/cases/mabe/session_{_UUID}",
    )


def _make_session_result(
    overall_confidence: float = 0.72,
    alert_triggered: bool = True,
) -> SessionResult:
    correlation = _make_correlation(
        overall_confidence=overall_confidence,
        alert_triggered=alert_triggered,
    )
    session = MagicMock()
    session.session_id = _UUID
    session.account = "j.harrison"
    session.bundle_dir = Path(f"/cases/mabe/session_{_UUID}")

    return SessionResult(
        session=session,
        correlation=correlation,
        mechanism_outputs=[],
        evaluation_time_ms=12.5,
    )


def _make_detection_result(
    n_benign: int = 3,
    include_alert: bool = True,
) -> DetectionResult:
    results = []

    if include_alert:
        results.append(_make_session_result(overall_confidence=0.72))

    # Add some non-alerted sessions
    for i in range(n_benign):
        uuid = f"bbbb{i:04d}-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        corr = _make_correlation(
            overall_confidence=0.15,
            alert_triggered=False,
            mechanisms_fired=[],
            mechanisms_absent=[
                MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC
            ],
            evidence_summary=[],
        )
        corr.session_id = uuid
        corr.triage_card.account = f"user{i}"
        s = MagicMock()
        s.session_id = uuid
        results.append(SessionResult(
            session=s,
            correlation=corr,
            mechanism_outputs=[],
            evaluation_time_ms=5.0,
        ))

    # Sort descending
    results.sort(key=lambda r: r.correlation.overall_confidence, reverse=True)

    return DetectionResult(
        sessions_evaluated=len(results),
        sessions_alerted=1 if include_alert else 0,
        alert_threshold=0.35,
        results=results,
        dataset_stats={
            "velocity": {
                "mean_aggregate_rate": 0.11,
                "std_aggregate_rate": 0.04,
            },
            "enumeration": {
                "mean_destination_count": 4.2,
                "std_destination_count": 1.8,
            },
        },
        run_duration_s=3.14,
        run_timestamp="2025-11-14T10:00:00.000Z",
    )


# ---------------------------------------------------------------------------
# Test: helper functions
# ---------------------------------------------------------------------------

class TestHelpers(unittest.TestCase):

    def test_confidence_badge_high(self):
        badge = _confidence_badge(0.80)
        self.assertIn("HIGH", badge)

    def test_confidence_badge_medium(self):
        badge = _confidence_badge(0.55)
        self.assertIn("MEDIUM", badge)

    def test_confidence_badge_low(self):
        badge = _confidence_badge(0.38)
        self.assertIn("LOW", badge)

    def test_score_bar_full(self):
        bar = _score_bar(1.0, width=10)
        self.assertEqual(bar.count("█"), 10)
        self.assertEqual(bar.count("░"), 0)

    def test_score_bar_empty(self):
        bar = _score_bar(0.0, width=10)
        self.assertEqual(bar.count("█"), 0)
        self.assertEqual(bar.count("░"), 10)

    def test_score_bar_half(self):
        bar = _score_bar(0.5, width=10)
        self.assertEqual(bar.count("█"), 5)

    def test_render_signal_row_contains_name(self):
        sig = _make_signal(name="test_signal")
        row = _render_signal_row(sig)
        self.assertIn("test_signal", row)

    def test_render_signal_row_contains_values(self):
        sig = _make_signal(observed=5.0, baseline=0.5, ratio=10.0)
        row = _render_signal_row(sig)
        self.assertIn("5.0", row)
        self.assertIn("0.5", row)

    def test_render_evidence_ref_contains_event_id(self):
        ev = _make_evidence_ref(event_id="test:ev:001")
        rendered = _render_evidence_ref(ev)
        self.assertIn("test:ev:001", rendered)

    def test_render_evidence_ref_contains_significance(self):
        ev = _make_evidence_ref(significance="fastest gap: 80ms")
        rendered = _render_evidence_ref(ev)
        self.assertIn("fastest gap: 80ms", rendered)

    def test_render_evidence_ref_inline_dst_host(self):
        ev = _make_evidence_ref(
            inline={"dst_host": "DC-01", "user": "alice", "success": True}
        )
        rendered = _render_evidence_ref(ev)
        self.assertIn("DC-01", rendered)
        self.assertIn("alice", rendered)

    def test_render_evidence_ref_no_inline(self):
        ev = _make_evidence_ref(inline=None)
        rendered = _render_evidence_ref(ev)
        # Should not crash and should still contain event_id
        self.assertIn("sess:ts", rendered)


# ---------------------------------------------------------------------------
# Test: report structure — deterministic mode
# ---------------------------------------------------------------------------

class TestReportStructure(unittest.TestCase):

    def setUp(self):
        self.reporter = ForensicReporter(llm_narrative=False)
        self.session_result = _make_session_result()

    def test_render_single_returns_string(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIsInstance(report, str)
        self.assertTrue(len(report) > 0)

    def test_header_contains_account(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("j.harrison", report)

    def test_header_contains_session_id(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn(_UUID, report)

    def test_triage_card_section_present(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Triage Card", report)

    def test_evidence_summary_section_present_when_alerted(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Evidence Summary", report)

    def test_mechanism_scores_table_present(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Mechanism Scores", report)

    def test_session_reference_section_present(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Session Reference", report)
        self.assertIn(f"/cases/mabe/session_{_UUID}", report)

    def test_confidence_value_present(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("0.7200", report)

    def test_velocity_mechanism_section_present(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Velocity", report)

    def test_enumeration_mechanism_section_present(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Enumeration", report)

    def test_traceability_section_present(self):
        """Each evidence section should include a Traceability block."""
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Traceability", report)

    def test_event_ids_in_traceability(self):
        report = self.reporter.render_single(self.session_result)
        # event_id from our fixture is "sess:ts"
        self.assertIn("sess:ts", report)

    def test_no_llm_notice_when_disabled(self):
        """No LLM attribution footer when llm_narrative=False."""
        report = self.reporter.render_single(self.session_result)
        self.assertNotIn("AI-generated narrative", report)

    def test_metadata_footer_present(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("MABE Detector SIFT", report)
        self.assertIn(REPORTER_VERSION, report)

    def test_no_alert_session_renders_without_evidence_summary(self):
        """Non-alerted sessions produce a report without evidence summary."""
        no_alert = _make_session_result(
            overall_confidence=0.15, alert_triggered=False
        )
        # Manually clear evidence_summary since CorrelationAgent only
        # populates it when alert_triggered is True
        no_alert.correlation.evidence_summary = []
        report = self.reporter.render_single(no_alert)
        self.assertNotIn("Evidence Summary", report)

    def test_high_confidence_floor_warning_when_applied(self):
        result = _make_session_result()
        result.correlation.high_confidence_floor_applied = True
        report = self.reporter.render_single(result)
        self.assertIn("floor applied", report)

    def test_signal_values_are_numeric_not_fabricated(self):
        """
        Signal values in the report must come from Signal.observed/baseline,
        not from any narrative source.
        """
        report = self.reporter.render_single(self.session_result)
        # Our fixture signal has observed=5.0, baseline=0.5
        self.assertIn("5.0", report)
        self.assertIn("0.5", report)

    def test_all_three_mechanisms_in_scores_table(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("Velocity", report)
        self.assertIn("Enumeration", report)
        self.assertIn("Privilege Escalation", report)

    def test_absent_mechanism_labeled_in_scores_table(self):
        report = self.reporter.render_single(self.session_result)
        self.assertIn("absent", report)


# ---------------------------------------------------------------------------
# Test: run summary
# ---------------------------------------------------------------------------

class TestRunSummary(unittest.TestCase):

    def setUp(self):
        self.reporter = ForensicReporter(llm_narrative=False)

    def test_summary_contains_session_count(self):
        dr = _make_detection_result(n_benign=3, include_alert=True)
        summary = self.reporter._render_summary(dr)
        self.assertIn("4", summary)  # 1 alert + 3 benign

    def test_summary_contains_alert_count(self):
        dr = _make_detection_result(include_alert=True)
        summary = self.reporter._render_summary(dr)
        self.assertIn("1", summary)

    def test_summary_contains_score_distribution(self):
        dr = _make_detection_result()
        summary = self.reporter._render_summary(dr)
        self.assertIn("Score Distribution", summary)

    def test_summary_contains_alerted_sessions_table(self):
        dr = _make_detection_result(include_alert=True)
        summary = self.reporter._render_summary(dr)
        self.assertIn("Alerted Sessions", summary)

    def test_summary_no_alert_message_when_none(self):
        dr = _make_detection_result(include_alert=False)
        summary = self.reporter._render_summary(dr)
        self.assertIn("No sessions exceeded", summary)

    def test_summary_contains_dataset_stats(self):
        dr = _make_detection_result()
        summary = self.reporter._render_summary(dr)
        self.assertIn("Dataset Statistics", summary)
        self.assertIn("0.11", summary)  # mean_aggregate_rate

    def test_summary_contains_threshold(self):
        dr = _make_detection_result()
        summary = self.reporter._render_summary(dr)
        self.assertIn("0.35", summary)


# ---------------------------------------------------------------------------
# Test: render() writes files to disk
# ---------------------------------------------------------------------------

class TestRenderToDisk(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.tmp.name) / "reports"

    def tearDown(self):
        self.tmp.cleanup()

    def test_render_creates_output_dir(self):
        reporter = ForensicReporter(
            output_dir=self.output_dir, llm_narrative=False
        )
        dr = _make_detection_result(include_alert=False)
        reporter.render(dr)
        self.assertTrue(self.output_dir.exists())

    def test_render_writes_run_summary(self):
        reporter = ForensicReporter(
            output_dir=self.output_dir, llm_narrative=False
        )
        dr = _make_detection_result()
        paths = reporter.render(dr)
        summary_path = self.output_dir / "run_summary.md"
        self.assertTrue(summary_path.exists())
        self.assertIn(summary_path, paths)

    def test_render_writes_session_report_for_alerted(self):
        reporter = ForensicReporter(
            output_dir=self.output_dir, llm_narrative=False
        )
        dr = _make_detection_result(include_alert=True)
        paths = reporter.render(dr)
        session_report = (
            self.output_dir / f"session_{_UUID}" / "report.md"
        )
        self.assertTrue(session_report.exists())
        self.assertIn(session_report, paths)

    def test_render_no_session_reports_when_no_alerts(self):
        reporter = ForensicReporter(
            output_dir=self.output_dir, llm_narrative=False
        )
        dr = _make_detection_result(include_alert=False)
        paths = reporter.render(dr)
        # Only run_summary.md should exist
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].name, "run_summary.md")

    def test_written_report_is_valid_utf8(self):
        reporter = ForensicReporter(
            output_dir=self.output_dir, llm_narrative=False
        )
        dr = _make_detection_result(include_alert=True)
        reporter.render(dr)
        session_report = (
            self.output_dir / f"session_{_UUID}" / "report.md"
        )
        # Should read without encoding errors
        content = session_report.read_text(encoding="utf-8")
        self.assertTrue(len(content) > 0)

    def test_convenience_function_matches_reporter(self):
        dr = _make_detection_result(include_alert=True)
        paths = render_reports(dr, output_dir=self.output_dir)
        self.assertIsInstance(paths, list)
        self.assertTrue(len(paths) >= 1)


# ---------------------------------------------------------------------------
# Test: LLM narrative — disabled by default
# ---------------------------------------------------------------------------

class TestLlmNarrativeDisabledByDefault(unittest.TestCase):

    def test_no_api_call_without_llm_enabled(self):
        """
        ForensicReporter with llm_narrative=False must never call
        the Anthropic API, even if a client is somehow set.
        """
        reporter = ForensicReporter(llm_narrative=False)
        # _client should be None when llm_narrative=False
        self.assertIsNone(reporter._client)

    def test_llm_flag_false_by_default(self):
        reporter = ForensicReporter()
        self.assertFalse(reporter._llm_narrative)


# ---------------------------------------------------------------------------
# Test: LLM narrative — enabled with mock client
# ---------------------------------------------------------------------------

class TestLlmNarrativeEnabled(unittest.TestCase):

    def _make_mock_client(self, response_json: dict) -> MagicMock:
        """Return a mock Anthropic client that returns a canned response."""
        content_block = MagicMock()
        content_block.text = json.dumps(response_json)

        message = MagicMock()
        message.content = [content_block]

        client = MagicMock()
        client.messages.create.return_value = message
        return client

    def _valid_llm_response(self) -> dict:
        return {
            "triage_paragraph": (
                "[OBSERVED] Account j.harrison accessed 31 distinct hosts "
                "at machine speed (5.2 events/sec). "
                "[INFERRED] Behavioral pattern is consistent with "
                "autonomous enumeration."
            ),
            "evidence_headlines": {
                "velocity":    "Machine-speed timing: 47x above baseline",
                "enumeration": "31 hosts in 5 minutes including DC and DB nodes",
                "priv_escalation": None,
            },
            "evidence_notes": {
                "velocity": [
                    "[OBSERVED] The session produced 5.2 events per second "
                    "against a baseline of 0.11 eps — a 47x ratio consistent "
                    "with autonomous execution rather than human operation."
                ],
                "enumeration": [
                    "[OBSERVED] 31 distinct destination hosts were contacted, "
                    "7.75x the baseline of 4."
                ],
                "priv_escalation": [],
            },
        }

    def test_llm_narrative_replaces_plain_english(self):
        """When LLM call succeeds, triage paragraph should be from LLM."""
        mock_client = self._make_mock_client(self._valid_llm_response())
        reporter = ForensicReporter(
            llm_narrative=True,
            anthropic_client=mock_client,
        )
        result = _make_session_result()
        report = reporter.render_single(result)
        self.assertIn("machine speed", report.lower())

    def test_llm_narrative_attribution_footer_present(self):
        mock_client = self._make_mock_client(self._valid_llm_response())
        reporter = ForensicReporter(
            llm_narrative=True,
            anthropic_client=mock_client,
        )
        result = _make_session_result()
        report = reporter.render_single(result)
        self.assertIn("AI-generated narrative", report)

    def test_llm_narrative_observed_inferred_tags_preserved(self):
        mock_client = self._make_mock_client(self._valid_llm_response())
        reporter = ForensicReporter(
            llm_narrative=True,
            anthropic_client=mock_client,
        )
        result = _make_session_result()
        report = reporter.render_single(result)
        self.assertIn("[OBSERVED]", report)
        self.assertIn("[INFERRED]", report)

    def test_llm_failure_falls_back_to_deterministic(self):
        """API error must not crash the reporter — falls back silently."""
        client = MagicMock()
        client.messages.create.side_effect = Exception("API error")
        reporter = ForensicReporter(
            llm_narrative=True,
            anthropic_client=client,
        )
        result = _make_session_result()
        # Must not raise
        report = reporter.render_single(result)
        self.assertIsInstance(report, str)
        self.assertIn("j.harrison", report)
        # Should not have LLM footer since LLM call failed
        self.assertNotIn("AI-generated narrative", report)

    def test_numeric_values_not_from_llm(self):
        """
        Even with LLM narrative enabled, numeric signal values must
        come from Signal objects, not from the LLM response.
        """
        # LLM response claims a different ratio — should not appear
        bad_response = self._valid_llm_response()
        bad_response["evidence_notes"]["velocity"] = [
            "The ratio was 999x."  # fabricated — should not appear as numeric
        ]
        mock_client = self._make_mock_client(bad_response)
        reporter = ForensicReporter(
            llm_narrative=True,
            anthropic_client=mock_client,
        )
        result = _make_session_result()
        report = reporter.render_single(result)
        # The signal table should show 10.0 (from our fixture), not 999
        # (The LLM note "999x" may appear as text in a bullet, but the
        # table row should still show 10.0)
        self.assertIn("10.0000x", report)  # from Signal.ratio in table


# ---------------------------------------------------------------------------
# Test: LLM payload and prompt construction
# ---------------------------------------------------------------------------

class TestLlmPayload(unittest.TestCase):

    def test_payload_contains_session_id(self):
        result = _make_session_result()
        payload = _build_llm_payload(result)
        self.assertEqual(payload["session_id"], _UUID)

    def test_payload_contains_account(self):
        result = _make_session_result()
        payload = _build_llm_payload(result)
        self.assertEqual(payload["account"], "j.harrison")

    def test_payload_contains_overall_confidence(self):
        result = _make_session_result(overall_confidence=0.72)
        payload = _build_llm_payload(result)
        self.assertEqual(payload["overall_confidence"], 0.72)

    def test_payload_mechanism_details_keyed_by_mechanism_id(self):
        result = _make_session_result()
        payload = _build_llm_payload(result)
        for mid in result.correlation.mechanisms_fired:
            self.assertIn(mid, payload["mechanism_details"])

    def test_payload_signal_fields_present(self):
        result = _make_session_result()
        payload = _build_llm_payload(result)
        for mid, detail in payload["mechanism_details"].items():
            for sig in detail["top_signals"]:
                for field in ("name", "observed", "baseline", "ratio"):
                    self.assertIn(field, sig)

    def test_payload_no_raw_event_records(self):
        """
        The payload should not contain full inline event records —
        only the summary fields (event_id, timestamp, significance).
        """
        result = _make_session_result()
        payload = _build_llm_payload(result)
        payload_str = json.dumps(payload)
        # "inline" is a field on EvidenceRef but should not be in the payload
        self.assertNotIn('"inline"', payload_str)

    def test_prompt_contains_json_block(self):
        result = _make_session_result()
        payload = _build_llm_payload(result)
        prompt = _build_llm_prompt(payload)
        self.assertIn("```json", prompt)

    def test_prompt_instructs_observed_inferred_tags(self):
        result = _make_session_result()
        payload = _build_llm_payload(result)
        prompt = _build_llm_prompt(payload)
        self.assertIn("[OBSERVED]", prompt)
        self.assertIn("[INFERRED]", prompt)


# ---------------------------------------------------------------------------
# Test: LLM response parsing
# ---------------------------------------------------------------------------

class TestParseLlmResponse(unittest.TestCase):

    def _valid(self) -> dict:
        return {
            "triage_paragraph": "Some paragraph.",
            "evidence_headlines": {
                "velocity": "headline",
                "enumeration": None,
                "priv_escalation": None,
            },
            "evidence_notes": {
                "velocity": ["note1"],
                "enumeration": [],
                "priv_escalation": [],
            },
        }

    def test_valid_json_parses(self):
        raw = json.dumps(self._valid())
        result = _parse_llm_response(raw, _UUID)
        self.assertIsNotNone(result)
        self.assertIn("triage_paragraph", result)

    def test_json_with_markdown_fences_stripped(self):
        raw = f"```json\n{json.dumps(self._valid())}\n```"
        result = _parse_llm_response(raw, _UUID)
        self.assertIsNotNone(result)

    def test_invalid_json_returns_none(self):
        result = _parse_llm_response("not json {{", _UUID)
        self.assertIsNone(result)

    def test_missing_required_key_returns_none(self):
        bad = self._valid()
        del bad["triage_paragraph"]
        result = _parse_llm_response(json.dumps(bad), _UUID)
        self.assertIsNone(result)

    def test_empty_string_returns_none(self):
        result = _parse_llm_response("", _UUID)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
